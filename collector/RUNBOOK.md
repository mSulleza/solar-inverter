# Solar inverter collector — runbook

Decodes the telemetry coming off the IGEN/Solarman **SWB1** WiFi logger stick
(firmware `SWB1-v1.44.5_SolarV70`) on your LAN and ships it to Neon Postgres,
which the Vercel dashboard reads.

- **Stick:** an IGEN/Solarman SWB1 (Shanghai High-Flying Wi-Fi module); `192.168.1.50` in the examples below
- **Inverter:** POWMR hybrid
- **Dashboard:** the Next.js app in this repo, on Vercel
- **Database:** Neon Postgres (`solar-inverter-db`, provisioned via Vercel)

## Why interception, not a local API

This stick is locked down. Its entire local web surface (behind a web
login) is a single firmware-upload page — `config_hide.html`, banner
`SWB1-v1.44.5_SolarV70`. It exposes **no** Modbus TCP (8899 closed), **no** UDP
AT interface (48899 silent), and no data pages. Everything it knows leaves only
one way: a TCP connection to the Solarman collection server on port **10000**,
wrapped in Solarman's "V5" framing, which is a thin envelope around the raw
Modbus RTU responses it polls from the inverter.

So we read that uplink. The collector relays the stick to the real Solarman
server byte-for-byte (your Solarman app keeps working) and decodes the frames on
the way past. Nothing on the inverter or stick is changed.

## Harden the stick first

That firmware-upload page is the stick's whole attack surface, so:

- **Change the stick's web password** from the factory default (its web UI,
  or the Solarman/installer app's device settings).
- **Disable its setup hotspot** (typically an `AP_<serial>` Wi-Fi it broadcasts for
  provisioning) if your firmware offers it; otherwise anyone in Wi-Fi range can
  join it and reach the upload page.
- **Put it on an isolated IoT network** (an IoT/guest SSID or VLAN with
  internet access but no route to your other devices). The collector machine
  must be on the same network segment as the stick for option B below.
- **Reserve the stick's IP** in the router's DHCP settings: the collector
  serves only that one address (`--stick-ip`).

## Getting the stick to connect to us

The stick has no configurable server address — it resolves a Solarman hostname
(`iot.talent-monitoring.com`) and connects there. We answer that DNS lookup with
our own address. Most consumer routers only support
one DNS server for the whole LAN (no per-device DNS), so pick one.
**Prefer option B.**

### Option B — stick-only, ARP redirect (recommended, narrow blast radius)
Leave the router alone. Run the collector with `--arp-redirect 192.168.1.50`
(see below) so only the stick is told the collector is its gateway/DNS. Nothing
else on the LAN is touched, and nothing breaks for anyone else when the
collector stops.

### Option A — LAN-wide DNS (only if B can't work)
Router → Advanced → Network → DHCP Server → set **Primary DNS** to the collector
machine's IP (for example `192.168.1.10`). Every device now resolves through the
collector, but everything except the Solarman hostnames is forwarded upstream
untouched. Run the collector with `--dns-allow-subnet` so it answers the
stick's /24 (by default it answers only the stick and drops everyone else's
queries). Caveats:

- **Reserve the collector machine's IP** in the router's DHCP settings first. If
  its address changes, every device on the LAN loses DNS.
- While the collector is stopped or asleep the whole LAN has no DNS.
- Devices outside the stick's /24 get no answers.

Fully reversible: set DNS back to automatic.

## Running it

```bash
cd collector
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# Pull the Neon connection string the dashboard already uses, and lock it down:
#   (from the repo root)  vercel env pull collector/.env
chmod 600 .env

# Option B (recommended) — no router change, redirect only the stick:
sudo "$PWD/.venv/bin/python" "$PWD/run.py" --arp-redirect 192.168.1.50 --env-file "$PWD/.env"

# Option A — you set router DNS to this machine, then:
sudo "$PWD/.venv/bin/python" "$PWD/run.py" --stick-ip 192.168.1.50 --dns-allow-subnet --env-file "$PWD/.env"
```

Use the venv's Python by absolute path (`$PWD` expands before `sudo` runs) and
**don't use `sudo -E`**: it would hand your whole shell environment
(`PYTHONPATH` and friends) to a root process. The connection string comes from
`--env-file` instead, which is read after root has been dropped. Keep the
`collector/` folder and the venv writable only by you — root runs code from
both before it drops privileges.

The collector binds one address: `--listen <this machine's LAN IP>`, or by
default the address of the interface that routes to the stick. It never listens
on all interfaces, and it serves only the stick: the proxy closes connections
from any other address and the DNS server drops their queries.

**When `sudo` is needed, and what runs as root:**

- **DNS (options A and B):** on macOS, binding port 53 on a specific address
  needs root (unprivileged binds below 1024 are only allowed on `0.0.0.0`, which
  the collector doesn't use).
- **ARP mode (option B):** root for `sysctl net.inet.ip.forwarding`, `pfctl`
  and sending raw ARP replies.
- **Neither** (`--no-dns`, proxy on port 10000): no `sudo` at all.

Started with `sudo`, the collector binds its sockets and sets up pf as root,
then **drops to your user** (from `SUDO_UID`/`SUDO_GID`) before it reads a
single packet; it refuses to run as root without them. In ARP mode a small root
parent process stays behind that only sends the stick's ARP replies and, when
the collector exits, flushes the pf anchor and puts IP forwarding and pf back
as they were. If it is killed with `kill -9`, undo that by hand:

```bash
sudo pfctl -a solar_collector -F all
sudo sysctl -w net.inet.ip.forwarding=0   # only if it was 0 before
```

Point a browser at the dashboard and readings appear within a minute or two.

The collector spools every reading to a local SQLite file first
(`collector_spool.db`) and only deletes rows after Neon confirms the insert, so
a flaky link never loses a sample. The spool now belongs to your user; if an
older version created it as root, `sudo chown $(id -un) collector_spool.db`.
Floods are capped: frames beyond 60 a minute are dropped, the spool stops
accepting rows at 20,000 queued, and V5 frames claiming more than 2 KB of
payload are discarded (each logged at most once a minute).

## Verifying the register map

`registers.py`'s POWMR map is a **best-effort hypothesis** — "POWMR" rebadges
several platforms and the layout varies. Every reading is therefore stored with
its raw register block (`raw_frames` table), so a wrong map can be corrected and
history re-derived. To check it against real data:

```bash
# rank which registers plausibly hold which metric, from a real capture
python capture.py --hex-file frames.hex --suggest

# decode a capture with the current map and eyeball the numbers
python capture.py --hex-file frames.hex
```

Get `frames.hex` from the `raw_frames.payload_hex` column once data is flowing,
or from a `tcpdump -i any 'tcp port 10000'` capture.

## Removing demo data

The dashboard ships seeded with 24h of demo data (`logger_serial = 111111111`).
It's replaced by real data automatically, or drop it explicitly:

```sql
delete from public.readings where logger_serial = 111111111;
```

## Tests

```bash
python -m pytest collector/ -q
```

Covers the V5 decoder, TCP reassembly across arbitrary chunk boundaries,
resync after garbage, Modbus exception handling, and a full
fake-stick → proxy → fake-server → decode → spool round-trip, plus the
security behaviour (`test_security.py`): non-stick sources rejected by the proxy
and DNS, connection cap, oversize frames, rate and spool caps, log sanitising,
spoof-resistant upstream lookup, privilege checks, and ARP-mode cleanup.
