# Solar inverter collector — runbook

Decodes the telemetry coming off the IGEN/Solarman **SWB1** WiFi logger stick
(firmware `SWB1-v1.44.5_SolarV70`) on your LAN and ships it to Neon Postgres,
which the Vercel dashboard reads.

- **Stick:** an IGEN/Solarman SWB1 (Shanghai High-Flying Wi-Fi module); `192.168.1.50` in the examples below
- **Inverter:** POWMR hybrid
- **Dashboard:** the Next.js app in this repo, on Vercel
- **Database:** Neon Postgres (`solar-inverter-db`, provisioned via Vercel)

## Why interception, not a local API

This stick is locked down. Its entire local web surface (behind
the factory default login) is a single firmware-upload page — `config_hide.html`, banner
`SWB1-v1.44.5_SolarV70`. It exposes **no** Modbus TCP (8899 closed), **no** UDP
AT interface (48899 silent), and no data pages. Everything it knows leaves only
one way: a TCP connection to the Solarman collection server on port **10000**,
wrapped in Solarman's "V5" framing, which is a thin envelope around the raw
Modbus RTU responses it polls from the inverter.

So we read that uplink. The collector relays the stick to the real Solarman
server byte-for-byte (your Solarman app keeps working) and decodes the frames on
the way past. Nothing on the inverter or stick is changed.

## Getting the stick to connect to us

The stick has no configurable server address — it resolves a Solarman hostname
(`iot.talent-monitoring.com`) and connects there. We answer that DNS lookup with
our own address. Most consumer routers only support
one DNS server for the whole LAN (no per-device DNS), so pick one:

### Option A — LAN-wide DNS (simplest, whole network)
Router → Advanced → Network → DHCP Server → set **Primary DNS** to the collector
machine's IP (for example `192.168.1.10`). Every device now resolves through the
collector, but everything except the Solarman hostnames is forwarded upstream
untouched. Fully reversible: set DNS back to automatic.

### Option B — stick-only, ARP redirect (narrow blast radius)
Leave the router alone. Run the collector with `--arp-redirect 192.168.1.50`
(see below) so only the stick is told the collector is its gateway/DNS. Nothing
else on the LAN is touched. This is the right call if you don't want to move the
whole network's DNS.

## Running it

```bash
cd collector
pip install -r requirements.txt

# Pull the Neon connection string the dashboard already uses:
#   (from the repo root)  vercel env pull collector/.env
set -a; source .env; set +a

# Option A — you set router DNS to this machine, then:
sudo -E python run.py

# Option B — no router change, redirect only the stick:
sudo -E python run.py --arp-redirect 192.168.1.50
```

`sudo` is needed only to bind DNS on port 53. `-E` keeps the `DATABASE_URL` from
your shell. Point a browser at the dashboard and readings appear within a
minute or two.

The collector spools every reading to a local SQLite file first
(`collector_spool.db`) and only deletes rows after Neon confirms the insert, so
a flaky link never loses a sample.

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
fake-stick → proxy → fake-server → decode → spool round-trip.
