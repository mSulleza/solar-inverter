# Solar Inverter Dashboard

Live telemetry from a **POWMR hybrid inverter**, decoded off its IGEN/Solarman
WiFi logger stick on the LAN and charted on a Vercel dashboard backed by Neon
Postgres.

## How it works

```
 POWMR inverter ──RS485──► SWB1 logger stick (on the LAN)
                                  │  Solarman "V5" frames (Modbus RTU inside)
                                  ▼  TCP :10000
                          collector (this machine)
                          ├─ relays uplink to real Solarman server  (app keeps working)
                          ├─ decodes V5 → Modbus registers → metrics
                          └─ spools locally, pushes to Neon Postgres
                                  │
                                  ▼
                       Vercel dashboard  ◄── reads Neon server-side
```

The stick is locked down — no local Modbus, no AT interface, only a
firmware-upload web page. Its telemetry leaves only over the Solarman cloud
uplink, so the collector reads that uplink rather than polling the inverter.
Full detail and setup steps: **[collector/RUNBOOK.md](collector/RUNBOOK.md)**.

## Layout

| Path | What |
|---|---|
| `collector/solarman_v5.py` | Solarman V5 frame decoder + TCP reassembly |
| `collector/registers.py`   | POWMR register map (+ autodetect helper) |
| `collector/proxy.py`       | transparent V5 uplink proxy |
| `collector/dns_redirect.py`| forwarding DNS with Solarman-host redirect |
| `collector/arp_redirect.py`| stick-only ARP interception (no router change) |
| `collector/sink.py`        | local spool → Neon Postgres, at-least-once |
| `collector/run.py`         | collector entrypoint |
| `collector/capture.py`     | offline decode of a captured session |
| `db/schema.sql`            | Neon schema (readings, raw_frames, views) |
| `db/seed_demo.py`          | 24h of demo data for the dashboard |
| `src/`                     | Next.js dashboard |

## Dev

```bash
npm run dev                 # dashboard at localhost:3000
python -m pytest collector/ # collector tests
```
