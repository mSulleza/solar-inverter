"""
Seed a day of plausible demo readings so the dashboard renders before the real
stick data arrives. Everything is tagged with a sentinel logger serial so it can
be told apart from real data and deleted in one statement:

    delete from public.readings where logger_serial = 111111111;
"""
import math, os, sys, datetime as dt
import psycopg2
from psycopg2.extras import execute_values

DEMO_SERIAL = 111111111
dsn = (os.environ.get("DATABASE_URL_UNPOOLED") or os.environ.get("POSTGRES_URL_NON_POOLING")
       or os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL"))
if not dsn:
    sys.exit("no DATABASE_URL in env")

conn = psycopg2.connect(dsn); conn.autocommit = True
cur = conn.cursor()
cur.execute("delete from public.readings where logger_serial=%s", (DEMO_SERIAL,))

now = dt.datetime.now(dt.timezone.utc)
start = now - dt.timedelta(hours=24)
rows = []
pv_energy = 0.0
load_energy = 0.0
soc = 55.0
step_min = 5
n = 24 * 60 // step_min

for i in range(n):
    t = start + dt.timedelta(minutes=i * step_min)
    hour = t.hour + t.minute / 60.0

    # Solar bell curve peaking ~13:00, zero at night.
    sun = max(0.0, math.sin((hour - 6) / 12 * math.pi)) if 6 <= hour <= 18 else 0.0
    pv = round(sun * 3200 * (0.85 + 0.15 * math.sin(i / 7.0)), 0)  # W, some cloud noise

    # Household load: morning and evening humps.
    base = 300
    load = base + 900 * math.exp(-((hour - 7.5) ** 2) / 2) + 1400 * math.exp(-((hour - 19) ** 2) / 3)
    load = round(load + 120 * math.sin(i / 3.0), 0)

    # Battery soaks up surplus PV, covers deficit; grid fills the rest.
    net = pv - load
    batt_power = round(max(-2000, min(2000, net)), 0)
    grid_power = round(load - pv - batt_power, 0)  # + = importing

    # SOC integrates battery power (48V pack ~ 5kWh usable).
    soc += (batt_power * (step_min / 60.0)) / 5000.0 * 100.0
    soc = max(20.0, min(100.0, soc))

    pv_energy += max(0.0, pv) * (step_min / 60.0) / 1000.0
    load_energy += max(0.0, load) * (step_min / 60.0) / 1000.0
    # daily counters reset at local midnight (approx UTC here for the demo)
    if t.hour == 0 and t.minute < step_min:
        pv_energy = 0.0
        load_energy = 0.0

    batt_v = round(48.0 + (soc - 50) * 0.04, 2)
    rows.append((
        t, DEMO_SERIAL,
        round(228 + 4 * math.sin(i / 11.0), 1),      # grid_voltage
        round(49.9 + 0.1 * math.sin(i / 5.0), 2),    # grid_frequency
        grid_power,
        round(320 * sun, 1), round(pv / 320 if sun else 0, 1), round(pv * 0.55, 0),  # pv1 v/i/p
        round(300 * sun, 1), round(pv / 300 if sun else 0, 1), round(pv * 0.45, 0),  # pv2 v/i/p
        pv,                                           # pv_power_total
        batt_v, round(batt_power / batt_v, 1), batt_power, round(soc, 1),
        round(229 + 3 * math.sin(i / 9.0), 1), load,  # load v / p
        round(32 + 8 * sun + 3 * math.sin(i / 13.0), 1),  # temperature
        round(pv_energy, 2), round(load_energy, 2),
        "powmr_hybrid", [],
    ))

cols = ("recorded_at","logger_serial","grid_voltage","grid_frequency","grid_power",
        "pv1_voltage","pv1_current","pv1_power","pv2_voltage","pv2_current","pv2_power",
        "pv_power_total","battery_voltage","battery_current","battery_power","battery_soc",
        "load_voltage","load_power","inverter_temperature","pv_energy_today","load_energy_today",
        "profile","registers")
execute_values(cur, f'insert into public.readings ({",".join(cols)}) values %s', rows)
cur.execute("select count(*) from public.readings where logger_serial=%s", (DEMO_SERIAL,))
print("seeded demo rows:", cur.fetchone()[0])
conn.close()
