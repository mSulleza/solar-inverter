-- Solar inverter telemetry schema (Neon Postgres).
--
-- Two tables rather than one: `readings` holds decoded metrics for the
-- dashboard to chart, and `raw_frames` holds the bytes exactly as the logger
-- stick sent them. The split matters because the POWMR register map is a
-- best-effort hypothesis -- keeping the raw frames means a wrong mapping can be
-- corrected later and the whole history re-derived, instead of being lost.
--
-- No row-level security or anon role here (unlike a Supabase setup): the Neon
-- connection string never reaches the browser. The Next.js dashboard queries
-- server-side and the collector inserts over the same wire protocol, so access
-- is controlled by who holds DATABASE_URL rather than by in-database policy.

create table if not exists public.readings (
    id                    bigint generated always as identity primary key,
    recorded_at           timestamptz not null default now(),
    logger_serial         bigint      not null,

    -- Grid / AC input
    grid_voltage          real,
    grid_frequency        real,
    grid_power            real,

    -- PV strings
    pv1_voltage           real,
    pv1_current           real,
    pv1_power             real,
    pv2_voltage           real,
    pv2_current           real,
    pv2_power             real,
    pv_power_total        real,

    -- Battery. battery_power is signed: positive charging, negative discharging.
    battery_voltage       real,
    battery_current       real,
    battery_power         real,
    battery_soc           real,

    -- Load / AC output
    load_voltage          real,
    load_power            real,

    inverter_temperature  real,
    pv_energy_today       real,
    load_energy_today     real,

    -- Which profile decoded this row, so rows decoded by different map versions
    -- stay distinguishable after a correction.
    profile               text not null default 'powmr_hybrid',
    registers             integer[] not null default '{}'
);

-- The dashboard almost always asks "latest N for this logger" or "range for
-- this logger", so serial first then time descending matches both.
create index if not exists readings_logger_time_idx
    on public.readings (logger_serial, recorded_at desc);
create index if not exists readings_time_idx
    on public.readings (recorded_at desc);

create table if not exists public.raw_frames (
    id             bigint generated always as identity primary key,
    received_at    timestamptz not null default now(),
    logger_serial  bigint,
    control_code   integer,
    control_name   text,
    sequence       integer,
    checksum_ok    boolean,
    modbus_crc_ok  boolean,
    modbus_slave   integer,
    modbus_func    integer,
    registers      integer[],
    payload_hex    text not null
);

create index if not exists raw_frames_time_idx
    on public.raw_frames (received_at desc);

-- Rolling 5-minute aggregate. The stick reports every ~1-5 minutes, so a day of
-- charting is a few hundred points; this view keeps longer ranges cheap.
create or replace view public.readings_5min as
select
    date_trunc('hour', recorded_at)
        + floor(extract(minute from recorded_at) / 5) * interval '5 minutes' as bucket,
    logger_serial,
    avg(pv_power_total)       as pv_power_total,
    avg(load_power)           as load_power,
    avg(battery_power)        as battery_power,
    avg(battery_soc)          as battery_soc,
    avg(grid_power)           as grid_power,
    avg(battery_voltage)      as battery_voltage,
    avg(inverter_temperature) as inverter_temperature,
    max(pv_energy_today)      as pv_energy_today,
    max(load_energy_today)    as load_energy_today,
    count(*)                  as samples
from public.readings
group by 1, 2;

-- Per-day energy totals. pv_energy_today is a daily counter that resets at
-- midnight, so its maximum within a day is that day's total.
create or replace view public.daily_energy as
select
    (recorded_at at time zone 'UTC')::date as day,
    logger_serial,
    max(pv_energy_today)   as pv_kwh,
    max(load_energy_today) as load_kwh,
    avg(battery_soc)       as avg_soc,
    min(battery_soc)       as min_soc,
    max(battery_soc)       as max_soc,
    count(*)               as samples
from public.readings
group by 1, 2;
