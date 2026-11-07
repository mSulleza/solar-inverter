"use client";

import { useCallback, useEffect, useState } from "react";
import { StatTile } from "./StatTile";
import { PowerFlow } from "./PowerFlow";
import { PowerChart, SocChart } from "./PowerChart";

type Latest = Record<string, number | string | null> | null;
type Point = Record<string, number | string | null>;

const RANGES = [
  { label: "6h", hours: 6 },
  { label: "24h", hours: 24 },
  { label: "7d", hours: 168 },
  { label: "30d", hours: 720 },
];

export function Dashboard() {
  const [latest, setLatest] = useState<Latest>(null);
  const [ageSeconds, setAge] = useState<number | null>(null);
  const [hours, setHours] = useState(24);
  const [points, setPoints] = useState<Point[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [r, s] = await Promise.all([
        fetch("/api/readings", { cache: "no-store" }).then((x) => x.json()),
        fetch(`/api/series?hours=${hours}`, { cache: "no-store" }).then((x) => x.json()),
      ]);
      if (r.error) throw new Error(r.error);
      setLatest(r.latest);
      setAge(r.ageSeconds);
      setPoints(s.points ?? []);
      setError(null);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [hours]);

  useEffect(() => {
    load();
    // Poll every 15s -- the stick reports on the order of minutes, so this is
    // comfortably faster than new data arrives without hammering the DB.
    const id = setInterval(load, 15000);
    return () => clearInterval(id);
  }, [load]);

  const n = (k: string) => {
    const v = latest?.[k];
    return typeof v === "number" ? v : null;
  };

  const fresh = ageSeconds !== null && ageSeconds < 600;
  const isDemo = String(latest?.logger_serial ?? "") === "111111111";

  return (
    <div className="max-w-6xl mx-auto px-4 py-6 flex flex-col gap-5">
      <header className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-semibold flex items-center gap-2">
            <span style={{ color: "var(--solar)" }}>◉</span> Solar Inverter
          </h1>
          <p className="text-xs" style={{ color: "var(--text-faint)" }}>
            POWMR hybrid · logger {latest?.logger_serial ?? "—"}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5 text-xs" style={{ color: fresh ? "var(--battery)" : "var(--text-faint)" }}>
            <span className={`inline-block w-2 h-2 rounded-full ${fresh ? "pulse" : ""}`}
                  style={{ background: fresh ? "var(--battery)" : "var(--text-faint)" }} />
            {ageSeconds === null ? "no data" : fresh ? "live" : `${Math.round(ageSeconds / 60)}m ago`}
          </span>
          <div className="flex rounded-lg overflow-hidden border" style={{ borderColor: "var(--border)" }}>
            {RANGES.map((r) => (
              <button key={r.hours} onClick={() => setHours(r.hours)}
                className="px-3 py-1 text-xs transition-colors"
                style={{
                  background: hours === r.hours ? "var(--bg-card)" : "transparent",
                  color: hours === r.hours ? "var(--text)" : "var(--text-faint)",
                }}>
                {r.label}
              </button>
            ))}
          </div>
        </div>
      </header>

      {isDemo && (
        <div className="text-xs rounded-lg px-3 py-2" style={{ background: "var(--solar-glow)", color: "var(--solar)" }}>
          Showing demo data. Live readings replace this automatically once the collector is running.
        </div>
      )}
      {error && (
        <div className="text-xs rounded-lg px-3 py-2" style={{ background: "rgba(255,95,86,0.1)", color: "var(--danger)" }}>
          {error}
        </div>
      )}

      <section className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatTile label="Solar Now" value={n("pv_power_total")} unit="W" accent="var(--solar)"
                  sub={`${(n("pv_energy_today") ?? 0).toFixed(1)} kWh today`} />
        <StatTile label="Battery" value={n("battery_soc")} unit="%" accent="var(--battery)"
                  sub={`${(n("battery_power") ?? 0) > 0 ? "charging" : "discharging"} ${Math.abs(n("battery_power") ?? 0).toFixed(0)} W`} />
        <StatTile label="Home Load" value={n("load_power")} unit="W" accent="var(--load)"
                  sub={`${(n("load_energy_today") ?? 0).toFixed(1)} kWh today`} />
        <StatTile label="Grid" value={n("grid_power")} unit="W" accent="var(--grid)"
                  sub={(n("grid_power") ?? 0) >= 0 ? "importing" : "exporting"} />
      </section>

      <section className="grid md:grid-cols-3 gap-4">
        <div className="md:col-span-1"><PowerFlow pv={n("pv_power_total")} battery={n("battery_power")} load={n("load_power")} grid={n("grid_power")} /></div>
        <div className="md:col-span-2"><PowerChart points={points} hours={hours} /></div>
      </section>

      <section className="grid md:grid-cols-3 gap-4">
        <div className="md:col-span-2"><SocChart points={points} hours={hours} /></div>
        <div className="grid grid-cols-2 gap-3 content-start">
          <StatTile label="Batt Voltage" value={n("battery_voltage")} unit="V" accent="var(--battery)" precision={2} />
          <StatTile label="Grid Voltage" value={n("grid_voltage")} unit="V" accent="var(--grid)" precision={1} />
          <StatTile label="Frequency" value={n("grid_frequency")} unit="Hz" accent="var(--text-dim)" precision={2} />
          <StatTile label="Temp" value={n("inverter_temperature")} unit="°C" accent="var(--danger)" precision={1} />
        </div>
      </section>

      <footer className="text-xs text-center pt-2" style={{ color: "var(--text-faint)" }}>
        {loading ? "loading…" : `${points.length} points · updates every 15s`}
      </footer>
    </div>
  );
}
