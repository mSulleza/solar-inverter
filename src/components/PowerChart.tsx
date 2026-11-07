"use client";

import {
  Area, AreaChart, CartesianGrid, Line, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from "recharts";

type Point = Record<string, number | string | null>;

const COLORS: Record<string, string> = {
  pv_power_total: "var(--solar)",
  load_power: "var(--load)",
  battery_power: "var(--battery)",
  grid_power: "var(--grid)",
  battery_soc: "var(--battery)",
  inverter_temperature: "var(--danger)",
};

function timeLabel(iso: string, hours: number) {
  const d = new Date(iso);
  return hours <= 48
    ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    : d.toLocaleDateString([], { month: "short", day: "numeric" });
}

// Power chart: PV and load as filled areas (the two quantities you watch), grid
// and battery as lines over the top so the balance between them stays readable.
export function PowerChart({ points, hours }: { points: Point[]; hours: number }) {
  const data = points.map((p) => ({
    ...p,
    t: timeLabel(p.recorded_at as string, hours),
  }));

  return (
    <div className="card p-4">
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm font-medium">Power</span>
        <Legend items={[["Solar", "var(--solar)"], ["Load", "var(--load)"], ["Battery", "var(--battery)"], ["Grid", "var(--grid)"]]} />
      </div>
      <ResponsiveContainer width="100%" height={260}>
        <AreaChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -12 }}>
          <defs>
            <linearGradient id="gPv" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--solar)" stopOpacity={0.5} />
              <stop offset="100%" stopColor="var(--solar)" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="gLoad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--load)" stopOpacity={0.35} />
              <stop offset="100%" stopColor="var(--load)" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="var(--border)" vertical={false} />
          <XAxis dataKey="t" tick={{ fill: "var(--text-faint)", fontSize: 11 }} minTickGap={40} axisLine={false} tickLine={false} />
          <YAxis tick={{ fill: "var(--text-faint)", fontSize: 11 }} axisLine={false} tickLine={false} width={44}
                 tickFormatter={(v) => (Math.abs(v) >= 1000 ? `${(v / 1000).toFixed(1)}k` : `${v}`)} />
          <Tooltip content={<ChartTooltip unit="W" />} />
          <Area type="monotone" dataKey="pv_power_total" stroke={COLORS.pv_power_total} fill="url(#gPv)" strokeWidth={2} name="Solar" dot={false} isAnimationActive={false} />
          <Area type="monotone" dataKey="load_power" stroke={COLORS.load_power} fill="url(#gLoad)" strokeWidth={2} name="Load" dot={false} isAnimationActive={false} />
          <Line type="monotone" dataKey="battery_power" stroke={COLORS.battery_power} strokeWidth={1.5} name="Battery" dot={false} isAnimationActive={false} />
          <Line type="monotone" dataKey="grid_power" stroke={COLORS.grid_power} strokeWidth={1.5} name="Grid" dot={false} isAnimationActive={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

export function SocChart({ points, hours }: { points: Point[]; hours: number }) {
  const data = points.map((p) => ({ ...p, t: timeLabel(p.recorded_at as string, hours) }));
  return (
    <div className="card p-4">
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm font-medium">Battery state of charge</span>
        <Legend items={[["SOC %", "var(--battery)"]]} />
      </div>
      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -12 }}>
          <defs>
            <linearGradient id="gSoc" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--battery)" stopOpacity={0.4} />
              <stop offset="100%" stopColor="var(--battery)" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="var(--border)" vertical={false} />
          <XAxis dataKey="t" tick={{ fill: "var(--text-faint)", fontSize: 11 }} minTickGap={40} axisLine={false} tickLine={false} />
          <YAxis domain={[0, 100]} tick={{ fill: "var(--text-faint)", fontSize: 11 }} axisLine={false} tickLine={false} width={44} />
          <Tooltip content={<ChartTooltip unit="%" />} />
          <Area type="monotone" dataKey="battery_soc" stroke="var(--battery)" fill="url(#gSoc)" strokeWidth={2} name="SOC" dot={false} isAnimationActive={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

function Legend({ items }: { items: [string, string][] }) {
  return (
    <div className="flex gap-3">
      {items.map(([label, color]) => (
        <span key={label} className="flex items-center gap-1 text-xs" style={{ color: "var(--text-dim)" }}>
          <span className="inline-block w-2.5 h-2.5 rounded-sm" style={{ background: color }} />
          {label}
        </span>
      ))}
    </div>
  );
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function ChartTooltip({ active, payload, label, unit }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="card p-2 text-xs" style={{ borderColor: "var(--border)" }}>
      <div className="mb-1" style={{ color: "var(--text-dim)" }}>{label}</div>
      {payload.map((p: any) => (
        <div key={p.name} className="flex justify-between gap-4 tabnum mono">
          <span style={{ color: p.stroke }}>{p.name}</span>
          <span>{Math.round(p.value)} {unit}</span>
        </div>
      ))}
    </div>
  );
}
