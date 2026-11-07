"use client";

// A compact energy-flow diagram: PV at the top, the inverter in the middle,
// and battery / home / grid around it. Arrow direction and colour follow the
// actual sign of each power value, so a glance tells you whether the battery is
// charging, whether you are importing from the grid, and where the sun is going.

type Props = {
  pv: number | null;
  battery: number | null; // + charging, - discharging
  load: number | null;
  grid: number | null; // + importing, - exporting
};

function fmt(w: number | null) {
  if (w === null || Number.isNaN(w)) return "-- W";
  const a = Math.abs(w);
  return a >= 1000 ? `${(w / 1000).toFixed(2)} kW` : `${Math.round(w)} W`;
}

function Node({
  label, value, color, x, y,
}: { label: string; value: string; color: string; x: number; y: number }) {
  return (
    <g transform={`translate(${x},${y})`}>
      <circle r="34" fill="var(--bg-elev)" stroke={color} strokeWidth="2" />
      <text textAnchor="middle" y="-2" fontSize="11" fill="var(--text-dim)">{label}</text>
      <text textAnchor="middle" y="14" fontSize="12" fontWeight="600" fill={color} className="mono">
        {value}
      </text>
    </g>
  );
}

// A flowing line whose dash animation runs only when power actually moves.
function Flow({
  x1, y1, x2, y2, active, color, reverse,
}: { x1: number; y1: number; x2: number; y2: number; active: boolean; color: string; reverse?: boolean }) {
  return (
    <line
      x1={reverse ? x2 : x1} y1={reverse ? y2 : y1}
      x2={reverse ? x1 : x2} y2={reverse ? y1 : y2}
      stroke={active ? color : "var(--border)"}
      strokeWidth={active ? 2.5 : 1.5}
      strokeDasharray={active ? "6 6" : "0"}
      opacity={active ? 1 : 0.4}
    >
      {active && (
        <animate attributeName="stroke-dashoffset" from="12" to="0" dur="0.7s" repeatCount="indefinite" />
      )}
    </line>
  );
}

export function PowerFlow({ pv, battery, load, grid }: Props) {
  const importing = (grid ?? 0) > 20;
  const exporting = (grid ?? 0) < -20;
  const charging = (battery ?? 0) > 20;
  const discharging = (battery ?? 0) < -20;

  return (
    <div className="card p-4">
      <div className="text-xs uppercase tracking-wider mb-2" style={{ color: "var(--text-faint)" }}>
        Live power flow
      </div>
      <svg viewBox="0 0 320 260" className="w-full" style={{ maxHeight: 280 }}>
        {/* PV -> inverter */}
        <Flow x1={160} y1={70} x2={160} y2={110} active={(pv ?? 0) > 20} color="var(--solar)" />
        {/* inverter -> home */}
        <Flow x1={160} y1={150} x2={160} y2={200} active={(load ?? 0) > 20} color="var(--load)" />
        {/* battery <-> inverter (left) */}
        <Flow x1={70} y1={130} x2={126} y2={130} active={charging || discharging}
              color="var(--battery)" reverse={discharging} />
        {/* grid <-> inverter (right) */}
        <Flow x1={194} y1={130} x2={250} y2={130} active={importing || exporting}
              color="var(--grid)" reverse={exporting} />

        {/* inverter core */}
        <rect x="126" y="110" width="68" height="40" rx="8" fill="var(--bg-elev)"
              stroke="var(--text-faint)" strokeWidth="1.5" />
        <text x="160" y="134" textAnchor="middle" fontSize="10" fill="var(--text-dim)">INVERTER</text>

        <Node label="Solar" value={fmt(pv)} color="var(--solar)" x={160} y={40} />
        <Node label={charging ? "Batt ▲" : discharging ? "Batt ▼" : "Batt"} value={fmt(battery)}
              color="var(--battery)" x={40} y={130} />
        <Node label={importing ? "Grid ▼" : exporting ? "Grid ▲" : "Grid"} value={fmt(grid)}
              color="var(--grid)" x={280} y={130} />
        <Node label="Home" value={fmt(load)} color="var(--load)" x={160} y={228} />
      </svg>
    </div>
  );
}
