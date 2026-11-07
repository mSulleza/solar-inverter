type Props = {
  label: string;
  value: number | null | undefined;
  unit: string;
  accent: string;
  sub?: string;
  precision?: number;
};

// One live metric. Kept dumb on purpose -- all it does is format a number and
// wear the domain colour of whatever quantity it shows.
export function StatTile({ label, value, unit, accent, sub, precision = 0 }: Props) {
  const display =
    value === null || value === undefined || Number.isNaN(value)
      ? "--"
      : value.toFixed(precision);

  return (
    <div className="card p-4 flex flex-col gap-1 relative overflow-hidden">
      <div
        className="absolute left-0 top-0 h-full w-1"
        style={{ background: accent }}
      />
      <span className="text-xs uppercase tracking-wider" style={{ color: "var(--text-faint)" }}>
        {label}
      </span>
      <div className="flex items-baseline gap-1">
        <span className="text-3xl font-semibold tabnum mono" style={{ color: accent }}>
          {display}
        </span>
        <span className="text-sm" style={{ color: "var(--text-dim)" }}>{unit}</span>
      </div>
      {sub && <span className="text-xs" style={{ color: "var(--text-faint)" }}>{sub}</span>}
    </div>
  );
}
