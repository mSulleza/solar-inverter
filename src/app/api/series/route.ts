import { NextResponse } from "next/server";
import { sql } from "@/lib/db";

export const dynamic = "force-dynamic";
export const revalidate = 0;

// Time series for the charts. `hours` selects the window; the 5-minute rollup
// view keeps longer ranges cheap while raw resolution is used for short ones.
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const hours = Math.min(720, Math.max(1, Number(searchParams.get("hours") ?? 24)));

  try {
    const useRollup = hours > 48;
    const rows = useRollup
      ? await sql`
          select bucket as recorded_at, pv_power_total, load_power, battery_power,
                 battery_soc, grid_power, inverter_temperature
          from public.readings_5min
          where bucket > now() - (${hours}::text || ' hours')::interval
          order by bucket asc`
      : await sql`
          select recorded_at, pv_power_total, load_power, battery_power,
                 battery_soc, grid_power, inverter_temperature
          from public.readings
          where recorded_at > now() - (${hours}::text || ' hours')::interval
          order by recorded_at asc`;

    return NextResponse.json({ hours, points: rows });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}
