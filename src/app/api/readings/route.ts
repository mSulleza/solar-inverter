import { NextResponse } from "next/server";
import { sql } from "@/lib/db";

// Latest reading per logger, plus how stale it is. The dashboard polls this for
// the live tiles. No caching -- the whole point is "what is happening now".
export const dynamic = "force-dynamic";
export const revalidate = 0;

export async function GET() {
  try {
    const rows = await sql`
      select distinct on (logger_serial) *
      from public.readings
      order by logger_serial, recorded_at desc
    `;
    const latest = rows[0] ?? null;
    const ageSeconds = latest
      ? Math.round((Date.now() - new Date(latest.recorded_at as string).getTime()) / 1000)
      : null;

    return NextResponse.json({ latest, loggers: rows, ageSeconds });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}
