import { neon } from "@neondatabase/serverless";

// Server-only. The connection string never reaches the browser -- every query
// here runs in a route handler or server component. Prefer the pooled URL since
// serverless functions open a fresh connection per invocation.
const connectionString =
  process.env.DATABASE_URL ||
  process.env.POSTGRES_URL ||
  process.env.DATABASE_URL_UNPOOLED ||
  process.env.POSTGRES_URL_NON_POOLING;

if (!connectionString) {
  throw new Error("No DATABASE_URL / POSTGRES_URL in environment");
}

export const sql = neon(connectionString);

export type Reading = {
  recorded_at: string;
  logger_serial: number;
  grid_voltage: number | null;
  grid_frequency: number | null;
  grid_power: number | null;
  pv_power_total: number | null;
  battery_voltage: number | null;
  battery_power: number | null;
  battery_soc: number | null;
  load_power: number | null;
  inverter_temperature: number | null;
  pv_energy_today: number | null;
  load_energy_today: number | null;
};
