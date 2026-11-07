import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Solar Inverter Dashboard",
  description: "Live telemetry from a POWMR hybrid inverter",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
