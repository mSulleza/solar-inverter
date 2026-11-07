"""
Collector entrypoint: intercept the stick's uplink, decode it, ship it.

Wires together the three pieces:

  1. a forwarding DNS server that answers the stick's lookup for the Solarman
     collection host with this machine's address (everything else passes through)
  2. a TCP proxy on port 10000 that relays the stick to the real Solarman server
     and decodes the V5 frames going past
  3. a sink that spools decoded readings locally and pushes them to Supabase

The Solarman app keeps working throughout -- this observes the uplink, it does
not replace it.

Both listeners want privileged ports (DNS on 53), so this normally runs under
sudo. Use --no-dns if the router can point the stick at a DNS server some other
way, or --once to decode a captured file instead of live traffic.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import arp_redirect  # noqa: E402
import dns_redirect  # noqa: E402
import proxy  # noqa: E402
from registers import PROFILES, derive  # noqa: E402
from sink import Sink, NeonConfig  # noqa: E402
from solarman_v5 import CONTROL_DATA, V5Frame  # noqa: E402

log = logging.getLogger("collector")


def local_ip() -> str:
    """Best guess at this machine's LAN address, as the stick would reach it."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]


class Collector:
    def __init__(self, sink: Sink, profile_name: str, store_raw: bool = True) -> None:
        self.sink = sink
        self.profile = PROFILES[profile_name]
        self.store_raw = store_raw
        self.frames_seen = 0
        self.readings_written = 0

    def on_frame(self, frame: V5Frame) -> None:
        self.frames_seen += 1

        if self.store_raw:
            self.sink.write("raw_frames", self._raw_row(frame))

        # Only data frames carry registers; hello and heartbeat frames are stick
        # housekeeping and have nothing to decode.
        if frame.control != CONTROL_DATA or frame.modbus is None:
            log.info("frame %s from logger %s", frame.control_name, frame.logger_serial)
            return

        modbus = frame.modbus
        if modbus.exception is not None:
            log.warning("inverter returned Modbus exception %s", modbus.exception)
            return

        if not modbus.registers:
            return

        if not modbus.crc_ok:
            # Still recorded as a raw frame above, but not trusted as a reading.
            log.warning("bad Modbus CRC, %d registers ignored", len(modbus.registers))
            return

        metrics = derive(self.profile.decode(modbus.registers))
        row = {
            "logger_serial": frame.logger_serial,
            "profile": self.profile.name,
            "registers": modbus.registers,
            **{k: round(v, 3) for k, v in metrics.items()},
        }
        self.sink.write("readings", row)
        self.readings_written += 1

        log.info(
            "reading #%d  pv=%.0fW load=%.0fW batt=%.0fW soc=%.0f%%",
            self.readings_written,
            metrics.get("pv_power_total", 0.0),
            metrics.get("load_power", 0.0),
            metrics.get("battery_power", 0.0),
            metrics.get("battery_soc", 0.0),
        )

    def _raw_row(self, frame: V5Frame) -> dict:
        modbus = frame.modbus
        return {
            "logger_serial": frame.logger_serial,
            "control_code": frame.control,
            "control_name": frame.control_name,
            "sequence": frame.sequence,
            "checksum_ok": frame.checksum_ok,
            "modbus_crc_ok": modbus.crc_ok if modbus else None,
            "modbus_slave": modbus.slave if modbus else None,
            "modbus_func": modbus.function if modbus else None,
            "registers": modbus.registers if modbus else [],
            "payload_hex": frame.raw.hex(),
        }


def build_sink(args) -> Sink:
    # Prefer the direct (unpooled) connection: the collector holds one
    # long-lived connection and reconnects per flush, so the pooler buys nothing
    # and the direct endpoint is simpler.
    dsn = (
        os.environ.get("DATABASE_URL_UNPOOLED")
        or os.environ.get("POSTGRES_URL_NON_POOLING")
        or os.environ.get("DATABASE_URL")
        or os.environ.get("POSTGRES_URL")
    )

    config = None
    if dsn:
        config = NeonConfig(dsn=dsn)
        log.info("uploading to Neon Postgres")
    else:
        # Not fatal: the spool keeps everything, so a run without a connection
        # string still captures data that can be uploaded once it is set.
        log.warning("no DATABASE_URL in env -- local spool only")

    return Sink(Path(args.spool), config)


def main() -> None:
    parser = argparse.ArgumentParser(description="Solar inverter collector")
    parser.add_argument("--profile", default="powmr_hybrid", choices=sorted(PROFILES))
    parser.add_argument("--spool", default="collector_spool.db")
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--proxy-port", type=int, default=10000)
    parser.add_argument("--dns-port", type=int, default=53)
    parser.add_argument("--no-dns", action="store_true", help="skip the DNS redirect")
    parser.add_argument("--arp-redirect", metavar="STICK_IP", default=None,
                        help="intercept ONLY this host via ARP instead of LAN-wide DNS")
    parser.add_argument("--upstream-host", default=proxy.DEFAULT_UPSTREAM_HOST)
    parser.add_argument("--upstream-port", type=int, default=proxy.DEFAULT_UPSTREAM_PORT)
    parser.add_argument("--resolver", default="1.1.1.1")
    parser.add_argument("--flush-interval", type=float, default=30.0)
    parser.add_argument("--advertise-ip", default=None, help="override the IP handed out by DNS")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)-8s %(message)s",
    )

    advertise = args.advertise_ip or local_ip()
    log.info("this machine is %s", advertise)

    sink = build_sink(args)
    collector = Collector(sink, args.profile)

    proxy.serve(
        listen_ip=args.listen,
        listen_port=args.proxy_port,
        upstream_host=args.upstream_host,
        upstream_port=args.upstream_port,
        on_frame=collector.on_frame,
        resolver=args.resolver,
    )

    arp = None
    if not args.no_dns:
        try:
            dns_redirect.serve(args.listen, advertise, args.resolver, args.dns_port)
        except PermissionError:
            log.error("port %s needs root -- rerun with sudo, or use --no-dns", args.dns_port)
            sys.exit(1)

    # Stick-only mode: pull just the stick's traffic to us via ARP and redirect
    # its DNS + uplink, leaving the rest of the LAN's DNS untouched.
    if args.arp_redirect:
        arp = arp_redirect.ArpRedirect(
            target_ip=args.arp_redirect,
            listen_ip=advertise,
            proxy_port=args.proxy_port,
        )
        try:
            arp.start()
        except Exception as exc:
            log.error("ARP redirect failed (%s) -- fall back to LAN-wide DNS", exc)
            sys.exit(1)

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    log.info("waiting for the stick to connect (point the router's DNS at %s)", advertise)

    last_report = 0.0
    while not stop.is_set():
        stop.wait(args.flush_interval)
        sent = sink.flush()
        now = time.time()
        if sent or now - last_report > 300:
            log.info(
                "frames=%d readings=%d uploaded=%d queued=%d",
                collector.frames_seen,
                collector.readings_written,
                sent,
                sink.pending(),
            )
            last_report = now

    log.info("shutting down, final flush...")
    if arp is not None:
        arp.stop()
    sink.flush()
    sink.close()


if __name__ == "__main__":
    main()
