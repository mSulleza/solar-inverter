"""
Collector entrypoint: intercept the stick's uplink, decode it, ship it.

Wires together the three pieces:

  1. a forwarding DNS server that answers the stick's lookup for the Solarman
     collection host with this machine's address (everything else passes through)
  2. a TCP proxy on port 10000 that relays the stick to the real Solarman server
     and decodes the V5 frames going past
  3. a sink that spools decoded readings locally and pushes them to Neon

The Solarman app keeps working throughout -- this observes the uplink, it does
not replace it.

Only the stick is served (--stick-ip, or the --arp-redirect target): the proxy
closes connections from anything else and the DNS server drops their queries
(--dns-allow-subnet widens DNS to the stick's /24 for whole-LAN DNS mode).
Listeners bind one address -- --listen, or by default this machine's address on
the interface that routes to the stick -- never all interfaces.

Privileges: on macOS, binding DNS port 53 on a specific address needs root, and
ARP mode needs root for sysctl, pfctl and raw ARP. Started with sudo, the
collector binds its sockets and sets up pf as root, then drops to the user who
ran sudo (SUDO_UID/SUDO_GID) before reading any network input. In ARP mode a
small root parent stays behind only to send the stick's ARP replies and to
restore pf and IP forwarding on exit; all traffic is handled by the unprivileged
child. Without DNS (--no-dns) no root is needed at all.
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import signal
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Optional

import arp_redirect
import dns_redirect
import privileges
import proxy
from logsafe import Throttle
from registers import PROFILES, derive
from sink import Sink, NeonConfig
from solarman_v5 import CONTROL_DATA, V5Frame

log = logging.getLogger("collector")

# The stick sends a data frame every minute or few plus the odd heartbeat;
# anything far beyond that is a flood and is not spooled.
MAX_FRAMES_PER_MINUTE = 60

# Prefer the direct (unpooled) connection: the collector holds one
# long-lived connection and reconnects per flush, so the pooler buys nothing
# and the direct endpoint is simpler.
DSN_KEYS = ("DATABASE_URL_UNPOOLED", "POSTGRES_URL_NON_POOLING", "DATABASE_URL", "POSTGRES_URL")


def route_ip_to(ip: str) -> str:
    """This machine's address on the interface that routes to ip (no packet is sent)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((ip, 9))
        return sock.getsockname()[0]


class Collector:
    def __init__(self, sink: Sink, profile_name: str, store_raw: bool = True,
                 max_frames_per_minute: int = MAX_FRAMES_PER_MINUTE) -> None:
        self.sink = sink
        self.profile = PROFILES[profile_name]
        self.store_raw = store_raw
        self.frames_seen = 0
        self.frames_dropped = 0
        self.readings_written = 0
        self._budget = Throttle(max_frames_per_minute, 60.0)
        self._flood_log = Throttle(1, 60.0)

    def on_frame(self, frame: V5Frame) -> None:
        if not self._budget.allow():
            self.frames_dropped += 1
            if self._flood_log.allow():
                log.warning("more than %d frames in a minute -- dropping the excess "
                            "(logged once a minute)", self._budget.limit)
            return
        self.frames_seen += 1

        if self.store_raw:
            self.sink.write("raw_frames", self._raw_row(frame))

        # Only data frames carry registers; hello and heartbeat frames are stick
        # housekeeping and have nothing to decode.
        if frame.control != CONTROL_DATA or frame.modbus is None:
            log.info("frame %s from logger %d", frame.control_name, frame.logger_serial)
            return

        modbus = frame.modbus
        if modbus.exception is not None:
            log.warning("inverter returned Modbus exception %d", modbus.exception)
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



def read_env_file(path: str) -> dict[str, str]:
    """
    Read the Postgres connection string from a dotenv file (as `vercel env pull`
    writes it). Only the DSN keys are taken. Used instead of `sudo -E`, which
    would hand the whole user environment to a root process.
    """
    file = Path(path)
    if file.stat().st_mode & 0o077:
        log.warning("%s is readable by other users -- chmod 600 it", path)
    values: dict[str, str] = {}
    for line in file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, sep, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not sep or key not in DSN_KEYS:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        values[key] = value
    return values


def build_sink(args) -> Sink:
    env = dict(os.environ)
    if args.env_file:
        env.update(read_env_file(args.env_file))
    dsn = next((env[k] for k in DSN_KEYS if env.get(k)), None)

    spool = Path(args.spool)
    if spool.exists() and not os.access(spool, os.W_OK):
        # Earlier versions ran as root and left a root-owned spool behind.
        sys.exit(f"{spool} is not writable by this user (left over from a root run?) -- "
                 f"fix with: sudo chown $(id -un) {spool}")

    config = None
    if dsn:
        config = NeonConfig(dsn=dsn)
        log.info("uploading to Neon Postgres")
    else:
        # Not fatal: the spool keeps everything, so a run without a connection
        # string still captures data that can be uploaded once it is set.
        log.warning("no DATABASE_URL (env or --env-file) -- local spool only")

    return Sink(spool, config)


def parse_args(argv: Optional[list[str]] = None) -> tuple[argparse.ArgumentParser, argparse.Namespace]:
    parser = argparse.ArgumentParser(description="Solar inverter collector")
    parser.add_argument("--profile", default="powmr_hybrid", choices=sorted(PROFILES))
    parser.add_argument("--spool", default="collector_spool.db")
    parser.add_argument("--env-file", default=None,
                        help="dotenv file holding DATABASE_URL (read after dropping root)")
    parser.add_argument("--stick-ip", default=None,
                        help="the logger stick's IP; the only client served (required unless --arp-redirect)")
    parser.add_argument("--listen", default=None,
                        help="this machine's LAN IP to bind (default: the address that routes to the stick)")
    parser.add_argument("--proxy-port", type=int, default=10000)
    parser.add_argument("--dns-port", type=int, default=53)
    parser.add_argument("--no-dns", action="store_true", help="skip the DNS redirect")
    parser.add_argument("--dns-allow-subnet", action="store_true",
                        help="answer DNS for the stick's whole /24, not just the stick (whole-LAN DNS mode)")
    parser.add_argument("--arp-redirect", metavar="STICK_IP", default=None,
                        help="intercept ONLY this host via ARP instead of LAN-wide DNS (needs root)")
    parser.add_argument("--upstream-host", default=proxy.DEFAULT_UPSTREAM_HOST)
    parser.add_argument("--upstream-port", type=int, default=proxy.DEFAULT_UPSTREAM_PORT)
    parser.add_argument("--resolver", default="1.1.1.1")
    parser.add_argument("--flush-interval", type=float, default=30.0)
    parser.add_argument("--advertise-ip", default=None,
                        help="override the IP handed out by DNS (default: the --listen address)")
    return parser, parser.parse_args(argv)


def addresses(parser: argparse.ArgumentParser, args: argparse.Namespace) -> tuple[str, str, str]:
    """(stick_ip, listen_ip, advertise_ip), validated."""
    if args.stick_ip and args.arp_redirect and args.stick_ip != args.arp_redirect:
        parser.error("--stick-ip and --arp-redirect name different hosts")
    stick = args.stick_ip or args.arp_redirect
    if not stick:
        parser.error("--stick-ip is required (or --arp-redirect STICK_IP)")
    try:
        stick_addr = ipaddress.IPv4Address(stick)
    except ValueError:
        parser.error(f"--stick-ip {stick!r} is not an IPv4 address")
    if stick_addr.is_unspecified or stick_addr.is_multicast:
        parser.error("--stick-ip must be the stick's own address")

    if args.listen:
        listen = args.listen
    else:
        try:
            listen = route_ip_to(str(stick_addr))
        except OSError as exc:
            parser.error(f"no route to the stick {stick_addr} ({exc}); pass --listen <this machine's LAN IP>")
    try:
        listen_addr = ipaddress.IPv4Address(listen)
    except ValueError:
        parser.error(f"--listen {listen!r} is not an IPv4 address")
    if listen_addr.is_unspecified:
        parser.error("--listen must be this machine's LAN IP; binding all interfaces is not supported")

    return str(stick_addr), str(listen_addr), args.advertise_ip or str(listen_addr)


def supervise_arp(arp: arp_redirect.ArpRedirect, child: int) -> int:
    """
    ARP mode, root parent: keep the stick's ARP cache pointed at us while the
    unprivileged child handles all traffic, then undo pf/forwarding/ARP however
    the child ends. Reads no network input.
    """
    deadline: Optional[float] = None

    def on_signal(_signum, _frame) -> None:
        nonlocal deadline
        if deadline is None:
            deadline = time.monotonic() + 30
        try:
            os.kill(child, signal.SIGTERM)
        except ProcessLookupError:
            pass

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)
    try:
        while True:
            pid, status = os.waitpid(child, os.WNOHANG)
            if pid:
                code = os.waitstatus_to_exitcode(status)
                return code if code >= 0 else 1
            if deadline is None:
                try:
                    arp.poison_once()
                except Exception:
                    log.exception("ARP send failed")
                time.sleep(arp.poison_interval)
            else:
                if time.monotonic() > deadline:
                    log.error("collector did not exit in time; killing it")
                    os.kill(child, signal.SIGKILL)
                time.sleep(0.2)
    finally:
        arp.stop()


def run_collector(args, proxy_server, dns_server, advertise: str,
                  parent_pid: Optional[int] = None) -> None:
    """The unprivileged part: everything that touches network input runs here."""
    sink = build_sink(args)
    collector = Collector(sink, args.profile)

    try:
        proxy.start(proxy_server, args.upstream_host, args.upstream_port,
                    collector.on_frame, args.resolver)
    except (RuntimeError, ValueError) as exc:
        # No fallback to the system resolver: it may be pointed at us.
        log.error("%s -- not starting", exc)
        sys.exit(1)
    if dns_server is not None:
        dns_redirect.start(dns_server, advertise, args.resolver)

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    log.info("waiting for the stick to connect (its DNS answers point at %s)", advertise)

    last_report = 0.0
    while not stop.is_set():
        stop.wait(args.flush_interval)
        if parent_pid is not None and os.getppid() != parent_pid:
            log.error("ARP supervisor exited; stopping")
            break
        sent = sink.flush()
        now = time.time()
        if sent or now - last_report > 300:
            log.info(
                "frames=%d dropped=%d readings=%d uploaded=%d queued=%d",
                collector.frames_seen,
                collector.frames_dropped,
                collector.readings_written,
                sent,
                sink.pending(),
            )
            last_report = now

    log.info("shutting down, final flush...")
    sink.flush()
    sink.close()


def main(argv: Optional[list[str]] = None) -> None:
    parser, args = parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)-8s %(message)s",
    )

    ids = privileges.sudo_ids()       # refuses root without SUDO_UID/SUDO_GID
    stick_ip, listen_ip, advertise = addresses(parser, args)
    if args.arp_redirect and args.no_dns:
        parser.error("--arp-redirect redirects the stick's DNS to us, so it needs the DNS server (drop --no-dns)")
    if args.arp_redirect and os.geteuid() != 0:
        parser.error("--arp-redirect needs root (sysctl, pfctl, raw ARP): run it with sudo")
    log.info("this machine is %s; serving only the stick at %s", listen_ip, stick_ip)

    # 1. Bind while (possibly) root. Nothing is read from these sockets yet.
    try:
        proxy_server = proxy.bind(listen_ip, args.proxy_port, stick_ip)
        dns_server = None
        if not args.no_dns:
            dns_server = dns_redirect.bind(
                listen_ip, args.dns_port,
                dns_redirect.allowed_network(stick_ip, args.dns_allow_subnet),
            )
    except PermissionError:
        log.error("binding %s port %s needs root on macOS -- rerun with sudo (see RUNBOOK), or use --no-dns",
                  listen_ip, args.dns_port)
        sys.exit(1)
    except OSError as exc:
        log.error("could not bind on %s: %s", listen_ip, exc)
        sys.exit(1)

    # 2. Stick-only mode: pull just the stick's traffic to us via ARP and redirect
    # its DNS + uplink, leaving the rest of the LAN's DNS untouched. The root
    # parent keeps the ARP replies going and owns cleanup; the child carries on.
    parent_pid = None
    if args.arp_redirect:
        arp = arp_redirect.ArpRedirect(
            target_ip=stick_ip,
            listen_ip=listen_ip,
            proxy_port=args.proxy_port,
            dns_port=args.dns_port,
        )
        try:
            arp.start(poison_in_thread=False)
        except Exception as exc:
            log.error("ARP redirect failed (%s) -- fall back to LAN-wide DNS", exc)
            sys.exit(1)
        parent_pid = os.getpid()
        child = os.fork()
        if child:
            proxy_server.socket.close()
            if dns_server is not None:
                dns_server.socket.close()
            sys.exit(supervise_arp(arp, child))

    # 3. Drop root for good before the first packet is read.
    privileges.drop(ids)
    run_collector(args, proxy_server, dns_server, advertise, parent_pid)


if __name__ == "__main__":
    main()
