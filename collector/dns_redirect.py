"""
Minimal DNS responder used to steer the logger stick's cloud uplink at us.

The stick has no configurable server address, so the only way to see its traffic
is to answer the DNS query it makes for the Solarman collection host. This is a
forwarding resolver: every query is logged (which is how we learn the exact
hostname a given stick firmware uses), queries matching REDIRECT_SUFFIXES are
answered with our own address, and everything else is passed through to the
upstream resolver untouched.

It only serves the clients it is told to: the stick's own address, or at most
the stick's /24 (for whole-LAN DNS mode). Queries from anywhere else are
dropped without a reply, so this is never an open resolver/relay. At most
MAX_INFLIGHT queries are handled at once; the rest are dropped.

Run it, point the stick's DNS at this machine, and watch the log.
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import socket
import socketserver
import struct
import threading
from typing import Optional, Union

import privileges
from logsafe import Throttle, clean

log = logging.getLogger("dns")

# Hostnames the Solarman/IGEN sticks are known to phone home to. Matching is by
# suffix so regional shards (cn-, eu-, sg- prefixes) are covered too.
REDIRECT_SUFFIXES = (
    "talent-monitoring.com",
    "solarmanpv.com",
    "solarman.cn",
    "igen-tech.com",
)

TYPE_A = 1
CLASS_IN = 1
MAX_INFLIGHT = 8

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def parse_question(data: bytes) -> tuple[Optional[str], Optional[int]]:
    """Pull the QNAME and QTYPE out of a DNS query. Returns (None, None) if malformed."""
    try:
        labels = []
        offset = 12  # skip the 12-byte header
        while True:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            # Compression pointers never appear in a question section.
            if length & 0xC0:
                return None, None
            labels.append(data[offset + 1 : offset + 1 + length].decode("ascii", "replace"))
            offset += 1 + length
        if offset + 2 > len(data):
            return None, None
        qtype = int.from_bytes(data[offset : offset + 2], "big")
        return ".".join(labels), qtype
    except (IndexError, UnicodeDecodeError):
        return None, None


def build_a_response(query: bytes, ip: str) -> bytes:
    """Build an A-record answer echoing the original question section."""
    transaction_id = query[:2]
    # QR=1 (response), RD+RA set, rcode 0.
    header = transaction_id + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0)

    # The question section runs from byte 12 to the end of QNAME + QTYPE + QCLASS.
    offset = 12
    while query[offset] != 0:
        offset += query[offset] + 1
    question = query[12 : offset + 5]

    answer = (
        b"\xc0\x0c"  # pointer back to the QNAME at offset 12
        + struct.pack(">HHIH", TYPE_A, CLASS_IN, 60, 4)
        + socket.inet_aton(ip)
    )
    return header + question + answer


def should_redirect(hostname: str) -> bool:
    lowered = hostname.lower()
    return any(lowered.endswith(suffix) for suffix in REDIRECT_SUFFIXES)


class Handler(socketserver.BaseRequestHandler):
    redirect_ip = "127.0.0.1"
    upstream = "1.1.1.1"

    def handle(self) -> None:
        data, sock = self.request
        hostname, qtype = parse_question(data)
        client = self.client_address[0]
        # Everything logged below that came from the packet goes through clean().
        name = clean(hostname) if hostname else "?"

        if hostname and qtype == TYPE_A and should_redirect(hostname):
            log.warning("REDIRECT %s asked for %s -> %s", client, name, self.redirect_ip)
            sock.sendto(build_a_response(data, self.redirect_ip), self.client_address)
            return

        if hostname:
            log.info("passthru %s asked for %s (type %d)", client, name, qtype)

        # Anything we are not intercepting is forwarded verbatim upstream.
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as up:
                up.settimeout(4)
                up.connect((self.upstream, 53))   # only accept replies from the upstream
                up.send(data)
                reply = up.recv(4096)
            if reply[:2] != data[:2]:
                log.debug("upstream reply id mismatch for %s; dropped", name)
                return
            sock.sendto(reply, self.client_address)
        except OSError as exc:
            log.debug("upstream lookup failed for %s: %s", name, exc)


class Server(socketserver.ThreadingUDPServer):
    """Threaded UDP server that answers only `allowed` clients, with an in-flight cap."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler_class, *, allowed: Network,
                 max_inflight: int = MAX_INFLIGHT, bind_and_activate: bool = True) -> None:
        self.allowed = allowed
        self._slots = threading.BoundedSemaphore(max_inflight)
        self._reject_log = Throttle(1, 60.0)
        self._full_log = Throttle(1, 60.0)
        super().__init__(server_address, handler_class, bind_and_activate)

    def verify_request(self, request, client_address) -> bool:
        try:
            ok = ipaddress.ip_address(client_address[0]) in self.allowed
        except ValueError:
            ok = False
        if not ok and self._reject_log.allow():
            log.warning("dropped DNS query from %s (allowed: %s); further drops this minute not logged",
                        clean(client_address[0]), self.allowed)
        return ok

    def process_request(self, request, client_address) -> None:
        if not self._slots.acquire(blocking=False):
            if self._full_log.allow():
                log.warning("DNS busy; dropping queries (first from %s)", clean(client_address[0]))
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def allowed_network(stick_ip: str, allow_subnet: bool = False) -> Network:
    """The stick alone, or (allow_subnet) the stick's /24 -- never wider."""
    prefix = 24 if allow_subnet else 32
    return ipaddress.ip_network(f"{ipaddress.IPv4Address(stick_ip)}/{prefix}", strict=False)


def bind(listen_ip: str, port: int, allowed: Network) -> Server:
    """Bind the DNS socket (port 53 on a specific IP needs root on macOS); serves nothing yet."""
    return Server((listen_ip, port), Handler, allowed=allowed)


def start(server: Server, redirect_ip: str, upstream: str) -> None:
    Handler.redirect_ip = redirect_ip
    Handler.upstream = upstream
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address[:2]
    log.info("DNS listening on %s:%s for %s, redirecting Solarman hosts to %s",
             host, port, server.allowed, redirect_ip)


def main() -> None:
    parser = argparse.ArgumentParser(description="Forwarding DNS with Solarman host redirect")
    parser.add_argument("--listen", required=True, help="this machine's LAN IP to bind (not 0.0.0.0)")
    parser.add_argument("--port", type=int, default=53)
    parser.add_argument("--stick-ip", required=True, help="the only client answered")
    parser.add_argument("--dns-allow-subnet", action="store_true",
                        help="also answer the rest of the stick's /24 (whole-LAN DNS mode)")
    parser.add_argument("--redirect-to", required=True, help="IP running the V5 proxy")
    parser.add_argument("--upstream", default="1.1.1.1")
    args = parser.parse_args()

    if ipaddress.ip_address(args.listen).is_unspecified:
        parser.error("--listen must be a specific address, not all interfaces")

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    ids = privileges.sudo_ids()          # refuses root without SUDO_UID
    server = bind(args.listen, args.port, allowed_network(args.stick_ip, args.dns_allow_subnet))
    privileges.drop(ids)                 # before the first query is read
    start(server, args.redirect_to, args.upstream)
    threading.Event().wait()


if __name__ == "__main__":
    main()
