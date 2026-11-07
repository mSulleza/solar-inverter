"""
Minimal DNS responder used to steer the logger stick's cloud uplink at us.

The stick has no configurable server address, so the only way to see its traffic
is to answer the DNS query it makes for the Solarman collection host. This is a
forwarding resolver: every query is logged (which is how we learn the exact
hostname a given stick firmware uses), queries matching REDIRECT_SUFFIXES are
answered with our own address, and everything else is passed through to the
upstream resolver untouched so the rest of the network is unaffected.

Run it, point the router's DHCP DNS at this machine, and watch the log.
"""

from __future__ import annotations

import argparse
import logging
import socket
import socketserver
import struct
import threading
from typing import Optional

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

        if hostname and qtype == TYPE_A and should_redirect(hostname):
            log.warning("REDIRECT %s asked for %s -> %s", client, hostname, self.redirect_ip)
            sock.sendto(build_a_response(data, self.redirect_ip), self.client_address)
            return

        if hostname:
            log.info("passthru %s asked for %s (type %s)", client, hostname, qtype)

        # Anything we are not intercepting is forwarded verbatim upstream so the
        # rest of the LAN keeps working normally while this is running.
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as up:
                up.settimeout(4)
                up.sendto(data, (self.upstream, 53))
                reply, _ = up.recvfrom(4096)
            sock.sendto(reply, self.client_address)
        except OSError as exc:
            log.debug("upstream lookup failed for %s: %s", hostname, exc)


class Server(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(listen_ip: str, redirect_ip: str, upstream: str, port: int = 53) -> Server:
    Handler.redirect_ip = redirect_ip
    Handler.upstream = upstream
    server = Server((listen_ip, port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log.info("DNS listening on %s:%s, redirecting Solarman hosts to %s", listen_ip, port, redirect_ip)
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="Forwarding DNS with Solarman host redirect")
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=53)
    parser.add_argument("--redirect-to", required=True, help="IP running the V5 proxy")
    parser.add_argument("--upstream", default="1.1.1.1")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    serve(args.listen, args.redirect_to, args.upstream, args.port)
    threading.Event().wait()


if __name__ == "__main__":
    main()
