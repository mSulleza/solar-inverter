"""
Transparent TCP proxy for the logger stick's Solarman uplink.

The stick opens one long-lived TCP connection to the Solarman collection server
on port 10000 and pushes V5 frames up it. With DNS pointed at this machine, the
stick connects here instead; we relay both directions to the real server so the
Solarman app keeps working exactly as before, and decode the stick->server
direction on the way past.

This is deliberately a pass-through rather than a terminator. Nothing is
modified, dropped, or injected -- if the decoder throws on an unexpected frame
the bytes still get forwarded, so a decoding bug can never take the user's
monitoring offline.

The upstream address is resolved through an explicit resolver rather than the
system one, because the system resolver may be pointed at our own redirecting
DNS server, which would send us back to ourselves.
"""

from __future__ import annotations

import logging
import socket
import socketserver
import struct
import threading
from typing import Callable, Optional

from solarman_v5 import V5Frame, V5Stream

log = logging.getLogger("proxy")

DEFAULT_UPSTREAM_HOST = "iot.talent-monitoring.com"
DEFAULT_UPSTREAM_PORT = 10000

FrameCallback = Callable[[V5Frame], None]


def resolve_via(hostname: str, resolver: str = "1.1.1.1", timeout: float = 5.0) -> Optional[str]:
    """
    Resolve an A record by querying `resolver` directly over UDP.

    Deliberately bypasses the system resolver: while the redirect is active the
    system resolver answers Solarman hostnames with our own address, and using
    it here would make the proxy connect to itself in a loop.
    """
    transaction_id = b"\x2a\x2a"
    query = transaction_id + struct.pack(">HHHHH", 0x0100, 1, 0, 0, 0)
    for label in hostname.split("."):
        query += bytes([len(label)]) + label.encode("ascii")
    query += b"\x00" + struct.pack(">HH", 1, 1)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(query, (resolver, 53))
            reply, _ = sock.recvfrom(4096)
    except OSError as exc:
        log.error("could not resolve %s via %s: %s", hostname, resolver, exc)
        return None

    answer_count = int.from_bytes(reply[6:8], "big")
    if answer_count == 0:
        return None

    # Skip the echoed question section, then walk answers for the first A record.
    offset = 12
    while reply[offset] != 0:
        offset += reply[offset] + 1
    offset += 5

    for _ in range(answer_count):
        offset += 2  # name pointer
        rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", reply[offset : offset + 10])
        offset += 10
        if rtype == 1 and rdlength == 4:
            return socket.inet_ntoa(reply[offset : offset + 4])
        offset += rdlength

    return None


class ProxyHandler(socketserver.BaseRequestHandler):
    upstream_addr: tuple[str, int] = (DEFAULT_UPSTREAM_HOST, DEFAULT_UPSTREAM_PORT)
    on_frame: Optional[FrameCallback] = None

    def handle(self) -> None:
        client = self.request
        peer = self.client_address[0]
        log.info("stick connected from %s", peer)

        try:
            upstream = socket.create_connection(self.upstream_addr, timeout=15)
        except OSError as exc:
            # Without an upstream we would be silently eating the stick's data,
            # so refuse the connection and let it retry rather than black-hole it.
            log.error("upstream %s unreachable (%s); dropping stick connection", self.upstream_addr, exc)
            client.close()
            return

        log.info("relaying %s <-> %s", peer, self.upstream_addr)
        stop = threading.Event()

        downstream = threading.Thread(
            target=self._pump, args=(upstream, client, stop, None), daemon=True
        )
        downstream.start()

        stream = V5Stream()
        self._pump(client, upstream, stop, stream)

        stop.set()
        for sock in (client, upstream):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        log.info("stick %s disconnected", peer)

    def _pump(
        self,
        src: socket.socket,
        dst: socket.socket,
        stop: threading.Event,
        stream: Optional[V5Stream],
    ) -> None:
        """Relay src -> dst, decoding along the way when a stream is supplied."""
        src.settimeout(1.0)
        while not stop.is_set():
            try:
                chunk = src.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            if not chunk:
                break

            try:
                dst.sendall(chunk)
            except OSError:
                break

            if stream is None or self.on_frame is None:
                continue

            # Decoding must never break the relay -- the bytes are already
            # forwarded above, so anything thrown here is logged and swallowed.
            try:
                for frame in stream.feed(chunk):
                    self.on_frame(frame)
            except Exception:
                log.exception("frame decode failed; relay continues")

        stop.set()


class ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(
    listen_ip: str,
    listen_port: int,
    upstream_host: str,
    upstream_port: int,
    on_frame: FrameCallback,
    resolver: str = "1.1.1.1",
) -> ProxyServer:
    upstream_ip = resolve_via(upstream_host, resolver) or upstream_host
    log.info("upstream %s resolved to %s", upstream_host, upstream_ip)

    ProxyHandler.upstream_addr = (upstream_ip, upstream_port)
    ProxyHandler.on_frame = staticmethod(on_frame)

    server = ProxyServer((listen_ip, listen_port), ProxyHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log.info("V5 proxy listening on %s:%s", listen_ip, listen_port)
    return server
