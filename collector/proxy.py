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

Only the stick is served: connections from any other address are closed before
a thread is spent on them, and at most MAX_CONNECTIONS relays run at once.

The upstream address is resolved through an explicit resolver rather than the
system one, because the system resolver may be pointed at our own redirecting
DNS server, which would send us back to ourselves. If that lookup fails the
collector stops rather than falling back to the system resolver.
"""

from __future__ import annotations

import ipaddress
import logging
import secrets
import socket
import socketserver
import struct
import threading
import time
from typing import Callable, Optional

from logsafe import Throttle, clean
from solarman_v5 import V5Frame, V5Stream

log = logging.getLogger("proxy")

DEFAULT_UPSTREAM_HOST = "iot.talent-monitoring.com"
DEFAULT_UPSTREAM_PORT = 10000
# The stick holds one connection (two briefly while it reconnects).
MAX_CONNECTIONS = 8

FrameCallback = Callable[[V5Frame], None]


def _encode_qname(hostname: str) -> bytes:
    out = b""
    for label in hostname.rstrip(".").split("."):
        raw = label.encode("ascii")
        if not 0 < len(raw) < 64:
            raise ValueError(f"bad hostname {hostname!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _read_name(msg: bytes, offset: int) -> tuple[str, int]:
    """Read a (possibly compressed) DNS name; return it and the offset after it."""
    labels: list[str] = []
    end: Optional[int] = None
    for _ in range(128):                      # bound pointer chains
        length = msg[offset]
        if length & 0xC0 == 0xC0:             # compression pointer
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | msg[offset + 1]
            continue
        if length == 0:
            return ".".join(labels), (end if end is not None else offset + 1)
        labels.append(msg[offset + 1 : offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    raise ValueError("DNS name too long or looping")


def _first_a_record(reply: bytes, hostname: str) -> Optional[str]:
    """First A record in a reply whose question matches hostname, else None."""
    try:
        flags = int.from_bytes(reply[2:4], "big")
        if not flags & 0x8000 or flags & 0x000F:      # not a response, or rcode != 0
            return None
        qdcount = int.from_bytes(reply[4:6], "big")
        ancount = int.from_bytes(reply[6:8], "big")
        if qdcount != 1:
            return None
        qname, offset = _read_name(reply, 12)
        if qname.lower().rstrip(".") != hostname.lower().rstrip("."):
            return None
        offset += 4                                   # QTYPE + QCLASS
        for _ in range(ancount):
            _name, offset = _read_name(reply, offset)
            rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", reply[offset : offset + 10])
            offset += 10
            if rtype == 1 and rdlength == 4:
                return socket.inet_ntoa(reply[offset : offset + 4])
            offset += rdlength
    except (IndexError, ValueError, struct.error):
        return None
    return None


def resolve_via(hostname: str, resolver: str = "1.1.1.1", timeout: float = 5.0,
                port: int = 53) -> Optional[str]:
    """
    Resolve an A record by querying `resolver` directly over UDP.

    Deliberately bypasses the system resolver: while the redirect is active the
    system resolver answers Solarman hostnames with our own address, and using
    it here would make the proxy connect to itself in a loop.

    Uses a random transaction id and a connected socket (the kernel drops
    datagrams from any other source), and ignores replies whose id or question
    don't match, so an off-path spoofer has to guess 16 bits plus our port.
    """
    txid = secrets.token_bytes(2)
    query = txid + struct.pack(">HHHHH", 0x0100, 1, 0, 0, 0) + _encode_qname(hostname) + struct.pack(">HH", 1, 1)
    deadline = time.monotonic() + timeout

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((resolver, port))
            sock.send(query)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise socket.timeout("no matching reply")
                sock.settimeout(remaining)
                reply = sock.recv(4096)
                if len(reply) < 12 or reply[:2] != txid:
                    log.warning("ignoring DNS reply with the wrong transaction id from %s", resolver)
                    continue
                return _first_a_record(reply, hostname)
    except OSError as exc:
        log.error("could not resolve %s via %s: %s", hostname, resolver, exc)
        return None


def own_address(ip: str) -> bool:
    """True if ip is loopback/unspecified or assigned to an interface on this machine."""
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback or addr.is_unspecified:
        return True
    family = socket.AF_INET6 if addr.version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        try:
            sock.bind((ip, 0))     # only succeeds for a local address
        except OSError:
            return False
    return True


def resolve_upstream(upstream_host: str, resolver: str) -> str:
    """Resolve the real Solarman server, refusing anything that points back at us."""
    try:
        ipaddress.ip_address(upstream_host)
        upstream_ip: Optional[str] = upstream_host
    except ValueError:
        upstream_ip = resolve_via(upstream_host, resolver)
    if not upstream_ip:
        raise RuntimeError(f"could not resolve upstream {upstream_host} via {resolver}")
    if own_address(upstream_ip):
        raise RuntimeError(
            f"upstream {upstream_host} resolved to {upstream_ip}, an address of this "
            "machine -- refusing to proxy to ourselves"
        )
    return upstream_ip


class ProxyHandler(socketserver.BaseRequestHandler):
    upstream_addr: Optional[tuple[str, int]] = None
    on_frame: Optional[FrameCallback] = None

    def handle(self) -> None:
        client = self.request
        peer = self.client_address[0]
        log.info("stick connected from %s", peer)

        if self.upstream_addr is None:
            log.error("no upstream configured; dropping stick connection")
            return

        try:
            upstream = socket.create_connection(self.upstream_addr, timeout=15)
        except OSError as exc:
            # Without an upstream we would be silently eating the stick's data,
            # so refuse the connection and let it retry rather than black-hole it.
            log.error("upstream %s unreachable (%s); dropping stick connection", self.upstream_addr, exc)
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
    """Threaded TCP server that serves only `stick_ip`, with a connection cap."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler_class, *, stick_ip: str,
                 max_connections: int = MAX_CONNECTIONS, bind_and_activate: bool = True) -> None:
        self.stick_ip = str(ipaddress.ip_address(stick_ip))
        self._slots = threading.BoundedSemaphore(max_connections)
        self._reject_log = Throttle(1, 60.0)
        self._full_log = Throttle(1, 60.0)
        super().__init__(server_address, handler_class, bind_and_activate)

    def verify_request(self, request, client_address) -> bool:
        if client_address[0] == self.stick_ip:
            return True
        if self._reject_log.allow():
            log.warning("closed connection from %s: not the stick (%s); further rejections this minute not logged",
                        clean(client_address[0]), self.stick_ip)
        return False

    def process_request(self, request, client_address) -> None:
        if not self._slots.acquire(blocking=False):
            if self._full_log.allow():
                log.warning("connection limit reached; closing new connection from %s", clean(client_address[0]))
            self.shutdown_request(request)
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


def bind(listen_ip: str, listen_port: int, stick_ip: str) -> ProxyServer:
    """Bind the listening socket (may need root for a low port); serves nothing yet."""
    return ProxyServer((listen_ip, listen_port), ProxyHandler, stick_ip=stick_ip)


def start(
    server: ProxyServer,
    upstream_host: str,
    upstream_port: int,
    on_frame: FrameCallback,
    resolver: str = "1.1.1.1",
) -> None:
    """Resolve the upstream and start serving. Raises RuntimeError if it can't resolve."""
    upstream_ip = resolve_upstream(upstream_host, resolver)
    log.info("upstream %s resolved to %s", upstream_host, upstream_ip)

    ProxyHandler.upstream_addr = (upstream_ip, upstream_port)
    ProxyHandler.on_frame = staticmethod(on_frame)

    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address[:2]
    log.info("V5 proxy listening on %s:%s, serving only %s", host, port, server.stick_ip)
