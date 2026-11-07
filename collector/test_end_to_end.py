"""
End-to-end test: fake stick -> proxy -> fake Solarman server, with decoding.

This exercises the arrangement that will run for real, minus the DNS redirect:
that the proxy relays faithfully in both directions (so the user's Solarman app
keeps working), and that frames going past are decoded into spooled readings.
"""

import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import proxy  # noqa: E402
from run import Collector  # noqa: E402
from sink import Sink  # noqa: E402
from test_solarman_v5 import build_data_payload, build_v5  # noqa: E402
from solarman_v5 import CONTROL_DATA  # noqa: E402


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakeSolarman(threading.Thread):
    """Stands in for the real collection server: records bytes, replies with an ack."""

    def __init__(self, port: int) -> None:
        super().__init__(daemon=True)
        self.port = port
        self.received = bytearray()
        self.ready = threading.Event()
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self) -> None:
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.listen(1)
        self.ready.set()
        conn, _ = self._sock.accept()
        conn.settimeout(5)
        with conn:
            conn.sendall(b"SERVER-ACK")
            while True:
                try:
                    chunk = conn.recv(4096)
                except (socket.timeout, OSError):
                    break
                if not chunk:
                    break
                self.received.extend(chunk)


def test_proxy_relays_and_collector_decodes():
    upstream_port = free_port()
    proxy_port = free_port()

    server = FakeSolarman(upstream_port)
    server.start()
    assert server.ready.wait(5)

    spool = Path(tempfile.mkdtemp()) / "spool.db"
    collector = Collector(Sink(spool, None), "powmr_hybrid")

    # Point the proxy straight at the fake server; no resolution needed.
    proxy.ProxyHandler.upstream_addr = ("127.0.0.1", upstream_port)
    proxy.ProxyHandler.on_frame = staticmethod(collector.on_frame)
    # The fake stick connects from 127.0.0.1, so that is the stick's address here.
    server_obj = proxy.ProxyServer(("127.0.0.1", proxy_port), proxy.ProxyHandler, stick_ip="127.0.0.1")
    threading.Thread(target=server_obj.serve_forever, daemon=True).start()
    time.sleep(0.3)

    registers = [2301, 5000, 450, 0, 0, 0, 3200, 85, 272, 0, 0, 0, 0, 0,
                 5210, 120, 625, 78, 2400, 0, 0, 0, 1800, 0, 285, 0, 0, 0, 124, 0, 56]
    frame = build_v5(CONTROL_DATA, 1234567890, build_data_payload(registers))

    stick = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    stick.settimeout(5)

    # The server speaks first; prove the downstream direction reaches the stick.
    assert stick.recv(64) == b"SERVER-ACK"

    # Split the frame to prove reassembly survives a real TCP boundary.
    stick.sendall(frame[:9])
    time.sleep(0.2)
    stick.sendall(frame[9:])
    time.sleep(0.6)

    # The real server must receive the frame byte-for-byte, unmodified.
    assert bytes(server.received) == frame, "proxy altered the uplink"

    assert collector.frames_seen == 1
    assert collector.readings_written == 1

    rows = collector.sink._db.execute(
        "select table_name, body from spool order by id"
    ).fetchall()
    tables = [r[0] for r in rows]
    assert "raw_frames" in tables and "readings" in tables

    import json
    reading = json.loads(next(body for table, body in rows if table == "readings"))
    assert reading["battery_soc"] == 78.0
    assert reading["logger_serial"] == 1234567890
    assert reading["pv_power_total"] == 272.0
    assert reading["registers"] == registers

    stick.close()
    server_obj.shutdown()
    collector.sink.close()
