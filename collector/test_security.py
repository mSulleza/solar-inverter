"""
Security behaviour of the collector: only the stick is served, oversize frames
are refused, network-supplied text is sanitised before logging, floods are
capped, the upstream lookup can't be spoofed or pointed back at us, root is
dropped, and ARP mode puts the machine back the way it found it.
"""

import logging
import os
import socket
import struct
import tempfile
import threading
import time
from pathlib import Path

import pytest

import arp_redirect
import dns_redirect
import privileges
import proxy
import run
from logsafe import Throttle, clean
from sink import Sink
from solarman_v5 import CONTROL_DATA, CONTROL_HEARTBEAT, MAX_PAYLOAD_LEN, START_BYTE, V5Stream, parse_frame
from test_solarman_v5 import build_data_payload, build_v5

NOT_THE_STICK = "10.255.255.1"   # nothing on this machine connects from here


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def dns_query(name: str, txid: bytes = b"\x12\x34", qtype: int = 1) -> bytes:
    q = txid + struct.pack(">HHHHH", 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        raw = label.encode("latin-1")
        q += bytes([len(raw)]) + raw
    return q + b"\x00" + struct.pack(">HH", qtype, 1)


# ---------------------------------------------------------------- stick only

class CountingUpstream(threading.Thread):
    """Accepts connections and counts them; stands in for the Solarman server."""

    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.accepted = 0
        self.conns = []

    def run(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.accepted += 1
            self.conns.append(conn)


def closed_by_peer(sock: socket.socket) -> bool:
    try:
        return sock.recv(16) == b""
    except ConnectionResetError:
        return True
    except socket.timeout:
        return False


def test_proxy_closes_connections_from_non_stick_source(monkeypatch):
    upstream = CountingUpstream()
    upstream.start()
    monkeypatch.setattr(proxy.ProxyHandler, "upstream_addr", ("127.0.0.1", upstream.port))

    server = proxy.ProxyServer(("127.0.0.1", 0), proxy.ProxyHandler, stick_ip=NOT_THE_STICK)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        assert server.verify_request(None, (NOT_THE_STICK, 1234))
        assert not server.verify_request(None, ("10.255.255.2", 1234))

        intruder = socket.create_connection(server.server_address, timeout=3)
        assert closed_by_peer(intruder), "non-stick connection was kept open"
        intruder.close()
        time.sleep(0.2)
        assert upstream.accepted == 0, "non-stick connection reached the upstream"
    finally:
        server.shutdown()
        server.server_close()
        upstream.sock.close()


def test_proxy_caps_concurrent_connections(monkeypatch):
    upstream = CountingUpstream()
    upstream.start()
    monkeypatch.setattr(proxy.ProxyHandler, "upstream_addr", ("127.0.0.1", upstream.port))

    server = proxy.ProxyServer(("127.0.0.1", 0), proxy.ProxyHandler, stick_ip="127.0.0.1",
                               max_connections=1)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        first = socket.create_connection(server.server_address, timeout=3)
        deadline = time.time() + 3
        while upstream.accepted < 1 and time.time() < deadline:
            time.sleep(0.05)
        assert upstream.accepted == 1

        second = socket.create_connection(server.server_address, timeout=3)
        assert closed_by_peer(second), "connection over the cap was kept open"
        assert upstream.accepted == 1
        first.close()
        second.close()
    finally:
        server.shutdown()
        server.server_close()
        upstream.sock.close()


def test_dns_answers_only_the_stick():
    assert str(dns_redirect.allowed_network("192.168.7.50")) == "192.168.7.50/32"
    assert str(dns_redirect.allowed_network("192.168.7.50", allow_subnet=True)) == "192.168.7.0/24"

    query = dns_query("iot.talent-monitoring.com")

    # Not in the allowed set: no answer at all (not an open resolver).
    outsider = dns_redirect.bind("127.0.0.1", 0, dns_redirect.allowed_network(NOT_THE_STICK))
    dns_redirect.start(outsider, "10.0.0.5", "127.0.0.1")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as c:
        c.settimeout(0.5)
        c.sendto(query, outsider.server_address)
        with pytest.raises(socket.timeout):
            c.recvfrom(512)
    outsider.shutdown()
    outsider.server_close()

    # The stick itself gets the redirect.
    stick = dns_redirect.bind("127.0.0.1", 0, dns_redirect.allowed_network("127.0.0.1"))
    dns_redirect.start(stick, "10.0.0.5", "127.0.0.1")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as c:
        c.settimeout(2)
        c.sendto(query, stick.server_address)
        reply, _ = c.recvfrom(512)
    stick.shutdown()
    stick.server_close()
    assert reply[:2] == query[:2]
    assert socket.inet_ntoa(reply[-4:]) == "10.0.0.5"


# ---------------------------------------------------------------- frame limits

def test_oversize_payload_len_rejected_and_stream_resyncs():
    good = build_v5(CONTROL_DATA, 42, build_data_payload([7, 8]))
    # Header claims a payload far beyond any real frame.
    bogus = bytes([START_BYTE]) + struct.pack("<HHHI", MAX_PAYLOAD_LEN + 1, CONTROL_DATA, 1, 42) + b"\x00" * 8

    stream = V5Stream()
    frames = stream.feed(bogus + good)
    assert [f.modbus.registers for f in frames] == [[7, 8]]

    # On its own the bogus header is discarded at once rather than buffered.
    stream = V5Stream()
    assert stream.feed(bogus) == []
    assert len(stream._buffer) < 13

    oversize = bytes([START_BYTE]) + struct.pack("<HHHI", 0xFFFF, CONTROL_DATA, 1, 42) + b"\x00\x15"
    assert parse_frame(oversize) is None


def test_collector_drops_frames_beyond_rate():
    sink = Sink(Path(tempfile.mkdtemp()) / "spool.db", None)
    collector = run.Collector(sink, "powmr_hybrid", max_frames_per_minute=3)
    heartbeat = parse_frame(build_v5(CONTROL_HEARTBEAT, 42, b"\x00"))
    for _ in range(5):
        collector.on_frame(heartbeat)
    assert collector.frames_seen == 3
    assert collector.frames_dropped == 2
    assert sink.pending() == 3
    sink.close()


def test_sink_refuses_rows_beyond_cap():
    sink = Sink(Path(tempfile.mkdtemp()) / "spool.db", None, max_pending=2)
    assert sink.write("raw_frames", {"logger_serial": 1})
    assert sink.write("raw_frames", {"logger_serial": 2})
    assert not sink.write("raw_frames", {"logger_serial": 3})
    assert sink.pending() == 2
    assert sink.rows_dropped == 1
    sink.close()


def test_throttle_window():
    now = [0.0]
    t = Throttle(2, 60.0, clock=lambda: now[0])
    assert [t.allow(), t.allow(), t.allow()] == [True, True, False]
    assert t.suppressed == 1
    now[0] = 61.0
    assert t.allow()


# ---------------------------------------------------------------- log sanitising

def test_clean_strips_and_caps():
    assert clean("iot.talent-monitoring.com") == "iot.talent-monitoring.com"
    dirty = clean("evil\n2026-01-01 INFO forged\x1b[31m")
    assert "\n" not in dirty and "\x1b" not in dirty and " " not in dirty
    assert set(dirty) <= set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-?")
    assert len(clean("a" * 500)) == 64 + len("...")


class FakeUdpSock:
    def __init__(self) -> None:
        self.sent = []

    def sendto(self, data, addr) -> None:
        self.sent.append((data, addr))


def test_dns_handler_logs_sanitised_names(caplog):
    caplog.set_level(logging.DEBUG, logger="dns")
    server = type("S", (), {})()

    # Redirected name with a log-forging label.
    sock = FakeUdpSock()
    dns_redirect.Handler.redirect_ip = "10.0.0.5"
    dns_redirect.Handler((dns_query("x\nCRITICAL forged.talent-monitoring.com"), sock), ("127.0.0.1", 5353), server)
    assert sock.sent, "redirect answer not sent"

    # Pass-through name; upstream on localhost:53 is (almost certainly) closed,
    # which exercises the failure log line too.
    dns_redirect.Handler.upstream = "127.0.0.1"
    dns_redirect.Handler((dns_query("y\r\nWARNING\x1b[2Jbad.example.org"), FakeUdpSock()), ("127.0.0.1", 5353), server)

    messages = [r.getMessage() for r in caplog.records]
    assert any("forged" in m for m in messages)
    for m in messages:
        assert "\n" not in m and "\r" not in m and "\x1b" not in m, m


# ---------------------------------------------------------------- upstream lookup

class FakeResolver(threading.Thread):
    """Answers one query: optionally a wrong-id reply first, then the real one."""

    def __init__(self, answer_ip: str, wrong_id_first: bool = False, qname_override=None) -> None:
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.answer_ip = answer_ip
        self.wrong_id_first = wrong_id_first
        self.qname_override = qname_override
        self.txids = []

    def reply(self, txid: bytes, question: bytes, ip: str) -> bytes:
        header = txid + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0)
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
        return header + question + answer

    def run(self) -> None:
        self.sock.settimeout(5)
        try:
            query, addr = self.sock.recvfrom(512)
        except OSError:
            return
        txid, question = query[:2], query[12:]
        self.txids.append(txid)
        if self.qname_override:
            question = dns_query(self.qname_override)[12:]
        if self.wrong_id_first:
            bad = bytes([txid[0] ^ 0xFF, txid[1]])
            self.sock.sendto(self.reply(bad, question, "6.6.6.6"), addr)
        self.sock.sendto(self.reply(txid, question, self.answer_ip), addr)


def test_resolve_via_ignores_wrong_transaction_id():
    r = FakeResolver("203.0.113.7", wrong_id_first=True)
    r.start()
    assert proxy.resolve_via("iot.example.com", "127.0.0.1", timeout=3, port=r.port) == "203.0.113.7"


def test_resolve_via_rejects_answer_for_another_name():
    r = FakeResolver("203.0.113.7", qname_override="evil.example.net")
    r.start()
    assert proxy.resolve_via("iot.example.com", "127.0.0.1", timeout=3, port=r.port) is None


def test_resolve_via_uses_random_transaction_ids():
    seen = set()
    for _ in range(4):
        r = FakeResolver("203.0.113.7")
        r.start()
        proxy.resolve_via("iot.example.com", "127.0.0.1", timeout=3, port=r.port)
        seen.update(r.txids)
    assert len(seen) > 1


def test_upstream_refuses_own_address_and_failed_lookup(monkeypatch):
    assert proxy.own_address("127.0.0.1")
    assert proxy.own_address("0.0.0.0")
    assert not proxy.own_address("192.0.2.1")      # TEST-NET-1, never local
    with pytest.raises(RuntimeError):
        proxy.resolve_upstream("127.0.0.1", "1.1.1.1")

    monkeypatch.setattr(proxy, "resolve_via", lambda *a, **k: None)
    with pytest.raises(RuntimeError):
        proxy.resolve_upstream("iot.talent-monitoring.com", "1.1.1.1")

    monkeypatch.setattr(proxy, "resolve_via", lambda *a, **k: "127.0.0.1")
    with pytest.raises(RuntimeError):
        proxy.resolve_upstream("iot.talent-monitoring.com", "1.1.1.1")


# ---------------------------------------------------------------- privileges + binding

def test_root_requires_sudo_uid():
    with pytest.raises(SystemExit):
        privileges.sudo_ids(euid=0, env={})
    with pytest.raises(SystemExit):
        privileges.sudo_ids(euid=0, env={"SUDO_UID": "0", "SUDO_GID": "0"})
    assert privileges.sudo_ids(euid=0, env={"SUDO_UID": "501", "SUDO_GID": "20"}) == (501, 20)
    assert privileges.sudo_ids(euid=501, env={}) is None
    privileges.drop(None)       # not root: nothing to do


def test_never_binds_all_interfaces():
    parser, args = run.parse_args(["--stick-ip", "127.0.0.1"])
    assert run.addresses(parser, args) == ("127.0.0.1", "127.0.0.1", "127.0.0.1")

    parser, args = run.parse_args(["--stick-ip", "127.0.0.1", "--listen", "0.0.0.0"])
    with pytest.raises(SystemExit):
        run.addresses(parser, args)

    parser, args = run.parse_args([])
    with pytest.raises(SystemExit):
        run.addresses(parser, args)          # --stick-ip is required

    parser, args = run.parse_args(["--arp-redirect", "127.0.0.1"])
    assert run.addresses(parser, args)[0] == "127.0.0.1"


def test_env_file_reads_only_dsn_keys(tmp_path):
    env = tmp_path / ".env"
    env.write_text('export DATABASE_URL="postgres://u:p@h/db"\nOTHER=1\n# c\nPOSTGRES_URL=\'x\'\n')
    env.chmod(0o600)
    assert run.read_env_file(str(env)) == {"DATABASE_URL": "postgres://u:p@h/db", "POSTGRES_URL": "x"}


# ---------------------------------------------------------------- ARP cleanup

class FakeRun:
    def __init__(self, forwarding: str, pf_status: str, fail_on=None) -> None:
        self.forwarding = forwarding
        self.pf_status = pf_status
        self.fail_on = fail_on
        self.calls = []

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        if self.fail_on and cmd[: len(self.fail_on)] == self.fail_on:
            raise OSError("boom")
        out, err = "", ""
        if cmd[:2] == ["sysctl", "-n"]:
            out = self.forwarding + "\n"
        elif cmd[:3] == ["pfctl", "-s", "info"]:
            out = f"Status: {self.pf_status} for 0 days\n"
        elif cmd == ["pfctl", "-E"]:
            err = "pf enabled\nToken : 98765\n"
        return type("P", (), {"returncode": 0, "stdout": out, "stderr": err})()


def started(fake: FakeRun) -> arp_redirect.ArpRedirect:
    r = arp_redirect.ArpRedirect("10.0.0.50", "10.0.0.10", gateway_ip="10.0.0.1")
    r._owner_pid = os.getpid()
    r._enable_forwarding()
    r._install_pf()
    return r


def test_arp_stop_restores_previous_forwarding_and_pf(monkeypatch):
    fake = FakeRun(forwarding="0", pf_status="Disabled")
    monkeypatch.setattr(arp_redirect, "_run", fake)
    r = started(fake)
    assert ["sysctl", "-w", "net.inet.ip.forwarding=1"] in fake.calls

    r.stop()
    assert ["pfctl", "-a", "solar_collector", "-F", "all"] in fake.calls
    assert ["pfctl", "-X", "98765"] in fake.calls                  # release only our pf reference
    assert fake.calls[-1] == ["sysctl", "-w", "net.inet.ip.forwarding=0"]

    n = len(fake.calls)
    r.stop()                                                        # idempotent (atexit runs it again)
    assert len(fake.calls) == n


def test_arp_stop_leaves_forwarding_on_if_it_was_on(monkeypatch):
    fake = FakeRun(forwarding="1", pf_status="Enabled")
    monkeypatch.setattr(arp_redirect, "_run", fake)
    r = started(fake)
    r.stop()
    assert not any(c[:2] == ["sysctl", "-w"] for c in fake.calls)


def test_arp_stop_restores_forwarding_even_if_pf_flush_fails(monkeypatch):
    fake = FakeRun(forwarding="0", pf_status="Disabled", fail_on=["pfctl", "-a", "solar_collector", "-F"])
    monkeypatch.setattr(arp_redirect, "_run", fake)
    r = started(fake)
    with pytest.raises(OSError):
        r.stop()
    assert ["pfctl", "-X", "98765"] in fake.calls
    assert ["sysctl", "-w", "net.inet.ip.forwarding=0"] in fake.calls


def test_arp_stop_is_a_no_op_in_a_forked_child(monkeypatch):
    fake = FakeRun(forwarding="0", pf_status="Disabled")
    monkeypatch.setattr(arp_redirect, "_run", fake)
    r = started(fake)
    r._owner_pid = os.getpid() + 1          # as seen from the unprivileged child
    n = len(fake.calls)
    r.stop()
    assert len(fake.calls) == n


def test_arp_supervisor_cleans_up_when_child_exits():
    import signal
    import subprocess
    import sys

    class FakeArp:
        poison_interval = 0.05
        poisoned = 0
        stopped = False

        def poison_once(self):
            self.poisoned += 1

        def stop(self):
            self.stopped = True

    arp = FakeArp()
    saved = signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM)
    child = subprocess.Popen([sys.executable, "-c", "import sys, time; time.sleep(0.3); sys.exit(3)"])
    try:
        assert run.supervise_arp(arp, child.pid) == 3
    finally:
        signal.signal(signal.SIGINT, saved[0])
        signal.signal(signal.SIGTERM, saved[1])
    assert arp.poisoned >= 1
    assert arp.stopped, "pf/forwarding cleanup did not run after the child exited"
