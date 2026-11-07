"""
Stick-only interception by ARP, for routers that can't do per-device DNS.

Most consumer routers only let you set one DNS
server for the whole LAN. To capture *only* the logger stick without touching
anyone else's traffic, we take a narrower route: convince the stick, and the
stick alone, that this machine is the router.

How it works:

  1. We send the stick gratuitous ARP replies claiming the router's IP is at our
     MAC. From then on the stick sends all its off-subnet traffic to us. Nobody
     else on the LAN is told anything, so nobody else is affected.
  2. We enable IP forwarding, so the stick's ordinary traffic (NTP, its normal
     internet) flows on through us to the real router and back -- the stick
     stays fully online.
  3. A pf redirect rule bends just two things the stick sends toward "the router"
     back into our own listeners: DNS (:53) and the Solarman uplink (:10000).
     The DNS server answers the Solarman hostname with our address; the proxy
     relays the uplink to the real server and decodes it.

This is deliberately surgical: one host poisoned, two ports redirected,
everything else forwarded untouched. On teardown we re-ARP the stick with the
router's real MAC so it recovers immediately instead of waiting for its cache to
expire.

Requires scapy (`pip install scapy`) and root. macOS uses pf for the redirect;
the rules are added to an anchor we own and flushed on exit. The previous
`net.inet.ip.forwarding` value and pf enable state are recorded at start and put
back by stop(), which runs from try/finally and atexit. If the process is
killed with SIGKILL, undo by hand:

    sudo pfctl -a solar_collector -F all
    sudo sysctl -w net.inet.ip.forwarding=0     # if it was 0 before
"""

from __future__ import annotations

import atexit
import logging
import os
import re
import signal
import subprocess
import sys
import threading
import time
from typing import Optional

log = logging.getLogger("arp")

PF_ANCHOR = "solar_collector"
FORWARDING = "net.inet.ip.forwarding"


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def get_mac(ip: str) -> Optional[str]:
    """Look up a MAC from the ARP table, pinging first to populate it."""
    _run(["ping", "-c", "1", "-W", "500", ip])
    out = _run(["arp", "-n", ip]).stdout
    for token in out.split():
        if token.count(":") == 5:
            return token
    return None


def default_gateway() -> Optional[str]:
    out = _run(["route", "-n", "get", "default"]).stdout
    for line in out.splitlines():
        if "gateway:" in line:
            return line.split(":", 1)[1].strip()
    return None


class ArpRedirect:
    """Pulls one target host's traffic to us, redirects DNS + uplink, cleans up."""

    def __init__(self, target_ip: str, listen_ip: str, gateway_ip: Optional[str] = None,
                 proxy_port: int = 10000, dns_port: int = 53, poison_interval: float = 2.0):
        self.target_ip = target_ip
        self.listen_ip = listen_ip
        self.gateway_ip = gateway_ip or default_gateway()
        self.proxy_port = proxy_port
        self.dns_port = dns_port
        self.poison_interval = poison_interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._target_mac: Optional[str] = None
        self._gateway_mac: Optional[str] = None
        self._poison_pkt = None
        # State recorded at start() so stop() can put the machine back as it was.
        self._owner_pid: Optional[int] = None
        self._prev_forwarding: Optional[str] = None
        self._pf_was_enabled: Optional[bool] = None
        self._pf_token: Optional[str] = None
        self._pf_plain_enabled = False      # we ran `pfctl -e` (no token available)
        self._pf_loaded = False
        self._stopped = False
        self._lock = threading.Lock()

    def start(self, poison_in_thread: bool = True) -> None:
        """
        Set up forwarding + pf as root. With poison_in_thread=False the caller
        drives poison_once() itself (run.py does, from its root supervisor).
        """
        try:
            from scapy.all import ARP, Ether
        except ImportError:
            log.error("scapy not installed -- run `pip install scapy`, or use LAN-wide DNS instead")
            raise

        if not self.gateway_ip:
            raise RuntimeError("could not determine the default gateway")

        self._target_mac = get_mac(self.target_ip)
        self._gateway_mac = get_mac(self.gateway_ip)
        if not self._target_mac:
            raise RuntimeError(f"could not resolve MAC for stick {self.target_ip}")
        log.info("stick %s is at %s, gateway %s is at %s",
                 self.target_ip, self._target_mac, self.gateway_ip, self._gateway_mac)

        # Tell the stick: the gateway IP lives at our MAC. Sent as an unsolicited
        # reply and repeated, since ARP caches expire and the real router keeps
        # re-announcing itself.
        self._poison_pkt = Ether(dst=self._target_mac) / ARP(
            op=2, psrc=self.gateway_ip, pdst=self.target_ip, hwdst=self._target_mac
        )

        # From here on there is state to undo: register cleanup before changing it.
        self._owner_pid = os.getpid()
        atexit.register(self.stop)
        try:
            self._enable_forwarding()
            self._install_pf()
        except BaseException:
            self.stop()
            raise

        if poison_in_thread:
            self._thread = threading.Thread(target=self._poison_loop, daemon=True)
            self._thread.start()
        log.info("ARP redirect active for %s only (everything else on the LAN is untouched)", self.target_ip)

    def poison_once(self) -> None:
        from scapy.all import sendp
        sendp(self._poison_pkt, verbose=False)

    def _poison_loop(self) -> None:
        while not self._stop.is_set():
            self.poison_once()
            self._stop.wait(self.poison_interval)

    def _enable_forwarding(self) -> None:
        # Without this the stick's non-redirected traffic would dead-end at us.
        prev = _run(["sysctl", "-n", FORWARDING]).stdout.strip()
        if prev not in ("0", "1"):
            raise RuntimeError(f"could not read {FORWARDING} (got {prev!r})")
        self._prev_forwarding = prev
        if prev != "1":
            proc = _run(["sysctl", "-w", f"{FORWARDING}=1"])
            if proc.returncode != 0:
                raise RuntimeError(f"sysctl failed: {proc.stderr.strip()}")

    def _install_pf(self) -> None:
        # Redirect only this stick's DNS and Solarman uplink back to us; forward
        # the rest. Scoped to an anchor so we never touch the user's own pf rules.
        self._pf_was_enabled = "Status: Enabled" in _run(["pfctl", "-s", "info"]).stdout
        rules = (
            f"rdr pass on lo0 inet proto udp from {self.target_ip} to any port 53 -> {self.listen_ip} port {self.dns_port}\n"
            f"rdr pass inet proto udp from {self.target_ip} to any port 53 -> {self.listen_ip} port {self.dns_port}\n"
            f"rdr pass inet proto tcp from {self.target_ip} to any port {self.proxy_port} -> {self.listen_ip} port {self.proxy_port}\n"
        )
        self._pf_loaded = True     # flush the anchor on stop even if the load half-failed
        proc = _run(["pfctl", "-a", PF_ANCHOR, "-f", "-"], input=rules)
        if proc.returncode != 0:
            raise RuntimeError(f"pfctl load failed: {proc.stderr.strip()}")

        # Take a reference-counted enable (-E): stop() releases just our
        # reference (-X), so pf is only switched off if nothing else wants it.
        proc = _run(["pfctl", "-E"])
        match = re.search(r"Token\s*:\s*(\d+)", proc.stdout + proc.stderr)
        if match:
            self._pf_token = match.group(1)
        elif not self._pf_was_enabled:
            _run(["pfctl", "-e"])
            self._pf_plain_enabled = True
        log.info("pf redirect installed in anchor '%s' (pf was %s)", PF_ANCHOR,
                 "enabled" if self._pf_was_enabled else "disabled")

    def _restore_pf(self) -> None:
        if self._pf_token:
            _run(["pfctl", "-X", self._pf_token])
        elif self._pf_plain_enabled:
            _run(["pfctl", "-d"])

    def _restore_forwarding(self) -> None:
        if self._prev_forwarding is not None and self._prev_forwarding != "1":
            _run(["sysctl", "-w", f"{FORWARDING}={self._prev_forwarding}"])

    def stop(self) -> None:
        """Undo everything start() did. Idempotent; only acts in the process that started it."""
        with self._lock:
            if self._stopped or self._owner_pid != os.getpid():
                return
            self._stopped = True
        self._stop.set()
        try:
            if self._thread:
                self._thread.join(timeout=3)
            # Heal the stick's ARP cache immediately with the router's real MAC.
            if self._target_mac and self._gateway_mac:
                try:
                    from scapy.all import ARP, Ether, sendp
                    heal = Ether(dst=self._target_mac) / ARP(
                        op=2, psrc=self.gateway_ip, hwsrc=self._gateway_mac,
                        pdst=self.target_ip, hwdst=self._target_mac
                    )
                    for _ in range(5):
                        sendp(heal, verbose=False)
                        time.sleep(0.2)
                except Exception:
                    log.exception("failed to heal stick ARP cache")
        finally:
            try:
                if self._pf_loaded:
                    _run(["pfctl", "-a", PF_ANCHOR, "-F", "all"])
            finally:
                try:
                    self._restore_pf()
                finally:
                    self._restore_forwarding()
        log.info("ARP redirect stopped: stick ARP cache healed, pf anchor flushed, "
                 "pf and %s restored", FORWARDING)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) < 3:
        print("usage: sudo python arp_redirect.py <stick_ip> <this_machine_ip>")
        sys.exit(1)
    # SIGTERM would otherwise kill us without running atexit cleanup.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    r = ArpRedirect(sys.argv[1], sys.argv[2])
    r.start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        r.stop()
