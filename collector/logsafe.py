"""
Helpers for logging things that arrived over the network, and for not logging
them too often.

Anything a packet can influence (DNS names, peer-supplied text) goes through
clean() before it reaches a log line, so a crafted query can't forge log
entries with embedded newlines or terminal escape sequences, or bloat the log
with a huge label. Throttle caps how often a repeated warning (a flood of
rejected connections, say) is written.
"""

from __future__ import annotations

import re
import threading
import time
from typing import Callable

_UNSAFE = re.compile(r"[^A-Za-z0-9.-]")


def clean(value: object, limit: int = 64) -> str:
    """Reduce value to [A-Za-z0-9.-] (anything else becomes '?'), capped at limit chars."""
    text = value if isinstance(value, str) else str(value)
    if len(text) > limit:
        return _UNSAFE.sub("?", text[:limit]) + "..."
    return _UNSAFE.sub("?", text)


class Throttle:
    """Allow at most `limit` events per `window` seconds; count the rest."""

    def __init__(self, limit: int, window: float = 60.0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.limit = limit
        self.window = window
        self._clock = clock
        self._lock = threading.Lock()
        self._start = clock()
        self._count = 0
        self.suppressed = 0   # events refused in the current window

    def allow(self) -> bool:
        with self._lock:
            now = self._clock()
            if now - self._start >= self.window:
                self._start, self._count, self.suppressed = now, 0, 0
            if self._count < self.limit:
                self._count += 1
                return True
            self.suppressed += 1
            return False
