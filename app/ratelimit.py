"""In-memory rate limiter for the audit endpoint.

MVP scope: single-process fixed-window counter keyed by client IP.
This is intentionally the simplest thing that enforces the architecture
doc's rule ("5 audits/day, from day one") before the endpoint runs an
LLM stage. It resets on process restart and does not share state across
processes — move the counter to Redis (`.env` REDIS_URL is already
reserved for this) before running more than one worker/instance.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass

DEFAULT_LIMIT = 5
DEFAULT_WINDOW_SECONDS = 24 * 60 * 60  # 24h, matches shipit-architecture.md


class RateLimitExceeded(Exception):
    """Raised when a key has used up its budget for the current window."""

    def __init__(self, retry_after: int):
        self.retry_after = retry_after
        super().__init__(f"rate limit exceeded, retry after {retry_after}s")


@dataclass
class _Window:
    start: float
    count: int


class RateLimiter:
    """Fixed-window limiter: `limit` calls per `window_seconds`, per key.

    `clock` is injectable so tests can move time without sleeping.
    """

    def __init__(
        self,
        limit: int = DEFAULT_LIMIT,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        clock=time.time,
    ):
        self.limit = limit
        self.window_seconds = window_seconds
        self._clock = clock
        self._windows: dict[str, _Window] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        """Raise RateLimitExceeded if `key` is over budget; else record the call."""
        now = self._clock()
        with self._lock:
            window = self._windows.get(key)
            if window is None or now - window.start >= self.window_seconds:
                self._windows[key] = _Window(start=now, count=1)
                return
            if window.count >= self.limit:
                retry_after = int(self.window_seconds - (now - window.start)) + 1
                raise RateLimitExceeded(retry_after)
            window.count += 1


def limiter_from_env() -> RateLimiter:
    limit = int(os.environ.get("AUDIT_RATE_LIMIT_PER_DAY", DEFAULT_LIMIT))
    return RateLimiter(limit=limit)
