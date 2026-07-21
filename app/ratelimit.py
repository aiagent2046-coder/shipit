"""Rate limiter for the audit endpoint.

Two interchangeable fixed-window implementations behind one interface
(`check(key, limit=None)` raising `RateLimitExceeded`):

- `RateLimiter`: in-memory, single-process counter keyed by client IP.
  Simplest thing that enforces the architecture doc's rule ("5 audits/day,
  from day one"). It resets on process restart and does not share state
  across processes.
- `RedisRateLimiter`: same window semantics backed by Redis, so the budget
  survives restarts/deploys and is shared across workers/instances.

`limiter_from_env()` picks Redis when `REDIS_URL` is set and falls back to
in-memory otherwise, so a deployment without Redis infrastructure keeps
working exactly as before (graceful degradation, no breaking change).
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

    def check(self, key: str, limit: int | None = None) -> None:
        """Raise RateLimitExceeded if `key` is over budget; else record the call.

        `limit` overrides this limiter's default budget for THIS call only,
        which is how tier-aware limits are enforced without a second limiter:
        the caller passes the resolved per-tier limit (see app/accounts.py).
        Omitted -> the limiter's own `limit` (today's behavior, unchanged).
        """
        effective = self.limit if limit is None else limit
        now = self._clock()
        with self._lock:
            self._evict_expired(now)
            window = self._windows.get(key)
            if window is None or now - window.start >= self.window_seconds:
                self._windows[key] = _Window(start=now, count=1)
                return
            if window.count >= effective:
                retry_after = int(self.window_seconds - (now - window.start)) + 1
                raise RateLimitExceeded(retry_after)
            window.count += 1

    def _evict_expired(self, now: float) -> None:
        """Drop windows whose window has fully elapsed. Without this a key
        seen once and never again sits in `_windows` forever -- an unbounded
        leak, since `/v1/audits` is public and keyed by client IP (rotating
        source IPs would grow the dict without limit). Bounds it to clients
        active within the last window. Caller holds `_lock`."""
        stale = [k for k, w in self._windows.items()
                 if now - w.start >= self.window_seconds]
        for k in stale:
            del self._windows[k]


# Fixed-window counter in one atomic round-trip: INCR the key, and only on
# the first hit of a window set its expiry, so the window is anchored at the
# first request (matching RateLimiter). Returns (count, pttl_ms) so the caller
# can compute retry_after from the real remaining TTL.
_WINDOW_LUA = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return {current, redis.call('PTTL', KEYS[1])}
"""


class RedisRateLimiter:
    """Fixed-window limiter backed by Redis: `limit` calls per `window_seconds`,
    per key. Same interface as RateLimiter, so it drops in behind
    `get_rate_limiter` unchanged. Unlike the in-memory limiter the budget
    survives process restarts/deploys and is shared across workers.

    `client` is any object exposing redis-py's `eval(script, numkeys, *args)`;
    injected so tests can pass an in-process fake instead of a real server.
    """

    def __init__(
        self,
        client,
        limit: int = DEFAULT_LIMIT,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        key_prefix: str = "ratelimit:",
    ):
        self.limit = limit
        self.window_seconds = window_seconds
        self._client = client
        self._key_prefix = key_prefix

    def check(self, key: str, limit: int | None = None) -> None:
        """Raise RateLimitExceeded if `key` is over budget; else record the call.

        `limit` overrides the default budget for THIS call only (tier-aware
        limits), exactly like RateLimiter.check.
        """
        effective = self.limit if limit is None else limit
        window_ms = self.window_seconds * 1000
        count, pttl = self._client.eval(
            _WINDOW_LUA, 1, f"{self._key_prefix}{key}", window_ms
        )
        if count > effective:
            # PTTL is ms remaining; -1/-2 mean "no expiry"/"missing", which
            # shouldn't happen right after INCR but is handled defensively.
            remaining_ms = pttl if pttl and pttl > 0 else window_ms
            retry_after = int(remaining_ms / 1000) + 1
            raise RateLimitExceeded(retry_after)


def limiter_from_env() -> RateLimiter | RedisRateLimiter:
    """Redis-backed limiter when REDIS_URL is set, else the in-memory one.

    Absence of Redis infrastructure is not a breaking change: the fallback is
    byte-for-byte the previous behavior. Provisioning Redis and setting
    REDIS_URL upgrades the same limiter to survive restarts.
    """
    limit = int(os.environ.get("AUDIT_RATE_LIMIT_PER_DAY", DEFAULT_LIMIT))
    redis_url = os.environ.get("REDIS_URL")
    if redis_url:
        import redis  # imported lazily so the dep is only needed when used

        client = redis.Redis.from_url(redis_url)
        return RedisRateLimiter(client, limit=limit)
    return RateLimiter(limit=limit)
