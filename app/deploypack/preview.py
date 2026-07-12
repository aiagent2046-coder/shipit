"""Ephemeral preview hosting — minimal scope.

Per shipit-architecture.md 2.4.1: after a successful sandbox boot,
keep the container alive (bounded TTL, memory-capped) instead of
tearing it down immediately, so the free/unpaid user can see their own
live app before paying — the "verify first" half of "verify first,
pay to unlock".

Explicitly NOT built here: the public `{job_id}.preview.shipit.app`
URL. That needs a real domain with wildcard DNS pointed at a real
public server running Caddy (or similar) as a reverse proxy — none of
which exist in this dev environment, and inventing a fake domain would
violate the same rule this whole project is built around ("not done if
it doesn't boot"). What IS real here: the container really stays
alive, really has a TTL, really gets reaped, really returns a working
`local_url` you can curl on the host running this process. Wiring a
public domain in front of it is real infra work for whoever deploys
this for real — see the module docstring notes in sandbox.py for how
to plug in.
"""

from __future__ import annotations

import random
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from app.deploypack.sandbox import Runner, verify_deploy_pack

DEFAULT_TTL_SECONDS = 24 * 60 * 60   # 24h, per architecture doc
DEFAULT_MEMORY_LIMIT = "256m"        # per architecture doc
PORT_RANGE = range(20000, 30000)


@dataclass
class PreviewInfo:
    job_id: str
    owner_key: str
    container: str
    image_tag: str
    host_port: int
    started_at: float
    expires_at: float


@dataclass
class PreviewResult:
    ok: bool
    detail: str
    local_url: str | None = None
    expires_at: float | None = None
    job_id: str | None = None
    build_log: str = ""


class PreviewRegistry:
    """In-memory only, one process — same honesty as RateLimiter about
    what that means: resets on restart, doesn't share state across
    workers. Move to Redis/DB (fixpack_jobs table, per the architecture
    doc's data layer) before running more than one worker."""

    def __init__(self, run: Runner = subprocess.run):
        self._run = run
        self._lock = threading.Lock()
        self._by_owner: dict[str, PreviewInfo] = {}

    def _used_ports(self) -> set[int]:
        return {info.host_port for info in self._by_owner.values()}

    def _allocate_port(self) -> int:
        used = self._used_ports()
        candidates = [p for p in PORT_RANGE if p not in used]
        if not candidates:
            raise RuntimeError("no free preview ports left in range")
        return random.choice(candidates)

    def start(
        self,
        build_dir: Path,
        container_port: int,
        owner_key: str,
        *,
        path: str = "/",
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        memory_limit: str = DEFAULT_MEMORY_LIMIT,
    ) -> PreviewResult:
        """One live preview per owner_key: starting a new one replaces
        (stops) any previous one for the same owner."""
        with self._lock:
            existing = self._by_owner.get(owner_key)
            if existing:
                self._stop_locked(existing)
            host_port = self._allocate_port()

        result = verify_deploy_pack(
            build_dir, host_port, container_port, path=path,
            keep_alive_on_success=True, memory_limit=memory_limit,
            run=self._run,
        )
        if not result.ok:
            return PreviewResult(ok=False, detail=result.detail, build_log=result.build_log)

        now = time.time()
        info = PreviewInfo(
            job_id=result.container, owner_key=owner_key,
            container=result.container, image_tag=result.image_tag,
            host_port=host_port, started_at=now, expires_at=now + ttl_seconds,
        )
        with self._lock:
            self._by_owner[owner_key] = info

        return PreviewResult(
            ok=True, detail=result.detail,
            local_url=f"http://localhost:{host_port}{path}",
            expires_at=info.expires_at, job_id=info.job_id,
        )

    def _stop_locked(self, info: PreviewInfo) -> None:
        """Caller must hold self._lock."""
        self._run(["docker", "stop", info.container],
                   capture_output=True, text=True, timeout=15)
        self._run(["docker", "rmi", "-f", info.image_tag],
                   capture_output=True, text=True, timeout=15)
        self._by_owner.pop(info.owner_key, None)

    def stop(self, owner_key: str) -> bool:
        with self._lock:
            info = self._by_owner.get(owner_key)
            if not info:
                return False
            self._stop_locked(info)
            return True

    def reap_expired(self, now: float | None = None) -> int:
        """Stop+remove everything past its TTL. Call this periodically
        (a cron-triggered endpoint, or a scheduled job) \u2014 there is no
        background scheduler in this process yet."""
        now = now if now is not None else time.time()
        with self._lock:
            expired = [info for info in self._by_owner.values() if info.expires_at <= now]
            for info in expired:
                self._stop_locked(info)
        return len(expired)

    def active_count(self) -> int:
        with self._lock:
            return len(self._by_owner)

    def list_active(self) -> list[PreviewInfo]:
        with self._lock:
            return list(self._by_owner.values())
