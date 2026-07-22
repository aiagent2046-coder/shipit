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

import datetime
import logging
import random
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from app.deploypack.sandbox import Runner, docker_available, verify_deploy_pack

logger = logging.getLogger(__name__)

DEFAULT_TTL_SECONDS = 24 * 60 * 60   # 24h, per architecture doc
DEFAULT_MEMORY_LIMIT = "256m"        # per architecture doc
PORT_RANGE = range(20000, 30000)

# Docker label keys stamped on every preview container (see verify_deploy_pack
# and PreviewRegistry.start). These are what reconcile_previews queries so it
# can reap orphans straight from Docker, not from this process's memory.
PREVIEW_LABEL = "shipit.preview"
EXPIRES_LABEL = "shipit.expires_at"
JOB_ID_LABEL = "shipit.job_id"


def _iso_utc(epoch: float) -> str:
    """UTC ISO-8601 for a Unix timestamp, e.g. '2026-07-18T12:00:00+00:00'."""
    return datetime.datetime.fromtimestamp(
        epoch, tz=datetime.timezone.utc
    ).isoformat()


def _parse_iso_utc(text: str) -> float | None:
    """Parse an ISO-8601 timestamp back to a Unix epoch, or None if it is
    missing/unparseable. A tz-naive value is assumed UTC (that's what we
    write). None means 'don't trust this label' — callers must not reap on it."""
    text = (text or "").strip()
    if not text:
        return None
    try:
        dt = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.timestamp()


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
        # Ports picked but not yet in _by_owner: a start() holds its port
        # here across the slow verify_deploy_pack build, so a concurrent
        # start() for a different owner (they run in parallel via
        # /v1/fixpacks' threadpool) can't be handed the same port mid-build.
        self._reserved: set[int] = set()

    def _used_ports(self) -> set[int]:
        return {info.host_port for info in self._by_owner.values()} | self._reserved

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
        # In-process fallback for TTL enforcement: reap anything already expired
        # before starting a new preview, so containers still age out even if the
        # external shipit-reap.timer is misconfigured or not firing. reap_expired
        # takes its own lock, so call it before acquiring ours below.
        self.reap_expired()
        with self._lock:
            existing = self._by_owner.get(owner_key)
            if existing:
                self._stop_locked(existing)
            host_port = self._allocate_port()
            self._reserved.add(host_port)

        # Compute expiry up front so the SAME value goes onto the container
        # as a Docker label and into the in-memory registry — the label is
        # the source of truth reconcile_previews trusts after a restart.
        now = time.time()
        expires_at = now + ttl_seconds
        try:
            result = verify_deploy_pack(
                build_dir, host_port, container_port, path=path,
                keep_alive_on_success=True, memory_limit=memory_limit,
                labels={
                    PREVIEW_LABEL: "true",
                    EXPIRES_LABEL: _iso_utc(expires_at),
                },
                run=self._run,
            )
            if not result.ok:
                return PreviewResult(ok=False, detail=result.detail, build_log=result.build_log)

            info = PreviewInfo(
                job_id=result.container, owner_key=owner_key,
                container=result.container, image_tag=result.image_tag,
                host_port=host_port, started_at=now, expires_at=expires_at,
            )
            with self._lock:
                self._by_owner[owner_key] = info

            return PreviewResult(
                ok=True, detail=result.detail,
                local_url=f"http://localhost:{host_port}{path}",
                expires_at=info.expires_at, job_id=info.job_id,
            )
        finally:
            # Drop the in-flight reservation either way: on success the
            # port is now covered by _by_owner (no gap where it's neither),
            # on failure it must return to the free pool, not leak.
            with self._lock:
                self._reserved.discard(host_port)

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


def reconcile_previews(
    run: Runner = subprocess.run, now: float | None = None
) -> dict:
    """Docker-truth orphan reaper for expired preview containers.

    `PreviewRegistry.reap_expired` only knows what is in THIS process's
    memory, so a restart wipes the map while the real containers keep
    running (especially keep_alive_on_success=True ones) — they would never
    be reaped. This function instead asks Docker directly: it lists every
    container carrying `shipit.preview=true` and force-removes any whose
    `shipit.expires_at` label is already in the past, regardless of whether
    any registry/DB row remembers it.

    Injectable `run` (defaults to subprocess.run) so tests can fake Docker.
    Returns a summary dict: how many preview containers were seen, and the
    orphans removed (each {container, job_id, expires_at}).
    """
    if not docker_available():
        return {"docker": False, "checked": 0, "removed": []}

    now = now if now is not None else time.time()
    ps = run(
        ["docker", "ps",
         "--filter", f"label={PREVIEW_LABEL}=true",
         "--format",
         '{{.ID}}\t{{.Label "shipit.job_id"}}\t{{.Label "shipit.expires_at"}}'],
        capture_output=True, text=True, timeout=15,
    )

    checked = 0
    removed: list[dict] = []
    for line in (ps.stdout or "").splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        container_id = parts[0].strip()
        job_id = parts[1].strip() if len(parts) > 1 else ""
        expires_raw = parts[2].strip() if len(parts) > 2 else ""
        if not container_id:
            continue
        checked += 1

        expires_at = _parse_iso_utc(expires_raw)
        if expires_at is None:
            # A preview-labelled container with no parseable expiry: don't
            # guess — leave it alone and flag it for a human to look at.
            logger.warning(
                "reconcile_previews: preview container %s has no valid "
                "%s label (%r); leaving it running",
                container_id, EXPIRES_LABEL, expires_raw,
            )
            continue
        if expires_at > now:
            continue  # still within TTL — not ours to kill yet

        run(["docker", "rm", "-f", container_id],
            capture_output=True, text=True, timeout=15)
        removed.append({
            "container": container_id, "job_id": job_id,
            "expires_at": expires_raw,
        })
        logger.info(
            "reconcile_previews: removed orphan preview container %s "
            "(job_id=%s, expired at %s)",
            container_id, job_id or "?", expires_raw,
        )

    return {"docker": True, "checked": checked, "removed": removed}
