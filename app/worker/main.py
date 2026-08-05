"""The audit worker: `python -m app.worker`.

This process drains the durable queue that migration 0022 introduced -- claim a
job, run the scan, persist the audits row, finalize the job -- so that an
audit's execution is not tied to the lifetime of an HTTP request or an API
restart. Since the Stage 2 cutover it is the ONLY thing that runs audit scans:
`POST /v1/audits` validates and enqueues, and returns 202 without waiting.

Shape of one slot's loop:

    reap expired leases (a separate background task, not per-slot)
    while not shutting down:
        if the emergency stop is engaged -> sleep, re-check
        claim_one -> nothing? sleep POLL_INTERVAL and go again
        run the scan under a heartbeat that renews the lease
        finalize succeeded / failed

The two things this file has to get right, because nothing downstream can fix
them afterwards:

  - **Never write for a lease you no longer hold.** The heartbeat is not just
    liveness: a renew_lease that returns False means the reaper already gave
    this job to someone else, and anything this slot writes would corrupt that
    other worker's attempt. On a lost lease the scan is cancelled and the slot
    returns having written nothing at all.
  - **Never lose a job to a redeploy.** SIGTERM stops new claims, gives
    in-flight work a budget, and hands back whatever did not finish via
    release_early -- rather than letting it sit unclaimable until the lease
    expires, which would make every routine deploy a multi-minute stall.
"""

from __future__ import annotations

import asyncio
import io
import logging
import os
import signal
import socket
import sys
import time

import psycopg

from app import db as db_mod
from app.alerts import notify_operator
from app.audit_spool import (
    cleanup_staged_archive,
    read_staged_archive,
    sweep_stale_archives,
)
from app.db import (
    AuditJobRepository,
    AuditRepository,
    LlmUsageRepository,
    ServiceFlagsRepository,
)
from app.ingest.github_fetch import RepoFetchError, fetch_repo_zip
from app.ingest.stack_detect import Stack, detect_stack
from app.ingest.validators import ArchiveValidationError, validate_zip
from app.llm.client import LLMClient, LLMError
from app.log_context import log_context, set_log_context
from app.logging_config import configure_logging
from app.scan.pipeline import (AUDIT_ENGINE_VERSION,
                              FREE_TIER_LLM_SKIP_REASON,
                              basis_for_account, content_digest)

# Reused rather than reimplemented, which is the whole point: the worker must
# run the same scan, under the same concurrency bound, with the same spend
# backstop and the same emergency stop as the inline path, or the two would
# drift the moment either is tuned. Importing app.main does not start a server
# -- it builds the FastAPI app object and reads env, nothing else -- and the
# dependency only points this way (app.main never imports app.worker).
from app.main import (  # noqa: E402  -- see comment above
    _anon_daily_cap_exceeded,
    _emergency_stop_active,
    _parse_github_repo_url,
    _record_llm_usage,
    _run_scan_offthread,
)

logger = logging.getLogger("app.worker")

# Independent asyncio slots. Since the API stopped scanning inline this is THE
# ceiling on concurrent audits, and so on concurrent LLM provider calls: the
# API-side AUDIT_CONCURRENCY semaphore it used to sit alongside is gone.
AUDIT_WORKER_CONCURRENCY = int(os.environ.get("AUDIT_WORKER_CONCURRENCY", "4"))

# Idle sleep between empty claims. Short, because it is the floor on how long a
# submitted audit waits before anyone looks at it, and an empty-queue claim is
# one indexed single-row UPDATE.
AUDIT_WORKER_POLL_INTERVAL_SECONDS = float(
    os.environ.get("AUDIT_WORKER_POLL_INTERVAL_SECONDS", "2"))

# How long a claim is good for without a heartbeat. An audit is normally ~2
# minutes; 300s leaves room for a large repo plus provider retries before the
# reaper would consider the holder dead.
AUDIT_WORKER_LEASE_TTL_SECONDS = int(
    os.environ.get("AUDIT_WORKER_LEASE_TTL_SECONDS", "300"))

# Renew at a third of the TTL, so two consecutive heartbeats can be lost
# (a blip, a slow query) before the lease actually lapses.
AUDIT_WORKER_HEARTBEAT_SECONDS = AUDIT_WORKER_LEASE_TTL_SECONDS / 3

# How long in-flight jobs get to finish after SIGTERM before they are cancelled
# and released back to 'queued'. Must stay under the unit's TimeoutStopSec
# (320) or systemd SIGKILLs us mid-release and the lease has to expire instead.
AUDIT_WORKER_SHUTDOWN_GRACE_SECONDS = float(
    os.environ.get("AUDIT_WORKER_SHUTDOWN_GRACE_SECONDS", "240"))

AUDIT_WORKER_REAP_INTERVAL_SECONDS = float(
    os.environ.get("AUDIT_WORKER_REAP_INTERVAL_SECONDS", "60"))

# How often the queue-depth heartbeat record is written. NOT the lease
# heartbeat above -- this one touches no job. It emits one INFO line so that
# `journalctl | jq` can reconstruct a coarse time series after the fact, which
# is the whole metrics story on a box with no room for a time-series database.
# Five minutes because the thing it measures (a backlog draining, or not) moves
# on the scale of minutes, and one line per five keeps a day of it readable.
AUDIT_WORKER_STATS_INTERVAL_SECONDS = float(
    os.environ.get("AUDIT_WORKER_STATS_INTERVAL_SECONDS", "300"))

# Slot numbers currently inside a job. Module-level because it mirrors what it
# measures: one worker process owns exactly one set of slots, and threading it
# through _slot's signature would only let a caller build a second one that
# cannot exist. Written by the slots and read by the heartbeat, both on the
# same event loop, so there is nothing to lock.
_active_slots: set[int] = set()

_REAP_MESSAGE = (
    "lease expired with no heartbeat -- the worker holding this job died or "
    "was SIGKILLed"
)

_STUCK_CREATED_MESSAGE = (
    "staging never completed -- the API process died between enqueue and "
    "mark_queued, so this job's payload was never written"
)

# How long a 'created' row may legitimately sit mid-staging. Staging is one
# fsync of at most MAX_ARCHIVE_BYTES on a local disk, so this is orders of
# magnitude above the honest case and exists only so a pathologically slow
# write is never mistaken for a dead API process.
AUDIT_WORKER_CREATED_TTL_SECONDS = int(
    os.environ.get("AUDIT_WORKER_CREATED_TTL_SECONDS", "600"))

# Backstop for staged archives whose job ended somewhere the worker could not
# clean up (lease-expiry dead-letter, reaped 'created', API crash). A full day
# is far past the longest a legitimately queued job can wait -- lease TTL times
# its attempt budget is well under an hour -- so nothing live is ever swept.
AUDIT_SPOOL_MAX_AGE_SECONDS = float(
    os.environ.get("AUDIT_SPOOL_MAX_AGE_SECONDS", str(24 * 3600)))


class JobExecutionError(Exception):
    """A job failed for a reason the queue should record verbatim.

    Carries the machine-readable `code` and whether a retry could ever help,
    so the classification lives at the point where the cause is known instead
    of being re-derived from an exception type further up."""

    def __init__(self, code: str, detail: str, *, permanent: bool):
        self.code = code
        self.detail = detail
        self.permanent = permanent
        super().__init__(f"{code}: {detail}")


def classify_failure(exc: BaseException) -> tuple[str, str, bool]:
    """Map an exception to (error_code, error_message, permanent).

    `permanent` is the only decision that matters: False buys the job another
    attempt with backoff, True dead-letters it now. The rule is "could the
    identical job ever succeed on a later attempt" -- not "how bad is this".

    The default is permanent, deliberately. An exception this function does
    not recognise is a bug, and a bug re-run three times is three workers
    burnt on the same poison pill; dead-lettering it puts it in front of a
    human instead, which is where an unknown crash belongs."""
    if isinstance(exc, JobExecutionError):
        return exc.code, exc.detail, exc.permanent

    if isinstance(exc, ArchiveValidationError):
        # A corrupt, oversized or hostile archive is corrupt on every attempt.
        return exc.reason, exc.detail or str(exc), True

    if isinstance(exc, RepoFetchError):
        # Exactly the split create_audit draws when it picks 422 vs 502: the
        # caller's fault is permanent, upstream's fault is worth retrying.
        permanent = exc.reason in ("repo_not_found", "too_large")
        return exc.reason, exc.detail or str(exc), permanent

    if isinstance(exc, LLMError):
        # Provider down / rate-limited / all providers failed. Transient by
        # nature. Rare in practice: run_scan catches LLMError itself and
        # degrades to a static-only result, so a provider outage normally ends
        # in finalize_succeeded with basis=static_only, exactly as it does on
        # the inline path today. This branch is for an LLMError raised outside
        # that guard.
        return "llm_unavailable", str(exc), False

    if isinstance(exc, (psycopg.Error, db_mod.DatabaseNotConfigured)):
        # The database being unreachable says nothing about the job itself, so
        # it must not consume the job's permanence budget -- retry it.
        return "database_unavailable", str(exc) or type(exc).__name__, False

    return "unexpected_error", f"{type(exc).__name__}: {exc}", True


def _elapsed_ms(started: float) -> int:
    """Milliseconds since a time.monotonic() mark, rounded to an int.

    monotonic rather than time(): these spans are compared against each other
    and must not jump when the clock is stepped by NTP mid-scan.
    """
    return int((time.monotonic() - started) * 1000)


def _worker_id(slot: int) -> str:
    """Lease holder identity, in the "<host>/<pid>/<slot>" form migration 0022
    documents. Enough to find the process in the journal from a stuck row."""
    return f"{socket.gethostname()}/{os.getpid()}/{slot}"


async def _load_payload(job: dict) -> tuple[bytes, str | None]:
    """Return (archive bytes, repo_url to record on the audit).

    The two intakes diverge only here. A 'zip' job's bytes were staged to disk
    at intake because they exist nowhere else; a 'repo_url' job's are re-fetched
    from GitHub, which is what create_audit does today and is cheaper than
    keeping a second copy of every public repo."""
    kind = job.get("source_kind")
    source_ref = job.get("source_ref")

    if kind == "zip":
        if not source_ref:
            raise JobExecutionError(
                "payload_missing",
                "a zip job reached the worker with no staged archive path",
                permanent=True,
            )
        try:
            raw = await asyncio.to_thread(read_staged_archive, source_ref)
        except FileNotFoundError as exc:
            # Cleaned up, or the host was rebuilt under a queued job. Retrying
            # cannot bring the bytes back, so this is terminal by definition.
            raise JobExecutionError(
                "payload_missing",
                f"staged archive is gone: {source_ref}",
                permanent=True,
            ) from exc
        return raw, None

    if kind == "repo_url":
        parsed = _parse_github_repo_url(source_ref)
        if parsed is None:
            raise JobExecutionError(
                "bad_repo_url",
                f"not a public github.com repo URL: {source_ref!r}",
                permanent=True,
            )
        owner, repo = parsed
        # Same SSRF posture as the endpoint: only the two validated segments
        # reach the fetch, and the host hit is the fixed api.github.com.
        raw = await asyncio.to_thread(fetch_repo_zip, owner, repo)
        return raw, (source_ref or "").strip()

    raise JobExecutionError(
        "bad_source_kind", f"unknown source_kind {kind!r}", permanent=True,
    )


async def _execute_job(
    job: dict, *, llm_client: LLMClient, audit_repo: AuditRepository,
    llm_usage_repo: LlmUsageRepository,
) -> str:
    """Run one job to an audits row and return its id.

    This is the second half of create_audit, unchanged in substance. The first
    half -- intake validation, tier resolution, quota -- belongs to the request
    and already happened; the job row carries what survived it (quota_key,
    account_id, content_hash). Raises on failure; the caller classifies."""
    raw, source_url = await _load_payload(job)

    buf = io.BytesIO(raw)
    report = validate_zip(buf, size_bytes=len(raw))
    buf.seek(0)
    stack = detect_stack(buf)
    if stack is Stack.UNSUPPORTED:
        raise JobExecutionError(
            "unsupported_stack",
            "We can audit Next.js, Vite + React, and FastAPI projects. "
            "This repository looks like none of them.",
            permanent=True,
        )

    # Recomputed rather than taken from job['content_hash']: for a repo_url job
    # the bytes were fetched just now and the default branch may have moved
    # since intake, so the hash the API recorded can be stale. The audits row
    # and the cache key must describe the content actually scanned.
    digest = content_digest(raw)
    cached = await audit_repo.get_by_content_hash(
        digest, AUDIT_ENGINE_VERSION, basis_for_account(job.get("account_id")))
    if cached is not None:
        # Someone audited identical content while this job waited in the queue.
        # Point the job at that result instead of paying for the same scan
        # twice -- the same reuse create_audit does, just later in the timeline.
        return str(cached["id"])

    # The free tier is static-only by policy, not by accident. The static rules
    # and secret scanning cost nothing to run and are what find committed
    # credentials; the LLM rubrics (auth, injection) are the paid depth.
    #
    # This replaces a daily-spend-cap check. That check now guards nothing on
    # this path -- an anonymous audit never reaches the provider at all -- and
    # the anonymous budget it read is still spent by monitoring re-audits, which
    # have a null account_id and have never consulted it. See the follow-up
    # issue; do not read DEFAULT_DAILY_SPEND_CAP_USD as protection for this path.
    llm_skip_reason: str | None = (
        None if job.get("account_id") else FREE_TIER_LLM_SKIP_REASON)
    if llm_skip_reason is not None:
        # Called for its alert side effect only; the return value decides
        # nothing now. Anonymous-attributed spend still accrues -- monitoring
        # re-audits write usage rows with a null account_id and have never
        # consulted this cap -- and this remains the only place that warns the
        # operator when it climbs. Dropping the call would silently remove that
        # alert along with the degrade it used to gate.
        await _anon_daily_cap_exceeded(llm_usage_repo)

    scan = await _run_scan_offthread(
        raw, llm_client, llm_skip_reason=llm_skip_reason)

    # Everything from here on is bookkeeping over money that is already spent:
    # the scan above made the provider calls. Whether this attempt goes on to
    # produce an audits row, fail, or be cancelled out from under us decides
    # what the row can point AT, never whether it is written -- an attempt whose
    # cost went unrecorded is an attempt nobody can bill or explain.
    try:
        persisted = await audit_repo.create(
            stack=stack.value, file_count=report.file_count,
            score_total=scan["score"]["total"], score_json=scan["score"],
            findings_json=scan["findings"], repo_url=source_url,
            content_hash=digest, engine_version=AUDIT_ENGINE_VERSION,
        )
        if persisted is None:
            # create_audit tolerates this by minting a throwaway id for its
            # response, but a job has nowhere to put an unpersisted result: it
            # must reference a real audits row. Transient, because the cause is
            # the database, not the job.
            raise JobExecutionError(
                "audit_not_persisted",
                "audit_repo.create returned nothing -- persistence unavailable",
                permanent=False,
            )
    except BaseException:
        # BaseException, not Exception: losing the lease cancels this coroutine
        # mid-await, and a cancelled attempt burned exactly as much money as a
        # failed one. Shielded so the insert survives the cancellation that
        # triggered it -- an unshielded await here would itself be cancelled and
        # write nothing, which is the bug this branch exists to fix.
        await asyncio.shield(_record_llm_usage(
            llm_usage_repo, job_type="audit", job_id=None,
            account_id=job.get("account_id"), llm_stats=scan["llm_usage"],
            audit_job_id=str(job["id"]),
        ))
        raise

    await _record_llm_usage(
        llm_usage_repo, job_type="audit", job_id=persisted["id"],
        account_id=job.get("account_id"), llm_stats=scan["llm_usage"],
        audit_job_id=str(job["id"]),
    )
    return str(persisted["id"])


def _discard_payload(job: dict) -> None:
    """Drop a finished zip job's staged archive. No-op for repo_url jobs, whose
    payload is a URL. Called only once the job is terminal -- a retryable
    failure keeps its bytes, or the retry would have nothing to read."""
    if job.get("source_kind") == "zip" and job.get("source_ref"):
        cleanup_staged_archive(job["source_ref"])


async def _alert_dead_letter(job_id: str, code: str, message: str) -> None:
    """One best-effort operator alert per dead-lettered job.

    Fired here rather than from a threshold check somewhere else because the
    worker is the only thing that watches a job all the way to terminal, and a
    dead_letter is by definition the end of the line: nothing will retry it, so
    nobody learns about it unless someone is told. Per-job dedupe key, matching
    _alert_fixpack_failed -- a crash-loop on one job stays one alert, but ten
    distinct jobs dying is ten, which is the signal worth waking up for. Never
    raises; notify_operator swallows its own errors."""
    await notify_operator(
        f"Drydock: audit job {job_id} dead-lettered — {code}: {message}"[:400],
        dedupe_key=f"audit-dead-letter:{job_id}",
    )


async def _heartbeat(
    *, job_id: str, worker_id: str, jobs: AuditJobRepository,
    lease_lost: asyncio.Event, scan_task: asyncio.Task,
) -> None:
    """Renew the lease until the scan finishes, or until it is no longer ours.

    A False from renew_lease is not a warning -- it is proof that this slot's
    attempt has already been written off (reaped, and possibly re-claimed by
    another worker). The scan is cancelled immediately rather than allowed to
    finish and be discarded: it would otherwise keep spending provider tokens
    on a result nobody can store."""
    while True:
        await asyncio.sleep(AUDIT_WORKER_HEARTBEAT_SECONDS)
        if await jobs.renew_lease(
            job_id=job_id, worker_id=worker_id,
            lease_seconds=AUDIT_WORKER_LEASE_TTL_SECONDS,
        ):
            continue
        logger.warning(
            "lost the lease on job %s (worker %s) -- abandoning it without "
            "writing anything", job_id, worker_id,
            extra={"step": "lease_renew"},
        )
        lease_lost.set()
        scan_task.cancel()
        return


async def _process_job(
    job: dict, *, worker_id: str, jobs: AuditJobRepository,
    llm_client: LLMClient, audit_repo: AuditRepository,
    llm_usage_repo: LlmUsageRepository, shutting_down: asyncio.Event,
) -> None:
    """Run one claimed job under a heartbeat and record its outcome.

    Every exit path is one of exactly four things: finalize_succeeded,
    finalize_failed, release_early (shutdown), or write nothing at all (lease
    lost). There is no path that leaves the row in 'running' with nobody
    working it -- and if a SIGKILL ever creates one, reap_expired is the
    backstop."""
    job_id = str(job["id"])
    lease_lost = asyncio.Event()
    # Wall time for the whole claimed-to-finalized span, so a slow job shows up
    # as one number on its terminal line instead of having to be reconstructed
    # from two timestamps.
    started = time.monotonic()

    scan_task = asyncio.create_task(
        _execute_job(
            job, llm_client=llm_client, audit_repo=audit_repo,
            llm_usage_repo=llm_usage_repo,
        )
    )
    heartbeat_task = asyncio.create_task(
        _heartbeat(
            job_id=job_id, worker_id=worker_id, jobs=jobs,
            lease_lost=lease_lost, scan_task=scan_task,
        )
    )

    try:
        audit_id = await scan_task
    except asyncio.CancelledError:
        if lease_lost.is_set():
            # The heartbeat cancelled us. Writing anything here would stomp on
            # the attempt the queue has already reassigned.
            return
        # Shutdown cancelled us. Hand the job straight back so a redeploy does
        # not park it until the lease expires. Shielded because we are already
        # inside a cancellation and this release must still complete.
        if shutting_down.is_set():
            released = await asyncio.shield(
                jobs.release_early(job_id=job_id, worker_id=worker_id))
            logger.info(
                "shutdown released job %s back to the queue (%s)",
                job_id, "ok" if released else "lease already gone",
                extra={"step": "release_early",
                       "duration_ms": _elapsed_ms(started)},
            )
        raise
    except Exception as exc:  # noqa: BLE001 -- classified, then recorded
        code, message, permanent = classify_failure(exc)
        logger.warning(
            "job %s failed (%s, permanent=%s)", job_id, code, permanent,
            exc_info=True,
            extra={"step": "execute", "duration_ms": _elapsed_ms(started),
                   "error_code": code},
        )
        if lease_lost.is_set():
            return
        wrote = await jobs.finalize_failed(
            job_id=job_id, worker_id=worker_id, error_code=code,
            error_message=message, permanent=permanent,
        )
        if not wrote:
            logger.warning(
                "job %s failure not recorded -- lease was already gone", job_id,
                extra={"step": "finalize_failed",
                       "duration_ms": _elapsed_ms(started)})
            return
        # finalize_failed picks the branch from the row's own attempts, so the
        # same condition is re-derived here to know whether the job is done.
        exhausted = job.get("attempts", 0) >= job.get("max_attempts", 0)
        if permanent or exhausted:
            _discard_payload(job)
            await _alert_dead_letter(job_id, code, message)
    else:
        if lease_lost.is_set():
            return
        set_log_context(audit_id=str(audit_id))
        wrote = await jobs.finalize_succeeded(
            job_id=job_id, worker_id=worker_id, audit_id=audit_id)
        if wrote:
            logger.info(
                "job %s succeeded -> audit %s", job_id, audit_id,
                extra={"step": "finalize",
                       "duration_ms": _elapsed_ms(started)})
            _discard_payload(job)
        else:
            logger.warning(
                "job %s produced audit %s but the lease was already gone -- "
                "the audit is persisted and reusable via its content hash, "
                "the job will be retried or dead-lettered by whoever holds it",
                job_id, audit_id,
                extra={"step": "finalize",
                       "duration_ms": _elapsed_ms(started)},
            )
    finally:
        heartbeat_task.cancel()


async def _slot(
    slot: int, *, jobs: AuditJobRepository, llm_client: LLMClient,
    audit_repo: AuditRepository, llm_usage_repo: LlmUsageRepository,
    flags_repo: ServiceFlagsRepository, shutting_down: asyncio.Event,
) -> None:
    """One independent claim-run-finalize loop. Slots share nothing but the
    connection pool, so a slow job in one never blocks another's claim."""
    worker_id = _worker_id(slot)
    logger.info("audit worker slot %s up as %s", slot, worker_id)

    while not shutting_down.is_set():
        # Emergency stop, same soft-degrade as process_pending_monitoring: a
        # background drain has nobody to 503, so it simply stops claiming and
        # leaves the backlog queued. The operator alert fires inside
        # _emergency_stop_active, throttled by its dedupe key.
        paused, _note = await _emergency_stop_active(flags_repo)
        if paused:
            await _sleep_or_shutdown(shutting_down)
            continue

        claim_started = time.monotonic()
        job = await jobs.claim_one(
            worker_id=worker_id,
            lease_seconds=AUDIT_WORKER_LEASE_TTL_SECONDS,
        )
        if job is None:
            await _sleep_or_shutdown(shutting_down)
            continue

        # Scoped to this job, not to the slot: the `with` restores the
        # previous values on EVERY exit -- success, failure, lost lease,
        # shutdown cancellation -- so the next claim cannot inherit the
        # previous job's ids. audit_id is bound to None here so that the reset
        # also clears the value _process_job sets when a scan succeeds.
        #
        # Slots are separate asyncio tasks, and a task runs in a COPY of the
        # context it was created in, so a value set inside one slot is
        # invisible to the others: two jobs running concurrently cannot mix up
        # their job_id in the logs. tests/test_log_context_wiring.py pins this.
        with log_context(
            job_id=str(job["id"]),
            trace_id=str(job["id"]),
            audit_id=None,
        ):
            logger.info("slot %s claimed job %s (attempt %s)",
                        slot, job["id"], job.get("attempts"),
                        extra={"step": "claim",
                               "duration_ms": _elapsed_ms(claim_started),
                               "attempt": job.get("attempts")})
            _active_slots.add(slot)
            try:
                await _process_job(
                    job, worker_id=worker_id, jobs=jobs, llm_client=llm_client,
                    audit_repo=audit_repo, llm_usage_repo=llm_usage_repo,
                    shutting_down=shutting_down,
                )
            finally:
                # finally, not a line after the call: a slot cancelled at
                # shutdown or killed by an unexpected error is no longer busy,
                # and a gauge that only decrements on the happy path drifts
                # upward until it permanently reads "fully saturated".
                _active_slots.discard(slot)

    logger.info("audit worker slot %s stopped claiming", slot)


async def _sleep_or_shutdown(shutting_down: asyncio.Event) -> None:
    """Idle for the poll interval, but wake immediately on SIGTERM so an empty
    worker shuts down at once instead of after a pointless sleep."""
    try:
        await asyncio.wait_for(
            shutting_down.wait(), timeout=AUDIT_WORKER_POLL_INTERVAL_SECONDS)
    except asyncio.TimeoutError:
        return


async def _reaper(
    *, jobs: AuditJobRepository, shutting_down: asyncio.Event
) -> None:
    """Recover jobs whose holder died, on its own clock.

    A background task rather than a step in each slot's loop: the slots are
    busy exactly when reaping matters most, and running it per-slot would mean
    N identical scans per pass for one shared piece of work.

    Three sweeps, one clock. Expired leases are the crashed-worker case. Stuck
    'created' rows are the crashed-API case: a job whose payload staging never
    finished can never be claimed, and while it sits there it holds its
    submission's idempotency key, so the caller's retry is turned away too. The
    spool sweep is the disk-side backstop for both, since a row reaped by
    either of the first two leaves bytes behind that no worker will ever read
    and MAX_SPOOL_BYTES eventually starts rejecting new uploads."""
    while not shutting_down.is_set():
        pass_started = time.monotonic()
        try:
            result = await jobs.reap_expired(error_message=_REAP_MESSAGE)
            if result["requeued"] or result["dead_lettered"]:
                logger.info(
                    "reaped expired leases: %s requeued, %s dead-lettered",
                    result["requeued"], result["dead_lettered"],
                    extra={"step": "reap",
                           "duration_ms": _elapsed_ms(pass_started)},
                )
            stuck = await jobs.reap_stuck_created(
                older_than_seconds=AUDIT_WORKER_CREATED_TTL_SECONDS,
                error_message=_STUCK_CREATED_MESSAGE,
            )
            if stuck:
                logger.warning(
                    "dead-lettered %s job(s) stuck in 'created' -- an API "
                    "process died mid-staging", stuck)
            await asyncio.to_thread(
                sweep_stale_archives,
                max_age_seconds=AUDIT_SPOOL_MAX_AGE_SECONDS)
        except Exception:  # noqa: BLE001 -- the reaper must outlive a blip
            logger.warning(
                "reap pass failed", exc_info=True,
                extra={"step": "reap", "duration_ms": _elapsed_ms(pass_started)})
        try:
            await asyncio.wait_for(
                shutting_down.wait(),
                timeout=AUDIT_WORKER_REAP_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            continue


async def _stats_heartbeat(
    *, jobs: AuditJobRepository, shutting_down: asyncio.Event
) -> None:
    """One INFO record per interval carrying the numbers a time series would.

    This is the metrics story for this deployment. A single VPS whose free
    memory is already spoken for by the Fix Pack sandboxes has no room for
    Prometheus, so rather than export a gauge the worker writes it into the log
    it is already writing: with LOG_FORMAT=json,

        journalctl -u shipit-audit-worker | jq -c 'select(.event=="heartbeat")'

    replays queue depth and slot occupancy over whatever journald retained.
    GET /internal/stats answers "what is true now" and needs the API up; this
    answers "what was true at 04:00 last Tuesday" and needs nothing.

    Unconditional, unlike the reaper's line, which only speaks when it reaped
    something: a missing heartbeat has to mean the worker was down, so the
    record cannot be contingent on there being anything interesting to say.

    Failures are swallowed and logged, matching the reaper -- a stats read that
    cannot reach the database must not take down the process whose health it is
    reporting on."""
    while not shutting_down.is_set():
        pass_started = time.monotonic()
        try:
            stats = await jobs.backlog_stats()
            logger.info(
                "heartbeat: %s queued, %s slot(s) busy",
                stats["queued"] if stats else 0, len(_active_slots),
                extra={
                    "event": "heartbeat",
                    "queue_depth": stats["queued"] if stats else 0,
                    "oldest_queued_seconds": (
                        stats["oldest_queued_seconds"] if stats else None),
                    "active_slots": len(_active_slots),
                    "duration_ms": _elapsed_ms(pass_started),
                },
            )
        except Exception:  # noqa: BLE001 -- reporting must not kill the worker
            logger.warning(
                "heartbeat pass failed", exc_info=True,
                extra={"event": "heartbeat",
                       "duration_ms": _elapsed_ms(pass_started)})
        try:
            await asyncio.wait_for(
                shutting_down.wait(),
                timeout=AUDIT_WORKER_STATS_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            continue


async def run_worker(
    *, concurrency: int = AUDIT_WORKER_CONCURRENCY,
    shutting_down: asyncio.Event | None = None,
    grace_seconds: float = AUDIT_WORKER_SHUTDOWN_GRACE_SECONDS,
) -> None:
    """Start the slots and the reaper, then wait for shutdown.

    Exposed separately from main() so tests can drive a real worker with their
    own shutdown event and grace budget instead of sending signals."""
    shutting_down = shutting_down or asyncio.Event()
    jobs = AuditJobRepository()
    audit_repo = AuditRepository()
    llm_usage_repo = LlmUsageRepository()
    flags_repo = ServiceFlagsRepository()
    llm_client = LLMClient()

    reaper_task = asyncio.create_task(
        _reaper(jobs=jobs, shutting_down=shutting_down))
    # Its own task, not a step in the claim loop: a slot inside a long scan is
    # exactly when the heartbeat matters most and exactly when that loop is not
    # coming back around. Separate, it keeps reporting through a fully
    # saturated worker and cannot delay a claim.
    heartbeat_task = asyncio.create_task(
        _stats_heartbeat(jobs=jobs, shutting_down=shutting_down))
    slot_tasks = [
        asyncio.create_task(
            _slot(
                slot, jobs=jobs, llm_client=llm_client, audit_repo=audit_repo,
                llm_usage_repo=llm_usage_repo, flags_repo=flags_repo,
                shutting_down=shutting_down,
            )
        )
        for slot in range(concurrency)
    ]

    # Wake on either a shutdown signal or a slot dying. A slot should never
    # return on its own, so if one does the process is already degraded --
    # drain the rest and let Restart=always give us a clean one.
    stop_waiter = asyncio.create_task(shutting_down.wait())
    try:
        await asyncio.wait(
            [stop_waiter, *slot_tasks], return_when=asyncio.FIRST_COMPLETED)
    finally:
        stop_waiter.cancel()
        shutting_down.set()

    # The grace budget: slots leave their loop as soon as they notice the flag,
    # so anything still running here is one in-flight job per slot.
    _done, pending = await asyncio.wait(slot_tasks,
                                        timeout=max(grace_seconds, 0.0))
    if pending:
        logger.warning(
            "%s job(s) still running after the %ss shutdown budget -- "
            "cancelling and releasing them back to the queue",
            len(pending), grace_seconds,
        )
        for task in pending:
            task.cancel()

    reaper_task.cancel()
    heartbeat_task.cancel()
    # return_exceptions so one slot's failure cannot hide the others' cleanup;
    # the exceptions were already logged where they happened.
    await asyncio.gather(*slot_tasks, reaper_task, heartbeat_task,
                         return_exceptions=True)
    await db_mod.close_pool()
    logger.info("audit worker stopped")


async def _amain() -> None:
    """Wire SIGTERM/SIGINT to the shutdown event, then run.

    loop.add_signal_handler rather than signal.signal: the handler has to touch
    an asyncio.Event, and only the loop-aware variant runs it on the loop
    thread. SIGTERM is what systemd sends on stop and restart, so this is the
    path every redeploy takes."""
    shutting_down = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _request_shutdown(signame: str) -> None:
        if shutting_down.is_set():
            # A second signal means the operator is impatient; systemd will
            # SIGKILL at TimeoutStopSec regardless, and reap_expired covers it.
            logger.warning("%s again -- already shutting down", signame)
            return
        logger.info("%s received: finishing in-flight audits, no new claims",
                    signame)
        shutting_down.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _request_shutdown, sig.name)

    await run_worker(shutting_down=shutting_down)


def main() -> int:
    """Entry point for `python -m app.worker`."""
    configure_logging()
    if not os.environ.get("DATABASE_URL"):
        # Not fatal -- every repository degrades to a no-op without a DB, so
        # the worker would simply idle. Loud, because an audit worker that can
        # never claim anything is an outage wearing a healthy process.
        logger.error(
            "DATABASE_URL is not set: the audit queue is unreachable and this "
            "worker will idle forever. Check /opt/shipit/.env.")
    try:
        asyncio.run(_amain())
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
