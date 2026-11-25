"""The audit-intake workflow: submission gating, cache and enqueue.

Shared by both interfaces -- the HTTP endpoint POST /v1/audits (registered
in app/main.py over the `create_audit` callable defined here) and the MCP
tool `drydock_start_audit` -- so neither interface imports the other.
Extracted from app/main.py during the import-cycles fix phase; this also
fixed a latent TypeError where the MCP tool called create_audit with
keyword arguments the endpoint had not accepted since the _AuditIntake
refactor.

Layering: gate_submission is the shared pre-form gate (emergency stop,
account resolution, quota peek -- deliberately BEFORE any multipart body
is read); _audit_intake is the FastAPI dependency that adds form parsing;
create_audit is the endpoint callable (validation, cache, enqueue).
"""
from __future__ import annotations

import hashlib
import io
import json
import logging
import time
import uuid
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, ValidationError

from app import accounts
from app.accounts import TIER_FREE, entitlements_for_tier
from app.audit_history import refresh_cached_preview_history
from app.audit_spool import SpoolFull, cleanup_staged_archive, stage_archive
from app.db import (
    AccountRepository,
    AuditJobIdempotencyConflict,
    AuditJobRepository,
    AuditRepository,
    ServiceFlagsRepository,
)
from app.github_repo import _parse_github_repo_url
from app.ingest.github_fetch import RepoFetchError
from app.ingest.stack_detect import detect_stack
from app.ingest.validators import (
    MAX_ARCHIVE_BYTES,
    ArchiveValidationError,
    validate_zip,
)
from app.log_context import set_log_context
from app.ratelimit import RateLimitExceeded, RateLimiter
from app.routes._shared import _bind_account, _client_key
from app.routes.dependencies import (
    get_account_repo,
    get_audit_job_repo,
    get_audit_repo,
    get_rate_limiter,
    get_repo_fetcher,
    get_service_flags_repo,
)
from app.sca.cache import needs_dependency_scan
from app.sca.snapshot import baseline_is_current, snapshot_is_current
from app.scan.pipeline import AUDIT_ENGINE_VERSION, basis_for_account, content_digest
from app.service_flags import _emergency_stop_active

logger = logging.getLogger(__name__)


def _elapsed_ms(started: float) -> int:
    """Milliseconds since a time.monotonic() mark, rounded to an int.

    monotonic rather than time(): these spans are compared against each other
    and must not jump when the clock is stepped by NTP mid-request.
    """
    return int((time.monotonic() - started) * 1000)


def _rate_gate(
    limiter: RateLimiter, quota_key: str, limit: int, *, consume: bool
) -> None:
    """Enforce one half of /v1/audits' split rate gate.

    consume=False is the pre-read peek: it only REJECTS a caller already at
    budget, before the source is read or fetched, and mutates nothing.
    consume=True is the historical quota charge, run after validation so a
    rejected upload never burns the client's daily budget. Both answer the
    same 429 rate_limited + Retry-After. A rate-limit STORE failure is
    deliberately NOT caught here: it propagates to the app-wide
    RateLimitStoreError handler and answers fail-closed 503 instead.
    """
    try:
        if consume:
            limiter.check(quota_key, limit=limit)
        else:
            limiter.peek(quota_key, limit=limit)
    except RateLimitExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail={
                "reason": "rate_limited",
                "detail": f"max {limiter.limit} audits per day",
            },
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc


class _AuditForm(BaseModel):
    archive: UploadFile | None = None
    repo_url: str | None = Field(
        None,
        description="Alternative to `archive`: a public github.com repo URL "
                    "(https://github.com/<owner>/<repo>). Provide exactly one "
                    "of `archive` or `repo_url`. Public GitHub repos only — no "
                    "private repos, no other hosts.",
    )


@dataclass(frozen=True)
class _AuditIntake:
    form: _AuditForm
    account: dict | None
    quota_key: str
    daily_limit: int
    started: float


async def gate_submission(
    request: Request,
    *,
    limiter: RateLimiter,
    account_repo: AccountRepository,
    service_flags_repo: ServiceFlagsRepository,
):
    """Shared pre-form intake gate: emergency stop, account resolution, the
    tier daily limit, the quota key, and the consumption-free quota peek.

    Deliberately BEFORE any multipart body is read, and shared by the HTTP
    dependency below and the MCP start-audit tool (which has no form body:
    it builds the form itself from its arguments)."""
    started = time.monotonic()
    paused, note = await _emergency_stop_active(service_flags_repo)
    if paused:
        raise HTTPException(
            status_code=503,
            detail={"reason": "service_paused", "detail": note},
        )
    account = await accounts.resolve_account(request, account_repo)
    _bind_account(account)
    tier = account["tier"] if account else TIER_FREE
    daily_limit = entitlements_for_tier(
        tier, free_daily_limit=limiter.limit
    ).daily_audit_limit
    quota_key = f"account:{account['id']}" if account else _client_key(request)
    _rate_gate(limiter, quota_key, limit=daily_limit, consume=False)
    return account, quota_key, daily_limit, started


async def _audit_intake(
    request: Request,
    limiter: RateLimiter = Depends(get_rate_limiter),
    account_repo: AccountRepository = Depends(get_account_repo),
    service_flags_repo: ServiceFlagsRepository = Depends(get_service_flags_repo),
):
    """Gate the HTTP body itself, before multipart parsing can spool any file.

    Form/File route parameters make FastAPI parse the entire request before
    resolving dependencies. This body-free dependency instead resolves the
    same injected services and caller first, then explicitly opens the form.
    The context manager closes uploaded files even when validation fails.
    Quota is still charged by create_audit only after archive validation.
    """
    account, quota_key, daily_limit, started = await gate_submission(
        request, limiter=limiter, account_repo=account_repo,
        service_flags_repo=service_flags_repo)

    async with request.form() as form:
        # Preserve optional Form field semantics: an empty string is absent.
        values = {key: value for key, value in form.items()
                  if key in _AuditForm.model_fields and value != ""}
        try:
            body = _AuditForm.model_validate(values)
        except ValidationError as exc:
            errors = [dict(error, loc=("body", *error["loc"]))
                      for error in exc.errors()]
            raise RequestValidationError(errors) from exc
        yield _AuditIntake(body, account, quota_key, daily_limit, started)


async def create_audit(
    request: Request,
    intake: _AuditIntake = Depends(_audit_intake),
    limiter: RateLimiter = Depends(get_rate_limiter),
    audit_repo: AuditRepository = Depends(get_audit_repo),
    repo_fetcher=Depends(get_repo_fetcher),
    audit_job_repo: AuditJobRepository = Depends(get_audit_job_repo),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
) -> dict:
    """Accept an audit and hand back a job to poll.

    Asynchronous since Stage 2: the scan itself runs in the audit worker
    (`python -m app.worker`), and this endpoint returns as soon as the job is
    durably queued. Everything that can be decided from the submission alone
    still happens here, before the enqueue, and still answers with the same
    status codes it always did -- intake shape, the emergency stop, the repo
    fetch, zip validation, stack detection, and the split quota gate (a
    consumption-free peek before the source is read, the quota charge itself
    after validation). Rejecting those at
    intake keeps the queue free of jobs that are already known to be dead, and
    keeps a client's error for a bad upload immediate instead of arriving two
    polls later.

    The content-hash cache is likewise still checked here, and a hit still
    returns the finished audit inline with no job created at all: the result
    already exists, so making the client poll for it would be slower for no
    gain.

    Response on a miss is 202 {job_id, access_token, state}. See
    GET /v1/audit-jobs/{job_id}."""
    archive, repo_url = intake.form.archive, intake.form.repo_url
    account = intake.account
    quota_key = intake.quota_key
    intake_started = intake.started

    # Exactly one intake method: not both, not neither. Both-None and
    # both-present are the two cases where the equality holds.
    if (archive is None) == (repo_url is None):
        raise HTTPException(
            status_code=422,
            detail={"reason": "bad_intake",
                    "detail": "provide exactly one of 'archive' (file upload) "
                              "or 'repo_url' (public GitHub repo URL)"},
        )

    # The source URL to remember on the audit, so a later Fix Pack purchase
    # can re-fetch the same repo without asking for it again. Only set on
    # the GitHub-URL intake path; null for zip uploads (nothing to re-fetch).
    source_url: str | None = None
    if archive is not None:
        raw = await archive.read(MAX_ARCHIVE_BYTES + 1)
    else:
        # This is where private-repo intake would be gated by tier. There is
        # no flag to consult: `private_repos_allowed` used to sit in
        # Entitlements and was removed, because reporting it over
        # GET /v1/account told every caller a feature existed that does not.
        # Private repos aren't fetchable at all yet — github_fetch.py is
        # public-only, no auth — so add the entitlement back together with
        # the intake that needs it, and gate it here.
        #
        # SSRF guard: validate the URL to a clean github.com owner/repo
        # BEFORE any network call. Only the two validated segments reach
        # the fetch; the host it hits is the fixed api.github.com.
        parsed = _parse_github_repo_url(repo_url)
        if parsed is None:
            raise HTTPException(
                status_code=422,
                detail={"reason": "bad_repo_url",
                        "detail": "repo_url must be "
                                  "https://github.com/<owner>/<repo> "
                                  "(public GitHub repos only)"},
            )
        owner, repo = parsed
        source_url = repo_url.strip()
        # Off the event loop: fetch_repo_zip does blocking network I/O.
        try:
            raw = await run_in_threadpool(repo_fetcher, owner, repo)
        except RepoFetchError as exc:
            # Caller's fault (bad/missing/too-big repo) -> 422; GitHub's or
            # the network's fault -> 502, same split the LLM client draws
            # between "our request is wrong" and "upstream is down".
            status = 422 if exc.reason in (
                "repo_not_found", "too_large") else 502
            raise HTTPException(
                status_code=status,
                detail={"reason": exc.reason, "detail": exc.detail},
            ) from exc

    logger.info(
        "audit intake: source read (%s bytes)", len(raw),
        extra={"step": "read_source", "duration_ms": _elapsed_ms(intake_started)},
    )

    buf = io.BytesIO(raw)

    stage_started = time.monotonic()
    try:
        validate_zip(buf, size_bytes=len(raw))
    except ArchiveValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail={"reason": exc.reason, "detail": exc.detail},
        ) from exc

    buf.seek(0)
    stack = detect_stack(buf)
    logger.info(
        "audit intake: archive validated as %s", stack.value,
        extra={"step": "validate", "duration_ms": _elapsed_ms(stage_started)},
    )
    # An unrecognised stack is recorded, not refused. Nothing the audit does
    # is stack-specific: app/scan/ never reads this value, the presence checks
    # look for .env / .gitignore / tests / CI, and the secret rules are regexes
    # over file bytes. All of that is exactly as true of a SvelteKit, Django or
    # Express repository as of the three the detector happens to name.
    #
    # Refusing here turned those visitors away from findings that would have
    # been correct, which is the opposite of the product's purpose -- a
    # committed .env is a committed .env whatever built it. The stack still
    # gates the things that genuinely need it, in their own modules: the
    # Deploy Pack raises UnsupportedForDeployPack for a stack with no
    # Dockerfile template, and the Fix Pack's verified-build gate returns None
    # outside its profile set and falls back to the semantic check.

    # Consume quota only after the upload proves to be real work: validation
    # and stack detection are free, so a garbage/hostile zip (or probing for
    # validation bypasses) can't burn a client's daily budget for a request
    # that never produced an audit. The read-only peek above already gated
    # the expensive read/fetch for callers already over budget, so this
    # charge stays exactly where the client-fairness contract wants it.
    _rate_gate(
        limiter, quota_key, limit=intake.daily_limit, consume=True
    )

    # Reproducibility: byte-identical content that was already audited reuses
    # the stored result rather than re-running the scan. The LLM stage is
    # non-deterministic even at temperature=0 (see app/scan/llm_scan.py), so a
    # re-scan of the same commit yields a different findings set and thus a
    # different score (observed in prod: 8.9/9.9/9.9 for one unchanged repo).
    # The score math itself is already deterministic (app/scan/scoring.py) --
    # this closes the loop by not recomputing it from fresh, variable findings.
    # The cache key is (content, engine version): identical content reuses a
    # prior result only if it was produced by the current audit engine, so an
    # engine change (AUDIT_ENGINE_VERSION bump) recomputes rather than serving
    # a stale row. See app/scan/pipeline.py and AuditRepository.get_by_content_hash.
    stage_started = time.monotonic()
    digest = content_digest(raw)
    # Third element of the cache key: the scan depth this caller is entitled to.
    # Without it an anonymous intake would reuse a paying account's full audit.
    cached = await audit_repo.get_by_content_hash(
        digest, AUDIT_ENGINE_VERSION,
        basis_for_account(account["id"] if account else None))
    if cached is not None and account:
        cached = await refresh_cached_preview_history(audit_repo, cached)
        if (not baseline_is_current(cached["score_json"])
                or needs_dependency_scan(cached)):
            # Complete missing stages in the worker, never in HTTP intake.
            cached = None
    elif cached is not None and not snapshot_is_current(cached["score_json"]):
        # The worker refreshes just the bundled advisory evidence; intake
        # never returns results from an older or repaired catalog.
        cached = None
    logger.info(
        "audit intake: cache %s for digest %s",
        "hit" if cached is not None else "miss", digest[:12],
        extra={"step": "cache_lookup", "duration_ms": _elapsed_ms(stage_started)},
    )
    if cached is not None:
        set_log_context(audit_id=str(cached["id"]))
        return {
            "audit_id": cached["id"],
            # The reused audit's own token, so the client can open its page.
            # Safe to hand over here: the caller proved possession of the
            # identical content that produced this audit (see content_digest).
            "access_token": cached.get("access_token"),
            "persisted": True,
            "status": "completed",
            "stack": cached["stack"],
            "file_count": cached["file_count"],
            "score": cached["score_json"],
            "findings": cached["findings_json"] or [],
            "repo_url": cached.get("repo_url"),
            "llm": {"reused_from_prior_audit": True},
            "reused": True,
        }

    stage_started = time.monotonic()
    enqueued = await _enqueue_audit_job(
        audit_job_repo,
        raw=raw if archive is not None else None,
        source_kind="zip" if archive is not None else "repo_url",
        source_url=source_url,
        digest=digest,
        stack=stack.value,
        account_id=account["id"] if account else None,
        quota_key=quota_key,
        idempotency_key=idempotency_key,
    )
    logger.info(
        "audit intake: queued job %s", enqueued["job_id"],
        extra={"step": "enqueue", "duration_ms": _elapsed_ms(stage_started)},
    )
    return enqueued


def _audit_idempotency_key(
    digest: str, account_id: str | None, *, source_kind: str = "zip",
    source_url: str | None = None, client_key: str | None = None,
) -> str:
    """Bind the optional client label to the validated submission, never access.

    Accounts have separate namespaces. Anonymous callers retain the existing
    identical-content possession policy used by the audit cache; an IP address
    is not an identity. Both content and source must match before a retry can
    join a live job. JSON encodes boundaries so a client label cannot alter the
    account/content/source fields. No raw client key is stored in the queue.
    """
    material = json.dumps([
        "audit-job-v2", account_id, digest, AUDIT_ENGINE_VERSION,
        source_kind, source_url if source_kind == "repo_url" else None,
        client_key or None,
    ], separators=(",", ":"))
    return hashlib.sha256(material.encode()).hexdigest()


async def _enqueue_audit_job(
    audit_job_repo: AuditJobRepository, *, raw: bytes | None, source_kind: str,
    source_url: str | None, digest: str, stack: str, account_id: str | None,
    quota_key: str | None, idempotency_key: str | None,
) -> dict:
    """Queue one validated submission and return the 202 body.

    A repo_url job is inserted straight into 'queued': its whole payload is the
    URL, which is already in the row. An uploaded archive exists only in this
    request's memory, so it goes through 'created' -- insert, write the bytes to
    the spool, and only then mark_queued. A worker can never claim a 'created'
    row, so a crash between the insert and the write cannot produce a claimable
    job pointing at a file that was never written (see migration 0022).

    The id is minted here rather than by the database because the spool filename
    IS the job id, so it must be known before the archive can be staged, which
    is before the row can be flipped to 'queued'.

    A duplicate submission (inserted=False) returns the live job it collided
    with, and deliberately does NOT re-stage: that job's payload is already on
    disk, and rewriting it under a worker that may be mid-read buys nothing."""
    job_id = str(uuid.uuid4())
    scoped_key = _audit_idempotency_key(
        digest, account_id, source_kind=source_kind, source_url=source_url,
        client_key=idempotency_key,
    )
    try:
        job = await audit_job_repo.enqueue(
            job_id=job_id,
            initial_state="created" if source_kind == "zip" else "queued",
            source_kind=source_kind,
            # Filled in below for a zip, once the bytes are actually on disk.
            source_ref=None if source_kind == "zip" else source_url,
            content_hash=digest,
            engine_version=AUDIT_ENGINE_VERSION,
            stack=stack,
            account_id=account_id,
            quota_key=quota_key,
            idempotency_key=scoped_key,
        )
    except AuditJobIdempotencyConflict:
        raise HTTPException(
            status_code=409, detail={"reason": "idempotency_conflict"},
        ) from None
    if job is None:
        # No DATABASE_URL: there is no queue to accept the job and no worker to
        # run it. Before the cutover this deployment could still scan inline and
        # return an unpersisted result; it cannot now, and saying so is better
        # than handing back a job id that does not exist.
        raise HTTPException(
            status_code=503,
            detail={"reason": "queue_unavailable",
                    "detail": "audit persistence isn't configured on this "
                              "deployment (see app/db.py)"},
        )

    # Defence in depth: even a legacy/misbehaving repository must not hand a
    # caller another submission's token. ZIP source_ref is a server spool path,
    # not the submitted identity, so it is deliberately excluded here.
    expected = {"account_id": account_id, "content_hash": digest,
                "engine_version": AUDIT_ENGINE_VERSION, "source_kind": source_kind}
    if source_kind == "repo_url":
        expected["source_ref"] = source_url
    if any(job.get(key) != value for key, value in expected.items()):
        raise HTTPException(
            status_code=409, detail={"reason": "idempotency_conflict"},
        )

    # job["id"] rather than the minted job_id: on a duplicate collision the row
    # returned is the live job this submission matched, not the one we minted,
    # and the id a caller will poll with is the one worth logging.
    set_log_context(job_id=str(job["id"]))

    if source_kind == "zip" and job.get("inserted"):
        await _stage_and_queue(audit_job_repo, job_id=str(job["id"]), raw=raw)

    return {
        "job_id": str(job["id"]),
        # The job's ownership token, delivered exactly once, here. It is the key
        # to GET /v1/audit-jobs/{job_id} and, through it, to the finished audit.
        "access_token": job.get("access_token"),
        "state": "queued",
    }


async def _stage_and_queue(
    audit_job_repo: AuditJobRepository, *, job_id: str, raw: bytes
) -> None:
    """Write a zip job's payload to the spool, then make the job claimable.

    On any staging failure the job is dead-lettered rather than left in
    'created'. That is not cosmetic: the live-job idempotency index covers
    'created', so an abandoned row would hold this submission's key and the
    caller's retry would be told to poll a job no worker will ever claim.
    Marking it terminal frees the key immediately, and the caller gets a 503 it
    can act on. (reap_stuck_created is the backstop for the one case this cannot
    cover -- the API process dying between the insert and here.)"""
    try:
        path = await run_in_threadpool(stage_archive, job_id, raw)
    except SpoolFull as exc:
        await audit_job_repo.abandon_created(
            job_id=job_id, error_code="spool_full", error_message=str(exc))
        raise HTTPException(
            status_code=503,
            detail={"reason": "spool_full",
                    "detail": "the upload spool is full; retry shortly"},
        ) from exc
    except OSError as exc:
        await audit_job_repo.abandon_created(
            job_id=job_id, error_code="staging_failed",
            error_message=f"{type(exc).__name__}: {exc}")
        logger.exception("staging the upload for job %s failed", job_id,
                         extra={"step": "stage"})
        raise HTTPException(
            status_code=503,
            detail={"reason": "staging_failed",
                    "detail": "could not stage the upload; retry shortly"},
        ) from exc

    if not await audit_job_repo.mark_queued(job_id=job_id, source_ref=path):
        # The row left 'created' while we were writing -- only
        # reap_stuck_created does that, so the write took longer than its age
        # bound. Nothing will read the file now.
        await run_in_threadpool(cleanup_staged_archive, path)
        raise HTTPException(
            status_code=503,
            detail={"reason": "staging_failed",
                    "detail": "the job was abandoned while its upload was "
                              "being staged; please resubmit"},
        )
