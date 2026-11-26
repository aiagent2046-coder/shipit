"""Drydock API gateway — MVP phase 1 surface.

Only what exists today: health check and archive intake with validation,
rate limiting, stack detection, static scan, and (when providers are
configured) the LLM auth/security scan. Persistence and the queue come
next — the scan stage runs off the event loop in a threadpool for now,
since the LLM call alone can take up to ~2 minutes.
"""

from __future__ import annotations

import functools
import io
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager

import httpx
from fastapi import (
    Depends, FastAPI, Form, HTTPException, Request, UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from app import alerts, monitor
from app.service_flags import (  # noqa: F401  (re-exported for the test suite)
    _emergency_stop_active,
    _llm_paid_ops_enabled,
    _reset_service_flag_cache,
)
from app.audit_workflow import _AuditForm, _elapsed_ms, create_audit
from app.llm_budget import (  # noqa: F401  (re-exported for the test suite)
    DEFAULT_DAILY_SPEND_CAP_USD, _ANON_SPEND_ALERT_FRACTION,
    _anon_daily_cap_exceeded,
)
from app.accounts import (
    CSRF_HEADER,
    validate_api_key_pepper_configured,
)
from app.billing import telegram_stars
from app.ops_endpoints import router as ops_router
from app.routes.accounts import router as accounts_router
from app.routes.bank_transfer import router as bank_transfer_router
from app.routes.billing import router as billing_router
from app.routes.capabilities import router as capabilities_router
from app.routes.operator import router as operator_router
from app.routes.reads import router as reads_router
from app.routes.bundle_check import router as bundle_check_router
from app.routes.rls_check import router as rls_check_router
from app.routes.session import router as session_router
from app.routes.storefront import router as storefront_router
from app.routes.yookassa import router as yookassa_router
from app.db import (
    AuditRepository,
    FixOutcomeRepository,
    FixpackJobRepository,
    LlmUsageRepository,
    MonitoringRunRepository,
    PaymentRepository,
    ProcessorLockBusy,
    ServiceFlagsRepository,
    SubscriptionRepository,
    database_url_from_env,
    fixpack_processor_lock,
    monitoring_processor_lock,
)
from app.audit_history import refresh_cached_preview_history, ensure_paid_baseline
from app.sca.snapshot import baseline_is_current
from app.sca.refresh import inventory_payload
from app.deploypack import github_app
from app.deploypack.delivery import DeliveryError, render_pr_body
from app.deploypack.paid_delivery_auth import paid_delivery_token, get_paid_delivery_store
from app.deploypack.delivery_auth import (
    DeliveryAuthorizationError, authorize_repository_delivery, validate_delivery_token,
)
from app.deploypack.generate import UnsupportedForDeployPack
from app.deploypack.pipeline import WorkspaceTooLarge, run_deploy_pack
from app.deploypack.preview import PreviewRegistry
from app.fixpack.generate import (
    has_auto_fixable_findings,
    build_fixpack_plan,
    render_pr_body as render_fixpack_pr_body,
    render_pr_title as render_fixpack_pr_title,
)
from app.fixpack.gate import run_semantic_check
from app.proof import (
    decide_proof_gate,
    render_proof_markdown,
    run_proof_stage,
)
from app.ingest.github_fetch import RepoFetchError
from app.ingest.stack_detect import detect_stack
from app import sandbox_client
from app.sandbox_client import SandboxRunnerUnavailable
from app.llm.client import LLMClient
from app.log_context import log_context, set_log_context
from app.logging_config import configure_logging, environment_from_env
from app.monitor import (
    repo_url_from_full_name,
)
from app.monitor.diff import new_high_severity_findings
from app.ratelimit import RateLimitExceeded, RateLimitStoreError, RateLimiter
from app.scan_pipeline import (AUDIT_ENGINE_VERSION, BASIS_FULL,
                              LLM_FAILURE_BILLING, content_digest, llm_failure_kind, run_scan)
from app.ingest.validators import (
    MAX_ARCHIVE_BYTES,
    ArchiveValidationError,
    validate_zip,
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    configure_logging()
    # Fail fast if a DB-backed deployment is missing API_KEY_PEPPER: with the
    # DB configured, accounts are live and key hashing/lookup would be broken
    # (all Pro users locked out) without the pepper. A DB-less deployment
    # needs no pepper -- accounts are unusable there anyway.
    validate_api_key_pepper_configured(
        database_configured=bool(database_url_from_env())
    )
    yield


# The interactive schema is a development tool, not a public one. On any
# non-development deployment /docs, /redoc and /openapi.json are switched off:
# the source repository is public, so an attacker who reads it already knows
# the code, but a live, machine-readable inventory of every route and request
# shape on the running host is a different thing -- it is reconnaissance
# handed over pre-formatted, and it tracks the deployment rather than the
# repository.
#
# Keyed on ENVIRONMENT, the same variable /version and every JSON log record
# already report, so there is one notion of "which deployment is this" rather
# than a second flag that can disagree with it. It defaults to "development",
# which means a plain local run keeps the docs and only a deliberately
# configured deployment loses them -- the safe direction is the one that
# requires no action.
_DOCS_ENABLED = environment_from_env() == "development"

app = FastAPI(
    title="Drydock",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs" if _DOCS_ENABLED else None,
    redoc_url="/redoc" if _DOCS_ENABLED else None,
    openapi_url="/openapi.json" if _DOCS_ENABLED else None,
)


# Vercel preview deploys get unpredictable per-deploy subdomains
# (https://shipit-web-<hash>-<team>.vercel.app), so they can't be listed
# explicitly. Starlette matches this with fullmatch().
_VERCEL_PREVIEW_ORIGIN_REGEX = r"^https://[a-z0-9-]+\.vercel\.app$"


def configure_cors(target: FastAPI) -> None:
    """Register CORS from env so the browser frontend (separate Vercel
    deployment) can call this API. Env-driven, never hardcoded, and
    deny-by-default: an unset CORS_ALLOWED_ORIGINS allows NO cross-origin
    browser access rather than "*", because this API now takes an
    `Authorization: Bearer` key and a wildcard + credentials would let any
    site make credentialed calls.

    Reads env at call time (not import), so tests build a throwaway app
    with monkeypatched env and get a fresh config.

    - CORS_ALLOWED_ORIGINS: comma-separated exact origins (default none).
    - CORS_ALLOW_VERCEL_PREVIEWS: "true" opts in to matching any
      *.vercel.app origin via regex (default false — explicit, not
      silently always-on).

    Credentials are enabled only when at least one explicit origin exists
    or the Vercel-preview regex is on; never with "*". "*" is never passed
    to allow_origins, so Starlette always echoes the specific matched
    origin and the disallowed wildcard+credentials combination can't occur.
    """
    raw = os.environ.get("CORS_ALLOWED_ORIGINS") or ""
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    allow_previews = (os.environ.get("CORS_ALLOW_VERCEL_PREVIEWS") or "").lower() == "true"
    origin_regex = _VERCEL_PREVIEW_ORIGIN_REGEX if allow_previews else None

    target.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_origin_regex=origin_regex,
        allow_credentials=bool(origins) or allow_previews,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type", CSRF_HEADER, "X-GitHub-Token"],
        expose_headers=["Retry-After"],
    )


configure_cors(app)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Set baseline security headers on every response (JSON and HTML).

    Global here is safe: there is no iframe/WebApp embed of this backend
    anywhere, so X-Frame-Options: DENY breaks nothing. A strict CSP is
    deliberately NOT set globally — it would break Swagger UI (/docs) and
    ReDoc (/redoc), which load CDN JS and use inline scripts. CSP is scoped
    per-route to the self-contained HTML audit report instead.

    Cache-Control: private, no-store is also global. Every response this
    backend serves is dynamic and private — audit content and reports (gated
    by per-row access tokens), account info, and the one-time API-key reveal
    on the payment-poll endpoints. Nothing here should be cached by browsers
    or shared proxies. Static frontend assets are served by Vercel, not this
    backend, so a blanket no-store breaks no legitimate caching.
    """
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault(
        "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
    )
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "private, no-store")
    return response


REQUEST_ID_HEADER = "X-Request-ID"


def new_request_id() -> str:
    """The correlation id minted for one request.

    Short because a user reads it off an error page and types it into a
    support message.
    """
    return uuid.uuid4().hex[:12]


# Registered after add_security_headers, and app.middleware inserts at position
# 0, so this is the OUTERMOST user middleware: every other middleware and every
# route runs inside the context it establishes.
@app.middleware("http")
async def bind_request_context(request: Request, call_next):
    """Give each request a correlation id, in the log context and on the way out.

    The id is always minted here and an inbound X-Request-ID is deliberately
    IGNORED. This is a public API: a client-supplied value is attacker-controlled
    text that would land in every log line of the request (newlines and all) and
    could be set to another user's id to poison a support investigation. Echoing
    a header is not worth either. Clients that want their own correlation id can
    keep it and match on ours from the response.

    Every context field is bound here, not just the two with values, so the reset
    on the way out covers whatever a route added underneath (account_id,
    audit_id, job_id). Without that a value set in a handler would survive into
    the next request served on the same keep-alive connection, which is the worst
    kind of logging bug: plausible, wrong, and attributed to a real id.

    request.state carries the id as well, for the one reader that cannot see the
    contextvar -- see unhandled_exception_handler.
    """
    request_id = new_request_id()
    request.state.request_id = request_id
    with log_context(
        request_id=request_id,
        trace_id=request_id,
        account_id=None,
        audit_id=None,
        job_id=None,
    ):
        response = await call_next(request)
    response.headers[REQUEST_ID_HEADER] = request_id
    return response


# Dependency providers live in app/routes/dependencies.py. They are re-exported
# here because 38 test modules import them from app.main, and
# app.dependency_overrides keys on object identity -- importing the same
# function objects keeps every existing override working untouched.
#
# This is a compatibility layer, not a dependency of main.py itself: some names
# below are no longer used in this module (their handlers moved to app/routes/)
# and exist solely so `from app.main import ...` keeps resolving. `__all__`
# below tells ruff they are intentional re-exports rather than dead imports.
# Removing one is a breaking change for the test suite -- delete only together
# with the imports in tests/.
from app.github_repo import (  # noqa: E402
    _VALID_OWNER_REPO_SEGMENT,
    _parse_github_repo_url,
)
from app.routes._shared import (  # noqa: E402
    _client_key,
    _require_bearer_token,
    _secret_equals,
)
from app.routes.github import router as github_router  # noqa: E402
from app.routes.telegram import router as telegram_router  # noqa: E402
from app.mcp.server import router as mcp_router  # noqa: E402
from app.routes.dependencies import (  # noqa: E402
    get_account_repo,
    get_audit_job_repo,
    get_audit_repo,
    get_billing_transport,
    get_fix_outcome_repo,
    get_fixpack_repo,
    get_llm_client,
    get_llm_usage_repo,
    get_monitoring_repo,
    get_payment_repo,
    get_pr_opener,
    get_preview_reconciler,
    get_preview_registry,
    get_rate_limiter,
    get_repo_fetcher,
    get_service_flags_repo,
    get_subscription_repo,
)

# Names re-exported for the test suite, listed so a linter does not read them as
# dead imports. Keep in sync with the import block above.
__all__ = [
    "app",
    "_client_key",
    "_secret_equals",
    "get_account_repo",
    "get_audit_job_repo",
    "get_audit_repo",
    "get_billing_transport",
    "get_fix_outcome_repo",
    "get_fixpack_repo",
    "get_llm_client",
    "get_llm_usage_repo",
    "get_monitoring_repo",
    "get_payment_repo",
    "get_pr_opener",
    "get_preview_reconciler",
    "get_preview_registry",
    "get_rate_limiter",
    "get_repo_fetcher",
    "get_service_flags_repo",
    "get_subscription_repo",
]










async def _record_llm_usage(
    llm_usage_repo: LlmUsageRepository, *, job_type: str,
    job_id: str | None, account_id: str | None, llm_stats: object,
    audit_job_id: str | None = None,
) -> None:
    """Write ONE llm_usage row per job attempt that contacted a provider.

    `llm_stats` is run_scan()["llm_usage"] -- the accounting key, not the `llm`
    diagnostic key. The distinction is the whole point: `llm` degrades to the
    string "failed: ..." when a provider dies mid-scan, and reading spend off it
    silently discarded every token the calls before that failure had already
    paid for. `llm_usage` carries successful-completion totals and provider
    attempts. The latter includes billed empty answers and timeouts with
    unknown charges, even when no .complete() call succeeded.

    Callers must invoke this on the FAILURE path too, passing job_id=None when
    no audits row exists to point at. Spend is a fact about the provider's
    ledger, not about whether we managed to save the result: an attempt that
    scanned and then lost its database is money gone, and a job that
    dead-letters after three such attempts cost three scans.

    `audit_job_id` is the audit_jobs row this attempt belongs to. Rows accumulate
    per attempt under it, so the cost of a job is their SUM -- see
    LlmUsageRepository.sum_by_audit_job.

    The reused-audit (content-hash cache hit) path never reaches this: it
    returns before run_scan is ever called, so a cache hit costs $0 and writes
    no row -- there is no double-charge for re-auditing identical content.

    Recording is best-effort and must never break the audit it is accounting
    for: llm_usage_repo.create no-ops (returns None) when DATABASE_URL isn't set,
    and any unexpected write failure is logged, not raised."""
    if not isinstance(llm_stats, dict):
        return
    try:
        from app.llm.accounting import estimate_stats_cost, provider_usage_summary

        calls = int(llm_stats.get("calls") or 0)
        try:
            provider_usage = provider_usage_summary(llm_stats.get("provider_attempts") or [])
        except Exception:  # noqa: BLE001 -- additive metadata must not discard legacy spend
            logger.warning("Invalid provider usage metadata for %s job %s", job_type, job_id)
            provider_usage = None
        if calls <= 0 and provider_usage is None:
            return
        input_tokens = int(llm_stats.get("input_tokens") or 0)
        output_tokens = int(llm_stats.get("output_tokens") or 0)
        model = llm_stats.get("model") or "unknown"
        cost = estimate_stats_cost(llm_stats)
        await llm_usage_repo.create(
            job_type=job_type, job_id=job_id, account_id=account_id,
            model=model, calls=calls, input_tokens=input_tokens,
            output_tokens=output_tokens, cost_usd=cost,
            audit_job_id=audit_job_id,
            **({"provider_usage": provider_usage} if provider_usage is not None else {}),
        )
    except Exception:  # noqa: BLE001 -- accounting must never fail the audit
        logger.warning("llm_usage recording failed for %s job %s",
                       job_type, job_id, exc_info=True)


# --- Stage 4 step 2: enforcement (daily cap, emergency stop) -----------------

# Daily USD backstop over ALL anonymous/free traffic (llm_usage rows with
# account_id IS NULL, summed since UTC midnight). NOT per-IP -- that is the
# request-count rate limiter's job -- and NOT a personal limit: it is a ceiling
# on total free spend. Crossing it soft-degrades new anonymous audits to
# static-only (same path as a provider failure), never a 402/429: an anonymous
# caller has nothing to pay. Pro accounts are deliberately NOT subject to this;
# their spend is bounded by PRO_DAILY_AUDIT_LIMIT (a call count) instead.










async def _run_scan_offthread(*args, **kwargs):
    """run_scan on the threadpool: it is blocking, and its LLM stage can take
    minutes, so it must never occupy the event loop.

    It used to also hold an AUDIT_CONCURRENCY semaphore. That semaphore is gone
    with the queue cutover: the number of scans that can run at once is now
    AUDIT_WORKER_CONCURRENCY, the audit worker's slot count, and a limit living
    in a different process from the work it is supposed to limit is not a limit.
    In this process only the monitoring drain still scans, and that drain is
    strictly one run at a time under monitoring_processor_lock, so it could
    never have reached a bound of 4 anyway.

    Still a named wrapper rather than an inline run_in_threadpool because it is
    the single definition of "how an audit scan is run", shared by the worker
    (which imports it) and the monitoring path -- the two must not drift."""
    return await run_in_threadpool(run_scan, *args, **kwargs)








async def run_repo_audit(
    repo_url: str, *, llm_client: LLMClient, audit_repo: AuditRepository,
    repo_fetcher, llm_usage_repo: LlmUsageRepository | None = None,
    job_type: str = "audit", zip_bytes: bytes | None = None,
) -> dict | None:
    """Fetch a public GitHub repo, audit it, and persist -- reusing the exact
    pipeline the POST /v1/audits URL path uses: the same content-hash cache
    (get_by_content_hash), the same run_scan, the same AUDIT_ENGINE_VERSION and
    AuditRepository.create. Returns {audit_id, findings, repo_url, reused} or
    None when there is nothing to audit (unfetchable-as-zip content, or a stack
    the MVP doesn't support).

    Used by the continuous-monitoring push webhook. It is a separate function
    from create_audit rather than a shared refactor of it on purpose:
    create_audit interleaves tier resolution, per-account daily quota, and HTTP
    error shaping that the internal monitoring trigger has no business running.
    What must be shared for cost and consistency -- one cache, one scan, one
    engine version -- is shared by calling the same primitives here.

    The cost guard lives in that shared cache: byte-identical repo content
    (nothing changed since the last audit) is a cache hit that returns the prior
    audit with NO LLM call, so a push that didn't change the audited content is
    free and produces an empty findings diff. RepoFetchError propagates to the
    caller (e.g. a repo that went private -> 404, indistinguishable by design;
    see app/ingest/github_fetch.py).

    `zip_bytes`, when given, is used instead of fetching: the paid Fix Pack
    path has the archive in hand already, and re-downloading it would not only
    waste the round trip but could pick up a push that landed in between --
    leaving the review describing code the fix was not built against, and a
    content_hash that disagrees with the plan. Same bytes, one fetch, two uses.
    """
    parsed = _parse_github_repo_url(repo_url)
    if parsed is None:
        return None
    owner, repo = parsed
    raw = (zip_bytes if zip_bytes is not None
           else await run_in_threadpool(repo_fetcher, owner, repo))
    buf = io.BytesIO(raw)
    try:
        report = validate_zip(buf, size_bytes=len(raw))
    except ArchiveValidationError:
        return None
    buf.seek(0)
    # Recorded, not refused -- same reasoning as the upload intake below.
    # A monitored repository whose stack the detector cannot name still gets
    # a real audit on every push; silently returning None here meant its
    # owner had a monitoring subscription that quietly never reported.
    stack = detect_stack(buf)

    digest = content_digest(raw)
    # BASIS_FULL, not the caller's tier: this path always runs the LLM stage
    # (see _run_scan_offthread below, called with no llm_skip_reason), so a
    # static-only row is not a valid result for it to reuse.
    cached = await audit_repo.get_by_content_hash(
        digest, AUDIT_ENGINE_VERSION, BASIS_FULL)
    if cached is not None:
        cached = await refresh_cached_preview_history(audit_repo, cached)
        if baseline_is_current(cached["score_json"]):
            return {
                "audit_id": cached["id"],
                "findings": cached["findings_json"] or [],
                "repo_url": cached.get("repo_url"),
                "access_token": cached.get("access_token"),
                # Always BASIS_FULL here -- that is what the lookup asked for --
                # but reported anyway so callers never have to know that.
                "basis": (cached.get("score_json") or {}).get("basis"),
                "reused": True,
            }

    scan = ({"score": cached["score_json"], "findings": cached["findings_json"] or [],
             "llm": {}, "llm_usage": {"calls": 0}} if cached else
            await _run_scan_offthread(raw, llm_client))
    # No sca_client here on purpose, and not because this path is unpaid: it
    # audits at BASIS_FULL for paying subscribers. It has no account context --
    # `account_id is None` immediately below, because these are system
    # re-audits -- so this trigger does not authorize a new dependency lookup.
    # Fresh scans here store no inventory. When reusing an existing answer,
    # preserve its inventory so that the refresh sweep can still update it.
    await _alert_llm_stage_failed(scan["llm"])
    # Cost accounting. account_id is None: this path serves system re-audits
    # (continuous monitoring), whose LLM cost is incurred once per push
    # regardless of how many subscribers watch the repo -- attributing it to any
    # single subscriber would be wrong, so it is recorded unattributed.
    # audit_job_id is None too: monitoring runs have their own table and never
    # pass through the audit_jobs queue.
    #
    # The scan above already spent the money, so the row is written whatever
    # audit_repo.create does next -- including raise, which is why this is a
    # try/except/else rather than a line after the call.
    try:
        async def record_preview(usage):
            if llm_usage_repo is not None:
                await _record_llm_usage(llm_usage_repo, job_type=job_type, job_id=None,
                                       account_id=None, llm_stats=usage)
        scan["score"] = await ensure_paid_baseline(
            audit_repo, scan, raw, llm_client, digest, AUDIT_ENGINE_VERSION,
            runner=_run_scan_offthread, record_usage=record_preview)
        if cached:
            scan["score"] = {**scan["score"], "analysis_reused_from":
                             scan["score"].get("analysis_reused_from") or str(cached["id"])}
        persisted = await audit_repo.create(
            stack=stack.value, file_count=report.file_count,
            score_total=scan["score"]["total"], score_json=scan["score"],
            findings_json=scan["findings"], repo_url=repo_url,
            content_hash=digest, engine_version=AUDIT_ENGINE_VERSION,
            # Preserve the original dependency answer when only its free
            # baseline was missing. A newly skipped check has no inventory.
            dependency_inventory=(cached.get("dependency_inventory") if cached else
                                  inventory_payload(raw, (scan.get("sca") or {}).get("asked_at"))),
        )
    except Exception:
        if llm_usage_repo is not None:
            await _record_llm_usage(
                llm_usage_repo, job_type=job_type, job_id=None,
                account_id=None, llm_stats=scan["llm_usage"],
            )
        raise
    audit_id = persisted["id"] if persisted else str(uuid.uuid4())
    if llm_usage_repo is not None:
        await _record_llm_usage(
            llm_usage_repo, job_type=job_type,
            job_id=persisted["id"] if persisted else None,
            account_id=None, llm_stats=scan["llm_usage"],
        )
    return {
        "audit_id": audit_id,
        "findings": scan["findings"],
        "repo_url": repo_url,
        "access_token": persisted.get("access_token") if persisted else None,
        # Reported because it can be static_only even here: run_scan catches
        # LLMError and degrades rather than raising, so a provider failure
        # mid-audit produces a persisted static-only row. A caller that sells
        # depth has to be able to tell that apart from success.
        "basis": (scan["score"] or {}).get("basis"),
        "reused": False,
    }





# Fix Pack processor lease tuning. A 'running' job whose lease is older
# than STALE_LEASE_MINUTES is treated as a crashed worker and reaped; a
# real generation (repo fetch + plan + Docker semantic check + PR) is
# minutes, so 15 is comfortably above the worst case. MAX_JOB_ATTEMPTS
# bounds re-queues so a poison-pill job that crashes the worker every time
# lands in 'failed' rather than looping forever. See PHASE3_QUEUE_PLAN.md.
STALE_LEASE_MINUTES = 15
MAX_JOB_ATTEMPTS = 3
# Operator page when a paid job has been waiting longer than this.
# Above the 2-minute fixpack timer and the 15-minute stale lease so
# a healthy backlog that is merely working its way down does not page;
# a silent processor (timer stopped, lock stuck, runner always down)
# does. Throttle is longer than the check interval — see the helper.
PAID_BACKLOG_ALERT_SECONDS = 20 * 60
PAID_BACKLOG_ALERT_THROTTLE_SECONDS = 30 * 60


def _fixpack_process_token() -> str | None:
    """Bearer token protecting POST /internal/fixpack/process-paid, same
    env-var pattern as PREVIEW_REAP_TOKEN / USDT_POLL_TOKEN. Unset -> the
    endpoint 503s rather than accept a no-op auth check."""
    return os.environ.get("FIXPACK_PROCESS_TOKEN") or None


def _monitoring_process_token() -> str | None:
    """Bearer token protecting POST /internal/monitoring/process-pending, same
    env-var pattern as FIXPACK_PROCESS_TOKEN. Unset -> the endpoint 503s rather
    than accept a no-op auth check."""
    return os.environ.get("MONITORING_PROCESS_TOKEN") or None


























@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Single catch-all for genuinely *unhandled* server errors (a bug, not
    control flow). Starlette routes only exceptions that aren't an
    HTTPException here, so the intentional 422/404/503/401 responses raised
    across the API stay normal control flow and never alert.

    The id in the log line, the operator alert and the response body is the one
    bind_request_context minted, so "I got error abc123" ties to every line of
    that request rather than to this handler alone. The alert is best-effort and
    deduped so a crash-loop can't spam the operator.

    It is read off request.state and not the contextvar, because this handler is
    the one place in the process that cannot see the contextvar: Starlette runs
    an Exception handler in ServerErrorMiddleware, which sits OUTSIDE the user
    middleware stack, so by the time the exception reaches here
    bind_request_context's `with` block has already reset the context. The scope
    dict travels with the request instead of with the context, so it survives.
    The same ordering is why this response sets the header itself -- it never
    passes back through the middleware that would otherwise add it."""
    request_id = getattr(request.state, "request_id", None)
    logger.exception(
        "unhandled error [request_id=%s] %s %s",
        request_id, request.method, request.url.path,
    )
    await alerts.notify_operator(
        f"Drydock: unhandled 5xx [{request_id}] on {request.method} "
        f"{request.url.path} — {type(exc).__name__}",
        dedupe_key=f"unhandled-5xx:{request.url.path}:{type(exc).__name__}",
    )
    return JSONResponse(
        status_code=500,
        content={"detail": {"reason": "internal_error", "request_id": request_id}},
        headers={REQUEST_ID_HEADER: request_id} if request_id else None,
    )


@app.exception_handler(RateLimitStoreError)
async def rate_limit_store_handler(
    request: Request, exc: RateLimitStoreError
) -> JSONResponse:
    """Rate-limit store (Redis) outage — deliberate fail-closed control flow.

    The request is DENIED with an explicit 503 whose reason mirrors the
    queue_unavailable convention, so a Redis blip reads as "try again later",
    not as an application bug. Registered for RateLimitStoreError specifically:
    that routes it through the in-stack exception middleware (the request-id
    header is added on the way out) and keeps it away from
    unhandled_exception_handler's operator alert — otherwise an outage would
    page the operator on every request for as long as it lasts.
    """
    logger.warning(
        "rate limit store unavailable [request_id=%s] %s %s: %s",
        getattr(request.state, "request_id", None),
        request.method,
        request.url.path,
        exc,
    )
    return JSONResponse(
        status_code=503,
        content={
            "detail": {
                "reason": "rate_limit_unavailable",
                "detail": "rate limit store unreachable; request denied "
                          "(fail-closed), retry shortly",
            }
        },
    )









































async def _process_one_monitoring_run(
    run: dict, *, monitoring_repo: MonitoringRunRepository,
    subscription_repo: SubscriptionRepository, audit_repo: AuditRepository,
    llm_client: LLMClient, repo_fetcher, transport,
    llm_usage_repo: LlmUsageRepository,
) -> str:
    """Do the real monitoring work for one claimed run: re-audit the repo, diff
    against its previous audit, and DM every active subscriber the NEW
    critical/high findings. Returns the outcome ('notified', 'no_new',
    'unfetchable', 'unauditable', 'no_subscription', or 'failed') and advances
    the run to a terminal state so a re-run of the processor doesn't pick it up
    again.

    This is the slow half lifted verbatim from the old synchronous
    _handle_monitoring_push, now off the HTTP path. The diff is taken against
    the latest completed audit of the SAME repo captured BEFORE run_repo_audit
    persists this run's audit, so a subscriber is told only about findings that
    are newly present (new_high_severity_findings, keyed on rule_id+file).

    Every failure is made visible (mark_failed with a diagnosable error + a
    logged traceback), the same hardening as _process_one_paid_job -- a 'failed'
    run must never be silent. A caught failure is terminal; only a true crash
    (the run left stuck 'running') is recovered by the stale-lease reaper."""
    run_id = run["id"]
    repo_full_name = run["repo_full_name"]
    # Same ambient-context binding _process_one_paid_job does, for the same
    # reason: this is the other durable queue, and its drain loop is the only
    # place that knows which run the lines below belong to. Bare set (not
    # log_context()) matches that function -- the loop is sequential, so each
    # claimed run overwrites the previous one's ids rather than nesting.
    set_log_context(job_id=str(run_id))
    try:
        subs = await subscription_repo.list_active_for_repo(repo_full_name)
        if not subs:
            # Every subscription lapsed between enqueue and now -- nothing to
            # notify. Benign; close the run out.
            await monitoring_repo.mark_done(run_id)
            return "no_subscription"

        # Baseline BEFORE the new audit persists, so the diff reflects only what
        # this push introduced.
        # BASIS_FULL: this path re-audits at full depth, so only full prior
        # audits are a comparable baseline. A free static-only row in the
        # baseline would make every LLM finding look newly appeared.
        #
        # The UNION of prior audits, not the latest one. A single-pass scan is
        # a sample: measured on four same-engine runs of unchanged code
        # (2026-08-18), high-severity keys reproduce at ~65-84% and one real
        # critical showed in 2 of 4 -- against a latest-only baseline, about
        # every third high on a re-audit would DM the subscriber as "new"
        # with nothing pushed. Seen in ANY prior audit means not news.
        prior = await audit_repo.list_findings_by_repo_url(
            repo_full_name, BASIS_FULL)
        previous_findings = [f for findings in prior for f in findings]

        try:
            result = await run_repo_audit(
                repo_url_from_full_name(repo_full_name), llm_client=llm_client,
                audit_repo=audit_repo, repo_fetcher=repo_fetcher,
                llm_usage_repo=llm_usage_repo, job_type="monitoring",
            )
        except RepoFetchError:
            # Repo went private/was deleted (404, indistinguishable by design).
            # Benign terminal state; the interval claim already stopped
            # re-enqueues.
            await monitoring_repo.mark_done(run_id)
            return "unfetchable"

        if result is None:
            await monitoring_repo.mark_done(run_id)
            return "unauditable"

        # The audit this run produced (or reused from the content-hash cache).
        # run_repo_audit doesn't bind it, so without this the notify half of the
        # run can't be joined to the audit it is diffing.
        set_log_context(audit_id=str(result["audit_id"]))

        new_findings = new_high_severity_findings(
            previous_findings, result["findings"]
        )
        notified = 0
        if new_findings:
            token = telegram_stars.bot_token_from_env()
            text = _monitoring_alert_text(repo_full_name, new_findings)
            for sub in subs:
                chat_id = sub.get("telegram_chat_id") or sub.get("telegram_user_id")
                if not (chat_id and token):
                    continue
                try:
                    await telegram_stars.send_message(
                        str(chat_id), text, token=token, transport=transport
                    )
                    notified += 1
                except Exception:  # noqa: BLE001 -- one bad DM must not abort the rest
                    logger.warning("monitoring alert send failed", exc_info=True)

        await monitoring_repo.mark_done(run_id)
        return "notified" if new_findings else "no_new"
    except Exception as exc:  # noqa: BLE001 -- every failure must be recorded
        # Fetch/audit/persist/notify errors land here. Log the full traceback
        # and persist a short reason so the failure is diagnosable from both the
        # logs and a `select ... from monitoring_runs` query -- never silent.
        logger.exception("monitoring run %s failed during processing", run_id)
        await monitoring_repo.mark_failed(run_id, _failure_detail(exc))
        return "failed"


def _monitoring_alert_text(repo_full_name: str, new_findings: list[dict]) -> str:
    """One DM summarizing the new critical/high findings from a monitored push.
    Lists up to a handful by rule/file so the subscriber knows what changed
    without us dumping an unbounded wall of text."""
    n = len(new_findings)
    lines = [
        f"⚠️ Continuous monitoring: {n} new "
        f"critical/high finding{'s' if n != 1 else ''} in {repo_full_name}",
        "",
    ]
    shown = new_findings[:10]
    for f in shown:
        sev = (f.get("severity") or "").upper()
        rule = f.get("rule_id") or "?"
        path = f.get("file") or "?"
        lines.append(f"• [{sev}] {rule} — {path}")
    if n > len(shown):
        lines.append(f"… and {n - len(shown)} more")
    return "\n".join(lines)



















def _reject_if_nothing_to_fix(audit: dict) -> None:
    """409 when this audit has no finding a Fix Pack could ever rewrite.

    Every rule the Fix Pack knows is fixed; every other finding is advice. An
    audit whose findings contain none of them has an empty plan before a
    customer pays, and no amount of running the job changes that.

    Audit 05fa18f5 was sold one anyway: zero eligible findings, job ran, payer
    got "Nothing to auto-fix" and was charged for it. The check needs no
    network and no LLM -- only the findings already stored on the audit.

    Deliberately one-directional. It proves "definitely nothing to fix" and
    never claims the opposite: a finding eligible here can still fall away
    when the repository is re-fetched, because the code may have moved since
    the audit. Refusing on the certain case is worth doing; promising a pull
    request is not something this can honestly do.
    """
    if not has_auto_fixable_findings(audit.get("findings_json") or []):
        raise HTTPException(
            status_code=409,
            detail={"reason": "no_auto_fixable_findings",
                    "detail": "This audit has no findings a Fix Pack can fix "
                              "automatically \u2014 the ones it found are "
                              "recommendations, or live in comments, docs or "
                              "tests. Buying one would produce an empty pull "
                              "request, so it isn't offered."},
        )


async def _reject_if_fixpack_already_live(fixpack_repo, audit_id: str) -> None:
    """409 when this audit already has a Fix Pack job that is paid or running.

    Selling one is the last moment refusing costs nothing. After the payment,
    every layer below reports success and none of them can undo it:
    create_paid is idempotent per audit, so a second confirmed payment joins
    the existing job instead of opening a second fix PR, and the buyer is told
    "completed" for work that was already bought and paid for once.

    The condition mirrors the ON CONFLICT predicate in create_paid --
    status in ('paid', 'running', 'awaiting_authorization') -- and must keep mirroring it. A stricter
    check here would refuse sales the database would have happily served:
    re-buying after a 'failed' job is a supported flow, and so is buying again
    once a previous Fix Pack was delivered and the audit re-run.

    get_by_audit returns the newest job, which is enough: migration 0025's
    partial unique index allows only one live job per audit, so a newer
    terminal row can only exist if no live one does.

    No-op when persistence isn't configured (get_by_audit returns None), same
    contract as every other repository call on this path.
    """
    job = await fixpack_repo.get_by_audit(audit_id)
    if job is None or job.get("status") not in ("paid", "running", "awaiting_authorization"):
        return
    raise HTTPException(
        status_code=409,
        detail={
            "reason": "fixpack_already_in_progress",
            "detail": "a Fix Pack for this audit has already been paid for "
                      "and is being generated. Watch this audit's page for "
                      "the pull request — buying a second one would fund no "
                      "extra work.",
        },
    )






async def _resolve_pr_token(owner: str, repo: str) -> str | None:
    """The token delivery.open_pull_request should use for owner/repo: a
    GitHub App installation token when the App is configured (works for any
    repo the App is installed on), else None so delivery falls back to the
    single-operator GITHUB_PR_TOKEN. This resolver is for the asynchronous
    paid processor; public Deploy Pack delivery instead uses only its caller's
    request-scoped credential (see docs/deploy-pack-delivery-access.md)."""
    app_creds = github_app.app_credentials_from_env()
    # Diagnostic for the "no GitHub token configured" incident: when App
    # creds look present in the process env yet resolution still yields no
    # token, this pins down whether os.environ actually carries them at
    # call time. Presence/length only — never the secret values.
    #
    # Only the contradiction is a warning. Resolving a token is the healthy
    # path and running with no App configured at all is a supported one (the
    # GITHUB_PR_TOKEN fallback in the docstring), so both log at debug — this
    # fires on every PR delivery and used to warn unconditionally. Both PEM
    # variables are counted, because a deployment on the base64 path has
    # GITHUB_APP_PRIVATE_KEY unset and is perfectly healthy.
    app_id_env = os.environ.get("GITHUB_APP_ID")
    pem_env = (os.environ.get("GITHUB_APP_PRIVATE_KEY")
               or os.environ.get("GITHUB_APP_PRIVATE_KEY_B64"))
    log = (logger.warning
           if app_creds is None and (app_id_env or pem_env)
           else logger.debug)
    log(
        "PR token resolve for %s/%s: GITHUB_APP_ID=%s, "
        "GITHUB_APP_PRIVATE_KEY=%s, github_app.app_credentials_from_env=%s",
        owner, repo,
        len(app_id_env) if app_id_env else "MISSING",
        len(pem_env) if pem_env else "MISSING",
        "None" if app_creds is None else "present",
    )
    if app_creds is None:
        return None
    app_id, private_key = app_creds
    return await run_in_threadpool(
        github_app.installation_token_for_repo, owner, repo,
        app_id=app_id, private_key=private_key,
    )


def _failure_detail(exc: BaseException, *, limit: int = 300) -> str:
    """A short, secret-free description of a failure for the fixpack_jobs
    `detail` column: exception type + message, truncated. Never carries a
    secret value — the generation pipeline never puts one in an exception,
    but truncation is a second guard against an over-long message."""
    detail = f"{type(exc).__name__}: {exc}".strip()
    return detail[:limit]


async def _announce_nothing_to_fix(
    payment_repo, *, job: dict, audit_id: str,
) -> None:
    """Tell the buyer, and the operator, that a paid Fix Pack changed nothing.

    THIS BRANCH USED TO BE SILENT. It wrote a status, recorded an outcome and
    returned; the payer heard nothing and neither did the operator, so the
    money simply stayed. Two real payments ended here on 2026-08-25, twenty
    minutes after a confirmation email promising "you will hear again when it
    lands or if it cannot finish".

    THE OPERATOR IS PAGED EVEN IF THE CUSTOMER CANNOT BE REACHED, and that
    ordering is the point: a refund is sent by a person, and the alert is the
    only thing that starts one. Writing to the customer first and letting a
    failure there skip the alert would reproduce the silence in a smaller way.

    THE BUYER IS FOUND THROUGH THE JOB, NEVER THROUGH THE AUDIT. The first
    version of this looked up the newest Fix Pack order on the audit, which is
    the same audit several jobs and several orders can share -- so on an audit
    bought twice it would have written to one buyer twice and to the other not
    at all. Migration 0035 records which order bought which job.

    When that link is missing the operator is paged WITHOUT an order number and
    the customer is not written to at all. A refund still gets started, by a
    person who can read the books; guessing which of several orders to name
    would put "we are refunding you" in front of somebody who is owed nothing,
    which is worse than the silence this function exists to end.

    Best-effort throughout. The job has already finished; an exception escaping
    here would turn a completed run into a 'failed' one and re-queue work that
    correctly found nothing to do.
    """
    job_id = job.get("id")
    reference = None
    payment = None
    try:
        payment = await payment_repo.get_completed_fixpack_for_job(str(job_id))
        reference = (payment or {}).get("external_ref")
    except Exception:  # noqa: BLE001
        logger.warning("could not look up the payer for job %s",
                       job_id, exc_info=True)

    if payment is None:
        await alerts.notify_operator(
            f"Drydock: Fix Pack {job_id} found nothing to change, and it was "
            f"paid for — but its order could not be identified, so nobody has "
            f"been told. Find the order on audit {audit_id} and refund it by "
            "hand. The buyer has NOT heard from us.",
            dedupe_key=f"fixpack-nothing-to-fix:{job_id}",
        )
        return

    await alerts.notify_operator(
        f"Drydock: Fix Pack {job_id} found nothing to change, and the "
        f"buyer paid for it. Order {reference} — "
        "send the refund. The audit's findings were probably fixed between "
        "the audit and the purchase.",
        dedupe_key=f"fixpack-nothing-to-fix:{job_id}",
    )

    from app.notify import messages
    from app.notify.router import Contact, notify_customer

    locale = payment.get("payer_locale")
    try:
        await notify_customer(
            contact=Contact.from_payment(payment),
            subject=messages.nothing_to_fix_subject(locale=locale),
            body=messages.nothing_to_fix_body(
                reference=str(reference or ""), locale=locale),
            reference=str(reference or ""),
            locale=locale,
        )
    except Exception:  # noqa: BLE001
        logger.warning("could not tell the payer their Fix Pack changed "
                       "nothing", exc_info=True)


async def _alert_fixpack_failed(job_id, detail: str) -> None:
    """Push one best-effort operator alert for a Fix Pack job that landed on
    'failed' (a paying customer's PR silently not opening is exactly the
    "learn about it manually" pain this phase targets). The detail is already
    secret-free (see `_failure_detail`). Per-job dedupe key so a crash-loop on
    one job can't spam, but distinct jobs each notify. Never raises —
    `notify_operator` swallows its own errors."""
    await alerts.notify_operator(
        f"Drydock: Fix Pack job {job_id} failed — {detail}",
        dedupe_key=f"fixpack-failed:{job_id}",
    )


async def _alert_llm_stage_failed(llm_summary: object) -> None:
    """One operator alert when the LLM stage lost the provider, or nothing.

    The audit still completes, still persists, and still returns 200 -- with
    three of six categories unexamined and a total that reads higher than the
    truth. That silence is the whole problem: on 2026-08-12 two paid audits
    came back at 9.7 within three minutes of each other and were found only
    because someone happened to be running one of them by hand.

    Deduped on the KIND, not the job. A dead provider fails every audit, so a
    per-job key would page once per submission for one cause -- the same
    reasoning as the GitHub App alert below. The text names the remedy rather
    than the symptom, because the useful thing to know is not that an audit
    degraded, it is that every audit will keep degrading until someone acts.
    """
    kind = llm_failure_kind(llm_summary)
    if kind is None:
        return

    if kind == LLM_FAILURE_BILLING:
        await alerts.notify_operator(
            "Drydock: the LLM provider is REFUSING CALLS FOR NON-PAYMENT. "
            "Every audit from now on silently degrades to static-only — it "
            "still returns 200, still says succeeded, and reports a HIGHER "
            "score with Auth, Money & Data and Frontend unexamined. Top up "
            "the provider account.",
            dedupe_key="llm-provider-billing",
        )
        return

    await alerts.notify_operator(
        "Drydock: the LLM provider is failing; audits are degrading to "
        "static-only and reporting higher scores than the code deserves. "
        f"Usually transient. {llm_summary}",
        dedupe_key="llm-provider-failure",
    )


async def _alert_github_app_auth_failed(detail: str) -> None:
    """One operator alert for a broken GitHub App credential.

    Deduped on the deployment, NOT on the job: the key is either right or
    wrong for everyone, so alerting per job would page once per queued Fix
    Pack for a single cause. The text names the cause and the file to edit,
    because the useful thing to know at 3am is not that a job failed -- it is
    that no Fix Pack on this deployment can be delivered until .env changes.
    """
    await alerts.notify_operator(
        "Drydock: GitHub App credentials REJECTED — no Fix Pack can open a "
        f"PR on this deployment until this is fixed. {detail} — check "
        "GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY_B64 in .env; the 401 log "
        "line carries a public-key fingerprint to compare against the App's "
        "registered key. Affected jobs are queued, not lost.",
        dedupe_key="github-app-auth-rejected",
    )


def _rule_ids_from_plan(plan) -> list[str]:
    """The deduplicated, sorted rule_ids a Fix Pack plan actually fixes --
    across both secret_fixes and config_fixes (one plan fixes many findings).
    Skipped findings (no longer matching on re-fetch) are not "fixed" and are
    excluded. Empty when there is no plan or nothing to fix."""
    if plan is None:
        return []
    return sorted(
        {f.rule_id for f in plan.secret_fixes}
        | {f.rule_id for f in plan.config_fixes}
    )


async def _record_fix_outcome(
    fix_outcome_repo: FixOutcomeRepository, *, job: dict, outcome: str,
    rule_ids: list[str], is_regression: bool, pr_url: str | None,
) -> None:
    """Best-effort write to the fix_outcomes knowledge base. Analytics is
    strictly secondary to the product: a failure here (bad connection, schema
    drift) must be logged, never raised into the delivery path, so a bookkeeping
    error can't turn a delivered PR into a 'failed' job. No-ops silently when
    DATABASE_URL isn't set (the repo returns None)."""
    try:
        await fix_outcome_repo.record(
            fixpack_job_id=job.get("id"),
            audit_id=job.get("audit_id"),
            rule_ids=rule_ids,
            stack=job.get("stack") or "unknown",
            outcome=outcome,
            is_regression=is_regression,
            pr_url=pr_url,
        )
    except Exception:  # noqa: BLE001 — analytics must never break delivery
        logger.exception(
            "Failed to record fix_outcome for job %s (outcome=%s)",
            job.get("id"), outcome,
        )


# What a Fix Pack buyer gets on top of the fix: one full-depth review of the
# same code, which the free static-only audit does not include. Delivered as a
# link in the PR body, with the audit row's own token -- GET /v1/audits/{id}
# authorises on it, so a bare URL would 404 (the defect that was #187).
_REVIEW_JOB_TYPE = "fixpack_review"


async def _deep_review_section(
    repo_url: str, zip_bytes: bytes, *, llm_client: LLMClient,
    audit_repo: AuditRepository, repo_fetcher,
    llm_usage_repo: LlmUsageRepository | None,
) -> str | None:
    """Run the full audit the buyer just paid for and return the PR section
    linking it, or None if it could not be produced.

    Placed after the semantic check and before the PR is composed, so the LLM
    is only paid for on jobs that are actually about to deliver: an empty plan
    or a blocked fix returns earlier and spends nothing.

    A NEW audit row, never an upgrade of the buyer's original: the free audit's
    archive is long gone (audit_spool cleans up), the Fix Pack works from a
    fresh copy, and writing findings from these bytes onto that row would leave
    its content_hash describing bytes that no longer match -- and that hash is
    the whole cache key.

    No leak: the row is `static+llm`, and anonymous callers ask the cache for
    `static_only`, so they cannot match it. run_repo_audit checks the full-basis
    cache first, so a second buyer of byte-identical content pays no LLM cost.

    Returns None rather than raising: the fix is already generated and verified,
    and losing a working PR because a bonus review failed would be the worse
    trade. The caller alerts instead.
    """
    result = await run_repo_audit(
        repo_url, llm_client=llm_client, audit_repo=audit_repo,
        repo_fetcher=repo_fetcher, llm_usage_repo=llm_usage_repo,
        job_type=_REVIEW_JOB_TYPE, zip_bytes=zip_bytes,
    )
    if result is None:
        return None
    if result.get("basis") != BASIS_FULL:
        # run_scan catches LLMError and degrades to static-only instead of
        # raising -- a 402 or a timeout mid-audit lands here with a persisted
        # static-only row. Linking that as "your full review" would be exactly
        # the false claim this feature exists to stop making, so treat it as a
        # failed review: the caller alerts and the fix still ships.
        logger.warning(
            "Fix Pack deep review degraded to %s; not advertising it as the "
            "full review", result.get("basis"),
        )
        return None
    audit_id, access_token = result["audit_id"], result.get("access_token")
    if not audit_id or not access_token:
        # Without the token the link is a 404. Say nothing rather than hand a
        # paying customer a dead URL -- same rule as the payment confirmation.
        return None
    link = (f"{telegram_stars.SITE_URL}/audit/{audit_id}"
            f"?token={access_token}")
    return (
        "### Your full review\n\n"
        "The free audit includes static checks and a limited model security "
        "preview when available. This review adds broader model analysis of "
        "authentication, access rules and security risks in selected code. "
        "The report states its source coverage and verification limits; it "
        "does not establish that every file or vulnerability was covered:\n\n"
        f"{link}\n\n"
        "It was run against the code fetched for this pull request, so it "
        "reflects your repository as it is now, not as it was when you first "
        "audited it. Keep the link: it is the only way in, and we cannot "
        "reissue it."
    )


async def _process_one_paid_job(
    job: dict, *, audit_repo: AuditRepository,
    fixpack_repo: FixpackJobRepository, fix_outcome_repo: FixOutcomeRepository,
    repo_fetcher, pr_opener, llm_client: LLMClient,
    llm_usage_repo: LlmUsageRepository | None = None,
    payment_repo: PaymentRepository | None = None,
) -> str:
    """Generate + deliver one paid Fix Pack job. Returns the outcome:
    'delivered', 'no_fix_needed', 'blocked', 'deferred', 'failed',
    'awaiting_authorization', or 'authorization_deferred'. Advances
    the job's status to match so a re-run of the processor doesn't pick it up
    again (a 'failed' or 'blocked' job stays visible for a human to retry/review
    rather than silently stuck on 'paid'). 'blocked' means the generated
    fix passed syntax validation but the semantic check (running the
    client's own tests against the patched tree) found a regression, so the
    PR was withheld for manual review.

    'deferred' keeps the running lease unchanged: the semantic
    check could not run at all (sandbox runner unreachable), so there is no
    verdict to act on and the job keeps its 'running' lease to be retried by the
    existing stale-lease reaper. Delivering would ship an unverified PR; blocking
    would blame the customer's fix for a test run that never happened.

    Every failure is made visible: the full traceback is logged and a short
    reason is written to the job's `detail` column. A job must never land on
    'failed' with a null detail and nothing in the logs — that makes a real
    production failure impossible to diagnose (see the silent-failure
    incident this path was hardened for)."""
    job_id = job["id"]
    set_log_context(job_id=str(job_id),
                    audit_id=str(job["audit_id"]) if job.get("audit_id") else None)
    started = time.monotonic()
    try:
        audit = await audit_repo.get(job["audit_id"]) if job.get("audit_id") else None
        if audit is None or not audit.get("repo_url"):
            detail = "audit missing or has no repo_url to re-fetch"
            logger.error("Fix Pack job %s failed: %s", job_id, detail,
                         extra={"step": "load_audit",
                                "duration_ms": _elapsed_ms(started)})
            await fixpack_repo.mark_status(job_id, "failed", detail=detail)
            await _record_fix_outcome(
                fix_outcome_repo, job=job, outcome="failed",
                rule_ids=[], is_regression=False, pr_url=None,
            )
            await _alert_fixpack_failed(job_id, detail)
            return "failed"

        parsed = _parse_github_repo_url(audit["repo_url"])
        if parsed is None:
            detail = f"unparseable repo_url: {audit['repo_url']!r}"
            logger.error("Fix Pack job %s failed: %s", job_id, detail,
                         extra={"step": "parse_repo_url",
                                "duration_ms": _elapsed_ms(started)})
            await fixpack_repo.mark_status(job_id, "failed", detail=detail)
            await _record_fix_outcome(
                fix_outcome_repo, job=job, outcome="failed",
                rule_ids=[], is_regression=False, pr_url=None,
            )
            await _alert_fixpack_failed(job_id, detail)
            return "failed"
        owner, repo = parsed

        await paid_delivery_token(job, audit)
        zip_bytes = await run_in_threadpool(repo_fetcher, owner, repo)

        findings = audit.get("findings_json") or []
        plan = await run_in_threadpool(build_fixpack_plan, zip_bytes, findings)

        if not plan.has_changes:
            # Everything was a test fixture, already fixed, or absent on
            # re-fetch: don't open an empty PR, record why there was no PR.
            await fixpack_repo.mark_status(job_id, "no_fix_needed")
            await _record_fix_outcome(
                fix_outcome_repo, job=job, outcome="no_fix_needed",
                rule_ids=[], is_regression=False, pr_url=None,
            )
            # AND SAY SO. Recording the outcome is bookkeeping; somebody paid
            # for this. app/fixpack/merit.py already calls the outcome
            # decisively ours -- "this is our mistake, not a disappointing
            # result" -- so the money is owed back, and until this line existed
            # nothing told the one person who can send it.
            if payment_repo is not None:
                await _announce_nothing_to_fix(
                    payment_repo, job=job, audit_id=str(job["audit_id"]))
            return "no_fix_needed"

        # Semantic safety net: run the client's own tests against the patched
        # tree (in Docker) and refuse to ship if we introduced a regression.
        # Synchronous and slow (real Docker), so off the event loop like the
        # scan. A blocked job is parked for a human, never auto-delivered.
        semantic = await run_in_threadpool(
            functools.partial(
                run_semantic_check, zip_bytes, plan,
                suite_runner=sandbox_client.run_suite,
                minimal_checker=sandbox_client.minimal_check,
                profile_runner=sandbox_client.run_verification_profile,
            )
        )
        if semantic.verification_unavailable:
            # The sandbox runner was unreachable, so nothing was verified. We
            # must neither deliver (an unverified PR to a paying customer) nor
            # block (telling them their fix broke tests that never ran). Leave
            # the 'running' lease alone and return: reap_stale_running puts the
            # job back to 'paid' once the lease expires, bounded by
            # MAX_JOB_ATTEMPTS, then fails it terminally. Deliberately no
            # second attempts counter here — that mechanism already exists.
            logger.warning(
                "Fix Pack job %s deferred, verification unavailable: %s",
                job_id, semantic.detail,
                extra={"step": "semantic_check",
                       "duration_ms": _elapsed_ms(started)},
            )
            await fixpack_repo.mark_status(job_id, "running", detail=semantic.detail)
            return "deferred"

        if semantic.regression or semantic.blocked:
            logger.warning(
                "Fix Pack job %s blocked by semantic check: %s",
                job_id, semantic.detail,
                extra={"step": "semantic_check",
                       "duration_ms": _elapsed_ms(started)},
            )
            await fixpack_repo.mark_status(job_id, "blocked", detail=semantic.detail)
            await _record_fix_outcome(
                fix_outcome_repo, job=job, outcome="blocked",
                rule_ids=_rule_ids_from_plan(plan),
                is_regression=semantic.regression,
                pr_url=None,
            )
            return "blocked"

        # Proof-of-Exploit → Proof-of-Fix (soft/hard gate via PROOF_GATE_MODE).
        proof_report = await run_proof_stage(
            job_id=job_id, zip_bytes=zip_bytes, plan=plan,
            fixpack_repo=fixpack_repo,
        )
        gate = decide_proof_gate(proof_report)
        if gate == "hard_fail":
            detail = (
                f"proof gate (hard): exploit still succeeds after patch "
                f"({proof_report.detail if proof_report else 'no report'})"
            )
            logger.warning(
                "Fix Pack job %s blocked by proof gate: %s",
                job_id, detail,
                extra={"step": "proof_gate",
                       "duration_ms": _elapsed_ms(started)},
            )
            await fixpack_repo.mark_status(job_id, "blocked", detail=detail)
            await _record_fix_outcome(
                fix_outcome_repo, job=job, outcome="blocked",
                rule_ids=_rule_ids_from_plan(plan),
                is_regression=False,
                pr_url=None,
            )
            return "blocked"

        title = render_fixpack_pr_title(plan)
        body = render_fixpack_pr_body(plan)
        if semantic.pr_note:
            body = f"{body}\n\n{semantic.pr_note}"
        if proof_report is not None:
            section = render_proof_markdown(proof_report)
            if section:
                body = f"{body}\n\n---\n\n{section}"
        if gate == "soft_fail":
            # Job still delivers; surface the soft failure in detail so
            # operators and status queries can see it without parsing the PR.
            soft_detail = (
                f"delivered with soft proof gate: exploit still succeeds "
                f"after patch ({proof_report.detail if proof_report else ''})"
            )
            logger.warning(
                "Fix Pack job %s soft proof gate: %s",
                job_id, soft_detail,
                extra={"step": "proof_gate",
                       "duration_ms": _elapsed_ms(started)},
            )
            # Best-effort detail write; delivery continues regardless.
            try:
                await fixpack_repo.mark_status(
                    job_id, "running", detail=soft_detail,
                )
            except Exception:  # noqa: BLE001
                logger.exception(
                    "Fix Pack job %s: could not persist soft-gate detail",
                    job_id,
                )

        # The second half of what was bought. Failure here must not cost the
        # customer the fix they also paid for, so the PR still opens and the
        # operator is told the review is owed.
        try:
            review = await _deep_review_section(
                audit["repo_url"], zip_bytes, llm_client=llm_client,
                audit_repo=audit_repo, repo_fetcher=repo_fetcher,
                llm_usage_repo=llm_usage_repo,
            )
        except Exception:  # noqa: BLE001 - the PR must ship regardless
            logger.exception(
                "Fix Pack job %s: deep review failed, delivering the fix "
                "without it", job_id,
                extra={"step": "deep_review",
                       "duration_ms": _elapsed_ms(started)},
            )
            review = None
        if review:
            body = f"{body}\n\n---\n\n{review}"
        else:
            await alerts.notify_operator(
                f"Drydock: Fix Pack {job_id} generated WITHOUT the full "
                "review the purchase includes. The full review is still "
                "owed. Re-run it manually and send the buyer the link."
            )
        token = await paid_delivery_token(job, audit)
        opened = await run_in_threadpool(
            pr_opener, owner, repo, plan.files,
            title=title, body=body, branch_prefix="drydock/fix-pack",
            deletions=plan.deletions, token=token, job_id=job_id,
        )
        await fixpack_repo.mark_fixpack_delivered(job_id, opened.html_url)
        try:
            await get_paid_delivery_store().clear_for_job(str(job_id))
        except Exception:  # cleanup must never reopen an already delivered job
            logger.warning("Fix Pack %s: delivery credential cleanup pending", job_id)
        await _record_fix_outcome(
            fix_outcome_repo, job=job, outcome="delivered",
            rule_ids=_rule_ids_from_plan(plan), is_regression=False,
            pr_url=opened.html_url,
        )
        return "delivered"
    except DeliveryAuthorizationError as exc:
        if exc.status_code >= 500:
            await fixpack_repo.release_to_paid(job_id, exc.reason)
            return "authorization_deferred"
        await get_paid_delivery_store().await_authorization(str(job_id), exc.reason)
        return "awaiting_authorization"
    except httpx.HTTPError:
        await fixpack_repo.release_to_paid(job_id, "github_delivery_unavailable")
        return "authorization_deferred"
    except DeliveryError as exc:
        # Upstream bodies must never reach logs, persisted detail or public output.
        if exc.retryable or exc.status_code == 429 or (exc.status_code and exc.status_code >= 500):
            await fixpack_repo.release_to_paid(job_id, "github_delivery_unavailable")
            return "authorization_deferred"
        if exc.status_code in (401, 403):
            await get_paid_delivery_store().await_authorization(
                str(job_id), "github_delivery_failed_check_token_permissions",
            )
            return "awaiting_authorization"
        detail = "github_delivery_failed"
        await fixpack_repo.mark_status(job_id, "failed", detail=detail)
        await _record_fix_outcome(
            fix_outcome_repo, job=job, outcome="failed", rule_ids=[],
            is_regression=False, pr_url=None,
        )
        await _alert_fixpack_failed(job_id, detail)
        return "failed"
    except Exception as exc:  # noqa: BLE001 — every failure must be recorded
        # Any error in fetch, generation, token exchange, or PR delivery
        # lands here. Log the full traceback (logger.exception attaches it)
        # and persist a short reason so the failure is diagnosable from both
        # the logs and a `select ... from fixpack_jobs` query.
        logger.exception("Fix Pack job %s failed during processing", job_id,
                         extra={"step": "fixpack",
                                "duration_ms": _elapsed_ms(started)})
        detail = _failure_detail(exc)
        await fixpack_repo.mark_status(job_id, "failed", detail=detail)
        await _record_fix_outcome(
            fix_outcome_repo, job=job, outcome="failed",
            rule_ids=[], is_regression=False, pr_url=None,
        )
        await _alert_fixpack_failed(job_id, detail)
        return "failed"


# A verified build may consume two long sandbox-runner requests. Keep one
# paid job inside each timer invocation so the operational timeout is a real,
# deterministic per-run budget. The timer schedules the next job after this
# service invocation becomes inactive.
FIXPACK_JOBS_PER_RUN = 1


async def _alert_paid_backlog_stale(
    *,
    backlog: int,
    oldest_paid_seconds: float | None,
) -> None:
    """Page the operator when a paid Fix Pack has been waiting too long.

    Metrics already expose oldest_paid_seconds on /internal/stats; this is the
    active half — a human gets a Telegram when the queue is not moving. Deduped
    on the deployment (not per job): one stuck processor is one cause.
    """
    if backlog <= 0 or oldest_paid_seconds is None:
        return
    if oldest_paid_seconds < PAID_BACKLOG_ALERT_SECONDS:
        return
    minutes = int(oldest_paid_seconds // 60)
    await alerts.notify_operator(
        "Drydock: paid Fix Pack backlog is not draining — "
        f"{backlog} job(s) waiting, oldest ~{minutes} min. "
        "Check shipit-fixpack.timer/service, sandbox runner health, and "
        "GET /internal/stats. Customers have paid; PRs are not opening.",
        dedupe_key="fixpack-paid-backlog-stale",
        throttle_seconds=PAID_BACKLOG_ALERT_THROTTLE_SECONDS,
    )


@app.post("/internal/fixpack/process-paid")
async def process_paid_fixpacks(
    request: Request,
    audit_repo: AuditRepository = Depends(get_audit_repo),
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
    fix_outcome_repo: FixOutcomeRepository = Depends(get_fix_outcome_repo),
    repo_fetcher=Depends(get_repo_fetcher),
    pr_opener=Depends(get_pr_opener),
    llm_client: LLMClient = Depends(get_llm_client),
    llm_usage_repo: LlmUsageRepository = Depends(get_llm_usage_repo),
    # Only for the outcome that owes somebody their money back: a job knows
    # its audit and nothing else, and the buyer's contact lives on the payment.
    payment_repo: PaymentRepository = Depends(get_payment_repo),
) -> dict:
    """Operational endpoint: process a bounded paid Fix Pack batch and turn each
    claimed job into a real fix PR — re-fetch the audited
    repo, remove hardcoded secrets, harden config, open the PR, and advance
    the job to 'delivered'. Meant for a scheduled caller (a systemd timer,
    same as the reaper and the USDT poller — this repo ships no unit file).
    Not part of the public API.

    Durable-processing model (see PHASE3_QUEUE_PLAN.md): the run takes a
    session advisory lock so two overlapping timer firings don't stampede;
    it first reaps stale 'running' leases (a crashed worker's job) back to
    'paid' (bounded by attempts) or to 'failed'; then it claims at most
    FIXPACK_JOBS_PER_RUN jobs, each atomically leased 'paid' -> 'running',
    so a single job can never be processed by two runs at once.

    Requires `Authorization: Bearer <FIXPACK_PROCESS_TOKEN>`, constant-time
    compared via the same helper the reaper and USDT poller use. 503 if the
    token isn't configured on this deployment — an unconfigured processor is
    an operational gap to notice, not a silent no-op.

    Returns a summary the scheduler can log: how many jobs were processed,
    delivered (PR opened), skipped (nothing eligible to fix), blocked,
    deferred (semantic check could not run — lease left for the reaper),
    failed, and requeued (stale leases put back for retry). If another run
    already holds the lock, returns {"skipped_locked": true} instead; if the
    sandbox runner is unhealthy, nothing is claimed and the summary carries
    {"skipped_unhealthy_runner": true}.
    """
    token = _fixpack_process_token()
    if not token:
        raise HTTPException(
            status_code=503,
            detail={"reason": "fixpack_process_not_configured",
                    "detail": "FIXPACK_PROCESS_TOKEN is not set on this deployment"},
        )
    _require_bearer_token(request, token)

    summary = {"processed": 0, "delivered": 0, "skipped": 0,
               "blocked": 0, "failed": 0, "requeued": 0, "deferred": 0}
    try:
        # One processor run at a time (advisory lock), so two overlapping
        # timer firings can't both work the backlog. The per-job claim below
        # already prevents double-processing a single job; this makes the
        # "one run" invariant explicit.
        async with fixpack_processor_lock():
            # Recover crashed leases first: a 'running' job older than the
            # stale threshold is re-queued (bounded by attempts) or failed,
            # so a mid-job restart never leaves a job stuck 'running'.
            reaped = await fixpack_repo.reap_stale_running(
                max_age_minutes=STALE_LEASE_MINUTES,
                max_attempts=MAX_JOB_ATTEMPTS,
            )
            summary["requeued"] = reaped["requeued"]
            summary["failed"] += reaped["failed"]
            # A lease reaped all the way to 'failed' is a paying customer whose
            # PR will never open, which is exactly what the operator alert is
            # for. The reaper writes the row itself, so without this the only
            # terminal failure nobody hears about would be the reaped one.
            for reaped_id in reaped.get("failed_ids", []):
                await _alert_fixpack_failed(
                    reaped_id,
                    f"stale lease reaped after {MAX_JOB_ATTEMPTS} attempt(s) — "
                    f"the job never completed (sandbox runner outage or a "
                    f"crashed worker)",
                )

            # Active page when money is waiting and the queue is not moving.
            # Stats endpoints already expose the numbers; without this the
            # only observer is whoever happens to open /internal/stats.
            try:
                stats = await fixpack_repo.backlog_stats()
            except Exception:  # noqa: BLE001 — alert path must not kill the run
                stats = None
            if stats is not None:
                await _alert_paid_backlog_stale(
                    backlog=int(stats.get("backlog") or 0),
                    oldest_paid_seconds=stats.get("oldest_paid_seconds"),
                )
                if stats.get("backlog"):
                    summary["paid_backlog"] = stats["backlog"]
                    summary["oldest_paid_seconds"] = stats.get(
                        "oldest_paid_seconds"
                    )

            # Don't claim anything while the sandbox runner is down: the
            # semantic check would be unable to run, every claim would burn one
            # of the job's MAX_JOB_ATTEMPTS, and a few minutes of runner
            # downtime would fail the whole paid backlog. Skipping turns an
            # outage into a pause — the next timer tick claims normally. Checked
            # once per run, not per job: a mid-run outage is still handled, by
            # the per-job 'deferred' path below.
            if not await run_in_threadpool(sandbox_client.runner_healthy):
                logger.warning(
                    "Fix Pack processor: sandbox runner unhealthy, claiming "
                    "nothing this pass (backlog is untouched, attempts unspent)"
                )
                summary["skipped_unhealthy_runner"] = True
                return summary

            # Bound one timer invocation to a deterministic number of paid
            # jobs. This matters once verified builds are enabled: original
            # and patched verification can each consume a long runner request.
            for _ in range(FIXPACK_JOBS_PER_RUN):
                job = await fixpack_repo.claim_one_paid()
                if job is None:
                    break
                summary["processed"] += 1
                outcome = await _process_one_paid_job(
                    job, audit_repo=audit_repo, fixpack_repo=fixpack_repo,
                    fix_outcome_repo=fix_outcome_repo,
                    repo_fetcher=repo_fetcher, pr_opener=pr_opener,
                    llm_client=llm_client, llm_usage_repo=llm_usage_repo,
                    payment_repo=payment_repo,
                )
                if outcome == "delivered":
                    summary["delivered"] += 1
                elif outcome == "no_fix_needed":
                    summary["skipped"] += 1
                elif outcome == "blocked":
                    summary["blocked"] += 1
                elif outcome == "deferred":
                    # Still 'running' on purpose; the reaper will re-queue it.
                    # Stop draining: the runner just went down mid-run, so every
                    # further claim would only spend another job's attempts.
                    summary["deferred"] += 1
                    break
                elif outcome == "awaiting_authorization":
                    summary["awaiting_authorization"] = summary.get("awaiting_authorization", 0) + 1
                elif outcome == "authorization_deferred":
                    summary["deferred"] += 1
                    break
                else:
                    summary["failed"] += 1
    except ProcessorLockBusy:
        # Another run holds the lock — benign, not an error. The scheduler
        # can log this and move on; the other run is draining the backlog.
        return {"skipped_locked": True}
    return summary


@app.post("/internal/monitoring/process-pending")
async def process_pending_monitoring(
    request: Request,
    subscription_repo: SubscriptionRepository = Depends(get_subscription_repo),
    monitoring_repo: MonitoringRunRepository = Depends(get_monitoring_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo),
    llm_client: LLMClient = Depends(get_llm_client),
    repo_fetcher=Depends(get_repo_fetcher),
    transport=Depends(get_billing_transport),
    llm_usage_repo: LlmUsageRepository = Depends(get_llm_usage_repo),
    service_flags_repo: ServiceFlagsRepository = Depends(get_service_flags_repo),
) -> dict:
    """Operational endpoint: drain the pending continuous-monitoring backlog.
    The GitHub push webhook enqueues one 'pending' run per eligible push and
    ACKs immediately (see MONITORING_ASYNC_PLAN.md); this drains those runs off
    the HTTP path -- re-audit the repo, diff against its previous audit, and DM
    subscribers the new critical/high findings. Meant for a scheduled caller (a
    systemd timer, same as the Fix Pack processor and the reaper -- this repo
    ships no unit file).

    Mirrors POST /internal/fixpack/process-paid exactly: a session advisory lock
    so two overlapping timer firings don't stampede; a stale-lease reap first (a
    crashed worker's run back to 'pending', bounded by attempts, else 'failed');
    then claim runs one at a time, each atomically leased 'pending' -> 'running'
    so a single run can never be processed by two passes at once.

    Requires `Authorization: Bearer <MONITORING_PROCESS_TOKEN>`, constant-time
    compared. 503 if the token isn't configured on this deployment -- an
    unconfigured processor is an operational gap to notice, not a silent no-op.

    Returns a summary the scheduler can log. If another run already holds the
    lock, returns {"skipped_locked": true} instead."""
    token = _monitoring_process_token()
    if not token:
        raise HTTPException(
            status_code=503,
            detail={"reason": "monitoring_process_not_configured",
                    "detail": "MONITORING_PROCESS_TOKEN is not set on this deployment"},
        )
    _require_bearer_token(request, token)

    # Emergency stop applies to monitoring too (each run is an LLM-spending
    # re-audit). A background drain has no user to 503, so it soft-degrades:
    # leave the backlog 'pending' and return without claiming anything. The
    # stop's operator alert has already fired inside _emergency_stop_active.
    paused, _note = await _emergency_stop_active(service_flags_repo)
    if paused:
        return {"skipped_paused": True}

    # Monitoring is withdrawn from sale (#184). Gating only the webhook closed
    # the entrance and left this drain able to process whatever was already
    # queued. Production's queue happened to be empty when that shipped, but
    # "happened to be" is not a guarantee, and every run here is an
    # LLM-spending re-audit of a product nobody can buy.
    #
    # Soft-degrade like the emergency stop above: a background drain has no
    # user to 503, so leave the backlog untouched and say so. Unlike the
    # emergency stop, ALERT -- a pending run existing at all while the product
    # is withdrawn means something got past the webhook gate or predates it,
    # and the operator needs the row id to find out which.
    if not monitor.MONITORING_FOR_SALE:
        queued = await monitoring_repo.pending_summary()
        total = (queued or {}).get("total", 0)
        if total:
            listed = ", ".join(
                f"{r['id']} ({r['repo_full_name']})"
                for r in (queued or {}).get("runs", [])
            )
            await alerts.notify_operator(
                f"Drydock: {total} monitoring run(s) are queued while "
                f"monitoring is WITHDRAWN from sale. Nothing was processed and "
                f"nothing was charged, but a push got past the webhook gate or "
                f"these rows predate it \u2014 worth finding out which.\n\n"
                f"Oldest first: {listed}\n\n"
                f"Inspect: select * from monitoring_runs where id in (...);"
            )
        return {"skipped_not_for_sale": True, "pending": total}

    summary = {"processed": 0, "notified": 0, "no_new": 0, "unfetchable": 0,
               "unauditable": 0, "no_subscription": 0, "failed": 0, "requeued": 0}
    try:
        async with monitoring_processor_lock():
            reaped = await monitoring_repo.reap_stale_running(
                max_age_minutes=STALE_LEASE_MINUTES,
                max_attempts=MAX_JOB_ATTEMPTS,
            )
            summary["requeued"] = reaped["requeued"]
            summary["failed"] += reaped["failed"]

            while True:
                run = await monitoring_repo.claim_one_pending()
                if run is None:
                    break
                summary["processed"] += 1
                outcome = await _process_one_monitoring_run(
                    run, monitoring_repo=monitoring_repo,
                    subscription_repo=subscription_repo, audit_repo=audit_repo,
                    llm_client=llm_client, repo_fetcher=repo_fetcher,
                    transport=transport, llm_usage_repo=llm_usage_repo,
                )
                if outcome in summary:
                    summary[outcome] += 1
                else:
                    summary["failed"] += 1
    except ProcessorLockBusy:
        # Another run holds the lock — benign. The scheduler logs and moves on.
        return {"skipped_locked": True}
    return summary
























create_audit = app.post(
    "/v1/audits", status_code=202,
    openapi_extra={"requestBody": {"content": {
        "multipart/form-data": {"schema": _AuditForm.model_json_schema()},
    }}},
)(create_audit)


@app.post("/v1/fixpacks", status_code=202)
async def create_fixpack(
    archive: UploadFile,
    request: Request,
    deliver_to: str | None = Form(
        None,
        description='"owner/repo" to open a real PR against, once verified. '
                    "Omit to just get the generated files back, unverified-safe.",
    ),
    want_preview: bool = Form(
        False,
        description="Keep the verified container alive for a live preview "
                     "instead of tearing it down. Returns a local_url, not a "
                     "public one — see app/deploypack/preview.py for why.",
    ),
    audit_id: str | None = Form(
        None,
        description="Link this Pack to a previously persisted audit, if you "
                     "have one. Optional — the API doesn't require an audit first.",
    ),
    limiter: RateLimiter = Depends(get_rate_limiter),
    pr_opener=Depends(get_pr_opener),
    preview_registry: PreviewRegistry = Depends(get_preview_registry),
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
) -> dict:
    """Deploy Pack only, minimal scope (fastapi + vite-react). Free,
    unpaid preview of the plan's "verify first, pay to unlock" flow —
    no payment gate yet. Persists a fixpack_jobs row when DATABASE_URL
    is configured (see app/db.py); `persisted: false` in the response
    otherwise, same request still works. Shares the audit rate limiter
    for now; should become "1 free Pack run per audit_id" now that
    audits are persisted.

    PR delivery requires the caller's X-GitHub-Token with repository write
    permission. Both the preflight and delivery use that exact token; this
    public endpoint never borrows the server's GitHub App or PAT authority.
    The token is request-only and is not persisted or returned. Generation
    without deliver_to remains public and does not require a GitHub token.

    `want_preview=true` keeps the container alive (24h TTL, 256MB RAM
    cap, 1 live preview per client key — same _client_key as the rate
    limiter) and reaps anything already expired before starting a new
    one. There's no background cron in this process yet, so a preview
    only gets reaped when someone next calls this endpoint — wire
    preview_registry.reap_expired() to a real periodic job before
    relying on the 24h TTL alone.
    """
    try:
        limiter.check(_client_key(request))
    except RateLimitExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail={
                "reason": "rate_limited",
                "detail": f"max {limiter.limit} audits per day",
            },
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc

    raw = await archive.read(MAX_ARCHIVE_BYTES + 1)
    buf = io.BytesIO(raw)

    try:
        validate_zip(buf, size_bytes=len(raw))
    except ArchiveValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail={"reason": exc.reason, "detail": exc.detail},
        ) from exc

    buf.seek(0)
    stack = detect_stack(buf)

    if audit_id is not None:
        try:
            uuid.UUID(audit_id)
        except ValueError:
            raise HTTPException(
                status_code=422,
                detail={"reason": "bad_audit_id",
                        "detail": "audit_id must be a valid UUID"},
            )
        # Bound only once the value is known to be a UUID, so a malformed
        # client string never reaches a log field.
        set_log_context(audit_id=audit_id)

    # Validate deliver_to before any expensive build or GitHub call: it's
    # user input that lands directly in GitHub REST API paths (owner/repo
    # in delivery.py + github_app.py). Reject anything that isn't exactly
    # two valid name segments so extra "/" or ".." can't reshape the path.
    owner = repo = None
    delivery_token: str | None = None
    if deliver_to:
        parts = deliver_to.split("/")
        if len(parts) != 2 or not all(_VALID_OWNER_REPO_SEGMENT.match(p) for p in parts):
            raise HTTPException(
                status_code=422,
                detail={"reason": "bad_deliver_to",
                        "detail": "deliver_to must be 'owner/repo', each part "
                                  "matching ^[A-Za-z0-9._-]+$"},
            )
        owner, repo = parts

        try:
            delivery_token = validate_delivery_token(request.headers.get("X-GitHub-Token"))
            await run_in_threadpool(authorize_repository_delivery, owner, repo, delivery_token)
        except DeliveryAuthorizationError as exc:
            raise HTTPException(status_code=exc.status_code, detail={"reason": exc.reason}) from None

    if want_preview:
        await run_in_threadpool(preview_registry.reap_expired)

    # Off the event loop: docker build/run/curl are real blocking
    # subprocess calls, up to a few minutes total.
    try:
        if want_preview:
            result = await run_in_threadpool(
                run_deploy_pack, raw, stack,
                preview=preview_registry, owner_key=_client_key(request),
            )
        else:
            result = await run_in_threadpool(run_deploy_pack, raw, stack)
    except UnsupportedForDeployPack as exc:
        raise HTTPException(
            status_code=422,
            detail={"reason": "unsupported_stack", "detail": str(exc)},
        )
    except WorkspaceTooLarge as exc:
        raise HTTPException(
            status_code=413,
            detail={"reason": "workspace_too_large", "detail": str(exc)},
        )
    except SandboxRunnerUnavailable as exc:
        # A live preview genuinely can't be built without the runner. The
        # non-preview verify path degrades to verified=None inside
        # run_deploy_pack; the preview path surfaces 503 so the caller retries.
        raise HTTPException(
            status_code=503,
            detail={"reason": "sandbox_runner_unavailable", "detail": str(exc)},
        )

    persisted_job = await fixpack_repo.create(
        audit_id=audit_id, pack="deploy", stack=stack.value,
        verified=result["verified"], detail=result["detail"],
        preview_local_url=result["preview"]["local_url"] if result["preview"] else None,
        preview_expires_at=result["preview"]["expires_at"] if result["preview"] else None,
    )
    job_id = persisted_job["id"] if persisted_job else str(uuid.uuid4())

    pr: dict | None = None
    if deliver_to:
        if result["verified"] is not True:
            pr = {"delivered": False, "reason": "not verified, refusing to open a PR"}
        else:
            body = render_pr_body("deploy", result["files"], result["detail"])
            try:
                opened = await run_in_threadpool(
                    pr_opener, owner, repo, result["files"], body=body,
                    token=delivery_token, job_id=job_id,
                )
            except (DeliveryError, httpx.HTTPError):
                # Upstream exceptions can contain request data. Never reflect
                # them to this caller or borrow server credentials on failure.
                pr = {"delivered": False,
                      "reason": "GitHub delivery failed; check repository permissions and retry."}
            else:
                pr = {"delivered": True, "url": opened.html_url,
                      "branch": opened.branch}
                if persisted_job:
                    await fixpack_repo.mark_delivered(job_id, opened.html_url)

    return {
        "fixpack_id": job_id,
        "persisted": persisted_job is not None,
        # The ownership token for this job, delivered exactly once here so the
        # creator can read it back via GET /v1/fixpacks/{id}?token=. None when
        # the row wasn't persisted (DATABASE_URL unset) -- same as audits.
        "access_token": persisted_job.get("access_token") if persisted_job else None,
        "pack": "deploy",
        "stack": stack.value,
        "verified": result["verified"],
        "detail": result["detail"],
        "files": result["files"],
        "pr": pr,
        "preview": result["preview"],
    }


# Routers are imported at the top of the module; include_router must run here,
# after `app` is constructed. Extracted route modules live in app/routes/.
app.include_router(ops_router)
app.include_router(capabilities_router)
app.include_router(accounts_router)
app.include_router(bank_transfer_router)
app.include_router(github_router)
app.include_router(telegram_router)
app.include_router(billing_router)
app.include_router(operator_router)
app.include_router(reads_router)
app.include_router(rls_check_router)
app.include_router(bundle_check_router)
app.include_router(session_router)
app.include_router(storefront_router)
app.include_router(yookassa_router)
from app.routes.paid_delivery import router as paid_delivery_router  # noqa: E402
app.include_router(paid_delivery_router)
# Off unless MCP_ENABLED is set: the router is always mounted, and the
# endpoint itself answers 404 when the flag is unset. Mounting
# conditionally would make the flag a restart-time decision that an
# operator cannot see in the route table, and would leave the tests for
# the disabled case with nothing to call.
app.include_router(mcp_router)
