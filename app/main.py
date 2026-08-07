"""Drydock API gateway — MVP phase 1 surface.

Only what exists today: health check and archive intake with validation,
rate limiting, stack detection, static scan, and (when providers are
configured) the LLM auth/security scan. Persistence and the queue come
next — the scan stage runs off the event loop in a threadpool for now,
since the LLM call alone can take up to ~2 minutes.
"""

from __future__ import annotations

import datetime
import functools
import hashlib
import hmac
import io
import json
import logging
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from decimal import Decimal

from fastapi import (
    Depends, FastAPI, Form, Header, HTTPException, Request, UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from starlette.concurrency import run_in_threadpool

from app import accounts, alerts
from app.audit_spool import SpoolFull, cleanup_staged_archive, stage_archive
from app.accounts import (
    CSRF_HEADER,
    TIER_FREE,
    entitlements_dict,
    entitlements_for_tier,
    validate_api_key_pepper_configured,
)
from app.billing import bank_transfer, telegram_stars, usdt_trc20
from app.ops_endpoints import router as ops_router
from app.routes.billing import router as billing_router
from app.routes.operator import router as operator_router
from app.routes.paypal import router as paypal_router
from app.routes.reads import router as reads_router
from app.routes.session import router as session_router
from app.routes.storefront import router as storefront_router
from app.db import (
    AccountRepository,
    AuditJobRepository,
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
    usdt_poll_lock,
)
from app.deploypack.delivery import DeliveryError, render_pr_body
from app.deploypack.generate import UnsupportedForDeployPack
from app.deploypack.github_app import (
    GitHubAppAuthError,
    GitHubAppError,
    app_credentials_from_env,
    build_install_url,
    installation_exists_for_repo,
    installation_token_for_repo,
)
from app.deploypack.pipeline import WorkspaceTooLarge, run_deploy_pack
from app.deploypack.preview import PreviewRegistry
from app.fixpack.generate import (
    has_auto_fixable_findings,
    build_fixpack_plan,
    render_pr_body as render_fixpack_pr_body,
    render_pr_title as render_fixpack_pr_title,
)
from app.fixpack.semantic_check import run_semantic_check
from app.ingest.github_fetch import RepoFetchError
from app.ingest.stack_detect import Stack, detect_stack
from app import sandbox_client
from app.sandbox_client import SandboxRunnerUnavailable
from app.llm.client import LLMClient
from app.llm import pricing
from app.log_context import log_context, set_log_context
from app.logging_config import configure_logging
from app.monitor import (
    MONITORING_FOR_SALE,
    normalize_repo_full_name,
    repo_url_from_full_name,
)
from app.monitor.diff import new_high_severity_findings
from app.ratelimit import RateLimitExceeded, RateLimiter
from app.scan.pipeline import (AUDIT_ENGINE_VERSION, BASIS_FULL,
                              basis_for_account, content_digest, run_scan)
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


app = FastAPI(title="Drydock", version="0.1.0", lifespan=lifespan)


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
        allow_headers=["Authorization", "Content-Type", CSRF_HEADER],
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


def _elapsed_ms(started: float) -> int:
    """Milliseconds since a time.monotonic() mark, rounded to an int.

    monotonic rather than time(): these spans are compared against each other
    and must not jump when the clock is stepped by NTP mid-request.
    """
    return int((time.monotonic() - started) * 1000)







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
from app.routes._shared import (  # noqa: E402
    _bind_account,
    _client_key,
    _json_object_body,
    _require_bearer_token,
    _secret_equals,
    _service_flags_token,
    _usdt_receiving_address,
)
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
    get_paypal_transport,
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
    "get_paypal_transport",
    "get_pr_opener",
    "get_preview_reconciler",
    "get_preview_registry",
    "get_rate_limiter",
    "get_repo_fetcher",
    "get_service_flags_repo",
    "get_subscription_repo",
]


# GitHub owner/repo names: alphanumerics, hyphen, underscore, period.
# Permissive-but-safe guard so a user-supplied deliver_to can't smuggle
# extra path segments (extra "/" or "..") into a GitHub REST API path.
_VALID_OWNER_REPO_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")

# Shape guard for the repo_url intake path. Host must be EXACTLY
# github.com (the literal `github.com/` right after the scheme rejects
# userinfo tricks like https://github.com@evil.com/... and any
# subdomain or :port), scheme must be https. The two path segments are
# then re-validated with _VALID_OWNER_REPO_SEGMENT — same rule as
# deliver_to, no second charset — so nothing but a clean owner/repo can
# reach the fetch. This runs before any network call: it is the SSRF guard.
_GITHUB_REPO_URL = re.compile(r"^https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$")


def _parse_github_repo_url(repo_url: str) -> tuple[str, str] | None:
    m = _GITHUB_REPO_URL.match(repo_url.strip())
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    if not (_VALID_OWNER_REPO_SEGMENT.match(owner)
            and _VALID_OWNER_REPO_SEGMENT.match(repo)):
        return None
    return owner, repo


async def _record_llm_usage(
    llm_usage_repo: LlmUsageRepository, *, job_type: str,
    job_id: str | None, account_id: str | None, llm_stats: object,
    audit_job_id: str | None = None,
) -> None:
    """Write ONE llm_usage row per ATTEMPT that actually bought tokens.

    `llm_stats` is run_scan()["llm_usage"] -- the accounting key, not the `llm`
    diagnostic key. The distinction is the whole point: `llm` degrades to the
    string "failed: ..." when a provider dies mid-scan, and reading spend off it
    silently discarded every token the calls before that failure had already
    paid for. `llm_usage` always carries the real totals, so calls>0 is now the
    single condition, and it means what it says.

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
    calls = int(llm_stats.get("calls") or 0)
    if calls <= 0:
        return
    input_tokens = int(llm_stats.get("input_tokens") or 0)
    output_tokens = int(llm_stats.get("output_tokens") or 0)
    # model is NOT NULL in the table; a job with calls>0 always set it, but fall
    # back to a sentinel that prices at DEFAULT_PRICE (fail-safe high) rather
    # than write a null or crash if a provider ever omitted it.
    model = llm_stats.get("model") or "unknown"
    cost = pricing.cost_usd(model, input_tokens, output_tokens)
    try:
        await llm_usage_repo.create(
            job_type=job_type, job_id=job_id, account_id=account_id,
            model=model, calls=calls, input_tokens=input_tokens,
            output_tokens=output_tokens, cost_usd=cost,
            audit_job_id=audit_job_id,
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
DEFAULT_DAILY_SPEND_CAP_USD = Decimal(
    os.environ.get("DEFAULT_DAILY_SPEND_CAP_USD", "2.00"))
_ANON_SPEND_ALERT_FRACTION = Decimal("0.8")

# How often an engaged emergency stop re-pages the operator. Half an hour, not
# alerts.DEFAULT_THROTTLE_SECONDS (60s): the audit worker consults the stop once
# per loop pass, so the default meant one Telegram message per minute for as
# long as the stop was on.
_PAUSED_ALERT_THROTTLE_S = 1800.0

# Emergency-stop flag cache. The kill switch is read on the request path, so it
# is cached for a few seconds to avoid a DB round-trip per request; a pause thus
# takes effect within _FLAG_TTL_S, which is well inside "emergency" tolerance.
_FLAG_TTL_S = 8.0
_llm_paid_ops_cache: dict[str, object] = {"at": 0.0, "enabled": True, "note": None}


def _reset_service_flag_cache() -> None:
    """Force the next _llm_paid_ops_enabled call to re-read the DB. Used by the
    toggle endpoint (so a just-set value is visible immediately) and by tests."""
    _llm_paid_ops_cache["at"] = 0.0


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


async def _llm_paid_ops_enabled(
    flags_repo: ServiceFlagsRepository,
) -> tuple[bool, str | None]:
    """(enabled, note) for the 'llm_paid_ops' emergency stop, cached for
    _FLAG_TTL_S. A missing row or unconfigured DB reads as enabled (fail-open):
    the kill switch must be an explicit operator action, never the accident of a
    missing table -- an unconfigured dev box must still run scans."""
    now = time.monotonic()
    if now - float(_llm_paid_ops_cache["at"]) < _FLAG_TTL_S:
        return bool(_llm_paid_ops_cache["enabled"]), _llm_paid_ops_cache["note"]  # type: ignore[return-value]
    flag = await flags_repo.get("llm_paid_ops")
    if flag is None:
        enabled, note = True, None
    else:
        enabled, note = bool(flag["enabled"]), flag.get("note")
    _llm_paid_ops_cache.update(at=now, enabled=enabled, note=note)
    return enabled, note


async def _emergency_stop_active(
    flags_repo: ServiceFlagsRepository,
) -> tuple[bool, str | None]:
    """True (with the operator note) when paid LLM ops are paused. Fires the
    mandatory operator alert as a side effect whenever the stop is found engaged;
    notify_operator self-throttles on the dedupe_key, so a burst of blocked
    requests collapses to one alert.

    The window is _PAUSED_ALERT_THROTTLE_S, not the 60s default, because the
    audit worker asks once per loop pass: at the default, an engaged stop paged
    the operator every single minute for as long as it stayed engaged. A
    reminder is wanted -- forgetting the stop is on means silently selling
    nothing -- but one a minute forever is how an operator learns to ignore
    alerts. Deliberately not a per-caller parameter: fifteen tests stub this
    function, so a new keyword would break them all and every future stub would
    have to remember it. One window for one alert is enough."""
    enabled, note = await _llm_paid_ops_enabled(flags_repo)
    if enabled:
        return False, None
    await alerts.notify_operator(
        f"Emergency stop ACTIVE: llm_paid_ops is OFF, rejecting paid LLM ops. "
        f"Note: {note or '(none)'}",
        dedupe_key="llm-paid-ops-paused",
        throttle_seconds=_PAUSED_ALERT_THROTTLE_S,
    )
    return True, note


async def _anon_daily_cap_exceeded(llm_usage_repo: LlmUsageRepository) -> bool:
    """True when anonymous traffic has spent at least the daily cap today, so a
    new anonymous audit must degrade to static-only. Fires the 80% operator
    alert as a side effect. A None sum (DATABASE_URL unset) reads as False --
    there is no journal to cap against."""
    spend = await llm_usage_repo.sum_anon_spend_today()
    if spend is None:
        return False
    if spend >= DEFAULT_DAILY_SPEND_CAP_USD * _ANON_SPEND_ALERT_FRACTION:
        await alerts.notify_operator(
            f"Anonymous LLM spend today is ${spend:.2f}, at/over "
            f"{int(_ANON_SPEND_ALERT_FRACTION * 100)}% of the "
            f"${DEFAULT_DAILY_SPEND_CAP_USD:.2f} daily cap.",
            dedupe_key="anon-budget-80",
        )
    return spend >= DEFAULT_DAILY_SPEND_CAP_USD


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
    stack = detect_stack(buf)
    if stack is Stack.UNSUPPORTED:
        return None

    digest = content_digest(raw)
    # BASIS_FULL, not the caller's tier: this path always runs the LLM stage
    # (see _run_scan_offthread below, called with no llm_skip_reason), so a
    # static-only row is not a valid result for it to reuse.
    cached = await audit_repo.get_by_content_hash(
        digest, AUDIT_ENGINE_VERSION, BASIS_FULL)
    if cached is not None:
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

    scan = await _run_scan_offthread(raw, llm_client)
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
        persisted = await audit_repo.create(
            stack=stack.value, file_count=report.file_count,
            score_total=scan["score"]["total"], score_json=scan["score"],
            findings_json=scan["findings"], repo_url=repo_url,
            content_hash=digest, engine_version=AUDIT_ENGINE_VERSION,
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




















@app.get("/v1/account")
async def get_account(
    request: Request,
    limiter: RateLimiter = Depends(get_rate_limiter),
    account_repo: AccountRepository = Depends(get_account_repo),
) -> dict:
    """The caller's tier and entitlements, resolved from an optional
    `Authorization: Bearer <api_key>` header. No key / unknown key /
    unconfigured database all return the anonymous free set — this never
    401s, matching the rest of this codebase's graceful-degradation tone
    (there's no "invalid session", only "not recognized as paying").

    Never echoes the API key back. `authenticated` says whether a real
    account was matched, so a caller can tell "my key worked" from "fell
    back to free" without the endpoint leaking which keys exist.
    """
    account = await accounts.resolve_account(request, account_repo)
    _bind_account(account)
    tier = account["tier"] if account else TIER_FREE
    entitlements = entitlements_for_tier(tier, free_daily_limit=limiter.limit)
    return {
        "tier": tier,
        "authenticated": account is not None,
        "entitlements": entitlements_dict(entitlements),
    }


@app.post("/v1/account/rotate-key")
async def rotate_account_key(
    request: Request,
    account_repo: AccountRepository = Depends(get_account_repo),
) -> dict:
    """Issue a new API key for the authenticated account, invalidating the
    old one. Auth is the CURRENT `Authorization: Bearer <api_key>` — this is
    the proactive path (rotate a key you still hold, e.g. on suspected
    leak). The lost-key path is Telegram's /rotatekey, which authenticates
    by chat ownership instead.

    Returns the new key exactly once (it is never stored). Unlike the
    graceful-degradation of GET /v1/account, an unrecognized key here 401s:
    there is no meaningful anonymous rotation, and echoing free-tier success
    would mislead the caller into thinking a bad key was rotated.
    """
    account = await accounts.resolve_account(request, account_repo)
    _bind_account(account)
    if account is None:
        raise HTTPException(
            status_code=401,
            detail={"reason": "unauthorized",
                    "detail": "no account recognized for the presented API key"},
        )
    rotated = await account_repo.rotate_key(account["id"])
    if rotated is None:
        raise HTTPException(
            status_code=401,
            detail={"reason": "unauthorized",
                    "detail": "account could not be rotated"},
        )
    return {
        "api_key": rotated["api_key"],
        "key_prefix": rotated["key_prefix"],
        "tier": rotated["tier"],
    }


@app.post("/v1/webhooks/telegram")
async def telegram_webhook(
    request: Request,
    account_repo: AccountRepository = Depends(get_account_repo),
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo),
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
    subscription_repo: SubscriptionRepository = Depends(get_subscription_repo),
    transport=Depends(get_billing_transport),
) -> dict:
    """Telegram Bot API webhook for Stars payments. Handles the
    pre_checkout_query (approve within 10s), successful_payment (grant pro /
    Fix Pack / subscription), subscription (BotSubscriptionUpdated renewal
    state changes) and callback_query (the operator's bank-transfer confirm
    button) update types; ignores everything else.

    Authenticity is Telegram's secret_token: setWebhook is called with a
    secret, echoed back in X-Telegram-Bot-Api-Secret-Token on every
    delivery. Constant-time compared here, same posture as the reap
    endpoint's bearer token. 503 if the bot token or webhook secret
    isn't configured — an unconfigured payment webhook is an operational
    gap to notice, not a silent no-op. See app/billing/telegram_stars.py.

    Note this header proves the update came from TELEGRAM, not from any
    particular person: it is shared by every user who can message the bot.
    The callback_query branch therefore does its own owner check against
    TELEGRAM_ADMIN_CHAT_ID before acting (telegram_stars._is_operator).
    """
    token = telegram_stars.bot_token_from_env()
    secret = telegram_stars.webhook_secret_from_env()
    if not token or not secret:
        raise HTTPException(
            status_code=503,
            detail={"reason": "telegram_not_configured",
                    "detail": "TELEGRAM_BOT_TOKEN and TELEGRAM_WEBHOOK_SECRET "
                              "must both be set on this deployment"},
        )
    provided = request.headers.get("x-telegram-bot-api-secret-token", "")
    if not _secret_equals(provided, secret):
        raise HTTPException(status_code=401, detail={"reason": "unauthorized"})

    update = await _json_object_body(request)
    return await telegram_stars.handle_update(
        update, account_repo=account_repo, payment_repo=payment_repo,
        audit_repo=audit_repo, fixpack_repo=fixpack_repo,
        subscription_repo=subscription_repo,
        token=token, transport=transport,
    )


def _github_webhook_secret() -> str | None:
    """The GitHub App's configured webhook secret, or None if unset. Used to
    verify X-Hub-Signature-256 on incoming deliveries. Must equal the secret
    set in the App's webhook settings on GitHub."""
    return os.environ.get("GITHUB_APP_WEBHOOK_SECRET") or None


def _verify_github_signature(secret: str, body: bytes, header: str) -> bool:
    """Verify a GitHub webhook delivery: header is X-Hub-Signature-256, of the
    form 'sha256=<hex>', where <hex> = HMAC-SHA256(secret, raw_body). Compared
    constant-time. GitHub also sends the older 'sha1' X-Hub-Signature, which we
    deliberately ignore -- sha256 is required and sha1 is deprecated."""
    if not header.startswith("sha256="):
        return False
    expected = hmac.new(
        secret.encode("utf-8"), body, hashlib.sha256
    ).hexdigest()
    provided = header.split("=", 1)[1]
    return _secret_equals(provided, expected)


@app.post("/v1/webhooks/github")
async def github_webhook(
    request: Request,
    fix_outcome_repo: FixOutcomeRepository = Depends(get_fix_outcome_repo),
    subscription_repo: SubscriptionRepository = Depends(get_subscription_repo),
    monitoring_repo: MonitoringRunRepository = Depends(get_monitoring_repo),
) -> dict:
    """GitHub App webhook. Two independent jobs, dispatched by X-GitHub-Event:

      * pull_request: when a Fix Pack PR is closed, record whether it was
        merged (fix_outcomes.pr_merged) -- the real-world signal for whether
        our fix shipped. Collection only (see PHASE_B_KNOWLEDGE_BASE_PLAN.md).
      * push: continuous monitoring (Phase C). A push to a repo's default
        branch ENQUEUES a monitoring run (at most once per 24h per repo) and
        ACKs immediately; the re-audit + diff + DM run later on the
        /internal/monitoring/process-pending processor (see
        MONITORING_ASYNC_PLAN.md).

    Authenticity is the standard GitHub scheme: X-Hub-Signature-256 =
    'sha256=' + HMAC-SHA256(GITHUB_APP_WEBHOOK_SECRET, raw body), compared
    constant-time over the *raw* bytes (not re-serialized JSON). 503 if the
    secret isn't configured -- an unconfigured webhook is an operational gap to
    notice, same posture as the Telegram webhook. 401 on a missing/invalid
    signature.

    Everything other than the two handled events is a 200 ack so GitHub stops
    retrying.

    NOTE: the App must be subscribed to BOTH the 'Pull request' AND 'Push'
    events in its GitHub settings for these deliveries to arrive at all -- a
    manual, one-time UI step (see README)."""
    secret = _github_webhook_secret()
    if not secret:
        raise HTTPException(
            status_code=503,
            detail={"reason": "github_webhook_not_configured",
                    "detail": "GITHUB_APP_WEBHOOK_SECRET is not set on this "
                              "deployment"},
        )
    body = await request.body()
    signature = request.headers.get("x-hub-signature-256", "")
    if not _verify_github_signature(secret, body, signature):
        raise HTTPException(status_code=401, detail={"reason": "unauthorized"})

    event = request.headers.get("x-github-event", "")
    payload = json.loads(body) if body else {}

    if event == "pull_request":
        if payload.get("action") != "closed":
            return {"ignored": True, "reason": "action_not_handled"}
        pr = payload.get("pull_request") or {}
        pr_url = pr.get("html_url")
        if not pr_url:
            return {"ignored": True, "reason": "no_pull_request_url"}
        merged = bool(pr.get("merged"))
        updated = await fix_outcome_repo.set_pr_merged_by_pr_url(pr_url, merged)
        return {"updated": updated, "merged": merged}

    if event == "push":
        return await _handle_monitoring_push(
            payload, subscription_repo=subscription_repo,
            monitoring_repo=monitoring_repo,
        )

    return {"ignored": True, "reason": "event_not_handled"}


async def _handle_monitoring_push(
    payload: dict, *, subscription_repo: SubscriptionRepository,
    monitoring_repo: MonitoringRunRepository,
) -> dict:
    """Fast half of continuous monitoring (see MONITORING_ASYNC_PLAN.md): decide
    whether a push warrants a monitoring run and, if so, ENQUEUE it and ACK 200
    immediately -- the real work (audit + diff + notify) runs later in
    POST /internal/monitoring/process-pending. Doing the audit inline used to
    make GitHub mark the delivery "timed out" (its webhook-response timeout is
    shorter than a ~10s-2min audit) even when the work succeeded.

    Only a push to the repo's OWN default branch counts -- a push to a feature
    branch isn't what ships, and re-auditing every branch push would burn the LLM
    budget for noise.

    The 24h cost cap and the enqueue-dedup are one and the same atomic write:
    claim_for_monitoring stamps last_monitored_at up front, iff the repo hasn't
    been monitored in the last 24h, and reports whether THIS call won the claim.
    Two near-simultaneous default-branch pushes race on that single UPDATE;
    exactly one wins and enqueues a run, the other is a no-op -- so a subscriber
    is neither double-audited nor double-notified. Stamping at enqueue (not after
    the audit) is also what makes a dead/private repo stop re-enqueuing on every
    push."""
    repository = payload.get("repository") or {}
    default_branch = repository.get("default_branch")
    ref = payload.get("ref") or ""
    if not default_branch or ref != f"refs/heads/{default_branch}":
        return {"ignored": True, "reason": "not_default_branch"}

    repo_full_name = normalize_repo_full_name(
        repository.get("full_name") or repository.get("html_url")
    )
    if repo_full_name is None:
        return {"ignored": True, "reason": "unparseable_repo"}

    # Checked BEFORE the subscription lookup, deliberately: an already-active
    # row must not drive spend either, and this is the single place a push
    # turns into an audit. See MONITORING_FOR_SALE.
    if not MONITORING_FOR_SALE:
        return {"ignored": True, "reason": "monitoring_not_for_sale"}

    subs = await subscription_repo.list_active_for_repo(repo_full_name)
    if not subs:
        return {"ignored": True, "reason": "no_active_subscription"}

    now = datetime.datetime.now(datetime.timezone.utc)
    if not await subscription_repo.claim_for_monitoring(repo_full_name, now):
        # Within 24h of the last run, or lost the race to a concurrent push.
        return {"ignored": True, "reason": "within_interval"}

    # Won the claim: enqueue a durable 'pending' run and ACK immediately. The
    # processor drains it off the HTTP path.
    run = await monitoring_repo.enqueue(repo_full_name)
    return {
        "queued": True, "repo_full_name": repo_full_name,
        "run_id": run["id"] if run else None,
    }


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
        # BASIS_FULL: this path re-audits at full depth, so only a full prior
        # audit is a comparable baseline. A free static-only row as the baseline
        # would make every LLM finding look newly appeared.
        previous = await audit_repo.get_latest_by_repo_url(
            repo_full_name, BASIS_FULL)
        previous_findings = (previous or {}).get("findings_json") or []

        try:
            result = await run_repo_audit(
                repo_url_from_full_name(repo_full_name), llm_client=llm_client,
                audit_repo=audit_repo, repo_fetcher=repo_fetcher,
                llm_usage_repo=llm_usage_repo, job_type="monitoring",
            )
        except RepoFetchError:
            # Repo went private/was deleted (404, indistinguishable by design).
            # Benign terminal state; the 24h claim already stopped re-enqueues.
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














# Distinct "I've paid" presses, per client key, per limiter window (24h).
# This bounds a flood of DIFFERENT invoices from one source; repeat presses of
# ONE invoice are already collapsed by notify_operator's dedupe_key. Well above
# what any real payer needs -- a payer opens one invoice, maybe two.
BANK_TRANSFER_PAID_LIMIT = 10

# Invoices opened per client key per limiter window (24h).
#
# Unauthenticated by necessity -- a buyer has no key until they have paid --
# which until now meant unbounded. Each invoice permanently consumed one of the
# 99 kopeck suffixes, so a hundred anonymous POSTs switched the operator's
# whole matching mechanism off. The TTL window in bank_transfer fixed the
# permanence; this bounds how fast one source can fill the window.
#
# Well above any real checkout: a buyer opens one invoice, changes their mind
# about Pro versus a Fix Pack, maybe reloads a stale page. Fifteen is generous
# for that and still a hundredth of what saturation needs.
BANK_TRANSFER_INVOICE_LIMIT = 15


def _check_invoice_rate_limit(request: Request, limiter: RateLimiter) -> None:
    """429 when one client has opened too many invoices today.

    Shared by the Pro and Fix Pack creators on ONE limiter key on purpose:
    they draw suffixes from the same pool, so a per-endpoint budget would let
    the same client take twice as much of it.
    """
    try:
        limiter.check(
            f"bank-transfer-invoice:{_client_key(request)}",
            limit=BANK_TRANSFER_INVOICE_LIMIT,
        )
    except RateLimitExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail={
                "reason": "rate_limited",
                "detail": f"max {BANK_TRANSFER_INVOICE_LIMIT} bank transfer "
                          "invoices per day",
            },
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc








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
    status in ('paid', 'running') -- and must keep mirroring it. A stricter
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
    if job is None or job.get("status") not in ("paid", "running"):
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


def _bank_transfer_details() -> dict[str, str]:
    """The configured payer-facing bank fields, or 503.

    All six or nothing (see bank_transfer.bank_details_from_env): a payer
    handed a SWIFT code with no account number cannot send anything, so a
    half-configured deployment must refuse rather than render an invoice that
    can't be paid."""
    details = bank_transfer.bank_details_from_env()
    if details is None:
        raise HTTPException(
            status_code=503,
            detail={"reason": "bank_transfer_not_configured",
                    "detail": "bank transfer is not configured on this "
                              "deployment (BANK_TRANSFER_CARD, "
                              "BANK_TRANSFER_BANK_NAME, "
                              "BANK_TRANSFER_SWIFT, BANK_TRANSFER_BENEFICIARY, "
                              "BANK_TRANSFER_ACCOUNT and BANK_TRANSFER_ADDRESS "
                              "must all be set)"},
        )
    return details




class PayerContact(BaseModel):
    """Who is sending the transfer. Since payment moved to a card number this
    is not bookkeeping colour, it is the MATCHING KEY: a card-to-card transfer
    carries no reference field, so the sender's name on the operator's
    statement is the only handle on the payment, with the email as tie-breaker
    between two payers of the same name. Hence both fields are now required
    and so is the request body.

    max_length is abuse protection, not validation -- it stops someone posting a
    megabyte into a text column. The email check is deliberately the weakest
    thing that still rejects an obvious non-address: nothing is ever sent here,
    so a work address with an unusual TLD must not cost a sale. See migration
    0026.
    """

    payer_name: str = Field(min_length=1, max_length=200)
    payer_email: str = Field(min_length=3, max_length=200)

    @field_validator("payer_name", "payer_email")
    @classmethod
    def _stripped_and_present(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must not be blank")
        return v

    @field_validator("payer_email")
    @classmethod
    def _looks_like_an_address(cls, v: str) -> str:
        if "@" not in v:
            raise ValueError("must contain @")
        return v


def _bank_transfer_not_persisted_error() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail={"reason": "not_persisted",
                "detail": "bank transfer invoices require DATABASE_URL (a "
                          "pending payment row carries the reference code the "
                          "operator matches against the bank statement)"},
    )


@app.post("/v1/billing/bank-transfer/pro", status_code=201)
async def create_bank_transfer_invoice(
    payer: PayerContact,
    request: Request,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    limiter: RateLimiter = Depends(get_rate_limiter),
    service_flags_repo: ServiceFlagsRepository = Depends(get_service_flags_repo),
) -> dict:
    """Open a bank-transfer invoice for the Pro tier.

    Returns the card number to pay, the amount, and the reference code that
    identifies this order. Many banks carry that reference in the transfer's
    comment field and some do not, so the payer's name and email stay required
    (422 without them, see PayerContact) as the fallback the operator matches
    on. Poll GET /v1/billing/bank-transfer/{reference} to collect the key once
    the operator confirms the money arrived.

    Rate limited because it is unauthenticated and writes a row per call.

    Gated by the same emergency stop as the Fix Pack creator: a stop that left
    either invoice creator open would not stop sales.

    503 if bank transfer isn't configured, if the service is paused, or if the
    pending row can't be persisted (no DATABASE_URL / no free reference code)."""
    paused, note = await _emergency_stop_active(service_flags_repo)
    if paused:
        raise HTTPException(
            status_code=503,
            detail={"reason": "service_paused", "detail": note},
        )
    _check_invoice_rate_limit(request, limiter)
    details = _bank_transfer_details()
    invoice = await bank_transfer.create_invoice(
        payment_repo, details=details,
        payer_name=payer.payer_name,
        payer_email=payer.payer_email,
    )
    if invoice is None:
        raise _bank_transfer_not_persisted_error()
    return invoice


@app.post("/v1/audits/{audit_id}/fixpack/bank-transfer", status_code=201)
async def create_fixpack_bank_transfer_invoice(
    audit_id: str,
    payer: PayerContact,
    request: Request,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo),
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
    limiter: RateLimiter = Depends(get_rate_limiter),
    service_flags_repo: ServiceFlagsRepository = Depends(get_service_flags_repo),
) -> dict:
    """Open a bank-transfer invoice to buy a Fix Pack for one audit. Same
    reference-code flow and same polling endpoint as the Pro invoice above, at
    the Fix Pack price and scoped to this audit.

    Same GitHub-URL-only gate as the USDT and PayPal Fix Pack routes: a zip
    audit has no repository to open a fix PR against, so 422 rather than sell
    something that can't be fulfilled. 404 if no such audit.

    Rate limited on the same key as the Pro creator, which is also why both are
    gated by the same emergency stop: this is the only live payment rail, so a
    stop that did not close it would not stop sales."""
    # Emergency stop closes the checkout, not just the work. Checked before the
    # rate limiter so a paused service neither spends nor consumes the caller's
    # quota, exactly as create_audit does it. Until this existed the stop paused
    # the Fix Pack worker while leaving the invoice creator open, so engaging it
    # mid-incident would have kept taking money for work that could not run.
    paused, note = await _emergency_stop_active(service_flags_repo)
    if paused:
        raise HTTPException(
            status_code=503,
            detail={"reason": "service_paused", "detail": note},
        )
    _check_invoice_rate_limit(request, limiter)
    audit = await audit_repo.get(audit_id)
    if audit is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "audit_not_found",
                    "detail": "no audit with this id, or persistence isn't "
                              "configured on this deployment (see app/db.py)"},
        )
    if not audit.get("repo_url"):
        raise HTTPException(
            status_code=422,
            detail={"reason": "not_github_audit",
                    "detail": "Fix Pack currently only supports audits run "
                              "from a public GitHub URL. This audit was created "
                              "from an uploaded zip, so there's no repository to "
                              "open a fix PR against — re-run the audit with your "
                              "GitHub repo URL, then buy a Fix Pack for it."},
        )
    await _reject_if_fixpack_already_live(fixpack_repo, audit_id)
    _reject_if_nothing_to_fix(audit)
    details = _bank_transfer_details()
    invoice = await bank_transfer.create_fixpack_invoice(
        payment_repo, details=details, audit_id=audit_id,
        payer_name=payer.payer_name,
        payer_email=payer.payer_email,
    )
    if invoice is None:
        raise _bank_transfer_not_persisted_error()
    return invoice





@app.post("/v1/billing/bank-transfer/{reference}/paid")
async def report_bank_transfer_paid(
    reference: str,
    request: Request,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    limiter: RateLimiter = Depends(get_rate_limiter),
    transport=Depends(get_billing_transport),
) -> dict:
    """The payer pressed "I've paid": notify the operator, grant nothing.

    This writes no state — the row stays 'pending' until a human has seen the
    money on the statement and pressed the Confirm button carried by the
    notification. Pressing this without paying achieves exactly nothing.

    Rate limited because it is unauthenticated and its whole job is to push a
    message to the operator's phone. The per-invoice repeat is already
    collapsed by notify_operator's dedupe window; this bounds how many
    DISTINCT invoices one client can page the operator about. 404 if there's
    no such invoice."""
    try:
        limiter.check(
            f"bank-transfer-paid:{_client_key(request)}",
            limit=BANK_TRANSFER_PAID_LIMIT,
        )
    except RateLimitExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail={
                "reason": "rate_limited",
                "detail": f"max {BANK_TRANSFER_PAID_LIMIT} bank transfer "
                          "notifications per day",
            },
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc

    result = await bank_transfer.mark_awaiting_confirmation(
        payment_repo, reference,
        transport=transport, site_url=telegram_stars.SITE_URL,
    )
    if result is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no bank transfer invoice with this reference, or "
                              "persistence isn't configured on this deployment"},
        )
    return result








@app.get("/v1/github/installation-status")
async def github_installation_status(owner: str, repo: str) -> dict:
    """Is the Drydock GitHub App installed on owner/repo? The audit results
    page checks this before offering a Fix Pack: a Fix Pack opens a real PR,
    which needs the App installed on the target repo (see
    app/deploypack/github_app.py). Audit intake itself is public-only and
    needs no App — this gate is Fix-Pack-specific.

    Reuses the same per-repo installation lookup the PR-delivery path uses
    (installation_exists_for_repo -> GET /repos/{owner}/{repo}/installation),
    so there is one source of truth for "installed on this repo" and no
    stored installation_id to drift.

    Shape:
      - app_configured=false: the App isn't set up on this deployment at all
        (PR delivery falls back to the operator PAT), so `installed` is null
        and the frontend should not gate on it.
      - app_configured=true, installed=true: good to go, install_url null.
      - app_configured=true, installed=false: install_url points the repo
        owner at the App's public install page, carrying state=owner/repo.
    """
    if not (_VALID_OWNER_REPO_SEGMENT.match(owner)
            and _VALID_OWNER_REPO_SEGMENT.match(repo)):
        raise HTTPException(
            status_code=422,
            detail={"reason": "bad_owner_repo",
                    "detail": "owner and repo must each match ^[A-Za-z0-9._-]+$"},
        )

    app_creds = app_credentials_from_env()
    if app_creds is None:
        return {"owner": owner, "repo": repo, "app_configured": False,
                "installed": None, "install_url": None}

    app_id, private_key = app_creds
    try:
        # Off the event loop: installation_exists_for_repo does blocking
        # network I/O, same as the token resolution the delivery path runs.
        installed = await run_in_threadpool(
            installation_exists_for_repo, owner, repo,
            app_id=app_id, private_key=private_key,
        )
    except GitHubAppError as exc:
        # The App IS configured but the check itself failed (bad key, GitHub
        # down). Surface as an upstream error rather than a misleading
        # "not installed" — same fault/caller split create_audit draws.
        raise HTTPException(
            status_code=502,
            detail={"reason": "installation_check_failed", "detail": str(exc)},
        ) from exc

    install_url = None if installed else build_install_url(f"{owner}/{repo}")
    return {"owner": owner, "repo": repo, "app_configured": True,
            "installed": installed, "install_url": install_url}


@app.post("/internal/billing/poll-usdt")
async def poll_usdt(
    request: Request,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    account_repo: AccountRepository = Depends(get_account_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo),
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
    transport=Depends(get_billing_transport),
) -> dict:
    """Operational endpoint: read incoming USDT transfers from TronGrid and
    complete any pending invoice whose exact amount arrived. Meant for a
    scheduled caller (a systemd timer like shipit-reap.timer — this repo
    ships no unit file, same as the reaper; see the README). Not part of
    the public API.

    Requires `Authorization: Bearer <USDT_POLL_TOKEN>`, constant-time
    compared, exactly like the reap endpoint. 503 if the token or the
    receiving address isn't configured.

    One poll at a time (advisory lock), like the Fix Pack and monitoring
    processors -- but load-bearing here rather than belt-and-suspenders,
    because matching a transfer is a read-then-write with no atomic claim
    behind it. Two overlapping polls both see the same invoice unpaid and both
    grant it, producing two pro accounts for one payment; see db.usdt_poll_lock
    for why the unique index on payments(provider, external_ref) doesn't stop
    that. If another poll holds the lock this returns {"skipped_locked": true},
    matching the other two endpoints.

    shipit-usdt-poller.timer alone won't overlap two runs on one host (oneshot
    + OnUnitInactiveSec re-arms only after the previous run exits), but nothing
    about this endpoint depends on that: it is plain authenticated HTTP, so an
    operator curl during a scheduled run, two app instances mid-deploy, or a
    second host all produce a concurrent poll. The lock, not the schedule, is
    what makes the grant safe.

    Cost of holding it: one of the pool's max_size=5 connections for the whole
    run, including the TronGrid call (30s timeout in fetch_transfers) -- the
    same trade-off the Fix Pack and monitoring processors already accept.
    """
    token = usdt_trc20.poll_token_from_env()
    if not token:
        raise HTTPException(
            status_code=503,
            detail={"reason": "poll_not_configured",
                    "detail": "USDT_POLL_TOKEN is not set on this deployment"},
        )
    _require_bearer_token(request, token)

    address = _usdt_receiving_address()
    if not address:
        raise HTTPException(
            status_code=503,
            detail={"reason": "usdt_not_configured",
                    "detail": "USDT_TRC20_ADDRESS is not set on this deployment"},
        )
    try:
        async with usdt_poll_lock():
            return await usdt_trc20.poll_and_match(
                payment_repo, account_repo, address=address,
                api_key=usdt_trc20.trongrid_api_key_from_env(), transport=transport,
                fixpack_repo=fixpack_repo, audit_repo=audit_repo,
            )
    except ProcessorLockBusy:
        # Another poll holds the lock — benign. The scheduler logs and moves on.
        return {"skipped_locked": True}


async def _resolve_pr_token(owner: str, repo: str) -> str | None:
    """The token delivery.open_pull_request should use for owner/repo: a
    GitHub App installation token when the App is configured (works for any
    repo the App is installed on), else None so delivery falls back to the
    single-operator GITHUB_PR_TOKEN. Same resolution the Deploy Pack flow
    does inline in create_fixpack — kept identical so both PR paths behave
    the same."""
    app_creds = app_credentials_from_env()
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
        "GITHUB_APP_PRIVATE_KEY=%s, app_credentials_from_env=%s",
        owner, repo,
        len(app_id_env) if app_id_env else "MISSING",
        len(pem_env) if pem_env else "MISSING",
        "None" if app_creds is None else "present",
    )
    if app_creds is None:
        return None
    app_id, private_key = app_creds
    return await run_in_threadpool(
        installation_token_for_repo, owner, repo,
        app_id=app_id, private_key=private_key,
    )


def _failure_detail(exc: BaseException, *, limit: int = 300) -> str:
    """A short, secret-free description of a failure for the fixpack_jobs
    `detail` column: exception type + message, truncated. Never carries a
    secret value — the generation pipeline never puts one in an exception,
    but truncation is a second guard against an over-long message."""
    detail = f"{type(exc).__name__}: {exc}".strip()
    return detail[:limit]


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
        "Your free audit was a static scan. This one adds the depth it left "
        "out -- authentication and access rules, injection risk in your "
        "queries -- and carries a readiness score, which a static-only audit "
        "deliberately does not:\n\n"
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
) -> str:
    """Generate + deliver one paid Fix Pack job. Returns the outcome:
    'delivered', 'no_fix_needed', 'blocked', 'deferred', or 'failed'. Advances
    the job's status to match so a re-run of the processor doesn't pick it up
    again (a 'failed' or 'blocked' job stays visible for a human to retry/review
    rather than silently stuck on 'paid'). 'blocked' means the generated
    fix passed syntax validation but the semantic check (running the
    client's own tests against the patched tree) found a regression, so the
    PR was withheld for manual review.

    'deferred' is the one outcome that does NOT advance the status: the semantic
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

        title = render_fixpack_pr_title(plan)
        body = render_fixpack_pr_body(plan)
        if semantic.pr_note:
            body = f"{body}\n\n{semantic.pr_note}"

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
                f"Drydock: Fix Pack {job_id} delivered WITHOUT the full "
                "review the purchase includes. The PR is fine; the review "
                "is owed. Re-run it manually and send the buyer the link."
            )
        token = await _resolve_pr_token(owner, repo)
        opened = await run_in_threadpool(
            pr_opener, owner, repo, plan.files,
            title=title, body=body, branch_prefix="drydock/fix-pack",
            deletions=plan.deletions, token=token, job_id=job_id,
        )
        await fixpack_repo.mark_fixpack_delivered(job_id, opened.html_url)
        await _record_fix_outcome(
            fix_outcome_repo, job=job, outcome="delivered",
            rule_ids=_rule_ids_from_plan(plan), is_regression=False,
            pr_url=opened.html_url,
        )
        return "delivered"
    except GitHubAppAuthError as exc:
        # GitHub refused our own App credentials. Nothing about this job or
        # this customer's repository was reached, so the three things the
        # generic handler below does would all be wrong here:
        #
        #   * 'failed' is terminal, and this job is perfectly deliverable the
        #     moment an operator fixes the key -- failing it bills a customer
        #     for our outage and leaves recovery to hand-editing the database;
        #   * the attempt the claim charged walks it toward the reaper's
        #     terminal 'failed' for a reason no retry of theirs can fix;
        #   * a fix_outcomes row would record OUR outage as the outcome of a
        #     fix, in the one table we intend to learn from later.
        #
        # So the job goes back on the queue, unspent, and the operator is told
        # what is actually broken. Same shape as the verification_unavailable
        # branch above: when we could not do our job, the customer's job waits.
        detail = _failure_detail(exc)
        logger.error(
            "Fix Pack job %s deferred: GitHub App credentials rejected (%s)",
            job_id, detail,
            extra={"step": "github_app_auth",
                   "duration_ms": _elapsed_ms(started)},
        )
        await fixpack_repo.release_to_paid(
            job_id,
            f"requeued: GitHub App credentials rejected — {detail}",
        )
        await _alert_github_app_auth_failed(detail)
        return "auth_rejected"
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
                elif outcome == "auth_rejected":
                    # Already back on 'paid' with its attempt refunded, so
                    # unlike the branch above this one is NOT waiting for the
                    # reaper -- it is immediately re-claimable, which is exactly
                    # why the loop must stop. A broken App key rejects every
                    # job identically, so draining on would spin through the
                    # whole backlog releasing and re-claiming the same rows.
                    #
                    # Reported separately from `deferred` because the two mean
                    # different things to whoever reads the summary: one is a
                    # sandbox outage that heals itself, the other needs a human
                    # to edit .env before any Fix Pack can ever be delivered.
                    summary["skipped_github_app_auth"] = True
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
    if not MONITORING_FOR_SALE:
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





















@app.post("/internal/service-flags/llm_paid_ops")
async def set_llm_paid_ops(
    request: Request,
    service_flags_repo: ServiceFlagsRepository = Depends(get_service_flags_repo),
) -> dict:
    """Operator-only emergency stop toggle for all paid LLM operations.

    Body: JSON {"enabled": bool, "note": str?}. Setting enabled=false pauses new
    /v1/audits (they 503 service_paused) and the monitoring drain (it no-ops,
    leaving the backlog pending); enabled=true resumes. The note is echoed to
    callers in the 503 detail, so use it to say who paused and why.

    Requires `Authorization: Bearer <SERVICE_FLAGS_TOKEN>`, constant-time
    compared. 503 if the token isn't configured -- a kill switch with no auth is
    worse than none. 503 too if DATABASE_URL isn't set: there is no flag store to
    write, so a caller must not believe a pause took effect when it didn't."""
    token = _service_flags_token()
    if not token:
        raise HTTPException(
            status_code=503,
            detail={"reason": "service_flags_not_configured",
                    "detail": "SERVICE_FLAGS_TOKEN is not set on this deployment"},
        )
    _require_bearer_token(request, token)

    # This endpoint already guarded the parse by hand; _json_object_body is
    # that same guard, so the local try/except would now only catch what it
    # already raised as a 422. The value check below stays -- the helper knows
    # the body is an object, not what belongs in it.
    body = await _json_object_body(request)
    if not isinstance(body.get("enabled"), bool):
        raise HTTPException(
            status_code=422,
            detail={"reason": "bad_request",
                    "detail": "body must be JSON with a boolean 'enabled'"},
        )
    enabled = body["enabled"]
    note = body.get("note")
    if note is not None and not isinstance(note, str):
        raise HTTPException(
            status_code=422,
            detail={"reason": "bad_request", "detail": "'note' must be a string"},
        )

    row = await service_flags_repo.set("llm_paid_ops", enabled=enabled, note=note)
    if row is None:
        raise HTTPException(
            status_code=503,
            detail={"reason": "not_configured",
                    "detail": "no flag store (DATABASE_URL is not set)"},
        )
    # Make the new value visible immediately rather than after the TTL, and
    # alert the operator when the stop is engaged (mandatory on emergency stop).
    _reset_service_flag_cache()
    if not enabled:
        await alerts.notify_operator(
            f"Emergency stop ENGAGED via API: llm_paid_ops set OFF. "
            f"Note: {note or '(none)'}",
            dedupe_key="llm-paid-ops-paused",
        )
    return {"key": "llm_paid_ops", "enabled": enabled, "note": note}


@app.post("/v1/audits", status_code=202)
async def create_audit(
    request: Request,
    archive: UploadFile | None = None,
    repo_url: str | None = Form(
        None,
        description="Alternative to `archive`: a public github.com repo URL "
                    "(https://github.com/<owner>/<repo>). Provide exactly one "
                    "of `archive` or `repo_url`. Public GitHub repos only — no "
                    "private repos, no other hosts.",
    ),
    limiter: RateLimiter = Depends(get_rate_limiter),
    audit_repo: AuditRepository = Depends(get_audit_repo),
    account_repo: AccountRepository = Depends(get_account_repo),
    repo_fetcher=Depends(get_repo_fetcher),
    service_flags_repo: ServiceFlagsRepository = Depends(get_service_flags_repo),
    audit_job_repo: AuditJobRepository = Depends(get_audit_job_repo),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
) -> dict:
    """Accept an audit and hand back a job to poll.

    Asynchronous since Stage 2: the scan itself runs in the audit worker
    (`python -m app.worker`), and this endpoint returns as soon as the job is
    durably queued. Everything that can be decided from the submission alone
    still happens here, before the enqueue, and still answers with the same
    status codes it always did -- intake shape, the emergency stop, the repo
    fetch, zip validation, stack detection, the daily quota. Rejecting those at
    intake keeps the queue free of jobs that are already known to be dead, and
    keeps a client's error for a bad upload immediate instead of arriving two
    polls later.

    The content-hash cache is likewise still checked here, and a hit still
    returns the finished audit inline with no job created at all: the result
    already exists, so making the client poll for it would be slower for no
    gain.

    Response on a miss is 202 {job_id, access_token, state}. See
    GET /v1/audit-jobs/{job_id}."""
    # Exactly one intake method: not both, not neither. Both-None and
    # both-present are the two cases where the equality holds.
    if (archive is None) == (repo_url is None):
        raise HTTPException(
            status_code=422,
            detail={"reason": "bad_intake",
                    "detail": "provide exactly one of 'archive' (file upload) "
                              "or 'repo_url' (public GitHub repo URL)"},
        )

    # Emergency stop: a direct API caller gets a clear 503 (with the operator's
    # note) before any repo fetch or scan work is done. Checked here, at the
    # very start, so a paused service spends nothing. The mandatory operator
    # alert fires inside _emergency_stop_active.
    intake_started = time.monotonic()
    paused, note = await _emergency_stop_active(service_flags_repo)
    if paused:
        raise HTTPException(
            status_code=503,
            detail={"reason": "service_paused", "detail": note},
        )

    # Resolve the caller's tier from an optional API key. No key -> None ->
    # free, with no DB call, so anonymous traffic is byte-for-byte unchanged.
    # The only entitlement enforced here is daily_audit_limit (below).
    account = await accounts.resolve_account(request, account_repo)
    _bind_account(account)
    tier = account["tier"] if account else TIER_FREE
    entitlements = entitlements_for_tier(tier, free_daily_limit=limiter.limit)

    # The source URL to remember on the audit, so a later Fix Pack purchase
    # can re-fetch the same repo without asking for it again. Only set on
    # the GitHub-URL intake path; null for zip uploads (nothing to re-fetch).
    source_url: str | None = None
    if archive is not None:
        raw = await archive.read(MAX_ARCHIVE_BYTES + 1)
    else:
        # `entitlements.private_repos_allowed` (free=False, pro=True) is the
        # flag that WOULD gate private-repo intake here — but private repos
        # aren't fetchable at all yet (github_fetch.py is public-only, no
        # auth), so there is nothing private to reach and the flag has no
        # visible effect until private-repo support is built. Not enforced
        # with a fake `if` that can never fire; wire the real gate here when
        # private intake exists.
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
    if stack is Stack.UNSUPPORTED:
        raise HTTPException(
            status_code=422,
            detail={"reason": "unsupported_stack",
                    "detail": "We can audit Next.js, Vite + React, and FastAPI "
                              "projects. This repository looks like none of "
                              "them."},
        )

    # Consume quota only after the upload proves to be real work: validation
    # and stack detection are free, so a garbage/hostile zip (or probing for
    # validation bypasses) can't burn a client's daily budget for a request
    # that never produced an audit.
    #
    # Tier-aware: an anonymous/free caller is keyed and limited exactly as
    # before (by client IP, at the limiter's configured limit — passing that
    # same limit explicitly is a no-op). A pro account is keyed by its own id
    # (so its budget follows the account, not whatever IP it calls from) and
    # gets the higher pro limit.
    if account is not None:
        quota_key = f"account:{account['id']}"
    else:
        quota_key = _client_key(request)
    try:
        limiter.check(quota_key, limit=entitlements.daily_audit_limit)
    except RateLimitExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail={
                "reason": "rate_limited",
                "detail": f"max {limiter.limit} audits per day",
            },
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc

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
        idempotency_key=(
            idempotency_key
            or _audit_idempotency_key(
                digest, account["id"] if account else None)
        ),
    )
    logger.info(
        "audit intake: queued job %s", enqueued["job_id"],
        extra={"step": "enqueue", "duration_ms": _elapsed_ms(stage_started)},
    )
    return enqueued


def _audit_idempotency_key(digest: str, account_id: str | None) -> str:
    """The default key for a submission the client did not label itself.

    (content, engine version, submitter) -- so a double-clicked upload joins the
    job already running instead of queueing a second identical scan, while two
    different callers submitting the same bytes stay independent (they have
    separate quotas, and one's job going terminal must not decide the other's
    outcome). The engine version is in the key for the same reason it is in the
    cache key: after a bump the same content is genuinely different work."""
    material = f"{digest}|{AUDIT_ENGINE_VERSION}|{account_id or 'anon'}"
    return hashlib.sha256(material.encode()).hexdigest()


async def _enqueue_audit_job(
    audit_job_repo: AuditJobRepository, *, raw: bytes | None, source_kind: str,
    source_url: str | None, digest: str, stack: str, account_id: str | None,
    quota_key: str | None, idempotency_key: str,
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
        idempotency_key=idempotency_key,
    )
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

    PR delivery uses a GitHub App installation token when
    GITHUB_APP_ID + GITHUB_APP_PRIVATE_KEY are configured (works for
    any repo the App is installed on, not just the operator's own),
    falling back to the single-operator GITHUB_PR_TOKEN otherwise —
    see app/deploypack/github_app.py and app/deploypack/delivery.py.

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
                token: str | None = None
                app_creds = app_credentials_from_env()
                if app_creds is not None:
                    app_id, private_key = app_creds
                    token = await run_in_threadpool(
                        installation_token_for_repo, owner, repo,
                        app_id=app_id, private_key=private_key,
                    )
                opened = await run_in_threadpool(
                    pr_opener, owner, repo, result["files"], body=body,
                    token=token, job_id=job_id,
                )
            except (DeliveryError, GitHubAppError) as exc:
                pr = {"delivered": False, "reason": str(exc)}
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
app.include_router(billing_router)
app.include_router(operator_router)
app.include_router(paypal_router)
app.include_router(reads_router)
app.include_router(session_router)
app.include_router(storefront_router)
