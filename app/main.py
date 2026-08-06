"""Drydock API gateway — MVP phase 1 surface.

Only what exists today: health check and archive intake with validation,
rate limiting, stack detection, static scan, and (when providers are
configured) the LLM auth/security scan. Persistence and the queue come
next — the scan stage runs off the event loop in a threadpool for now,
since the LLM call alone can take up to ~2 minutes.
"""

from __future__ import annotations

import asyncio
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
    Depends, FastAPI, Form, Header, HTTPException, Request, Response, UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field, field_validator
from starlette.concurrency import run_in_threadpool

from app.alerts import notify_operator
from app.audit_spool import SpoolFull, cleanup_staged_archive, stage_archive
from app.accounts import (
    CSRF_HEADER,
    TIER_FREE,
    account_for_key,
    clear_api_key_cookie,
    entitlements_dict,
    entitlements_for_tier,
    resolve_account,
    set_api_key_cookie,
    validate_api_key_pepper_configured,
)
from app.billing import bank_transfer, paypal, telegram_stars, usdt_trc20
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
    STALE_LEASE_DETAIL_PREFIX,
    ServiceFlagsRepository,
    SubscriptionRepository,
    database_url_from_env,
    fixpack_processor_lock,
    monitoring_processor_lock,
    usdt_poll_lock,
)
from app.deploypack.delivery import DeliveryError, open_pull_request, render_pr_body
from app.deploypack.generate import UnsupportedForDeployPack
from app.deploypack.github_app import (
    GitHubAppAuthError,
    GitHubAppError,
    app_auth_ok,
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
from app.ingest.github_fetch import RepoFetchError, fetch_repo_zip
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
from app.report.html import render_report
from app.ratelimit import RateLimitExceeded, RateLimiter, limiter_from_env
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


def _bind_account(account: dict | None) -> None:
    """Put the resolved account on the log context for the rest of the request.

    Anonymous traffic leaves the field as None rather than writing a
    placeholder, so "account_id absent" reads as "no key presented" instead of
    being confusable with a real account. Safe to call unscoped:
    bind_request_context binds account_id too, so its reset on the way out
    clears whatever a handler set here.
    """
    if account is not None:
        set_log_context(account_id=str(account["id"]))




_limiter = limiter_from_env()


def get_rate_limiter() -> RateLimiter:
    """FastAPI dependency indirection — overridable in tests."""
    return _limiter


def get_llm_client() -> LLMClient:
    """FastAPI dependency indirection — overridable in tests."""
    return LLMClient()


def get_pr_opener():
    """FastAPI dependency indirection — overridable in tests."""
    return open_pull_request


def get_repo_fetcher():
    """FastAPI dependency indirection — overridable in tests so the URL
    intake path never makes a real network call under pytest."""
    return fetch_repo_zip


_preview_registry = PreviewRegistry()


def get_preview_registry() -> PreviewRegistry:
    """FastAPI dependency indirection — overridable in tests. In-memory,
    single-process, same caveat as get_rate_limiter."""
    return _preview_registry


def get_preview_reconciler():
    """FastAPI dependency indirection — overridable in tests so the reap
    endpoint never shells out to a real `docker ps`. Routes through the
    sandbox-runner client (Variant A): the backend never execs docker itself."""
    return sandbox_client.reconcile_previews


_audit_repo = AuditRepository()
_audit_job_repo = AuditJobRepository()
_fixpack_repo = FixpackJobRepository()
_fix_outcome_repo = FixOutcomeRepository()
_account_repo = AccountRepository()
_payment_repo = PaymentRepository()
_subscription_repo = SubscriptionRepository()
_monitoring_repo = MonitoringRunRepository()
_llm_usage_repo = LlmUsageRepository()
_service_flags_repo = ServiceFlagsRepository()


def get_payment_repo() -> PaymentRepository:
    """FastAPI dependency indirection — overridable in tests. No-ops
    (returns None/[]) when DATABASE_URL isn't set — see app/db.py."""
    return _payment_repo


def get_billing_transport():
    """Outbound HTTP transport for the billing providers (Telegram Bot
    API, TronGrid). None -> httpx's real transport in production;
    overridden in tests with an httpx.MockTransport so the suite never
    touches the network, same idea as get_repo_fetcher."""
    return None


def get_paypal_transport():
    """Outbound HTTP transport for the PayPal REST calls (OAuth token, orders,
    subscriptions, webhook-signature verify). None -> httpx's real transport in
    production; overridden in tests with an httpx.MockTransport so the suite
    never touches PayPal, same idea as get_billing_transport."""
    return None


def get_account_repo() -> AccountRepository:
    """FastAPI dependency indirection — overridable in tests. No-ops
    (returns None) when DATABASE_URL isn't set, so a request carrying an
    API key on an unconfigured deployment falls back to anonymous/free —
    see app/db.py and app/accounts.py."""
    return _account_repo


def get_audit_repo() -> AuditRepository:
    """FastAPI dependency indirection — overridable in tests. No-ops
    (returns None from create/get) when DATABASE_URL isn't set — see
    app/db.py."""
    return _audit_repo


def get_audit_job_repo() -> AuditJobRepository:
    """Same as get_audit_repo, for the durable audit queue (migration 0022).

    Registered here so the queue has one canonical, test-overridable instance
    from the moment the schema lands. Nothing depends on it yet -- the endpoints
    that will (enqueue + poll) arrive in PR2."""
    return _audit_job_repo


def get_fixpack_repo() -> FixpackJobRepository:
    """Same as get_audit_repo, for fixpack_jobs."""
    return _fixpack_repo


def get_fix_outcome_repo() -> FixOutcomeRepository:
    """Same as get_audit_repo, for the fix_outcomes knowledge base."""
    return _fix_outcome_repo


def get_subscription_repo() -> SubscriptionRepository:
    """Same as get_audit_repo, for recurring Stars subscriptions."""
    return _subscription_repo


def get_monitoring_repo() -> MonitoringRunRepository:
    """Same as get_audit_repo, for the async continuous-monitoring queue."""
    return _monitoring_repo


def get_llm_usage_repo() -> LlmUsageRepository:
    """Same as get_audit_repo, for the llm_usage cost journal."""
    return _llm_usage_repo


def get_service_flags_repo() -> ServiceFlagsRepository:
    """Same as get_audit_repo, for the service_flags kill switches."""
    return _service_flags_repo


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
    await notify_operator(
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
        await notify_operator(
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


def _reap_token() -> str | None:
    """Same env-var pattern as GITHUB_PR_TOKEN in delivery.py. Unset by
    default — the endpoint below refuses to run rather than accept an
    empty/no-op auth check."""
    return os.environ.get("PREVIEW_REAP_TOKEN") or None


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


def _audit_jobs_stats_token() -> str | None:
    """Bearer token protecting GET /internal/audit-jobs/stats, same env-var
    pattern as the other internal endpoints.

    Its own token rather than a reused one on purpose: the existing tokens
    authorise ACTIONS (drain a backlog, flip the kill switch), and the thing
    that wants queue depth is a monitoring scraper -- something that should be
    able to read without holding a credential that can also start work. Unset
    -> the endpoint 503s rather than accept a no-op auth check."""
    return os.environ.get("AUDIT_JOBS_STATS_TOKEN") or None


def _service_flags_token() -> str | None:
    """Bearer token protecting the emergency-stop toggle endpoint, same env-var
    pattern as MONITORING_PROCESS_TOKEN. Unset -> the endpoint 503s rather than
    accept a no-op auth check on a switch that can halt all paid LLM ops."""
    return os.environ.get("SERVICE_FLAGS_TOKEN") or None


def _secret_equals(provided: str, expected: str) -> bool:
    """Constant-time comparison of a header value against a configured secret.

    `hmac.compare_digest` on two str arguments raises TypeError the moment
    either side holds a character above 127 -- "comparing strings with
    non-ASCII characters is not supported". Header values reach us as str, and
    a client is free to put any byte in one, so a request with a Cyrillic
    Authorization header used to raise inside the auth check and land in the
    global handler: a 500, a traceback, and an operator alert, for a request
    that should simply have been told 401.

    Comparing bytes instead has no such restriction. The two sides are encoded
    differently on purpose:

      - `provided` came from the wire, and the ASGI server decoded those bytes
        as latin-1, which is a byte-for-byte mapping. Encoding it back as
        latin-1 therefore reconstructs exactly what the client sent, and can
        never fail, because every character is <= 0xFF by construction.
      - `expected` came from the environment as text, so it encodes as UTF-8,
        which is what a shell wrote into it.

    That pairing means a non-ASCII secret actually WORKS, rather than being
    compared against mismatched bytes. An ASCII secret -- every one we have --
    encodes identically either way, so nothing about today's behaviour moves
    except that the wrong answer is now 401 instead of 500.
    """
    return hmac.compare_digest(
        provided.encode("latin-1"), expected.encode("utf-8")
    )


def _require_bearer_token(request: Request, token: str) -> None:
    """Constant-time check of `Authorization: Bearer <token>`, raising 401
    on mismatch. The single implementation shared by every internal
    operational endpoint (reaper, USDT poller, Fix Pack processor) so the
    comparison stays constant-time in one place and can't drift."""
    provided = request.headers.get("authorization", "")
    if not _secret_equals(provided, f"Bearer {token}"):
        raise HTTPException(status_code=401, detail={"reason": "unauthorized"})


def _client_key(request: Request) -> str:
    """Client IP, honoring exactly one reverse-proxy hop (Caddy in prod).

    The LAST X-Forwarded-For entry, not the first. Caddy appends the peer
    address to whatever header arrived, so on `XFF: 1.2.3.4` from a client the
    backend sees `1.2.3.4, <real ip>` — reading entry [0] returns a value the
    client chose. That is the free tier's daily audit quota, so a client
    rotating the header buys unlimited LLM spend. Entry [-1] is the one our own
    proxy wrote and is the only entry nobody upstream of it can forge.

    Assumes exactly one trusted hop. If a CDN is ever put in front of Caddy the
    trusted entry moves and this has to count hops instead. Only safe behind a
    proxy at all — do not reuse this helper if the app is ever exposed to the
    internet directly.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.get("/health")
async def health(
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
) -> dict:
    """Richer, still-public health probe. Unlike the static /healthz (kept
    for the race-after-restart liveness check the README documents), this
    reports two things that actually fail in this system:

      * `db` — is the database reachable at all (distinguishes "process up"
        from "process up but the Supabase pooler is unreachable");
      * `fixpack_backlog` / `oldest_paid_seconds` — is the Fix Pack processor
        timer draining the queue, or is a paid job stuck (see
        FixpackJobRepository.backlog_stats);
      * `github_app` — does GitHub still accept our App credentials. A key
        that no longer matches the App breaks every Fix Pack delivery on
        this deployment, and before this it was invisible until a paying
        customer's job hit a 401. `null` means App auth isn't configured
        here at all (the PAT path), which is not a fault. Cached for five
        minutes inside app_auth_ok, so this stays cheap for a pinger.

    Deliberately leak-free: only booleans and coarse counts/ages — never ids,
    urls, or error text — so it's safe to expose to a dumb uptime pinger or
    the systemd timer without a token. Always 200: an unconfigured or
    unreachable DB is reported as db:false (a live process honestly saying
    it's degraded), not a transport-level failure the pinger can't read."""
    # Blocking httpx call, so off the event loop. Never raises by contract.
    github_app = await run_in_threadpool(app_auth_ok)
    stats = await fixpack_repo.backlog_stats()
    if stats is None:
        # DATABASE_URL unset, or the pool couldn't be built — either way the
        # DB isn't usable. Report degraded rather than 503 (see docstring).
        return {"db": False, "fixpack_backlog": None,
                "oldest_paid_seconds": None, "github_app": github_app}
    return {
        "db": True,
        "fixpack_backlog": stats["backlog"],
        "oldest_paid_seconds": stats["oldest_paid_seconds"],
        "github_app": github_app,
    }


async def _json_object_body(request: Request) -> dict:
    """The request body as a JSON object, or 422.

    `await request.json()` raises on a malformed body, and every endpoint that
    called it bare turned a typo into a 500 -- which the global handler logs
    with a traceback AND pages the operator for. A client sending broken JSON
    is not an incident; it is the client's mistake, and the response should
    say which.

    Non-objects are refused for the same reason one level down. A body of `[]`
    or `"hi"` parses fine, and the next line is always `body.get(...)`, so it
    became AttributeError -- a 500 by a slightly longer route.

    422 rather than 400 to match every other body-shape refusal in this API,
    including the one place that already guarded this (the service-flags
    endpoint). Webhook senders retry on any non-2xx, so this does not stop
    Telegram or PayPal re-delivering an unparseable payload -- but a retry that
    fails identically is cheap, while a 500 also wakes someone up.
    """
    try:
        body = await request.json()
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        body = None

    if not isinstance(body, dict):
        raise HTTPException(
            status_code=422,
            detail={"reason": "invalid_json",
                    "detail": "request body must be a JSON object"},
        )
    return body


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
    await notify_operator(
        f"Drydock: unhandled 5xx [{request_id}] on {request.method} "
        f"{request.url.path} — {type(exc).__name__}",
        dedupe_key=f"unhandled-5xx:{request.url.path}:{type(exc).__name__}",
    )
    return JSONResponse(
        status_code=500,
        content={"detail": {"reason": "internal_error", "request_id": request_id}},
        headers={REQUEST_ID_HEADER: request_id} if request_id else None,
    )


@app.post("/internal/preview/reap")
async def reap_previews(
    request: Request,
    preview_registry: PreviewRegistry = Depends(get_preview_registry),
    reconciler=Depends(get_preview_reconciler),
) -> dict:
    """Operational endpoint for the scheduled reaper — called hourly by
    shipit-reap.timer on the production VPS (a former GitHub Actions
    workflow doing the same thing was removed 2026-07-14: it never had
    its repo secrets configured and was redundant once the VPS timer
    existed). Not part of the public API surface; there's no
    user-facing reason to call this directly.

    Requires `Authorization: Bearer <PREVIEW_REAP_TOKEN>`. Returns 503
    if the token isn't configured on this deployment at all, rather
    than silently doing nothing — an unconfigured reaper is an
    operational gap someone needs to notice, not a quiet no-op.
    """
    token = _reap_token()
    if not token:
        raise HTTPException(
            status_code=503,
            detail={"reason": "reap_not_configured",
                    "detail": "PREVIEW_REAP_TOKEN is not set on this deployment"},
        )
    # Constant-time compare so response latency doesn't leak the token.
    _require_bearer_token(request, token)

    reaped = await run_in_threadpool(preview_registry.reap_expired)
    # In-memory reap only knows this process's containers; after a restart the
    # registry is empty while real preview containers may still be running.
    # reconcile_previews asks Docker directly and ages out orphans by their
    # shipit.expires_at label, regardless of what this process remembers.
    reconciled = await run_in_threadpool(reconciler)
    return {
        "reaped": reaped,
        "active": preview_registry.active_count(),
        "reconciled": reconciled,
    }


@app.get("/v1/audits/{audit_id}")
async def get_audit(
    audit_id: str,
    token: str | None = None,
    audit_repo: AuditRepository = Depends(get_audit_repo),
) -> dict:
    # Ownership check: the audit is readable only by presenting its per-row
    # access_token (?token=...), delivered once at creation. A leaked id is
    # not enough. A missing/wrong token is answered 404 (not 403) so this
    # never confirms an id exists to someone who doesn't hold its token.
    #
    # Bound before the lookup, not after: a failed authorization is exactly the
    # request whose logs need the id someone asked for.
    set_log_context(audit_id=audit_id)
    row = await audit_repo.get_authorized(audit_id, token)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no audit with this id and token, or persistence "
                               "isn't configured on this deployment (see app/db.py)"},
        )
    # Whether a Fix Pack could produce anything for this audit. Computed here,
    # not in the browser: the answer depends on which rules the Fix Pack knows
    # how to rewrite, and a second copy of that list in TypeScript would drift
    # from this one -- which is precisely what #132 was about. The page uses it
    # to explain instead of offering a purchase that cannot deliver.
    return {
        **row,
        "fixpack_auto_fixable": has_auto_fixable_findings(
            row.get("findings_json") or []
        ),
    }


@app.get("/v1/audit-jobs/{job_id}")
async def get_audit_job(
    job_id: str,
    token: str | None = None,
    audit_job_repo: AuditJobRepository = Depends(get_audit_job_repo),
) -> dict:
    """Poll one queued audit's progress (durable queue, migration 0022).

    Same ownership model as GET /v1/audits/{id}: the per-row access_token,
    handed to the submitter once at enqueue, is the only key, and anything that
    doesn't match -- wrong token, no token, unknown id -- is a flat 404 so this
    never confirms a job id to someone who doesn't hold its token.

    Deliberately narrow. `state` and `audit_id` are what a client polls for
    (audit_id is null until the job succeeds, then it is the row to fetch via
    GET /v1/audits/{id}), and `error_code` is the machine-readable reason a
    terminal job has no result. The internals a caller has no business acting
    on -- claimed_by, lease_expires_at, attempts, quota_key, idempotency_key,
    the free-text error_message -- stay server-side, and the job's own
    access_token is never selected by get_authorized in the first place.

    The one addition is `audit_access_token`: the finished audit is protected by
    its OWN token, so audit_id alone would leave a poller unable to read the
    result it waited for. It is null until the job succeeds. Handing it to the
    holder of the job token is not a widening -- POST /v1/audits returned the
    audit token directly to that same submitter before the cutover."""
    set_log_context(job_id=job_id)
    row = await audit_job_repo.get_authorized(job_id=job_id, access_token=token)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no audit job with this id and token, or "
                              "persistence isn't configured on this "
                              "deployment (see app/db.py)"},
        )
    return {
        "id": row["id"],
        "state": row["state"],
        "error_code": row["error_code"],
        "audit_id": row["audit_id"],
        "audit_access_token": row.get("audit_access_token"),
        "created_at": row["created_at"],
        "completed_at": row["completed_at"],
    }


@app.get("/v1/audits/{audit_id}/report")
async def get_audit_report(
    audit_id: str,
    token: str | None = None,
    audit_repo: AuditRepository = Depends(get_audit_repo),
) -> HTMLResponse:
    """The shareable artifact: the same persisted audit rendered as a
    self-contained, plain-language HTML page. Requires the audit's
    access_token (?token=...) -- same ownership check as GET /v1/audits/{id}."""
    set_log_context(audit_id=audit_id)
    row = await audit_repo.get_authorized(audit_id, token)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no audit with this id and token, or persistence "
                               "isn't configured on this deployment (see app/db.py)"},
        )
    # render_report expects a well-formed score dict; guard at the API
    # boundary so a partially-written/backfilled row (null or malformed
    # score_json) is a deliberate error, not an unhandled KeyError -> 500.
    score = row.get("score_json")
    if not isinstance(score, dict) or "total" not in score or "categories" not in score:
        raise HTTPException(
            status_code=422,
            detail={"reason": "report_unavailable",
                    "detail": "this audit has no complete score to render a "
                               "report from (score_json is missing or malformed)"},
        )
    result = {"score": score, "findings": row.get("findings_json") or []}
    html = render_report(result, project_name=f"audit {audit_id[:8]}")
    # Tight CSP scoped to this self-contained report page: it inlines a
    # <style> block (hence style-src 'unsafe-inline') but loads no scripts,
    # images, or any external asset, so everything else is denied. Scoped
    # here so it never touches /docs, /redoc, or JSON responses.
    csp = (
        "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
        "form-action 'none'; frame-ancestors 'none'"
    )
    return HTMLResponse(content=html, headers={"Content-Security-Policy": csp})


@app.post("/v1/auth/login")
async def auth_login(
    request: Request,
    response: Response,
    limiter: RateLimiter = Depends(get_rate_limiter),
    account_repo: AccountRepository = Depends(get_account_repo),
) -> dict:
    """Exchange an API key for a session cookie the page cannot read.

    The one place that sets the cookie. The key is revealed by several
    endpoints -- rotate-key and each payment poll -- and it was tempting to
    set the cookie on all of them; that spreads a credential-handling
    decision across five handlers that otherwise share nothing. The frontend
    already funnels every "I have a key" event through one call, so this
    stays one handler with one test.

    Answers exactly like GET /v1/account, so the caller needs no second
    request to learn what the key bought. An unrecognized key 401s rather
    than quietly returning the free tier: the caller asserted they have a
    key, and silently downgrading them would look like a working login that
    bought nothing.
    """
    body = await _json_object_body(request)
    api_key = str(body.get("api_key") or "").strip()
    if not api_key:
        raise HTTPException(
            status_code=422,
            detail={"reason": "bad_intake", "detail": "'api_key' is required"},
        )

    account = await account_for_key(api_key, account_repo)
    if account is None:
        raise HTTPException(
            status_code=401,
            detail={"reason": "unauthorized",
                    "detail": "no account recognized for the presented API key"},
        )

    _bind_account(account)
    set_api_key_cookie(response, api_key)
    entitlements = entitlements_for_tier(
        account["tier"], free_daily_limit=limiter.limit)
    return {
        "tier": account["tier"],
        "authenticated": True,
        "entitlements": entitlements_dict(entitlements),
    }


@app.post("/v1/auth/logout")
async def auth_logout(response: Response) -> dict:
    """Forget the session cookie.

    Parity, not a feature: "forget this key" used to be a sessionStorage
    removal the page did by itself. An HttpOnly cookie can only be cleared by
    the server that set it, so without this the UI's clear button would leave
    the session live -- worse than what it replaced.

    Unauthenticated on purpose. Clearing your own cookie is not a privileged
    act, and requiring a valid session to log out means a stale one can never
    be cleared.
    """
    clear_api_key_cookie(response)
    return {"ok": True}


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
    account = await resolve_account(request, account_repo)
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
    account = await resolve_account(request, account_repo)
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


def _usdt_receiving_address() -> str | None:
    """Configured receiving address as a base58check "T..." string, or None
    if unset. A set-but-malformed USDT_TRC20_ADDRESS is a 503 (misconfig)
    rather than a 500 or, far worse, a bad address handed to a payer."""
    try:
        return usdt_trc20.receiving_address_from_env()
    except usdt_trc20.InvalidTronAddressError as exc:
        raise HTTPException(
            status_code=503,
            detail={"reason": "usdt_misconfigured",
                    "detail": f"USDT_TRC20_ADDRESS is not a valid TRON address: {exc}"},
        )


@app.post("/v1/billing/usdt/invoice", status_code=201)
async def create_usdt_invoice(
    request: Request,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    limiter: RateLimiter = Depends(get_rate_limiter),
) -> dict:
    """Open a USDT/TRC20 invoice: returns the fixed receiving address and
    a unique amount to send (base price + sub-cent nonce, so incoming
    transfers can be matched back to invoices without per-invoice
    addresses). Poll GET /v1/billing/usdt/invoice/{id} to collect the API
    key once the on-chain transfer is seen. See app/billing/usdt_trc20.py.

    503 if the receiving address isn't configured, or if DATABASE_URL
    isn't set (the pending invoice row can't be persisted, so there'd be
    nothing to match a later payment against).
    """
    address = _usdt_receiving_address()
    if not address:
        raise HTTPException(
            status_code=503,
            detail={"reason": "usdt_not_configured",
                    "detail": "USDT_TRC20_ADDRESS is not set on this deployment"},
        )
    # After the configuration gates, before the write: a client on a
    # deployment with no address configured should learn that, not be told to
    # slow down about an endpoint that cannot work anyway.
    _check_usdt_invoice_rate_limit(request, limiter)
    invoice = await usdt_trc20.create_invoice(payment_repo, address=address)
    if invoice is None:
        raise HTTPException(
            status_code=503,
            detail={"reason": "not_persisted",
                    "detail": "USDT invoices require DATABASE_URL (a pending "
                              "payment row is created to match payment against)"},
        )
    return invoice


@app.get("/v1/billing/usdt/invoice/{invoice_id}")
async def get_usdt_invoice(
    invoice_id: str,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    account_repo: AccountRepository = Depends(get_account_repo),
) -> dict:
    """Poll one USDT invoice. Reveals the API key only once the invoice is
    `completed` (payment confirmed on-chain by the poller); pending or
    expired invoices never leak a key. 404 if no such invoice."""
    address = _usdt_receiving_address() or ""
    status = await usdt_trc20.invoice_status(
        payment_repo, account_repo, invoice_id, address=address
    )
    if status is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no USDT invoice with this id, or persistence "
                               "isn't configured on this deployment (see app/db.py)"},
        )
    return status


@app.post("/v1/audits/{audit_id}/fixpack/usdt-invoice", status_code=201)
async def create_fixpack_usdt_invoice(
    audit_id: str,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo),
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
) -> dict:
    """Open a USDT/TRC20 invoice to buy a Fix Pack for one specific audit.
    Mirrors POST /v1/billing/usdt/invoice (fixed address + unique amount so
    transfers match without per-invoice addresses; poll the same GET
    /v1/billing/usdt/invoice/{id} to watch it), but at the Fix Pack price
    and scoped to this audit.

    V1 supports GitHub-URL audits only: an audit created from a zip upload
    has no repository to open a fix PR against, so this returns 422 with a
    clear explanation rather than sell a Fix Pack that can't be fulfilled.

    404 if no such audit. 503 if the receiving address isn't configured, or
    if DATABASE_URL isn't set (the pending invoice row can't be persisted).
    """
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
    address = _usdt_receiving_address()
    if not address:
        raise HTTPException(
            status_code=503,
            detail={"reason": "usdt_not_configured",
                    "detail": "USDT_TRC20_ADDRESS is not set on this deployment"},
        )
    invoice = await usdt_trc20.create_fixpack_invoice(
        payment_repo, address=address, audit_id=audit_id
    )
    if invoice is None:
        raise HTTPException(
            status_code=503,
            detail={"reason": "not_persisted",
                    "detail": "USDT invoices require DATABASE_URL (a pending "
                              "payment row is created to match payment against)"},
        )
    return invoice


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


# USDT invoices opened per client key per limiter window (24h).
#
# Unauthenticated for the same reason as the bank-transfer pair: a buyer has
# no API key until they have paid. Until now that meant unbounded -- this was
# the one anonymous endpoint that writes a row per call with nothing to stop
# it repeating.
#
# A SEPARATE limiter key from BANK_TRANSFER_INVOICE_LIMIT, where the two bank
# transfer creators deliberately share one. The reason those share is that
# they draw from the same 99-suffix pool, so one budget is what keeps a client
# from taking twice as much of it. USDT does not draw from that pool at all:
# its nonce is a full micro-dollar (base + randbelow(1_000_000)) and an
# invoice expires after 30 minutes, so exhaustion is not the risk here and a
# shared budget would only make a USDT invoice eat a bank-transfer one.
#
# What IS the risk is anonymous row creation, so the same generous number is
# right for the same reason: well above any real checkout, far below abuse.
USDT_INVOICE_LIMIT = 15


def _check_usdt_invoice_rate_limit(request: Request, limiter: RateLimiter) -> None:
    """429 when one client has opened too many USDT invoices today."""
    try:
        limiter.check(
            f"usdt-invoice:{_client_key(request)}",
            limit=USDT_INVOICE_LIMIT,
        )
    except RateLimitExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail={
                "reason": "rate_limited",
                "detail": f"max {USDT_INVOICE_LIMIT} USDT invoices per day",
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


@app.get("/v1/pricing")
async def get_pricing() -> dict:
    """What is on sale and what it costs, for the storefront.

    Read from the same accessor the invoice creator calls
    (bank_transfer.fixpack_price_usd) so the advertised figure cannot drift
    from the charged one. That is the whole reason this exists as an endpoint
    instead of a number typed into the page: /pricing previously showed no
    price at all, and the comparison table it did show had been stale since
    the free tier dropped to 3 audits.

    FIX PACK ONLY, by product decision. The free tier is static-only and
    costs us nothing to run, so Pro's single live benefit -- a higher daily
    audit limit -- is not something we are willing to take money for. The Pro
    purchase routes stay reachable for the existing customer and the bot;
    they are simply no longer advertised.

    USD only. Telegram Stars and USDT carry their own prices from their own
    accessors, and quoting those here without the channel they belong to
    would invite exactly the mismatch this endpoint exists to prevent.

    Deliberately separate from /v1/billing/details: that payload carries a
    card number for the footer, and a page that only needs a price should not
    have to fetch a payment instrument to get one.
    """
    return {
        "fixpack": {
            "amount": bank_transfer.fixpack_price_usd(),
            "currency": bank_transfer.CURRENCY,
        },
    }


@app.get("/v1/billing/details")
async def get_billing_details() -> dict:
    """The publishable payment requisites, for the site footer.

    Public and unauthenticated on purpose: the footer renders on every page,
    including to visitors who have not started a purchase, and the operator's
    decision is that these requisites are published information. This endpoint
    is the single source for them -- they are still never mirrored into a
    NEXT_PUBLIC_* build variable, so rotating the card is an env change and a
    restart, with no frontend rebuild.

    Returns 200 with `bank: null` rather than 503 when bank transfer isn't
    configured. A footer is not a checkout: an unconfigured deployment should
    render a footer without a requisites block, not an error.
    """
    return {"bank": bank_transfer.bank_details_from_env()}


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


@app.get("/v1/billing/bank-transfer/{reference}")
async def get_bank_transfer_invoice(
    reference: str,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    account_repo: AccountRepository = Depends(get_account_repo),
) -> dict:
    """Poll one bank-transfer invoice. Reveals the API key only once the
    operator has confirmed the transfer arrived (status 'completed'); a
    pending or expired invoice never leaks a key. 404 if no such invoice.

    An 'expired' status here is cosmetic: it tells a payer the quote is stale,
    but the operator can still confirm a transfer that surfaces later, because
    a slow bank must never become lost money."""
    status = await bank_transfer.invoice_status(
        payment_repo, account_repo, reference,
        details=bank_transfer.bank_details_from_env(),
    )
    if status is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no bank transfer invoice with this reference, or "
                              "persistence isn't configured on this deployment"},
        )
    return status


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


def _paypal_not_configured_error() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail={"reason": "paypal_not_configured",
                "detail": "PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET must both "
                          "be set on this deployment"},
    )


def _paypal_not_persisted_error() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail={"reason": "not_persisted",
                "detail": "PayPal checkout requires DATABASE_URL (a pending row "
                          "is created so the webhook capture can grant against "
                          "it, and the browser can poll the key back)"},
    )


@app.post("/v1/paypal/orders", status_code=201)
async def create_paypal_order(
    request: Request,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo),
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
    transport=Depends(get_paypal_transport),
) -> dict:
    """Open a PayPal order for a ONE-TIME product (Pro or a Fix Pack), the
    PayPal counterpart to POST /v1/billing/usdt/invoice. Returns the PayPal
    order id the browser JS SDK approves + captures against; the capture then
    arrives as a PAYMENT.CAPTURE.COMPLETED webhook that grants. Poll
    GET /v1/paypal/orders/{id} to collect the Pro key once captured.

    Body: {"product": "pro"} or {"product": "fixpack", "audit_id": "<id>"}.

    503 if PayPal isn't configured, or if DATABASE_URL isn't set -- the latter
    is checked BEFORE creating the PayPal order, so an unpersistable order is
    never opened at PayPal and left orphaned. Fix Pack: 404 unknown audit, 422
    if the audit has no GitHub repo to open a fix PR against (same gate as the
    USDT Fix Pack invoice)."""
    if not paypal.is_configured():
        raise _paypal_not_configured_error()
    if not database_url_from_env():
        raise _paypal_not_persisted_error()

    body = await _json_object_body(request)
    product = (body.get("product") or "").strip().lower()

    if product == "fixpack":
        audit_id = body.get("audit_id")
        if not audit_id:
            raise HTTPException(
                status_code=422,
                detail={"reason": "missing_audit_id",
                        "detail": "product 'fixpack' requires an audit_id"},
            )
        audit = await audit_repo.get(audit_id)
        if audit is None:
            raise HTTPException(
                status_code=404,
                detail={"reason": "audit_not_found",
                        "detail": "no audit with this id, or persistence isn't "
                                  "configured on this deployment"},
            )
        if not audit.get("repo_url"):
            raise HTTPException(
                status_code=422,
                detail={"reason": "not_github_audit",
                        "detail": "Fix Pack currently only supports audits run "
                                  "from a public GitHub URL. This audit was "
                                  "created from an uploaded zip, so there's no "
                                  "repository to open a fix PR against."},
            )
        await _reject_if_fixpack_already_live(fixpack_repo, audit_id)
        _reject_if_nothing_to_fix(audit)
        try:
            order = await paypal.create_fixpack_order(
                payment_repo, audit_id=audit_id, transport=transport
            )
        except paypal.PayPalError as exc:
            raise _paypal_upstream_error(exc) from exc
        if order is None:
            raise _paypal_not_persisted_error()
        return order

    if product == "pro":
        try:
            order = await paypal.create_pro_order(payment_repo, transport=transport)
        except paypal.PayPalError as exc:
            raise _paypal_upstream_error(exc) from exc
        if order is None:
            raise _paypal_not_persisted_error()
        return order

    raise HTTPException(
        status_code=422,
        detail={"reason": "unknown_product",
                "detail": "product must be 'pro' or 'fixpack'"},
    )


@app.get("/v1/paypal/orders/{order_id}")
async def get_paypal_order(
    order_id: str,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    account_repo: AccountRepository = Depends(get_account_repo),
) -> dict:
    """Poll one PayPal Pro order, the counterpart to GET
    /v1/billing/usdt/invoice/{id}. Reveals the API key only once the webhook
    has captured and granted (status 'completed'); a pending order never leaks
    a key. 404 if there's no such order (or persistence isn't configured)."""
    status = await paypal.order_status(payment_repo, account_repo, order_id)
    if status is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no PayPal order with this id, or persistence "
                              "isn't configured on this deployment"},
        )
    return status


def _monitoring_not_for_sale_error() -> HTTPException:
    """503 rather than 404: the route exists and works, the product is
    withdrawn. 404 would read as a client mistake and send someone hunting for
    a typo in a URL that is correct."""
    return HTTPException(
        status_code=503,
        detail={"reason": "monitoring_not_for_sale",
                "detail": "continuous monitoring is not on sale right now. Its "
                          "price, its spend attribution and its spend cap are "
                          "unresolved, so it was withdrawn rather than sold at "
                          "a placeholder price. Nothing was charged."},
    )


@app.post("/v1/paypal/subscriptions", status_code=201)
async def create_paypal_subscription(
    request: Request,
    subscription_repo: SubscriptionRepository = Depends(get_subscription_repo),
    transport=Depends(get_paypal_transport),
) -> dict:
    """Open a PayPal monitoring subscription (RECURRING), the PayPal
    counterpart to the Telegram /monitor flow. Returns the subscription id and
    the `approve` URL the browser sends the buyer to; PayPal then delivers
    BILLING.SUBSCRIPTION.ACTIVATED and recurring PAYMENT.SALE.COMPLETED
    webhooks. The subscriptions row is pre-inserted here (repo bound) so every
    later webhook resolves by paypal_subscription_id.

    Body: {"repo_url": "https://github.com/<owner>/<repo>"}.

    503 if PayPal isn't configured, if PAYPAL_MONITOR_PLAN_ID (the billing plan)
    isn't set, or if DATABASE_URL isn't set (checked before creating the
    subscription at PayPal). 422 on a repo_url that isn't a clean github.com
    owner/repo.

    503 before any of those when monitoring is withdrawn from sale, which it
    currently is -- see MONITORING_FOR_SALE. Checked first so a withdrawn
    product and an unconfigured deployment never report each other's reason."""
    if not MONITORING_FOR_SALE:
        raise _monitoring_not_for_sale_error()
    if not paypal.is_configured():
        raise _paypal_not_configured_error()
    plan_id = paypal.monitor_plan_id_from_env()
    if not plan_id:
        raise HTTPException(
            status_code=503,
            detail={"reason": "paypal_plan_not_configured",
                    "detail": "PAYPAL_MONITOR_PLAN_ID (the PayPal billing plan "
                              "id for the monitoring subscription) is not set on "
                              "this deployment"},
        )
    if not database_url_from_env():
        raise _paypal_not_persisted_error()

    body = await _json_object_body(request)
    repo_full_name = normalize_repo_full_name(body.get("repo_url"))
    if repo_full_name is None:
        raise HTTPException(
            status_code=422,
            detail={"reason": "bad_repo_url",
                    "detail": "repo_url must be "
                              "https://github.com/<owner>/<repo> "
                              "(public GitHub repos only)"},
        )
    try:
        sub = await paypal.create_monitor_subscription(
            subscription_repo, repo_full_name=repo_full_name, plan_id=plan_id,
            transport=transport,
        )
    except paypal.PayPalError as exc:
        raise _paypal_upstream_error(exc) from exc
    if sub is None:
        raise _paypal_not_persisted_error()
    return sub


@app.post("/v1/webhooks/paypal")
async def paypal_webhook(
    request: Request,
    account_repo: AccountRepository = Depends(get_account_repo),
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo),
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
    subscription_repo: SubscriptionRepository = Depends(get_subscription_repo),
    transport=Depends(get_paypal_transport),
) -> dict:
    """PayPal webhook. Authenticity is verified the way PayPal requires -- an
    outbound POST to /v1/notifications/verify-webhook-signature carrying the
    transmission headers and the raw event (NOT a local HMAC like Telegram or
    GitHub) -- so this needs PAYPAL_WEBHOOK_ID plus the OAuth credentials.

    Handles PAYMENT.CAPTURE.COMPLETED (one-time Pro/Fix Pack),
    BILLING.SUBSCRIPTION.ACTIVATED / PAYMENT.SALE.COMPLETED (recurring
    monitoring), and BILLING.SUBSCRIPTION.CANCELLED/SUSPENDED/EXPIRED; anything
    else is a 200 ack so PayPal stops retrying. See app/billing/paypal.py.

    503 if PayPal or the webhook id isn't configured -- an unverifiable webhook
    must never be trusted (same posture as the Telegram/GitHub webhooks). 401 on
    a failed signature verification."""
    if not paypal.is_configured():
        raise _paypal_not_configured_error()
    webhook_id = paypal.webhook_id_from_env()
    if not webhook_id:
        raise HTTPException(
            status_code=503,
            detail={"reason": "paypal_webhook_not_configured",
                    "detail": "PAYPAL_WEBHOOK_ID is not set on this deployment"},
        )

    event = await _json_object_body(request)
    try:
        verified = await paypal.verify_webhook_signature(
            headers=request.headers, event=event, webhook_id=webhook_id,
            transport=transport,
        )
    except paypal.PayPalError as exc:
        raise _paypal_upstream_error(exc) from exc
    if not verified:
        raise HTTPException(status_code=401, detail={"reason": "unauthorized"})

    return await paypal.handle_webhook_event(
        event, account_repo=account_repo, payment_repo=payment_repo,
        audit_repo=audit_repo, fixpack_repo=fixpack_repo,
        subscription_repo=subscription_repo, transport=transport,
    )


def _paypal_upstream_error(exc: Exception) -> HTTPException:
    """A PayPal REST call failed (non-2xx / unusable body). Surface as 502 --
    upstream's fault, not the caller's -- same split the LLM client and the
    GitHub fetcher draw between a bad request and a bad upstream."""
    logger.warning("paypal upstream call failed: %s", exc)
    return HTTPException(
        status_code=502,
        detail={"reason": "paypal_upstream_error",
                "detail": "PayPal did not accept the request; try again later"},
    )


@app.get("/v1/audits/{audit_id}/fixpack-status")
async def get_fixpack_status(
    audit_id: str,
    audit_repo: AuditRepository = Depends(get_audit_repo),
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
) -> dict:
    """Lightweight poll target for the audit results page: the outcome of a
    Fix Pack purchase for this audit, without needing the job id up front.

    Returns the most recent Fix Pack job's status and pr_url. status is one
    of the fixpack_jobs states — 'paid' (bought, generating), 'delivered'
    (PR opened, pr_url set), 'no_fix_needed', or 'failed'. When no Fix Pack
    has been purchased yet (or persistence isn't configured), status is null
    so the frontend can poll a stable shape rather than treat "no job" as an
    error. 404 only when the audit itself doesn't exist.

    On 'failed', failure_kind says whose fault it was: 'infrastructure' when the
    job was reaped after never completing (a sandbox-runner outage or a crashed
    worker — nothing to do with the client's code), else null for a genuine
    generation failure. Derived from the detail the reaper writes, so it needs no
    schema change; null for every non-failed status.
    """
    set_log_context(audit_id=audit_id)
    audit = await audit_repo.get(audit_id)
    if audit is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "audit_not_found",
                    "detail": "no audit with this id, or persistence isn't "
                              "configured on this deployment (see app/db.py)"},
        )
    job = await fixpack_repo.get_by_audit(audit_id)
    if job is None:
        return {"audit_id": audit_id, "status": None, "pr_url": None,
                "failure_kind": None}
    status = job.get("status")
    detail = job.get("detail") or ""
    failure_kind = None
    if status == "failed" and detail.startswith(STALE_LEASE_DETAIL_PREFIX):
        failure_kind = "infrastructure"
    return {
        "audit_id": audit_id,
        "status": status,
        "pr_url": job.get("pr_url"),
        "failure_kind": failure_kind,
    }


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
    await notify_operator(
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
    await notify_operator(
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
            await notify_operator(
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
            await notify_operator(
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


@app.get("/internal/audit-jobs/stats")
async def audit_jobs_stats(
    request: Request,
    audit_job_repo: AuditJobRepository = Depends(get_audit_job_repo),
) -> dict:
    """Operational read: how deep the audit queue is, broken down by state.

    /readyz carries the two numbers a health check needs; this is the view for
    a human or a scraper diagnosing WHY, which needs the whole state histogram.
    `dead_letter` is the one to watch -- the worker alerts on each new one, and
    a rising total here is what confirms a pattern rather than a one-off.

    Requires `Authorization: Bearer <AUDIT_JOBS_STATS_TOKEN>`, constant-time
    compared. 503 if the token isn't configured, and 503 if DATABASE_URL isn't
    set, because zeros from a queue you cannot see are worse than an error.

    Superseded by GET /internal/stats, which reports this queue alongside the
    others from the same backlog_stats() call. Kept, unchanged: this path and
    its response shape are already deployed and hand-curled, and there is no
    logic here that can drift from the new endpoint -- both are projections of
    one repository read."""
    token = _audit_jobs_stats_token()
    if not token:
        raise HTTPException(
            status_code=503,
            detail={"reason": "audit_jobs_stats_not_configured",
                    "detail": "AUDIT_JOBS_STATS_TOKEN is not set on this "
                              "deployment"},
        )
    _require_bearer_token(request, token)

    stats = await audit_job_repo.backlog_stats()
    if stats is None:
        raise HTTPException(
            status_code=503,
            detail={"reason": "not_configured",
                    "detail": "persistence isn't configured on this deployment "
                              "(see app/db.py)"},
        )
    return {
        "states": stats["states"],
        "queued": stats["queued"],
        "oldest_queued_seconds": stats["oldest_queued_seconds"],
        "dead_letter": stats["states"].get("dead_letter", 0),
    }


STATS_RECENT_WINDOW_SECONDS = 3600
STATS_DAY_WINDOW_SECONDS = 24 * 3600

# When a rule has enough evidence to learn from.
#
# 20 labelled outcomes and 5 distinct audits, per rule. The second number is
# the load-bearing one: twenty merges from one customer's repository say that
# this fix suits that repository, and generalising from it is how a knowledge
# base learns something false with confidence. Five audits is not a large
# sample either, but it is the point past which a signal is at least not one
# codebase's opinion.
#
# These are a stated position, not a derived one -- there is no dataset to
# derive them from yet, which is rather the point. They live here so the
# question "is there enough data?" is answered by a query instead of by
# whoever is asked.
LEARNING_MIN_LABELLED = 20
LEARNING_MIN_AUDITS = 5


@app.get("/internal/stats")
async def internal_stats(
    request: Request,
    audit_job_repo: AuditJobRepository = Depends(get_audit_job_repo),
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
    llm_usage_repo: LlmUsageRepository = Depends(get_llm_usage_repo),
    fix_outcome_repo: FixOutcomeRepository = Depends(get_fix_outcome_repo),
) -> dict:
    """Every queue and the LLM bill, aggregated, in one authenticated read.

    The deployment is a single VPS whose spare memory is already contended for
    by the Fix Pack sandbox containers, so there is no Prometheus and no
    metrics process: the aggregates are computed on demand from the tables that
    already hold the facts (audit_jobs, fixpack_jobs, llm_usage), and this is
    what a scraper or a human polls. Counts and percentiles only, never rows,
    so the response size does not grow with the size of the queues.

    Same auth as /internal/audit-jobs/stats and deliberately the same token:
    AUDIT_JOBS_STATS_TOKEN exists so a monitoring reader can see queue depth
    without holding a credential that can also start work, which is exactly
    this endpoint's audience. A second token for the same reader would be two
    secrets to rotate for one job.

    Every number comes from a repository method, several of which /readyz and
    /internal/audit-jobs/stats already call, so "backlog" and "oldest queued"
    have one definition in the codebase rather than one per reader.

    503 rather than zeros when the token or the database is missing: a stats
    endpoint answering 200 with empty counters while it cannot see the queue is
    worse than one that fails, because a dashboard cannot tell the difference
    and a silent zero reads as healthy."""
    token = _audit_jobs_stats_token()
    if not token:
        raise HTTPException(
            status_code=503,
            detail={"reason": "audit_jobs_stats_not_configured",
                    "detail": "AUDIT_JOBS_STATS_TOKEN is not set on this "
                              "deployment"},
        )
    _require_bearer_token(request, token)

    audit_backlog = await audit_job_repo.backlog_stats()
    if audit_backlog is None:
        raise HTTPException(
            status_code=503,
            detail={"reason": "not_configured",
                    "detail": "persistence isn't configured on this deployment "
                              "(see app/db.py)"},
        )
    # Past this point the pool is known to exist, so the remaining reads
    # cannot return the not-configured None.
    audit_recent = await audit_job_repo.recent_outcomes(
        window_seconds=STATS_RECENT_WINDOW_SECONDS)
    fixpack_backlog = await fixpack_repo.backlog_stats()
    fixpack_statuses = await fixpack_repo.status_counts()
    spend_hour = await llm_usage_repo.spend_since(
        window_seconds=STATS_RECENT_WINDOW_SECONDS)
    spend_day = await llm_usage_repo.spend_since(
        window_seconds=STATS_DAY_WINDOW_SECONDS)
    learning = await fix_outcome_repo.learning_readiness(
        min_labelled=LEARNING_MIN_LABELLED,
        min_audits=LEARNING_MIN_AUDITS,
    )

    return {
        "window_seconds": STATS_RECENT_WINDOW_SECONDS,
        "audit_jobs": {
            "states": audit_backlog["states"],
            "queued": audit_backlog["queued"],
            "oldest_queued_seconds": audit_backlog["oldest_queued_seconds"],
            "recent": audit_recent,
        },
        "fixpack_jobs": {
            "statuses": fixpack_statuses,
            "paid_backlog": fixpack_backlog["backlog"],
            "oldest_paid_seconds": fixpack_backlog["oldest_paid_seconds"],
        },
        "llm_usage": {
            "last_hour": _spend_view(spend_hour),
            "last_24h": _spend_view(spend_day),
        },
        # audit_jobs only, and named so rather than presented as a service-wide
        # figure it is not: fixpack_jobs stamps no timestamp on a terminal
        # transition, so "failed in the last hour" is not computable for that
        # queue without a schema change, and quietly folding in its lifetime
        # totals would make the ratio mean nothing.
        "errors": {
            "source": "audit_jobs",
            "window_seconds": STATS_RECENT_WINDOW_SECONDS,
            "terminal_total": audit_recent["terminal_total"],
            "failed": audit_recent["failed"],
            "error_rate": audit_recent["error_rate"],
            "top_error_codes": audit_recent["top_error_codes"],
        },
        # Lifetime, not windowed like everything above it: the question this
        # answers is "has enough evidence accumulated to learn from", and an
        # hour of it is not evidence.
        "learning": learning,
    }


def _spend_view(spend: dict) -> dict:
    """One llm_usage window as JSON. cost_usd is quantized to the column's own
    numeric(12,6) scale and then floated -- the repository hands back a Decimal
    so nothing rounds before it must, and this is where it must, because JSON
    has no decimal type."""
    return {
        "calls": spend["calls"],
        "cost_usd": float(spend["cost_usd"].quantize(Decimal("0.000001"))),
    }


@app.post("/internal/payments/{payment_id}/refund")
async def refund_payment(
    payment_id: str,
    request: Request,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
) -> dict:
    """Record that a completed payment was given back.

    Body: JSON {"reason": str}. Requires `Authorization: Bearer
    <SERVICE_FLAGS_TOKEN>`.

    This endpoint moves no money, and no endpoint here could. A bank transfer
    lands on a private individual's account and goes back the same way, by
    hand; Telegram Stars and USDT have no refund call this deployment holds a
    credential for. The operator sends the money and then tells the system, in
    that order.

    So the value is the record. Until now a refunded payment stayed
    `completed` for ever, and a month later nothing distinguished money kept
    from money returned -- an error that is always in the flattering
    direction. It became concrete on 2026-08-01, when DRY-UPRQKH charged 10.79
    for a Fix Pack on an audit with nothing a Fix Pack could fix. The customer
    was the operator testing his own product; the next one will not be.

    SERVICE_FLAGS_TOKEN rather than a token of its own. It is already the
    operator-privileged credential -- it can halt every paid LLM operation --
    and this is the same audience. AUDIT_JOBS_STATS_TOKEN would be wrong for
    the reason its own docstring gives: it exists so a monitoring reader can
    see queue depth WITHOUT holding a credential that can also act.

    404 when the payment does not exist OR is not `completed`: an invoice
    nobody paid has no refund to record, and the two cases are deliberately
    not distinguished to an unauthenticated-by-id caller. Repeating the call
    is a no-op for the same reason -- one refund must not become two entries
    because a command was run twice.

    Deliberately does NOT revoke anything. A Fix Pack PR that was delivered
    stays delivered; Pro access stays granted. Whether a refund should take
    back what it paid for is a policy question with a different cost of being
    wrong, and mixing it into the record-keeping would mean neither could be
    changed alone.
    """
    token = _service_flags_token()
    if not token:
        raise HTTPException(
            status_code=503,
            detail={"reason": "not_configured",
                    "detail": "SERVICE_FLAGS_TOKEN is not set on this deployment"},
        )
    _require_bearer_token(request, token)

    body = await _json_object_body(request)
    reason = body.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise HTTPException(
            status_code=422,
            detail={"reason": "bad_request",
                    "detail": "body must be JSON with a non-empty 'reason'"},
        )

    try:
        uuid.UUID(payment_id)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail={"reason": "bad_request", "detail": "payment_id must be a UUID"},
        )

    payment = await payment_repo.mark_refunded(payment_id, reason=reason.strip())
    if payment is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_refundable",
                    "detail": "no completed payment with that id"},
        )
    return payment


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
        await notify_operator(
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
    account = await resolve_account(request, account_repo)
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


@app.get("/v1/fixpacks/{job_id}")
async def get_fixpack(
    job_id: str,
    token: str | None = None,
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
) -> dict:
    # Ownership check: the job is readable only by presenting its per-row
    # access_token (?token=...), delivered once at creation. A leaked id is
    # not enough. A missing/wrong token is answered 404 (not 403) so this
    # never confirms an id exists to someone who doesn't hold its token --
    # same model as GET /v1/audits/{id} (migration 0012 mirrors 0010).
    set_log_context(job_id=job_id)
    row = await fixpack_repo.get_authorized(job_id, token)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no fixpack job with this id and token, or persistence "
                               "isn't configured on this deployment (see app/db.py)"},
        )
    return row


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


# Production operations endpoints.
from app.ops_endpoints import router as ops_router

app.include_router(ops_router)
