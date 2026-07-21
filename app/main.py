"""Drydock API gateway — MVP phase 1 surface.

Only what exists today: health check and archive intake with validation,
rate limiting, stack detection, static scan, and (when providers are
configured) the LLM auth/security scan. Persistence and the queue come
next — the scan stage runs off the event loop in a threadpool for now,
since the LLM call alone can take up to ~2 minutes.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import io
import json
import logging
import os
import re
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.concurrency import run_in_threadpool

from app.alerts import notify_operator
from app.accounts import (
    TIER_FREE,
    entitlements_dict,
    entitlements_for_tier,
    resolve_account,
    validate_api_key_pepper_configured,
)
from app.billing import paypal, telegram_stars, usdt_trc20
from app.db import (
    AccountRepository,
    AuditRepository,
    FixOutcomeRepository,
    FixpackJobRepository,
    MonitoringRunRepository,
    PaymentRepository,
    ProcessorLockBusy,
    SubscriptionRepository,
    database_url_from_env,
    fixpack_processor_lock,
    monitoring_processor_lock,
)
from app.deploypack.delivery import DeliveryError, open_pull_request, render_pr_body
from app.deploypack.generate import UnsupportedForDeployPack
from app.deploypack.github_app import (
    GitHubAppError,
    app_credentials_from_env,
    build_install_url,
    installation_exists_for_repo,
    installation_token_for_repo,
)
from app.deploypack.pipeline import run_deploy_pack
from app.deploypack.preview import PreviewRegistry, reconcile_previews
from app.fixpack.generate import (
    build_fixpack_plan,
    render_pr_body as render_fixpack_pr_body,
    render_pr_title as render_fixpack_pr_title,
)
from app.fixpack.semantic_check import run_semantic_check
from app.ingest.github_fetch import RepoFetchError, fetch_repo_zip
from app.ingest.stack_detect import Stack, detect_stack
from app.llm.client import LLMClient
from app.monitor import normalize_repo_full_name, repo_url_from_full_name
from app.monitor.diff import new_high_severity_findings
from app.report.html import render_report
from app.ratelimit import RateLimitExceeded, RateLimiter, limiter_from_env
from app.scan.pipeline import AUDIT_ENGINE_VERSION, content_digest, run_scan
from app.ingest.validators import (
    MAX_ARCHIVE_BYTES,
    ArchiveValidationError,
    validate_zip,
)

logger = logging.getLogger(__name__)


_VALID_LOG_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}


def configure_logging() -> None:
    """Make log level/format explicit instead of inherited-by-accident.

    Until now nothing called basicConfig, so app loggers rode on Python's
    last-resort handler (WARNING-only, bare format) — INFO lines never
    showed and there was no timestamp/level/name prefix to grep in
    journalctl. This sets one plain-text (NOT JSON — deliberate at this log
    volume) format and an env-overridable level. basicConfig is a no-op if a
    handler is already installed, so it never fights uvicorn's own loggers or
    double-configures across test app instances."""
    level = (os.environ.get("LOG_LEVEL") or "INFO").upper()
    if level not in _VALID_LOG_LEVELS:
        level = "INFO"
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


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
        allow_headers=["Authorization", "Content-Type"],
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
    """
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault(
        "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
    )
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


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
    endpoint never shells out to a real `docker ps`."""
    return reconcile_previews


_audit_repo = AuditRepository()
_fixpack_repo = FixpackJobRepository()
_fix_outcome_repo = FixOutcomeRepository()
_account_repo = AccountRepository()
_payment_repo = PaymentRepository()
_subscription_repo = SubscriptionRepository()
_monitoring_repo = MonitoringRunRepository()


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


async def run_repo_audit(
    repo_url: str, *, llm_client: LLMClient, audit_repo: AuditRepository,
    repo_fetcher,
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
    see app/ingest/github_fetch.py)."""
    parsed = _parse_github_repo_url(repo_url)
    if parsed is None:
        return None
    owner, repo = parsed
    raw = await run_in_threadpool(repo_fetcher, owner, repo)
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
    cached = await audit_repo.get_by_content_hash(digest, AUDIT_ENGINE_VERSION)
    if cached is not None:
        return {
            "audit_id": cached["id"],
            "findings": cached["findings_json"] or [],
            "repo_url": cached.get("repo_url"),
            "access_token": cached.get("access_token"),
            "reused": True,
        }

    scan = await run_in_threadpool(run_scan, raw, llm_client)
    persisted = await audit_repo.create(
        stack=stack.value, file_count=report.file_count,
        score_total=scan["score"]["total"], score_json=scan["score"],
        findings_json=scan["findings"], repo_url=repo_url,
        content_hash=digest, engine_version=AUDIT_ENGINE_VERSION,
    )
    audit_id = persisted["id"] if persisted else str(uuid.uuid4())
    return {
        "audit_id": audit_id,
        "findings": scan["findings"],
        "repo_url": repo_url,
        "access_token": persisted.get("access_token") if persisted else None,
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


def _require_bearer_token(request: Request, token: str) -> None:
    """Constant-time check of `Authorization: Bearer <token>`, raising 401
    on mismatch. The single implementation shared by every internal
    operational endpoint (reaper, USDT poller, Fix Pack processor) so the
    comparison stays constant-time in one place and can't drift."""
    provided = request.headers.get("authorization", "")
    if not hmac.compare_digest(provided, f"Bearer {token}"):
        raise HTTPException(status_code=401, detail={"reason": "unauthorized"})


def _client_key(request: Request) -> str:
    """Client IP, honoring one reverse-proxy hop (Caddy in prod).

    Trusts the first X-Forwarded-For entry. Only safe because this
    endpoint sits behind our own known proxy — do not reuse this helper
    if the app is ever exposed directly to the internet without one.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
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
        FixpackJobRepository.backlog_stats).

    Deliberately leak-free: only booleans and coarse counts/ages — never ids,
    urls, or error text — so it's safe to expose to a dumb uptime pinger or
    the systemd timer without a token. Always 200: an unconfigured or
    unreachable DB is reported as db:false (a live process honestly saying
    it's degraded), not a transport-level failure the pinger can't read."""
    stats = await fixpack_repo.backlog_stats()
    if stats is None:
        # DATABASE_URL unset, or the pool couldn't be built — either way the
        # DB isn't usable. Report degraded rather than 503 (see docstring).
        return {"db": False, "fixpack_backlog": None, "oldest_paid_seconds": None}
    return {
        "db": True,
        "fixpack_backlog": stats["backlog"],
        "oldest_paid_seconds": stats["oldest_paid_seconds"],
    }


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Single catch-all for genuinely *unhandled* server errors (a bug, not
    control flow). Starlette routes only exceptions that aren't an
    HTTPException here, so the intentional 422/404/503/401 responses raised
    across the API stay normal control flow and never alert.

    This is the one place the request-id correlation gap gets its minimal
    fix: mint a short id, put it in the 500 log line, the operator alert, and
    the response body, so a user's report ("I got error abc123") ties to an
    exact log line and alert without full structured logging. The alert is
    best-effort and deduped so a crash-loop can't spam the operator."""
    request_id = uuid.uuid4().hex[:12]
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
    row = await audit_repo.get_authorized(audit_id, token)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no audit with this id and token, or persistence "
                               "isn't configured on this deployment (see app/db.py)"},
        )
    return row


@app.get("/v1/audits/{audit_id}/report")
async def get_audit_report(
    audit_id: str,
    token: str | None = None,
    audit_repo: AuditRepository = Depends(get_audit_repo),
) -> HTMLResponse:
    """The shareable artifact: the same persisted audit rendered as a
    self-contained, plain-language HTML page. Requires the audit's
    access_token (?token=...) -- same ownership check as GET /v1/audits/{id}."""
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
    tier = account["tier"] if account else TIER_FREE
    entitlements = entitlements_for_tier(tier, free_daily_limit=limiter.limit)
    return {
        "tier": tier,
        "authenticated": account is not None,
        "entitlements": entitlements_dict(entitlements),
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
    Fix Pack / subscription), and subscription (BotSubscriptionUpdated
    renewal state changes) update types; ignores everything else.

    Authenticity is Telegram's secret_token: setWebhook is called with a
    secret, echoed back in X-Telegram-Bot-Api-Secret-Token on every
    delivery. Constant-time compared here, same posture as the reap
    endpoint's bearer token. 503 if the bot token or webhook secret
    isn't configured — an unconfigured payment webhook is an operational
    gap to notice, not a silent no-op. See app/billing/telegram_stars.py.
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
    if not hmac.compare_digest(provided, secret):
        raise HTTPException(status_code=401, detail={"reason": "unauthorized"})

    update = await request.json()
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
    return hmac.compare_digest(provided, expected)


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
    try:
        subs = await subscription_repo.list_active_for_repo(repo_full_name)
        if not subs:
            # Every subscription lapsed between enqueue and now -- nothing to
            # notify. Benign; close the run out.
            await monitoring_repo.mark_done(run_id)
            return "no_subscription"

        # Baseline BEFORE the new audit persists, so the diff reflects only what
        # this push introduced.
        previous = await audit_repo.get_latest_by_repo_url(repo_full_name)
        previous_findings = (previous or {}).get("findings_json") or []

        try:
            result = await run_repo_audit(
                repo_url_from_full_name(repo_full_name), llm_client=llm_client,
                audit_repo=audit_repo, repo_fetcher=repo_fetcher,
            )
        except RepoFetchError:
            # Repo went private/was deleted (404, indistinguishable by design).
            # Benign terminal state; the 24h claim already stopped re-enqueues.
            await monitoring_repo.mark_done(run_id)
            return "unfetchable"

        if result is None:
            await monitoring_repo.mark_done(run_id)
            return "unauditable"

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
    payment_repo: PaymentRepository = Depends(get_payment_repo),
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

    body = await request.json()
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
    owner/repo."""
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

    body = await request.json()
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

    event = await request.json()
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
    """
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
        return {"audit_id": audit_id, "status": None, "pr_url": None}
    return {
        "audit_id": audit_id,
        "status": job.get("status"),
        "pr_url": job.get("pr_url"),
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
    return await usdt_trc20.poll_and_match(
        payment_repo, account_repo, address=address,
        api_key=usdt_trc20.trongrid_api_key_from_env(), transport=transport,
        fixpack_repo=fixpack_repo, audit_repo=audit_repo,
    )


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
    app_id_env = os.environ.get("GITHUB_APP_ID")
    pem_env = os.environ.get("GITHUB_APP_PRIVATE_KEY")
    logger.warning(
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


async def _process_one_paid_job(
    job: dict, *, audit_repo: AuditRepository,
    fixpack_repo: FixpackJobRepository, fix_outcome_repo: FixOutcomeRepository,
    repo_fetcher, pr_opener,
) -> str:
    """Generate + deliver one paid Fix Pack job. Returns the outcome:
    'delivered', 'no_fix_needed', 'blocked', or 'failed'. Advances the job's
    status to match so a re-run of the processor doesn't pick it up again (a
    'failed' or 'blocked' job stays visible for a human to retry/review
    rather than silently stuck on 'paid'). 'blocked' means the generated
    fix passed syntax validation but the semantic check (running the
    client's own tests against the patched tree) found a regression, so the
    PR was withheld for manual review.

    Every failure is made visible: the full traceback is logged and a short
    reason is written to the job's `detail` column. A job must never land on
    'failed' with a null detail and nothing in the logs — that makes a real
    production failure impossible to diagnose (see the silent-failure
    incident this path was hardened for)."""
    job_id = job["id"]
    try:
        audit = await audit_repo.get(job["audit_id"]) if job.get("audit_id") else None
        if audit is None or not audit.get("repo_url"):
            detail = "audit missing or has no repo_url to re-fetch"
            logger.error("Fix Pack job %s failed: %s", job_id, detail)
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
            logger.error("Fix Pack job %s failed: %s", job_id, detail)
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
        semantic = await run_in_threadpool(run_semantic_check, zip_bytes, plan)
        if semantic.regression:
            logger.warning(
                "Fix Pack job %s blocked by semantic check: %s",
                job_id, semantic.detail,
            )
            await fixpack_repo.mark_status(job_id, "blocked", detail=semantic.detail)
            await _record_fix_outcome(
                fix_outcome_repo, job=job, outcome="blocked",
                rule_ids=_rule_ids_from_plan(plan), is_regression=True,
                pr_url=None,
            )
            return "blocked"

        title = render_fixpack_pr_title(plan)
        body = render_fixpack_pr_body(plan)
        if semantic.pr_note:
            body = f"{body}\n\n{semantic.pr_note}"
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
    except Exception as exc:  # noqa: BLE001 — every failure must be recorded
        # Any error in fetch, generation, token exchange, or PR delivery
        # lands here. Log the full traceback (logger.exception attaches it)
        # and persist a short reason so the failure is diagnosable from both
        # the logs and a `select ... from fixpack_jobs` query.
        logger.exception("Fix Pack job %s failed during processing", job_id)
        detail = _failure_detail(exc)
        await fixpack_repo.mark_status(job_id, "failed", detail=detail)
        await _record_fix_outcome(
            fix_outcome_repo, job=job, outcome="failed",
            rule_ids=[], is_regression=False, pr_url=None,
        )
        await _alert_fixpack_failed(job_id, detail)
        return "failed"


@app.post("/internal/fixpack/process-paid")
async def process_paid_fixpacks(
    request: Request,
    audit_repo: AuditRepository = Depends(get_audit_repo),
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
    fix_outcome_repo: FixOutcomeRepository = Depends(get_fix_outcome_repo),
    repo_fetcher=Depends(get_repo_fetcher),
    pr_opener=Depends(get_pr_opener),
) -> dict:
    """Operational endpoint: drain the paid-but-not-yet-generated Fix Pack
    backlog and turn each job into a real fix PR — re-fetch the audited
    repo, remove hardcoded secrets, harden config, open the PR, and advance
    the job to 'delivered'. Meant for a scheduled caller (a systemd timer,
    same as the reaper and the USDT poller — this repo ships no unit file).
    Not part of the public API.

    Durable-processing model (see PHASE3_QUEUE_PLAN.md): the run takes a
    session advisory lock so two overlapping timer firings don't stampede;
    it first reaps stale 'running' leases (a crashed worker's job) back to
    'paid' (bounded by attempts) or to 'failed'; then it claims jobs one at
    a time, each atomically leased 'paid' -> 'running' so a single job can
    never be processed by two runs at once (no duplicate PR per payment).

    Requires `Authorization: Bearer <FIXPACK_PROCESS_TOKEN>`, constant-time
    compared via the same helper the reaper and USDT poller use. 503 if the
    token isn't configured on this deployment — an unconfigured processor is
    an operational gap to notice, not a silent no-op.

    Returns a summary the scheduler can log: how many jobs were processed,
    delivered (PR opened), skipped (nothing eligible to fix), blocked,
    failed, and requeued (stale leases put back for retry). If another run
    already holds the lock, returns {"skipped_locked": true} instead.
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
               "blocked": 0, "failed": 0, "requeued": 0}
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

            # Claim-process-claim until the backlog is drained. Each claim
            # atomically leases one 'paid' job into 'running' (see
            # claim_one_paid), so a re-queued or newly purchased job is
            # picked up in the same run.
            while True:
                job = await fixpack_repo.claim_one_paid()
                if job is None:
                    break
                summary["processed"] += 1
                outcome = await _process_one_paid_job(
                    job, audit_repo=audit_repo, fixpack_repo=fixpack_repo,
                    fix_outcome_repo=fix_outcome_repo,
                    repo_fetcher=repo_fetcher, pr_opener=pr_opener,
                )
                if outcome == "delivered":
                    summary["delivered"] += 1
                elif outcome == "no_fix_needed":
                    summary["skipped"] += 1
                elif outcome == "blocked":
                    summary["blocked"] += 1
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
                    transport=transport,
                )
                if outcome in summary:
                    summary[outcome] += 1
                else:
                    summary["failed"] += 1
    except ProcessorLockBusy:
        # Another run holds the lock — benign. The scheduler logs and moves on.
        return {"skipped_locked": True}
    return summary


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
    llm_client: LLMClient = Depends(get_llm_client),
    audit_repo: AuditRepository = Depends(get_audit_repo),
    account_repo: AccountRepository = Depends(get_account_repo),
    repo_fetcher=Depends(get_repo_fetcher),
) -> dict:
    # Exactly one intake method: not both, not neither. Both-None and
    # both-present are the two cases where the equality holds.
    if (archive is None) == (repo_url is None):
        raise HTTPException(
            status_code=422,
            detail={"reason": "bad_intake",
                    "detail": "provide exactly one of 'archive' (file upload) "
                              "or 'repo_url' (public GitHub repo URL)"},
        )

    # Resolve the caller's tier from an optional API key. No key -> None ->
    # free, with no DB call, so anonymous traffic is byte-for-byte unchanged.
    # The only entitlement enforced here is daily_audit_limit (below).
    account = await resolve_account(request, account_repo)
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

    buf = io.BytesIO(raw)

    try:
        report = validate_zip(buf, size_bytes=len(raw))
    except ArchiveValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail={"reason": exc.reason, "detail": exc.detail},
        ) from exc

    buf.seek(0)
    stack = detect_stack(buf)
    if stack is Stack.UNSUPPORTED:
        raise HTTPException(
            status_code=422,
            detail={"reason": "unsupported_stack",
                    "detail": "MVP supports Next.js and FastAPI only"},
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
    digest = content_digest(raw)
    cached = await audit_repo.get_by_content_hash(digest, AUDIT_ENGINE_VERSION)
    if cached is not None:
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

    # Off the event loop: the LLM stage does real network I/O and can
    # take up to ~2 minutes. Moves to the arq worker + queue in phase 2.
    scan = await run_in_threadpool(run_scan, raw, llm_client)

    persisted = await audit_repo.create(
        stack=stack.value, file_count=report.file_count,
        score_total=scan["score"]["total"], score_json=scan["score"],
        findings_json=scan["findings"], repo_url=source_url,
        content_hash=digest, engine_version=AUDIT_ENGINE_VERSION,
    )
    audit_id = persisted["id"] if persisted else str(uuid.uuid4())

    return {
        "audit_id": audit_id,
        # The ownership token for this audit, delivered exactly once here.
        # None on an unpersisted (no-DATABASE_URL) deployment, where there is
        # no stored row to protect and the id is ephemeral anyway.
        "access_token": persisted.get("access_token") if persisted else None,
        "persisted": persisted is not None,
        "status": "completed",
        "stack": stack.value,
        "file_count": report.file_count,
        "score": scan["score"],
        "findings": scan["findings"],
        "repo_url": source_url,
        "llm": scan["llm"],
    }


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
