"""Drydock API gateway — MVP phase 1 surface.

Only what exists today: health check and archive intake with validation,
rate limiting, stack detection, static scan, and (when providers are
configured) the LLM auth/security scan. Persistence and the queue come
next — the scan stage runs off the event loop in a threadpool for now,
since the LLM call alone can take up to ~2 minutes.
"""

from __future__ import annotations

import hmac
import io
import os
import re
import uuid

from fastapi import Depends, FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from starlette.concurrency import run_in_threadpool

from app.accounts import (
    TIER_FREE,
    entitlements_dict,
    entitlements_for_tier,
    resolve_account,
)
from app.billing import telegram_stars, usdt_trc20
from app.db import (
    AccountRepository,
    AuditRepository,
    FixpackJobRepository,
    PaymentRepository,
)
from app.deploypack.delivery import DeliveryError, open_pull_request, render_pr_body
from app.deploypack.generate import UnsupportedForDeployPack
from app.deploypack.github_app import (
    GitHubAppError,
    app_credentials_from_env,
    installation_token_for_repo,
)
from app.deploypack.pipeline import run_deploy_pack
from app.deploypack.preview import PreviewRegistry
from app.ingest.github_fetch import RepoFetchError, fetch_repo_zip
from app.ingest.stack_detect import Stack, detect_stack
from app.llm.client import LLMClient
from app.report.html import render_report
from app.ratelimit import RateLimitExceeded, RateLimiter, limiter_from_env
from app.scan.pipeline import run_scan
from app.ingest.validators import (
    MAX_ARCHIVE_BYTES,
    ArchiveValidationError,
    validate_zip,
)

app = FastAPI(title="Drydock", version="0.1.0")


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


_audit_repo = AuditRepository()
_fixpack_repo = FixpackJobRepository()
_account_repo = AccountRepository()
_payment_repo = PaymentRepository()


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


def _reap_token() -> str | None:
    """Same env-var pattern as GITHUB_PR_TOKEN in delivery.py. Unset by
    default — the endpoint below refuses to run rather than accept an
    empty/no-op auth check."""
    return os.environ.get("PREVIEW_REAP_TOKEN") or None


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


@app.post("/internal/preview/reap")
async def reap_previews(
    request: Request,
    preview_registry: PreviewRegistry = Depends(get_preview_registry),
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
    provided = request.headers.get("authorization", "")
    if not hmac.compare_digest(provided, f"Bearer {token}"):
        raise HTTPException(status_code=401, detail={"reason": "unauthorized"})

    reaped = await run_in_threadpool(preview_registry.reap_expired)
    return {"reaped": reaped, "active": preview_registry.active_count()}


@app.get("/v1/audits/{audit_id}")
async def get_audit(
    audit_id: str,
    audit_repo: AuditRepository = Depends(get_audit_repo),
) -> dict:
    row = await audit_repo.get(audit_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no audit with this id, or persistence isn't "
                               "configured on this deployment (see app/db.py)"},
        )
    return row


@app.get("/v1/audits/{audit_id}/report")
async def get_audit_report(
    audit_id: str,
    audit_repo: AuditRepository = Depends(get_audit_repo),
) -> HTMLResponse:
    """The shareable artifact: the same persisted audit rendered as a
    self-contained, plain-language HTML page."""
    row = await audit_repo.get(audit_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no audit with this id, or persistence isn't "
                               "configured on this deployment (see app/db.py)"},
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
    return HTMLResponse(content=html)


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
    transport=Depends(get_billing_transport),
) -> dict:
    """Telegram Bot API webhook for Stars payments. Handles the
    pre_checkout_query (approve within 10s) and successful_payment
    (grant pro, DM the API key) update types; ignores everything else.

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
        token=token, transport=transport,
    )


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


@app.post("/internal/billing/poll-usdt")
async def poll_usdt(
    request: Request,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    account_repo: AccountRepository = Depends(get_account_repo),
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
    provided = request.headers.get("authorization", "")
    if not hmac.compare_digest(provided, f"Bearer {token}"):
        raise HTTPException(status_code=401, detail={"reason": "unauthorized"})

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
    )


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

    # Off the event loop: the LLM stage does real network I/O and can
    # take up to ~2 minutes. Moves to the arq worker + queue in phase 2.
    scan = await run_in_threadpool(run_scan, raw, llm_client)

    persisted = await audit_repo.create(
        stack=stack.value, file_count=report.file_count,
        score_total=scan["score"]["total"], score_json=scan["score"],
        findings_json=scan["findings"],
    )
    audit_id = persisted["id"] if persisted else str(uuid.uuid4())

    return {
        "audit_id": audit_id,
        "persisted": persisted is not None,
        "status": "completed",
        "stack": stack.value,
        "file_count": report.file_count,
        "score": scan["score"],
        "findings": scan["findings"],
        "llm": scan["llm"],
    }


@app.get("/v1/fixpacks/{job_id}")
async def get_fixpack(
    job_id: str,
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
) -> dict:
    row = await fixpack_repo.get(job_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no fixpack job with this id, or persistence "
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
                    pr_opener, owner, repo, result["files"], body=body, token=token,
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
        "pack": "deploy",
        "stack": stack.value,
        "verified": result["verified"],
        "detail": result["detail"],
        "files": result["files"],
        "pr": pr,
        "preview": result["preview"],
    }
