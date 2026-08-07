"""Liveness, readiness, and API-key session endpoints.

Extracted from app/main.py verbatim -- handler bodies are unchanged, only the
decorators moved from ``@app.<verb>`` to ``@router.<verb>``.

Two unrelated concerns share this module because both are about *reaching* the
service rather than using it:

  - /healthz is a pure liveness ping; /health additionally reports whether the
    database, the Fix Pack queue and the GitHub App are usable, and is what the
    production watchdog polls.
  - /v1/auth/login and /v1/auth/logout exchange an API key for an HttpOnly
    session cookie, so the key itself never has to live in browser-reachable
    storage.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool

from app.accounts import (
    account_for_key,
    clear_api_key_cookie,
    entitlements_dict,
    entitlements_for_tier,
    set_api_key_cookie,
)
from app.db import AccountRepository, FixpackJobRepository
from app.deploypack.github_app import app_auth_ok
from app.ratelimit import RateLimiter
from app.routes._shared import _bind_account, _json_object_body
from app.routes.dependencies import (
    get_account_repo,
    get_fixpack_repo,
    get_rate_limiter,
)

router = APIRouter()


@router.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@router.get("/health")
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





@router.post("/v1/auth/login")
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


@router.post("/v1/auth/logout")
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
