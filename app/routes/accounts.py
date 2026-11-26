"""Account self-service and the paid-LLM kill switch.

Extracted from app/main.py verbatim -- handler bodies are unchanged, only the
decorators moved from ``@app.<verb>`` to ``@router.<verb>``.

``accounts.resolve_account`` and ``alerts.notify_operator`` are called through
their modules rather than imported by name. That is deliberate: the test suite
patches both on the module that defines them, so calling them this way means a
handler can live in any route module without a fixture needing to learn about a
new binding.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from app import accounts, alerts
from app.service_flags import _reset_service_flag_cache
from app.accounts import TIER_FREE, entitlements_dict, entitlements_for_tier
from app.db import AccountRepository, ServiceFlagsRepository
from app.ratelimit import RateLimiter
from app.routes._shared import (
    _bind_account,
    _json_object_body,
    _require_bearer_token,
    _service_flags_token,
)
from app.routes.dependencies import (
    get_account_repo,
    get_rate_limiter,
    get_service_flags_repo,
)

router = APIRouter()


@router.get("/v1/account")
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


@router.post("/v1/account/rotate-key")
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





@router.post("/internal/service-flags/llm_paid_ops")
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
