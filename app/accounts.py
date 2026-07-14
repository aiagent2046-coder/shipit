"""Account tiers and entitlements — the identity foundation for the
paywall. Stage 1 of 2: the account/tier/entitlement layer that a
follow-up task's payment providers (Telegram Stars, USDT/TRC20) plug
into. No provider logic lives here.

This is the FIRST identity concept in the codebase. Everything stays
anonymous by default: a request may optionally carry an opaque API key
(`Authorization: Bearer sk_live_...`, same header scheme the reap
endpoint uses) to be recognized as a paying `pro` account. No key, an
unknown key, or DATABASE_URL not configured all degrade to anonymous
`free` — exactly today's behavior — never an error. There is no
"invalid session" here, only "not recognized as a paying account".

Accounts are NOT created here or via any public endpoint: they're
created by Stage 2's payment flow (a successful payment creates the
account and hands back its key). A free "create account" endpoint would
be an abuse hole (unlimited free pro accounts), so it deliberately does
not exist — tests create accounts directly through AccountRepository.
"""

from __future__ import annotations

import secrets
from dataclasses import asdict, dataclass
from typing import Any, Protocol

TIER_FREE = "free"
TIER_PRO = "pro"

# Materially higher than free's limit (which is the RateLimiter's
# configured value, AUDIT_RATE_LIMIT_PER_DAY, default 5).
PRO_DAILY_AUDIT_LIMIT = 100

_API_KEY_PREFIX = "sk_live_"


def generate_api_key() -> str:
    """Opaque, server-generated. Used by Stage 2's payment flow when it
    creates an account — kept here so key format lives with the identity
    model, not scattered into whatever provider mints the first one."""
    return f"{_API_KEY_PREFIX}{secrets.token_urlsafe(32)}"


@dataclass(frozen=True)
class Entitlements:
    """What a tier is allowed. Deliberately short and matched to what
    actually exists in the code today — don't add flags for features that
    don't exist anywhere yet.

    Only `daily_audit_limit` is really enforced (in app/main.py's
    create_audit, via the existing rate limiter). `private_repos_allowed`
    and `priority_queue` are honest placeholders: the flags exist and are
    reported by GET /v1/account, but neither gates anything real yet —
    private-repo intake doesn't exist (only public repos are fetchable at
    all, see app/ingest/github_fetch.py) and there is no job queue in this
    codebase to prioritize (the scan runs inline in a threadpool). They're
    here so Stage 2 and later work have a defined place to switch on.
    """

    daily_audit_limit: int
    private_repos_allowed: bool
    priority_queue: bool


def entitlements_for_tier(tier: str, *, free_daily_limit: int) -> Entitlements:
    """Resolve a tier string to its entitlements.

    `free_daily_limit` is passed in (the live RateLimiter's configured
    limit) rather than hardcoded, so what GET /v1/account reports for a
    free caller is exactly what create_audit enforces — no second source
    of truth for the free number that could drift from the env-configured
    limiter.

    Anything not exactly `pro` maps to free: anonymous, unknown key, or a
    row with an unexpected tier value all get the free entitlement set.
    """
    if tier == TIER_PRO:
        return Entitlements(
            daily_audit_limit=PRO_DAILY_AUDIT_LIMIT,
            private_repos_allowed=True,
            priority_queue=True,
        )
    return Entitlements(
        daily_audit_limit=free_daily_limit,
        private_repos_allowed=False,
        priority_queue=False,
    )


def entitlements_dict(ent: Entitlements) -> dict[str, Any]:
    return asdict(ent)


class _AccountLookup(Protocol):
    async def get_by_api_key(self, api_key: str) -> dict[str, Any] | None: ...


def api_key_from_request(request: Any) -> str | None:
    """Pull the API key out of `Authorization: Bearer <key>`, matching the
    reap endpoint's header scheme. Missing/other schemes -> None."""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer "):].strip() or None
    return None


async def resolve_account(
    request: Any, account_repo: _AccountLookup
) -> dict[str, Any] | None:
    """The account for this request, or None for anonymous/free.

    Returns None (no DB call) when there's no API key — so anonymous
    traffic is completely unaffected: same code path, no added latency.
    A present key is looked up; an unknown key or an unconfigured database
    both return None (get_by_api_key's not-configured contract), i.e.
    fall back to free, never raise.
    """
    key = api_key_from_request(request)
    if not key:
        return None
    return await account_repo.get_by_api_key(key)
