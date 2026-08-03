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

import hashlib
import hmac
import os
import secrets
from dataclasses import asdict, dataclass
from typing import Any, Protocol

TIER_FREE = "free"
TIER_PRO = "pro"

# Materially higher than free's limit (which is the RateLimiter's
# configured value, AUDIT_RATE_LIMIT_PER_DAY, default 5).
PRO_DAILY_AUDIT_LIMIT = 100

_API_KEY_PREFIX = "sk_live_"

# The key_prefix stored/displayed for a key: enough to eyeball-identify a
# key in logs/a dashboard, short enough to reveal nothing usable. Covers
# the `sk_live_` marker plus a few chars of the random body.
KEY_PREFIX_LEN = 12

# Server-side HMAC secret ("pepper"), env-only, NEVER in the DB or git.
# A DB-only leak therefore can't offline-brute the stored hashes without
# also stealing this. Read at use time so tests can set it per-case.
API_KEY_PEPPER_ENV = "API_KEY_PEPPER"


def generate_api_key() -> str:
    """Opaque, server-generated. Used by Stage 2's payment flow when it
    creates an account — kept here so key format lives with the identity
    model, not scattered into whatever provider mints the first one."""
    return f"{_API_KEY_PREFIX}{secrets.token_urlsafe(32)}"


def api_key_prefix(api_key: str) -> str:
    """The safe-to-display prefix of a key (see KEY_PREFIX_LEN)."""
    return api_key[:KEY_PREFIX_LEN]


def _pepper_from_env() -> bytes | None:
    value = os.environ.get(API_KEY_PEPPER_ENV)
    return value.encode() if value else None


def require_pepper() -> bytes:
    """The configured pepper, or a loud error. Never silently substitutes
    an empty/default pepper — a wrong pepper would make every key hash
    mismatch (locking out all Pro users) while looking like it works, so
    this must fail obviously instead."""
    pepper = _pepper_from_env()
    if pepper is None:
        raise RuntimeError(
            f"{API_KEY_PEPPER_ENV} is not set — cannot hash or verify account "
            "API keys. Set it to the server-side pepper (never commit it)."
        )
    return pepper


def hash_api_key(api_key: str) -> str:
    """HMAC-SHA256(pepper, key) as hex. This is what's stored in and looked
    up from accounts.key_hash — the plaintext key is never persisted."""
    return hmac.new(require_pepper(), api_key.encode(), hashlib.sha256).hexdigest()


def pepper_is_configured() -> bool:
    return _pepper_from_env() is not None


def validate_api_key_pepper_configured(*, database_configured: bool) -> None:
    """Startup guard: if the DB is configured, accounts are live, so the
    pepper MUST be set or key hashing/lookup is broken. Refuse to boot
    rather than fall back silently. On a DB-less deployment accounts are
    unusable anyway, so a missing pepper is fine (no-op)."""
    if database_configured and not pepper_is_configured():
        raise RuntimeError(
            f"{API_KEY_PEPPER_ENV} is not set but DATABASE_URL is configured; "
            "refusing to start with account API-key hashing unconfigured. "
            "Generate a random pepper (e.g. `openssl rand -hex 32`) and set "
            f"{API_KEY_PEPPER_ENV} in the environment."
        )


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
    async def get_by_key_hash(self, key_hash: str) -> dict[str, Any] | None: ...


API_KEY_COOKIE = "shipit_api_key"

# Presence of this header is the CSRF defence for the cookie path. Its value
# is deliberately never checked, because the value is not the mechanism: a
# cross-origin request carrying ANY header outside the CORS-safelisted set
# forces the browser to preflight, and the preflight is answered against
# CORS_ALLOWED_ORIGINS. An attacker's page never gets to send the real
# request, so there is nothing for it to guess.
#
# A double-submit token would give the same guarantee here and cost a second
# cookie, a generator and a comparison. The topology already provides the
# protection; adding a token would be re-implementing the preflight in
# application code.
#
# This is only needed because the cookie must be SameSite=None. The frontend
# is a separate origin (Vercel) from this API, so every call is cross-site
# and SameSite=Lax would simply never send the cookie. None restores that,
# and hands CSRF back to us to solve -- which is what this header does.
CSRF_HEADER = "x-drydock-web"


def api_key_from_request(request: Any) -> str | None:
    """Pull the API key out of `Authorization: Bearer <key>`, matching the
    reap endpoint's header scheme, then out of the session cookie.

    Header first, and it is unconditional: a caller that sets Authorization
    holds the key already, which is CSRF-immune by construction -- a third
    party's page cannot set that header cross-origin without a preflight it
    will not pass. Scripts, curl and the docs page keep working untouched.

    The cookie is the browser's path, and it is only honoured alongside
    CSRF_HEADER. Without that check a cookie would ride along on any
    cross-site request the victim's browser can be made to issue, and ten of
    this API's POST endpoints parse no body at all -- /v1/account/rotate-key
    among them, which would let any page a customer visits invalidate the key
    they paid for.

    An unaccompanied cookie reads as no key rather than an error, matching
    what resolve_account already does with an unknown one: fall back to
    anonymous, never raise. The endpoints that cannot serve anonymous
    (rotate-key) answer 401 on their own.
    """
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer "):].strip() or None
    cookies = getattr(request, "cookies", None) or {}
    key = (cookies.get(API_KEY_COOKIE) or "").strip()
    if not key:
        return None
    if not request.headers.get(CSRF_HEADER):
        return None
    return key


def set_api_key_cookie(response: Any, api_key: str) -> None:
    """Hand the browser the key in a form its JavaScript cannot read.

    HttpOnly is the whole point: an XSS on the frontend, or a compromised
    dependency, can no longer read the credential out of sessionStorage and
    keep it. It can still act as the user while the page is open -- HttpOnly
    stops exfiltration, not abuse -- but a stolen key works forever and an
    open tab does not.

    No max_age, so this expires with the browser session. That is exactly
    what sessionStorage did, and matching it keeps this change to one
    variable: the key stops being readable, and nothing else moves.

    SameSite=None because the frontend is a different site from this API;
    Secure is mandatory with it and correct regardless.
    """
    response.set_cookie(
        API_KEY_COOKIE,
        api_key,
        httponly=True,
        secure=True,
        samesite="none",
        path="/",
    )


def clear_api_key_cookie(response: Any) -> None:
    """Drop the session cookie. Needed for parity: "forget this key" used to
    be a sessionStorage removal the frontend could do by itself, and an
    HttpOnly cookie can only be cleared by the server that set it."""
    response.delete_cookie(API_KEY_COOKIE, path="/", secure=True, samesite="none")


async def resolve_account(
    request: Any, account_repo: _AccountLookup
) -> dict[str, Any] | None:
    """The account for this request, or None for anonymous/free.

    Returns None (no DB call) when there's no API key — so anonymous
    traffic is completely unaffected: same code path, no added latency.
    A present key is looked up; an unknown key or an unconfigured database
    both return None (the repo's not-configured contract), i.e. fall back
    to free, never raise.

    Keys are matched only by HMAC hash on key_hash. Without a configured
    pepper we can't hash, so we return None (fall back to free) rather than
    raising — a real deployment with a DB is guaranteed to have a pepper by
    the startup guard. Plaintext at rest no longer exists (migration 0019
    dropped the api_key column), so there is no recoverable-key path.
    """
    key = api_key_from_request(request)
    if not key:
        return None
    return await account_for_key(key, account_repo)


async def account_for_key(
    api_key: str, account_repo: _AccountLookup
) -> dict[str, Any] | None:
    """Look up an account by the key itself, for the one caller that has the
    key without a request to read it from: POST /v1/auth/login, where it
    arrives in the body.

    Extracted from resolve_account rather than duplicated there. Two copies of
    "how a key becomes an account" is how one of them ends up skipping the
    pepper check."""
    if not api_key:
        return None
    if not pepper_is_configured():
        return None
    return await account_repo.get_by_key_hash(hash_api_key(api_key))
