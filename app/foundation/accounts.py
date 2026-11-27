"""Account tiers and entitlements — the identity foundation for the
paywall: the account/tier/entitlement layer a payment provider plugs into.
No provider logic lives here, which is why four providers could come and three
could go without this file changing.

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

    It used to carry two more: `private_repos_allowed` and `priority_queue`,
    described in this docstring as "honest placeholders". They were honest
    HERE and dishonest on the wire. A caller reading GET /v1/account saw
    `priority_queue: false` on free and `true` on pro and drew the only
    reasonable conclusion — that paying buys a faster queue. It did not. The
    comment explaining that was in a file the caller never sees, and a
    product whose README has a section titled "What Drydock deliberately does
    not claim" cannot ship two claims of exactly that kind in its own API
    response.

    So they are gone rather than annotated. Removing a field from a v1
    response is a compatibility break and worth naming as one: nothing reads
    them (web/src/lib/types.ts declared them and no component consumed them),
    and a field that means nothing cannot break anything by ceasing to exist.
    The place to record that private intake and queue priority are planned is
    the code that will gate them and the status record — not a payload that
    tells every caller they already work.

    Only `daily_audit_limit` remains, and it is really enforced, in
    app/main.py's create_audit via the rate limiter.
    """

    daily_audit_limit: int


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
        return Entitlements(daily_audit_limit=PRO_DAILY_AUDIT_LIMIT)
    return Entitlements(daily_audit_limit=free_daily_limit)


def entitlements_dict(ent: Entitlements) -> dict[str, Any]:
    return asdict(ent)


class _AccountLookup(Protocol):
    async def get_by_key_hash(self, key_hash: str) -> dict[str, Any] | None: ...


API_KEY_COOKIE = "shipit_api_key"

# Not the CSRF mechanism. SameSite=Lax is -- see set_api_key_cookie. This is
# the second lock, and it exists for a specific hole Lax leaves open rather
# than as a general precaution.
#
# SameSite draws its boundary at the registrable domain, so EVERY subdomain of
# drydock.co is same-site and gets the cookie. Deploy Pack previews are meant
# to be served per job (README: the `{job_id}.preview.*` URL still needs a
# real domain), and a preview runs the CUSTOMER'S code. Put those on a
# drydock.co subdomain -- the obvious choice -- and Lax alone would hand that
# code a customer's session.
#
# This header closes that: a request carrying any header outside the
# CORS-safelisted set must be preflighted, and the preflight is answered
# against CORS_ALLOWED_ORIGINS, which a preview subdomain is not in. The value
# is deliberately never checked, because the value is not the mechanism --
# there is nothing here for an attacker to guess.
#
# A double-submit token would add a second cookie, a generator and a
# comparison for the same guarantee the preflight already gives.
CSRF_HEADER = "x-drydock-web"


def api_key_from_request(request: Any) -> str | None:
    """Pull the API key out of `Authorization: Bearer <key>`, matching the
    reap endpoint's header scheme, then out of the session cookie.

    Header first, and it is unconditional: a caller that sets Authorization
    holds the key already, which is CSRF-immune by construction -- a third
    party's page cannot set that header cross-origin without a preflight it
    will not pass. Scripts, curl and the docs page keep working untouched.

    The cookie is the browser's path, and it is only honoured alongside
    CSRF_HEADER. SameSite=Lax already stops a cross-SITE request from
    carrying it; this check stops a same-site one, which a Deploy Pack
    preview on a drydock.co subdomain would be while running customer code.
    Ten of this API's POST endpoints parse no body at all --
    /v1/account/rotate-key among them, which would let such a page invalidate
    the key a customer paid for.

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

    SameSite=Lax, which is the CSRF defence: the browser will not attach this
    cookie to a cross-site POST at all, so the ten body-less POST endpoints
    here stop being reachable from anyone else's page.

    Lax is only available because the API moved to api.drydock.co (#172).
    Against the old 45-10-40-169.sslip.io host this was a different site from
    the frontend, which forced SameSite=None -- and a None cookie is a
    third-party cookie, which Safari and Firefox block outright. The earlier
    shape of this change would have failed silently in both.

    Secure regardless: the only thing served over anything but https here is
    a developer's localhost, which browsers already treat as secure.
    """
    response.set_cookie(
        API_KEY_COOKIE,
        api_key,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )


def clear_api_key_cookie(response: Any) -> None:
    """Drop the session cookie. Needed for parity: "forget this key" used to
    be a sessionStorage removal the frontend could do by itself, and an
    HttpOnly cookie can only be cleared by the server that set it."""
    response.delete_cookie(API_KEY_COOKIE, path="/", secure=True, samesite="lax")


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
