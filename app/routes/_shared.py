"""Request/response helpers shared by more than one route module.

Extracted from app/main.py verbatim. Everything here is used by at least two
endpoint groups -- that shared use is the reason it lives in its own module
rather than beside a single router.

Names keep their leading underscore. They were private to main.py and are
still not part of any public surface; the underscore records that, and keeping
it means the move is a pure relocation with no rename to chase through
callers.
"""

from __future__ import annotations

import json

from fastapi import HTTPException, Request

import hmac
import os
import re

from app.fixpack.generate import has_auto_fixable_findings
from app.log_context import set_log_context


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


# --- Bearer-token and client-identity helpers -------------------------------
#
# Moved here from app/main.py because the operator-only endpoints that use them
# are spread across several route modules. main.py re-exports _secret_equals
# and _client_key: tests/test_non_ascii_auth_headers.py and
# tests/test_ratelimit.py import them from app.main.


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


def _service_flags_token() -> str | None:
    """Bearer token protecting the emergency-stop toggle endpoint, same env-var
    pattern as MONITORING_PROCESS_TOKEN. Unset -> the endpoint 503s rather than
    accept a no-op auth check on a switch that can halt all paid LLM ops."""
    return os.environ.get("SERVICE_FLAGS_TOKEN") or None


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


# --- GitHub owner/repo parsing ------------------------------------------------
#
# Moved here from app/main.py: used by the installation-status endpoint (now in
# app/routes/github.py) and by three code paths still in main.py, so it belongs
# with the other cross-module helpers rather than in either one.


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
