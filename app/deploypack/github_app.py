"""GitHub App authentication — mints short-lived installation tokens
instead of relying on a single operator PAT.

Why this exists: shipit-architecture.md 2.1 marks the GitHub App
"обязателен" for PR delivery. A single PAT (delivery.py's original
scope) can only open PRs on repos the PAT's owner has write access to
— a real stranger's repo can never receive a PR that way. Once a
stranger installs this App on their own repo, GitHub issues a token
scoped to exactly that installation, regardless of who operates Drydock.

Real, unavoidable manual step this module cannot do for you: creating
the App itself. GitHub requires someone to click through
https://github.com/settings/apps/new (or the manifest flow) — there is
no API that creates an App from nothing without that click, and no
Drydock operator credential can substitute for it. Once created, this
module only needs:

  GITHUB_APP_ID          — the App's Client ID (e.g. "Iv23..."), which
                            GitHub now recommends for the JWT `iss`
                            claim over the older numeric App ID (see
                            https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app).
                            The numeric App ID still works — not
                            deprecated, just no longer recommended. Both
                            are sent as a string `iss` (PyJWT forbids a
                            non-string `iss`); GitHub accepts a digit
                            string App ID fine, so `iss` type is not a
                            cause of "could not be decoded" 401s.
  GITHUB_APP_PRIVATE_KEY — the full PEM private key GitHub generates
                            when you create the App

Falls back to GITHUB_PR_TOKEN (delivery.py) when these aren't set —
this module is additive, not a replacement for the working PAT path.
See app/main.py for how the two are chosen between.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import os
import time
import urllib.parse

import httpx
import jwt
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
_HEADERS_BASE = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

# Public slug of the GitHub App as it appears in its install URL
# (https://github.com/apps/<slug>). This App was flipped Private -> Public
# in the GitHub UI, so any account can now install it. Overridable via env
# for a differently-named App, but the default is the real one so a stock
# deployment builds a working install link with no extra config.
GITHUB_APP_SLUG_DEFAULT = "aiagent2046-coder-shipit"


class GitHubAppError(Exception):
    """Raised when App auth IS configured but a step failed. Distinct
    from "not configured at all" (app_credentials_from_env returning
    None), which callers should treat as "use the PAT path instead",
    not an error."""


def _normalize_pem(raw: str) -> str:
    """A flat systemd EnvironmentFile line holds one KEY=VALUE per
    physical line and cannot carry a raw multi-line PEM block, so the
    only way to fit a PEM into it is to store literal two-character
    ``\\n`` escapes instead of real newlines. jwt.encode needs a real
    PEM with actual newline characters, so undo that escaping here.

    Unescape whenever literal ``\\n`` is present. A correctly-formatted
    multi-line PEM contains real newlines but NO literal ``\\n`` sequences,
    so this replace is a no-op on it — the "no double-unescape" guarantee
    holds without gating on the absence of real newlines. The old
    ``and "\\n" not in raw`` gate caused the production failure this fixes:
    when the env value carried literal ``\\n`` escapes AND even one stray
    real newline (e.g. a trailing newline the loader kept), the gate skipped
    unescaping entirely, leaving the 27 literal ``\\n`` intact so the PEM
    parser rejected the key ("not a valid PEM private key")."""
    if "\\n" in raw:
        raw = raw.replace("\\n", "\n")
    return raw


def _private_key_from_b64() -> str | None:
    """Decode GITHUB_APP_PRIVATE_KEY_B64 — a base64 encoding of the raw
    PEM (real newlines and all) — into a usable PEM string.

    Why this path exists: systemd's EnvironmentFile= applies one layer of
    C-style escape processing when it parses values, so it consumes a
    backslash before our code ever runs. A value stored as literal
    two-char ``\\n`` escapes (for _normalize_pem to undo) therefore loses
    that backslash inside systemd, leaving bare letter "n" instead of
    newlines — the PEM is then always invalid under systemd (confirmed on
    prod: a 1700-char file value arrives as 1674 chars in /proc/<pid>/environ,
    exactly 26 fewer — one per interior newline — with 0 real newlines seen
    by Python). base64's alphabet contains no backslash, newline, or other
    special characters, so it is immune to any escape processing and survives
    systemd untouched.

    Returns None (not an error) when the variable is unset/empty or cannot
    be decoded, so the caller falls back to the escaping-based path."""
    raw = os.environ.get("GITHUB_APP_PRIVATE_KEY_B64")
    if not raw:
        return None
    try:
        return base64.b64decode(raw, validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        # Structure-only diagnostic: the decode failure type, never the value.
        logger.warning(
            "GITHUB_APP_PRIVATE_KEY_B64 could not be decoded (%s) — "
            "falling back to GITHUB_APP_PRIVATE_KEY",
            type(exc).__name__,
        )
        return None


def app_credentials_from_env() -> tuple[str, str] | None:
    app_id = os.environ.get("GITHUB_APP_ID")
    if not app_id:
        return None
    # Prefer the base64 path (systemd-safe); fall back to the literal-\n
    # escaping path, which still works for non-systemd delivery mechanisms
    # that pass the secret through without escape processing.
    private_key = _private_key_from_b64()
    if not private_key:
        raw = os.environ.get("GITHUB_APP_PRIVATE_KEY")
        private_key = _normalize_pem(raw) if raw else None
    if not private_key:
        return None
    return app_id, private_key


def mint_app_jwt(app_id: str, private_key: str, *, now: float | None = None) -> str:
    """Short-lived (9 min, under GitHub's 10 min cap) JWT identifying
    the App itself. Used only to look up installations and mint
    installation tokens below — never to call the Git Data API
    directly, which needs an installation token instead.

    ``iss`` is sent as a string: PyJWT (>=2, issue #1039) raises
    TypeError for a non-string ``iss``, so it CANNOT be a JSON number
    here. GitHub accepts a digit-string App ID ("4278482") as ``iss``
    fine, so this is not the cause of a "could not be decoded" 401 —
    that verdict is signature/structure level (wrong keypair or clock
    skew), never the ``iss`` type."""
    now = now if now is not None else time.time()
    payload = {"iat": int(now) - 60, "exp": int(now) + 9 * 60, "iss": app_id.strip()}
    private_key = _normalize_pem(private_key)
    try:
        return jwt.encode(payload, private_key, algorithm="RS256")
    except (ValueError, jwt.exceptions.PyJWTError) as exc:
        # Structure-only diagnostics for PEM parse failures: the exact
        # underlying library error, the real-newline count after normalize,
        # and the first/last 15 chars (PEM boundary markers, never key
        # material). Enough to tell a truncated/mis-escaped key from a
        # genuinely wrong one without ever logging the secret.
        logger.warning(
            "PEM parse failed: %s: %s | real newlines after normalize=%d | "
            "head=%r | tail=%r",
            type(exc).__name__, exc, private_key.count("\n"),
            private_key[:15], private_key[-15:],
        )
        raise GitHubAppError(
            "GITHUB_APP_PRIVATE_KEY is not a valid PEM private key — "
            "check for missing newlines or truncation"
        ) from exc


def _public_key_fingerprint(private_key: str) -> str:
    """A short, NON-secret SHA-256 fingerprint of the *public* half of the
    loaded private key. Lets an operator confirm whether the key actually
    in use matches the one registered for a given App: download the App's
    .pem, run
    ``openssl rsa -in app.pem -pubout -outform DER | openssl dgst -sha256``
    and compare. A "could not be decoded" 401 with a fingerprint that does
    NOT match the App means the wrong keypair is loaded — the single most
    likely cause of that error, and invisible without this. Public-key
    material only; the private key never leaves the process."""
    try:
        key = serialization.load_pem_private_key(
            _normalize_pem(private_key).encode(), password=None
        )
        der = key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return "sha256:" + hashlib.sha256(der).hexdigest()[:16]
    except (ValueError, TypeError) as exc:
        return f"unavailable ({type(exc).__name__})"


def installation_token_for_repo(
    owner: str,
    repo: str,
    *,
    app_id: str,
    private_key: str,
    transport: httpx.BaseTransport | None = None,
) -> str:
    """Resolve which installation covers owner/repo, then mint a
    short-lived (1h) installation access token scoped to that
    installation's repos — never the broader App JWT.

    Raises GitHubAppError with a specific, actionable message when the
    App isn't installed on this repo at all — that's the single most
    likely real-world failure and deserves a distinct message from a
    generic API error.
    """
    app_jwt = mint_app_jwt(app_id, private_key)
    headers = {**_HEADERS_BASE, "Authorization": f"Bearer {app_jwt}"}
    with httpx.Client(base_url=GITHUB_API, headers=headers, timeout=30,
                       transport=transport) as client:
        resp = client.get(f"/repos/{owner}/{repo}/installation")
        if resp.status_code == 401:
            # GitHub rejected the App JWT itself (e.g. "A JSON web token
            # could not be decoded"). That is a signature/structure verdict,
            # never the iss type \u2014 so surface the structural facts that
            # distinguish its causes: which App ID we claimed, the token
            # shape, and a NON-secret fingerprint of the loaded keypair to
            # check against the App's registered key. No secret is logged.
            logger.warning(
                "App JWT rejected (401) resolving %s/%s: %s | app_id(iss)=%r | "
                "jwt segments=%d | jwt len=%d | public key %s",
                owner, repo, resp.text[:200], app_id.strip(),
                app_jwt.count(".") + 1, len(app_jwt),
                _public_key_fingerprint(private_key),
            )
        if resp.status_code == 404:
            raise GitHubAppError(
                f"GitHub App is not installed on {owner}/{repo} \u2014 "
                "the repo owner needs to install it first"
            )
        if resp.status_code >= 300:
            raise GitHubAppError(
                f"resolve installation failed: {resp.status_code} {resp.text[:300]}"
            )
        installation_id = resp.json()["id"]

        token_resp = client.post(f"/app/installations/{installation_id}/access_tokens")
        if token_resp.status_code >= 300:
            raise GitHubAppError(
                f"mint installation token failed: {token_resp.status_code} "
                f"{token_resp.text[:300]}"
            )
        return token_resp.json()["token"]


def installation_exists_for_repo(
    owner: str,
    repo: str,
    *,
    app_id: str,
    private_key: str,
    transport: httpx.BaseTransport | None = None,
) -> bool:
    """Does the App have an installation covering owner/repo?

    The same per-repo lookup installation_token_for_repo does (GET
    /repos/{owner}/{repo}/installation with an App JWT), minus the token
    mint — a status check has no reason to spend an installation token.
    Returns False for GitHub's 404 (the App simply isn't installed on that
    repo, the one answer a "should we show the install button?" caller
    needs) and True for a 200. Any other non-2xx is a real fault (bad App
    JWT, GitHub down) and raises GitHubAppError, so the caller can tell
    "not installed" apart from "could not check" instead of conflating
    both into a misleading False.
    """
    app_jwt = mint_app_jwt(app_id, private_key)
    headers = {**_HEADERS_BASE, "Authorization": f"Bearer {app_jwt}"}
    with httpx.Client(base_url=GITHUB_API, headers=headers, timeout=30,
                      transport=transport) as client:
        resp = client.get(f"/repos/{owner}/{repo}/installation")
        if resp.status_code == 404:
            return False
        if resp.status_code >= 300:
            raise GitHubAppError(
                f"resolve installation failed: {resp.status_code} {resp.text[:300]}"
            )
        return True


def app_slug_from_env() -> str:
    """The App's public slug, env-overridable but defaulting to the real
    one so a stock deployment needs no extra config to build install links."""
    return os.environ.get("GITHUB_APP_SLUG") or GITHUB_APP_SLUG_DEFAULT


def build_install_url(state: str) -> str:
    """The public "install this App" URL for a stranger's browser. `state`
    is echoed back verbatim to the App's Setup URL after install (we pass
    owner/repo through it), url-encoded so a "/" survives the round trip."""
    slug = app_slug_from_env()
    return (
        f"https://github.com/apps/{slug}/installations/new"
        f"?state={urllib.parse.quote(state, safe='')}"
    )
