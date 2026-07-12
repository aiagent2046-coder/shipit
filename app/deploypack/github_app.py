"""GitHub App authentication — mints short-lived installation tokens
instead of relying on a single operator PAT.

Why this exists: shipit-architecture.md 2.1 marks the GitHub App
"обязателен" for PR delivery. A single PAT (delivery.py's original
scope) can only open PRs on repos the PAT's owner has write access to
— a real stranger's repo can never receive a PR that way. Once a
stranger installs this App on their own repo, GitHub issues a token
scoped to exactly that installation, regardless of who operates ShipIt.

Real, unavoidable manual step this module cannot do for you: creating
the App itself. GitHub requires someone to click through
https://github.com/settings/apps/new (or the manifest flow) — there is
no API that creates an App from nothing without that click, and no
ShipIt operator credential can substitute for it. Once created, this
module only needs:

  GITHUB_APP_ID          — the App's Client ID (e.g. "Iv23..."), which
                            GitHub now recommends for the JWT `iss`
                            claim over the older numeric App ID (see
                            https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app).
                            The numeric App ID still works — not
                            deprecated, just no longer recommended.
                            Either is a plain string here; no branching
                            needed since `iss` is just a string per the
                            JWT spec.
  GITHUB_APP_PRIVATE_KEY — the full PEM private key GitHub generates
                            when you create the App

Falls back to GITHUB_PR_TOKEN (delivery.py) when these aren't set —
this module is additive, not a replacement for the working PAT path.
See app/main.py for how the two are chosen between.
"""

from __future__ import annotations

import os
import time

import httpx
import jwt

GITHUB_API = "https://api.github.com"
_HEADERS_BASE = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


class GitHubAppError(Exception):
    """Raised when App auth IS configured but a step failed. Distinct
    from "not configured at all" (app_credentials_from_env returning
    None), which callers should treat as "use the PAT path instead",
    not an error."""


def app_credentials_from_env() -> tuple[str, str] | None:
    app_id = os.environ.get("GITHUB_APP_ID")
    private_key = os.environ.get("GITHUB_APP_PRIVATE_KEY")
    if not app_id or not private_key:
        return None
    return app_id, private_key


def mint_app_jwt(app_id: str, private_key: str, *, now: float | None = None) -> str:
    """Short-lived (9 min, under GitHub's 10 min cap) JWT identifying
    the App itself. Used only to look up installations and mint
    installation tokens below — never to call the Git Data API
    directly, which needs an installation token instead."""
    now = now if now is not None else time.time()
    payload = {"iat": int(now) - 60, "exp": int(now) + 9 * 60, "iss": app_id}
    return jwt.encode(payload, private_key, algorithm="RS256")


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
