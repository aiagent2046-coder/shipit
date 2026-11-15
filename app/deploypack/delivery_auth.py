"""Caller-scoped authorization for the synchronous, public Deploy Pack API.

An installed server App is not evidence that an HTTP caller owns its repository.
This path uses the caller's token both to check access and to perform delivery;
GitHub still enforces that token's actual write scopes on each mutation.
"""
from __future__ import annotations

import re

import httpx

from app.deploypack.delivery import GITHUB_API, _HEADERS_BASE, github_retryable


class DeliveryAuthorizationError(Exception):
    """Fixed public diagnostics; never include upstream text or credentials."""

    def __init__(self, status_code: int, reason: str):
        self.status_code = status_code
        self.reason = reason
        super().__init__(reason)


def validate_delivery_token(token: str | None) -> str:
    if not token:
        raise DeliveryAuthorizationError(401, "github_token_required")
    if len(token) > 4096 or re.fullmatch(r"[A-Za-z0-9_.-]+", token) is None:
        raise DeliveryAuthorizationError(401, "invalid_github_token")
    return token


def authorize_repository_delivery(
    owner: str, repo: str, token: str, *, transport: httpx.BaseTransport | None = None,
) -> None:
    """Preflight the exact target without writing anything or following redirects.

permissions.push checks the authenticated principal's repository role, not all
token scopes. The SAME caller token must therefore be used for the later write;
this check must never authorize use of the server's more powerful App or PAT.
"""
    token = validate_delivery_token(token)
    try:
        with httpx.Client(
            base_url=GITHUB_API,
            headers={**_HEADERS_BASE, "Authorization": f"Bearer {token}"},
            timeout=10, follow_redirects=False, transport=transport,
        ) as client:
            response = client.get(f"/repos/{owner}/{repo}")
        if github_retryable(response):
            raise DeliveryAuthorizationError(502, "github_authorization_unavailable")
        if response.status_code == 401:
            raise DeliveryAuthorizationError(401, "invalid_github_token")
        if response.status_code in (403, 404) or response.is_redirect:
            raise DeliveryAuthorizationError(403, "repository_write_access_required")
        if response.status_code != 200:
            raise DeliveryAuthorizationError(502, "github_authorization_unavailable")
        data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise DeliveryAuthorizationError(502, "github_authorization_unavailable") from exc
    permissions = data.get("permissions") if isinstance(data, dict) else None
    if (not isinstance(data, dict)
            or not isinstance(data.get("full_name"), str)
            or data["full_name"].casefold() != f"{owner}/{repo}".casefold()
            or not isinstance(permissions, dict)
            or permissions.get("push") is not True):
        raise DeliveryAuthorizationError(403, "repository_write_access_required")
