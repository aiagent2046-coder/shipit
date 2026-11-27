"""Short-lived, invoice-bound caller authority for asynchronous PR delivery.

The same credential that the buyer provides performs the eventual GitHub writes.
No service App/PAT fallback is permitted. Only an authenticated encrypted envelope
is persisted, in a separate store that is never part of public payment responses.
"""
from __future__ import annotations

import json
import os

from cryptography.fernet import Fernet, InvalidToken
from starlette.concurrency import run_in_threadpool

from app.runtime.github_repo import _parse_github_repo_url
from app.services.deploypack.delivery_auth import (
    DeliveryAuthorizationError,
    authorize_repository_delivery,
    validate_delivery_token,
)

GRANT_TTL_SECONDS = 7 * 24 * 60 * 60


def _cipher() -> Fernet:
    try:
        return Fernet(os.environ.get("FIXPACK_DELIVERY_ENCRYPTION_KEY", "").encode("ascii"))
    except (ValueError, UnicodeError):
        raise DeliveryAuthorizationError(503, "delivery_authorization_not_configured") from None


def repository_name(audit: dict) -> str:
    parsed = _parse_github_repo_url(audit.get("repo_url") or "")
    if parsed is None:
        raise DeliveryAuthorizationError(422, "not_github_audit")
    return "/".join(parsed)


async def authorize_paid_checkout(audit: dict, token: str | None) -> str:
    token = validate_delivery_token(token)
    _cipher()  # Refuse before issuing an invoice if durable authority is unavailable.
    owner, repo = repository_name(audit).split("/")
    await run_in_threadpool(authorize_repository_delivery, owner, repo, token)
    return token


def seal_paid_grant(
    token: str, *, provider: str, external_ref: str, audit_id: str,
    repo_full_name: str,
) -> str:
    payload = {
        "v": 1, "token": validate_delivery_token(token), "provider": provider,
        "external_ref": external_ref, "audit_id": str(audit_id),
        "repo_full_name": repo_full_name.casefold(),
    }
    return _cipher().encrypt(json.dumps(payload, separators=(",", ":")).encode()).decode()


def open_paid_grant(
    encrypted: str | None, *, provider: str, external_ref: str, audit_id: str,
    repo_full_name: str,
) -> str:
    if not encrypted:
        raise DeliveryAuthorizationError(401, "github_delivery_authorization_required")
    cipher = _cipher()
    try:
        data = json.loads(cipher.decrypt(encrypted.encode(), ttl=GRANT_TTL_SECONDS))
        expected = {"v": 1, "provider": provider, "external_ref": external_ref,
                    "audit_id": str(audit_id), "repo_full_name": repo_full_name.casefold()}
        if not isinstance(data, dict) or any(data.get(k) != v for k, v in expected.items()):
            raise ValueError("grant binding mismatch")
        return validate_delivery_token(data.get("token"))
    except (InvalidToken, ValueError, UnicodeError, TypeError, AttributeError):
        raise DeliveryAuthorizationError(401, "github_delivery_authorization_expired") from None


def get_paid_delivery_store():
    from app.services.deploypack.paid_delivery_store import PaidDeliveryStore
    return PaidDeliveryStore()


async def paid_delivery_token(job: dict, audit: dict) -> str:
    """Re-read committed funding and authority on every check, including delivery."""
    store = get_paid_delivery_store()
    row = await store.get_for_job(str(job["id"]))
    if row is None:
        # Settlement commits the job before linking the confirmed invoice.
        # This brief interval is not a revoked or missing buyer credential.
        if await store.funding_pending(str(job["id"])):
            raise DeliveryAuthorizationError(503, "delivery_funding_pending")
        # Settlement may have committed between the two reads above.
        row = await store.get_for_job(str(job["id"]))
    if row is None or str(row.get("audit_id")) != str(job.get("audit_id")):
        raise DeliveryAuthorizationError(401, "github_delivery_authorization_required")
    name = repository_name(audit)
    token = open_paid_grant(
        row.get("encrypted_grant"), provider=row["provider"],
        external_ref=row["external_ref"], audit_id=str(job["audit_id"]),
        repo_full_name=name,
    )
    owner, repo = name.split("/")
    await run_in_threadpool(authorize_repository_delivery, owner, repo, token)
    return token
