"""ShipIt API gateway — MVP phase 1 surface.

Only what exists today: health check and archive intake with validation,
rate limiting, stack detection, static scan, and (when providers are
configured) the LLM auth/security scan. Persistence and the queue come
next — the scan stage runs off the event loop in a threadpool for now,
since the LLM call alone can take up to ~2 minutes.
"""

from __future__ import annotations

import io
import os
import uuid

from fastapi import Depends, FastAPI, Form, HTTPException, Request, UploadFile
from starlette.concurrency import run_in_threadpool

from app.deploypack.delivery import DeliveryError, open_pull_request, render_pr_body
from app.deploypack.generate import UnsupportedForDeployPack
from app.deploypack.pipeline import run_deploy_pack
from app.deploypack.preview import PreviewRegistry
from app.ingest.stack_detect import Stack, detect_stack
from app.llm.client import LLMClient
from app.ratelimit import RateLimitExceeded, RateLimiter, limiter_from_env
from app.scan.pipeline import run_scan
from app.ingest.validators import (
    MAX_ARCHIVE_BYTES,
    ArchiveValidationError,
    validate_zip,
)

app = FastAPI(title="ShipIt", version="0.1.0")

_limiter = limiter_from_env()


def get_rate_limiter() -> RateLimiter:
    """FastAPI dependency indirection — overridable in tests."""
    return _limiter


def get_llm_client() -> LLMClient:
    """FastAPI dependency indirection — overridable in tests."""
    return LLMClient()


def get_pr_opener():
    """FastAPI dependency indirection — overridable in tests."""
    return open_pull_request


_preview_registry = PreviewRegistry()


def get_preview_registry() -> PreviewRegistry:
    """FastAPI dependency indirection — overridable in tests. In-memory,
    single-process, same caveat as get_rate_limiter."""
    return _preview_registry


def _reap_token() -> str | None:
    """Same env-var pattern as GITHUB_PR_TOKEN in delivery.py. Unset by
    default — the endpoint below refuses to run rather than accept an
    empty/no-op auth check."""
    return os.environ.get("PREVIEW_REAP_TOKEN") or None


def _client_key(request: Request) -> str:
    """Client IP, honoring one reverse-proxy hop (Caddy in prod).

    Trusts the first X-Forwarded-For entry. Only safe because this
    endpoint sits behind our own known proxy — do not reuse this helper
    if the app is ever exposed directly to the internet without one.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.post("/internal/preview/reap")
async def reap_previews(
    request: Request,
    preview_registry: PreviewRegistry = Depends(get_preview_registry),
) -> dict:
    """Operational endpoint for the scheduled reaper — see
    .github/workflows/preview-reaper.yml. Not part of the public API
    surface; there's no user-facing reason to call this directly.

    Requires `Authorization: Bearer <PREVIEW_REAP_TOKEN>`. Returns 503
    if the token isn't configured on this deployment at all, rather
    than silently doing nothing — an unconfigured reaper is an
    operational gap someone needs to notice, not a quiet no-op.
    """
    token = _reap_token()
    if not token:
        raise HTTPException(
            status_code=503,
            detail={"reason": "reap_not_configured",
                    "detail": "PREVIEW_REAP_TOKEN is not set on this deployment"},
        )
    if request.headers.get("authorization") != f"Bearer {token}":
        raise HTTPException(status_code=401, detail={"reason": "unauthorized"})

    reaped = await run_in_threadpool(preview_registry.reap_expired)
    return {"reaped": reaped, "active": preview_registry.active_count()}


@app.post("/v1/audits", status_code=202)
async def create_audit(
    archive: UploadFile,
    request: Request,
    limiter: RateLimiter = Depends(get_rate_limiter),
    llm_client: LLMClient = Depends(get_llm_client),
) -> dict:
    try:
        limiter.check(_client_key(request))
    except RateLimitExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail={
                "reason": "rate_limited",
                "detail": f"max {limiter.limit} audits per day",
            },
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc

    raw = await archive.read(MAX_ARCHIVE_BYTES + 1)
    buf = io.BytesIO(raw)

    try:
        report = validate_zip(buf, size_bytes=len(raw))
    except ArchiveValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail={"reason": exc.reason, "detail": exc.detail},
        ) from exc

    buf.seek(0)
    stack = detect_stack(buf)
    if stack is Stack.UNSUPPORTED:
        raise HTTPException(
            status_code=422,
            detail={"reason": "unsupported_stack",
                    "detail": "MVP supports Next.js and FastAPI only"},
        )

    # Off the event loop: the LLM stage does real network I/O and can
    # take up to ~2 minutes. Moves to the arq worker + queue in phase 2.
    scan = await run_in_threadpool(run_scan, raw, llm_client)

    return {
        "audit_id": str(uuid.uuid4()),
        "status": "completed",
        "stack": stack.value,
        "file_count": report.file_count,
        "score": scan["score"],
        "findings": scan["findings"],
        "llm": scan["llm"],
    }


@app.post("/v1/fixpacks", status_code=202)
async def create_fixpack(
    archive: UploadFile,
    request: Request,
    deliver_to: str | None = Form(
        None,
        description='"owner/repo" to open a real PR against, once verified. '
                    "Omit to just get the generated files back, unverified-safe.",
    ),
    want_preview: bool = Form(
        False,
        description="Keep the verified container alive for a live preview "
                     "instead of tearing it down. Returns a local_url, not a "
                     "public one — see app/deploypack/preview.py for why.",
    ),
    limiter: RateLimiter = Depends(get_rate_limiter),
    pr_opener=Depends(get_pr_opener),
    preview_registry: PreviewRegistry = Depends(get_preview_registry),
) -> dict:
    """Deploy Pack only, minimal scope (fastapi + vite-react). Free,
    unpaid preview of the plan's "verify first, pay to unlock" flow —
    no payment gate yet, no persistence yet. PR delivery uses a single
    operator token (GITHUB_PR_TOKEN), not a GitHub App — see
    app/deploypack/delivery.py. Shares the audit rate limiter for now;
    should become "1 free Pack run per audit_id" once audits are
    persisted (phase 2).

    `want_preview=true` keeps the container alive (24h TTL, 256MB RAM
    cap, 1 live preview per client key — same _client_key as the rate
    limiter) and reaps anything already expired before starting a new
    one. There's no background cron in this process yet, so a preview
    only gets reaped when someone next calls this endpoint — wire
    preview_registry.reap_expired() to a real periodic job before
    relying on the 24h TTL alone.
    """
    try:
        limiter.check(_client_key(request))
    except RateLimitExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail={
                "reason": "rate_limited",
                "detail": f"max {limiter.limit} audits per day",
            },
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc

    raw = await archive.read(MAX_ARCHIVE_BYTES + 1)
    buf = io.BytesIO(raw)

    try:
        validate_zip(buf, size_bytes=len(raw))
    except ArchiveValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail={"reason": exc.reason, "detail": exc.detail},
        ) from exc

    buf.seek(0)
    stack = detect_stack(buf)

    if want_preview:
        await run_in_threadpool(preview_registry.reap_expired)

    # Off the event loop: docker build/run/curl are real blocking
    # subprocess calls, up to a few minutes total.
    try:
        if want_preview:
            result = await run_in_threadpool(
                run_deploy_pack, raw, stack,
                preview=preview_registry, owner_key=_client_key(request),
            )
        else:
            result = await run_in_threadpool(run_deploy_pack, raw, stack)
    except UnsupportedForDeployPack:
        raise HTTPException(
            status_code=422,
            detail={"reason": "unsupported_stack",
                    "detail": "Deploy Pack supports fastapi and vite-react only"},
        )

    pr: dict | None = None
    if deliver_to:
        if result["verified"] is not True:
            pr = {"delivered": False, "reason": "not verified, refusing to open a PR"}
        else:
            try:
                owner, repo = deliver_to.split("/", 1)
            except ValueError:
                pr = {"delivered": False, "reason": "deliver_to must be 'owner/repo'"}
            else:
                body = render_pr_body("deploy", result["files"], result["detail"])
                try:
                    opened = await run_in_threadpool(
                        pr_opener, owner, repo, result["files"], body=body,
                    )
                except DeliveryError as exc:
                    pr = {"delivered": False, "reason": str(exc)}
                else:
                    pr = {"delivered": True, "url": opened.html_url,
                          "branch": opened.branch}

    return {
        "fixpack_id": str(uuid.uuid4()),
        "pack": "deploy",
        "stack": stack.value,
        "verified": result["verified"],
        "detail": result["detail"],
        "files": result["files"],
        "pr": pr,
        "preview": result["preview"],
    }
