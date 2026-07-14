"""ShipIt API gateway — MVP phase 1 surface.

Only what exists today: health check and archive intake with validation,
rate limiting, stack detection, static scan, and (when providers are
configured) the LLM auth/security scan. Persistence and the queue come
next — the scan stage runs off the event loop in a threadpool for now,
since the LLM call alone can take up to ~2 minutes.
"""

from __future__ import annotations

import hmac
import io
import os
import re
import uuid

from fastapi import Depends, FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse
from starlette.concurrency import run_in_threadpool

from app.db import AuditRepository, FixpackJobRepository
from app.deploypack.delivery import DeliveryError, open_pull_request, render_pr_body
from app.deploypack.generate import UnsupportedForDeployPack
from app.deploypack.github_app import (
    GitHubAppError,
    app_credentials_from_env,
    installation_token_for_repo,
)
from app.deploypack.pipeline import run_deploy_pack
from app.deploypack.preview import PreviewRegistry
from app.ingest.stack_detect import Stack, detect_stack
from app.llm.client import LLMClient
from app.report.html import render_report
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


_audit_repo = AuditRepository()
_fixpack_repo = FixpackJobRepository()


def get_audit_repo() -> AuditRepository:
    """FastAPI dependency indirection — overridable in tests. No-ops
    (returns None from create/get) when DATABASE_URL isn't set — see
    app/db.py."""
    return _audit_repo


def get_fixpack_repo() -> FixpackJobRepository:
    """Same as get_audit_repo, for fixpack_jobs."""
    return _fixpack_repo


# GitHub owner/repo names: alphanumerics, hyphen, underscore, period.
# Permissive-but-safe guard so a user-supplied deliver_to can't smuggle
# extra path segments (extra "/" or "..") into a GitHub REST API path.
_VALID_OWNER_REPO_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")


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
    """Operational endpoint for the scheduled reaper — called hourly by
    shipit-reap.timer on the production VPS (a former GitHub Actions
    workflow doing the same thing was removed 2026-07-14: it never had
    its repo secrets configured and was redundant once the VPS timer
    existed). Not part of the public API surface; there's no
    user-facing reason to call this directly.

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
    # Constant-time compare so response latency doesn't leak the token.
    provided = request.headers.get("authorization", "")
    if not hmac.compare_digest(provided, f"Bearer {token}"):
        raise HTTPException(status_code=401, detail={"reason": "unauthorized"})

    reaped = await run_in_threadpool(preview_registry.reap_expired)
    return {"reaped": reaped, "active": preview_registry.active_count()}


@app.get("/v1/audits/{audit_id}")
async def get_audit(
    audit_id: str,
    audit_repo: AuditRepository = Depends(get_audit_repo),
) -> dict:
    row = await audit_repo.get(audit_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no audit with this id, or persistence isn't "
                               "configured on this deployment (see app/db.py)"},
        )
    return row


@app.get("/v1/audits/{audit_id}/report")
async def get_audit_report(
    audit_id: str,
    audit_repo: AuditRepository = Depends(get_audit_repo),
) -> HTMLResponse:
    """The shareable artifact: the same persisted audit rendered as a
    self-contained, plain-language HTML page."""
    row = await audit_repo.get(audit_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no audit with this id, or persistence isn't "
                               "configured on this deployment (see app/db.py)"},
        )
    result = {
        "score": row.get("score_json") or {},
        "findings": row.get("findings_json") or [],
    }
    html = render_report(result, project_name=f"audit {audit_id[:8]}")
    return HTMLResponse(content=html)


@app.post("/v1/audits", status_code=202)
async def create_audit(
    archive: UploadFile,
    request: Request,
    limiter: RateLimiter = Depends(get_rate_limiter),
    llm_client: LLMClient = Depends(get_llm_client),
    audit_repo: AuditRepository = Depends(get_audit_repo),
) -> dict:
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

    # Consume quota only after the upload proves to be real work: validation
    # and stack detection are free, so a garbage/hostile zip (or probing for
    # validation bypasses) can't burn a client's 5-audits-a-day budget for a
    # request that never produced an audit.
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

    # Off the event loop: the LLM stage does real network I/O and can
    # take up to ~2 minutes. Moves to the arq worker + queue in phase 2.
    scan = await run_in_threadpool(run_scan, raw, llm_client)

    persisted = await audit_repo.create(
        stack=stack.value, file_count=report.file_count,
        score_total=scan["score"]["total"], score_json=scan["score"],
        findings_json=scan["findings"],
    )
    audit_id = persisted["id"] if persisted else str(uuid.uuid4())

    return {
        "audit_id": audit_id,
        "persisted": persisted is not None,
        "status": "completed",
        "stack": stack.value,
        "file_count": report.file_count,
        "score": scan["score"],
        "findings": scan["findings"],
        "llm": scan["llm"],
    }


@app.get("/v1/fixpacks/{job_id}")
async def get_fixpack(
    job_id: str,
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
) -> dict:
    row = await fixpack_repo.get(job_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no fixpack job with this id, or persistence "
                               "isn't configured on this deployment (see app/db.py)"},
        )
    return row


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
    audit_id: str | None = Form(
        None,
        description="Link this Pack to a previously persisted audit, if you "
                     "have one. Optional — the API doesn't require an audit first.",
    ),
    limiter: RateLimiter = Depends(get_rate_limiter),
    pr_opener=Depends(get_pr_opener),
    preview_registry: PreviewRegistry = Depends(get_preview_registry),
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
) -> dict:
    """Deploy Pack only, minimal scope (fastapi + vite-react). Free,
    unpaid preview of the plan's "verify first, pay to unlock" flow —
    no payment gate yet. Persists a fixpack_jobs row when DATABASE_URL
    is configured (see app/db.py); `persisted: false` in the response
    otherwise, same request still works. Shares the audit rate limiter
    for now; should become "1 free Pack run per audit_id" now that
    audits are persisted.

    PR delivery uses a GitHub App installation token when
    GITHUB_APP_ID + GITHUB_APP_PRIVATE_KEY are configured (works for
    any repo the App is installed on, not just the operator's own),
    falling back to the single-operator GITHUB_PR_TOKEN otherwise —
    see app/deploypack/github_app.py and app/deploypack/delivery.py.

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

    if audit_id is not None:
        try:
            uuid.UUID(audit_id)
        except ValueError:
            raise HTTPException(
                status_code=422,
                detail={"reason": "bad_audit_id",
                        "detail": "audit_id must be a valid UUID"},
            )

    # Validate deliver_to before any expensive build or GitHub call: it's
    # user input that lands directly in GitHub REST API paths (owner/repo
    # in delivery.py + github_app.py). Reject anything that isn't exactly
    # two valid name segments so extra "/" or ".." can't reshape the path.
    owner = repo = None
    if deliver_to:
        parts = deliver_to.split("/")
        if len(parts) != 2 or not all(_VALID_OWNER_REPO_SEGMENT.match(p) for p in parts):
            raise HTTPException(
                status_code=422,
                detail={"reason": "bad_deliver_to",
                        "detail": "deliver_to must be 'owner/repo', each part "
                                  "matching ^[A-Za-z0-9._-]+$"},
            )
        owner, repo = parts

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

    persisted_job = await fixpack_repo.create(
        audit_id=audit_id, pack="deploy", stack=stack.value,
        verified=result["verified"], detail=result["detail"],
        preview_local_url=result["preview"]["local_url"] if result["preview"] else None,
        preview_expires_at=result["preview"]["expires_at"] if result["preview"] else None,
    )
    job_id = persisted_job["id"] if persisted_job else str(uuid.uuid4())

    pr: dict | None = None
    if deliver_to:
        if result["verified"] is not True:
            pr = {"delivered": False, "reason": "not verified, refusing to open a PR"}
        else:
            body = render_pr_body("deploy", result["files"], result["detail"])
            try:
                token: str | None = None
                app_creds = app_credentials_from_env()
                if app_creds is not None:
                    app_id, private_key = app_creds
                    token = await run_in_threadpool(
                        installation_token_for_repo, owner, repo,
                        app_id=app_id, private_key=private_key,
                    )
                opened = await run_in_threadpool(
                    pr_opener, owner, repo, result["files"], body=body, token=token,
                )
            except (DeliveryError, GitHubAppError) as exc:
                pr = {"delivered": False, "reason": str(exc)}
            else:
                pr = {"delivered": True, "url": opened.html_url,
                      "branch": opened.branch}
                if persisted_job:
                    await fixpack_repo.mark_delivered(job_id, opened.html_url)

    return {
        "fixpack_id": job_id,
        "persisted": persisted_job is not None,
        "pack": "deploy",
        "stack": stack.value,
        "verified": result["verified"],
        "detail": result["detail"],
        "files": result["files"],
        "pr": pr,
        "preview": result["preview"],
    }
