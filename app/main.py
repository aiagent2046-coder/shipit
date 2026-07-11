"""ShipIt API gateway — MVP phase 1 surface.

Only what exists today: health check and archive intake with validation,
rate limiting, and stack detection. Persistence, queue, and LLM scan come
next.
"""

from __future__ import annotations

import io
import uuid

from fastapi import Depends, FastAPI, HTTPException, Request, UploadFile

from app.ingest.stack_detect import Stack, detect_stack
from app.ratelimit import RateLimitExceeded, RateLimiter, limiter_from_env
from app.scan.static import run_static_scan
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


@app.post("/v1/audits", status_code=202)
async def create_audit(
    archive: UploadFile,
    request: Request,
    limiter: RateLimiter = Depends(get_rate_limiter),
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

    # Synchronous for now; moves to the arq worker with the LLM stage.
    buf.seek(0)
    scan = run_static_scan(buf)

    return {
        "audit_id": str(uuid.uuid4()),
        "status": "completed",
        "stack": stack.value,
        "file_count": report.file_count,
        "score": scan["score"],
        "findings": scan["findings"],
    }
