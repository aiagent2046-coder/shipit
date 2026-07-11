"""ShipIt API gateway — MVP phase 1 surface.

Only what exists today: health check and archive intake with validation
and stack detection. Persistence, queue, and LLM scan come next.
"""

from __future__ import annotations

import io
import uuid

from fastapi import FastAPI, HTTPException, UploadFile

from app.ingest.stack_detect import Stack, detect_stack
from app.scan.static import run_static_scan
from app.ingest.validators import (
    MAX_ARCHIVE_BYTES,
    ArchiveValidationError,
    validate_zip,
)

app = FastAPI(title="ShipIt", version="0.1.0")


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.post("/v1/audits", status_code=202)
async def create_audit(archive: UploadFile) -> dict:
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
