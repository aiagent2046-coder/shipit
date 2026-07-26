from __future__ import annotations

import logging
import os

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.db import AuditJobRepository, FixpackJobRepository


logger = logging.getLogger(__name__)
router = APIRouter()
_fixpack_repo = FixpackJobRepository()
_audit_job_repo = AuditJobRepository()


@router.get("/readyz", include_in_schema=False)
async def readyz() -> JSONResponse:
    """Readiness: process can serve requests and its database is reachable.

    Reports both queues. The audit numbers matter more than they look: since
    the cutover, POST /v1/audits only enqueues, so a stopped audit worker is
    invisible from the API's own health -- every request still succeeds while
    nothing is ever scanned. A growing oldest_audit_queued_seconds is the only
    thing that shows it.

    They are reported but deliberately do NOT decide readiness: a backlog means
    the worker is behind, not that this API process should be pulled out of
    service. Only db-unreachable is not_ready, exactly as before."""
    try:
        stats = await _fixpack_repo.backlog_stats()
    except Exception as exc:
        logger.warning("readiness database check failed: %s", type(exc).__name__)
        stats = None

    if stats is None:
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "db": False,
                "fixpack_backlog": None,
                "oldest_paid_seconds": None,
                "audit_backlog": None,
                "oldest_audit_queued_seconds": None,
            },
        )

    try:
        audit_stats = await _audit_job_repo.backlog_stats()
    except Exception as exc:
        logger.warning("audit backlog check failed: %s", type(exc).__name__)
        audit_stats = None

    return JSONResponse(
        status_code=200,
        content={
            "status": "ready",
            "db": True,
            "fixpack_backlog": stats["backlog"],
            "oldest_paid_seconds": stats["oldest_paid_seconds"],
            "audit_backlog": audit_stats["queued"] if audit_stats else None,
            "oldest_audit_queued_seconds": (
                audit_stats["oldest_queued_seconds"] if audit_stats else None
            ),
        },
    )


@router.get("/version", include_in_schema=False)
async def version() -> dict[str, str]:
    return {
        "release": os.environ.get("SHIPIT_RELEASE", "unknown"),
        "environment": os.environ.get("ENVIRONMENT", "development"),
    }
