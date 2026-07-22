from __future__ import annotations

import logging
import os

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.db import FixpackJobRepository


logger = logging.getLogger(__name__)
router = APIRouter()
_fixpack_repo = FixpackJobRepository()


@router.get("/readyz", include_in_schema=False)
async def readyz() -> JSONResponse:
    """Readiness: process can serve requests and its database is reachable."""
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
            },
        )

    return JSONResponse(
        status_code=200,
        content={
            "status": "ready",
            "db": True,
            "fixpack_backlog": stats["backlog"],
            "oldest_paid_seconds": stats["oldest_paid_seconds"],
        },
    )


@router.get("/version", include_in_schema=False)
async def version() -> dict[str, str]:
    return {
        "release": os.environ.get("SHIPIT_RELEASE", "unknown"),
        "environment": os.environ.get("ENVIRONMENT", "development"),
    }
