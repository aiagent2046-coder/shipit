"""What the static audit can look for, served for anyone to read.

No authentication and no per-row token: this describes the engine, not a
customer's repository, and somebody deciding whether the audit is worth buying
should be able to read what it covers without an account first.

The answer comes from `app.capabilities`, the same declaration that backs the
`checks_run` list and the per-check scope sentences a report carries. This is
the currently deployed engine; historical audits retain their own engine
revision and per-scan evidence.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.capabilities import manifest
from app.scan.pipeline import AUDIT_ENGINE_VERSION

router = APIRouter()


@router.get("/v1/capabilities")
async def capabilities() -> dict:
    """Every static check, the rule ids it can emit, and what it cannot see."""
    return manifest(AUDIT_ENGINE_VERSION)
