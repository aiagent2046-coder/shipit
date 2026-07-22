"""Bearer-token auth for the sandbox-runner, mirroring the backend's internal
endpoints (reaper / fixpack processor): the token comes from the env, an unset
token makes the endpoint refuse to run (503) rather than accept a no-op check,
and the comparison is constant-time.

The runner also listens on a Unix socket whose file permissions are the primary
access control (O5); the token is a second line of defence so a stray local
process that can reach the socket still can't drive docker without it."""

from __future__ import annotations

import hmac
import os

from fastapi import HTTPException, Request

SANDBOX_RUNNER_TOKEN = os.environ.get("SANDBOX_RUNNER_TOKEN", "")


def require_sandbox_token(request: Request) -> None:
    if not SANDBOX_RUNNER_TOKEN:
        raise HTTPException(
            status_code=503,
            detail={"reason": "runner_not_configured",
                    "detail": "SANDBOX_RUNNER_TOKEN is not set on this runner"},
        )
    provided = request.headers.get("authorization", "")
    if not hmac.compare_digest(provided, f"Bearer {SANDBOX_RUNNER_TOKEN}"):
        raise HTTPException(status_code=401, detail={"reason": "unauthorized"})
