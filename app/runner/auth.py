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
    # Compared as bytes, not str: hmac.compare_digest raises TypeError on two
    # str arguments if either holds a character above 127, and a caller can put
    # any byte in a header -- which turned a bad token into a 500 instead of a
    # 401. Encodings differ by side because the header arrived as bytes the
    # ASGI server decoded latin-1, while the token came from the env as text.
    # Same reasoning, and the same wording, as _secret_equals in app/main.py;
    # this module deliberately mirrors the backend rather than importing it.
    provided = request.headers.get("authorization", "")
    expected = f"Bearer {SANDBOX_RUNNER_TOKEN}"
    if not hmac.compare_digest(
        provided.encode("latin-1"), expected.encode("utf-8")
    ):
        raise HTTPException(status_code=401, detail={"reason": "unauthorized"})
