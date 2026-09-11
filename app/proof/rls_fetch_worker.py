"""One live RLS request, isolated so its parent can stop DNS as well as HTTP.

The private pipe protocol accepts credentials on stdin and returns only the
oracle's sanitized verdict or a fixed error code. Never emit upstream bodies,
exception text, or credentials to stdout/stderr.
"""
from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import asdict

import httpx

from app.proof.rls_probe import (
    MAX_WORKER_REQUEST_BYTES,
    MAX_WORKER_RESULT_BYTES,
    ProbeResponseError,
    _evaluate_response,
    _fetch_response,
)


def main() -> None:
    try:
        raw = sys.stdin.buffer.read(MAX_WORKER_REQUEST_BYTES + 1)
        if len(raw) > MAX_WORKER_REQUEST_BYTES:
            raise ValueError("invalid worker request")
        request = json.loads(raw)
        status, body = asyncio.run(_fetch_response(
            request["base"], request["anon_key"], request["table"],
            request["limit"], request["timeout_s"],
        ))
        verdict = _evaluate_response(
            status, body, request["table"], request["limit"],
        )
        envelope = {"verdict": asdict(verdict)}
    except ProbeResponseError as exc:
        envelope = {"error": exc.reason}
    except (TimeoutError, httpx.TimeoutException):
        envelope = {"error": "request_timeout"}
    except Exception:
        envelope = {"error": "request_failed"}
    output = json.dumps(envelope, ensure_ascii=True).encode()
    if len(output) > MAX_WORKER_RESULT_BYTES:
        output = b'{"error":"invalid_response"}'
    sys.stdout.buffer.write(output)


if __name__ == "__main__":
    main()
