"""Ask a live Supabase project which rows its public key can read.

Part B of SUPABASE_RLS_YIELD_PLAN.md. One `select`, judged by
app.proof.rls_oracle, returned as an ExploitAttempt so the before/after pair
composes with app.proof.compare.build_proof_report exactly like the CORS pair.

WHY THIS CLASS SIDESTEPS EVERYTHING THE CORS DETECTOR DIED ON: there is no
build, no container, no sandbox. The application is already deployed and the
key already ships to the browser. The three blockers that ended the CORS
detector at 0 of 7 — no root Dockerfile, BuildKit, build-time egress — cannot
apply to a single HTTPS GET.

TWO RULES ARE ENFORCED IN CODE HERE, NOT IN THE PLAN DOCUMENT.

1. CONSENT. This reads a real database belonging to a real person. `consent`
   has no default: a caller that has not thought about it cannot accidentally
   run this. Without it the attempt is `skipped`, not `failure` — we did not
   check, and that is a different sentence from "nothing was wrong".

2. THE URL IS NOT THE REPOSITORY'S TO CHOOSE. The project URL is read out of
   the customer's own source, which makes an unrestricted request here an SSRF
   primitive: a repository could aim it at a cloud metadata endpoint or an
   internal service and have our infrastructure fetch the result. Only
   `https://<ref>.supabase.co` is accepted. This is the same rule that keeps
   the CORS probe on loopback, arriving from the opposite direction — there the
   address had to be ours, here it has to be theirs and of one exact shape.
"""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.proof.rls_oracle import RlsVerdict, evaluate_rls_response
from app.proof.types import ExploitAttempt

TEMPLATE_ID = "rls_open_runtime"

PROBE_TIMEOUT_S = 15
MAX_RESPONSE_BYTES = 256 * 1024
MAX_ROWS = 3
MAX_WORKER_REQUEST_BYTES = 64 * 1024
MAX_WORKER_RESULT_BYTES = 4 * MAX_RESPONSE_BYTES


class ProbeResponseError(ValueError):
    """A bounded, fixed-code response failure; never carries response content."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


_RESPONSE_ERRORS = {
    "response_too_large": "ответ превысил лимит размера; доступ не определён",
    "unsupported_encoding": "сжатый ответ не поддерживается; доступ не определён",
    "invalid_response": "ответ имеет неверный формат; доступ не определён",
}


# `https://<20-char ref>.supabase.co`, and nothing else. Self-hosted Supabase
# on a custom domain is deliberately unsupported rather than pattern-matched:
# a looser rule is how the SSRF gets back in, and a self-hosted customer can be
# handled explicitly when one exists.
_PROJECT_URL = re.compile(
    r"^https://(?P<ref>[a-z0-9]{16,32})\.supabase\.co/?$", re.IGNORECASE)

# The local stack the e2e stands up (`supabase start`). Off by default: a
# loopback address accepted in production would be an SSRF into our own host.
_LOCAL_URL = re.compile(r"^http://(?:127\.0\.0\.1|localhost):\d{2,5}/?$")


class UnsafeProjectUrl(ValueError):
    """The URL is not a Supabase project endpoint we are willing to call."""


def validate_project_url(url: str, *, allow_loopback: bool = False) -> str:
    """Return the normalised base URL, or raise.

    Rejecting is the safe direction: a project we decline to probe produces a
    `skipped` attempt, while a project we probe at an attacker-chosen address
    turns this service into a request relay.
    """
    candidate = (url or "").strip().rstrip("/")
    if _PROJECT_URL.match(candidate + "/"):
        return candidate
    if allow_loopback and _LOCAL_URL.match(candidate + "/"):
        return candidate
    raise UnsafeProjectUrl(
        f"not a Supabase project URL: {candidate[:80]!r}")


def run_rls_probe(
    *,
    project_url: str,
    anon_key: str,
    table: str,
    consent: bool,
    limit: int = 3,
    allow_loopback: bool = False,
    fetch: Callable[..., tuple[int, Any]] | None = None,
    timeout_s: float = PROBE_TIMEOUT_S,
) -> ExploitAttempt:
    """One anonymous `select` against ``table``, judged and returned.

    ``fetch`` is injectable so the status table can be tested without a
    network, the same pattern cors_probe.py uses for ``verify``.
    """
    started = time.monotonic()

    if not consent:
        # NOT `failure`. We did not look, and a report saying "the attack did
        # not work" over a check that never ran is the inflation this project
        # has removed twice.
        return _attempt(
            "skipped", False,
            "проба не запускалась: нет подтверждённого согласия владельца "
            "проекта",
            {"table": table, "reason": "no_consent"}, started)

    try:
        base = validate_project_url(project_url, allow_loopback=allow_loopback)
    except UnsafeProjectUrl:
        return _attempt(
            "skipped", False, "неподдерживаемый URL проекта",
            {"table": table, "reason": "unsafe_project_url"}, started)

    if not _safe_table_name(table):
        return _attempt(
            "skipped", False, "недопустимое имя таблицы",
            {"table": "", "reason": "unsafe_table_name"}, started)

    import httpx

    limit = max(1, min(int(limit), MAX_ROWS))
    try:
        if timeout_s <= 0:
            raise TimeoutError
        if fetch is None:
            verdict = _default_fetch(
                base, anon_key, table, limit,
                timeout_s=min(timeout_s, PROBE_TIMEOUT_S),
            )
        else:
            # Trusted test seam; production uses the bounded worker process.
            status_code, body = fetch(base, anon_key, table, limit)
            verdict = _evaluate_response(status_code, body, table, limit)
    except ProbeResponseError as exc:
        return _attempt(
            "error", False, _RESPONSE_ERRORS[exc.reason],
            {"table": table, "reason": exc.reason}, started)
    except (TimeoutError, httpx.TimeoutException):
        return _attempt(
            "error", False, "время ожидания ответа истекло; доступ не определён",
            {"table": table, "reason": "request_timeout"}, started)
    except Exception:  # noqa: BLE001 — infrastructure, not a verdict
        return _attempt(
            "error", False, "запрос к проекту не выполнился; доступ не определён",
            {"table": table, "reason": "request_failed"}, started)

    if not verdict.conclusive:
        # The probe ran and learned nothing — a bad key, a 5xx. `error`, never
        # `failure`: "we checked and it was fine" is a claim this has not
        # earned.
        return _attempt("error", False, verdict.detail,
                        {**verdict.evidence, "reason": verdict.reason}, started)

    return _attempt(
        "success" if verdict.exposed else "failure",
        verdict.exposed,
        verdict.detail,
        {**verdict.evidence, "reason": verdict.reason},
        started,
    )


def _safe_table_name(table: str) -> bool:
    """A table name goes into the request path. It comes from parsed customer
    SQL, so it is untrusted input like any other."""
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", table or ""))


def _default_fetch(base: str, anon_key: str, table: str,
                   limit: int, *, timeout_s: float = PROBE_TIMEOUT_S,
                   ) -> RlsVerdict:
    """Wait for a bounded worker, including startup, DNS and client cleanup.

    Cancelling asyncio DNS does not stop the system resolver's executor thread.
    A per-request process lets the parent end that work too when time runs out.
    Credentials use stdin; stdout carries only the sanitized verdict.
    """
    deadline = time.monotonic() + timeout_s
    request = json.dumps({
        "base": base, "anon_key": anon_key, "table": table,
        "limit": limit, "timeout_s": timeout_s,
    }).encode()
    if len(request) > MAX_WORKER_REQUEST_BYTES:
        raise ValueError("invalid worker request")
    with subprocess.Popen(
        [sys.executable, "-m", "app.proof.rls_fetch_worker"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        cwd=Path(__file__).resolve().parents[2],
    ) as process:
        try:
            output, _ = process.communicate(
                input=request, timeout=max(0.0, deadline - time.monotonic()),
            )
        except BaseException as exc:
            # Reap before returning: no DNS thread or HTTP reader survives.
            process.kill()
            process.communicate()
            if isinstance(exc, subprocess.TimeoutExpired):
                raise TimeoutError from None
            raise
    if process.returncode or len(output) > MAX_WORKER_RESULT_BYTES:
        raise ValueError("invalid worker response")
    envelope = json.loads(output)
    error = envelope.get("error")
    if error == "request_timeout":
        raise TimeoutError
    if error in _RESPONSE_ERRORS:
        raise ProbeResponseError(error)
    if error is not None:
        raise ValueError("worker request failed")
    return RlsVerdict(**envelope["verdict"])


def _evaluate_response(status_code: int, body: Any, table: str,
                       limit: int) -> RlsVerdict:
    if status_code == 200 and isinstance(body, list) and len(body) > limit:
        raise ProbeResponseError("invalid_response")
    return evaluate_rls_response(status_code, body, table=table)


async def _fetch_response(base: str, anon_key: str, table: str,
                          limit: int, timeout_s: float) -> tuple[int, Any]:
    """Bound async I/O; the parent process also bounds DNS and loop shutdown.

    HTTPX's read timeout alone resets on each chunk. asyncio.timeout cancels
    the in-flight request at the deadline. The parent terminates the worker
    if a blocking resolver or transport cleanup outlives that deadline.
    Request identity encoding and reject compression before reading so that a
    decompression bomb cannot allocate an unbounded decoded chunk.
    """
    import httpx

    async with asyncio.timeout(timeout_s):
        async with httpx.AsyncClient(
            timeout=timeout_s, follow_redirects=False,
        ) as client:
            async with client.stream(
                "GET", f"{base}/rest/v1/{table}",
                params={"select": "*", "limit": str(limit)},
                headers={
                    "apikey": anon_key,
                    "Authorization": f"Bearer {anon_key}",
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
            ) as response:
                encoding = response.headers.get("content-encoding", "identity")
                if encoding.strip().lower() not in ("", "identity"):
                    raise ProbeResponseError("unsupported_encoding")
                length = response.headers.get("content-length", "")
                if length.isdigit() and int(length) > MAX_RESPONSE_BYTES:
                    raise ProbeResponseError("response_too_large")
                data = bytearray()
                async for chunk in response.aiter_raw(chunk_size=4096):
                    if len(data) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise ProbeResponseError("response_too_large")
                    data.extend(chunk)
                try:
                    body = json.loads(data)
                except (ValueError, RecursionError):
                    raise ProbeResponseError("invalid_response") from None
                return response.status_code, body


def _attempt(status: str, success: bool, detail: str,
             evidence: dict[str, Any], started: float) -> ExploitAttempt:
    return ExploitAttempt(
        template_id=TEMPLATE_ID,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        success=success,
        detail=detail,
        evidence=evidence,
        duration_ms=max(0, int((time.monotonic() - started) * 1000)),
    )
