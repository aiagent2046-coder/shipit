"""Ask a live Supabase project, with its own public key, for rows it should
not hand out.

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

import re
import time
from collections.abc import Callable
from typing import Any

from app.proof.rls_oracle import evaluate_rls_response
from app.proof.types import ExploitAttempt

TEMPLATE_ID = "rls_open_runtime"

PROBE_TIMEOUT_S = 15

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
    except UnsafeProjectUrl as exc:
        return _attempt(
            "skipped", False, str(exc),
            {"table": table, "reason": "unsafe_project_url"}, started)

    if not _safe_table_name(table):
        return _attempt(
            "skipped", False, f"недопустимое имя таблицы: {table[:40]!r}",
            {"table": table, "reason": "unsafe_table_name"}, started)

    fetch = fetch or _default_fetch
    try:
        status_code, body = fetch(base, anon_key, table, limit)
    except Exception as exc:  # noqa: BLE001 — infrastructure, not a verdict
        return _attempt(
            "error", False,
            f"запрос к проекту не выполнился: {type(exc).__name__}",
            {"table": table, "reason": "request_failed"}, started)

    verdict = evaluate_rls_response(status_code, body, table=table)
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
                   limit: int) -> tuple[int, Any]:
    """GET /rest/v1/<table>?select=*&limit=N as the anonymous role."""
    import httpx

    response = httpx.get(
        f"{base}/rest/v1/{table}",
        params={"select": "*", "limit": str(int(limit))},
        headers={
            "apikey": anon_key,
            "Authorization": f"Bearer {anon_key}",
            "Accept": "application/json",
        },
        timeout=PROBE_TIMEOUT_S,
        follow_redirects=False,
    )
    try:
        return response.status_code, response.json()
    except ValueError:
        return response.status_code, None


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
