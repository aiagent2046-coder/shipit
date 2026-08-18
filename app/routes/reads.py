"""Read-only lookups for audits, audit jobs, and Fix Pack jobs.

Extracted from app/main.py verbatim -- handler bodies are unchanged, only the
decorators moved from ``@app.<verb>`` to ``@router.<verb>``.

Every handler here is a GET that authorises against a per-row access token and
returns 404 rather than 403 on a bad one, so a caller cannot use the response
to learn whether an id exists. None of them writes, charges, or calls an LLM.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse

from app.db import (
    STALE_LEASE_DETAIL_PREFIX,
    AuditJobRepository,
    AuditRepository,
    FixpackJobRepository,
)
from app.fixpack.generate import has_auto_fixable_findings
from app.report.grouping import group_for_display
from app.log_context import set_log_context
from app.report.html import render_report
from app.routes.dependencies import (
    get_audit_job_repo,
    get_audit_repo,
    get_fixpack_repo,
)

router = APIRouter()


@router.get("/v1/audits/{audit_id}")
async def get_audit(
    audit_id: str,
    token: str | None = None,
    audit_repo: AuditRepository = Depends(get_audit_repo),
) -> dict:
    # Ownership check: the audit is readable only by presenting its per-row
    # access_token (?token=...), delivered once at creation. A leaked id is
    # not enough. A missing/wrong token is answered 404 (not 403) so this
    # never confirms an id exists to someone who doesn't hold its token.
    #
    # Bound before the lookup, not after: a failed authorization is exactly the
    # request whose logs need the id someone asked for.
    set_log_context(audit_id=audit_id)
    row = await audit_repo.get_authorized(audit_id, token)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no audit with this id and token, or persistence "
                               "isn't configured on this deployment (see app/db.py)"},
        )
    # Whether a Fix Pack could produce anything for this audit. Computed here,
    # not in the browser: the answer depends on which rules the Fix Pack knows
    # how to rewrite, and a second copy of that list in TypeScript would drift
    # from this one -- which is precisely what #132 was about. The page uses it
    # to explain instead of offering a purchase that cannot deliver.
    # `fixpack_auto_fixable` is computed over the STORED rows, before any
    # grouping: what the Fix Pack can rewrite is a fact about the findings, not
    # about how many rows the reader is shown.
    return {
        **row,
        "findings_json": group_for_display(row.get("findings_json") or []),
        "fixpack_auto_fixable": has_auto_fixable_findings(
            row.get("findings_json") or []
        ),
    }


@router.get("/v1/audit-jobs/{job_id}")
async def get_audit_job(
    job_id: str,
    token: str | None = None,
    audit_job_repo: AuditJobRepository = Depends(get_audit_job_repo),
) -> dict:
    """Poll one queued audit's progress (durable queue, migration 0022).

    Same ownership model as GET /v1/audits/{id}: the per-row access_token,
    handed to the submitter once at enqueue, is the only key, and anything that
    doesn't match -- wrong token, no token, unknown id -- is a flat 404 so this
    never confirms a job id to someone who doesn't hold its token.

    Deliberately narrow. `state` and `audit_id` are what a client polls for
    (audit_id is null until the job succeeds, then it is the row to fetch via
    GET /v1/audits/{id}), and `error_code` is the machine-readable reason a
    terminal job has no result. The internals a caller has no business acting
    on -- claimed_by, lease_expires_at, attempts, quota_key, idempotency_key,
    the free-text error_message -- stay server-side, and the job's own
    access_token is never selected by get_authorized in the first place.

    The one addition is `audit_access_token`: the finished audit is protected by
    its OWN token, so audit_id alone would leave a poller unable to read the
    result it waited for. It is null until the job succeeds. Handing it to the
    holder of the job token is not a widening -- POST /v1/audits returned the
    audit token directly to that same submitter before the cutover."""
    set_log_context(job_id=job_id)
    row = await audit_job_repo.get_authorized(job_id=job_id, access_token=token)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no audit job with this id and token, or "
                              "persistence isn't configured on this "
                              "deployment (see app/db.py)"},
        )
    return {
        "id": row["id"],
        "state": row["state"],
        "error_code": row["error_code"],
        "audit_id": row["audit_id"],
        "audit_access_token": row.get("audit_access_token"),
        "created_at": row["created_at"],
        "completed_at": row["completed_at"],
    }


@router.get("/v1/audits/{audit_id}/report")
async def get_audit_report(
    audit_id: str,
    token: str | None = None,
    audit_repo: AuditRepository = Depends(get_audit_repo),
) -> HTMLResponse:
    """The shareable artifact: the same persisted audit rendered as a
    self-contained, plain-language HTML page. Requires the audit's
    access_token (?token=...) -- same ownership check as GET /v1/audits/{id}."""
    set_log_context(audit_id=audit_id)
    row = await audit_repo.get_authorized(audit_id, token)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no audit with this id and token, or persistence "
                               "isn't configured on this deployment (see app/db.py)"},
        )
    # render_report expects a well-formed score dict; guard at the API
    # boundary so a partially-written/backfilled row (null or malformed
    # score_json) is a deliberate error, not an unhandled KeyError -> 500.
    score = row.get("score_json")
    if not isinstance(score, dict) or "total" not in score or "categories" not in score:
        raise HTTPException(
            status_code=422,
            detail={"reason": "report_unavailable",
                    "detail": "this audit has no complete score to render a "
                               "report from (score_json is missing or malformed)"},
        )
    result = {"score": score, "findings": row.get("findings_json") or []}
    # The stack has been detected and stored on the row since the audit was
    # written, and the report header has a slot for it -- but this dict never
    # carried it, so EVERY web-served report printed "stack: ?" while the
    # value sat one key away. Only the CLI path passed it, which is why it
    # went unnoticed: the reports read during development were the ones that
    # worked. Guarded on truthiness so a null column stays "?" rather than
    # rendering the string "None".
    if row.get("stack"):
        result["stack"] = row["stack"]
    html = render_report(result, project_name=f"audit {audit_id[:8]}")
    # Tight CSP scoped to this self-contained report page: it inlines a
    # <style> block (hence style-src 'unsafe-inline') but loads no scripts,
    # images, or any external asset, so everything else is denied. Scoped
    # here so it never touches /docs, /redoc, or JSON responses.
    csp = (
        "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
        "form-action 'none'; frame-ancestors 'none'"
    )
    return HTMLResponse(content=html, headers={"Content-Security-Policy": csp})


@router.get("/v1/audits/{audit_id}/fixpack-status")
async def get_fixpack_status(
    audit_id: str,
    audit_repo: AuditRepository = Depends(get_audit_repo),
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
) -> dict:
    """Lightweight poll target for the audit results page: the outcome of a
    Fix Pack purchase for this audit, without needing the job id up front.

    Returns the most recent Fix Pack job's status and pr_url. status is one
    of the fixpack_jobs states — 'paid' (bought, generating), 'delivered'
    (PR opened, pr_url set), 'no_fix_needed', or 'failed'. When no Fix Pack
    has been purchased yet (or persistence isn't configured), status is null
    so the frontend can poll a stable shape rather than treat "no job" as an
    error. 404 only when the audit itself doesn't exist.

    On 'failed', failure_kind says whose fault it was: 'infrastructure' when the
    job was reaped after never completing (a sandbox-runner outage or a crashed
    worker — nothing to do with the client's code), else null for a genuine
    generation failure. Derived from the detail the reaper writes, so it needs no
    schema change; null for every non-failed status.
    """
    set_log_context(audit_id=audit_id)
    audit = await audit_repo.get(audit_id)
    if audit is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "audit_not_found",
                    "detail": "no audit with this id, or persistence isn't "
                              "configured on this deployment (see app/db.py)"},
        )
    job = await fixpack_repo.get_by_audit(audit_id)
    if job is None:
        return {"audit_id": audit_id, "status": None, "pr_url": None,
                "failure_kind": None}
    status = job.get("status")
    detail = job.get("detail") or ""
    failure_kind = None
    if status == "failed" and detail.startswith(STALE_LEASE_DETAIL_PREFIX):
        failure_kind = "infrastructure"
    return {
        "audit_id": audit_id,
        "status": status,
        "pr_url": job.get("pr_url"),
        "failure_kind": failure_kind,
    }


@router.get("/v1/fixpacks/{job_id}")
async def get_fixpack(
    job_id: str,
    token: str | None = None,
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
) -> dict:
    # Ownership check: the job is readable only by presenting its per-row
    # access_token (?token=...), delivered once at creation. A leaked id is
    # not enough. A missing/wrong token is answered 404 (not 403) so this
    # never confirms an id exists to someone who doesn't hold its token --
    # same model as GET /v1/audits/{id} (migration 0012 mirrors 0010).
    set_log_context(job_id=job_id)
    row = await fixpack_repo.get_authorized(job_id, token)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no fixpack job with this id and token, or persistence "
                               "isn't configured on this deployment (see app/db.py)"},
        )
    return row
