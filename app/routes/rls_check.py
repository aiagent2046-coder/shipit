"""The one consented request the product makes against a customer's database.

Every other endpoint here reads a copy of the customer's code. This one asks a
live Supabase project, with the public key out of that same repository, whether
it hands out rows it should not. It is offered AFTER the static report, on
demand, because consent given while looking at the list of tables that will be
asked about is consent to something the customer can see.

CONSENT IS A TYPED PHRASE, NOT A BOOLEAN. `consent=true` is what a client
library sets by default, what a copied curl carries, and what a form submits
because a checkbox was already ticked. `i-own-this-project`, spelled exactly,
cannot be arrived at without having read what it means. The same rule already
guards scripts/probe_supabase_rls_live.py; this is it at the API edge.

WHAT THE RESPONSE MAY SAY. `checked` and `refused` are different answers and
neither is "your database is fine". Within a check, rows coming back is the
only thing reported as exposed: RLS filters rather than denies, so a protected
table and an empty one answer identically, and a request that failed settles
nothing at all. app/proof/rls_live_check.py keeps those apart and this layer
does not flatten them.
"""

from __future__ import annotations

import io
import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Request, UploadFile
from fastapi.concurrency import run_in_threadpool

from app.db import AuditRepository, RlsLiveCheckRepository
from app.ingest.validators import (
    MAX_ARCHIVE_BYTES,
    ArchiveValidationError,
    validate_zip,
)
from app.log_context import set_log_context
from app.proof.rls_live_check import (
    MAX_TABLES,
    LiveCheckResult,
    run_live_rls_check,
)
from app.ratelimit import RateLimitExceeded, RateLimiter
from app.routes._shared import _client_key, _parse_github_repo_url
from app.routes.dependencies import (
    get_audit_repo,
    get_rate_limiter,
    get_repo_fetcher,
    get_rls_fetch,
    get_rls_live_check_repo,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Spelled exactly. See the module docstring: the point is that it cannot be
# submitted by a default.
CONSENT_PHRASE = "i-own-this-project"


def _payload(result: LiveCheckResult) -> dict:
    """One shape, two endpoints.

    Both routes answer the same question and a caller should not be able to
    tell which one produced a result. Two hand-built dicts is how the counts
    added in one place quietly go missing from the other — the drift this
    project has paid for more than once.
    """
    return {
        "status": result.status,
        "reason": result.reason,
        "project_ref": result.project_ref,
        "key_source": result.key_source,
        "checked": result.checked,
        "not_checked": result.not_checked,
        "exposed_tables": result.exposed_tables,
        "inconclusive": result.inconclusive,
        # Reported beside the other two on purpose: 0 exposed and 0
        # inconclusive read as an all-clear, and over a run of empty answers
        # that is not what happened. See LiveCheckResult.empty_but_unproven.
        "empty_but_unproven": result.empty_but_unproven,
        "max_tables": MAX_TABLES,
        "attempts": [
            {"status": a.status, "detail": a.detail, "evidence": a.evidence}
            for a in result.attempts
        ],
    }


def _refusal(reason: str, *, persisted: bool) -> dict:
    """A refusal in the same shape as a result, so a caller parses one thing."""
    return {
        "persisted": persisted,
        "status": "refused",
        "reason": reason,
        "project_ref": "", "key_source": "", "checked": [], "not_checked": [],
        "exposed_tables": [], "inconclusive": 0, "empty_but_unproven": 0,
        "max_tables": MAX_TABLES, "attempts": [],
    }


@router.post("/v1/rls-check", status_code=200)
async def create_rls_check(
    archive: UploadFile,
    request: Request,
    consent: str = Form(
        ...,
        description=f'Must be exactly "{CONSENT_PHRASE}". This endpoint sends '
                    "requests to a live database; a boolean would be settable "
                    "by a client default, and this is not.",
    ),
    audit_id: str | None = Form(
        None, description="Link the check to a persisted audit, if you have one.",
    ),
    anon_key: str | None = Form(
        None,
        description="Your project's PUBLIC anon key, if the repository does "
                    "not commit it. Optional — we look in the repository "
                    "first. Never a service_role key: that one is refused.",
    ),
    limiter: RateLimiter = Depends(get_rate_limiter),
    check_repo: RlsLiveCheckRepository = Depends(get_rls_live_check_repo),
    rls_fetch=Depends(get_rls_fetch),
) -> dict:
    """Ask a customer's own Supabase project for rows it should not hand out.

    The project and the key are derived from the uploaded repository, never
    supplied by the caller — see app/proof/supabase_target.py for why the URL
    is built from the key's own `ref` claim rather than read out of the tree,
    and why a service_role key is refused rather than used.
    """
    if consent != CONSENT_PHRASE:
        # 422 rather than 403: nothing was denied, the request did not carry
        # the thing that makes it a request we may act on.
        raise HTTPException(
            status_code=422,
            detail={
                "reason": "consent_not_given",
                "detail": f'consent must be exactly "{CONSENT_PHRASE}"',
            },
        )

    try:
        limiter.check(_client_key(request))
    except RateLimitExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail={"reason": "rate_limited",
                    "detail": f"max {limiter.limit} per day"},
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc

    raw = await archive.read(MAX_ARCHIVE_BYTES + 1)
    try:
        validate_zip(io.BytesIO(raw), size_bytes=len(raw))
    except ArchiveValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail={"reason": exc.reason, "detail": exc.detail},
        ) from exc

    # Written BEFORE the requests go out. A ledger that only records completed
    # checks cannot show the one that crashed halfway, which is the case
    # somebody would actually ask about.
    ledger_row = await check_repo.start(
        audit_id=audit_id,
        client_key=_client_key(request),
        consent_phrase=consent,
    )
    if audit_id:
        set_log_context(audit_id=audit_id)
    if ledger_row:
        # The check id belongs to this call, not to the surrounding context —
        # `extra=` rather than set_log_context, which is what the allowlist in
        # app/log_context.py is drawing the line about.
        logger.info("live RLS check started",
                    extra={"step": "rls_check_start",
                           "rls_check_id": str(ledger_row["id"])})

    # run_in_threadpool because the check is up to MAX_TABLES sequential
    # HTTPS requests. Called directly it would block the event loop for
    # seconds, and every other request to this process with it.
    result = await run_in_threadpool(
        run_live_rls_check, raw, consent=True, anon_key=anon_key,
        fetch=rls_fetch)

    payload = _payload(result)

    if ledger_row:
        await check_repo.complete(
            str(ledger_row["id"]),
            project_ref=result.project_ref,
            outcome=result.status,
            tables_asked=result.checked,
            result=payload,
        )

    return {"persisted": ledger_row is not None, **payload}


@router.post("/v1/audits/{audit_id}/rls-check", status_code=200)
async def create_rls_check_for_audit(
    audit_id: str,
    request: Request,
    token: str | None = Form(None),
    consent: str = Form(...),
    anon_key: str | None = Form(None),
    limiter: RateLimiter = Depends(get_rate_limiter),
    audit_repo: AuditRepository = Depends(get_audit_repo),
    check_repo: RlsLiveCheckRepository = Depends(get_rls_live_check_repo),
    repo_fetcher=Depends(get_repo_fetcher),
    rls_fetch=Depends(get_rls_fetch),
) -> dict:
    """The same check, reachable from a report the customer is already looking at.

    THE ARCHIVE IS NOT RE-UPLOADED. `POST /v1/rls-check` takes one because it
    has to work standalone, but a browser rendering a finished report does not
    have the customer's repository and asking for it again is a bad trade for a
    button. The Fix Pack solved this first: the audit row stores `repo_url` and
    the server re-fetches. This does the same, which also means the repository
    read is the one WE fetch rather than one a caller assembled.

    Ownership is the audit's per-row access token, and a missing or wrong one
    is answered 404 rather than 403 — the same rule as GET /v1/audits/{id}, so
    this never confirms an id exists to somebody who does not hold its token.
    """
    if consent != CONSENT_PHRASE:
        raise HTTPException(
            status_code=422,
            detail={"reason": "consent_not_given",
                    "detail": f'consent must be exactly "{CONSENT_PHRASE}"'},
        )

    set_log_context(audit_id=audit_id)
    audit = await audit_repo.get_authorized(audit_id, token)
    if audit is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no audit with this id and token, or persistence "
                              "isn't configured on this deployment"},
        )

    try:
        limiter.check(_client_key(request))
    except RateLimitExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail={"reason": "rate_limited",
                    "detail": f"max {limiter.limit} per day"},
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc

    # An audit created from a zip upload has no URL to re-fetch. That is a
    # REFUSAL with a reason, not an error: the customer can still use
    # POST /v1/rls-check with the archive, and saying so is more useful than a
    # 400 that reads like something broke.
    parsed = _parse_github_repo_url(audit.get("repo_url") or "")
    if parsed is None:
        return _refusal(
            "this audit was created from an uploaded archive, so there is no "
            "repository for us to re-read. Use POST /v1/rls-check with the "
            "archive instead",
            persisted=False)

    ledger_row = await check_repo.start(
        audit_id=audit_id,
        client_key=_client_key(request),
        consent_phrase=consent,
    )

    owner, repo = parsed
    try:
        raw = await run_in_threadpool(repo_fetcher, owner, repo)
    except Exception as exc:  # noqa: BLE001 — the fetch is infrastructure
        logger.warning("live RLS check could not re-fetch %s/%s: %s",
                       owner, repo, type(exc).__name__,
                       extra={"step": "rls_check_refetch"})
        payload = _refusal(
            f"we could not re-read {owner}/{repo} to work out which tables to "
            f"ask about",
            persisted=ledger_row is not None)
        if ledger_row:
            # Closed even though nothing was sent. A ledger row left open
            # means "a check was started and we do not know what happened",
            # which is a different and more alarming thing than this.
            await check_repo.complete(
                str(ledger_row["id"]), project_ref="", outcome="refused",
                tables_asked=[], result=payload)
        return payload

    result = await run_in_threadpool(
        run_live_rls_check, raw, consent=True, anon_key=anon_key,
        fetch=rls_fetch)
    payload = _payload(result)

    if ledger_row:
        await check_repo.complete(
            str(ledger_row["id"]),
            project_ref=result.project_ref,
            outcome=result.status,
            tables_asked=result.checked,
            result=payload,
        )
    return {"persisted": ledger_row is not None, **payload}
