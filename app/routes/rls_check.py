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

from app.db import RlsLiveCheckRepository
from app.ingest.validators import (
    MAX_ARCHIVE_BYTES,
    ArchiveValidationError,
    validate_zip,
)
from app.log_context import set_log_context
from app.proof.rls_live_check import MAX_TABLES, run_live_rls_check
from app.ratelimit import RateLimitExceeded, RateLimiter
from app.routes._shared import _client_key
from app.routes.dependencies import (
    get_rate_limiter,
    get_rls_fetch,
    get_rls_live_check_repo,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Spelled exactly. See the module docstring: the point is that it cannot be
# submitted by a default.
CONSENT_PHRASE = "i-own-this-project"


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
        run_live_rls_check, raw, consent=True, fetch=rls_fetch)

    payload = {
        "status": result.status,
        "reason": result.reason,
        "project_ref": result.project_ref,
        "checked": result.checked,
        "not_checked": result.not_checked,
        "exposed_tables": result.exposed_tables,
        "inconclusive": result.inconclusive,
        "max_tables": MAX_TABLES,
        "attempts": [
            {"status": a.status, "detail": a.detail, "evidence": a.evidence}
            for a in result.attempts
        ],
    }

    if ledger_row:
        await check_repo.complete(
            str(ledger_row["id"]),
            project_ref=result.project_ref,
            outcome=result.status,
            tables_asked=result.checked,
            result=payload,
        )

    return {"persisted": ledger_row is not None, **payload}
