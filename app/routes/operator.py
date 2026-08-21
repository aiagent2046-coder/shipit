"""Operator-only endpoints: preview reaping, queue stats, and refunds.

Extracted from app/main.py verbatim -- handler bodies are unchanged, only the
decorators moved from ``@app.<verb>`` to ``@router.<verb>``.

Every endpoint here is gated by a bearer token read from the environment, and
each returns 503 rather than 200 when its token is unset, so an unconfigured
deployment fails loudly instead of exposing an operator surface anonymously.

Note the module name: these are the *operator* endpoints that still lived in
main.py. app/ops_endpoints.py is a separate, older module with its own router;
the two are not related and neither supersedes the other.
"""

from __future__ import annotations

import logging
import os
import uuid
from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from app.db import (
    AuditJobRepository,
    FixOutcomeRepository,
    FixpackJobRepository,
    LlmUsageRepository,
    PaymentRepository,
)
from app.deploypack.preview import PreviewRegistry
from app.fixpack.merit import UNDETERMINED, Reason, Verdict, assess
from app.notify import messages
from app.routes._shared import (
    _json_object_body,
    _require_bearer_token,
    _service_flags_token,
)
from app.routes.dependencies import (
    get_audit_job_repo,
    get_billing_transport,
    get_fix_outcome_repo,
    get_fixpack_repo,
    get_llm_usage_repo,
    get_payment_repo,
    get_preview_reconciler,
    get_preview_registry,
)

logger = logging.getLogger(__name__)

router = APIRouter()


def _reap_token() -> str | None:
    """Same env-var pattern as GITHUB_PR_TOKEN in delivery.py. Unset by
    default — the endpoint below refuses to run rather than accept an
    empty/no-op auth check."""
    return os.environ.get("PREVIEW_REAP_TOKEN") or None


@router.post("/internal/preview/reap")
async def reap_previews(
    request: Request,
    preview_registry: PreviewRegistry = Depends(get_preview_registry),
    reconciler=Depends(get_preview_reconciler),
) -> dict:
    """Operational endpoint for the scheduled reaper — called hourly by
    shipit-reap.timer on the production VPS (a former GitHub Actions
    workflow doing the same thing was removed 2026-07-14: it never had
    its repo secrets configured and was redundant once the VPS timer
    existed). Not part of the public API surface; there's no
    user-facing reason to call this directly.

    Requires `Authorization: Bearer <PREVIEW_REAP_TOKEN>`. Returns 503
    if the token isn't configured on this deployment at all, rather
    than silently doing nothing — an unconfigured reaper is an
    operational gap someone needs to notice, not a quiet no-op.
    """
    token = _reap_token()
    if not token:
        raise HTTPException(
            status_code=503,
            detail={"reason": "reap_not_configured",
                    "detail": "PREVIEW_REAP_TOKEN is not set on this deployment"},
        )
    # Constant-time compare so response latency doesn't leak the token.
    _require_bearer_token(request, token)

    reaped = await run_in_threadpool(preview_registry.reap_expired)
    # In-memory reap only knows this process's containers; after a restart the
    # registry is empty while real preview containers may still be running.
    # reconcile_previews asks Docker directly and ages out orphans by their
    # shipit.expires_at label, regardless of what this process remembers.
    reconciled = await run_in_threadpool(reconciler)
    return {
        "reaped": reaped,
        "active": preview_registry.active_count(),
        "reconciled": reconciled,
    }


def _audit_jobs_stats_token() -> str | None:
    """Bearer token protecting GET /internal/audit-jobs/stats, same env-var
    pattern as the other internal endpoints.

    Its own token rather than a reused one on purpose: the existing tokens
    authorise ACTIONS (drain a backlog, flip the kill switch), and the thing
    that wants queue depth is a monitoring scraper -- something that should be
    able to read without holding a credential that can also start work. Unset
    -> the endpoint 503s rather than accept a no-op auth check."""
    return os.environ.get("AUDIT_JOBS_STATS_TOKEN") or None


@router.get("/internal/audit-jobs/stats")
async def audit_jobs_stats(
    request: Request,
    audit_job_repo: AuditJobRepository = Depends(get_audit_job_repo),
) -> dict:
    """Operational read: how deep the audit queue is, broken down by state.

    /readyz carries the two numbers a health check needs; this is the view for
    a human or a scraper diagnosing WHY, which needs the whole state histogram.
    `dead_letter` is the one to watch -- the worker alerts on each new one, and
    a rising total here is what confirms a pattern rather than a one-off.

    Requires `Authorization: Bearer <AUDIT_JOBS_STATS_TOKEN>`, constant-time
    compared. 503 if the token isn't configured, and 503 if DATABASE_URL isn't
    set, because zeros from a queue you cannot see are worse than an error.

    Superseded by GET /internal/stats, which reports this queue alongside the
    others from the same backlog_stats() call. Kept, unchanged: this path and
    its response shape are already deployed and hand-curled, and there is no
    logic here that can drift from the new endpoint -- both are projections of
    one repository read."""
    token = _audit_jobs_stats_token()
    if not token:
        raise HTTPException(
            status_code=503,
            detail={"reason": "audit_jobs_stats_not_configured",
                    "detail": "AUDIT_JOBS_STATS_TOKEN is not set on this "
                              "deployment"},
        )
    _require_bearer_token(request, token)

    stats = await audit_job_repo.backlog_stats()
    if stats is None:
        raise HTTPException(
            status_code=503,
            detail={"reason": "not_configured",
                    "detail": "persistence isn't configured on this deployment "
                              "(see app/db.py)"},
        )
    return {
        "states": stats["states"],
        "queued": stats["queued"],
        "oldest_queued_seconds": stats["oldest_queued_seconds"],
        "dead_letter": stats["states"].get("dead_letter", 0),
    }


STATS_RECENT_WINDOW_SECONDS = 3600


STATS_DAY_WINDOW_SECONDS = 24 * 3600


# When a rule has enough evidence to learn from.
#
# 20 labelled outcomes and 5 distinct audits, per rule. The second number is
# the load-bearing one: twenty merges from one customer's repository say that
# this fix suits that repository, and generalising from it is how a knowledge
# base learns something false with confidence. Five audits is not a large
# sample either, but it is the point past which a signal is at least not one
# codebase's opinion.
#
# These are a stated position, not a derived one -- there is no dataset to
# derive them from yet, which is rather the point. They live here so the
# question "is there enough data?" is answered by a query instead of by
# whoever is asked.
LEARNING_MIN_LABELLED = 20


LEARNING_MIN_AUDITS = 5


@router.get("/internal/stats")
async def internal_stats(
    request: Request,
    audit_job_repo: AuditJobRepository = Depends(get_audit_job_repo),
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
    llm_usage_repo: LlmUsageRepository = Depends(get_llm_usage_repo),
    fix_outcome_repo: FixOutcomeRepository = Depends(get_fix_outcome_repo),
) -> dict:
    """Every queue and the LLM bill, aggregated, in one authenticated read.

    The deployment is a single VPS whose spare memory is already contended for
    by the Fix Pack sandbox containers, so there is no Prometheus and no
    metrics process: the aggregates are computed on demand from the tables that
    already hold the facts (audit_jobs, fixpack_jobs, llm_usage), and this is
    what a scraper or a human polls. Counts and percentiles only, never rows,
    so the response size does not grow with the size of the queues.

    Same auth as /internal/audit-jobs/stats and deliberately the same token:
    AUDIT_JOBS_STATS_TOKEN exists so a monitoring reader can see queue depth
    without holding a credential that can also start work, which is exactly
    this endpoint's audience. A second token for the same reader would be two
    secrets to rotate for one job.

    Every number comes from a repository method, several of which /readyz and
    /internal/audit-jobs/stats already call, so "backlog" and "oldest queued"
    have one definition in the codebase rather than one per reader.

    503 rather than zeros when the token or the database is missing: a stats
    endpoint answering 200 with empty counters while it cannot see the queue is
    worse than one that fails, because a dashboard cannot tell the difference
    and a silent zero reads as healthy."""
    token = _audit_jobs_stats_token()
    if not token:
        raise HTTPException(
            status_code=503,
            detail={"reason": "audit_jobs_stats_not_configured",
                    "detail": "AUDIT_JOBS_STATS_TOKEN is not set on this "
                              "deployment"},
        )
    _require_bearer_token(request, token)

    audit_backlog = await audit_job_repo.backlog_stats()
    if audit_backlog is None:
        raise HTTPException(
            status_code=503,
            detail={"reason": "not_configured",
                    "detail": "persistence isn't configured on this deployment "
                              "(see app/db.py)"},
        )
    # Past this point the pool is known to exist, so the remaining reads
    # cannot return the not-configured None.
    audit_recent = await audit_job_repo.recent_outcomes(
        window_seconds=STATS_RECENT_WINDOW_SECONDS)
    fixpack_backlog = await fixpack_repo.backlog_stats()
    fixpack_statuses = await fixpack_repo.status_counts()
    spend_hour = await llm_usage_repo.spend_since(
        window_seconds=STATS_RECENT_WINDOW_SECONDS)
    spend_day = await llm_usage_repo.spend_since(
        window_seconds=STATS_DAY_WINDOW_SECONDS)
    learning = await fix_outcome_repo.learning_readiness(
        min_labelled=LEARNING_MIN_LABELLED,
        min_audits=LEARNING_MIN_AUDITS,
    )

    return {
        "window_seconds": STATS_RECENT_WINDOW_SECONDS,
        "audit_jobs": {
            "states": audit_backlog["states"],
            "queued": audit_backlog["queued"],
            "oldest_queued_seconds": audit_backlog["oldest_queued_seconds"],
            "recent": audit_recent,
        },
        "fixpack_jobs": {
            "statuses": fixpack_statuses,
            "paid_backlog": fixpack_backlog["backlog"],
            "oldest_paid_seconds": fixpack_backlog["oldest_paid_seconds"],
        },
        "llm_usage": {
            "last_hour": _spend_view(spend_hour),
            "last_24h": _spend_view(spend_day),
        },
        # audit_jobs only, and named so rather than presented as a service-wide
        # figure it is not: fixpack_jobs stamps no timestamp on a terminal
        # transition, so "failed in the last hour" is not computable for that
        # queue without a schema change, and quietly folding in its lifetime
        # totals would make the ratio mean nothing.
        "errors": {
            "source": "audit_jobs",
            "window_seconds": STATS_RECENT_WINDOW_SECONDS,
            "terminal_total": audit_recent["terminal_total"],
            "failed": audit_recent["failed"],
            "error_rate": audit_recent["error_rate"],
            "top_error_codes": audit_recent["top_error_codes"],
        },
        # Lifetime, not windowed like everything above it: the question this
        # answers is "has enough evidence accumulated to learn from", and an
        # hour of it is not evidence.
        "learning": learning,
    }


def _spend_view(spend: dict) -> dict:
    """One llm_usage window as JSON. cost_usd is quantized to the column's own
    numeric(12,6) scale and then floated -- the repository hands back a Decimal
    so nothing rounds before it must, and this is where it must, because JSON
    has no decimal type."""
    return {
        "calls": spend["calls"],
        "cost_usd": float(spend["cost_usd"].quantize(Decimal("0.000001"))),
    }





@router.get("/internal/payments/{payment_id}/fixpack-merit")
async def fixpack_merit(
    payment_id: str,
    request: Request,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
    outcome_repo: FixOutcomeRepository = Depends(get_fix_outcome_repo),
) -> dict:
    """Did the Fix Pack this payment bought do what it was sold as?

    Requires `Authorization: Bearer <SERVICE_FLAGS_TOKEN>`, the same operator
    credential the refund endpoint takes -- this reads a customer's purchase
    history and belongs to the same audience.

    READ THIS BEFORE USING THE ANSWER. It is not a "was the customer right to
    complain" check, and app/fixpack/merit.py explains at length why that
    distinction is the whole design. `owed` means OUR OWN RECORDS show the Fix
    Pack did not deliver what it was sold as -- refund without argument.
    `undetermined` is the common answer and stays a real one. Nothing here can
    deny a refund; the mechanism exists to find the cases where we are at
    fault, not to catch a customer lying.

    Deliberately GET and deliberately side-effect free. The verdict is
    something to consult BEFORE deciding, so it must be safe to ask twice, and
    asking must not record anything about a refund that has not happened.

    404 when there is no such payment.
    """
    token = _service_flags_token()
    if not token:
        raise HTTPException(
            status_code=503,
            detail={"reason": "not_configured",
                    "detail": "SERVICE_FLAGS_TOKEN is not set on this deployment"},
        )
    _require_bearer_token(request, token)

    try:
        uuid.UUID(payment_id)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail={"reason": "bad_request", "detail": "payment_id must be a UUID"},
        )

    payment = await payment_repo.get(payment_id)
    if payment is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found", "detail": "no payment with that id"},
        )

    verdict = await assess_payment(
        payment, fixpack_repo=fixpack_repo, outcome_repo=outcome_repo)
    return {
        "payment_id": str(payment["id"]),
        "audit_id": payment.get("audit_id"),
        "status": payment.get("status"),
        "refunded_at": payment.get("refunded_at"),
        **verdict.as_dict(),
    }


@router.post("/internal/payments/{payment_id}/refund")
async def refund_payment(
    payment_id: str,
    request: Request,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
    outcome_repo: FixOutcomeRepository = Depends(get_fix_outcome_repo),
    # The same outbound seam the bot uses. Named for billing because that is
    # where it started; what it is, is "the transport the tests replace", and
    # telling a customer about their refund needs exactly that.
    transport=Depends(get_billing_transport),
) -> dict:
    """Record that a completed payment was given back.

    Body: JSON {"reason": str}. Requires `Authorization: Bearer
    <SERVICE_FLAGS_TOKEN>`.

    This endpoint moves no money, and no endpoint here could. A bank transfer
    lands on a private individual's account and goes back the same way, by
    hand. That was true of the rails that have since been removed too, and it
    will be true of Robokassa until this deployment holds a credential that can
    ask for a refund. The operator sends the money and then tells the system,
    in that order.

    So the value is the record. Until now a refunded payment stayed
    `completed` for ever, and a month later nothing distinguished money kept
    from money returned -- an error that is always in the flattering
    direction. It became concrete on 2026-08-01, when DRY-UPRQKH charged 10.79
    for a Fix Pack on an audit with nothing a Fix Pack could fix. The customer
    was the operator testing his own product; the next one will not be.

    SERVICE_FLAGS_TOKEN rather than a token of its own. It is already the
    operator-privileged credential -- it can halt every paid LLM operation --
    and this is the same audience. AUDIT_JOBS_STATS_TOKEN would be wrong for
    the reason its own docstring gives: it exists so a monitoring reader can
    see queue depth WITHOUT holding a credential that can also act.

    404 when the payment does not exist OR is not `completed`: an invoice
    nobody paid has no refund to record, and the two cases are deliberately
    not distinguished to an unauthenticated-by-id caller. Repeating the call
    is a no-op for the same reason -- one refund must not become two entries
    because a command was run twice.

    Deliberately does NOT revoke anything. A Fix Pack PR that was delivered
    stays delivered; Pro access stays granted. Whether a refund should take
    back what it paid for is a policy question with a different cost of being
    wrong, and mixing it into the record-keeping would mean neither could be
    changed alone.

    IT DOES TELL THE CUSTOMER, on every channel they gave (app/notify/router.py).
    The money went back by hand, days after they asked, and until now nothing
    said so: they were left refreshing a bank statement, and the natural next
    move for somebody who paid, complained and heard nothing is a chargeback.

    The send is after the record and cannot undo it. A refund that failed to be
    announced is still a refund; a refund that 500s because the mail server was
    down would be recorded nowhere and sent again. When NOTHING reaches them,
    the router pages the operator -- the customer still has to be told, and only
    a person can find another way.
    """
    token = _service_flags_token()
    if not token:
        raise HTTPException(
            status_code=503,
            detail={"reason": "not_configured",
                    "detail": "SERVICE_FLAGS_TOKEN is not set on this deployment"},
        )
    _require_bearer_token(request, token)

    body = await _json_object_body(request)
    reason = body.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise HTTPException(
            status_code=422,
            detail={"reason": "bad_request",
                    "detail": "body must be JSON with a non-empty 'reason'"},
        )

    try:
        uuid.UUID(payment_id)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail={"reason": "bad_request", "detail": "payment_id must be a UUID"},
        )

    payment = await payment_repo.mark_refunded(payment_id, reason=reason.strip())
    if payment is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_refundable",
                    "detail": "no completed payment with that id"},
        )

    delivery = await _tell_them_about_the_refund(payment, transport=transport)
    # Wrapped HERE and deliberately not in the GET next door. The record of the
    # refund is this endpoint's whole product, and it is already written by the
    # time we get here; letting an unreachable analytics table raise would turn
    # a completed refund into a 500 that gets retried. The GET is the opposite
    # case -- the operator asked for the verdict and nothing else, so a failure
    # there must surface rather than answer "undetermined" and be believed.
    try:
        verdict = await assess_payment(
            payment, fixpack_repo=fixpack_repo, outcome_repo=outcome_repo)
    except Exception:  # noqa: BLE001
        logger.warning("could not assess the Fix Pack behind a refund",
                       exc_info=True)
        verdict = Verdict(UNDETERMINED, (Reason(
            "assessment_unavailable",
            "The Fix Pack records could not be read while recording this "
            "refund. The refund itself is recorded; ask again on the "
            "fixpack-merit endpoint.",
        ),))
    return {
        **payment,
        "notified": list(delivery.delivered),
        "fixpack_merit": verdict.as_dict(),
    }


async def assess_payment(
    payment: dict, *, fixpack_repo, outcome_repo,
) -> Verdict:
    """What our own records say about the Fix Pack this payment bought.

    Returns UNDETERMINED with a reason for anything that is not a Fix Pack
    purchase, rather than inventing a verdict about a Pro subscription. The
    caller renders `reasons` next to the number, the same way the score does:
    a conclusion with nothing attached is an authority nobody can check.
    """
    if (payment.get("product") or "") != "fixpack":
        return Verdict(UNDETERMINED, (Reason(
            "not_a_fixpack",
            "This payment did not buy a Fix Pack, so there is no generated "
            "work to judge.",
        ),))

    audit_id = payment.get("audit_id")
    if not audit_id:
        return Verdict(UNDETERMINED, (Reason(
            "no_audit",
            "This Fix Pack payment carries no audit id, so the job it paid "
            "for cannot be found.",
        ),))

    job = await fixpack_repo.get_by_audit(str(audit_id))
    outcome = None
    if job is not None:
        outcome = await outcome_repo.get_by_job(str(job["id"]))
    return assess(job=job, outcome=outcome)


def _refund_body(payment: dict) -> str:
    """What the customer reads.

    The REASON is not repeated back to them, in any language. It is the
    operator's note for the books -- "customer says the Fix Pack was wrong",
    "duplicate charge" -- written to be true rather than to be read by the
    person it is about. What they need is the amount, the order, and that it
    is on its way.

    The words live in app/notify/messages.py, in the language recorded on the
    payment (migration 0033). NULL reads as English, which is every row made
    before that column existed.
    """
    return messages.refund_body(
        amount=payment.get("amount"),
        currency=payment.get("currency"),
        reference=str(payment.get("external_ref") or ""),
        locale=payment.get("payer_locale"),
    )


async def _tell_them_about_the_refund(payment: dict, *, transport=None):
    """Best-effort, and wrapped. The refund is already recorded; an exception
    escaping here would report it as a failure and invite a second one."""
    from app.notify.router import Contact, Delivery, notify_customer

    try:
        return await notify_customer(
            contact=Contact.from_payment(payment),
            subject=messages.refund_subject(
                locale=payment.get("payer_locale")),
            body=_refund_body(payment),
            reference=str(payment.get("external_ref") or ""),
            transport=transport,
        )
    except Exception:  # noqa: BLE001
        logger.warning("could not tell a customer about their refund",
                       exc_info=True)
        return Delivery()
