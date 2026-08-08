"""Bank-transfer invoices: opening them, and marking one paid.

Moved out of app/main.py; handler bodies are unchanged apart from the
decorators, which went from ``@app.post`` to ``@router.post``.

This module owns the two rate-limit constants it reads. They deliberately live
next to the code that uses them rather than staying in main.py: a constant read
through one module and patched on another is the ``MONITORING_FOR_SALE`` trap
this split keeps running into -- the patch lands on a name nothing reads, the
limit never changes, and the test passes while proving nothing. The three tests
that patch them were repointed at this module in the same commit.

``_check_invoice_rate_limit`` is shared by the two invoice creators on ONE
limiter key on purpose: they draw reference-code suffixes from the same pool,
so a per-endpoint budget would let one client take twice as much of it.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from app.billing import bank_transfer, telegram_stars
from app.db import (
    AuditRepository,
    FixpackJobRepository,
    PaymentRepository,
    ServiceFlagsRepository,
)
from app.ratelimit import RateLimitExceeded, RateLimiter
from app.routes._shared import (
    _client_key,
    _reject_if_fixpack_already_live,
    _reject_if_nothing_to_fix,
)
from app.routes.dependencies import (
    get_audit_repo,
    get_billing_transport,
    get_fixpack_repo,
    get_payment_repo,
    get_rate_limiter,
    get_service_flags_repo,
)
from app.service_flags import _emergency_stop_active

router = APIRouter()

# Distinct "I've paid" presses, per client key, per limiter window (24h).
# This bounds a flood of DIFFERENT invoices from one source; repeat presses of
# ONE invoice are already collapsed by notify_operator's dedupe_key. Well above
# what any real payer needs -- a payer opens one invoice, maybe two.
BANK_TRANSFER_PAID_LIMIT = 10

# Invoices opened per client key per limiter window (24h).
#
# Unauthenticated by necessity -- a buyer has no key until they have paid --
# which until now meant unbounded. Each invoice permanently consumed one of the
# 99 kopeck suffixes, so a hundred anonymous POSTs switched the operator's
# whole matching mechanism off. The TTL window in bank_transfer fixed the
# permanence; this bounds how fast one source can fill the window.
#
# Well above any real checkout: a buyer opens one invoice, changes their mind
# about Pro versus a Fix Pack, maybe reloads a stale page. Fifteen is generous
# for that and still a hundredth of what saturation needs.
BANK_TRANSFER_INVOICE_LIMIT = 15


def _check_invoice_rate_limit(request: Request, limiter: RateLimiter) -> None:
    """429 when one client has opened too many invoices today.

    Shared by the Pro and Fix Pack creators on ONE limiter key on purpose:
    they draw suffixes from the same pool, so a per-endpoint budget would let
    the same client take twice as much of it.
    """
    try:
        limiter.check(
            f"bank-transfer-invoice:{_client_key(request)}",
            limit=BANK_TRANSFER_INVOICE_LIMIT,
        )
    except RateLimitExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail={
                "reason": "rate_limited",
                "detail": f"max {BANK_TRANSFER_INVOICE_LIMIT} bank transfer "
                          "invoices per day",
            },
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc

def _bank_transfer_details() -> dict[str, str]:
    """The configured payer-facing bank fields, or 503.

    All six or nothing (see bank_transfer.bank_details_from_env): a payer
    handed a SWIFT code with no account number cannot send anything, so a
    half-configured deployment must refuse rather than render an invoice that
    can't be paid."""
    details = bank_transfer.bank_details_from_env()
    if details is None:
        raise HTTPException(
            status_code=503,
            detail={"reason": "bank_transfer_not_configured",
                    "detail": "bank transfer is not configured on this "
                              "deployment (BANK_TRANSFER_CARD, "
                              "BANK_TRANSFER_BANK_NAME, "
                              "BANK_TRANSFER_SWIFT, BANK_TRANSFER_BENEFICIARY, "
                              "BANK_TRANSFER_ACCOUNT and BANK_TRANSFER_ADDRESS "
                              "must all be set)"},
        )
    return details

class PayerContact(BaseModel):
    """Who is sending the transfer. Since payment moved to a card number this
    is not bookkeeping colour, it is the MATCHING KEY: a card-to-card transfer
    carries no reference field, so the sender's name on the operator's
    statement is the only handle on the payment, with the email as tie-breaker
    between two payers of the same name. Hence both fields are now required
    and so is the request body.

    max_length is abuse protection, not validation -- it stops someone posting a
    megabyte into a text column. The email check is deliberately the weakest
    thing that still rejects an obvious non-address: nothing is ever sent here,
    so a work address with an unusual TLD must not cost a sale. See migration
    0026.
    """

    payer_name: str = Field(min_length=1, max_length=200)
    payer_email: str = Field(min_length=3, max_length=200)

    @field_validator("payer_name", "payer_email")
    @classmethod
    def _stripped_and_present(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must not be blank")
        return v

    @field_validator("payer_email")
    @classmethod
    def _looks_like_an_address(cls, v: str) -> str:
        if "@" not in v:
            raise ValueError("must contain @")
        return v

def _bank_transfer_not_persisted_error() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail={"reason": "not_persisted",
                "detail": "bank transfer invoices require DATABASE_URL (a "
                          "pending payment row carries the reference code the "
                          "operator matches against the bank statement)"},
    )

@router.post("/v1/billing/bank-transfer/pro", status_code=201)
async def create_bank_transfer_invoice(
    payer: PayerContact,
    request: Request,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    limiter: RateLimiter = Depends(get_rate_limiter),
    service_flags_repo: ServiceFlagsRepository = Depends(get_service_flags_repo),
) -> dict:
    """Open a bank-transfer invoice for the Pro tier.

    Returns the card number to pay, the amount, and the reference code that
    identifies this order. Many banks carry that reference in the transfer's
    comment field and some do not, so the payer's name and email stay required
    (422 without them, see PayerContact) as the fallback the operator matches
    on. Poll GET /v1/billing/bank-transfer/{reference} to collect the key once
    the operator confirms the money arrived.

    Rate limited because it is unauthenticated and writes a row per call.

    Gated by the same emergency stop as the Fix Pack creator: a stop that left
    either invoice creator open would not stop sales.

    503 if bank transfer isn't configured, if the service is paused, or if the
    pending row can't be persisted (no DATABASE_URL / no free reference code)."""
    paused, note = await _emergency_stop_active(service_flags_repo)
    if paused:
        raise HTTPException(
            status_code=503,
            detail={"reason": "service_paused", "detail": note},
        )
    _check_invoice_rate_limit(request, limiter)
    details = _bank_transfer_details()
    invoice = await bank_transfer.create_invoice(
        payment_repo, details=details,
        payer_name=payer.payer_name,
        payer_email=payer.payer_email,
    )
    if invoice is None:
        raise _bank_transfer_not_persisted_error()
    return invoice


@router.post("/v1/audits/{audit_id}/fixpack/bank-transfer", status_code=201)
async def create_fixpack_bank_transfer_invoice(
    audit_id: str,
    payer: PayerContact,
    request: Request,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo),
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
    limiter: RateLimiter = Depends(get_rate_limiter),
    service_flags_repo: ServiceFlagsRepository = Depends(get_service_flags_repo),
) -> dict:
    """Open a bank-transfer invoice to buy a Fix Pack for one audit. Same
    reference-code flow and same polling endpoint as the Pro invoice above, at
    the Fix Pack price and scoped to this audit.

    Same GitHub-URL-only gate as the USDT and PayPal Fix Pack routes: a zip
    audit has no repository to open a fix PR against, so 422 rather than sell
    something that can't be fulfilled. 404 if no such audit.

    Rate limited on the same key as the Pro creator, which is also why both are
    gated by the same emergency stop: this is the only live payment rail, so a
    stop that did not close it would not stop sales."""
    # Emergency stop closes the checkout, not just the work. Checked before the
    # rate limiter so a paused service neither spends nor consumes the caller's
    # quota, exactly as create_audit does it. Until this existed the stop paused
    # the Fix Pack worker while leaving the invoice creator open, so engaging it
    # mid-incident would have kept taking money for work that could not run.
    paused, note = await _emergency_stop_active(service_flags_repo)
    if paused:
        raise HTTPException(
            status_code=503,
            detail={"reason": "service_paused", "detail": note},
        )
    _check_invoice_rate_limit(request, limiter)
    audit = await audit_repo.get(audit_id)
    if audit is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "audit_not_found",
                    "detail": "no audit with this id, or persistence isn't "
                              "configured on this deployment (see app/db.py)"},
        )
    if not audit.get("repo_url"):
        raise HTTPException(
            status_code=422,
            detail={"reason": "not_github_audit",
                    "detail": "Fix Pack currently only supports audits run "
                              "from a public GitHub URL. This audit was created "
                              "from an uploaded zip, so there's no repository to "
                              "open a fix PR against — re-run the audit with your "
                              "GitHub repo URL, then buy a Fix Pack for it."},
        )
    await _reject_if_fixpack_already_live(fixpack_repo, audit_id)
    _reject_if_nothing_to_fix(audit)
    details = _bank_transfer_details()
    invoice = await bank_transfer.create_fixpack_invoice(
        payment_repo, details=details, audit_id=audit_id,
        payer_name=payer.payer_name,
        payer_email=payer.payer_email,
    )
    if invoice is None:
        raise _bank_transfer_not_persisted_error()
    return invoice





@router.post("/v1/billing/bank-transfer/{reference}/paid")
async def report_bank_transfer_paid(
    reference: str,
    request: Request,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    limiter: RateLimiter = Depends(get_rate_limiter),
    transport=Depends(get_billing_transport),
) -> dict:
    """The payer pressed "I've paid": notify the operator, grant nothing.

    This writes no state — the row stays 'pending' until a human has seen the
    money on the statement and pressed the Confirm button carried by the
    notification. Pressing this without paying achieves exactly nothing.

    Rate limited because it is unauthenticated and its whole job is to push a
    message to the operator's phone. The per-invoice repeat is already
    collapsed by notify_operator's dedupe window; this bounds how many
    DISTINCT invoices one client can page the operator about. 404 if there's
    no such invoice."""
    try:
        limiter.check(
            f"bank-transfer-paid:{_client_key(request)}",
            limit=BANK_TRANSFER_PAID_LIMIT,
        )
    except RateLimitExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail={
                "reason": "rate_limited",
                "detail": f"max {BANK_TRANSFER_PAID_LIMIT} bank transfer "
                          "notifications per day",
            },
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc

    result = await bank_transfer.mark_awaiting_confirmation(
        payment_repo, reference,
        transport=transport, site_url=telegram_stars.SITE_URL,
    )
    if result is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no bank transfer invoice with this reference, or "
                              "persistence isn't configured on this deployment"},
        )
    return result
