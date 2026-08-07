"""USDT invoices and bank-transfer invoice lookup.

Extracted from app/main.py verbatim -- handler bodies are unchanged, only the
decorators moved from ``@app.<verb>`` to ``@router.<verb>``.

Only the endpoints whose rate limiting is not driven by a module-level limit
constant live here. ``create_usdt_invoice``, the bank-transfer invoice
creators, and the paid-report endpoint are still in main.py: they read
``USDT_INVOICE_LIMIT`` / ``BANK_TRANSFER_INVOICE_LIMIT`` /
``BANK_TRANSFER_PAID_LIMIT``, which the suite monkeypatches on the ``app.main``
module object. Moving those without also teaching the tests about the new
binding would leave the patch pointing at a name nothing reads -- the
``MONITORING_FOR_SALE`` failure mode. They move in a later commit, with the
test-side change made deliberately rather than as collateral.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from app.billing import bank_transfer, usdt_trc20
from app.db import (
    AccountRepository,
    AuditRepository,
    FixpackJobRepository,
    PaymentRepository,
)
from app.routes._shared import (
    _client_key,
    _reject_if_fixpack_already_live,
    _reject_if_nothing_to_fix,
    _usdt_receiving_address,
)
from app.ratelimit import RateLimitExceeded, RateLimiter
from app.routes.dependencies import (
    get_account_repo,
    get_audit_repo,
    get_fixpack_repo,
    get_payment_repo,
    get_rate_limiter,
)

router = APIRouter()





@router.get("/v1/billing/usdt/invoice/{invoice_id}")
async def get_usdt_invoice(
    invoice_id: str,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    account_repo: AccountRepository = Depends(get_account_repo),
) -> dict:
    """Poll one USDT invoice. Reveals the API key only once the invoice is
    `completed` (payment confirmed on-chain by the poller); pending or
    expired invoices never leak a key. 404 if no such invoice."""
    address = _usdt_receiving_address() or ""
    status = await usdt_trc20.invoice_status(
        payment_repo, account_repo, invoice_id, address=address
    )
    if status is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no USDT invoice with this id, or persistence "
                               "isn't configured on this deployment (see app/db.py)"},
        )
    return status


@router.post("/v1/audits/{audit_id}/fixpack/usdt-invoice", status_code=201)
async def create_fixpack_usdt_invoice(
    audit_id: str,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo),
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
) -> dict:
    """Open a USDT/TRC20 invoice to buy a Fix Pack for one specific audit.
    Mirrors POST /v1/billing/usdt/invoice (fixed address + unique amount so
    transfers match without per-invoice addresses; poll the same GET
    /v1/billing/usdt/invoice/{id} to watch it), but at the Fix Pack price
    and scoped to this audit.

    V1 supports GitHub-URL audits only: an audit created from a zip upload
    has no repository to open a fix PR against, so this returns 422 with a
    clear explanation rather than sell a Fix Pack that can't be fulfilled.

    404 if no such audit. 503 if the receiving address isn't configured, or
    if DATABASE_URL isn't set (the pending invoice row can't be persisted).
    """
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
    address = _usdt_receiving_address()
    if not address:
        raise HTTPException(
            status_code=503,
            detail={"reason": "usdt_not_configured",
                    "detail": "USDT_TRC20_ADDRESS is not set on this deployment"},
        )
    invoice = await usdt_trc20.create_fixpack_invoice(
        payment_repo, address=address, audit_id=audit_id
    )
    if invoice is None:
        raise HTTPException(
            status_code=503,
            detail={"reason": "not_persisted",
                    "detail": "USDT invoices require DATABASE_URL (a pending "
                              "payment row is created to match payment against)"},
        )
    return invoice


@router.get("/v1/billing/bank-transfer/{reference}")
async def get_bank_transfer_invoice(
    reference: str,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    account_repo: AccountRepository = Depends(get_account_repo),
) -> dict:
    """Poll one bank-transfer invoice. Reveals the API key only once the
    operator has confirmed the transfer arrived (status 'completed'); a
    pending or expired invoice never leaks a key. 404 if no such invoice.

    An 'expired' status here is cosmetic: it tells a payer the quote is stale,
    but the operator can still confirm a transfer that surfaces later, because
    a slow bank must never become lost money."""
    status = await bank_transfer.invoice_status(
        payment_repo, account_repo, reference,
        details=bank_transfer.bank_details_from_env(),
    )
    if status is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no bank transfer invoice with this reference, or "
                              "persistence isn't configured on this deployment"},
        )
    return status


# USDT invoices opened per client key per limiter window (24h).
#
# Unauthenticated for the same reason as the bank-transfer pair: a buyer has
# no API key until they have paid. Until now that meant unbounded -- this was
# the one anonymous endpoint that writes a row per call with nothing to stop
# it repeating.
#
# A SEPARATE limiter key from BANK_TRANSFER_INVOICE_LIMIT, where the two bank
# transfer creators deliberately share one. The reason those share is that
# they draw from the same 99-suffix pool, so one budget is what keeps a client
# from taking twice as much of it. USDT does not draw from that pool at all:
# its nonce is a full micro-dollar (base + randbelow(1_000_000)) and an
# invoice expires after 30 minutes, so exhaustion is not the risk here and a
# shared budget would only make a USDT invoice eat a bank-transfer one.
#
# What IS the risk is anonymous row creation, so the same generous number is
# right for the same reason: well above any real checkout, far below abuse.
USDT_INVOICE_LIMIT = 15


def _check_usdt_invoice_rate_limit(request: Request, limiter: RateLimiter) -> None:
    """429 when one client has opened too many USDT invoices today."""
    try:
        limiter.check(
            f"usdt-invoice:{_client_key(request)}",
            limit=USDT_INVOICE_LIMIT,
        )
    except RateLimitExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail={
                "reason": "rate_limited",
                "detail": f"max {USDT_INVOICE_LIMIT} USDT invoices per day",
            },
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc


@router.post("/v1/billing/usdt/invoice", status_code=201)
async def create_usdt_invoice(
    request: Request,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    limiter: RateLimiter = Depends(get_rate_limiter),
) -> dict:
    """Open a USDT/TRC20 invoice: returns the fixed receiving address and
    a unique amount to send (base price + sub-cent nonce, so incoming
    transfers can be matched back to invoices without per-invoice
    addresses). Poll GET /v1/billing/usdt/invoice/{id} to collect the API
    key once the on-chain transfer is seen. See app/billing/usdt_trc20.py.

    503 if the receiving address isn't configured, or if DATABASE_URL
    isn't set (the pending invoice row can't be persisted, so there'd be
    nothing to match a later payment against).
    """
    address = _usdt_receiving_address()
    if not address:
        raise HTTPException(
            status_code=503,
            detail={"reason": "usdt_not_configured",
                    "detail": "USDT_TRC20_ADDRESS is not set on this deployment"},
        )
    # After the configuration gates, before the write: a client on a
    # deployment with no address configured should learn that, not be told to
    # slow down about an endpoint that cannot work anyway.
    _check_usdt_invoice_rate_limit(request, limiter)
    invoice = await usdt_trc20.create_invoice(payment_repo, address=address)
    if invoice is None:
        raise HTTPException(
            status_code=503,
            detail={"reason": "not_persisted",
                    "detail": "USDT invoices require DATABASE_URL (a pending "
                              "payment row is created to match payment against)"},
        )
    return invoice
