"""Bank-transfer invoice lookup.

This module was "USDT invoices and bank-transfer invoice lookup" until USDT was
removed as a way to pay. What is left is the poll endpoint a payer's browser
sits on between pressing "I've paid" and the operator tapping Confirm.

Extracted from app/main.py verbatim -- handler bodies are unchanged, only the
decorators moved from ``@app.<verb>`` to ``@router.<verb>``.

Only the endpoints whose rate limiting is not driven by a module-level limit
constant live here. The bank-transfer invoice creators and the paid-report
endpoint are still in main.py: they read ``BANK_TRANSFER_INVOICE_LIMIT`` /
``BANK_TRANSFER_PAID_LIMIT``, which the suite monkeypatches on the ``app.main``
module object. Moving those without also teaching the tests about the new
binding would leave the patch pointing at a name nothing reads -- the
``MONITORING_FOR_SALE`` failure mode. They move in a later commit, with the
test-side change made deliberately rather than as collateral.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.billing import bank_transfer
from app.db import AccountRepository, PaymentRepository
from app.routes.dependencies import get_account_repo, get_payment_repo

router = APIRouter()


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
