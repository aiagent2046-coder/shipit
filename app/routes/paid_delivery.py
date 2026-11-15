"""Renew caller authority on an existing paid order without charging again."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.billing import bank_transfer, yookassa
from app.db import AuditRepository, PaymentRepository
from app.deploypack.delivery_auth import DeliveryAuthorizationError
from app.deploypack.paid_delivery_auth import (
    authorize_paid_checkout, get_paid_delivery_store, repository_name, seal_paid_grant,
)
from app.ratelimit import RateLimiter
from app.routes.bank_transfer import _check_invoice_rate_limit
from app.routes.dependencies import get_audit_repo, get_payment_repo, get_rate_limiter

router = APIRouter()


class RenewDelivery(BaseModel):
    reference: str = Field(min_length=1, max_length=128)
    audit_token: str


@router.post("/v1/audits/{audit_id}/fixpack/delivery-authorization")
async def renew_delivery_authorization(
    audit_id: str, body: RenewDelivery, request: Request,
    audit_repo: AuditRepository = Depends(get_audit_repo),
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    limiter: RateLimiter = Depends(get_rate_limiter),
    grant_store=Depends(get_paid_delivery_store),
) -> dict:
    _check_invoice_rate_limit(request, limiter)
    audit = await audit_repo.get_authorized(audit_id, body.audit_token)
    if audit is None:
        raise HTTPException(404, detail={"reason": "not_found"})
    candidates = []
    for provider in (bank_transfer.PROVIDER, yookassa.PROVIDER):
        row = await payment_repo.get_by_external_ref(provider, body.reference)
        if (row and row.get("provider") == provider
                and str(row.get("audit_id")) == audit_id
                and row.get("product") == "fixpack" and row.get("status") == "completed"):
            candidates.append(row)
    if len(candidates) != 1:
        raise HTTPException(404, detail={"reason": "not_found"})
    payment = candidates[0]
    try:
        token = await authorize_paid_checkout(audit, request.headers.get("x-github-token"))
        encrypted = seal_paid_grant(
            token, provider=payment["provider"], external_ref=payment["external_ref"],
            audit_id=audit_id, repo_full_name=repository_name(audit),
        )
    except DeliveryAuthorizationError as exc:
        raise HTTPException(exc.status_code, detail={"reason": exc.reason}) from None
    if not await grant_store.replace_for_payment(str(payment["id"]), encrypted):
        raise HTTPException(409, detail={"reason": "delivery_authorization_not_waiting"})
    return {"status": "paid"}
