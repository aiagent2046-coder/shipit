"""Buying a Fix Pack through ЮKassa, and being told about it afterwards.

TWO ENDPOINTS AND ONE ASYMMETRY BETWEEN THEM.

The first is ours: a buyer with an audit asks for a payment, we open one with
ЮKassa and hand back the URL to send them to. Everything about that request is
under our control.

The second is not ours at all. It is a POST from the public internet claiming
that a payment succeeded, and ЮKassa DOES NOT SIGN IT -- see app/billing/
yookassa.py for the full argument. So the handler below reads exactly one field
out of that body, the payment id, and then throws the rest away and asks ЮKassa
what actually happened.

Everything that grants anything is decided from OUR request's answer. If that
distinction is ever softened -- if any field from the notification body reaches
a comparison that gates the grant -- then anyone who learns this URL owns a
free Fix Pack, and the first sign of it will be an invoice from an LLM
provider.
"""

from __future__ import annotations

import logging
import os
import re

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Request,
)
from pydantic import Field, field_validator

from app.billing import bank_transfer, grant_fixpack, yookassa
from app.db import (
    AuditRepository,
    FixpackJobRepository,
    PaymentRepository,
    ServiceFlagsRepository,
)
from app.routes.bank_transfer import (
    PayerContact,
    _check_invoice_rate_limit,
    _emergency_stop_active,
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
from app.ratelimit import RateLimiter

logger = logging.getLogger(__name__)

router = APIRouter()

SITE_URL = "https://drydock.co"

# What the buyer sees on their bank statement and on the fiscal receipt. Short,
# because ЮKassa truncates at 128 characters and a truncated description is a
# line somebody has to interpret months later.
DESCRIPTION = "Drydock Fix Pack"


def _credentials() -> tuple[str, str]:
    creds = yookassa.credentials_from_env()
    if creds is None:
        raise HTTPException(
            status_code=503,
            detail={"reason": "yookassa_not_configured",
                    "detail": "card payment is not configured on this "
                              "deployment (YOOKASSA_SHOP_ID and "
                              "YOOKASSA_SECRET_KEY must both be set)"},
        )
    return creds


def _receipt_settings() -> tuple[int, int | None] | None:
    """`(vat_code, tax_system_code)` when this shop issues fiscal receipts.

    None means no receipt is sent with the payment. That is a LEGAL position,
    not a technical one: payments work either way, and whether a receipt is
    required depends on the merchant's tax regime. So it is configuration with
    no default -- a guessed VAT rate is a fiscal document making a false
    statement about somebody's tax, filed with the tax authority in their name.

    tax_system_code is optional even when receipts are on: ЮKassa requires it
    only for a merchant registered under more than one regime.
    """
    raw = (os.environ.get("YOOKASSA_VAT_CODE") or "").strip()
    if not raw:
        return None
    try:
        vat_code = int(raw)
    except ValueError:
        logger.error("YOOKASSA_VAT_CODE is not an integer; sending no receipt")
        return None

    tax_raw = (os.environ.get("YOOKASSA_TAX_SYSTEM_CODE") or "").strip()
    try:
        tax_system_code = int(tax_raw) if tax_raw else None
    except ValueError:
        logger.error("YOOKASSA_TAX_SYSTEM_CODE is not an integer; omitting it")
        tax_system_code = None
    return vat_code, tax_system_code


_ACCESS_TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")


class CardPayer(PayerContact):
    """The manual rail's payer, plus where to send them back to.

    `return_token` is the audit's access token, and it exists because the
    buyer has to be able to READ the page they are returned to. An audit is a
    per-row capability: `/audit/{id}` without `?token=` renders "No audit found
    for this link". Until this field existed the return URL was built without
    one, so a real card buyer would have paid and landed on a page that could
    not show them what they had bought.

    It is a TOKEN, not a URL, and that is the security of it. Accepting a
    caller-supplied return address would make this an open redirect with a
    payment page in front of it: ЮKassa sends the payer wherever we said, and
    "wherever we said" would be whatever a stranger posted. Here the host and
    the path are ours and only this one query value varies.

    Anything that is not exactly a 32-character hex token is dropped rather
    than rejected. It is the shape migration 0010 mints, the buyer did not type
    it, and losing the order over a mangled query parameter would cost a sale
    to protect a link.
    """

    return_token: str | None = Field(default=None, max_length=64)

    @field_validator("return_token")
    @classmethod
    def _hex_or_nothing(cls, v: str | None) -> str | None:
        v = (v or "").strip().lower()
        return v if _ACCESS_TOKEN_RE.match(v) else None


def _return_url(audit_id: str, token: str | None) -> str:
    """Where ЮKassa sends the payer when they are done.

    `paid=1` MARKS A RETURN, NOT A PAYMENT. The grant is decided by the
    notification handler below, from an answer ЮKassa gives to a request we
    make; this flag reaches the page in the payer's own browser and anyone can
    type it. So it may change what the page SAYS and never what it does -- and
    what it says has to stay true for someone who typed it, which is why the
    page's wording is conditional ("if your payment went through") rather than
    congratulatory.

    Without it the payer lands back on a page that still shows the checkout
    form, because the notification has not arrived yet, and has no way to tell
    whether anything happened.

    No quoting: `token` has already been validated to 32 hex characters, and
    `audit_id` is the path segment this handler was routed on. A value that
    needed escaping here would mean the validator above had stopped working,
    which is a thing to fix rather than to paper over.
    """
    base = f"{SITE_URL}/audit/{audit_id}"
    return f"{base}?token={token}&paid=1" if token else f"{base}?paid=1"


@router.post("/v1/audits/{audit_id}/fixpack/yookassa", status_code=201)
async def create_fixpack_payment(
    audit_id: str,
    payer: CardPayer,
    request: Request,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo),
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
    limiter: RateLimiter = Depends(get_rate_limiter),
    service_flags_repo: ServiceFlagsRepository = Depends(get_service_flags_repo),
    transport=Depends(get_billing_transport),
) -> dict:
    """Open a ЮKassa payment for one audit's Fix Pack and say where to pay it.

    THE SAME GATES AS THE MANUAL RAIL, IN THE SAME ORDER, and that is deliberate
    rather than copied. A second way to pay that skips one of them is a way to
    buy something the first way refuses to sell: the emergency stop would pause
    one checkout and leave the other open, a paused service would still take
    money, and an audit with nothing auto-fixable could be sold a Fix Pack that
    can only disappoint. The stop is checked before the rate limiter so a paused
    service neither spends nor consumes the caller's quota.

    A ROW IS WRITTEN BEFORE ЮKASSA IS CALLED. The order must exist here before
    it exists there, because the notification comes back addressed to the
    metadata we set, and metadata for a row that was never written names
    nothing. The cost is a `pending` row for every abandoned checkout, which is
    the same cost the manual rail already pays and the same one the merit
    endpoint now knows to say nothing about (`not_paid`).

    The idempotence key is the order reference, so a retried create is the same
    request rather than a second payment. See app/billing/yookassa.py: ЮKassa
    treats an unrecognised key as a new charge.
    """
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

    credentials = _credentials()
    amount = bank_transfer.fixpack_price_rub()

    reference = await bank_transfer.reserve_reference(
        payment_repo, provider=yookassa.PROVIDER)
    if reference is None:
        raise HTTPException(
            status_code=503,
            detail={"reason": "not_persisted",
                    "detail": "could not open an order on this deployment"},
        )

    row = await payment_repo.create(
        account_id=None, provider=yookassa.PROVIDER, external_ref=reference,
        amount=float(amount), currency=yookassa.CURRENCY, status="pending",
        tier_granted=None, product=bank_transfer.PRODUCT_FIXPACK,
        audit_id=audit_id,
        payer_name=payer.payer_name, payer_email=payer.payer_email,
        payer_x=payer.payer_x, payer_locale=payer.payer_locale,
    )
    if row is None:
        raise HTTPException(
            status_code=503,
            detail={"reason": "not_persisted",
                    "detail": "the order could not be recorded, so it was not "
                              "opened — nothing has been charged"},
        )

    receipt = None
    settings = _receipt_settings()
    if settings is not None:
        vat_code, tax_system_code = settings
        receipt = yookassa.receipt_for(
            email=payer.payer_email, description=DESCRIPTION, amount=amount,
            vat_code=vat_code, tax_system_code=tax_system_code,
        )

    try:
        payment = await yookassa.create_payment(
            credentials=credentials, amount=amount, description=DESCRIPTION,
            return_url=_return_url(audit_id, payer.return_token),
            idempotence_key=reference,
            metadata={"reference": reference},
            receipt=receipt, transport=transport,
        )
    except yookassa.YooKassaError:
        # The row stays `pending`. It records an order that was opened and never
        # paid, which is true, and is exactly what the merit endpoint refuses to
        # judge. Deleting it would be worse: a create that actually landed and
        # only failed to answer us would then have a payment at ЮKassa with
        # metadata pointing at nothing.
        logger.warning("could not open a ЮKassa payment for %s", reference,
                       exc_info=True)
        raise HTTPException(
            status_code=502,
            detail={"reason": "payment_system_unavailable",
                    "detail": "the payment system did not answer. Nothing has "
                              "been charged — please try again."},
        ) from None

    url = yookassa.confirmation_url(payment)
    if not url:
        logger.error("ЮKassa opened %s with no confirmation url", reference)
        raise HTTPException(
            status_code=502,
            detail={"reason": "payment_system_unavailable",
                    "detail": "the payment system did not return a payment "
                              "page. Nothing has been charged."},
        )

    provider_payment_id = payment.get("id")
    if isinstance(provider_payment_id, str) and provider_payment_id:
        await payment_repo.set_provider_payment_id(
            str(row["id"]), provider_payment_id)

    return {
        "reference": reference,
        "amount": amount,
        "currency": yookassa.CURRENCY,
        "confirmation_url": url,
    }


async def _tell_the_payer_after_answering(
    payment_repo: PaymentRepository, *, payment_id: str, transport=None,
) -> None:
    """Send the confirmation once the notification has already been answered.

    Runs as a background task, and that is the point rather than tidiness. On
    2026-08-25 a live notification took eleven seconds to answer, nine of them
    inside this send: an outbound SMTP conversation, on the request path of a
    payment provider that RETRIES anything it does not get a 2xx for. The mail
    timeout alone is 20 seconds and the Telegram fallback's is 30, so a mail
    server that is merely slow -- not down, slow -- turns one payment into a
    retry loop at ЮKassa's pace.

    Re-reads the row rather than taking the caller's copy, because the grant
    has just rewritten it and the confirmation quotes what is now stored.

    Best-effort by inheritance: _tell_the_payer swallows its own failures and
    pages the operator when nothing reached the customer, which is the right
    contract here too -- an exception escaping a background task is logged by
    starlette and changes nothing about a payment that is already granted.
    """
    from app.billing.bank_transfer import _tell_the_payer

    row = await payment_repo.get(payment_id)
    if row is None:
        logger.warning("could not re-read a confirmed payment to announce it")
        return
    await _tell_the_payer(
        row, product=bank_transfer.PRODUCT_FIXPACK, transport=transport)


@router.post("/v1/billing/yookassa/notifications")
async def receive_notification(
    request: Request,
    background: BackgroundTasks,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo),
    transport=Depends(get_billing_transport),
) -> dict:
    """ЮKassa says something happened. We go and find out what.

    THE BODY IS NEVER EVIDENCE. Exactly one field is read from it -- the payment
    id -- and it is used only as the argument to a request WE make, with OUR
    credentials, to a host WE named. Status, amount and currency are then read
    from that answer. Nothing from the POST reaches the comparison that gates
    the grant.

    This is the whole security of the rail. ЮKassa does not sign notifications
    (their own SDK offers only an IP allowlist), and this service sits behind a
    reverse proxy where the apparent source address is a header the sender
    writes. Trusting the body would mean anyone who learns this URL can POST
    `{"event": "payment.succeeded"}` and be given a Fix Pack.

    ALWAYS 200, AND NEVER AN ERROR THE SENDER CAN READ. ЮKassa retries a
    notification that does not get a 2xx, so a 500 here becomes a retry storm
    on a problem retrying cannot fix. And a distinguishable response is a probe:
    a stranger POSTing payment ids would learn which ones exist from the status
    code alone. Everything is logged; nothing is explained to the caller. That
    goes for the BODY as well as the status -- it is `{"ok": true}` on every
    path, including the one that granted something.

    ANSWERED BEFORE THE CUSTOMER IS TOLD. The only work between the request
    arriving and the 200 is verifying the payment with ЮKassa and recording the
    grant; the confirmation to the payer is a background task. Announcing it
    inline held a live notification for eleven seconds -- nine of them in an
    SMTP conversation -- on a path whose failure mode is a retry.
    """
    source = request.headers.get("x-forwarded-for") or (
        request.client.host if request.client else None)
    # First hop only. The header is a chain the sender can prepend to, so the
    # rightmost entry is the one our own proxy wrote -- but the leftmost is what
    # a caller controls, and taking the whole string would never parse anyway.
    first_hop = source.split(",")[0].strip() if source else None

    if not yookassa.is_notification_source_trusted(first_hop):
        # A filter, not the authorisation. Costs nothing and turns away noise
        # before we spend a request on it.
        logger.info("ЮKassa notification from an untrusted source, ignored")
        return {"ok": True}

    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        logger.info("ЮKassa notification was not JSON, ignored")
        return {"ok": True}

    if not isinstance(body, dict):
        return {"ok": True}

    event = body.get("event")
    obj = body.get("object")
    payment_id = obj.get("id") if isinstance(obj, dict) else None

    if event != yookassa.EVENT_PAYMENT_SUCCEEDED:
        # canceled and refund.succeeded are recorded by the operator's own
        # flow, not here. Answering 200 stops the retries either way.
        logger.info("ЮKassa notification %r, nothing to do", event)
        return {"ok": True}

    if not isinstance(payment_id, str) or not payment_id:
        logger.warning("ЮKassa succeeded notification carried no payment id")
        return {"ok": True}

    credentials = yookassa.credentials_from_env()
    if credentials is None:
        logger.error("ЮKassa notification arrived but this deployment has no "
                     "credentials to check it with")
        return {"ok": True}

    try:
        payment = await yookassa.get_payment(
            payment_id, credentials=credentials, transport=transport)
    except yookassa.YooKassaError:
        # We could not verify, so we grant nothing. Answering 200 anyway: this
        # will not resolve on a retry either, and the operator has the log.
        logger.warning("could not read back a ЮKassa payment", exc_info=True)
        return {"ok": True}

    metadata = payment.get("metadata")
    reference = metadata.get("reference") if isinstance(metadata, dict) else None
    if not isinstance(reference, str) or not reference:
        logger.warning("a ЮKassa payment carries no order reference")
        return {"ok": True}

    row = await payment_repo.get_by_external_ref(yookassa.PROVIDER, reference)
    if row is None:
        logger.warning("a ЮKassa payment names an order we do not have")
        return {"ok": True}

    expected = f"{float(row.get('amount') or 0):.2f}"
    if not yookassa.is_paid(payment, expected_amount=expected):
        # Succeeded is not the same as paid-for-this. A payment of one rouble
        # is succeeded too, and this is the check that stops one buying a
        # 990-rouble product.
        logger.warning("a ЮKassa payment for %s did not pay for it", reference)
        return {"ok": True}

    # Read BEFORE the grant, which is what rewrites it. ЮKassa retries a
    # notification it did not get a 2xx for, the operator can confirm the same
    # payment by hand, and grant_fixpack is idempotent through all of that --
    # but _tell_the_payer is not. It simply sends, so without this a retry is a
    # second "your payment is confirmed" to someone who already read the first.
    # A duplicate has no recovery; a send that failed pages the operator and
    # can be repeated by hand, so the guard errs towards saying it once.
    already_confirmed = (
        str(row.get("status") or "").strip().lower() == "completed")

    granted = await grant_fixpack(
        fixpack_repo=fixpack_repo, payment_repo=payment_repo,
        audit_repo=audit_repo, provider=yookassa.PROVIDER,
        external_ref=reference, amount=row.get("amount"),
        currency=row.get("currency") or yookassa.CURRENCY,
        audit_id=row.get("audit_id"), invoice_payment_id=str(row["id"]),
    )

    if not granted:
        # The money is real and the Fix Pack was not recorded. Announcing it
        # would promise a pull request nothing is going to open, so this stays
        # silent to the payer and loud in the log.
        logger.error("ЮKassa payment %s was paid but granted no Fix Pack",
                     reference)
        return {"ok": True}

    logger.info("ЮKassa payment confirmed for %s", reference)

    if not already_confirmed:
        background.add_task(
            _tell_the_payer_after_answering, payment_repo,
            payment_id=str(row["id"]), transport=transport)

    # THE SAME ANSWER TO EVERY CALLER, which the docstring above has always
    # claimed and this used to break by returning `granted`. The body was the
    # one thing that told a stranger apart from ЮKassa: a payment id that
    # bought something answered differently from one that did not.
    return {"ok": True}
