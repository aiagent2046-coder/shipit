"""ЮKassa — the first rail on this deployment that can take money by itself.

WHAT MAKES THIS DIFFERENT FROM bank_transfer.py. That provider has no oracle: a
human looks at their banking app and presses a button, and no amount of code
can shorten that. This one has an oracle, and the whole difficulty is that the
oracle speaks to us over an unauthenticated channel.

ЮKassa DOES NOT SIGN ITS NOTIFICATIONS. This is not an oversight on their part
that we are working around -- it is the documented design, and their own SDK
(yookassa 3.12.1, domain/common/security_helper.py) offers exactly one defence:
a list of source IP ranges. That defence is weak here for a specific reason.
This service sits behind a reverse proxy, so the socket's peer address is the
proxy's, and the payer's apparent address is whatever `X-Forwarded-For` says --
a header written by whoever sent the request.

So the rule this module exists to enforce:

    A NOTIFICATION IS A HINT. IT IS NEVER EVIDENCE.

Nothing in a notification body is acted on. Its only permitted use is to learn
which payment id to ask about; the answer comes from GET /v3/payments/{id},
made by us, with our own credentials, over TLS to a host we named. The IP list
is kept as a cheap first filter -- it costs nothing and turns away noise -- but
it authorises nothing on its own.

The failure it prevents is not subtle: without it, anyone who learns the
notification URL grants themselves a paid Fix Pack by POSTing
`{"event": "payment.succeeded", ...}`. That is the same class of defect this
product audits other people's repositories for, and it would be embarrassing
in a way that is also expensive.

IDEMPOTENCE IS SPELLED THEIR WAY. The header is `Idempotence-Key`, not
`Idempotency-Key`. A silent typo there is a duplicate charge: ЮKassa treats a
request with no recognised key as a new payment, so a retried create becomes a
second charge on the same customer for the same order.

MONEY IS IN KOPECKS AS A STRING. The API takes `amount.value` as a decimal
string with two places ("990.00"), not a float and not an integer of minor
units. Floats are kept out of this module entirely -- see `_amount`.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)

PROVIDER = "yookassa"

API_ROOT = "https://api.yookassa.ru/v3"

# Their spelling. See the module docstring: this is a duplicate charge if it is
# ever "corrected" to the more common English word.
IDEMPOTENCE_HEADER = "Idempotence-Key"

CURRENCY = "RUB"

# Where ЮKassa's own SDK says notifications come from (yookassa 3.12.1,
# domain/common/security_helper.py, YOOKASSA_NETWORKS). Copied rather than
# imported: taking a dependency on their SDK to reach one list would pull in a
# requests-based HTTP client this codebase does not use and cannot inject a
# transport into.
#
# THIS LIST AUTHORISES NOTHING. It is a filter that turns away obvious noise
# before we spend a request on it. The authorisation is the re-fetch.
NOTIFICATION_NETWORKS: tuple[str, ...] = (
    "77.75.153.0/25",
    "77.75.156.11/32",
    "77.75.156.35/32",
    "77.75.154.128/25",
    "185.71.76.0/27",
    "185.71.77.0/27",
    "2a02:5180:0:1509::/64",
    "2a02:5180:0:2655::/64",
    "2a02:5180:0:1533::/64",
    "2a02:5180:0:2669::/64",
)

_NETWORKS = tuple(ipaddress.ip_network(n) for n in NOTIFICATION_NETWORKS)

# The statuses a payment can be in. Only `succeeded` grants anything.
STATUS_PENDING = "pending"
STATUS_WAITING_FOR_CAPTURE = "waiting_for_capture"
STATUS_SUCCEEDED = "succeeded"
STATUS_CANCELED = "canceled"

# The notification events we accept. `payment.waiting_for_capture` is
# deliberately absent: this shop creates payments with capture=true, so a
# payment that stops there is a payment something is wrong with, and granting
# on it would hand over the product before the money is actually ours.
EVENT_PAYMENT_SUCCEEDED = "payment.succeeded"
EVENT_PAYMENT_CANCELED = "payment.canceled"
EVENT_REFUND_SUCCEEDED = "refund.succeeded"


class YooKassaError(RuntimeError):
    """A call to ЮKassa did not return what we asked for.

    Carries no response body. Their errors quote the request back, and the
    request contains the payer's email on the receipt -- a log line is the
    wrong place for that.
    """


def credentials_from_env() -> tuple[str, str] | None:
    """`(shop_id, secret_key)`, or None when this deployment has no shop.

    Both or neither, like bank_details_from_env: a shop id with no key cannot
    sign a request, and a deployment holding half a credential should refuse to
    offer the rail rather than fail at the moment somebody tries to pay.
    """
    shop_id = (os.environ.get("YOOKASSA_SHOP_ID") or "").strip()
    secret = (os.environ.get("YOOKASSA_SECRET_KEY") or "").strip()
    if not shop_id or not secret:
        return None
    return shop_id, secret


def is_test_shop() -> bool:
    """Whether the configured key is a test key.

    ЮKassa prefixes test secret keys with `test_`. Worth being able to say out
    loud: a deployment that believes it is live while holding a test key takes
    no money at all, and the failure looks like "customers are not paying"
    rather than like a misconfiguration.
    """
    creds = credentials_from_env()
    return bool(creds and creds[1].startswith("test_"))


def is_notification_source_trusted(ip: str | None) -> bool:
    """Whether `ip` is inside ЮKassa's published ranges.

    A FILTER, NOT AN AUTHORISATION -- see the module docstring. False here
    means "do not spend a request on this"; True here means nothing except that
    it is worth asking ЮKassa about.

    Anything unparseable is untrusted. `X-Forwarded-For` is attacker-controlled
    text, and the honest reading of text that is not an address is that we do
    not know where this came from.
    """
    if not ip:
        return False
    try:
        parsed = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    return any(parsed in network for network in _NETWORKS)


def _amount(value: str) -> dict[str, str]:
    """`{"value": "990.00", "currency": "RUB"}`.

    The value is formatted from a string through Decimal, never through float:
    a price that has survived being a `float` is a price that can arrive as
    990.0000000001, and ЮKassa rejects the request -- at checkout, in front of
    the buyer.
    """
    from decimal import Decimal

    return {"value": f"{Decimal(value):.2f}", "currency": CURRENCY}


def receipt_for(
    *, email: str, description: str, amount: str,
    vat_code: int, tax_system_code: int | None,
) -> dict[str, Any]:
    """The 54-ФЗ receipt ЮKassa sends to the fiscal register on our behalf.

    Included in the payment request rather than sent separately, which is the
    simpler of the two flows their API offers and the only one that cannot end
    with a payment taken and a receipt never issued.

    `vat_code` and `tax_system_code` are the merchant's tax position, not
    ours to infer: they are read from the environment by the caller and there
    is no default here, because a guessed VAT rate is a fiscal document that
    says something untrue about somebody's tax.

    `payment_subject` is "service" and `payment_mode` is "full_payment": the
    Fix Pack is a service, paid once, in full, before delivery.
    """
    item: dict[str, Any] = {
        "description": description[:128],
        "quantity": "1.00",
        "amount": _amount(amount),
        "vat_code": vat_code,
        "payment_subject": "service",
        "payment_mode": "full_payment",
    }
    receipt: dict[str, Any] = {"customer": {"email": email}, "items": [item]}
    if tax_system_code is not None:
        receipt["tax_system_code"] = tax_system_code
    return receipt


async def _call(
    method: str, path: str, *,
    credentials: tuple[str, str],
    json_body: dict[str, Any] | None = None,
    idempotence_key: str | None = None,
    transport: httpx.BaseTransport | None = None,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """One request to ЮKassa, raising YooKassaError on anything but 2xx.

    `transport` is the seam the suite replaces. Nothing in the tests reaches
    the network, and nothing in this module reads a global client.
    """
    shop_id, secret = credentials
    headers = {"Content-Type": "application/json"}
    if idempotence_key:
        headers[IDEMPOTENCE_HEADER] = idempotence_key

    async with httpx.AsyncClient(
        transport=transport, timeout=timeout, auth=(shop_id, secret),
    ) as client:
        try:
            response = await client.request(
                method, f"{API_ROOT}{path}", headers=headers, json=json_body,
            )
        except httpx.HTTPError as exc:
            raise YooKassaError(
                f"{method} {path} did not complete: {type(exc).__name__}"
            ) from exc

    if response.status_code // 100 != 2:
        # The status, and nothing else. Their error bodies echo the request,
        # and the request carries the payer's email on the receipt.
        raise YooKassaError(f"{method} {path} answered {response.status_code}")

    try:
        payload = response.json()
    except ValueError as exc:
        raise YooKassaError(f"{method} {path} answered with non-JSON") from exc

    if not isinstance(payload, dict):
        raise YooKassaError(f"{method} {path} answered with a non-object")
    return payload


async def create_payment(
    *,
    credentials: tuple[str, str],
    amount: str,
    description: str,
    return_url: str,
    idempotence_key: str,
    metadata: dict[str, str] | None = None,
    receipt: dict[str, Any] | None = None,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Open a payment and get the URL to send the payer to.

    `capture=True` -- one stage. Two-stage exists so a merchant can inspect an
    order before taking the money, and there is nothing to inspect here: the
    product is generated automatically the moment payment is confirmed. A
    two-stage flow would add a state in which the payer has paid, we have not
    captured, and a timeout silently returns their money.

    `idempotence_key` is REQUIRED rather than defaulted to a fresh uuid, which
    is what ЮKassa's own SDK does. A generated key makes every retry a new
    payment, so the one situation the header exists for -- our request timed
    out and we do not know whether it landed -- is the one it would not cover.
    The caller passes something derived from the order, so a retry is the same
    request twice.

    `metadata` is how the notification finds its way back to a row here. It is
    OUR identifiers only: never the payer's name or address, which would put
    personal data in a third party's dashboard for no reason we need.
    """
    body: dict[str, Any] = {
        "amount": _amount(amount),
        "capture": True,
        "description": description[:128],
        "confirmation": {"type": "redirect", "return_url": return_url},
    }
    if metadata:
        body["metadata"] = metadata
    if receipt:
        body["receipt"] = receipt

    return await _call(
        "POST", "/payments", credentials=credentials, json_body=body,
        idempotence_key=idempotence_key, transport=transport,
    )


async def get_payment(
    payment_id: str, *,
    credentials: tuple[str, str],
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """What ЮKassa says about one payment, asked by us.

    THIS IS THE AUTHORITY, and the notification handler's only real job is to
    get here. Everything acted on -- status, amount, currency, metadata -- is
    read from this response and never from the body that arrived unsigned.
    """
    if not payment_id or "/" in payment_id:
        # A path segment out of an unsigned notification. Refuse rather than
        # concatenate: a value with a slash in it addresses a different
        # endpoint than the one this function claims to call.
        raise YooKassaError("payment id is missing or not a single segment")
    return await _call(
        "GET", f"/payments/{payment_id}", credentials=credentials,
        transport=transport,
    )


def confirmation_url(payment: dict[str, Any]) -> str | None:
    """Where to send the payer, out of a create_payment response."""
    confirmation = payment.get("confirmation")
    if not isinstance(confirmation, dict):
        return None
    url = confirmation.get("confirmation_url")
    return url if isinstance(url, str) and url.startswith("https://") else None


def is_paid(payment: dict[str, Any], *, expected_amount: str) -> bool:
    """Whether this payment, as ЮKassa describes it, actually paid for the thing.

    THREE CONDITIONS, AND THE AMOUNT IS THE ONE THAT IS EASY TO FORGET.
    `status == "succeeded"` says money moved; it does not say how much. A
    payment created for a different order, or for one rouble, is `succeeded`
    too -- and `paid` is separately false while a succeeded payment is being
    settled, so both are checked rather than either.

    Compared as Decimal, not as strings: "990.00" and "990.0" are the same
    amount and different text, and rejecting a correct payment over formatting
    would refuse a customer who paid.
    """
    from decimal import Decimal, InvalidOperation

    if payment.get("status") != STATUS_SUCCEEDED:
        return False
    if payment.get("paid") is not True:
        return False

    amount = payment.get("amount")
    if not isinstance(amount, dict):
        return False
    if amount.get("currency") != CURRENCY:
        return False
    try:
        return Decimal(str(amount.get("value"))) == Decimal(expected_amount)
    except (InvalidOperation, TypeError):
        return False
