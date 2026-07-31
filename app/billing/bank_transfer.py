"""Bank transfer payment provider -- manually confirmed by the operator.

Interim method for a deployment with no legal entity yet, and therefore no
business acquiring: money arrives on a personal bank account and the
operator confirms it by hand. A personal account has no API to poll, so
unlike USDT/TRC20 (TronGrid) or PayPal (webhook) there is no automatic
confirmation and there never will be for this provider -- a human looking at
their banking app IS the oracle.

Structurally, though, this is the SAME flow as usdt_trc20: a pending
`payments` row is written up front (the invoice the payer is shown), and a
later, separate event transitions it to completed via
`grant_pro_tier`/`grant_fixpack` with `invoice_payment_id=`. That branch runs
through `mark_completed`/`mark_completed_fixpack`, whose compare-and-set
predicate is what makes a repeated confirmation safe -- press the confirm
button twice and the second press returns the same account/job, mints no
second key, and creates no second Fix Pack. Going through the other branch of
those functions (the INSERT path Telegram Stars uses) would NOT be safe here,
because a human can and will press a button twice.

Matching is by PAYER IDENTITY, corroborated by a KOPECK SUFFIX on the amount.
The payer pays a card number, and a card-to-card transfer has no
payment-reference field the payer could type a code into, so the operator
matches the sender's name against the name and email the payer gave on the
checkout page. On top of that, every open invoice is quoted a unique amount --
5.07 rather than 5.00 -- so two orders from the same person, or two payers with
the same name, are still told apart on the statement.

The suffix is a HINT, never a key, and the ordering matters:

  - It survives only a same-currency transfer. If the payer's bank converts,
    what lands is a converted figure and the kopecks are gone -- which is why
    amount cannot be the primary key here the way it is for USDT.
  - There are 99 slots. Under saturation the price is quoted bare and identity
    is all that is left (see _reserve_unique_amount).

This module deliberately does not try to record the amount that actually
arrived -- the operator eyeballs sufficiency before confirming, and storing a
number that is wrong in a knowable way is worse than storing what was quoted.

The reference code survives as the ORDER ID, not as a bank-statement key: it
is what /link presents to claim a paid invoice's key and what the payer quotes
to support. It just no longer has to travel through the bank.

Bank details are read from env and never hardcoded: they are a private
individual's account and beneficiary name, not public infrastructure like a
TRON address. They are published, on the operator's explicit instruction, by
GET /v1/billing/details so the site footer can show them -- that endpoint is
the single source, and they are still never mirrored into a NEXT_PUBLIC_*
build variable.
"""

from __future__ import annotations

import datetime
import logging
import os
import re
import secrets
from typing import Any

logger = logging.getLogger(__name__)

PROVIDER = "bank_transfer"
CURRENCY = "USD"

PRODUCT_PRO = "pro_tier"
PRODUCT_FIXPACK = "fixpack"

_DEFAULT_PRO_PRICE_USD = "5.00"
_DEFAULT_FIXPACK_PRICE_USD = "10.00"

# Seven days, against usdt_trc20's thirty minutes. A SWIFT transfer takes one
# to three business days before it is even visible to the operator, and the
# payer may well start the invoice on a Friday. Anything shorter would show
# "expired" to a payer whose money is still legitimately in flight.
#
# Expiry here is COSMETIC ONLY: it changes what invoice_status() tells the
# payer and nothing else. confirm() deliberately does not consult it, so a
# transfer that surfaces on day nine is still confirmable. A TTL that could
# block confirmation would turn a slow bank into lost money, which is exactly
# the failure this provider exists to avoid.
INVOICE_TTL_SECONDS = 7 * 24 * 60 * 60

REFERENCE_PREFIX = "DRY-"

# Uppercase letters and digits minus the four that get misread when a human
# copies a code off a screen into a banking app: O/0 and I/1. 32 symbols over
# 6 positions is ~10^9 codes, and collisions are additionally re-rolled below.
_REFERENCE_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
_REFERENCE_BODY_LEN = 6
_REFERENCE_ATTEMPTS = 20

# Same alphabet as above, as a character class. Used by /link to tell a bank
# reference apart from a TRC20 transaction hash (64 hex chars) without asking
# the payer which provider they used.
REFERENCE_RE = re.compile(r"^DRY-[2-9A-HJ-NP-Z]{6}$")

# Every field the payer needs to actually make the transfer. All six are
# required together: a payer given a SWIFT code but no account number cannot
# send anything, so a half-configured deployment must refuse (503) rather than
# render an unusable invoice.
#
# `card` is the one the checkout page actually shows. The other five are the
# full requisites behind that card, shown in the site footer for payers whose
# bank needs them.
_BANK_ENV_FIELDS: tuple[tuple[str, str], ...] = (
    ("card", "BANK_TRANSFER_CARD"),
    ("bank_name", "BANK_TRANSFER_BANK_NAME"),
    ("swift", "BANK_TRANSFER_SWIFT"),
    ("beneficiary", "BANK_TRANSFER_BENEFICIARY"),
    ("account", "BANK_TRANSFER_ACCOUNT"),
    ("address", "BANK_TRANSFER_ADDRESS"),
)


def bank_details_from_env() -> dict[str, str] | None:
    """The six payer-facing bank fields, or None if any is unset.

    All-or-nothing on purpose, and never defaulted: these are one private
    individual's real banking details, so there is no sensible fallback value
    and a partially-configured deployment is an operator error to surface
    (endpoint -> 503), not something to paper over.
    """
    details = {
        key: (os.environ.get(var) or "").strip()
        for key, var in _BANK_ENV_FIELDS
    }
    if not all(details.values()):
        return None
    return details


def _price_from_env(var: str, default: str) -> str:
    """A fiat amount as a fixed-2dp string. Same shape and same
    unparseable-override-falls-back-to-default contract as paypal._price_from_env,
    because both quote a catalogue price in USD to a human."""
    raw = os.environ.get(var) or default
    try:
        return f"{float(raw):.2f}"
    except ValueError:
        return f"{float(default):.2f}"


def pro_price_usd() -> str:
    return _price_from_env("BANK_TRANSFER_PRO_PRICE_USD", _DEFAULT_PRO_PRICE_USD)


def fixpack_price_usd() -> str:
    return _price_from_env(
        "BANK_TRANSFER_FIXPACK_PRICE_USD", _DEFAULT_FIXPACK_PRICE_USD
    )


# The kopeck nonce added to every quoted price, so two open invoices are never
# quoted the same amount and the operator can tell one incoming card transfer
# from another. Same idea as usdt_trc20._reserve_unique_amount, at two decimals
# instead of six -- which is the whole difference that matters:
#
#  - 99 slots, not a million. Exhaustion is reachable (100 invoices open inside
#    the 7-day TTL), so _reserve_unique_amount walks the free slots instead of
#    re-rolling blind, and falls back to the bare price rather than duplicating
#    an amount that is already in flight.
#  - The nonce is 1..99, never 0: an invoice quoted at a round 5.00 carries no
#    information, and this is the only provider where a human, not an exact
#    integer comparison, does the matching.
#
# It raises the price by under a dollar, and always UPWARDS, so a nonce can
# never undercharge -- the same direction usdt_trc20 adds its nonce in.
_CENTS_NONCE_MIN = 1
_CENTS_NONCE_MAX = 99


def amount_to_cents(amount: float) -> int:
    """A quoted amount as integer cents. round() not int(): 5.07 * 100 is
    506.9999... in binary float and int() would truncate it to 506. Same
    reasoning and same fix as usdt_trc20.amount_to_micros."""
    return int(round(amount * 100))


async def _reserve_unique_amount(payment_repo: Any, price: str) -> str:
    """`price` plus a kopeck nonce no currently-open invoice is already quoted.

    The nonce is what makes the amount a MATCHING HINT rather than noise: the
    operator sees 5.07 on the statement and knows which of two open orders it
    belongs to without waiting for the payer to confirm their name.

    It is a hint and not a key, deliberately, and the caller must not treat it
    as one:

      - It only survives a same-currency transfer. If the payer's bank converts,
        what lands is a converted figure and the kopecks are gone. Payer name
        and email stay the primary handle for exactly this reason.
      - With all 99 slots taken it returns the bare price. Two invoices then
        share an amount, which name and email still disambiguate -- whereas
        blocking a sale because a hundred invoices are open would be absurd.

    Shared by the Pro and Fix Pack creators, both drawing from the same pending
    set and comparing whole amounts, so a Pro and a Fix Pack invoice cannot
    collide with each other either.
    """
    base_cents = amount_to_cents(float(price))
    pending = await payment_repo.list_pending(PROVIDER)
    taken = {
        amount_to_cents(p["amount"])
        for p in pending
        if p.get("amount") is not None
    }

    free = [
        base_cents + n
        for n in range(_CENTS_NONCE_MIN, _CENTS_NONCE_MAX + 1)
        if base_cents + n not in taken
    ]
    if not free:
        logger.warning(
            "every kopeck nonce for %s is in flight; quoting the bare price and "
            "leaving the payer's name as the only handle on this payment",
            price,
        )
        return price
    return f"{secrets.choice(free) / 100:.2f}"


def generate_reference() -> str:
    """One candidate reference code. `secrets`, not `random`: the code is what
    a /link caller presents to claim a paid invoice's key, so guessing one must
    be as hard as guessing any other bearer token of this length."""
    body = "".join(
        secrets.choice(_REFERENCE_ALPHABET) for _ in range(_REFERENCE_BODY_LEN)
    )
    return f"{REFERENCE_PREFIX}{body}"


async def _reserve_reference(payment_repo: Any) -> str | None:
    """A reference code no existing bank-transfer payment is already using.

    Same re-roll-off-what-is-taken shape as usdt_trc20._reserve_unique_amount,
    and with the same residual race: two concurrent creations could both clear
    the check and pick the same code. Migration 0004's partial unique index on
    (provider, external_ref) is the backstop -- the loser's INSERT fails and the
    caller sees a 5xx it can retry, rather than two payers sharing one code.
    At 32^6 codes against a handful of open invoices that race is theoretical;
    the check is here so a code is never silently reused after wrap-around of a
    small alphabet, not because a collision is expected.

    None means 20 consecutive candidates were all taken, which cannot happen
    with a sane number of open invoices and is surfaced as 503 rather than
    looping forever.
    """
    for _ in range(_REFERENCE_ATTEMPTS):
        candidate = generate_reference()
        if await payment_repo.get_by_external_ref(PROVIDER, candidate) is None:
            return candidate
    logger.error(
        "could not reserve a free bank-transfer reference in %d attempts",
        _REFERENCE_ATTEMPTS,
    )
    return None


def _created_at(row: dict[str, Any]) -> datetime.datetime:
    """created_at as an aware UTC datetime, whether psycopg handed back a
    datetime (real DB) or an ISO string (a fake in tests). Same helper and same
    reason as usdt_trc20._created_at."""
    ca = row["created_at"]
    if isinstance(ca, str):
        ca = datetime.datetime.fromisoformat(ca.replace("Z", "+00:00"))
    if ca.tzinfo is None:
        ca = ca.replace(tzinfo=datetime.timezone.utc)
    return ca


def _expiry_of(row: dict[str, Any]) -> datetime.datetime:
    return _created_at(row) + datetime.timedelta(seconds=INVOICE_TTL_SECONDS)


def is_expired(row: dict[str, Any], *, now: datetime.datetime | None = None) -> bool:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return now > _expiry_of(row)


def _invoice_view(
    row: dict[str, Any], *, details: dict[str, str], amount: str
) -> dict[str, Any]:
    """The payer-facing invoice. `bank` carries the same details GET
    /v1/billing/details publishes; the checkout page renders only `bank.card`
    from it, because the card number is all a payer needs to pay."""
    return {
        "payment_id": row["id"],
        "reference": row["external_ref"],
        "amount": amount,
        "currency": CURRENCY,
        "bank": dict(details),
        "expires_at": _expiry_of(row).isoformat(),
    }


async def create_invoice(
    payment_repo: Any, *, details: dict[str, str],
    payer_name: str | None = None, payer_email: str | None = None,
) -> dict[str, Any] | None:
    """Open a bank-transfer invoice for the Pro tier.

    `account_id` is deliberately None, exactly as in usdt_trc20.create_invoice:
    the account does not exist yet and is minted by grant_pro_tier at
    confirmation time, which overwrites this column anyway (see
    PaymentRepository.mark_completed). Setting it here would be a value nobody
    reads.

    `payer_name`/`payer_email` are how the operator finds this payment when the
    kopeck suffix on the amount does not survive the payer's bank converting it:
    a card transfer has no reference field, so the sender's name on the statement
    is the only handle left, and the email is the tie-breaker when two payers
    share a name. The endpoint requires both (see main.PayerContact); they stay
    Optional in this signature because rows written before card payments have
    them blank and nothing here may assume otherwise. Nothing is ever sent to
    the address -- see migration 0026.

    Returns None when the row could not be written -- no DATABASE_URL, or no
    free reference code -- so the endpoint can 503 instead of showing a payer
    an invoice that was never recorded and can therefore never be confirmed.
    """
    reference = await _reserve_reference(payment_repo)
    if reference is None:
        return None
    amount = await _reserve_unique_amount(payment_repo, pro_price_usd())
    row = await payment_repo.create(
        account_id=None, provider=PROVIDER, external_ref=reference,
        amount=float(amount), currency=CURRENCY, status="pending",
        tier_granted="pro", product=PRODUCT_PRO,
        payer_name=payer_name, payer_email=payer_email,
    )
    if row is None:
        return None
    return _invoice_view(row, details=details, amount=amount)


async def create_fixpack_invoice(
    payment_repo: Any, *, details: dict[str, str], audit_id: str,
    payer_name: str | None = None, payer_email: str | None = None,
) -> dict[str, Any] | None:
    """Open a bank-transfer invoice for a Fix Pack scoped to one audit. Same
    reference-code disambiguation as create_invoice, at the Fix Pack price and
    tagged product='fixpack' + audit_id so confirm() knows to create a
    fixpack_jobs row rather than grant a tier. Payer contact is recorded the
    same way and for the same reason as in create_invoice."""
    reference = await _reserve_reference(payment_repo)
    if reference is None:
        return None
    amount = await _reserve_unique_amount(payment_repo, fixpack_price_usd())
    row = await payment_repo.create(
        account_id=None, provider=PROVIDER, external_ref=reference,
        amount=float(amount), currency=CURRENCY, status="pending",
        tier_granted=None, product=PRODUCT_FIXPACK, audit_id=audit_id,
        payer_name=payer_name, payer_email=payer_email,
    )
    if row is None:
        return None
    view = _invoice_view(row, details=details, amount=amount)
    view["audit_id"] = audit_id
    return view


async def get_invoice(payment_repo: Any, reference: str) -> dict[str, Any] | None:
    """The payments row behind a reference code, or None. Reference codes are
    looked up per-provider, so a code that happens to collide with some other
    provider's external_ref cannot be reached from here."""
    if not reference:
        return None
    row = await payment_repo.get_by_external_ref(PROVIDER, reference)
    if row is None or row.get("provider") != PROVIDER:
        return None
    return row


async def invoice_status(
    payment_repo: Any, account_repo: Any, reference: str,
    *, details: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    """State of one invoice for the checkout page to poll. Returns None if
    there's no such invoice (endpoint -> 404).

    A completed Pro invoice mints and reveals the API key exactly once, via
    deliver_key_once -- same one-shot contract as the USDT invoice poll, and it
    matters more here: confirmation arrives hours or days later, so the tab that
    started the purchase is usually long gone. /link with the reference code is
    the recovery door for that case.

    A completed Fix Pack invoice reveals nothing: no account and no key exist
    for it. The generated fix PR shows up on the audit page instead.

    There is deliberately no distinct "awaiting confirmation" state here even
    though the payer may already have pressed "I've paid". Recording that would
    mean moving the row off status='pending', and the CAS predicate in
    mark_completed / mark_completed_fixpack only admits 'pending' (or a replay
    of the same external_ref) -- a third status would make every such payment
    permanently unconfirmable. The frontend tracks "I pressed it" locally; the
    database keeps the one status that keeps the money safe.
    """
    from app.billing import deliver_key_once

    row = await get_invoice(payment_repo, reference)
    if row is None:
        return None

    if row["status"] == "completed":
        if row.get("product") == PRODUCT_FIXPACK:
            return {
                "reference": reference,
                "status": "completed",
                "product": PRODUCT_FIXPACK,
                "audit_id": row.get("audit_id"),
            }
        api_key = await deliver_key_once(
            account_repo=account_repo, payment_repo=payment_repo, payment=row,
        )
        return {
            "reference": reference,
            "status": "completed",
            "product": PRODUCT_PRO,
            "tier": "pro",
            "api_key": api_key,
            "key_already_delivered": api_key is None,
        }

    if is_expired(row):
        # Cosmetic only -- confirm() ignores this, so a late transfer is still
        # confirmable and the payer is told so rather than told to start over.
        return {"reference": reference, "status": "expired"}

    status: dict[str, Any] = {
        "reference": reference,
        "status": "pending",
        "product": row.get("product") or PRODUCT_PRO,
        "amount": f"{float(row['amount']):.2f}" if row.get("amount") is not None else None,
        "currency": row.get("currency") or CURRENCY,
        "expires_at": _expiry_of(row).isoformat(),
    }
    if details is not None:
        status["bank"] = dict(details)
    if row.get("audit_id"):
        status["audit_id"] = row["audit_id"]
    return status


CONFIRM_CALLBACK_PREFIX = "bt_confirm:"


def _confirmation_keyboard(payment_id: str) -> dict[str, Any]:
    """The operator's one-tap confirm button. `callback_data` is capped at 64
    bytes by the Bot API; prefix plus a UUID is 47, so there is room to spare."""
    return {
        "inline_keyboard": [[{
            "text": "Confirm payment received",
            "callback_data": f"{CONFIRM_CALLBACK_PREFIX}{payment_id}",
        }]]
    }


def _notification_text(row: dict[str, Any], *, site_url: str | None = None) -> str:
    product = row.get("product") or PRODUCT_PRO
    what = "Fix Pack" if product == PRODUCT_FIXPACK else "Pro tier"
    amount = row.get("amount")
    quoted = f"{float(amount):.2f}" if amount is not None else "?"
    lines = [
        f"Bank transfer reported — {what}",
        "",
        # Amount first: the kopeck suffix is unique per open invoice, so on a
        # same-currency transfer this line alone identifies the payment.
        f"Expect exactly: {quoted} {row.get('currency') or CURRENCY}",
        f"Reference: {row.get('external_ref')}",
    ]
    # This message is the only place the payer contact from migration 0026 is
    # ever read, and it is the fallback the kopeck suffix above degrades to when
    # the payer's bank converted the amount. Rows created before card payments
    # may still have these blank, so the lines stay conditional -- a "Payer: "
    # with nothing after it tells the operator less than no line.
    payer_name = (row.get("payer_name") or "").strip()
    payer_email = (row.get("payer_email") or "").strip()
    if payer_name:
        lines.append(f"Payer: {payer_name}")
    if payer_email:
        lines.append(f"Email: {payer_email}")
    if row.get("audit_id"):
        lines.append(f"Audit: {row['audit_id']}")
        if site_url:
            lines.append(f"{site_url.rstrip('/')}/audit/{row['audit_id']}")
    lines += [
        "",
        "Find the incoming card transfer by the exact amount above — its "
        "kopecks are unique to this order. If the payer's bank converted, the "
        "kopecks are gone: match on the payer name instead and check the "
        "amount is sufficient. Only then press Confirm.",
    ]
    return "\n".join(lines)


async def mark_awaiting_confirmation(
    payment_repo: Any, reference: str, *,
    transport: Any = None, site_url: str | None = None,
) -> dict[str, Any] | None:
    """The payer pressed "I've paid": tell the operator, grant nothing.

    Writes no state at all. The row stays 'pending' (see invoice_status for why
    a third status would break confirmation), and access is granted only when a
    human has seen the money and pressed the button this notification carries.
    A payer who presses the button without paying achieves exactly nothing.

    Returns None if there's no such invoice (endpoint -> 404); otherwise a small
    dict saying whether a notification actually went out. `notified` is False for
    every quiet outcome -- alerting not configured, or notify_operator's throttle
    suppressing a repeat press of the same invoice -- and none of those are
    errors the payer should see.
    """
    from app.alerts import notify_operator

    row = await get_invoice(payment_repo, reference)
    if row is None:
        return None
    if row["status"] == "completed":
        # Already confirmed; don't page the operator to look at it again.
        return {"reference": reference, "status": "completed", "notified": False}

    notified = await notify_operator(
        _notification_text(row, site_url=site_url),
        # One notification per invoice per throttle window, so a payer
        # hammering the button can't hammer the operator's phone. The rate
        # limiter on the endpoint is what bounds a flood of DISTINCT invoices.
        dedupe_key=f"bank-transfer:{row['id']}",
        reply_markup=_confirmation_keyboard(str(row["id"])),
        transport=transport,
    )
    return {"reference": reference, "status": "pending", "notified": notified}


async def confirm(
    *, payment_repo: Any, account_repo: Any, payment_id: str,
    fixpack_repo: Any = None, audit_repo: Any = None,
) -> dict[str, Any] | None:
    """The operator confirmed the money arrived: grant what was bought.

    Dispatches on `product` exactly like usdt_trc20.poll_and_match, and always
    passes `invoice_payment_id` so the grant runs through the CAS-gated
    mark_completed / mark_completed_fixpack rather than inserting a second
    payment row. That is what makes pressing the button twice safe: the replay
    matches the same external_ref, the CAS predicate admits it, and the caller
    gets the original account or job back with no second key and no second job.

    `external_ref` is the invoice's own reference code, already on the row. It
    is deliberately not the bank's transaction id: a second press would then
    carry a DIFFERENT external_ref, the CAS gate would refuse, and a correct
    re-confirmation would look like a money anomaly.

    Expiry is not consulted. A transfer that took nine days is still a transfer.

    Returns None when there's no such bank-transfer payment. Otherwise a dict
    with `granted` False only if persistence refused (no DATABASE_URL), which
    the caller reports rather than swallowing.
    """
    from app.billing import grant_fixpack, grant_pro_tier

    row = await payment_repo.get(payment_id)
    if row is None or row.get("provider") != PROVIDER:
        return None
    reference = row.get("external_ref")
    if not reference:
        # Every invoice this module creates carries one; a row without it
        # cannot be confirmed idempotently, so refuse rather than invent a key.
        logger.error("bank-transfer payment %s has no reference", payment_id)
        return None

    product = row.get("product") or PRODUCT_PRO
    if product == PRODUCT_FIXPACK:
        granted = await grant_fixpack(
            fixpack_repo=fixpack_repo, payment_repo=payment_repo,
            audit_repo=audit_repo, provider=PROVIDER, external_ref=reference,
            amount=row.get("amount"), currency=row.get("currency") or CURRENCY,
            audit_id=row.get("audit_id"), invoice_payment_id=str(row["id"]),
        )
    else:
        granted = await grant_pro_tier(
            account_repo=account_repo, payment_repo=payment_repo,
            provider=PROVIDER, external_ref=reference,
            amount=row.get("amount"), currency=row.get("currency") or CURRENCY,
            invoice_payment_id=str(row["id"]),
        )
    return {
        "payment_id": str(row["id"]),
        "reference": reference,
        "product": product,
        "audit_id": row.get("audit_id"),
        "granted": granted is not None,
    }
