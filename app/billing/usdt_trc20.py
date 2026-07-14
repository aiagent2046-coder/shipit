"""USDT/TRC20 payment provider -- self-hosted, no third-party gateway.

Design: ONE fixed receiving address (env USDT_TRC20_ADDRESS, public --
not a secret). Invoices are disambiguated not by per-invoice addresses
but by a UNIQUE AMOUNT: a base price plus a small random sub-cent nonce.
TRC20 USDT has exactly 6 decimals, so there's a million distinct
micro-USDT slots below every whole dollar -- ample room to give each
open invoice its own exact amount. The payer sends that exact amount to
the address; a poller reads the address's incoming transfers and matches
each transfer's amount back to the invoice that requested it.

Matching is on EXACT base units, not a float tolerance. Both sides are
exact integers of micro-USDT -- TronGrid returns the transfer `value` as
an integer string of base units, and we derive each invoice's expected
base units from its stored amount -- so an exact `==` is both simpler and
stricter than a tolerance window, and can't accidentally match a
neighbouring invoice a cent away.

Invoices expire (INVOICE_TTL_SECONDS) so a released amount can be reused
and a payer isn't told to send to a stale amount forever; an expired,
still-unpaid invoice is never matched even if the exact amount arrives
later (that late payment needs manual handling -- documented, not
silently granted).

TronGrid REST: GET /v1/accounts/{address}/transactions/trc20 (confirmed
live from this sandbox, unauthenticated, 200 -- see the README). An API
key is optional and only needed for higher rate limits; when
TRONGRID_API_KEY is set it's sent as the TRON-PRO-API-KEY header.

Not exercised against a real on-chain payment: there's no funded address
or real transfer here. Outbound HTTP is injectable (`transport=`) for
tests, and scripts/verify_usdt_trc20_locally.py does a real read against
a caller-supplied address.
"""

from __future__ import annotations

import datetime
import os
import secrets
from typing import Any

import httpx

TRONGRID_API = "https://api.trongrid.io"
PROVIDER = "usdt_trc20"
CURRENCY = "USDT"
_DECIMALS = 6
_MICRO = 10 ** _DECIMALS

# Mainnet USDT (Tether) TRC20 contract. Overridable (e.g. a testnet
# contract) but defaulted so it works out of the box. Used to filter the
# address's transfers to USDT only, ignoring any other TRC20 token sent
# to the same address.
_DEFAULT_USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

# 30 minutes: comfortably longer than a TRON transfer takes to confirm
# (seconds) plus a human copy-paste-and-send delay, short enough that a
# unique amount frees up and a forgotten invoice doesn't linger.
INVOICE_TTL_SECONDS = 30 * 60

_DEFAULT_PRICE_USDT = "5"


def receiving_address_from_env() -> str | None:
    return os.environ.get("USDT_TRC20_ADDRESS") or None


def poll_token_from_env() -> str | None:
    """Bearer token protecting POST /internal/billing/poll-usdt, exactly
    like PREVIEW_REAP_TOKEN protects the reaper. Unset -> endpoint 503s."""
    return os.environ.get("USDT_POLL_TOKEN") or None


def trongrid_api_key_from_env() -> str | None:
    return os.environ.get("TRONGRID_API_KEY") or None


def usdt_contract_from_env() -> str:
    return os.environ.get("USDT_TRC20_CONTRACT") or _DEFAULT_USDT_CONTRACT


def _base_price_micros() -> int:
    raw = os.environ.get("USDT_PRICE") or _DEFAULT_PRICE_USDT
    try:
        return int(round(float(raw) * _MICRO))
    except ValueError:
        return int(round(float(_DEFAULT_PRICE_USDT) * _MICRO))


def _micros_to_amount(micros: int) -> float:
    return micros / _MICRO


def amount_to_micros(amount: float) -> int:
    """Invoice amount (USDT) -> integer base units, the matching key.
    round() not int(): 5.123456 * 1e6 is 5123455.9999 in binary float, and
    int() would truncate it to ...55. Amounts have at most 6 decimals, so
    rounding lands on the exact integer."""
    return int(round(amount * _MICRO))


async def create_invoice(
    payment_repo: Any, *, address: str
) -> dict[str, Any] | None:
    """Reserve a unique amount and persist a pending payment row (the
    invoice). Returns the payer-facing details, or None if DATABASE_URL
    isn't configured (the pending row can't be written, so there'd be
    nothing to match a payment against later -- the endpoint surfaces
    that as 503 rather than hand out an unrecorded amount).
    """
    base = _base_price_micros()
    pending = await payment_repo.list_pending(PROVIDER)
    taken = {amount_to_micros(p["amount"]) for p in pending if p.get("amount") is not None}

    micros = base + secrets.randbelow(_MICRO)  # base + 0.000000..0.999999
    # Vanishingly unlikely to collide, but a live collision would make two
    # invoices indistinguishable, so re-roll off any active amount.
    for _ in range(50):
        if micros not in taken:
            break
        micros = base + secrets.randbelow(_MICRO)

    amount = _micros_to_amount(micros)
    row = await payment_repo.create(
        account_id=None, provider=PROVIDER, external_ref=None,
        amount=amount, currency=CURRENCY, status="pending", tier_granted="pro",
    )
    if row is None:
        return None
    return {
        "invoice_id": row["id"],
        "network": "TRC20",
        "address": address,
        "amount": amount,
        "currency": CURRENCY,
        "expires_at": _expiry_of(row).isoformat(),
    }


def _created_at(row: dict[str, Any]) -> datetime.datetime:
    """created_at as an aware UTC datetime, whether psycopg handed back a
    datetime (real DB) or an ISO string (a fake in tests)."""
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


async def invoice_status(
    payment_repo: Any, account_repo: Any, invoice_id: str, *, address: str,
) -> dict[str, Any] | None:
    """State of one invoice for the checkout page to poll. Reveals the
    api_key ONLY once the invoice is completed (the payer proved payment
    by sending the exact amount); a pending/expired invoice never leaks a
    key. Returns None if there's no such invoice (endpoint -> 404)."""
    row = await payment_repo.get(invoice_id)
    if row is None or row.get("provider") != PROVIDER:
        return None

    if row["status"] == "completed":
        account = await account_repo.get_by_id(row["account_id"]) if row.get("account_id") else None
        return {
            "invoice_id": row["id"],
            "status": "completed",
            "tier": "pro",
            # The whole point of the poll: hand back the key once paid.
            "api_key": account["api_key"] if account else None,
        }

    if is_expired(row):
        return {"invoice_id": row["id"], "status": "expired"}

    return {
        "invoice_id": row["id"],
        "status": "pending",
        "network": "TRC20",
        "address": address,
        "amount": row["amount"],
        "currency": CURRENCY,
        "expires_at": _expiry_of(row).isoformat(),
    }


async def fetch_transfers(
    address: str, *, api_key: str | None = None, limit: int = 50,
    transport: httpx.BaseTransport | None = None,
) -> list[dict[str, Any]]:
    """Incoming TRC20 transfers to `address`, USDT only. `only_to=true`
    asks TronGrid for transfers where the address is the recipient; we
    still re-check `to` and the contract ourselves rather than trust the
    filter. Raises TronGridError on a non-2xx or success=false body."""
    headers = {"TRON-PRO-API-KEY": api_key} if api_key else {}
    params = {
        "only_to": "true",
        "limit": str(limit),
        "contract_address": usdt_contract_from_env(),
    }
    async with httpx.AsyncClient(
        base_url=TRONGRID_API, timeout=30, transport=transport, headers=headers
    ) as client:
        resp = await client.get(
            f"/v1/accounts/{address}/transactions/trc20", params=params
        )
        if resp.status_code >= 300:
            raise TronGridError(f"trongrid {resp.status_code}: {resp.text[:300]}")
        body = resp.json()
    if not body.get("success", False):
        raise TronGridError(f"trongrid success=false: {str(body)[:300]}")
    return body.get("data", [])


class TronGridError(Exception):
    """TronGrid returned a non-2xx response or success=false."""


async def poll_and_match(
    payment_repo: Any, account_repo: Any, *, address: str,
    api_key: str | None = None, transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Read incoming USDT transfers and complete any pending invoice whose
    exact amount arrived. Idempotent per transfer via external_ref (a tx
    seen on a later poll is skipped). Returns a small summary for the
    caller/scheduler to log."""
    from app.billing import grant_pro_tier

    transfers = await fetch_transfers(
        address, api_key=api_key, transport=transport
    )
    usdt_contract = usdt_contract_from_env()

    pending = await payment_repo.list_pending(PROVIDER)
    now = datetime.datetime.now(datetime.timezone.utc)
    # Exact-base-units -> invoice, expired ones excluded so a late payment
    # to a dead invoice's amount is never auto-granted.
    by_micros: dict[int, dict[str, Any]] = {}
    for inv in pending:
        if inv.get("amount") is None or is_expired(inv, now=now):
            continue
        by_micros[amount_to_micros(inv["amount"])] = inv

    matched = 0
    for tr in transfers:
        if tr.get("type") != "Transfer" or tr.get("to") != address:
            continue
        if (tr.get("token_info") or {}).get("address") != usdt_contract:
            continue
        try:
            value = int(tr["value"])
        except (KeyError, ValueError, TypeError):
            continue
        inv = by_micros.get(value)
        if inv is None:
            continue
        tx_id = tr.get("transaction_id")
        if not tx_id:
            continue
        # Skip a transfer already applied (idempotency across polls).
        seen = await payment_repo.get_by_external_ref(PROVIDER, tx_id)
        if seen is not None:
            continue
        granted = await grant_pro_tier(
            account_repo=account_repo, payment_repo=payment_repo,
            provider=PROVIDER, external_ref=tx_id,
            amount=inv["amount"], currency=CURRENCY,
            invoice_payment_id=inv["id"],
        )
        if granted is not None:
            matched += 1
            # One invoice per amount: don't let a second identical transfer
            # in the same batch re-consume it.
            by_micros.pop(value, None)

    return {"checked": len(transfers), "pending": len(pending), "matched": matched}
