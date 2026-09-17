"""Generated payment histories against real Postgres, never fake repositories.

Every prefix of a history must preserve one account per settled charge and the
invoice/charge association chosen by the first successful settlement. These
sequential properties complement the concurrent/rollback cases in
test_billing_concurrency_postgres.py; they do not establish race safety alone.

Each Hypothesis example owns fresh database state and closes its pool before
asyncio.run closes the event loop. DATABASE_URL is captured before conftest's
autouse fixture removes it; without it these tests are explicitly skipped.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from decimal import Decimal
import os

from hypothesis import given, settings, strategies as st
import pytest

from app import db
from app.billing import grant_pro_tier


_DB_URL = os.environ.get("DATABASE_URL")
_PROVIDER = "bank_transfer"
_AMOUNT = Decimal("5.13")

pytestmark = pytest.mark.skipif(
    not _DB_URL,
    reason="real-Postgres payment properties: set DATABASE_URL to a disposable Postgres",
)


@st.composite
def _replayed_charges(draw):
    size = draw(st.integers(min_value=2, max_value=3))
    repeats = draw(st.lists(st.integers(2, 4), min_size=size, max_size=size))
    events = tuple(index for index, count in enumerate(repeats) for _ in range(count))
    return size, draw(st.permutations(events))


@st.composite
def _invoice_charge_histories(draw):
    size = draw(st.integers(min_value=2, max_value=3))
    # Include every potential association plus a replay for each diagonal.
    # Order determines which associations are valid, so the oracle tracks
    # successful first claims rather than assuming invoice i owns charge i.
    events = tuple((invoice, charge) for invoice in range(size) for charge in range(size))
    events += tuple((index, index) for index in range(size))
    return size, draw(st.permutations(events))


@asynccontextmanager
async def _fresh_ledger():
    assert _DB_URL is not None
    # A function-scoped pytest fixture would run once for all generated
    # examples. Own setup/cleanup here instead; no health checks are disabled.
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("DATABASE_URL", _DB_URL)
        patch.setenv("API_KEY_PEPPER", "payment-properties-test-pepper")
        await db.close_pool()
        pool = await db.get_pool()
        try:
            async with pool.connection() as conn:
                await conn.execute("truncate accounts, payments cascade")
            yield pool
        finally:
            try:
                async with pool.connection() as conn:
                    await conn.execute("truncate accounts, payments cascade")
            finally:
                await db.close_pool()


def _reference(index):
    return f"PBT-CHARGE-{index}"


async def _invoice(payments):
    invoice = await payments.create(
        account_id=None, provider=_PROVIDER, external_ref=None,
        amount=float(_AMOUNT), currency="USD", status="pending",
        tier_granted=None, product="pro_tier",
    )
    assert invoice is not None
    return str(invoice["id"])


async def _confirm(payments, charge, invoice_id=None):
    return await grant_pro_tier(
        payment_repo=payments, provider=_PROVIDER,
        external_ref=_reference(charge), amount=float(_AMOUNT), currency="USD",
        invoice_payment_id=invoice_id,
    )


async def _ledger(pool):
    async with pool.connection() as conn:
        accounts = await (await conn.execute("select * from accounts order by id")).fetchall()
        payments = await (await conn.execute("select * from payments order by id")).fetchall()
    return accounts, payments


def _assert_settled(payment, charge, account_id):
    assert str(payment["account_id"]) == account_id
    assert payment["provider"] == _PROVIDER
    assert payment["external_ref"] == _reference(charge)
    assert payment["status"] == "completed"
    assert payment["product"] == "pro_tier"
    assert payment["tier_granted"] == "pro"
    assert payment["amount"] == _AMOUNT
    assert payment["currency"] == "USD"


@pytest.mark.parametrize("with_invoice", [False, True])
@settings(max_examples=16, deadline=None)
@given(history=_replayed_charges())
def test_reordered_replays_preserve_independent_grants(with_invoice, history):
    async def exercise():
        size, events = history
        async with _fresh_ledger() as pool:
            payments = db.PaymentRepository()
            invoices = [await _invoice(payments) for _ in range(size)] if with_invoice else []
            granted = {}
            keys = set()
            payment_ids = {}

            for charge in events:
                account = await _confirm(
                    payments, charge, invoices[charge] if with_invoice else None,
                )
                assert account is not None
                account_id = str(account["id"])
                if charge in granted:
                    assert account_id == granted[charge]
                    assert account.get("api_key") is None
                else:
                    assert account_id not in granted.values()
                    assert account.get("api_key")
                    assert account["api_key"] not in keys
                    granted[charge] = account_id
                    keys.add(account["api_key"])

                accounts, rows = await _ledger(pool)
                assert {str(row["id"]) for row in accounts} == set(granted.values())
                assert all(row["tier"] == "pro" for row in accounts)
                assert len(rows) == (size if with_invoice else len(granted))
                for index, bound_account in granted.items():
                    matches = [row for row in rows if row["external_ref"] == _reference(index)]
                    assert len(matches) == 1
                    row = matches[0]
                    _assert_settled(row, index, bound_account)
                    payment_id = str(row["id"])
                    assert payment_ids.setdefault(index, payment_id) == payment_id
                    if with_invoice:
                        assert payment_id == invoices[index]
                if with_invoice:
                    for index in set(range(size)) - granted.keys():
                        pending = next(row for row in rows if str(row["id"]) == invoices[index])
                        assert pending["status"] == "pending"
                        assert pending["account_id"] is None
                        assert pending["external_ref"] is None

            assert len(granted) == len(keys) == size

    asyncio.run(exercise())


@settings(max_examples=16, deadline=None)
@given(history=_invoice_charge_histories())
def test_first_settlement_owns_invoice_and_charge_through_conflicting_replays(history):
    async def exercise():
        size, events = history
        async with _fresh_ledger() as pool:
            payments = db.PaymentRepository()
            invoices = [await _invoice(payments) for _ in range(size)]
            invoice_charge = {}
            charge_invoice = {}
            account_by_invoice = {}

            for invoice, charge in events:
                before = await _ledger(pool)
                conflict = (
                    invoice in invoice_charge and invoice_charge[invoice] != charge
                ) or (charge in charge_invoice and charge_invoice[charge] != invoice)
                account = await _confirm(payments, charge, invoices[invoice])
                if conflict:
                    assert account is None
                    assert await _ledger(pool) == before
                elif invoice in invoice_charge:
                    assert account is not None
                    assert str(account["id"]) == account_by_invoice[invoice]
                    assert account.get("api_key") is None
                else:
                    assert account is not None and account.get("api_key")
                    account_id = str(account["id"])
                    assert account_id not in account_by_invoice.values()
                    invoice_charge[invoice] = charge
                    charge_invoice[charge] = invoice
                    account_by_invoice[invoice] = account_id

                accounts, rows = await _ledger(pool)
                assert {str(row["id"]) for row in accounts} == set(account_by_invoice.values())
                assert len(rows) == size
                by_id = {str(row["id"]): row for row in rows}
                for index, invoice_id in enumerate(invoices):
                    row = by_id[invoice_id]
                    if index in invoice_charge:
                        _assert_settled(row, invoice_charge[index], account_by_invoice[index])
                    else:
                        assert row["status"] == "pending"
                        assert row["account_id"] is None
                        assert row["external_ref"] is None

            # Every pairing was attempted: no unmatched invoice and charge
            # can remain. Conflicting attempts must not block unrelated grants.
            assert len(invoice_charge) == len(charge_invoice) == size

    asyncio.run(exercise())
