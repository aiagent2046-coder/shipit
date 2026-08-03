"""Real-Postgres concurrency tests for the money paths.

These cannot be written with fakes. Every race here lives in the gap between a
read and a write on one row, and a fake dict has no such gap -- an
asyncio.gather over two fake-backed calls interleaves at await points that the
real driver does not share. The bug this file pins shipped precisely because
the fake-backed suite could not express it.

SKIPPED unless DATABASE_URL is set, following tests/test_db_postgres_smoke.py:
the value is captured at IMPORT time because conftest's autouse fixture deletes
it before any test body runs.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from app import db
from app.billing import grant_pro_tier


_DB_URL = os.environ.get("DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not _DB_URL,
    reason=(
        "real-Postgres concurrency test: set DATABASE_URL to a live Postgres "
        "(CI does; local runs without it are skipped)"
    ),
)


@pytest.fixture
async def live_db(monkeypatch):
    """A clean accounts/payments pair on the CI database, with the pool torn
    down afterwards so each test starts from a known state."""
    monkeypatch.setenv("DATABASE_URL", _DB_URL)
    monkeypatch.setenv("API_KEY_PEPPER", "concurrency-test-pepper")

    await db.close_pool()
    pool = await db.get_pool()
    async with pool.connection() as conn:
        await conn.execute("truncate accounts, payments cascade")
    yield pool
    await db.close_pool()


async def _count(pool, sql: str, params=()) -> int:
    async with pool.connection() as conn:
        cur = await conn.execute(sql, params)
        row = await cur.fetchone()
        return next(iter(row.values()))


async def _open_invoice(payments) -> dict:
    """A bank-transfer invoice as the payer was shown it: pending, no
    external_ref yet, no account."""
    return await payments.create(
        account_id=None, provider="bank_transfer", external_ref=None,
        amount=5.13, currency="USD", status="pending",
        tier_granted=None, product="pro_tier",
    )


class _BarrierAtTheRead(db.PaymentRepository):
    """A real PaymentRepository that pauses each caller just after it reads the
    payment, until both callers have read it or a short deadline passes.

    Without this the test is not a test. `asyncio.gather` over two grants
    interleaves wherever the driver happens to yield, so whether the two reads
    both land before either mint depends on pool warmth and scheduling -- the
    first version of this test passed against the broken code as often as it
    failed. The barrier makes the window certain in BOTH directions:

      * unguarded, both callers pass the read and then both mint;
      * with grant_lock held, the loser cannot even reach the read until the
        winner is done, so it never arrives -- hence the deadline rather than a
        plain barrier, which would hang forever waiting for it.
    """

    def __init__(self, expected: int, deadline: float = 0.5) -> None:
        super().__init__()
        self._barrier = asyncio.Barrier(expected)
        self._deadline = deadline

    async def get_by_external_ref(self, provider: str, external_ref: str):
        row = await super().get_by_external_ref(provider, external_ref)
        try:
            async with asyncio.timeout(self._deadline):
                await self._barrier.wait()
        except (TimeoutError, asyncio.BrokenBarrierError):
            # Serialized after all: the other caller is behind a lock and will
            # never join us here. That IS the fix working.
            pass
        return row


async def test_two_concurrent_confirmations_grant_exactly_one_account(live_db):
    """The bug, reproduced. An operator double-tapping Confirm, or two
    operators on the same invoice, used to produce:

        accounts in DB:       2
        returned account ids: 2 distinct
        keys handed out:      2
        ORPHANED accounts:    1

    Two Pro accounts for one payment, and one of the two keys handed out
    pointed at an account the payment does not reference -- so /mykey and
    /rotatekey for that payer led nowhere.
    """
    accounts = db.AccountRepository()
    payments = _BarrierAtTheRead(expected=2)
    invoice = await _open_invoice(payments)
    reference = "DRY-RACE01"

    async def confirm():
        return await grant_pro_tier(
            account_repo=accounts, payment_repo=payments,
            provider="bank_transfer", external_ref=reference,
            amount=5.13, currency="USD",
            invoice_payment_id=str(invoice["id"]),
        )

    first, second = await asyncio.gather(confirm(), confirm())

    assert await _count(live_db, "select count(*) from accounts") == 1

    # Both callers report success -- the grant did happen, and telling the
    # loser otherwise would make an operator press Confirm a third time.
    assert first is not None and second is not None
    assert str(first["id"]) == str(second["id"])

    # Exactly one plaintext key exists, because only the winner minted one.
    # This is the assertion that matters most: two keys meant one payer held a
    # credential for an account nothing referenced.
    assert sum(1 for r in (first, second) if r.get("api_key")) == 1

    linked = await _count(
        live_db, "select count(*) from payments where account_id = %s",
        (first["id"],),
    )
    assert linked == 1


async def test_the_lock_does_not_serialize_unrelated_charges(live_db):
    """The lock key is derived from (provider, external_ref), not global. Two
    different payers confirming at the same moment must not queue behind each
    other -- and each must get its own account and its own key."""
    accounts, payments = db.AccountRepository(), db.PaymentRepository()
    one, two = await _open_invoice(payments), await _open_invoice(payments)

    async def confirm(invoice, reference):
        return await grant_pro_tier(
            account_repo=accounts, payment_repo=payments,
            provider="bank_transfer", external_ref=reference,
            amount=5.13, currency="USD",
            invoice_payment_id=str(invoice["id"]),
        )

    first, second = await asyncio.gather(
        confirm(one, "DRY-AAA111"), confirm(two, "DRY-BBB222"),
    )

    assert await _count(live_db, "select count(*) from accounts") == 2
    assert str(first["id"]) != str(second["id"])
    assert first.get("api_key") and second.get("api_key")
    assert first["api_key"] != second["api_key"]


async def test_a_sequential_replay_is_still_idempotent(live_db):
    """The path that must NOT change. A retried webhook or a transfer seen on
    a second poll arrives after the first grant committed, returns the same
    account, and mints no key -- that contract predates this fix and several
    callers depend on it (they fall back to deliver_key_once)."""
    accounts, payments = db.AccountRepository(), db.PaymentRepository()
    invoice = await _open_invoice(payments)
    reference = "DRY-REPLAY"

    async def confirm():
        return await grant_pro_tier(
            account_repo=accounts, payment_repo=payments,
            provider="bank_transfer", external_ref=reference,
            amount=5.13, currency="USD",
            invoice_payment_id=str(invoice["id"]),
        )

    first = await confirm()
    second = await confirm()

    assert await _count(live_db, "select count(*) from accounts") == 1
    assert str(first["id"]) == str(second["id"])
    assert first.get("api_key")           # the winner delivers the key
    assert second.get("api_key") is None  # the replay cannot, by design


async def test_mark_completed_refuses_to_move_a_linked_account(live_db):
    """The backstop, tested directly rather than through a race.

    Even with the lock bypassed entirely, the account_id on a completed
    payment can never be reassigned. This is what makes the fix money-safe if
    the lock is ever unavailable -- see grant_lock's timeout path.
    """
    accounts, payments = db.AccountRepository(), db.PaymentRepository()
    invoice = await _open_invoice(payments)

    winner = await accounts.create(api_key="k1-" + "a" * 30, tier="pro")
    loser = await accounts.create(api_key="k2-" + "b" * 30, tier="pro")

    linked = await payments.mark_completed(
        str(invoice["id"]), account_id=str(winner["id"]),
        external_ref="DRY-SAMEREF",
    )
    assert linked is not None

    # Same external_ref -- the branch that used to admit this and overwrite.
    refused = await payments.mark_completed(
        str(invoice["id"]), account_id=str(loser["id"]),
        external_ref="DRY-SAMEREF",
    )
    assert refused is None

    still = await _count(
        live_db, "select count(*) from payments where id = %s and account_id = %s",
        (invoice["id"], winner["id"]),
    )
    assert still == 1


async def test_the_kopeck_lock_degrades_instead_of_crashing(live_db, caplog):
    """Not this fix, but found while making it, and it belongs with the other
    money-path concurrency proofs.

    app/db.py had no `import logging` and no module `logger`, while
    bank_transfer_amount_lock's saturation path called logger.warning. That
    path only runs after ~1s of real contention, so no test reached it -- and
    in production it would have raised NameError from the very branch whose job
    is to degrade gracefully. Here the lock is held from another connection, so
    the retry budget is exhausted for real and the branch executes.
    """
    entered = False

    async with live_db.connection() as holder:
        await holder.execute(
            "select pg_advisory_lock(%s)", (db._BANK_TRANSFER_AMOUNT_LOCK_KEY,)
        )
        try:
            with caplog.at_level("WARNING"):
                async with db.bank_transfer_amount_lock():
                    entered = True
        finally:
            await holder.execute(
                "select pg_advisory_unlock(%s)",
                (db._BANK_TRANSFER_AMOUNT_LOCK_KEY,),
            )

    # It yielded anyway rather than raising -- graceful degradation, as
    # designed -- and said so.
    assert entered
    assert any("reserving without it" in r.message for r in caplog.records)


# --- a Fix Pack must not take away a Pro payer's key ---
#
# /link stamped the chat onto the payment BEFORE checking whether that payment
# grants an account. A Fix Pack grants none by design -- it is delivered as a
# pull request -- so a Pro customer who ran /link with a Fix Pack reference
# ended up with the chat pointing at an account-less row.
#
# /mykey and /rotatekey read the NEWEST completed payment carrying the chat.
# The Fix Pack, being the later purchase, won. Both answered "no account" from
# then on, permanently: nothing unlinks a chat.
#
# Real Postgres because the whole defect lives in `order by created_at desc
# limit 1` over two rows -- a fake returning one dict cannot express it.


async def _completed_pro(payments, accounts, chat_id: str) -> dict:
    account = await accounts.create(api_key="pro-" + "a" * 28, tier="pro")
    invoice = await payments.create(
        account_id=None, provider="bank_transfer", external_ref=None,
        amount=5.13, currency="USD", status="pending",
        tier_granted=None, product="pro_tier",
    )
    await payments.mark_completed(
        str(invoice["id"]), account_id=str(account["id"]),
        external_ref="DRY-PROAA2",
    )
    await payments.link_telegram_chat_id(str(invoice["id"]), chat_id)
    return account


async def _completed_fixpack(payments, chat_id: str | None) -> dict:
    invoice = await payments.create(
        account_id=None, provider="bank_transfer", external_ref=None,
        amount=29.07, currency="USD", status="pending",
        tier_granted=None, product="fixpack",
    )
    await payments.mark_completed_fixpack(
        str(invoice["id"]), external_ref="DRY-FXPK23",
    )
    if chat_id is not None:
        await payments.link_telegram_chat_id(str(invoice["id"]), chat_id)
    return invoice


async def test_a_newer_fixpack_does_not_hide_the_pro_account(live_db):
    """The repair, and the half that acts retroactively: anyone already in
    this state gets their key recovery back on deploy, with no data surgery."""
    accounts, payments = db.AccountRepository(), db.PaymentRepository()
    chat = "555001"

    account = await _completed_pro(payments, accounts, chat)
    await _completed_fixpack(payments, chat)   # later, and account-less

    found = await payments.get_completed_by_telegram_chat_id(chat)

    assert found is not None, "/mykey would answer 'no account'"
    assert str(found["account_id"]) == str(account["id"])
    assert found["product"] == "pro_tier"


async def test_a_chat_with_only_a_fixpack_still_has_no_account(live_db):
    """The boundary. The predicate must not invent an account for someone who
    genuinely has none -- a Fix Pack buyer who never bought Pro."""
    payments = db.PaymentRepository()
    chat = "555002"

    await _completed_fixpack(payments, chat)

    assert await payments.get_completed_by_telegram_chat_id(chat) is None


async def test_the_newest_pro_payment_still_wins(live_db):
    """Two Pro payments on one chat -- an upgrade, a re-purchase after a
    refund -- must still resolve to the later one. The fix narrows which rows
    are considered, not the ordering among them."""
    accounts, payments = db.AccountRepository(), db.PaymentRepository()
    chat = "555003"

    await _completed_pro(payments, accounts, chat)
    second = await accounts.create(api_key="pro-" + "b" * 28, tier="pro")
    invoice = await payments.create(
        account_id=None, provider="bank_transfer", external_ref=None,
        amount=5.14, currency="USD", status="pending",
        tier_granted=None, product="pro_tier",
    )
    await payments.mark_completed(
        str(invoice["id"]), account_id=str(second["id"]),
        external_ref="DRY-PROAA3",
    )
    await payments.link_telegram_chat_id(str(invoice["id"]), chat)

    found = await payments.get_completed_by_telegram_chat_id(chat)
    assert str(found["account_id"]) == str(second["id"])
