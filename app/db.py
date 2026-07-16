"""Postgres persistence for audits and fixpack_jobs. Minimal scope --
see migrations/0001_audits_and_fixpack_jobs.sql for what was trimmed
from shipit-architecture.md 2.5's full schema and why.

Optional, not required: `DatabaseNotConfigured` is raised by `get_pool`
when `DATABASE_URL` isn't set, and both repositories below catch it and
return `None` from `create`/`get` instead of failing the request --
same pattern as GITHUB_PR_TOKEN, GITHUB_APP_ID, PREVIEW_REAP_TOKEN
elsewhere in this codebase. app/main.py surfaces whether persistence
actually happened (`"persisted": true/false`) rather than hiding it.

Driver: psycopg3, not asyncpg. Tried asyncpg first -- schema and SQL
were verified for real against a real Supabase Postgres 17 project via
the Supabase migration tool, but asyncpg itself hung indefinitely (no
error) on the very first parameterized query through Supabase's
Supavisor pooler, in BOTH session (5432) and transaction (6543) modes,
confirmed by hand across two networks. That's a documented, open
Supabase-side bug (github.com/supabase/supabase/issues/39227), not a
Drydock bug or a network issue -- `psql`'s \\bind (same wire-level
extended protocol, different client implementation) worked fine over
the identical connection, which is what pointed at the client library
rather than the network. `prepare_threshold=None` below disables
psycopg's server-side statement preparation, matching the workaround
that avoids the class of pooler incompatibility entirely (psycopg
wraps real libpq, the same library psql uses).

What is NOT proven from this sandbox: this exact driver code
connecting over the wire to the real project (DATABASE_URL contains a
password and is a raw Postgres-protocol secret, not something safe to
proxy into this sandbox). See scripts/verify_db_locally.py -- run by
the user, with their own DATABASE_URL, never sent here. It DID get run
by hand against the real project during this migration and confirmed
working end to end.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import os
import uuid
from typing import Any

from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

DATABASE_URL_ENV = "DATABASE_URL"

_pool: AsyncConnectionPool | None = None
_pool_lock = asyncio.Lock()


class DatabaseNotConfigured(Exception):
    """DATABASE_URL isn't set. Distinct from a real connection failure
    (bad host, bad password, etc.), which should propagate as a loud
    error, not get treated as "not configured"."""


def database_url_from_env() -> str | None:
    return os.environ.get(DATABASE_URL_ENV) or None


async def get_pool() -> AsyncConnectionPool:
    global _pool
    if _pool is not None:
        return _pool
    # Lock so concurrent first-callers don't each build+open a pool (the
    # loser's pool would leak, never closed). Re-check inside: another
    # caller may have finished while we waited.
    async with _pool_lock:
        if _pool is None:
            url = database_url_from_env()
            if not url:
                raise DatabaseNotConfigured(f"{DATABASE_URL_ENV} is not set")
            # prepare_threshold=None: disables psycopg's server-side statement
            # preparation entirely -- see the module docstring for why. Without
            # this, the pool hangs on the first parameterized query through
            # Supabase's Supavisor pooler, confirmed by hand.
            pool = AsyncConnectionPool(
                url, min_size=1, max_size=5, open=False,
                kwargs={"prepare_threshold": None, "row_factory": dict_row},
            )
            # Publish to _pool only after open() succeeds: a failed open
            # (bad password, transient blip) leaves _pool None so the next
            # call retries, instead of caching a broken pool forever.
            await pool.open()
            _pool = pool
    return _pool


async def close_pool() -> None:
    """For tests/shutdown -- lets a fresh get_pool() reconnect."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


def _json_field(value: Any) -> Any:
    """jsonb columns: psycopg3 may hand back an already-parsed
    dict/list, or a raw string depending on codec registration --
    handle both rather than assume one."""
    if value is None:
        return None
    return json.loads(value) if isinstance(value, str) else value


def _row_to_audit(row: dict[str, Any]) -> dict[str, Any]:
    d = dict(row)
    d["id"] = str(d["id"])
    # score_total is a Postgres `numeric`, which psycopg3 hands back as a
    # decimal.Decimal -> a JSON *string* under the default encoder. Cast to
    # float so it serializes as a number, matching score_json.total (both
    # rounded to 1 dp -- see app/scan/scoring.py).
    if d.get("score_total") is not None:
        d["score_total"] = round(float(d["score_total"]), 1)
    d["score_json"] = _json_field(d["score_json"])
    d["findings_json"] = _json_field(d["findings_json"])
    return d


def _row_to_fixpack_job(row: dict[str, Any]) -> dict[str, Any]:
    d = dict(row)
    d["id"] = str(d["id"])
    d["audit_id"] = str(d["audit_id"]) if d["audit_id"] else None
    return d


def _row_to_account(row: dict[str, Any]) -> dict[str, Any]:
    d = dict(row)
    d["id"] = str(d["id"])
    return d


def _row_to_payment(row: dict[str, Any]) -> dict[str, Any]:
    d = dict(row)
    d["id"] = str(d["id"])
    d["account_id"] = str(d["account_id"]) if d["account_id"] else None
    # amount is a Postgres `numeric` -> decimal.Decimal -> a JSON *string*
    # under the default encoder; cast to float so it serializes as a number,
    # same fix as score_total in _row_to_audit.
    if d.get("amount") is not None:
        d["amount"] = float(d["amount"])
    return d


class AuditRepository:
    """Real-Postgres-backed by default. Tests use an in-memory fake
    with the same method signatures instead of this class -- see
    tests/test_db.py."""

    async def create(
        self, *, stack: str, file_count: int,
        score_total: float | None, score_json: dict | None,
        findings_json: list | None,
    ) -> dict[str, Any] | None:
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into audits (stack, file_count, score_total, score_json, findings_json)
                values (%s, %s, %s, %s::jsonb, %s::jsonb)
                returning id, stack, status, file_count, score_total,
                          score_json, findings_json, created_at
                """,
                (
                    stack, file_count, score_total,
                    json.dumps(score_json) if score_json is not None else None,
                    json.dumps(findings_json) if findings_json is not None else None,
                ),
            )
            row = await cur.fetchone()
        return _row_to_audit(row)

    async def get(self, audit_id: str) -> dict[str, Any] | None:
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        try:
            parsed_id = uuid.UUID(audit_id)
        except ValueError:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, stack, status, file_count, score_total,
                       score_json, findings_json, created_at
                from audits where id = %s
                """,
                (parsed_id,),
            )
            row = await cur.fetchone()
        return _row_to_audit(row) if row else None


class FixpackJobRepository:
    """Same real/fake split as AuditRepository -- see tests/test_db.py."""

    async def create(
        self, *, audit_id: str | None, pack: str, stack: str,
        verified: bool | None, detail: str,
        preview_local_url: str | None, preview_expires_at: float | None,
    ) -> dict[str, Any] | None:
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        parsed_audit_id = uuid.UUID(audit_id) if audit_id else None
        expires_dt = None
        if preview_expires_at is not None:
            expires_dt = datetime.datetime.fromtimestamp(
                preview_expires_at, tz=datetime.timezone.utc
            )
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into fixpack_jobs
                    (audit_id, pack, stack, verified, detail,
                     preview_local_url, preview_expires_at)
                values (%s, %s, %s, %s, %s, %s, %s)
                returning id, audit_id, pack, stack, verified, detail,
                          preview_local_url, preview_expires_at,
                          pr_url, pr_delivered, created_at
                """,
                (parsed_audit_id, pack, stack, verified, detail,
                 preview_local_url, expires_dt),
            )
            row = await cur.fetchone()
        return _row_to_fixpack_job(row)

    async def mark_delivered(self, job_id: str, pr_url: str) -> None:
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return
        async with pool.connection() as conn:
            await conn.execute(
                "update fixpack_jobs set pr_url = %s, pr_delivered = true where id = %s",
                (pr_url, uuid.UUID(job_id)),
            )

    async def get(self, job_id: str) -> dict[str, Any] | None:
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        try:
            parsed_id = uuid.UUID(job_id)
        except ValueError:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, audit_id, pack, stack, verified, detail,
                       preview_local_url, preview_expires_at,
                       pr_url, pr_delivered, created_at
                from fixpack_jobs where id = %s
                """,
                (parsed_id,),
            )
            row = await cur.fetchone()
        return _row_to_fixpack_job(row) if row else None


class AccountRepository:
    """Accounts for the paywall foundation (see app/accounts.py). Same
    real/fake split and not-configured contract as AuditRepository: when
    DATABASE_URL isn't set, create/get_by_api_key return None instead of
    failing, so a request carrying an API key on an unconfigured
    deployment simply falls back to anonymous/free.

    No public create-account endpoint exists (that would be an abuse
    hole) -- create() is used by Stage 2's payment flow and by tests."""

    async def create(self, *, api_key: str, tier: str) -> dict[str, Any] | None:
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into accounts (api_key, tier)
                values (%s, %s)
                returning id, api_key, tier, created_at
                """,
                (api_key, tier),
            )
            row = await cur.fetchone()
        return _row_to_account(row)

    async def get_by_api_key(self, api_key: str) -> dict[str, Any] | None:
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, api_key, tier, created_at
                from accounts where api_key = %s
                """,
                (api_key,),
            )
            row = await cur.fetchone()
        return _row_to_account(row) if row else None

    async def get_by_id(self, account_id: str) -> dict[str, Any] | None:
        """Look up an account by its uuid. Used by Stage 2's billing flow
        to re-fetch the just-granted account (and its api_key) for
        delivery -- e.g. re-sending the key on a duplicate Telegram
        webhook, or revealing it from the USDT invoice-status endpoint."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        try:
            parsed_id = uuid.UUID(account_id)
        except ValueError:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, api_key, tier, created_at
                from accounts where id = %s
                """,
                (parsed_id,),
            )
            row = await cur.fetchone()
        return _row_to_account(row) if row else None


class PaymentRepository:
    """Generic purchase records for the paywall foundation. Schema only in
    Stage 1 -- no payment provider writes here yet; this exists so Stage
    2's providers have a place to record attempts/completions. Minimal
    create/get pair, matching AuditRepository's shape and not-configured
    contract."""

    async def create(
        self, *, account_id: str | None, provider: str,
        external_ref: str | None, amount: float | None, currency: str | None,
        status: str, tier_granted: str | None,
    ) -> dict[str, Any] | None:
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        parsed_account_id = uuid.UUID(account_id) if account_id else None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into payments
                    (account_id, provider, external_ref, amount, currency,
                     status, tier_granted)
                values (%s, %s, %s, %s, %s, %s, %s)
                returning id, account_id, provider, external_ref, amount,
                          currency, status, tier_granted, created_at
                """,
                (parsed_account_id, provider, external_ref, amount, currency,
                 status, tier_granted),
            )
            row = await cur.fetchone()
        return _row_to_payment(row)

    async def get(self, payment_id: str) -> dict[str, Any] | None:
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        try:
            parsed_id = uuid.UUID(payment_id)
        except ValueError:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, account_id, provider, external_ref, amount,
                       currency, status, tier_granted, created_at
                from payments where id = %s
                """,
                (parsed_id,),
            )
            row = await cur.fetchone()
        return _row_to_payment(row) if row else None

    async def get_by_external_ref(
        self, provider: str, external_ref: str
    ) -> dict[str, Any] | None:
        """Idempotency lookup for Stage 2: a provider's charge/transaction
        id resolves to at most one payment (see migration 0004's partial
        unique index). Used to avoid double-granting on a retried Telegram
        webhook or a TRC20 transfer seen on more than one poll."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, account_id, provider, external_ref, amount,
                       currency, status, tier_granted, created_at
                from payments where provider = %s and external_ref = %s
                """,
                (provider, external_ref),
            )
            row = await cur.fetchone()
        return _row_to_payment(row) if row else None

    async def list_pending(self, provider: str) -> list[dict[str, Any]]:
        """Open (unpaid) invoices for a provider, newest first. Used by the
        USDT poller to match incoming on-chain transfers to invoices it
        hasn't seen paid yet. Returns [] when DATABASE_URL isn't set, same
        not-configured contract as create/get (an empty list, not None, so
        callers can iterate without a guard)."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return []
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, account_id, provider, external_ref, amount,
                       currency, status, tier_granted, created_at
                from payments
                where provider = %s and status = 'pending'
                order by created_at desc
                """,
                (provider,),
            )
            rows = await cur.fetchall()
        return [_row_to_payment(r) for r in rows]

    async def mark_completed(
        self, payment_id: str, *, account_id: str, external_ref: str
    ) -> None:
        """Transition a pending invoice to completed and link the account
        it granted. The USDT flow's counterpart to Telegram creating a
        completed row outright -- see app/billing/grant_pro_tier. No-op
        when DATABASE_URL isn't set, matching mark_delivered."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return
        async with pool.connection() as conn:
            await conn.execute(
                """
                update payments
                set status = 'completed', account_id = %s, external_ref = %s
                where id = %s
                """,
                (uuid.UUID(account_id), external_ref, uuid.UUID(payment_id)),
            )
