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
import hashlib
import json
import logging
import os
import sys
import uuid
import weakref
from contextlib import asynccontextmanager
from typing import Any

from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from app.pipeline.scan_pipeline import BASIS_STATIC_ONLY
from app.scan.reporting.scoring import CATEGORIES

logger = logging.getLogger("app.db")

DATABASE_URL_ENV = "DATABASE_URL"

_pool: AsyncConnectionPool | None = None
_pool_lock = asyncio.Lock()


class DatabaseNotConfigured(Exception):
    """DATABASE_URL isn't set. Distinct from a real connection failure
    (bad host, bad password, etc.), which should propagate as a loud
    error, not get treated as "not configured"."""


class AuditJobIdempotencyConflict(RuntimeError):
    """A live idempotency key belongs to a different audit submission."""


class ProGrantConflict(RuntimeError):
    """A Pro settlement was refused after its transaction started writing.

    Propagating this exception rolls back the account as well as the payment;
    callers must never turn it into a successfully provisioned entitlement.
    """


def database_url_from_env() -> str | None:
    return os.environ.get(DATABASE_URL_ENV) or None


def _facade():
    return sys.modules.get("app.db")


def _resolve_get_pool():
    mod = _facade()
    return getattr(mod, "get_pool", get_pool) if mod is not None else get_pool


def _grant_lock_timeout_ms() -> int | float:
    mod = _facade()
    if mod is None:
        return GRANT_LOCK_TIMEOUT_MS
    return getattr(mod, "GRANT_LOCK_TIMEOUT_MS", GRANT_LOCK_TIMEOUT_MS)


async def get_pool() -> AsyncConnectionPool:
    global _pool
    mod = _facade()
    current = getattr(mod, "_pool", _pool) if mod is not None else _pool
    if current is not None:
        return current
    async with _pool_lock:
        current = getattr(mod, "_pool", _pool) if mod is not None else _pool
        if current is None:
            url = database_url_from_env()
            if not url:
                raise DatabaseNotConfigured(f"{DATABASE_URL_ENV} is not set")
            pool_cls = (
                getattr(mod, "AsyncConnectionPool", AsyncConnectionPool)
                if mod is not None else AsyncConnectionPool
            )
            pool = pool_cls(
                url, min_size=1, max_size=5, open=False,
                kwargs={"prepare_threshold": None, "row_factory": dict_row},
            )
            await pool.open()
            _pool = pool
            if mod is not None:
                mod._pool = pool
            current = pool
    return current


async def close_pool() -> None:
    """For tests/shutdown -- lets a fresh get_pool() reconnect."""
    global _pool
    mod = _facade()
    current = getattr(mod, "_pool", _pool) if mod is not None else _pool
    if current is not None:
        await current.close()
        _pool = None
        if mod is not None:
            mod._pool = None


# Arbitrary but fixed keys for the processors' session advisory locks -- ascii
# "FIXP", "MONI" and "BNKA". Any value works as long as it is stable and not
# shared with another advisory-lock user in this database; each holder uses a
# distinct key so a Fix Pack run, a monitoring run and a bank-transfer amount
# reservation never serialize against each other.
#
# 0x55534454 ("USDT") was the USDT poller's and is deliberately NOT reused: a
# host mid-deploy can run old and new code at once, and a recycled advisory-lock
# key is a lock shared between two things that know nothing about each other.
_FIXPACK_PROCESSOR_LOCK_KEY = 0x46495850
_MONITORING_PROCESSOR_LOCK_KEY = 0x4D4F4E49
_BANK_TRANSFER_AMOUNT_LOCK_KEY = 0x424E4B41  # "BNKA"
# "DEPS": the dependency-refresh sweep. Its own key so a slow refresh never
# serializes a Fix Pack run or a monitoring drain.
_DEPENDENCY_REFRESH_LOCK_KEY = 0x44455053


class ProcessorLockBusy(Exception):
    """Another processor run already holds the advisory lock, so this run must
    not proceed -- returned to the caller as a benign skipped-because-locked
    outcome, not an error. Shared by the Fix Pack and monitoring
    processors."""


@asynccontextmanager
async def _advisory_processor_lock(key: int):
    """Serialize processor runs with a session-level Postgres advisory lock on
    `key`. Belt-and-suspenders on top of the atomic per-job claim (claim_one_paid
    / claim_one_pending): the claim already makes double-processing of a single
    job impossible, this makes "one processor run at a time" explicit and
    observable so overlapping timer firings don't stampede the backlog.

    Acquired on a dedicated pooled connection held for the whole run and released
    on exit (both on success and on error). Raises ProcessorLockBusy if the lock
    is already held. When DATABASE_URL isn't configured there is nothing to
    serialize, so it yields without a lock -- same not-configured contract as the
    repositories."""
    try:
        pool = await _resolve_get_pool()()
    except DatabaseNotConfigured:
        yield
        return
    async with pool.connection() as conn:
        cur = await conn.execute(
            "select pg_try_advisory_lock(%s) as locked", (key,)
        )
        row = await cur.fetchone()
        if not (row and row["locked"]):
            raise ProcessorLockBusy()
        try:
            yield
        finally:
            await conn.execute("select pg_advisory_unlock(%s)", (key,))


# Namespace for the per-charge grant lock -- ascii "GRNT". Postgres advisory
# locks take an optional second int32, so this is key1 and a hash of
# (provider, external_ref) is key2: two confirmations of the SAME charge
# serialize, and two confirmations of different charges do not.
_GRANT_LOCK_NAMESPACE = 0x47524E54

# How long to wait for another confirmation of the same charge before giving up
# on the lock. The section it guards is a few short queries, so anything near
# this means something is wrong; five seconds is long enough that ordinary
# contention never reaches it.
GRANT_LOCK_TIMEOUT_MS = 5000


def _grant_lock_key(provider: str, external_ref: str) -> int:
    """A stable signed int32 from the charge identity, for advisory-lock key2.

    sha256 rather than hash() because Python's hash is salted per process:
    two web workers must derive the SAME key for the same charge, which is the
    entire point.
    """
    digest = hashlib.sha256(f"{provider}:{external_ref}".encode()).digest()
    return int.from_bytes(digest[:4], "big", signed=True)


_confirmation_slots: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


class PaymentConfirmationBusy(TimeoutError):
    """Retry the webhook; no confirmation was processed without the lock."""


@asynccontextmanager
async def payment_confirmation_lock(provider: str, external_ref: str):
    """Serialize notification decisions across workers, failing closed on timeout.

    Waiting callers return their pooled connection before sleeping. Only the
    winner holds one while repository calls use other connections. Transaction
    scope releases the advisory lock on exceptions/cancellation as well.
    Unconfigured storage keeps the repository contract used by isolated fakes.
    """
    try:
        pool = await _resolve_get_pool()()
    except DatabaseNotConfigured:
        yield
        return
    # Repository operations need another connection from the five-slot pool.
    # Bound holders even for DIFFERENT charges; try-lock alone only protects
    # same-charge contention from pool starvation. Per-pool state also respects
    # shutdown/reopen and the event loop that owns that pool.
    slots = _confirmation_slots.setdefault(pool, asyncio.Semaphore(2))
    try:
        async with asyncio.timeout(_grant_lock_timeout_ms() / 1000):
            await slots.acquire()
    except TimeoutError as exc:
        raise PaymentConfirmationBusy("Payment confirmation capacity is busy") from exc
    try:
        async with _locked_payment_confirmation(pool, provider, external_ref):
            yield
    finally:
        slots.release()


@asynccontextmanager
async def _locked_payment_confirmation(pool, provider: str, external_ref: str):
    deadline = asyncio.get_running_loop().time() + _grant_lock_timeout_ms() / 1000
    while True:
        async with pool.connection() as conn:
            async with conn.transaction():
                cur = await conn.execute(
                    "select pg_try_advisory_xact_lock(%s, %s) as acquired",
                    (_GRANT_LOCK_NAMESPACE, _grant_lock_key(provider, external_ref)),
                )
                row = await cur.fetchone()
                if row["acquired"]:
                    yield
                    return
        if asyncio.get_running_loop().time() >= deadline:
            raise PaymentConfirmationBusy("Payment confirmation is busy; retry later")
        await asyncio.sleep(0.05)


def fixpack_processor_lock():
    """The Fix Pack processor's advisory lock (see _advisory_processor_lock)."""
    return _advisory_processor_lock(_FIXPACK_PROCESSOR_LOCK_KEY)


def monitoring_processor_lock():
    """The continuous-monitoring processor's advisory lock, on a distinct key so
    it never serializes against a Fix Pack run (see _advisory_processor_lock)."""
    return _advisory_processor_lock(_MONITORING_PROCESSOR_LOCK_KEY)


def dependency_refresh_lock():
    """The dependency-refresh sweep's advisory lock, on its own key."""
    return _advisory_processor_lock(_DEPENDENCY_REFRESH_LOCK_KEY)


# Retry budget for the kopeck-suffix lock. ~1s of contention before giving up,
# which is far longer than the read-plus-insert it protects and short enough
# that a checkout never visibly stalls on it.
_AMOUNT_LOCK_ATTEMPTS = 20
_AMOUNT_LOCK_DELAY_SECONDS = 0.05


@asynccontextmanager
async def bank_transfer_amount_lock():
    """Serialize kopeck-suffix reservation: read the open invoices, pick a free
    suffix, insert -- with nobody else doing the same in between.

    Without it two concurrent checkouts both read the same set of taken
    suffixes and both pick the same free one. Measured with a suspension point
    where the real round-trip sits: 12 duplicate amounts per 200 concurrent
    invoices.

    Three deliberate differences from _advisory_processor_lock, all forced by
    this being on a user's checkout rather than a background timer:

      * It retries instead of raising. ProcessorLockBusy is the right answer
        for an overlapping timer firing -- skip this run, the next one picks
        the backlog up. On a buyer pressing Pay it is a 5xx, and refusing a
        sale to protect a matching HINT is backwards.
      * It releases the connection between attempts. Blocking on
        pg_advisory_lock while holding a pooled connection deadlocks at
        max_size=5: five concurrent checkouts hold all five connections
        waiting, and the one holding the lock cannot get a sixth to do its
        work. A waiter that sleeps without a connection cannot starve the
        holder.
      * On exhausting the retries it proceeds WITHOUT the lock rather than
        failing. The degraded outcome is two open invoices sharing an amount,
        which the operator separates by payer name and email -- the fallback
        those fields exist for. That is strictly better than a lost sale, and
        it is logged so the calibration can be revisited if it ever happens.

    Yields without a lock when DATABASE_URL isn't set: nothing to serialize,
    same not-configured contract as the repositories.
    """
    try:
        pool = await _resolve_get_pool()()
    except DatabaseNotConfigured:
        yield
        return
    for _ in range(_AMOUNT_LOCK_ATTEMPTS):
        async with pool.connection() as conn:
            cur = await conn.execute(
                "select pg_try_advisory_lock(%s) as locked",
                (_BANK_TRANSFER_AMOUNT_LOCK_KEY,),
            )
            row = await cur.fetchone()
            if row and row["locked"]:
                try:
                    yield
                finally:
                    await conn.execute(
                        "select pg_advisory_unlock(%s)",
                        (_BANK_TRANSFER_AMOUNT_LOCK_KEY,),
                    )
                return
        # Connection released before sleeping -- see the deadlock note above.
        await asyncio.sleep(_AMOUNT_LOCK_DELAY_SECONDS)
    logger.warning(
        "kopeck-suffix lock busy for %.1fs; reserving without it, two open "
        "invoices may share an amount and be separated by payer name instead",
        _AMOUNT_LOCK_ATTEMPTS * _AMOUNT_LOCK_DELAY_SECONDS,
    )
    yield


def _json_field(value: Any) -> Any:
    """jsonb columns: psycopg3 may hand back an already-parsed
    dict/list, or a raw string depending on codec registration --
    handle both rather than assume one."""
    if value is None:
        return None
    return json.loads(value) if isinstance(value, str) else value


def _uuid_or_none(value: str | None) -> uuid.UUID | None:
    """Parse a uuid string for a nullable uuid column, treating a
    missing/unparseable value as absent (NULL) rather than raising -- used where
    the row must be written even if a linkage id is missing (see
    LlmUsageRepository.create)."""
    if not value:
        return None
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError):
        return None


def _seconds_to_ms(value: Any) -> int | None:
    """Postgres epoch-seconds (numeric/Decimal) to whole milliseconds, keeping
    NULL as None so "no rows in the window" stays distinguishable from zero.
    Milliseconds because that is the unit `duration_ms` already uses in the
    logs, and a stats reader should not have to convert between the two."""
    return None if value is None else int(float(value) * 1000)


def _row_to_audit(row: dict[str, Any]) -> dict[str, Any]:
    d = dict(row)
    d["id"] = str(d["id"])
    # score_total is a Postgres `numeric`, which psycopg3 hands back as a
    # decimal.Decimal -> a JSON *string* under the default encoder. Cast to
    # float so it serializes as a number, matching score_json.total (both
    # rounded to 1 dp -- see app/scan/scoring.py).
    if d.get("score_total") is not None:
        d["score_total"] = round(float(d["score_total"]), 1)
    d["score_json"] = _backfill_unexamined(_json_field(d["score_json"]))
    d["findings_json"] = _json_field(d["findings_json"])
    if "dependency_inventory" in d:
        d["dependency_inventory"] = _json_field(d["dependency_inventory"])
    return d


def _backfill_unexamined(score: Any) -> Any:
    """Fill in `unexamined` for a row stored before the scorer recorded it.

    Both report surfaces now publish the free tier's score, and they decide
    whether to draw a category's bar from this key. A stored static-only row
    that predates it would arrive without one -- and Auth would render as a
    full green 10.0, which is precisely the claim (issue #181) the key exists
    to prevent. Absent must not read as "everything was examined".

    A FROZEN LIST, AND NO LONGER THE LIVE CONSTANT. This used to derive from
    LLM_ONLY_CATEGORIES on the argument that the backfill must agree with a
    fresh audit. That argument inverted the day Frontend left that set: a row
    with no `unexamined` key predates the key itself, so it predates
    app/scan/error_boundary.py by weeks, and on the engine that produced it
    nothing looked at Frontend at all. Its 10.0 there is as unearned as its
    Auth 10.0. Reading today's constant would have those old rows start
    claiming a Frontend examination that never happened -- the exact defect
    this function exists to prevent, arriving through the fix for it.

    The set is what LLM-only meant for every engine that stored a row without
    this key. It does not track the constant, by design, and is asserted in
    tests/test_db.py as the historical fact it is.
    """
    if not isinstance(score, dict) or "unexamined" in score:
        return score
    if str(score.get("basis") or "") != BASIS_STATIC_ONLY:
        return score
    return {**score,
            "unexamined": [c for c in CATEGORIES
                           if c in _LLM_ONLY_BEFORE_UNEXAMINED_WAS_STORED]}


# What LLM_ONLY_CATEGORIES contained on every engine that stored a score
# without an `unexamined` key. Frontend joined the live set on 2026-08-2x with
# only the web rubric producing it, and left on 2026-09-01 when the
# error-boundary scan became a static producer; every row this backfill
# touches was scored while it was in. See _backfill_unexamined.
_LLM_ONLY_BEFORE_UNEXAMINED_WAS_STORED = frozenset(
    {"Auth", "Money & Data", "Frontend"})


# Marks a fixpack_jobs.detail written by the stale-lease reaper rather than by the
# delivery path. A job only lands there when it never completed -- a runner outage
# or a crashed worker -- never because of anything in the client's code, so the
# status endpoint uses this prefix to tell an infrastructure failure apart from a
# generation failure.
STALE_LEASE_DETAIL_PREFIX = "stale lease reaped:"


def _row_to_fixpack_job(row: dict[str, Any]) -> dict[str, Any]:
    d = dict(row)
    d["id"] = str(d["id"])
    d["audit_id"] = str(d["audit_id"]) if d["audit_id"] else None
    return d


def _row_to_fix_outcome(row: dict[str, Any]) -> dict[str, Any]:
    d = dict(row)
    d["id"] = str(d["id"])
    d["fixpack_job_id"] = (
        str(d["fixpack_job_id"]) if d.get("fixpack_job_id") else None
    )
    d["audit_id"] = str(d["audit_id"]) if d.get("audit_id") else None
    d["rule_ids"] = _json_field(d.get("rule_ids")) or []
    return d


def _row_to_account(row: dict[str, Any]) -> dict[str, Any]:
    d = dict(row)
    d["id"] = str(d["id"])
    return d


def _row_to_payment(row: dict[str, Any]) -> dict[str, Any]:
    d = dict(row)
    d["id"] = str(d["id"])
    d["account_id"] = str(d["account_id"]) if d["account_id"] else None
    if d.get("audit_id"):
        d["audit_id"] = str(d["audit_id"])
    if d.get("fixpack_job_id"):
        d["fixpack_job_id"] = str(d["fixpack_job_id"])
    # amount is a Postgres `numeric` -> decimal.Decimal -> a JSON *string*
    # under the default encoder; cast to float so it serializes as a number,
    # same fix as score_total in _row_to_audit.
    if d.get("amount") is not None:
        d["amount"] = float(d["amount"])
    return d


def _row_to_subscription(row: dict[str, Any]) -> dict[str, Any]:
    d = dict(row)
    d["id"] = str(d["id"])
    d["account_id"] = str(d["account_id"]) if d.get("account_id") else None
    return d


def _row_to_monitoring_run(row: dict[str, Any]) -> dict[str, Any]:
    d = dict(row)
    d["id"] = str(d["id"])
    return d


def _row_to_audit_job(row: dict[str, Any]) -> dict[str, Any]:
    d = dict(row)
    d["id"] = str(d["id"])
    d["account_id"] = str(d["account_id"]) if d.get("account_id") else None
    d["audit_id"] = str(d["audit_id"]) if d.get("audit_id") else None
    return d


def _expires_at_to_timestamptz(expires_at: Any) -> datetime.datetime | None:
    """Telegram's successful_payment.subscription_expiration_date is Unix time
    (an int, seconds since the epoch), but subscriptions.expires_at is
    timestamptz and psycopg does no implicit int->timestamptz cast -- passing
    the raw int raises DatatypeMismatch. Convert at the DB boundary, the same
    way FixpackJobRepository.create handles preview_expires_at. None passes
    through (no expiry known); an already-converted datetime passes through
    unchanged."""
    if expires_at is None:
        return None
    if isinstance(expires_at, (int, float)):
        return datetime.datetime.fromtimestamp(expires_at, tz=datetime.timezone.utc)
    return expires_at


def _row_to_mcp_key(row: dict[str, Any]) -> dict[str, Any]:
    d = dict(row)
    d["id"] = str(d["id"])
    return d
