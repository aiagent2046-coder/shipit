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
from contextlib import asynccontextmanager
from decimal import Decimal
from typing import Any

from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from app.accounts import api_key_prefix, generate_api_key, hash_api_key

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


# Arbitrary but fixed keys for the processors' session advisory locks -- ascii
# "FIXP" and "MONI". Any value works as long as it is stable and not shared with
# another advisory-lock user in this database; the two processors use distinct
# keys so a Fix Pack run and a monitoring run never serialize against each other.
_FIXPACK_PROCESSOR_LOCK_KEY = 0x46495850
_MONITORING_PROCESSOR_LOCK_KEY = 0x4D4F4E49


class ProcessorLockBusy(Exception):
    """Another processor run already holds the advisory lock, so this run must
    not proceed -- returned to the caller as a benign skipped-because-locked
    outcome, not an error. Shared by the Fix Pack and monitoring processors."""


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
        pool = await get_pool()
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


def fixpack_processor_lock():
    """The Fix Pack processor's advisory lock (see _advisory_processor_lock)."""
    return _advisory_processor_lock(_FIXPACK_PROCESSOR_LOCK_KEY)


def monitoring_processor_lock():
    """The continuous-monitoring processor's advisory lock, on a distinct key so
    it never serializes against a Fix Pack run (see _advisory_processor_lock)."""
    return _advisory_processor_lock(_MONITORING_PROCESSOR_LOCK_KEY)


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


class AuditRepository:
    """Real-Postgres-backed by default. Tests use an in-memory fake
    with the same method signatures instead of this class -- see
    tests/test_db.py."""

    async def create(
        self, *, stack: str, file_count: int,
        score_total: float | None, score_json: dict | None,
        findings_json: list | None, repo_url: str | None = None,
        content_hash: str | None = None, engine_version: str | None = None,
    ) -> dict[str, Any] | None:
        # access_token is not inserted here: the column default
        # (migration 0010, encode(gen_random_bytes(16),'hex')) mints a
        # per-row token, and RETURNING hands it back so the API can deliver
        # it to the creator exactly once. It is the ownership secret for
        # GET /v1/audits/{id} and /report -- see get_authorized().
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into audits (stack, file_count, score_total, score_json,
                                    findings_json, repo_url, content_hash,
                                    engine_version)
                values (%s, %s, %s, %s::jsonb, %s::jsonb, %s, %s, %s)
                returning id, stack, status, file_count, score_total,
                          score_json, findings_json, repo_url, content_hash,
                          engine_version, access_token, created_at
                """,
                (
                    stack, file_count, score_total,
                    json.dumps(score_json) if score_json is not None else None,
                    json.dumps(findings_json) if findings_json is not None else None,
                    repo_url, content_hash, engine_version,
                ),
            )
            row = await cur.fetchone()
        return _row_to_audit(row)

    async def get_by_content_hash(
        self, content_hash: str, engine_version: str
    ) -> dict[str, Any] | None:
        """Most recent completed audit for this exact content produced by
        this exact engine version, or None.

        The reproducibility backstop: an identical re-audit reuses this
        row instead of re-running the LLM scan, which returns a different
        findings set -- and thus a different score -- run to run even at
        temperature=0 (see app/scan/llm_scan.py, app/scan/scoring.py).

        The engine_version filter (migration 0013) is what keeps that reuse
        from freezing a stale result across an engine change: a row written
        under an older AUDIT_ENGINE_VERSION no longer matches, so it falls
        through to None -- a cache miss that recomputes under the current
        engine, exactly as if content_hash hadn't matched. Returns None when
        DATABASE_URL isn't set, same not-configured contract as get()."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, stack, status, file_count, score_total,
                       score_json, findings_json, repo_url, content_hash,
                       engine_version, access_token, created_at
                from audits
                where content_hash = %s and engine_version = %s
                      and status = 'completed'
                order by created_at desc
                limit 1
                """,
                (content_hash, engine_version),
            )
            row = await cur.fetchone()
        return _row_to_audit(row) if row else None

    async def get_latest_by_repo_url(
        self, repo_full_name: str
    ) -> dict[str, Any] | None:
        """Most recent completed audit for a repo, matched by a canonical
        'owner/repo' (Phase C monitoring's diff baseline). audits.repo_url is
        stored as typed at intake (full github URL, 0006); this normalizes it in
        SQL -- extract owner/repo, drop a trailing '.git'/slash, lowercase -- so
        it matches regardless of the casing/suffix the audit was created with.
        The same normalization app/monitor.normalize_repo_full_name does in
        Python, kept in lockstep so a push and a stored audit for the same repo
        always join. Returns None when DATABASE_URL isn't set."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, stack, status, file_count, score_total,
                       score_json, findings_json, repo_url, created_at
                from audits
                where repo_url is not null
                      and lower(regexp_replace(
                          repo_url,
                          '^https://github\\.com/(.+?)(\\.git)?/?$',
                          '\\1')) = %s
                      and status = 'completed'
                order by created_at desc
                limit 1
                """,
                (repo_full_name,),
            )
            row = await cur.fetchone()
        return _row_to_audit(row) if row else None

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
                       score_json, findings_json, repo_url, created_at
                from audits where id = %s
                """,
                (parsed_id,),
            )
            row = await cur.fetchone()
        return _row_to_audit(row) if row else None

    async def get_authorized(
        self, audit_id: str, access_token: str | None
    ) -> dict[str, Any] | None:
        """Ownership-checked fetch for the public report endpoints: return
        the audit only if `access_token` matches the row's per-row token
        (migration 0010). A missing/wrong token, an unknown id, a malformed
        id, and an unconfigured DB all return None -- so the endpoint answers
        404 uniformly and never confirms an id's existence to a caller who
        doesn't hold its token. The token is matched in SQL and is NOT in the
        selected columns, so it never rides back out in the response body.

        Distinct from get(), which is the trusted server-side lookup (fixpack
        processing) with no token gate."""
        if not access_token:
            return None
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
                       score_json, findings_json, repo_url, created_at
                from audits where id = %s and access_token = %s
                """,
                (parsed_id, access_token),
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
        # access_token is not inserted here: the column default
        # (migration 0012, encode(gen_random_bytes(16),'hex')) mints a
        # per-row token, and RETURNING hands it back so the API can deliver
        # it to the creator exactly once. It is the ownership secret for
        # GET /v1/fixpacks/{job_id} -- see get_authorized().
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
                          pr_url, pr_delivered, status, access_token, created_at
                """,
                (parsed_audit_id, pack, stack, verified, detail,
                 preview_local_url, expires_dt),
            )
            row = await cur.fetchone()
        return _row_to_fixpack_job(row)

    async def create_paid(
        self, *, audit_id: str | None, stack: str
    ) -> dict[str, Any] | None:
        """Insert a Fix Pack job in the 'paid' state: purchased, not yet
        generated. Distinct from create() (the Deploy Pack flow's already-
        generated rows, which default to status 'generated') -- a separate
        follow-up step picks up 'paid' rows and generates the fix PR.
        pack='fixpack' names the product; the other generation outputs
        (verified, detail, preview_*) stay null until that step runs."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        parsed_audit_id = uuid.UUID(audit_id) if audit_id else None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into fixpack_jobs (audit_id, pack, stack, status)
                values (%s, 'fixpack', %s, 'paid')
                returning id, audit_id, pack, stack, verified, detail,
                          preview_local_url, preview_expires_at,
                          pr_url, pr_delivered, status, access_token, created_at
                """,
                (parsed_audit_id, stack),
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

    async def claim_one_paid(self) -> dict[str, Any] | None:
        """Atomically claim the oldest purchased-but-not-yet-generated Fix
        Pack job (status 'paid') into a 'running' lease, and return it --
        or None when there is nothing to claim (or DATABASE_URL isn't set).

        This is the concurrency guard. The inner SELECT ... FOR UPDATE SKIP
        LOCKED LIMIT 1 row-locks exactly one candidate and skips any a
        concurrent run already locked, and the surrounding single-row UPDATE
        flips it 'paid' -> 'running' in the same statement. So two
        overlapping processor runs can never both claim the same job -- the
        loser's SELECT skips the locked row and moves on -- which is what
        stops one payment from producing two fix PRs. started_at stamps the
        lease (the stale-lease reaper reads it) and attempts is incremented
        so retries are bounded.

        The processor calls this in a loop (claim -> process -> claim next)
        until it returns None, instead of listing all 'paid' rows up front,
        so a job purchased mid-run is still picked up and nothing is held in
        memory across the slow Docker/PR work."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update fixpack_jobs
                   set status = 'running',
                       started_at = now(),
                       attempts = attempts + 1
                 where id = (
                     select id from fixpack_jobs
                      where status = 'paid'
                      order by created_at asc
                      for update skip locked
                      limit 1
                 )
                returning id, audit_id, pack, stack, verified, detail,
                          preview_local_url, preview_expires_at,
                          pr_url, pr_delivered, status, created_at
                """,
            )
            row = await cur.fetchone()
        return _row_to_fixpack_job(row) if row else None

    async def reap_stale_running(
        self, *, max_age_minutes: int, max_attempts: int
    ) -> dict[str, int]:
        """Recover Fix Pack jobs whose worker crashed mid-run: a 'running'
        lease older than max_age_minutes means no process is still working
        it (a real generation is minutes, not tens of minutes). Run at the
        start of each processor pass, before claiming.

        Two outcomes, bounded by attempts (incremented at each claim):
          - attempts < max_attempts -> back to 'paid' (started_at cleared)
            so the next claim retries it;
          - attempts >= max_attempts -> 'failed' with a diagnosable detail,
            so a poison-pill job that crashes the worker every time stops
            re-queuing forever and stays visible for a human.

        Returns {'requeued': n, 'failed': m}. No-op ({'requeued': 0,
        'failed': 0}) when DATABASE_URL isn't set, matching the other
        not-configured contracts. This is the required counterpart to
        introducing the 'running' lease: without it, a crashed lease would
        be exactly the zombie-forever state the durable design set out to
        avoid."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return {"requeued": 0, "failed": 0}
        async with pool.connection() as conn:
            requeued_cur = await conn.execute(
                """
                update fixpack_jobs
                   set status = 'paid', started_at = null
                 where status = 'running'
                   and started_at < now() - make_interval(mins => %s)
                   and attempts < %s
                returning id
                """,
                (max_age_minutes, max_attempts),
            )
            requeued = len(await requeued_cur.fetchall())
            failed_cur = await conn.execute(
                """
                update fixpack_jobs
                   set status = 'failed',
                       detail = %s
                 where status = 'running'
                   and started_at < now() - make_interval(mins => %s)
                   and attempts >= %s
                returning id
                """,
                (
                    f"stale lease reaped: no completion after {max_attempts} "
                    f"attempt(s), last lease older than {max_age_minutes}m",
                    max_age_minutes,
                    max_attempts,
                ),
            )
            failed = len(await failed_cur.fetchall())
        return {"requeued": requeued, "failed": failed}

    async def backlog_stats(self) -> dict[str, Any] | None:
        """Health signal for the Fix Pack processor: how many jobs are still
        'paid' (purchased, not yet generated) and how old the oldest one is,
        in seconds. Since fixpack_jobs has no delivered_at/updated_at, the age
        of the oldest still-queued 'paid' job is the honest, zero-schema
        proxy for "is the processor timer draining the backlog" — if it grows
        past the timer interval, the processor isn't running.

        Returns {'backlog': n, 'oldest_paid_seconds': float | None} (the age
        is None when the backlog is empty), or None when DATABASE_URL isn't
        set so /health can report db:false without guessing."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select count(*) as backlog,
                       extract(epoch from (now() - min(created_at)))
                           as oldest_paid_seconds
                  from fixpack_jobs
                 where status = 'paid'
                """,
            )
            row = await cur.fetchone()
        backlog = int(row["backlog"]) if row else 0
        oldest = row["oldest_paid_seconds"] if row else None
        return {
            "backlog": backlog,
            "oldest_paid_seconds": float(oldest) if oldest is not None else None,
        }

    async def mark_fixpack_delivered(self, job_id: str, pr_url: str) -> None:
        """A paid Fix Pack job whose fix PR was successfully opened: record
        the PR url and advance status to 'delivered'. 'delivered' is the
        terminal success state for the Fix Pack flow, deliberately distinct
        from the Deploy Pack rows' default 'generated' (migration 0007) and
        from the 'paid' a purchase inserts — a status query can tell a
        finished Fix Pack from one still waiting to be processed. No-op when
        DATABASE_URL isn't set, matching mark_delivered."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return
        async with pool.connection() as conn:
            await conn.execute(
                """
                update fixpack_jobs
                set pr_url = %s, pr_delivered = true, status = 'delivered'
                where id = %s
                """,
                (pr_url, uuid.UUID(job_id)),
            )

    async def mark_status(
        self, job_id: str, status: str, detail: str | None = None
    ) -> None:
        """Advance a Fix Pack job to a non-delivered terminal state:
        'no_fix_needed' (nothing eligible to fix, so no PR was opened) or
        'failed' (generation/delivery errored — left visible for retry/ops
        rather than silently stuck on 'paid'). No-op when DATABASE_URL isn't
        set, matching mark_delivered.

        When `detail` is given (the failure path always passes one), it is
        written to the `detail` column so a failed job is diagnosable from a
        status query — a 'failed' row with a null detail is exactly the
        silent failure this was hardened against. Omitting it leaves the
        column untouched, so the 'no_fix_needed' path doesn't clobber it."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return
        async with pool.connection() as conn:
            if detail is None:
                await conn.execute(
                    "update fixpack_jobs set status = %s where id = %s",
                    (status, uuid.UUID(job_id)),
                )
            else:
                await conn.execute(
                    "update fixpack_jobs set status = %s, detail = %s "
                    "where id = %s",
                    (status, detail, uuid.UUID(job_id)),
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
                       pr_url, pr_delivered, status, created_at
                from fixpack_jobs where id = %s
                """,
                (parsed_id,),
            )
            row = await cur.fetchone()
        return _row_to_fixpack_job(row) if row else None

    async def get_authorized(
        self, job_id: str, access_token: str | None
    ) -> dict[str, Any] | None:
        """Ownership-checked fetch for the public GET /v1/fixpacks/{job_id}
        endpoint: return the job only if `access_token` matches the row's
        per-row token (migration 0012). A missing/wrong token, an unknown id, a
        malformed id, and an unconfigured DB all return None -- so the endpoint
        answers 404 uniformly and never confirms an id's existence to a caller
        who doesn't hold its token. The token is matched in SQL and is NOT in
        the selected columns, so it never rides back out in the response body.

        Mirrors AuditRepository.get_authorized. Distinct from get(), the trusted
        server-side lookup with no token gate."""
        if not access_token:
            return None
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
                       pr_url, pr_delivered, status, created_at
                from fixpack_jobs where id = %s and access_token = %s
                """,
                (parsed_id, access_token),
            )
            row = await cur.fetchone()
        return _row_to_fixpack_job(row) if row else None

    async def get_by_audit(self, audit_id: str) -> dict[str, Any] | None:
        """The most recent Fix Pack job for an audit, so the results page can
        poll one audit's purchase outcome (status + pr_url) without knowing a
        job id up front. Newest first because a re-purchase after a 'failed'
        job should surface the latest attempt. Returns None when there's no
        job yet or DATABASE_URL isn't set."""
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
                select id, audit_id, pack, stack, verified, detail,
                       preview_local_url, preview_expires_at,
                       pr_url, pr_delivered, status, created_at
                from fixpack_jobs where audit_id = %s
                order by created_at desc
                limit 1
                """,
                (parsed_id,),
            )
            row = await cur.fetchone()
        return _row_to_fixpack_job(row) if row else None


class FixOutcomeRepository:
    """The fix-outcome knowledge base (migration 0014). One row per terminal
    Fix Pack job outcome; collection only, nothing reads it for decisions yet
    (see PHASE_B_KNOWLEDGE_BASE_PLAN.md). Same real/fake split and
    not-configured contract as the other repositories: when DATABASE_URL isn't
    set, record()/set_pr_merged_by_pr_url() no-op instead of failing, so the
    Fix Pack delivery path never breaks over a missing analytics store."""

    async def record(
        self, *, fixpack_job_id: str | None, audit_id: str | None,
        rule_ids: list[str], stack: str, outcome: str,
        is_regression: bool, pr_url: str | None,
    ) -> dict[str, Any] | None:
        """Insert one outcome row. pr_merged is left NULL -- only the
        pull_request.closed webhook sets it, and only for delivered PRs.
        Returns None when DATABASE_URL isn't configured."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        parsed_job_id = uuid.UUID(fixpack_job_id) if fixpack_job_id else None
        parsed_audit_id = uuid.UUID(audit_id) if audit_id else None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into fix_outcomes
                    (fixpack_job_id, audit_id, rule_ids, stack, outcome,
                     is_regression, pr_url)
                values (%s, %s, %s::jsonb, %s, %s, %s, %s)
                returning id, fixpack_job_id, audit_id, rule_ids, stack,
                          outcome, is_regression, pr_url, pr_merged,
                          created_at, updated_at
                """,
                (
                    parsed_job_id, parsed_audit_id, json.dumps(rule_ids),
                    stack, outcome, is_regression, pr_url,
                ),
            )
            row = await cur.fetchone()
        return _row_to_fix_outcome(row)

    async def set_pr_merged_by_pr_url(self, pr_url: str, merged: bool) -> int:
        """Backfill pr_merged for the delivered outcome whose PR just closed,
        matched by the PR's html_url (the exact value stored at delivery).
        Returns the number of rows updated so the webhook can distinguish a
        matched PR (1) from an unknown one (0) -- an unknown PR is a benign
        no-op, not an error. Returns 0 when DATABASE_URL isn't set."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return 0
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update fix_outcomes
                   set pr_merged = %s, updated_at = now()
                 where pr_url = %s
                """,
                (merged, pr_url),
            )
            return cur.rowcount


class AccountRepository:
    """Accounts for the paywall foundation (see app/accounts.py). Same
    real/fake split and not-configured contract as AuditRepository: when
    DATABASE_URL isn't set, create/get_by_key_hash/rotate_key return None
    instead of failing, so a request carrying an API key on an unconfigured
    deployment simply falls back to anonymous/free.

    No public create-account endpoint exists (that would be an abuse
    hole) -- create() is used by Stage 2's payment flow and by tests."""

    async def create(self, *, api_key: str, tier: str) -> dict[str, Any] | None:
        """Mint an account for a freshly generated `api_key`. Stores only
        the safe prefix and the HMAC hash -- NEVER the plaintext key -- so a
        DB leak yields no usable keys. The plaintext is returned in the
        result dict for one-time delivery to the buyer (it can never be
        recovered afterward; there is no plaintext at rest to re-send)."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        # Compute only once the DB is actually configured, so the
        # not-configured contract (return None) doesn't require a pepper.
        # hash_api_key raises loudly if the pepper is missing on a DB-backed
        # deployment -- never a silent empty-pepper hash.
        key_prefix = api_key_prefix(api_key)
        key_hash = hash_api_key(api_key)
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into accounts (key_prefix, key_hash, tier)
                values (%s, %s, %s)
                returning id, key_prefix, key_hash, tier, created_at
                """,
                (key_prefix, key_hash, tier),
            )
            row = await cur.fetchone()
        account = _row_to_account(row)
        # api_key is never persisted. Surface the plaintext in-memory so the
        # caller can deliver it exactly once (it cannot be recovered later).
        account["api_key"] = api_key
        return account

    async def get_by_key_hash(self, key_hash: str) -> dict[str, Any] | None:
        """Primary (and only) authenticated lookup: match the HMAC hash of
        the presented key. See app/accounts.resolve_account."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, key_prefix, key_hash, tier, created_at
                from accounts where key_hash = %s
                """,
                (key_hash,),
            )
            row = await cur.fetchone()
        return _row_to_account(row) if row else None

    async def rotate_key(self, account_id: str) -> dict[str, Any] | None:
        """Issue a NEW key for an existing account, invalidating the old one.

        Overwrites key_prefix/key_hash with a freshly generated key: the old
        key's hash is gone, so it stops resolving immediately. The new
        plaintext is returned in-memory for one-time delivery, exactly like
        create() -- it is never persisted and cannot be recovered later.
        Returns None if the DB isn't configured or no such account exists.

        This is the recovery path for a lost key (there is no plaintext at
        rest to re-send) and the response to a suspected leak."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        try:
            parsed_id = uuid.UUID(account_id)
        except ValueError:
            return None
        new_key = generate_api_key()
        key_prefix = api_key_prefix(new_key)
        key_hash = hash_api_key(new_key)
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update accounts
                set key_prefix = %s, key_hash = %s
                where id = %s
                returning id, key_prefix, key_hash, tier, created_at
                """,
                (key_prefix, key_hash, parsed_id),
            )
            row = await cur.fetchone()
        if row is None:
            return None
        account = _row_to_account(row)
        account["api_key"] = new_key
        return account

    async def get_by_id(self, account_id: str) -> dict[str, Any] | None:
        """Look up an account by its uuid. Used by the billing flow to
        re-fetch the just-granted account -- e.g. on a duplicate Telegram
        webhook, or the USDT invoice-status endpoint. The plaintext key is
        never stored, so this cannot re-deliver the key text -- the key is
        shown once at creation; a lost key is replaced via rotate_key, not
        recovered. Only key_prefix is available here for identification."""
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
                select id, key_prefix, key_hash, tier, created_at
                from accounts where id = %s
                """,
                (parsed_id,),
            )
            row = await cur.fetchone()
        return _row_to_account(row) if row else None


class LlmUsageRepository:
    """The single journal of what each LLM-backed job cost (migration
    0020_llm_usage.sql). Same real/fake split and not-configured contract as
    AuditRepository: when DATABASE_URL isn't set, create() returns None instead
    of failing, so a scan on an unconfigured deployment still runs -- it just
    doesn't record usage (there is nowhere to record it).

    Write-only in this step: nothing reads it to block a request yet. The
    per-account daily-spend aggregate a follow-up step will add is a single
    SUM(cost_usd) over this table (see the account/created_at index), so no read
    method is added here until that enforcement work lands and can be tested
    against real behavior."""

    async def create(
        self, *, job_type: str, job_id: str | None,
        account_id: str | None, model: str, calls: int,
        input_tokens: int, output_tokens: int, cost_usd: Any,
    ) -> dict[str, Any] | None:
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        # Both foreign-keyish columns are nullable uuids: a scan with no
        # persisted audit row (job_id) or an anonymous/system job (account_id)
        # must still record its cost, not be dropped. An unparseable id is
        # treated as absent rather than raising -- the cost fact matters more
        # than the linkage.
        parsed_job_id = _uuid_or_none(job_id)
        parsed_account_id = _uuid_or_none(account_id)
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into llm_usage
                    (job_type, job_id, account_id, model, calls,
                     input_tokens, output_tokens, cost_usd)
                values (%s, %s, %s, %s, %s, %s, %s, %s)
                returning id, job_type, job_id, account_id, model, calls,
                          input_tokens, output_tokens, cost_usd, created_at
                """,
                (job_type, parsed_job_id, parsed_account_id, model,
                 int(calls), int(input_tokens), int(output_tokens), cost_usd),
            )
            row = await cur.fetchone()
        return dict(row) if row else None

    async def sum_anon_spend_today(self) -> Decimal | None:
        """Total USD spent today (UTC) by anonymous/free traffic -- every
        llm_usage row with account_id IS NULL since UTC midnight. This is a
        GLOBAL backstop over all anonymous callers, not a per-IP figure
        (account_id IS NULL can't tell two anon callers apart; per-IP is the
        request-count rate limiter's job). The daily-spend cap in app/main.py
        reads this before running a scan. Returns None when DATABASE_URL isn't
        set -- an unconfigured deployment has no journal to cap against and the
        caller treats None as "no data, don't degrade"."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select coalesce(sum(cost_usd), 0) as spend
                from llm_usage
                where account_id is null
                  and created_at >= date_trunc('day', now() at time zone 'UTC')
                """,
            )
            row = await cur.fetchone()
        return Decimal(row["spend"]) if row else Decimal(0)


class ServiceFlagsRepository:
    """Operator-controlled kill switches (migration 0021_service_flags.sql).
    One row per flag; the only one used today is key='llm_paid_ops', the
    emergency stop for all LLM-spending work. Same not-configured contract as
    the other repositories: with no DATABASE_URL, get() returns None and the
    caller treats "no flag store" as "not paused" -- an unconfigured dev box
    must still run scans."""

    async def get(self, key: str) -> dict[str, Any] | None:
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select key, enabled, note, updated_at
                from service_flags where key = %s
                """,
                (key,),
            )
            row = await cur.fetchone()
        return dict(row) if row else None

    async def set(self, key: str, *, enabled: bool,
                  note: str | None = None) -> dict[str, Any] | None:
        """Upsert a flag (used by the internal toggle endpoint). Returns the
        stored row, or None when DATABASE_URL isn't set."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into service_flags (key, enabled, note, updated_at)
                values (%s, %s, %s, now())
                on conflict (key) do update
                   set enabled = excluded.enabled,
                       note = excluded.note,
                       updated_at = now()
                returning key, enabled, note, updated_at
                """,
                (key, enabled, note),
            )
            row = await cur.fetchone()
        return dict(row) if row else None


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
        product: str = "pro_tier", audit_id: str | None = None,
        paypal_order_id: str | None = None,
    ) -> dict[str, Any] | None:
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        parsed_account_id = uuid.UUID(account_id) if account_id else None
        parsed_audit_id = uuid.UUID(audit_id) if audit_id else None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into payments
                    (account_id, provider, external_ref, amount, currency,
                     status, tier_granted, product, audit_id, paypal_order_id)
                values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                returning id, account_id, provider, external_ref, amount,
                          currency, status, tier_granted, telegram_chat_id,
                          product, audit_id, paypal_order_id, created_at
                """,
                (parsed_account_id, provider, external_ref, amount, currency,
                 status, tier_granted, product, parsed_audit_id,
                 paypal_order_id),
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
                       currency, status, tier_granted, telegram_chat_id,
                       product, audit_id, paypal_order_id, created_at
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
                       currency, status, tier_granted, telegram_chat_id,
                       product, audit_id, paypal_order_id, created_at
                from payments where provider = %s and external_ref = %s
                """,
                (provider, external_ref),
            )
            row = await cur.fetchone()
        return _row_to_payment(row) if row else None

    async def get_by_paypal_order_id(
        self, paypal_order_id: str
    ) -> dict[str, Any] | None:
        """The pending payment created at PayPal order time, keyed by the order
        id (migration 0018's partial unique index). Backs both the webhook
        (transition the pending row to completed via invoice_payment_id) and
        GET /v1/paypal/orders/{id} (poll the granted key back). None when
        DATABASE_URL isn't set or there's no such order."""
        if not paypal_order_id:
            return None
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, account_id, provider, external_ref, amount,
                       currency, status, tier_granted, telegram_chat_id,
                       product, audit_id, paypal_order_id, created_at
                from payments where paypal_order_id = %s
                """,
                (paypal_order_id,),
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
                       currency, status, tier_granted, telegram_chat_id,
                       product, audit_id, paypal_order_id, created_at
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

    async def mark_completed_fixpack(
        self, payment_id: str, *, external_ref: str
    ) -> None:
        """Transition a pending Fix Pack invoice to completed, stamping the
        on-chain tx as its external_ref. The Fix Pack counterpart to
        mark_completed -- but a Fix Pack grants no account/tier, so this
        never sets account_id (it stays null). No-op when DATABASE_URL isn't
        set, matching mark_completed."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return
        async with pool.connection() as conn:
            await conn.execute(
                """
                update payments
                set status = 'completed', external_ref = %s
                where id = %s
                """,
                (external_ref, uuid.UUID(payment_id)),
            )

    async def get_completed_by_telegram_chat_id(
        self, telegram_chat_id: str
    ) -> dict[str, Any] | None:
        """The completed payment linked to this Telegram chat_id, if any
        (newest first). Backs /mykey: a chat_id has an account -- and thus
        a recoverable key -- exactly when a completed payment carries it
        (Stars stamps it at purchase, USDT via /link). Returns None when
        DATABASE_URL isn't set, same not-configured contract as get."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, account_id, provider, external_ref, amount,
                       currency, status, tier_granted, telegram_chat_id,
                       product, audit_id, paypal_order_id, created_at
                from payments
                where telegram_chat_id = %s and status = 'completed'
                order by created_at desc
                limit 1
                """,
                (telegram_chat_id,),
            )
            row = await cur.fetchone()
        return _row_to_payment(row) if row else None

    async def link_telegram_chat_id(
        self, payment_id: str, telegram_chat_id: str
    ) -> dict[str, Any] | None:
        """First-successful-link-wins: stamp telegram_chat_id onto a payment
        ONLY if it has none yet (WHERE telegram_chat_id is null). This is the
        atomic guard behind /link's anti-hijack rule -- two racing callers
        can't both claim the same on-chain payment, the second's update
        touches zero rows. Idempotent for the same claimer via the OR clause.
        Always returns the row's CURRENT state (whoever owns it now), so the
        caller can tell whether it won the claim or lost to an earlier one.
        No-op-safe when DATABASE_URL isn't set (returns None)."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        pid = uuid.UUID(payment_id)
        async with pool.connection() as conn:
            await conn.execute(
                """
                update payments set telegram_chat_id = %s
                where id = %s
                  and (telegram_chat_id is null or telegram_chat_id = %s)
                """,
                (telegram_chat_id, pid, telegram_chat_id),
            )
            cur = await conn.execute(
                """
                select id, account_id, provider, external_ref, amount,
                       currency, status, tier_granted, telegram_chat_id,
                       product, audit_id, paypal_order_id, created_at
                from payments where id = %s
                """,
                (pid,),
            )
            row = await cur.fetchone()
        return _row_to_payment(row) if row else None


class SubscriptionRepository:
    """Recurring Stars subscriptions (migration 0015). Same real/fake split
    and not-configured contract as the other repositories: when DATABASE_URL
    isn't set every method no-ops (returns None) instead of failing, so the
    Telegram webhook still answers even on a deployment without a database.

    The natural key is (telegram_user_id, invoice_payload): a
    BotSubscriptionUpdated update (Bot API `subscription` field) carries only
    those two fields, never a charge id, so they are the only stable way to
    resolve a state change back to a row. upsert_first / renew / set_status
    all pivot on it. See migration 0015 for the full rationale."""

    async def get_by_user_and_payload(
        self, telegram_user_id: str, invoice_payload: str
    ) -> dict[str, Any] | None:
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, account_id, telegram_user_id, telegram_chat_id,
                       tier, invoice_payload, telegram_payment_charge_id,
                       status, expires_at, payment_provider,
                       paypal_subscription_id, created_at, updated_at
                from subscriptions
                where telegram_user_id = %s and invoice_payload = %s
                """,
                (telegram_user_id, invoice_payload),
            )
            row = await cur.fetchone()
        return _row_to_subscription(row) if row else None

    async def get_active_by_user(
        self, telegram_user_id: str
    ) -> dict[str, Any] | None:
        """The most recent still-charging subscription for a user (status
        'active'), newest first. Backs /unsubscribe, which needs the stored
        telegram_payment_charge_id to call editUserStarSubscription."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, account_id, telegram_user_id, telegram_chat_id,
                       tier, invoice_payload, telegram_payment_charge_id,
                       status, expires_at, payment_provider,
                       paypal_subscription_id, created_at, updated_at
                from subscriptions
                where telegram_user_id = %s and status = 'active'
                order by created_at desc
                limit 1
                """,
                (telegram_user_id,),
            )
            row = await cur.fetchone()
        return _row_to_subscription(row) if row else None

    async def upsert_first(
        self, *, telegram_user_id: str, invoice_payload: str, tier: str,
        telegram_chat_id: str | None, telegram_payment_charge_id: str | None,
        expires_at: Any, repo_full_name: str | None = None,
    ) -> dict[str, Any] | None:
        """Record the first payment of a subscription (is_first_recurring).
        Upsert on the natural key so a retried first-payment webhook lands on
        the same row (idempotent) and re-enabling a previously canceled/expired
        subscription reactivates its row rather than colliding. Sets status
        back to 'active'.

        repo_full_name (Phase C) is the canonical 'owner/repo' this subscription
        monitors, or None for the legacy no-repo tier. It rides the natural key
        via the invoice_payload ('sub:monitor:<owner/repo>'), so a re-upsert for
        the same payload always carries the same repo."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        expires_dt = _expires_at_to_timestamptz(expires_at)
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into subscriptions
                    (telegram_user_id, invoice_payload, tier, telegram_chat_id,
                     telegram_payment_charge_id, status, repo_full_name,
                     expires_at)
                values (%s, %s, %s, %s, %s, 'active', %s, %s)
                on conflict (telegram_user_id, invoice_payload) do update
                   set tier = excluded.tier,
                       telegram_chat_id = excluded.telegram_chat_id,
                       telegram_payment_charge_id =
                           excluded.telegram_payment_charge_id,
                       status = 'active',
                       expires_at = excluded.expires_at,
                       repo_full_name = excluded.repo_full_name,
                       updated_at = now()
                returning id, account_id, telegram_user_id, telegram_chat_id,
                          tier, invoice_payload, telegram_payment_charge_id,
                          status, expires_at, repo_full_name, last_monitored_at,
                          payment_provider, paypal_subscription_id,
                          created_at, updated_at
                """,
                (telegram_user_id, invoice_payload, tier, telegram_chat_id,
                 telegram_payment_charge_id, repo_full_name, expires_dt),
            )
            row = await cur.fetchone()
        return _row_to_subscription(row) if row else None

    async def list_active_for_repo(
        self, repo_full_name: str
    ) -> list[dict[str, Any]]:
        """Monitoring subscriptions with live access for a repo: expires_at in
        the future (the access boundary from 0015, which honors a
        canceled-but-still-in-period subscription). Matched on the canonical
        repo_full_name (app/monitor.normalize_repo_full_name), stored
        already-normalized, so this is an exact-equality lookup. Empty list when
        DATABASE_URL isn't set."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return []
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, account_id, telegram_user_id, telegram_chat_id,
                       tier, invoice_payload, telegram_payment_charge_id,
                       status, expires_at, repo_full_name, last_monitored_at,
                       payment_provider, paypal_subscription_id,
                       created_at, updated_at
                from subscriptions
                where repo_full_name = %s
                      and expires_at is not null and expires_at > now()
                order by created_at asc
                """,
                (repo_full_name,),
            )
            rows = await cur.fetchall()
        return [_row_to_subscription(r) for r in rows]

    async def claim_for_monitoring(
        self, repo_full_name: str, at: datetime.datetime
    ) -> bool:
        """Atomically claim this repo for a monitoring run and report whether the
        claim was won. In one write it stamps last_monitored_at = `at` on the
        repo's subscription rows IFF none has been monitored within the last 24h
        -- so this is BOTH the 24h-per-repo cost cap AND the concurrency guard.

        Two near-simultaneous default-branch pushes race on this UPDATE: the
        first commits and stamps the rows; the second, under READ COMMITTED,
        re-checks its WHERE against the freshly-committed rows, finds them no
        longer eligible, updates nothing, and returns an empty set -- so exactly
        one push re-audits and notifies. Same idea as the Fix Pack processor's
        FOR UPDATE SKIP LOCKED job claim, expressed as a conditional UPDATE.

        Returns False (nothing claimed) when DATABASE_URL isn't set. Callers must
        claim BEFORE the audit, not after, so the stamp also throttles retries of
        a dead/unfetchable repo."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return False
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update subscriptions
                   set last_monitored_at = %s, updated_at = now()
                 where repo_full_name = %s
                   and (last_monitored_at is null
                        or last_monitored_at < %s - interval '24 hours')
                returning id
                """,
                (at, repo_full_name, at),
            )
            rows = await cur.fetchall()
        return len(rows) > 0

    async def renew(
        self, subscription_id: str, *, expires_at: Any,
        telegram_payment_charge_id: str | None,
    ) -> dict[str, Any] | None:
        """A recurring renewal (is_recurring, not first): push expires_at out
        and rotate telegram_payment_charge_id to this period's charge (the id
        editUserStarSubscription needs is the latest one). Never creates a row.
        Also clears any failed/canceled status back to active, since a
        successful charge means the subscription is charging again."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        expires_dt = _expires_at_to_timestamptz(expires_at)
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update subscriptions
                   set expires_at = %s,
                       telegram_payment_charge_id = %s,
                       status = 'active',
                       updated_at = now()
                 where id = %s
                returning id, account_id, telegram_user_id, telegram_chat_id,
                          tier, invoice_payload, telegram_payment_charge_id,
                          status, expires_at, payment_provider,
                          paypal_subscription_id, created_at, updated_at
                """,
                (expires_dt, telegram_payment_charge_id,
                 uuid.UUID(subscription_id)),
            )
            row = await cur.fetchone()
        return _row_to_subscription(row) if row else None

    async def set_status(
        self, subscription_id: str, status: str
    ) -> dict[str, Any] | None:
        """Update only the renewal status (canceled/active/failed/expired).
        expires_at is deliberately untouched -- access is expires_at-based, and
        a canceled or failed-renewal subscription keeps the period it paid
        for. See migration 0015."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update subscriptions
                   set status = %s, updated_at = now()
                 where id = %s
                returning id, account_id, telegram_user_id, telegram_chat_id,
                          tier, invoice_payload, telegram_payment_charge_id,
                          status, expires_at, payment_provider,
                          paypal_subscription_id, created_at, updated_at
                """,
                (status, uuid.UUID(subscription_id)),
            )
            row = await cur.fetchone()
        return _row_to_subscription(row) if row else None

    # --- PayPal (migration 0018) ---
    #
    # PayPal monitoring subscriptions have neither a telegram_user_id nor an
    # invoice_payload, so the Stars natural key can't identify them. These
    # methods pivot on paypal_subscription_id instead (the 'I-XXXX' id), the
    # PayPal-side natural key, and set payment_provider='paypal'. Exactly
    # parallel to upsert_first / renew / get_by_user_and_payload above.

    async def create_paypal(
        self, *, paypal_subscription_id: str, tier: str,
        repo_full_name: str | None,
    ) -> dict[str, Any] | None:
        """Pre-insert the subscriptions row at PayPal subscription-create time
        (status 'approval_pending', repo bound), before the buyer approves. This
        binds the repo while we still know it, so every later webhook just
        updates by paypal_subscription_id. Idempotent on the partial unique
        index: a retried create lands on the same row and leaves it untouched
        (the webhooks own status/expires_at). None when DATABASE_URL isn't set."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into subscriptions
                    (payment_provider, paypal_subscription_id, tier,
                     repo_full_name, status)
                values ('paypal', %s, %s, %s, 'approval_pending')
                on conflict (paypal_subscription_id)
                    where paypal_subscription_id is not null do nothing
                returning id, account_id, telegram_user_id, telegram_chat_id,
                          tier, invoice_payload, telegram_payment_charge_id,
                          status, expires_at, repo_full_name, last_monitored_at,
                          payment_provider, paypal_subscription_id,
                          created_at, updated_at
                """,
                (paypal_subscription_id, tier, repo_full_name),
            )
            row = await cur.fetchone()
        if row is not None:
            return _row_to_subscription(row)
        # ON CONFLICT DO NOTHING returns no row on a retry -- re-fetch it so the
        # caller always gets the current row rather than a spurious None.
        return await self.get_by_paypal_subscription_id(paypal_subscription_id)

    async def get_by_paypal_subscription_id(
        self, paypal_subscription_id: str
    ) -> dict[str, Any] | None:
        """Resolve a PayPal webhook (ACTIVATED / SALE / CANCELLED) back to its
        row by the 'I-XXXX' subscription id. None when DATABASE_URL isn't set or
        there's no such subscription."""
        if not paypal_subscription_id:
            return None
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, account_id, telegram_user_id, telegram_chat_id,
                       tier, invoice_payload, telegram_payment_charge_id,
                       status, expires_at, repo_full_name, last_monitored_at,
                       payment_provider, paypal_subscription_id,
                       created_at, updated_at
                from subscriptions where paypal_subscription_id = %s
                """,
                (paypal_subscription_id,),
            )
            row = await cur.fetchone()
        return _row_to_subscription(row) if row else None

    async def upsert_first_paypal(
        self, *, paypal_subscription_id: str, tier: str, expires_at: Any,
        repo_full_name: str | None,
    ) -> dict[str, Any] | None:
        """First-period activation (BILLING.SUBSCRIPTION.ACTIVATED): move the
        row to active with expires_at, creating it if the pre-insert was skipped
        or a SALE renewal arrived first. Upsert on paypal_subscription_id so a
        retried ACTIVATED lands on the same row (idempotent) -- the PayPal
        counterpart to upsert_first. Preserves the already-bound repo_full_name
        if this event lacks one. None when DATABASE_URL isn't set."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        expires_dt = _expires_at_to_timestamptz(expires_at)
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into subscriptions
                    (payment_provider, paypal_subscription_id, tier,
                     repo_full_name, status, expires_at)
                values ('paypal', %s, %s, %s, 'active', %s)
                on conflict (paypal_subscription_id)
                    where paypal_subscription_id is not null do update
                   set tier = excluded.tier,
                       status = 'active',
                       expires_at = excluded.expires_at,
                       repo_full_name =
                           coalesce(excluded.repo_full_name,
                                    subscriptions.repo_full_name),
                       updated_at = now()
                returning id, account_id, telegram_user_id, telegram_chat_id,
                          tier, invoice_payload, telegram_payment_charge_id,
                          status, expires_at, repo_full_name, last_monitored_at,
                          payment_provider, paypal_subscription_id,
                          created_at, updated_at
                """,
                (paypal_subscription_id, tier, repo_full_name, expires_dt),
            )
            row = await cur.fetchone()
        return _row_to_subscription(row) if row else None

    async def renew_paypal(
        self, subscription_id: str, *, expires_at: Any,
    ) -> dict[str, Any] | None:
        """A recurring PayPal renewal (PAYMENT.SALE.COMPLETED): push expires_at
        out and clear any canceled/suspended status back to active, since a
        successful charge means it's charging again. Never creates a row -- the
        caller falls back to upsert_first_paypal when the row is missing. The
        PayPal counterpart to renew (no charge id to rotate: PayPal keys the
        row on paypal_subscription_id, not the sale id). None when DATABASE_URL
        isn't set."""
        expires_dt = _expires_at_to_timestamptz(expires_at)
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update subscriptions
                   set expires_at = %s, status = 'active', updated_at = now()
                 where id = %s
                returning id, account_id, telegram_user_id, telegram_chat_id,
                          tier, invoice_payload, telegram_payment_charge_id,
                          status, expires_at, repo_full_name, last_monitored_at,
                          payment_provider, paypal_subscription_id,
                          created_at, updated_at
                """,
                (expires_dt, uuid.UUID(subscription_id)),
            )
            row = await cur.fetchone()
        return _row_to_subscription(row) if row else None


class MonitoringRunRepository:
    """The async continuous-monitoring job queue (migration 0017). Directly
    analogous to FixpackJobRepository's durable-lease model: the push webhook
    enqueues one 'pending' run per won claim, and the processor claims each into
    a 'running' lease, runs the audit+diff+notify, and marks it terminal.

    Same real/fake split and not-configured contract as the other repositories:
    when DATABASE_URL isn't set every method no-ops (returns None / a zero
    result) instead of failing, so an enqueue on a DB-less deployment simply does
    nothing rather than breaking the fast webhook ACK."""

    async def enqueue(self, repo_full_name: str) -> dict[str, Any] | None:
        """Insert one 'pending' monitoring run for a repo whose push just won the
        claim_for_monitoring gate. Fast INSERT (no audit) so the webhook can ACK
        200 immediately. Returns None when DATABASE_URL isn't set."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into monitoring_runs (repo_full_name, status)
                values (%s, 'pending')
                returning id, repo_full_name, status, attempts, started_at,
                          error, created_at, completed_at
                """,
                (repo_full_name,),
            )
            row = await cur.fetchone()
        return _row_to_monitoring_run(row) if row else None

    async def claim_one_pending(self) -> dict[str, Any] | None:
        """Atomically claim the oldest 'pending' monitoring run into a 'running'
        lease, and return it -- or None when there is nothing to claim (or
        DATABASE_URL isn't set).

        Same concurrency guard as FixpackJobRepository.claim_one_paid: the inner
        SELECT ... FOR UPDATE SKIP LOCKED LIMIT 1 row-locks exactly one candidate
        and skips any a concurrent run already locked, and the surrounding UPDATE
        flips it 'pending' -> 'running' in the same statement, so two overlapping
        processor runs can never both claim the same run. started_at stamps the
        lease (the reaper reads it) and attempts is incremented so crash-requeues
        are bounded."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update monitoring_runs
                   set status = 'running',
                       started_at = now(),
                       attempts = attempts + 1
                 where id = (
                     select id from monitoring_runs
                      where status = 'pending'
                      order by created_at asc
                      for update skip locked
                      limit 1
                 )
                returning id, repo_full_name, status, attempts, started_at,
                          error, created_at, completed_at
                """,
            )
            row = await cur.fetchone()
        return _row_to_monitoring_run(row) if row else None

    async def mark_done(self, run_id: str) -> None:
        """Advance a run to the terminal 'done' state (audit+diff+notify finished,
        whether or not it found new findings). No-op when DATABASE_URL isn't
        set."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return
        async with pool.connection() as conn:
            await conn.execute(
                """
                update monitoring_runs
                   set status = 'done', completed_at = now()
                 where id = %s
                """,
                (uuid.UUID(run_id),),
            )

    async def mark_failed(self, run_id: str, error: str) -> None:
        """Advance a run to the terminal 'failed' state with a diagnosable
        reason. The `error` is always written so a 'failed' row is never a silent
        failure (same hardening as fixpack_jobs.detail). No-op when DATABASE_URL
        isn't set."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return
        async with pool.connection() as conn:
            await conn.execute(
                """
                update monitoring_runs
                   set status = 'failed', error = %s, completed_at = now()
                 where id = %s
                """,
                (error, uuid.UUID(run_id)),
            )

    async def reap_stale_running(
        self, *, max_age_minutes: int, max_attempts: int
    ) -> dict[str, int]:
        """Recover monitoring runs whose worker crashed mid-audit: a 'running'
        lease older than max_age_minutes means no process is still working it.
        Run at the start of each processor pass, before claiming. Identical
        pattern to FixpackJobRepository.reap_stale_running:

          - attempts < max_attempts -> back to 'pending' (started_at cleared) so
            the next claim retries it;
          - attempts >= max_attempts -> 'failed' with a diagnosable error, so a
            poison-pill run that crashes the worker every time stops re-queuing
            forever and stays visible for a human.

        Returns {'requeued': n, 'failed': m}. No-op ({'requeued': 0, 'failed': 0})
        when DATABASE_URL isn't set."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return {"requeued": 0, "failed": 0}
        async with pool.connection() as conn:
            requeued_cur = await conn.execute(
                """
                update monitoring_runs
                   set status = 'pending', started_at = null
                 where status = 'running'
                   and started_at < now() - make_interval(mins => %s)
                   and attempts < %s
                returning id
                """,
                (max_age_minutes, max_attempts),
            )
            requeued = len(await requeued_cur.fetchall())
            failed_cur = await conn.execute(
                """
                update monitoring_runs
                   set status = 'failed',
                       error = %s,
                       completed_at = now()
                 where status = 'running'
                   and started_at < now() - make_interval(mins => %s)
                   and attempts >= %s
                returning id
                """,
                (
                    f"stale lease reaped: no completion after {max_attempts} "
                    f"attempt(s), last lease older than {max_age_minutes}m",
                    max_age_minutes,
                    max_attempts,
                ),
            )
            failed = len(await failed_cur.fetchall())
        return {"requeued": requeued, "failed": failed}


# Every audit_jobs column except access_token, which is the row's ownership
# secret: it is minted by the column default, handed back exactly once from
# enqueue()'s RETURNING, and thereafter only ever matched in SQL by
# get_authorized() -- never re-selected into a payload. Named once because the
# list is long enough that repeating it per statement invites drift.
_AUDIT_JOB_COLUMN_NAMES = (
    "id", "state", "source_kind", "source_ref", "content_hash",
    "engine_version", "stack", "account_id", "quota_key", "idempotency_key",
    "claimed_by", "claimed_at", "lease_expires_at", "attempts", "max_attempts",
    "available_at", "audit_id", "error_code", "error_message", "created_at",
    "updated_at", "completed_at",
)
_AUDIT_JOB_COLUMNS = ", ".join(_AUDIT_JOB_COLUMN_NAMES)
# The same list qualified for get_authorized's join against audits, where a
# bare `id` would be ambiguous.
_AUDIT_JOB_COLUMNS_QUALIFIED = ", ".join(
    f"j.{name}" for name in _AUDIT_JOB_COLUMN_NAMES
)


class AuditJobRepository:
    """The durable audit queue (migration 0022) -- Stage 2's answer to an audit
    that today runs inline in the API process and leaves no row behind if the
    process restarts mid-scan.

    Third instance of the lease model already in production here
    (FixpackJobRepository.claim_one_paid, MonitoringRunRepository.
    claim_one_pending), with two deliberate additions those two do not have:

      - a RENEWABLE lease (lease_expires_at + renew_lease) instead of a flat
        `started_at < now() - max_age`, because an audit's honest runtime varies
        by an order of magnitude with repo size and provider retries; and
      - every post-claim transition gated on `claimed_by`, so a worker whose
        lease was already reaped cannot overwrite the row a second worker now
        legitimately holds. Each such method returns a bool saying whether it
        still owned the row -- False means "you lost the lease, write nothing".

    Same not-configured contract as every other repository: when DATABASE_URL
    isn't set each method returns None / False / a zero result rather than
    failing, so a DB-less deployment degrades instead of breaking.
    """

    async def enqueue(
        self, *, source_kind: str, source_ref: str | None,
        content_hash: str, engine_version: str, stack: str | None,
        account_id: str | None, quota_key: str | None,
        idempotency_key: str, job_id: str | None = None,
        initial_state: str = "queued",
    ) -> dict[str, Any] | None:
        """Insert one claimable job, or return the live job that already covers
        this submission.

        `initial_state` defaults to 'queued' -- the right answer for a repo_url
        job, whose whole payload is the URL already in the row. An uploaded
        archive has to be written to the spool before any worker may claim the
        job, so that caller passes 'created' and flips the row with
        mark_queued() once the bytes are on disk; a crash in between leaves a
        row no worker will ever claim rather than a claimable job pointing at a
        payload that was never written. `job_id` exists for the same caller: the
        spool filename is the job id, so the id has to be known before the
        archive can be staged, which means before the INSERT. Left None, the
        column default (gen_random_uuid()) still mints it.

        The ON CONFLICT arbiter names audit_jobs_idempotency_live_idx by
        repeating its predicate, so a duplicate submission collides only with a
        job that is still live -- once the earlier job is terminal the same key
        inserts a fresh row. DO UPDATE rather than DO NOTHING because only DO
        UPDATE returns the conflicting row; the assignment is a deliberate no-op
        (updated_at to its own value) so re-submitting does not disturb the
        existing job's timestamps. DO NOTHING + a follow-up SELECT would be two
        statements and could observe the row after another transaction moved it
        on.

        `inserted` distinguishes the two outcomes for the caller (a fresh job
        vs. joining one in flight) via the xmax idiom: on a plain INSERT the new
        tuple has no updating transaction, so xmax is 0.

        Returns None when DATABASE_URL isn't set."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        parsed_account_id = uuid.UUID(account_id) if account_id else None
        parsed_job_id = uuid.UUID(job_id) if job_id else None
        async with pool.connection() as conn:
            cur = await conn.execute(
                f"""
                insert into audit_jobs
                    (id, state, source_kind, source_ref, content_hash,
                     engine_version, stack, account_id, quota_key,
                     idempotency_key)
                values (coalesce(%s::uuid, gen_random_uuid()),
                        %s, %s, %s, %s, %s, %s, %s, %s, %s)
                on conflict (idempotency_key)
                    where state in ('created', 'queued', 'claimed', 'running')
                do update set updated_at = audit_jobs.updated_at
                returning access_token, (xmax = 0) as inserted,
                          {_AUDIT_JOB_COLUMNS}
                """,
                (
                    parsed_job_id, initial_state, source_kind, source_ref,
                    content_hash, engine_version, stack, parsed_account_id,
                    quota_key, idempotency_key,
                ),
            )
            row = await cur.fetchone()
        return _row_to_audit_job(row) if row else None

    async def mark_queued(
        self, *, job_id: str, source_ref: str | None = None
    ) -> bool:
        """Promote a staged 'created' job to 'queued', making it claimable, and
        record where its payload landed.

        source_ref is written in the same statement rather than at insert time
        because a spool path only becomes true once the bytes are there: a row
        naming a file that does not exist yet is a row that lies for as long as
        the write takes.

        Gated on state = 'created' so it can only ever fire once and can never
        drag a job that has already been claimed, finished or abandoned back
        into the queue. False means the row was not in 'created' (or the id is
        unknown / the DB unconfigured) -- the caller has just staged a payload
        for a job that no longer wants it and should clean up."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return False
        try:
            parsed_id = uuid.UUID(job_id)
        except ValueError:
            return False
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update audit_jobs
                   set state = 'queued', available_at = now(),
                       source_ref = coalesce(%s, source_ref),
                       updated_at = now()
                 where id = %s and state = 'created'
                returning id
                """,
                (source_ref, parsed_id),
            )
            row = await cur.fetchone()
        return row is not None

    async def abandon_created(
        self, *, job_id: str, error_code: str, error_message: str
    ) -> bool:
        """Dead-letter a job whose payload staging failed, without it ever
        having been claimable.

        This is not just tidiness. audit_jobs_idempotency_live_idx covers
        'created', so a row left there holds that submission's idempotency key
        hostage: the caller retries, collides with a job no worker will ever
        claim, and is told to poll a job that will never move. Marking it
        terminal releases the key immediately, so the retry gets a fresh job.

        Gated on 'created' for the same reason as mark_queued."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return False
        try:
            parsed_id = uuid.UUID(job_id)
        except ValueError:
            return False
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update audit_jobs
                   set state = 'dead_letter', error_code = %s,
                       error_message = %s, completed_at = now(),
                       updated_at = now()
                 where id = %s and state = 'created'
                returning id
                """,
                (error_code, error_message, parsed_id),
            )
            row = await cur.fetchone()
        return row is not None

    async def reap_stuck_created(
        self, *, older_than_seconds: int, error_message: str
    ) -> int:
        """Sweep 'created' rows whose staging never completed and never failed
        cleanly -- i.e. the API process died between the INSERT and
        mark_queued/abandon_created.

        reap_expired cannot cover these: it looks for an expired
        lease_expires_at, and a 'created' row has never been claimed, so it has
        no lease. Without this sweep 'created' would be a state nothing can
        leave, and its idempotency key would be held forever.

        The age bound is what keeps this from racing a staging that is merely
        slow: a large upload being fsynced is a live 'created' row, and only one
        far older than any plausible write is abandoned. Straight to
        'dead_letter', never 'queued' -- the payload was never written, so there
        is nothing for a worker to run.

        Returns the number of rows swept; 0 when DATABASE_URL isn't set."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return 0
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update audit_jobs
                   set state = 'dead_letter',
                       error_code = 'staging_incomplete',
                       error_message = %s,
                       completed_at = now(),
                       updated_at = now()
                 where state = 'created'
                   and created_at < now() - make_interval(
                       secs => %s::double precision)
                returning id
                """,
                (error_message, older_than_seconds),
            )
            rows = await cur.fetchall()
        return len(rows)

    async def claim_one(
        self, *, worker_id: str, lease_seconds: int
    ) -> dict[str, Any] | None:
        """Atomically lease the oldest claimable job to `worker_id`, or None
        when there is nothing to claim (or DATABASE_URL isn't set).

        Same concurrency guard as claim_one_paid / claim_one_pending: the inner
        SELECT ... FOR UPDATE SKIP LOCKED LIMIT 1 row-locks exactly one
        candidate and skips any a concurrent worker already locked, and the
        surrounding single-row UPDATE flips it 'queued' -> 'running' in the same
        statement -- so two workers can never both claim one job, which is what
        stops one upload from being scanned (and paid for) twice.

        `available_at <= now()` is the backoff gate: a job a transient failure
        pushed into the future is skipped until its retry is due.

        Goes straight to 'running' rather than writing 'claimed' first: a
        separate round-trip buys nothing here, and 'claimed' belongs to PR2's
        staged-payload flow. attempts is incremented here, so the attempt is
        counted even if the worker dies before reporting anything -- which is
        precisely what bounds crash-requeues."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                f"""
                update audit_jobs
                   set state = 'running',
                       claimed_by = %s,
                       claimed_at = now(),
                       lease_expires_at = now() + make_interval(secs => %s),
                       attempts = attempts + 1,
                       updated_at = now()
                 where id = (
                     select id from audit_jobs
                      where state = 'queued'
                        and available_at <= now()
                      order by created_at asc
                      for update skip locked
                      limit 1
                 )
                returning {_AUDIT_JOB_COLUMNS}
                """,
                (worker_id, lease_seconds),
            )
            row = await cur.fetchone()
        return _row_to_audit_job(row) if row else None

    async def renew_lease(
        self, *, job_id: str, worker_id: str, lease_seconds: int
    ) -> bool:
        """Push this worker's lease out by another `lease_seconds`. Called on a
        heartbeat while a long audit runs.

        True means the worker still holds the lease. False means it does not --
        the reaper already requeued or dead-lettered the row, or another worker
        holds it now -- and the caller MUST abort and write nothing, because any
        result it produces belongs to an attempt the queue has already written
        off. Also False when DATABASE_URL isn't set or the id is malformed."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return False
        try:
            parsed_id = uuid.UUID(job_id)
        except ValueError:
            return False
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update audit_jobs
                   set lease_expires_at = now() + make_interval(secs => %s),
                       updated_at = now()
                 where id = %s and claimed_by = %s and state = 'running'
                returning id
                """,
                (lease_seconds, parsed_id, worker_id),
            )
            row = await cur.fetchone()
        return row is not None

    async def finalize_succeeded(
        self, *, job_id: str, worker_id: str, audit_id: str
    ) -> bool:
        """Terminal success: record which audits row this job produced.

        Same lease gate and same False contract as renew_lease -- a worker that
        lost its lease must not be able to mark the job done, or a job the
        reaper already handed to someone else would end up with two results and
        one of them silently orphaned."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return False
        try:
            parsed_id = uuid.UUID(job_id)
            parsed_audit_id = uuid.UUID(audit_id)
        except ValueError:
            return False
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update audit_jobs
                   set state = 'succeeded',
                       audit_id = %s,
                       completed_at = now(),
                       updated_at = now()
                 where id = %s and claimed_by = %s and state = 'running'
                returning id
                """,
                (parsed_audit_id, parsed_id, worker_id),
            )
            row = await cur.fetchone()
        return row is not None

    async def finalize_failed(
        self, *, job_id: str, worker_id: str, error_code: str,
        error_message: str, permanent: bool, backoff_seconds: int = 30,
    ) -> bool:
        """Terminal failure, or a bounded retry -- one statement, because the
        branch depends on `attempts`, which only the row knows.

        `permanent=True` (a corrupt archive, an unsupported stack, a poison-pill
        crash) goes straight to 'dead_letter': re-running it would fail the same
        way and burn another worker. `permanent=False` (provider 5xx, rate
        limit, upstream fetch failure) goes back to 'queued' with exponential
        backoff while attempts remain, and to 'dead_letter' once they don't.

        attempts is NOT touched here -- claim_one already counted this attempt.

        A requeue clears the lease so the row is claimable again; a dead_letter
        keeps claimed_by/claimed_at as the forensic record of which worker last
        held it, and stamps completed_at. Same lease gate and False contract as
        finalize_succeeded.

        error_code/error_message are written in both branches, so on a requeued
        row they mean "why the PREVIOUS attempt failed", not "this job failed" --
        read them together with `state`, never alone.

        Named parameters, unlike the rest of this module: the branch condition
        appears in five assignments and repeating it positionally would make the
        argument order the only thing keeping them in agreement."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return False
        try:
            parsed_id = uuid.UUID(job_id)
        except ValueError:
            return False
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update audit_jobs
                   set state = case when %(terminal)s or attempts >= max_attempts
                                    then 'dead_letter' else 'queued' end,
                       error_code = %(error_code)s,
                       error_message = %(error_message)s,
                       claimed_by = case when %(terminal)s or attempts >= max_attempts
                                         then claimed_by else null end,
                       claimed_at = case when %(terminal)s or attempts >= max_attempts
                                         then claimed_at else null end,
                       lease_expires_at = null,
                       available_at = case
                           when %(terminal)s or attempts >= max_attempts
                           then available_at
                           else now() + make_interval(
                               secs => %(backoff_seconds)s::double precision
                                       * power(2, attempts))
                       end,
                       completed_at = case
                           when %(terminal)s or attempts >= max_attempts
                           then now() else null end,
                       updated_at = now()
                 where id = %(job_id)s
                   and claimed_by = %(worker_id)s
                   and state = 'running'
                returning id
                """,
                {
                    "terminal": permanent,
                    "error_code": error_code,
                    "error_message": error_message,
                    "backoff_seconds": backoff_seconds,
                    "job_id": parsed_id,
                    "worker_id": worker_id,
                },
            )
            row = await cur.fetchone()
        return row is not None

    async def release_early(self, *, job_id: str, worker_id: str) -> bool:
        """Hand a claimed job straight back to the queue, unrun and unpenalised.

        This is the graceful-shutdown path: on SIGTERM the worker stops
        claiming and gives in-flight jobs a budget to finish, and whatever is
        still running when that budget expires is released here. Waiting for
        the lease to expire instead would strand the job for up to the full
        TTL on every ordinary redeploy, which is the opposite of graceful.

        attempts is decremented (floored at zero) because claim_one counts an
        attempt optimistically and this attempt did not happen -- the job was
        interrupted by an operator action, not by anything about the job. Left
        alone, three routine redeploys during one long audit would dead-letter
        a perfectly good submission.

        error_code/error_message are deliberately not written: a released job
        is not a failed one, exactly as in reap_expired's requeue branch.

        Same lease gate and same False contract as the finalize_* methods, so
        a worker that already lost its lease cannot yank a job back out from
        under the worker now legitimately running it."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return False
        try:
            parsed_id = uuid.UUID(job_id)
        except ValueError:
            return False
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update audit_jobs
                   set state = 'queued',
                       claimed_by = null,
                       claimed_at = null,
                       lease_expires_at = null,
                       available_at = now(),
                       attempts = greatest(attempts - 1, 0),
                       updated_at = now()
                 where id = %s and claimed_by = %s and state = 'running'
                returning id
                """,
                (parsed_id, worker_id),
            )
            row = await cur.fetchone()
        return row is not None

    async def reap_expired(self, *, error_message: str) -> dict[str, int]:
        """Recover jobs whose worker died holding the lease: an expired
        lease_expires_at means nobody is renewing it, so nobody is working it.
        Run at the start of each worker pass, before claiming.

        Two outcomes, bounded by attempts (incremented at each claim), exactly
        as in FixpackJobRepository.reap_stale_running:

          - attempts < max_attempts -> back to 'queued', lease cleared and
            available_at reset to now() so the next pass retries it immediately.
            No error_code is written: a requeued job is not in a failed state,
            and a stale code would misreport the next attempt.
          - attempts >= max_attempts -> 'dead_letter' with error_code
            'lease_expired', so a job that kills its worker every time stops
            re-queuing forever and stays visible for a human.

        This is the required counterpart to the lease: without it a crashed
        worker's job is the zombie-forever state the durable design exists to
        avoid, and it is also what makes a SIGKILLed worker safe -- the job is
        never lost, only delayed by at most the lease TTL.

        Returns {'requeued': n, 'dead_lettered': m}; zeros when DATABASE_URL
        isn't set."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return {"requeued": 0, "dead_lettered": 0}
        async with pool.connection() as conn:
            requeued_cur = await conn.execute(
                """
                update audit_jobs
                   set state = 'queued',
                       claimed_by = null,
                       claimed_at = null,
                       lease_expires_at = null,
                       available_at = now(),
                       updated_at = now()
                 where state in ('claimed', 'running')
                   and lease_expires_at < now()
                   and attempts < max_attempts
                returning id
                """,
            )
            requeued = len(await requeued_cur.fetchall())
            dead_cur = await conn.execute(
                """
                update audit_jobs
                   set state = 'dead_letter',
                       error_code = 'lease_expired',
                       error_message = %s,
                       completed_at = now(),
                       updated_at = now()
                 where state in ('claimed', 'running')
                   and lease_expires_at < now()
                   and attempts >= max_attempts
                returning id
                """,
                (error_message,),
            )
            dead_lettered = len(await dead_cur.fetchall())
        return {"requeued": requeued, "dead_lettered": dead_lettered}

    async def get_authorized(
        self, *, job_id: str, access_token: str | None
    ) -> dict[str, Any] | None:
        """Ownership-checked fetch for the future public poll endpoint: return
        the job only if `access_token` matches the row's per-row token. A
        missing/wrong token, an unknown id, a malformed id and an unconfigured
        DB all return None, so the endpoint can answer 404 uniformly and never
        confirm a job id's existence to a caller who doesn't hold its token.
        The token is matched in SQL and is not among the selected columns, so it
        never rides back out in a response body.

        Same contract and same shape as AuditRepository.get_authorized
        (migration 0010's pattern).

        The join adds `audit_access_token`: the finished audit's own ownership
        secret, which is a DIFFERENT token living on the audits row. Without it
        a caller holding the job token could learn its audit_id and still not
        read the audit. Handing it over is not a widening -- the job token is
        minted for, and returned exactly once to, the same submitter that would
        have been handed the audit token directly by the old synchronous
        response. It is null until the job succeeds and links its audit."""
        if not access_token:
            return None
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
                f"""
                select {_AUDIT_JOB_COLUMNS_QUALIFIED},
                       a.access_token as audit_access_token
                  from audit_jobs j
                  left join audits a on a.id = j.audit_id
                 where j.id = %s and j.access_token = %s
                """,
                (parsed_id, access_token),
            )
            row = await cur.fetchone()
        return _row_to_audit_job(row) if row else None

    async def backlog_stats(self) -> dict[str, Any] | None:
        """Health signal for the audit worker: how many jobs sit in each state,
        plus the age in seconds of the oldest still-queued job.

        The age is the honest "is the worker draining the queue" signal -- if it
        grows past the lease TTL, no worker is claiming. `states` only contains
        states that currently have rows, so a caller reading a specific one
        should use .get(name, 0).

        Returns None when DATABASE_URL isn't set, so a health endpoint can
        report db:false rather than guessing. Consumed by /readyz and by
        GET /internal/audit-jobs/stats."""
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select state, count(*) as jobs,
                       extract(epoch from (now() - min(created_at)))
                           as oldest_seconds
                  from audit_jobs
                 group by state
                """,
            )
            rows = await cur.fetchall()
        states = {row["state"]: int(row["jobs"]) for row in rows}
        oldest_queued = next(
            (row["oldest_seconds"] for row in rows if row["state"] == "queued"),
            None,
        )
        return {
            "states": states,
            "queued": states.get("queued", 0),
            "oldest_queued_seconds": (
                float(oldest_queued) if oldest_queued is not None else None
            ),
        }
