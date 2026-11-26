from __future__ import annotations

import datetime
import json
import uuid
from typing import Any

from app.db._core import (
    AuditJobIdempotencyConflict,
    DatabaseNotConfigured,
    STALE_LEASE_DETAIL_PREFIX,
    _resolve_get_pool,
    _row_to_audit_job,
    _row_to_fixpack_job,
    _seconds_to_ms,
)


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
            pool = await _resolve_get_pool()()
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
        self, *, audit_id: str | None, stack: str, funding_key: str | None = None,
    ) -> dict[str, Any] | None:
        """Reserve one job for a payment, retaining its identity after completion.

        Another payment can join a live audit job, but cannot replace its funding
        key. The caller must reconcile that payment rather than promise new work.
        A retry of the original payment returns its job even if it is terminal.
        """
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        parsed_audit_id = uuid.UUID(audit_id) if audit_id else None
        columns = """id, audit_id, pack, stack, verified, detail,
                     preview_local_url, preview_expires_at, pr_url, pr_delivered,
                     status, access_token, created_at, funding_key"""
        async with pool.connection() as conn:
            for _ in range(3):
                if funding_key is not None:
                    cur = await conn.execute(
                        f"select {columns}, false as inserted from fixpack_jobs "
                        "where funding_key = %s", (funding_key,),
                    )
                    row = await cur.fetchone()
                    if row:
                        return _row_to_fixpack_job(row)
                cur = await conn.execute(
                    "insert into fixpack_jobs (audit_id, pack, stack, status, funding_key) "
                    "values (%s, 'fixpack', %s, 'paid', %s) on conflict do nothing "
                    f"returning {columns}, true as inserted",
                    (parsed_audit_id, stack, funding_key),
                )
                row = await cur.fetchone()
                if row:
                    return _row_to_fixpack_job(row)
                cur = await conn.execute(
                    f"select {columns}, false as inserted from fixpack_jobs "
                    "where funding_key = %s or (audit_id = %s "
                    "and status in ('paid', 'running', 'awaiting_authorization')) "
                    "order by (funding_key = %s) desc nulls last limit 1",
                    (funding_key, parsed_audit_id, funding_key),
                )
                row = await cur.fetchone()
                if row:
                    return _row_to_fixpack_job(row)
                # The conflicting job became terminal before the SELECT.
            raise RuntimeError("Fix Pack reservation changed repeatedly; retry payment confirmation")

    async def mark_delivered(self, job_id: str, pr_url: str) -> None:
        try:
            pool = await _resolve_get_pool()()
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
            pool = await _resolve_get_pool()()
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

        Returns {'requeued': n, 'failed': m, 'failed_ids': [...]}. The ids are
        returned because a lease reaped to 'failed' is a terminal failure the
        processor must alert the operator about, and this row is written here
        rather than on the delivery path. No-op (zeros, empty list) when
        DATABASE_URL isn't set, matching the other
        not-configured contracts. This is the required counterpart to
        introducing the 'running' lease: without it, a crashed lease would
        be exactly the zombie-forever state the durable design set out to
        avoid."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return {"requeued": 0, "failed": 0, "failed_ids": []}
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
                    f"{STALE_LEASE_DETAIL_PREFIX} no completion after "
                    f"{max_attempts} "
                    f"attempt(s), last lease older than {max_age_minutes}m",
                    max_age_minutes,
                    max_attempts,
                ),
            )
            failed_ids = [str(row["id"]) for row in await failed_cur.fetchall()]
        return {"requeued": requeued, "failed": len(failed_ids),
                "failed_ids": failed_ids}

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
            pool = await _resolve_get_pool()()
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

    async def status_counts(self) -> dict[str, int] | None:
        """How many Fix Pack jobs sit in each status, right now.

        The histogram backlog_stats deliberately does not carry: /readyz only
        needs the one number that decides "is the processor draining", while a
        human diagnosing WHY needs to see 'failed' and 'blocked' next to it.

        Only statuses with rows appear, so read with .get(name, 0). None when
        DATABASE_URL isn't set, matching backlog_stats.

        Deliberately not windowed, unlike AuditJobRepository.recent_outcomes:
        fixpack_jobs records no terminal timestamp (created_at and started_at
        are all it has), so "what finished in the last hour" is not answerable
        from this table without a schema change."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                "select status, count(*) as jobs from fixpack_jobs "
                "group by status",
            )
            rows = await cur.fetchall()
        return {row["status"]: int(row["jobs"]) for row in rows}

    async def set_proof_json(self, job_id: str, proof: dict) -> None:
        """Persist a Proof-of-Exploit report on the job (jsonb).

        Called after the proof pair runs and before the PR is opened (or
        blocked). Failures here must not break delivery — callers wrap this
        in try/except. No-op when DATABASE_URL is not set.
        """
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return
        async with pool.connection() as conn:
            await conn.execute(
                "update fixpack_jobs set proof_json = %s::jsonb where id = %s",
                (json.dumps(proof), uuid.UUID(job_id)),
            )

    async def mark_fixpack_delivered(self, job_id: str, pr_url: str) -> None:
        """A paid Fix Pack job whose fix PR was successfully opened: record
        the PR url and advance status to 'delivered'. 'delivered' is the
        terminal success state for the Fix Pack flow, deliberately distinct
        from the Deploy Pack rows' default 'generated' (migration 0007) and
        from the 'paid' a purchase inserts — a status query can tell a
        finished Fix Pack from one still waiting to be processed. No-op when
        DATABASE_URL isn't set, matching mark_delivered."""
        try:
            pool = await _resolve_get_pool()()
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

    async def release_to_paid(self, job_id: str, detail: str) -> None:
        """Hand a claimed job back to the queue as if it had never been
        claimed: 'running' -> 'paid', lease cleared, and the attempt the
        claim charged for refunded.

        For the one class of failure that is ours, not the job's -- GitHub
        rejecting our own App credentials. Nothing about the customer's
        repository was even reached, so charging the job an attempt walks it
        toward the reaper's terminal 'failed' over a problem no retry of
        theirs can fix.

        Distinct from reap_stale_running, which also returns jobs to 'paid':
        that one is for a crashed worker and deliberately KEEPS the attempt,
        because a job that reliably kills its worker must eventually stop
        being retried. Here the opposite is true -- the job is fine and the
        deployment is broken, so the count must not move.

        `detail` is written so the row explains itself while it waits.
        Guarded on status = 'running' so a concurrently-reaped job is not
        resurrected out from under the reaper."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return
        async with pool.connection() as conn:
            await conn.execute(
                """
                update fixpack_jobs
                   set status = 'paid',
                       started_at = null,
                       attempts = greatest(attempts - 1, 0),
                       detail = %s
                 where id = %s
                   and status = 'running'
                """,
                (detail, uuid.UUID(job_id)),
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
            pool = await _resolve_get_pool()()
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
            pool = await _resolve_get_pool()()
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
                       pr_url, pr_delivered, status, created_at, funding_key
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
            pool = await _resolve_get_pool()()
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
        """The live job, otherwise the latest job, for an audit.

        Deploy Pack previews share this table and may create a newer generated
        row while paid work is running or waiting for authorization. Live work
        must remain visible both to polling and to the duplicate-purchase gate.
        Among terminal jobs the newest attempt still wins. Returns None when
        no job exists or persistence is unavailable.
        """
        try:
            pool = await _resolve_get_pool()()
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
                order by (status in ('paid', 'running', 'awaiting_authorization')) desc,
                         created_at desc
                limit 1
                """,
                (parsed_id,),
            )
            row = await cur.fetchone()
        return _row_to_fixpack_job(row) if row else None



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

        The conflict update additionally requires the same account, content,
        engine and source. A key alone never authorizes returning a job token.
        A ZIP's source_ref becomes its private spool path after insertion and
        is therefore not part of its submitted identity. A repository URL is.
        Raises AuditJobIdempotencyConflict if a live key belongs to another
        submission. Returns None only when DATABASE_URL isn't set."""
        try:
            pool = await _resolve_get_pool()()
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
                where audit_jobs.account_id is not distinct from excluded.account_id
                  and audit_jobs.content_hash = excluded.content_hash
                  and audit_jobs.engine_version = excluded.engine_version
                  and audit_jobs.source_kind = excluded.source_kind
                  and (excluded.source_kind = 'zip'
                       or audit_jobs.source_ref is not distinct from excluded.source_ref)
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
        if row is None:
            raise AuditJobIdempotencyConflict("idempotency key belongs to another submission")
        return _row_to_audit_job(row)

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
            pool = await _resolve_get_pool()()
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
            pool = await _resolve_get_pool()()
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
            pool = await _resolve_get_pool()()
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
            pool = await _resolve_get_pool()()
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
            pool = await _resolve_get_pool()()
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
            pool = await _resolve_get_pool()()
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
            pool = await _resolve_get_pool()()
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
            pool = await _resolve_get_pool()()
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
            pool = await _resolve_get_pool()()
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
            pool = await _resolve_get_pool()()
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
            pool = await _resolve_get_pool()()
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

    async def recent_outcomes(
        self, *, window_seconds: int, top_error_codes: int = 5,
    ) -> dict[str, Any] | None:
        """What finished in the trailing window, and how it went.

        backlog_stats answers "how deep is the queue right now"; this answers
        "is work completing, how fast, and how much of it is failing" -- the
        two questions a rising backlog forces you to ask next, and neither is
        answerable from a state histogram of live rows.

        Windowed on completed_at, which finalize_succeeded and the terminal
        branch of finalize_failed both stamp. A requeued attempt writes
        error_code but NOT completed_at, so a transient failure that later
        succeeds is not counted as a failure here -- a job contributes one
        outcome, when it reaches a terminal state.

        Durations are completed_at - claimed_at of the succeeded rows: how long
        the worker actually held the job, not how long since submission, which
        would fold queue depth into a number meant to measure scan speed.

        Returns None when DATABASE_URL isn't set, matching backlog_stats."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select state, count(*) as jobs,
                       avg(extract(epoch from (completed_at - claimed_at)))
                           as avg_seconds,
                       percentile_cont(0.95) within group (
                           order by extract(epoch from
                                            (completed_at - claimed_at)))
                           as p95_seconds
                  from audit_jobs
                 where completed_at >= now()
                       - make_interval(secs => %s::double precision)
                 group by state
                """,
                (float(window_seconds),),
            )
            outcome_rows = await cur.fetchall()
            cur = await conn.execute(
                """
                select coalesce(error_code, 'unknown') as error_code,
                       count(*) as jobs
                  from audit_jobs
                 where completed_at >= now()
                       - make_interval(secs => %s::double precision)
                   and state <> 'succeeded'
                 group by 1
                 order by jobs desc, error_code
                 limit %s
                """,
                (float(window_seconds), int(top_error_codes)),
            )
            error_rows = await cur.fetchall()

        outcomes = {row["state"]: int(row["jobs"]) for row in outcome_rows}
        succeeded = next(
            (row for row in outcome_rows if row["state"] == "succeeded"), None)
        total = sum(outcomes.values())
        failed = total - outcomes.get("succeeded", 0)
        return {
            "window_seconds": window_seconds,
            "terminal": outcomes,
            "terminal_total": total,
            "failed": failed,
            # None rather than 0.0 on an idle window: "nothing failed" and
            # "nothing finished" are different answers, and an alert built on
            # this has to be able to tell them apart.
            "error_rate": (failed / total) if total else None,
            "succeeded_duration_ms": {
                "avg": _seconds_to_ms(
                    succeeded["avg_seconds"] if succeeded else None),
                "p95": _seconds_to_ms(
                    succeeded["p95_seconds"] if succeeded else None),
            },
            "top_error_codes": [
                {"error_code": row["error_code"], "jobs": int(row["jobs"])}
                for row in error_rows
            ],
        }
