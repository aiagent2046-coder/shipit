"""Postgres persistence for audits and fixpack_jobs. Minimal scope --
see migrations/0001_audits_and_fixpack_jobs.sql for what was trimmed
from shipit-architecture.md 2.5's full schema and why.

Optional, not required: `DatabaseNotConfigured` is raised by `get_pool`
when `DATABASE_URL` isn't set, and both repositories below catch it and
return `None` from `create`/`get` instead of failing the request --
same pattern as GITHUB_PR_TOKEN, GITHUB_APP_ID, PREVIEW_REAP_TOKEN
elsewhere in this codebase. app/main.py surfaces whether persistence
actually happened (`"persisted": true/false`) rather than hiding it.

Real Postgres this was written against: a real Supabase project
(Postgres 17), schema applied via the Supabase migration tool, verified
with real INSERT/SELECT round trips through that same tool -- not just
asserted against a mock. What is NOT proven from this sandbox: the
asyncpg driver code below actually connecting over the wire to that
real database, since DATABASE_URL contains a password and is a raw
Postgres-protocol secret, not an HTTPS credential that can be safely
proxied into this sandbox. See scripts/verify_db_locally.py -- run by
the user, with their own DATABASE_URL, never sent here.
"""

from __future__ import annotations

import datetime
import json
import os
import uuid
from typing import Any

import asyncpg

DATABASE_URL_ENV = "DATABASE_URL"

_pool: asyncpg.Pool | None = None


class DatabaseNotConfigured(Exception):
    """DATABASE_URL isn't set. Distinct from a real connection failure
    (bad host, bad password, etc.), which should propagate as a loud
    error, not get treated as "not configured"."""


def database_url_from_env() -> str | None:
    return os.environ.get(DATABASE_URL_ENV) or None


async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        url = database_url_from_env()
        if not url:
            raise DatabaseNotConfigured(f"{DATABASE_URL_ENV} is not set")
        # statement_cache_size=0: asyncpg's default named-prepared-statement
        # cache hangs (not even an error, a real hang) the moment it tries a
        # parameterized query through Supabase's Supavisor session pooler --
        # confirmed by hand against the real project. Session-mode pgbouncer
        # is documented as supporting prepared statements fine, so this looks
        # like a Supavisor-specific quirk, not the usual PgBouncer
        # transaction-mode "prepared statement does not exist" error everyone
        # else reports. Unnamed statements (this setting) sidestep it
        # entirely. Costs a little query-plan caching, not correctness.
        _pool = await asyncpg.create_pool(
            url, min_size=1, max_size=5, statement_cache_size=0,
        )
    return _pool


async def close_pool() -> None:
    """For tests/shutdown -- lets a fresh get_pool() reconnect."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


def _row_to_audit(row: asyncpg.Record) -> dict[str, Any]:
    d = dict(row)
    d["id"] = str(d["id"])
    d["score_json"] = json.loads(d["score_json"]) if d["score_json"] else None
    d["findings_json"] = json.loads(d["findings_json"]) if d["findings_json"] else None
    return d


def _row_to_fixpack_job(row: asyncpg.Record) -> dict[str, Any]:
    d = dict(row)
    d["id"] = str(d["id"])
    d["audit_id"] = str(d["audit_id"]) if d["audit_id"] else None
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
        row = await pool.fetchrow(
            """
            insert into audits (stack, file_count, score_total, score_json, findings_json)
            values ($1, $2, $3, $4::jsonb, $5::jsonb)
            returning id, stack, status, file_count, score_total,
                      score_json, findings_json, created_at
            """,
            stack, file_count, score_total,
            json.dumps(score_json) if score_json is not None else None,
            json.dumps(findings_json) if findings_json is not None else None,
        )
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
        row = await pool.fetchrow(
            """
            select id, stack, status, file_count, score_total,
                   score_json, findings_json, created_at
            from audits where id = $1
            """,
            parsed_id,
        )
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
        row = await pool.fetchrow(
            """
            insert into fixpack_jobs
                (audit_id, pack, stack, verified, detail,
                 preview_local_url, preview_expires_at)
            values ($1, $2, $3, $4, $5, $6, $7)
            returning id, audit_id, pack, stack, verified, detail,
                      preview_local_url, preview_expires_at,
                      pr_url, pr_delivered, created_at
            """,
            parsed_audit_id, pack, stack, verified, detail,
            preview_local_url, expires_dt,
        )
        return _row_to_fixpack_job(row)

    async def mark_delivered(self, job_id: str, pr_url: str) -> None:
        try:
            pool = await get_pool()
        except DatabaseNotConfigured:
            return
        await pool.execute(
            "update fixpack_jobs set pr_url = $1, pr_delivered = true where id = $2",
            pr_url, uuid.UUID(job_id),
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
        row = await pool.fetchrow(
            """
            select id, audit_id, pack, stack, verified, detail,
                   preview_local_url, preview_expires_at,
                   pr_url, pr_delivered, created_at
            from fixpack_jobs where id = $1
            """,
            parsed_id,
        )
        return _row_to_fixpack_job(row) if row else None
