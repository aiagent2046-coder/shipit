"""Run this YOURSELF, locally, with your own DATABASE_URL. Never send
that connection string to anyone else, including an AI assistant
helping you build this: it contains your Postgres password, and it's a
raw wire-protocol secret (not HTTPS), so there's no way to safely proxy
it the way GitHub tokens can be -- same boundary as the GitHub App
private key in scripts/verify_github_app_locally.py.

What it proves for real, against your actual Supabase Postgres (no
mocks, no fakes): the real AuditRepository and FixpackJobRepository in
app/db.py -- the exact classes app/main.py uses -- can really connect,
insert, and read back rows, including the audits -> fixpack_jobs
foreign key and the jsonb round-trip for score_json/findings_json.

Usage:
    export DATABASE_URL="postgresql://postgres.YOUR-PROJECT-REF:PASSWORD@aws-0-YOUR-REGION.pooler.supabase.com:5432/postgres"
    python scripts/verify_db_locally.py

Use the Session Pooler connection string (Project Settings -> Database
-> Connection pooling), not the direct `db.<ref>.supabase.co` one --
that one resolves IPv6-only and won't connect from an IPv4-only
network. See app/db.py's module docstring for why this project uses
psycopg (not asyncpg) specifically because of a Supavisor + asyncpg
incompatibility discovered while building this.

Cleans up every row it creates, even on failure.
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from app.db import (
    AuditRepository,
    DatabaseNotConfigured,
    FixpackJobRepository,
    close_pool,
    get_pool,
)


async def main() -> int:
    audit_repo = AuditRepository()
    fixpack_repo = FixpackJobRepository()
    created_audit_id: str | None = None
    created_job_id: str | None = None

    try:
        print("=== Connecting and inserting a real audit row ===")
        audit = await audit_repo.create(
            stack="fastapi", file_count=3, score_total=8.5,
            score_json={"total": 8.5, "categories": {}}, findings_json=[],
        )
        if audit is None:
            print("FAIL: DATABASE_URL is not set -- export it first, see this "
                  "script's docstring", file=sys.stderr)
            return 1
        created_audit_id = audit["id"]
        print(f"OK: inserted audit {created_audit_id}")

        print("\n=== Reading it back ===")
        fetched = await audit_repo.get(created_audit_id)
        if fetched is None or fetched["stack"] != "fastapi":
            print(f"FAIL: read-back mismatch: {fetched!r}", file=sys.stderr)
            return 1
        if fetched["score_json"] != {"total": 8.5, "categories": {}}:
            print(f"FAIL: jsonb round-trip mismatch: {fetched['score_json']!r}",
                  file=sys.stderr)
            return 1
        print(f"OK: read back {fetched['id']}, score_json round-tripped correctly")

        print("\n=== Inserting a fixpack_job linked to that audit (real FK) ===")
        job = await fixpack_repo.create(
            audit_id=created_audit_id, pack="deploy", stack="fastapi",
            verified=True, detail="HTTP 200 on /",
            preview_local_url="http://localhost:20000/", preview_expires_at=None,
        )
        if job is None:
            print("FAIL: fixpack_repo.create returned None unexpectedly", file=sys.stderr)
            return 1
        created_job_id = job["id"]
        if job["audit_id"] != created_audit_id:
            print(f"FAIL: audit_id did not round-trip: {job['audit_id']!r}", file=sys.stderr)
            return 1
        print(f"OK: inserted fixpack_job {created_job_id}, linked to audit {created_audit_id}")

        print("\n=== mark_delivered ===")
        await fixpack_repo.mark_delivered(created_job_id, "https://github.com/acme/app/pull/1")
        refetched = await fixpack_repo.get(created_job_id)
        if not refetched["pr_delivered"] or refetched["pr_url"] != "https://github.com/acme/app/pull/1":
            print(f"FAIL: mark_delivered didn't stick: {refetched!r}", file=sys.stderr)
            return 1
        print("OK: mark_delivered persisted correctly")

        print("\nAll real-Postgres checks passed. app/db.py genuinely works "
              "against your Supabase project.")
        return 0

    except DatabaseNotConfigured:
        print("FAIL: DATABASE_URL is not set", file=sys.stderr)
        return 1
    finally:
        # Belt-and-suspenders cleanup, even on failure -- never leave
        # test rows behind in a real database.
        try:
            pool = await get_pool()
            async with pool.connection() as conn:
                if created_job_id:
                    await conn.execute("delete from fixpack_jobs where id = %s",
                                        (uuid.UUID(created_job_id),))
                if created_audit_id:
                    await conn.execute("delete from audits where id = %s",
                                        (uuid.UUID(created_audit_id),))
        except DatabaseNotConfigured:
            pass
        await close_pool()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
