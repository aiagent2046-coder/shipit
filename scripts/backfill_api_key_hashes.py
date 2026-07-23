"""Backfill key_prefix / key_hash for accounts issued before migration
0009 (which added the columns but wrote no data — DDL only).

RUN THIS YOURSELF, against the real DB, once, after deploying the code
that carries the transitional plaintext fallback (see the rollout plan in
the PR). It reads the server pepper from the environment at run time — the
pepper must NEVER live in a migration, this file, or git history.

    export DATABASE_URL=postgresql://...        # same var app/db.py uses
    export API_KEY_PEPPER=<the production pepper>
    python scripts/backfill_api_key_hashes.py

What it does: for every account with `key_hash IS NULL AND api_key IS NOT
NULL`, it recomputes `key_prefix` and `key_hash` from the existing
plaintext `api_key` (using the same app.accounts helpers the app uses) and
UPDATEs the row. It is idempotent — already-backfilled rows (key_hash set)
are skipped — so it is safe to re-run.

It never logs api keys or hashes; only counts. After it reports every row
backfilled, a follow-up migration can drop the plaintext fallback and the
api_key column.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from app.accounts import (
    api_key_prefix,
    hash_api_key,
    require_pepper,
)
from app.db import DatabaseNotConfigured, get_pool


async def backfill() -> int:
    # Fail loudly up front if the pepper isn't set, before touching the DB —
    # a wrong/empty pepper would write hashes that never match at lookup.
    require_pepper()

    try:
        pool = await get_pool()
    except DatabaseNotConfigured:
        print("DATABASE_URL is not set — nothing to do.", file=sys.stderr)
        return 1

    async with pool.connection() as conn:
        cur = await conn.execute(
            """
            select id, api_key
            from accounts
            where key_hash is null and api_key is not null
            """
        )
        rows = await cur.fetchall()

    total = len(rows)
    print(f"Found {total} account(s) needing a key_hash backfill.")

    updated = 0
    for row in rows:
        key_prefix = api_key_prefix(row["api_key"])
        key_hash = hash_api_key(row["api_key"])
        async with pool.connection() as conn:
            await conn.execute(
                """
                update accounts
                set key_prefix = %s, key_hash = %s
                where id = %s and key_hash is null
                """,
                (key_prefix, key_hash, row["id"]),
            )
        updated += 1
        if updated % 50 == 0 or updated == total:
            print(f"  backfilled {updated}/{total}")

    print(f"Done. Backfilled {updated}/{total} account(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(backfill()))
