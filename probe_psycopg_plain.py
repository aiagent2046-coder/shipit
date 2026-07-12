"""Minimal repro: THREE sequential parameterized queries on a single
plain psycopg AsyncConnection (no pool at all), to isolate whether the
hang seen in scripts/verify_db_locally.py (which uses AsyncConnectionPool)
is caused by the pool's connection-reuse/health-check machinery, or is
a deeper psycopg-vs-Supavisor issue that a plain connection also hits.

Run with: DATABASE_URL=... python probe_psycopg_plain.py
"""
import asyncio
import os
import sys

import psycopg


async def main():
    url = os.environ["DATABASE_URL"]
    print("Connecting (plain, no pool)...")
    conn = await psycopg.AsyncConnection.connect(url, prepare_threshold=None)
    print("OK: connected")

    for i in range(1, 4):
        print(f"--- query {i} ---")
        cur = await conn.execute("select %s::int", (i,))
        row = await cur.fetchone()
        await conn.commit()
        print(f"OK: query {i} -> {row}")

    print("Closing...")
    await conn.close()
    print("OK: closed cleanly")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("INTERRUPTED", file=sys.stderr)
