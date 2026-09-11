"""Execute the shipped collector and compare its review with real PostgreSQL.

DATABASE_URL is captured before conftest clears it. The shared test gate
refuses hosted databases; CI provides a disposable PostgreSQL 17 service.
"""
import json
import os
from pathlib import Path

import psycopg
import pytest

from app.proof.rls_metadata import parse_access_review, review_metadata

DATABASE = os.environ.get("DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE, reason="requires disposable PostgreSQL")
COLLECTOR = Path(__file__).resolve().parents[1] / "web/public/collect-rls-metadata.sql"


def collect(conn):
    sql = COLLECTOR.read_text().replace("REPLACE_WITH_PROJECT_REF", "abcdefghijklmnopqrst")
    sql = sql.replace("ARRAY[]::text[]", "ARRAY['rls_meta_fixture']::text[]")
    cursor = conn.execute(sql)
    snapshot = None
    while True:
        if cursor.description:
            snapshot = cursor.fetchone()[0]
        if not cursor.nextset():
            break
    assert snapshot is not None
    return snapshot


def review(snapshot):
    data = parse_access_review(json.dumps({"snapshot": snapshot, "auth_model": "backend",
        "expectations": [{"table": "rls_meta_fixture", "read": "public_subset", "write": "backend_only"}]}))
    return review_metadata(data, [])["tables"][0]


def test_collector_public_filter_override_and_recovery():
    with psycopg.connect(DATABASE, autocommit=True) as conn:
        created_roles = []
        try:
            for role in ("anon", "authenticated"):
                if not conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
                    conn.execute(psycopg.sql.SQL("CREATE ROLE {} NOLOGIN").format(psycopg.sql.Identifier(role)))
                    created_roles.append(role)
            conn.execute("""
                CREATE TABLE public.rls_meta_fixture(id integer, is_public boolean);
                INSERT INTO public.rls_meta_fixture VALUES (1, true), (2, false), (3, null);
                GRANT SELECT, INSERT, UPDATE, DELETE ON public.rls_meta_fixture TO anon, authenticated;
                ALTER TABLE public.rls_meta_fixture ENABLE ROW LEVEL SECURITY;
                CREATE POLICY published ON public.rls_meta_fixture FOR SELECT USING (is_public = true);
                CREATE POLICY accidental_all ON public.rls_meta_fixture USING (true);
            """)
            before = collect(conn)
            table = before["tables"][0]
            assert table["collector_rls_applies"] is False
            assert {p["using"] for p in table["policies"]} == {"always", "conditional"}
            assert all(set(p["applies_to"]) == {"anon", "authenticated"} for p in table["policies"])
            assert {o["scope"] for o in review(before)["operations"]} == {"unrestricted"}
            conn.execute("SET ROLE anon")
            assert conn.execute("SELECT count(*) FROM public.rls_meta_fixture").fetchone()[0] == 3
            conn.execute("RESET ROLE")
            conn.execute("DROP POLICY accidental_all ON public.rls_meta_fixture")
            after = collect(conn)
            for op in review(after)["operations"]:
                assert op["scope"] == ("conditional" if op["operation"] == "SELECT" else "blocked")
            conn.execute("SET ROLE anon")
            assert conn.execute("SELECT count(*) FROM public.rls_meta_fixture").fetchone()[0] == 1
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute("INSERT INTO public.rls_meta_fixture VALUES (4, true)")
            assert conn.execute("UPDATE public.rls_meta_fixture SET is_public = true").rowcount == 0
            assert conn.execute("DELETE FROM public.rls_meta_fixture").rowcount == 0
            conn.execute("RESET ROLE")
            assert conn.execute("SELECT count(*) FROM public.rls_meta_fixture").fetchone()[0] == 3
        finally:
            conn.execute("ROLLBACK; RESET ROLE; DROP TABLE IF EXISTS public.rls_meta_fixture")
            for role in created_roles:
                conn.execute(psycopg.sql.SQL("DROP ROLE {}").format(psycopg.sql.Identifier(role)))
