"""Two SQL readers exist. They must not disagree.

app/scan/sql_schema.py was written for the Fix Pack; the measurement script
(scripts/measure_supabase_rls_yield.py) kept the reader it was built with,
layered with heuristics the fix does not need. Converging them means editing a
tool whose numbers are already published, so for now they are pinned to each
other instead.

The verdict that matters is the same on both sides: can the anonymous role read
this table. If that ever diverges, a measurement and a customer's pull request
start describing the same schema differently, and this test is the thing that
says so first.
"""

from __future__ import annotations

import pytest

from app.scan.sql_schema import parse_schema as fix_parse
from scripts.measure_supabase_rls_yield import parse_schema as measure_parse

CASES = {
    "rls never enabled": """
        create table public.t (id uuid primary key, email text);
    """,
    "rls on, no policy (default deny)": """
        create table public.t (id uuid primary key, email text);
        alter table public.t enable row level security;
    """,
    "rls on, permissive policy": """
        create table public.t (id uuid primary key, email text);
        alter table public.t enable row level security;
        create policy p on public.t for select using (true);
    """,
    "rls on, predicated policy": """
        create table public.t (id uuid primary key, email text);
        alter table public.t enable row level security;
        create policy p on public.t for select using (auth.uid() = id);
    """,
    "policy for authenticated only": """
        create table public.t (id uuid primary key, email text);
        alter table public.t enable row level security;
        create policy p on public.t for select to authenticated using (true);
    """,
    "policy to anon explicitly": """
        create table public.t (id uuid primary key, email text);
        alter table public.t enable row level security;
        create policy p on public.t for select to anon using (true);
    """,
    "write policy is not a read grant": """
        create table public.t (id uuid primary key, email text);
        alter table public.t enable row level security;
        create policy p on public.t for insert with check (true);
    """,
    "alter table if exists": """
        create table public.t (id uuid primary key, email text);
        alter table if exists public.t enable row level security;
    """,
    "non-public schema": """
        create table internal.t (id uuid primary key, email text);
    """,
    "nested predicate": """
        create table public.t (id uuid primary key, match_id uuid);
        alter table public.t enable row level security;
        create policy p on public.t for select using (
          EXISTS (SELECT 1 FROM m WHERE ((m.id = t.match_id) AND (m.x = 1))));
    """,
}


@pytest.mark.parametrize("name,sql", list(CASES.items()))
def test_both_readers_agree_on_whether_anon_can_read(name, sql) -> None:
    fix = fix_parse(sql)["t"]
    measure = measure_parse(sql)["t"]
    assert fix.anon_can_read[0] == measure.anon_readable[0], name


@pytest.mark.parametrize("name,sql", list(CASES.items()))
def test_both_readers_agree_on_rls_state(name, sql) -> None:
    assert fix_parse(sql)["t"].rls_enabled == measure_parse(sql)["t"].rls_enabled


# --- where they no longer agree, on purpose ---------------------------------
#
# On 2026-08-18 the production reader learned that a migration chain is a
# sequence of edits: DROP POLICY, DISABLE ROW LEVEL SECURITY, and what a
# repeated CREATE TABLE means. The measurement reader did not follow, and that
# is deliberate — its numbers are published in SUPABASE_RLS_YIELD_PLAN.md and
# were computed by the code as it stands. Changing it would detach a recorded
# result from the thing that produced it.
#
# So the divergence is pinned rather than left to be discovered. These tests
# fail if production regresses, and they also fail if the measurement reader
# catches up without this file being updated — which is the moment to converge
# the two and re-run Part A, not to edit an assertion.

DIVERGENT = {
    "a dropped policy": """
        create table public.t (id uuid primary key, email text);
        alter table public.t enable row level security;
        create policy "open" on public.t for select using (true);
        drop policy "open" on public.t;
    """,
    "rls disabled again": """
        create table public.t (id uuid primary key, email text);
        alter table public.t enable row level security;
        alter table public.t disable row level security;
    """,
}


@pytest.mark.parametrize("name,sql", list(DIVERGENT.items()))
def test_the_measurement_reader_is_known_to_be_behind(name, sql) -> None:
    """Production is right here and the measurement tool is not. Asserted so
    the gap is a recorded decision instead of a surprise in six months."""
    fix = fix_parse(sql)["t"]
    measure = measure_parse(sql)["t"]
    assert fix.anon_can_read[0] != measure.anon_readable[0], name


def test_both_readers_find_the_same_columns() -> None:
    sql = """
        create table public.t (
          id uuid primary key,
          amount numeric(10, 2),
          user_id uuid references auth.users(id),
          primary key (id),
          constraint fk foreign key (id) references other (id)
        );
    """
    assert fix_parse(sql)["t"].columns == measure_parse(sql)["t"].columns
