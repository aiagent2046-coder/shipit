"""The RLS oracle: what counts as exposed, and what must not.

This decides a number that decides whether a feature gets built, so the two
ways it could be wrong are pinned here directly.

TRAP 1 — RLS enabled is not protection. `USING (true)` is the same hole wearing
a seatbelt. An oracle that greps for ENABLE ROW LEVEL SECURITY calls those
secure and undercounts the real rate.

TRAP 2 — a table anyone may read is not automatically a finding. `products`,
`blog_posts`, a public leaderboard are APIs. Counting them is the same error as
scoring `Access-Control-Allow-Origin: *` without credentials as an exploit —
which this project made once, in the CORS oracle, and removed.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.measure_supabase_rls_yield import parse_schema  # noqa: E402

USERS = """
create table public.users (
  id uuid primary key,
  email text not null,
  full_name text
);
"""


def _verdict(sql: str, table: str = "users") -> tuple[bool, bool]:
    """(private_shaped, anon_readable) for one table."""
    t = parse_schema(sql)[table]
    return t.private_shaped[0], t.anon_readable[0]


# --- the base case ----------------------------------------------------------

def test_a_users_table_with_no_rls_is_exposed() -> None:
    private, readable = _verdict(USERS)
    assert private and readable


def test_the_reason_is_reported_so_a_human_can_overrule_it() -> None:
    """Every verdict prints why. A heuristic that cannot be checked is a
    heuristic that gets believed."""
    t = parse_schema(USERS)["users"]
    assert "users" in t.private_shaped[1]
    assert "RLS never enabled" in t.anon_readable[1]


# --- TRAP 1: RLS on is not the same as protected ----------------------------

def test_rls_enabled_with_using_true_is_still_exposed() -> None:
    """The load-bearing case. This repository has RLS switched on, which is
    what a shallow scan looks for, and is wide open to the anon key."""
    private, readable = _verdict(USERS + """
        alter table public.users enable row level security;
        create policy "public read" on public.users for select using (true);
    """)
    assert private and readable


def test_using_1_equals_1_is_the_same_hole() -> None:
    _, readable = _verdict(USERS + """
        alter table public.users enable row level security;
        create policy p on public.users for select using (1=1);
    """)
    assert readable


def test_a_for_all_policy_with_only_with_check_leaves_reads_open() -> None:
    """FOR ALL constrains writes through WITH CHECK while leaving SELECT
    unqualified — valid SQL, and a read grant."""
    _, readable = _verdict(USERS + """
        alter table public.users enable row level security;
        create policy p on public.users for all with check (auth.uid() = id);
    """)
    assert readable


def test_a_predicated_policy_is_not_exposed() -> None:
    _, readable = _verdict(USERS + """
        alter table public.users enable row level security;
        create policy p on public.users for select using (auth.uid() = id);
    """)
    assert not readable


def test_rls_on_with_no_policy_at_all_is_default_deny() -> None:
    """Postgres denies everything when RLS is on and no policy matches. This
    is the most common CORRECT configuration and must not be counted."""
    t = parse_schema(USERS + "alter table public.users enable row level security;")["users"]
    readable, why = t.anon_readable
    assert not readable
    assert "default deny" in why


def test_a_policy_for_authenticated_only_does_not_expose_anon() -> None:
    _, readable = _verdict(USERS + """
        alter table public.users enable row level security;
        create policy p on public.users for select to authenticated using (true);
    """)
    assert not readable


def test_a_write_policy_is_not_a_read_grant() -> None:
    _, readable = _verdict(USERS + """
        alter table public.users enable row level security;
        create policy p on public.users for insert with check (true);
    """)
    assert not readable


def test_to_anon_is_caught_as_well_as_to_public() -> None:
    _, readable = _verdict(USERS + """
        alter table public.users enable row level security;
        create policy p on public.users for select to anon using (true);
    """)
    assert readable


# --- TRAP 2: public-by-design is not a finding ------------------------------

def test_a_products_table_wide_open_is_not_a_finding() -> None:
    """A storefront's catalogue is meant to be readable. Reporting it would be
    the CORS `*`-without-credentials error in another costume.

    `notes` is deliberately present: it matches the private-column hints, so
    this table is only excluded because the name says public-by-design. A
    first draft used `title`/`price`, which trip nothing — that version passed
    with the exclusion deleted, i.e. it tested nothing at all."""
    private, readable = _verdict("""
        create table public.products (
          id uuid primary key,
          title text,
          notes text,
          price numeric
        );
    """, "products")
    assert readable        # it IS readable
    assert not private     # and that is not a finding


def test_blog_posts_are_public_even_though_they_have_content() -> None:
    """`content` is in the private-column hints; the table name overrules it.
    Public-by-design is checked first, on purpose."""
    private, _ = _verdict("""
        create table public.posts (
          id uuid primary key,
          content text
        );
    """, "posts")
    assert not private


def test_a_neutrally_named_table_with_pii_columns_still_counts() -> None:
    """The name says nothing; `email` does."""
    private, readable = _verdict("""
        create table public.entries (
          id uuid primary key,
          email text,
          note text
        );
    """, "entries")
    assert private and readable


def test_a_table_with_neither_a_private_name_nor_private_columns_is_ignored() -> None:
    private, _ = _verdict("""
        create table public.counters (
          id int primary key,
          value int
        );
    """, "counters")
    assert not private


# --- reachability -----------------------------------------------------------

def test_a_table_outside_the_public_schema_is_not_reachable() -> None:
    """PostgREST exposes `public`. A table in an internal schema is not anon
    territory however its RLS is set."""
    _, readable = _verdict("""
        create table internal.users (
          id uuid primary key,
          email text
        );
    """)
    assert not readable


# --- parsing ----------------------------------------------------------------

def test_table_level_constraints_are_not_mistaken_for_columns() -> None:
    """`primary key (a, b)` is not a column named `primary`, and a stray
    identifier there could flip a verdict."""
    t = parse_schema("""
        create table public.things (
          a uuid,
          b uuid,
          primary key (a, b),
          constraint fk foreign key (a) references other (id)
        );
    """)["things"]
    assert t.columns == ["a", "b"]


def test_a_column_with_a_parenthesised_type_does_not_split_the_list() -> None:
    t = parse_schema("""
        create table public.things (
          id uuid,
          amount numeric(10, 2),
          label varchar(255)
        );
    """)["things"]
    assert t.columns == ["id", "amount", "label"]


def test_quoted_and_schema_qualified_names_resolve_to_one_table() -> None:
    t = parse_schema('''
        create table "public"."users" (id uuid, email text);
        alter table "public"."users" enable row level security;
        create policy p on "public"."users" for select using (true);
    ''')["users"]
    assert t.rls_enabled and t.open_policy


def test_if_not_exists_is_handled() -> None:
    assert "users" in parse_schema(
        "create table if not exists public.users (id uuid, email text);")


import pytest  # noqa: E402


@pytest.mark.parametrize("stmt", [
    "alter table public.users enable row level security;",
    "alter table if exists public.users enable row level security;",
    "alter table only public.users enable row level security;",
    "alter table if exists only public.users enable row level security;",
    "alter table users enable row level security;",
    'alter table "public"."users" enable row level security;',
    "alter table public.users\n  enable row level security;",
    "ALTER TABLE IF EXISTS public.users ENABLE ROW LEVEL SECURITY;",
])
def test_every_valid_spelling_of_enabling_rls_is_recognised(stmt) -> None:
    """A spelling the reader misses reports the table as "RLS never enabled" —
    a FALSE EXPOSURE, in the direction that invents a finding about a
    customer's data.

    `IF EXISTS` was missed by the first version. It is valid PostgreSQL and
    common in generated migrations, so every table protected that way would
    have been reported as wide open. Found by probing the regex with the
    syntax variants, not by a repository happening to use one — which is the
    only reason it was found before the number was quoted.
    """
    t = parse_schema(USERS + stmt)["users"]
    assert t.rls_enabled, f"not recognised: {stmt!r}"
    assert not t.anon_readable[0]


def test_an_exposed_verdict_carries_the_statement_that_caused_it() -> None:
    """A finding about someone's data that cannot be checked against the
    source is a finding that gets believed instead of read."""
    t = parse_schema(USERS + """
        alter table public.users enable row level security;
        create policy "anyone can read" on public.users for select using (true);
    """)["users"]
    assert "create policy" in t.open_policy_sql.lower()
    assert "using (true)" in t.open_policy_sql.lower()


def test_multiple_migrations_concatenate_into_one_view_of_the_table() -> None:
    """Real repos enable RLS in a later migration than the CREATE TABLE."""
    t = parse_schema(USERS + """
        -- 0002_enable_rls.sql
        alter table public.users enable row level security;
    """)["users"]
    assert t.rls_enabled
