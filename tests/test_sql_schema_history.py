"""A migration chain is a sequence of edits, not a set of statements.

WHY THIS FILE EXISTS, measured 2026-08-18 while surveying 199 repositories. One
of them carried, in `supabase/migrations/archive/`:

    CREATE POLICY "Allow public to insert KYC documents" ON kyc_documents
      FOR INSERT TO anon, authenticated WITH CHECK (true);

and, four migrations later, the developer's own fix:

    DROP POLICY IF EXISTS "Allow public to insert KYC documents" ON …;

The reader knew CREATE and not DROP, so it reported the hole its owner had
already closed — on a table of KYC documents, citing a file inside a directory
named `archive`. That is the most expensive shape of wrong this product has:
not a guess that missed, but a confident accusation the customer's own commit
refutes. Two more of the same family turned up in the same repository, and all
three are pinned below.
"""

from __future__ import annotations

import io
import zipfile

from app.scan.rls import RULE_ID, WRITE_RULE_ID, read_committed_sql, scan_rls
from app.scan.sql_schema import parse_schema


def make_zip(entries: dict[str, str]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in entries.items():
            zf.writestr(name, body)
    buf.seek(0)
    return buf


# --- DROP POLICY ------------------------------------------------------------

def test_a_dropped_policy_stops_counting() -> None:
    """The measured case, reduced."""
    schema = parse_schema("""
        create table public.kyc_documents (id uuid primary key, file text);
        alter table public.kyc_documents enable row level security;
        create policy "Allow public to insert KYC documents"
          on public.kyc_documents for insert to anon with check (true);
        drop policy if exists "Allow public to insert KYC documents"
          on "public"."kyc_documents";
    """)
    assert schema["kyc_documents"].anon_can_write()[0] == frozenset()


def test_a_drop_before_the_create_does_not_remove_it() -> None:
    """`DROP POLICY IF EXISTS` followed by `CREATE POLICY` is the standard
    idempotent-migration idiom. Order is the only thing separating it from the
    case above, and a set-based reader cannot tell them apart at all."""
    schema = parse_schema("""
        create table public.t (id uuid primary key, email text);
        alter table public.t enable row level security;
        drop policy if exists "open" on public.t;
        create policy "open" on public.t for select using (true);
    """)
    assert schema["t"].anon_can_read[0] is True


def test_the_drop_matches_regardless_of_quoting_and_case() -> None:
    schema = parse_schema("""
        create table public.t (id uuid primary key, email text);
        alter table public.t enable row level security;
        create policy "Open Read" on public.t for select using (true);
        drop policy "open read" on t;
    """)
    assert schema["t"].anon_can_read[0] is False


def test_dropping_one_policy_leaves_the_others() -> None:
    """The control. A drop that removed everything would pass the tests above
    and quietly close every table in the corpus."""
    schema = parse_schema("""
        create table public.t (id uuid primary key, email text);
        alter table public.t enable row level security;
        create policy "a" on public.t for select using (true);
        create policy "b" on public.t for select using (true);
        drop policy "a" on public.t;
    """)
    assert schema["t"].anon_can_read[0] is True


# --- DISABLE ROW LEVEL SECURITY ---------------------------------------------

def test_rls_disabled_again_is_off() -> None:
    schema = parse_schema("""
        create table public.t (id uuid primary key, email text);
        alter table public.t enable row level security;
        alter table public.t disable row level security;
    """)
    assert schema["t"].rls_enabled is False
    assert schema["t"].anon_can_read[0] is True


def test_rls_re_enabled_after_a_disable_is_on() -> None:
    """The other order. Without ordering, both spellings collapse to whichever
    pass happened to run last."""
    schema = parse_schema("""
        create table public.t (id uuid primary key, email text);
        alter table public.t disable row level security;
        alter table public.t enable row level security;
    """)
    assert schema["t"].rls_enabled is True


# --- what a repeated CREATE TABLE means -------------------------------------

def test_create_table_if_not_exists_does_not_wipe_the_protection() -> None:
    """An idempotent migration exists to do nothing. Treating it as a fresh
    declaration threw away the RLS established earlier and invented an
    exposure out of a no-op."""
    schema = parse_schema("""
        create table public.t (id uuid primary key, email text);
        alter table public.t enable row level security;
        create policy p on public.t for select using (auth.uid() = id);
        create table if not exists public.t (id uuid primary key, email text);
    """)
    assert schema["t"].rls_enabled is True
    assert schema["t"].anon_can_read[0] is False


def test_if_not_exists_still_picks_up_columns_it_adds() -> None:
    schema = parse_schema("""
        create table public.t (id uuid primary key);
        create table if not exists public.t (id uuid primary key, email text);
    """)
    assert "email" in schema["t"].columns


def test_a_plain_re_create_restates_the_table_and_resets_it() -> None:
    """A pg_dump or a squashed baseline redeclares the whole schema, and
    Postgres would reject a plain re-CREATE against a live table — so this is
    a fresh declaration, and what an archived migration said before it stops
    applying. MEASURED: without this, a dumped baseline carried permissive
    policies from 2025 that it existed to replace."""
    schema = parse_schema("""
        create table public.t (id uuid primary key, email text);
        alter table public.t enable row level security;
        create policy "old_open" on public.t for select using (true);
        create table public.t (id uuid primary key, email text);
        alter table public.t enable row level security;
        create policy "scoped" on public.t for select using (auth.uid() = id);
    """)
    assert [p.name for p in schema["t"].policies] == ["scoped"]
    assert schema["t"].anon_can_read[0] is False


# --- the order files are read in --------------------------------------------

def test_migrations_are_ordered_by_filename_not_by_path() -> None:
    """MEASURED: a repository with 258 superseded migrations in
    `supabase/migrations/archive/` beside 50 live ones. Sorted by full path,
    `…/archive/20251022…` lands AFTER `…/20260523…` — "a" is greater than "2" —
    so the oldest migrations in the repository were applied last and the schema
    came out reading like 2025. The timestamp prefix is what encodes time, and
    it is in the filename."""
    sql, paths = read_committed_sql(make_zip({
        "repo/supabase/migrations/20260523_baseline.sql": "-- newer\n",
        "repo/supabase/migrations/archive/20251022_old.sql": "-- older\n",
    }))
    assert paths == ["supabase/migrations/archive/20251022_old.sql",
                     "supabase/migrations/20260523_baseline.sql"]
    assert sql.index("older") < sql.index("newer")


def test_an_archived_hole_closed_by_a_later_baseline_is_not_reported() -> None:
    """End to end, the shape of the real repository: an old migration in
    `archive/` opens the table, a later dumped baseline restates it closed.
    Every layer has to hold for the finding to disappear — the ordering, the
    re-create semantics, and the detector reading the result."""
    findings = scan_rls(make_zip({
        "repo/supabase/migrations/archive/20251022_init.sql": """
            create table public.customers (id uuid primary key, email text);
            alter table public.customers enable row level security;
            create policy "Allow public read" on public.customers
              for select to anon using (true);
        """,
        "repo/supabase/migrations/20260523_baseline_squash.sql": """
            create table public.customers (id uuid primary key, email text);
            alter table public.customers enable row level security;
            create policy "own_row" on public.customers
              for select to authenticated using (auth.uid() = id);
        """,
    }))
    assert [f.rule_id for f in findings] == []


def test_the_same_repo_the_other_way_round_is_still_reported() -> None:
    """The control for the test above, and the one that matters: a table left
    open by the NEWEST migration must still be found. A reader that had simply
    become good at going quiet would pass everything else here."""
    findings = scan_rls(make_zip({
        "repo/supabase/migrations/archive/20251022_init.sql": """
            create table public.customers (id uuid primary key, email text);
            alter table public.customers enable row level security;
            create policy "own_row" on public.customers
              for select to authenticated using (auth.uid() = id);
        """,
        "repo/supabase/migrations/20260523_oops.sql": """
            create table public.customers (id uuid primary key, email text);
            alter table public.customers enable row level security;
            create policy "Allow public read" on public.customers
              for select to anon using (true);
        """,
    }))
    assert RULE_ID in [f.rule_id for f in findings]


def test_a_lead_form_insert_survives_all_of_this() -> None:
    """From the same repository: `Public can insert coverage leads … WITH
    CHECK (true)` is real, current, and correctly medium rather than critical.
    The history handling must not swallow it."""
    findings = scan_rls(make_zip({
        "repo/supabase/migrations/20260101_leads.sql": """
            create table public.coverage_leads (id uuid primary key, email text);
            alter table public.coverage_leads enable row level security;
            create policy "Public can insert coverage leads"
              on public.coverage_leads for insert to anon with check (true);
        """,
    }))
    writes = [f for f in findings if f.rule_id == WRITE_RULE_ID]
    assert len(writes) == 1
    assert writes[0].severity == "medium"
