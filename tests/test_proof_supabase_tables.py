"""Where the probe's table names come from, now that enumeration is closed.

MEASURED 2026-08-18: PostgREST's OpenAPI root answers the anon key with
`401 {"hint": "Only the service_role API key can be used for this endpoint"}`.
The only credential that could list a project's tables is the one we refuse to
send anywhere, so the names come out of the repository — and for the 32% that
commit no schema, out of the client code, which is the whole reason this is
not just a loop over parse_schema.
"""

from __future__ import annotations

import io
import zipfile

from app.proof.supabase_tables import find_probe_tables


def make_zip(entries: dict[str, str]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in entries.items():
            zf.writestr(name, body)
    buf.seek(0)
    return buf


def names(entries: dict[str, str]) -> list[str]:
    return [c.name for c in find_probe_tables(make_zip(entries))]


MIGRATION = {"repo/supabase/migrations/0001.sql": """
    create table public.users (id uuid primary key, email text);
    create table public.products (id uuid primary key, title text);
"""}

CLIENT = {"repo/src/lib/db.ts": """
    export const load = async () => {
      const { data } = await supabase.from('waitlist').select('*');
      const p = await supabase.from("profiles").select('id');
      return { data, p };
    };
"""}


# --- the blind spot is where this earns its keep ----------------------------

def test_client_code_names_tables_when_no_schema_is_committed() -> None:
    """The 32%. Static analysis is silent by construction there, and a client
    that talks to Supabase has to name its tables to use them."""
    assert set(names(CLIENT)) == {"waitlist", "profiles"}


def test_migrations_and_client_code_are_merged_with_their_source() -> None:
    entries = {**MIGRATION, "repo/src/db.ts":
               "supabase.from('users').select('*'); supabase.from('carts')"}
    found = {c.name: c.source for c in find_probe_tables(make_zip(entries))}
    assert found["users"] == "both"
    assert found["products"] == "migrations"
    assert found["carts"] == "client-code"


def test_a_repo_with_neither_yields_nothing() -> None:
    assert names({"repo/README.md": "# hello"}) == []


# --- order, because the caller caps the number of requests ------------------

def test_the_three_shape_verdicts_order_the_queue() -> None:
    """An arbitrary cap over an arbitrary order checks whatever sorted first,
    so all three verdicts have to separate — not just "private beats the rest".
    A first version of this test asserted `products` came LAST and failed for
    the wrong reason: `zzz_notes` is also "no", and within a rank the order is
    alphabetical.
    """
    ordered = find_probe_tables(make_zip({
        "repo/supabase/migrations/0001.sql": """
            create table public.users (id uuid primary key, email text);
            create table public.entries (id uuid primary key, user_id uuid);
            create table public.products (id uuid primary key, title text);
        """,
    }))
    assert [c.name for c in ordered] == ["users", "entries", "products"]
    assert [c.private_shape for c in ordered] == ["yes", "uncertain", "no"]


def test_the_shape_verdict_is_recorded_not_used_to_filter() -> None:
    """Public-by-design keeps a table out of the READ FINDING, not out of the
    probe. The probe is the thing that can actually answer, and refusing to
    ask about `products` would decide the question by heuristic again."""
    verdicts = {c.name: c.private_shape
                for c in find_probe_tables(make_zip(MIGRATION))}
    assert verdicts["products"] == "no"
    assert "products" in verdicts


# --- what must not reach a URL ----------------------------------------------

def test_a_variable_table_name_is_not_guessed() -> None:
    """`.from(tableName)` cannot be resolved, and inventing a string would put
    it in a request aimed at a customer's database."""
    assert names({"repo/src/db.ts":
                  "supabase.from(tableName).select('*'); supabase.from(`x${y}`)"}) == []


def test_postgrest_builtins_are_not_probed() -> None:
    assert names({"repo/src/db.ts":
                  "supabase.from('rpc'); supabase.from('schema_migrations')"}) == []


def test_only_source_files_are_read_for_from_calls() -> None:
    """A `.from('x')` inside documentation or a changelog is prose, not a call.
    Without the extension filter the corpus turns every code sample in a README
    into a request against a live project."""
    assert names({"repo/README.md": "call supabase.from('ghost_table')"}) == []


def test_a_non_public_schema_table_is_not_offered() -> None:
    assert names({"repo/supabase/migrations/0001.sql":
                  "create table internal.audit (id uuid primary key);"}) == []
