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
    assert found["users"] == "migrations+client-code"
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


# --- generated types, the only source that can outrun the migrations --------
#
# MEASURED across 226 Supabase repositories: of the 74 that commit no schema,
# 16 carry a `supabase gen types typescript` file — 22% [14-32%] of the blind
# spot going from no table names at all to between 3 and 52 of them. It splits
# hard by generator (Lovable 54%, bolt and hand-written 6%), and the paths say
# why: almost every one is `src/integrations/supabase/types.ts`, Lovable's own
# scaffold, which writes the integration and not the migrations.

GENERATED_TYPES = {"repo/src/integrations/supabase/types.ts": """
export type Database = {
  public: {
    Tables: {
      agent_projects: {
        Row: { id: string; summary: string | null }
        Insert: { id?: string }
        Update: { id?: string }
      }
      founder_profiles: {
        Row: { id: string; email: string }
        Insert: { id?: string }
      }
    }
    Views: { [_ in never]: never }
  }
}
"""}


def test_a_generated_types_file_names_tables_no_migration_declares() -> None:
    """The measured gap, in one test. `agent_projects` was the only table ever
    found genuinely exposed on the deployment we checked, and it appeared in
    neither the migrations nor the client code."""
    found = {c.name: c.source for c in find_probe_tables(make_zip(GENERATED_TYPES))}
    assert set(found) == {"agent_projects", "founder_profiles"}
    assert found["agent_projects"] == "generated-types"


def test_provenance_survives_when_several_sources_agree() -> None:
    """"Only the generated types know about this table" is the interesting
    case, so the sources are kept rather than collapsed to a flag."""
    entries = {**GENERATED_TYPES,
               "repo/supabase/migrations/0001.sql":
                   "create table public.founder_profiles (id uuid primary key);",
               "repo/src/db.ts": "supabase.from('founder_profiles').select('*')"}
    found = {c.name: c.source for c in find_probe_tables(make_zip(entries))}
    assert found["founder_profiles"] == "migrations+client-code+generated-types"
    assert found["agent_projects"] == "generated-types"


def test_a_hand_written_interface_is_not_mistaken_for_a_table_map() -> None:
    """`Row:` appears in plenty of hand-written TypeScript. `Tables: {` is what
    says this file is the generator's output, and without that scope any
    interface with a Row field would put invented names into a URL aimed at a
    customer's database."""
    assert names({"repo/src/grid.ts": """
        export interface DataGrid {
          header: { Row: string[] }
          footer: { Row: string[] }
        }
    """}) == []


def test_a_storage_bucket_is_not_probed_as_a_table() -> None:
    """`supabase.storage.from('avatars')` is the identical call shape against
    a STORAGE BUCKET, and the probe sends a real request to whatever this
    returns. Asking a customer's project about a bucket as though it were a
    table proves nothing about their rows and puts an invented table name in a
    URL aimed at their database.

    Excluded by call site, not by a list of bucket-ish names: `documents` and
    `files` are ordinary table names, and a name list would drop the real ones
    along with the buckets."""
    assert names({"repo/src/upload.ts": """
        await supabase.storage.from('avatars').upload(path, file);
        await supabase.storage.from('documents').list();
    """}) == []


def test_a_table_keeps_its_place_when_the_same_file_uploads_to_storage() -> None:
    """The exclusion is the storage receiver, not the word `from`."""
    assert names({"repo/src/upload.ts": """
        await supabase.storage.from('avatars').upload(path, file);
        const { data } = await supabase.from('documents').select('*');
    """}) == ["documents"]
