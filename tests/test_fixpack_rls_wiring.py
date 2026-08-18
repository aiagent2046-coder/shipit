"""From a finding to a migration, and from a refusal to a recorded reason.

The generator and the detector are each tested on their own. This is the seam
between them, which is where a feature quietly becomes decorative: a detector
whose findings nothing consumes, or a Fix Pack that drops what it declined to
fix and leaves the customer thinking there was nothing else.
"""

from __future__ import annotations

import io
import zipfile

from app.fixpack.generate import build_fixpack_plan
from app.scan.rls import RULE_ID, scan_rls


def make_zip(entries: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in entries.items():
            zf.writestr(name, body)
    return buf.getvalue()


# A precedent exists: `messages` is scoped by match_id and carries a working
# policy, so `agent_projects` can be fixed by copying it. This is the real
# shape from the project the live before/after was run against.
WITH_PRECEDENT = {"supabase/migrations/0001.sql": """
    create table public.founder_profiles (
      id uuid primary key,
      user_id uuid references auth.users(id),
      email text
    );
    create table public.matches (
      id uuid primary key,
      founder1_id uuid references founder_profiles(id),
      founder2_id uuid references founder_profiles(id)
    );
    create table public.messages (
      id uuid primary key,
      match_id uuid references matches(id),
      body text
    );
    alter table public.messages enable row level security;
    create policy "messages_select" on public.messages for select using (
      EXISTS (SELECT 1 FROM matches m WHERE ((m.id = messages.match_id)
        AND ((SELECT auth.uid()) IN (SELECT founder_profiles.user_id
             FROM founder_profiles
             WHERE (founder_profiles.id = ANY (ARRAY[m.founder1_id, m.founder2_id])))))));

    create table public.agent_projects (
      match_id uuid references matches(id),
      summary text
    );
"""}

NO_PRECEDENT = {"supabase/migrations/0001.sql": """
    create table public.leads (id uuid primary key, email text);
"""}


def _findings(entries: dict[str, str]) -> list[dict]:
    buf = io.BytesIO(make_zip(entries))
    return [
        {"rule_id": f.rule_id, "title": f.title, "severity": f.severity,
         "confidence": f.confidence, "category": f.category, "file": f.file,
         "explanation": f.explanation, "fix_hint": f.fix_hint}
        for f in scan_rls(buf)
    ]


# --- the seam ---------------------------------------------------------------

def test_a_finding_becomes_a_migration_in_the_plan() -> None:
    zip_bytes = make_zip(WITH_PRECEDENT)
    findings = _findings(WITH_PRECEDENT)
    assert any(f["rule_id"] == RULE_ID for f in findings)

    plan = build_fixpack_plan(zip_bytes, findings)
    migrations = [p for p in plan.files if "enable_rls" in p]
    assert migrations, plan.files.keys()
    path = migrations[0]
    assert path.startswith("supabase/migrations/")
    assert path.endswith("_enable_rls_agent_projects.sql")

    sql = plan.files[path]
    assert "agent_projects.match_id" in sql
    assert "enable row level security" in sql.lower()
    assert "create policy" in sql.lower()


def test_the_migration_is_a_new_file_and_edits_no_existing_one() -> None:
    """A customer's migration chain has already run against their database;
    rewriting a link in it desynchronises the two."""
    plan = build_fixpack_plan(make_zip(WITH_PRECEDENT),
                              _findings(WITH_PRECEDENT))
    assert "supabase/migrations/0001.sql" not in plan.files
    assert plan.deletions == []


def test_the_plan_describes_the_change_for_the_pull_request_body() -> None:
    """A file appearing in a Pack with nothing said about it is how a customer
    merges a migration they did not understand."""
    plan = build_fixpack_plan(make_zip(WITH_PRECEDENT),
                              _findings(WITH_PRECEDENT))
    described = [c for c in plan.config_fixes if c.rule_id == RULE_ID]
    assert described
    detail = described[0].detail
    assert "messages_select" in detail          # the precedent it copied
    assert "close the table to your application" in detail


# --- refusals ---------------------------------------------------------------

def test_a_refusal_is_recorded_rather_than_dropped() -> None:
    """The customer paid for a Fix Pack. "We saw this and would not guess at
    your authorisation model" is information; silence is not."""
    plan = build_fixpack_plan(make_zip(NO_PRECEDENT), _findings(NO_PRECEDENT))
    assert not [p for p in plan.files if "enable_rls" in p]
    reasons = [s.reason for s in plan.skipped if s.rule_id == RULE_ID]
    assert reasons
    assert "no foreign key" in reasons[0] or "no other table" in reasons[0]


def test_a_finding_whose_table_is_not_in_the_schema_is_refused() -> None:
    """The table name is taken from the detector's title and then CHECKED. A
    reworded title must produce a recorded refusal, not a migration for a
    table that does not exist."""
    plan = build_fixpack_plan(make_zip(WITH_PRECEDENT), [{
        "rule_id": RULE_ID,
        "title": "Table `nonexistent_table` is readable with your public key",
        "severity": "high", "confidence": 0.6, "category": "Security",
        "file": "supabase/migrations/0001.sql",
    }])
    assert not [p for p in plan.files if "enable_rls" in p]
    assert [s for s in plan.skipped if s.rule_id == RULE_ID]


# --- it does not disturb the rest of the Pack -------------------------------

def test_a_repo_with_no_rls_findings_produces_no_migration() -> None:
    plan = build_fixpack_plan(make_zip({"src/a.ts": "export const x = 1;"}), [])
    assert not [p for p in plan.files if "enable_rls" in p]


def test_two_exposed_tables_get_distinct_migration_filenames() -> None:
    """Supabase orders migrations by filename; a collision would drop one and
    make the other's order arbitrary.

    Both tables need a PRECEDENT or nothing is generated and the assertion
    passes on two empty lists — which is what the first version of this test
    did.
    """
    entries = {"supabase/migrations/0001.sql": WITH_PRECEDENT[
        "supabase/migrations/0001.sql"] + """
        create table public.agent_notes (
          match_id uuid references matches(id),
          summary text
        );
    """}
    plan = build_fixpack_plan(make_zip(entries), _findings(entries))
    migrations = [p for p in plan.files if "enable_rls" in p]
    assert len(migrations) == 2, migrations
    assert len(set(migrations)) == 2
    assert {"agent_projects", "agent_notes"} == {
        p.rsplit("_enable_rls_", 1)[1][: -len(".sql")] for p in migrations}
