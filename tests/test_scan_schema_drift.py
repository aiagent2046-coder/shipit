"""Tables the repository names but its migrations never declare.

MEASURED, and the two sources are reported apart because their evidence is
not the same strength. See app/scan/schema_drift.py for the numbers and what
each one licenses the report to say.
"""

from __future__ import annotations

import io
import zipfile

from app.scan.schema_drift import RULE_ID, scan_schema_drift


def make_zip(entries: dict[str, str]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in entries.items():
            zf.writestr(name, body)
    buf.seek(0)
    return buf


SCHEMA = """
    create table public.users (id uuid primary key, email text);
    create table public.products (id uuid primary key, title text);
"""

TYPES = """
export type Database = {
  public: {
    Tables: {
      users: { Row: { id: string } },
      agent_projects: { Row: { id: string, owner: string } }
    }
  }
}
"""


def test_reports_a_table_the_client_calls_and_no_migration_declares():
    findings = scan_schema_drift(make_zip({
        "repo/supabase/migrations/0001.sql": SCHEMA,
        "repo/src/lib/db.ts": "await supabase.from('waitlist').select('*');",
    }))
    assert len(findings) == 1
    assert findings[0].rule_id == RULE_ID
    assert "waitlist" in findings[0].explanation


def test_silent_when_the_repository_commits_no_schema():
    # Not "clean" -- undetermined, and app/scan/rls.py is silent on the same
    # repositories for the same reason: with nothing declared there is no
    # drift to measure, only an absence, and a finding on every schemaless
    # repository is noise. The live probe is what answers that population.
    assert scan_schema_drift(make_zip({
        "repo/src/lib/db.ts": "await supabase.from('waitlist').select('*');",
    })) == []


def test_silent_when_everything_named_is_declared():
    assert scan_schema_drift(make_zip({
        "repo/supabase/migrations/0001.sql": SCHEMA,
        "repo/src/lib/db.ts": "await supabase.from('users').select('*');",
    })) == []


def test_one_finding_lists_every_drifted_table():
    # MEASURED 2026-08-19 (n=108): median gap 3 tables, p90 13, max 67. One
    # finding per table would put 67 entries in a report nobody then reads.
    findings = scan_schema_drift(make_zip({
        "repo/supabase/migrations/0001.sql": SCHEMA,
        "repo/src/a.ts": ("supabase.from('waitlist').select();"
                          "supabase.from('leads').select();"
                          "supabase.from('orders').select();"),
    }))
    assert len(findings) == 1
    for name in ("waitlist", "leads", "orders"):
        assert name in findings[0].explanation


def test_generated_types_and_client_code_are_not_claimed_alike():
    """The whole reason the two sources are kept apart.

    A generated types file is written FROM THE LIVE PROJECT, so a name in it
    is evidence the table existed in the database. A `.from()` call is
    evidence the application expects it -- a call left behind after the table
    was dropped looks identical. The report must not launder the second into
    the first.
    """
    from_types = scan_schema_drift(make_zip({
        "repo/supabase/migrations/0001.sql": SCHEMA,
        "repo/src/integrations/supabase/types.ts": TYPES,
    }))[0]
    from_code = scan_schema_drift(make_zip({
        "repo/supabase/migrations/0001.sql": SCHEMA,
        "repo/src/a.ts": "supabase.from('waitlist').select();",
    }))[0]

    assert "agent_projects" in from_types.explanation
    assert from_types.confidence > from_code.confidence
    assert from_types.explanation != from_code.explanation


def test_a_stale_call_is_never_called_an_existing_table():
    """RISK, UNMEASURED: code calling a dropped table looks exactly like code
    calling a table created in the dashboard. The wording carries that."""
    finding = scan_schema_drift(make_zip({
        "repo/supabase/migrations/0001.sql": SCHEMA,
        "repo/src/a.ts": "supabase.from('waitlist').select();",
    }))[0]
    lowered = finding.explanation.lower()
    assert "exists in your database" not in lowered
    assert "your code" in lowered or "application" in lowered


def test_the_list_never_claims_to_be_complete():
    # MEASURED 2026-08-19: 72% [63-80] of the repositories analysed contain a
    # `.from(variable)`, which names no table. A list presented without that
    # caveat is claiming a completeness it does not have.
    finding = scan_schema_drift(make_zip({
        "repo/supabase/migrations/0001.sql": SCHEMA,
        "repo/src/a.ts": ("supabase.from('waitlist').select();"
                          "supabase.from(tableName).select();"),
    }))[0]
    assert "literal" in finding.explanation.lower()


def test_views_and_internal_names_are_not_reported_as_missing_tables():
    findings = scan_schema_drift(make_zip({
        "repo/supabase/migrations/0001.sql": SCHEMA,
        "repo/src/a.ts": ("supabase.from('active_users_view').select();"
                          "supabase.from('_internal').select();"
                          "supabase.from('schema_migrations').select();"),
    }))
    assert findings == []


def test_storage_buckets_are_not_reported_as_tables():
    # `supabase.storage.from('avatars')` is the same call shape. Reporting a
    # bucket as a missing table is a false claim about a customer's data --
    # the error class app/scan/rls.py's PUBLIC_BY_DESIGN list exists to stop.
    assert scan_schema_drift(make_zip({
        "repo/supabase/migrations/0001.sql": SCHEMA,
        "repo/src/a.ts": "supabase.storage.from('avatars').upload(f);",
    })) == []


def test_severity_stays_medium_and_confidence_below_the_rls_read_rule():
    # This is a coverage and documentation gap, not a proven exposure. The
    # read rule sits at 0.6 after being wrong twice on a real deployment;
    # nothing here has been checked against a database at all.
    finding = scan_schema_drift(make_zip({
        "repo/supabase/migrations/0001.sql": SCHEMA,
        "repo/src/a.ts": "supabase.from('waitlist').select();",
    }))[0]
    assert finding.severity == "medium"
    assert finding.confidence <= 0.6
