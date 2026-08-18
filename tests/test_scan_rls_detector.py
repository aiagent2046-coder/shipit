"""The RLS detector, and the wording it is allowed to use.

The detector reads a repository's committed migrations. MEASURED 2026-08-18
against a real deployment: those migrations did not describe it — two tables
this method called exposed were protected, and the one that WAS exposed had no
migration at all. So the finding is worth making and must not be phrased as an
observation of the customer's database, and that constraint is tested here
rather than left to whoever edits the string next.
"""

from __future__ import annotations

import io
import zipfile

from app.scan.rls import RULE_ID, private_shape, scan_rls
from app.scan.static import run_static_scan


def make_zip(entries: dict[str, str]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in entries.items():
            zf.writestr(name, body)
    buf.seek(0)
    return buf


EXPOSED = {"supabase/migrations/0001_init.sql": """
    create table public.users (
      id uuid primary key,
      email text not null
    );
"""}


# --- what it reports --------------------------------------------------------

def test_a_private_table_with_no_rls_is_reported() -> None:
    findings = scan_rls(make_zip(EXPOSED))
    assert [f.rule_id for f in findings] == [RULE_ID]
    assert "users" in findings[0].title


def test_a_public_by_design_table_is_not_reported() -> None:
    """A catalogue is an API. Reporting it is the `*`-without-credentials
    error in another costume."""
    assert scan_rls(make_zip({"supabase/migrations/0001.sql": """
        create table public.products (id uuid primary key, title text);
    """})) == []


def test_a_protected_table_is_not_reported() -> None:
    assert scan_rls(make_zip({"supabase/migrations/0001.sql": """
        create table public.users (id uuid primary key, email text);
        alter table public.users enable row level security;
        create policy p on public.users for select using (auth.uid() = id);
    """})) == []


def test_rls_on_with_no_policy_is_default_deny_and_not_reported() -> None:
    """The most common CORRECT configuration. Reporting it would push the
    customer toward ADDING a policy, i.e. toward opening the table."""
    assert scan_rls(make_zip({"supabase/migrations/0001.sql": """
        create table public.users (id uuid primary key, email text);
        alter table public.users enable row level security;
    """})) == []


def test_a_repo_with_no_committed_schema_is_silent() -> None:
    """Not "secure" — undetermined. But a scanner that said so on every repo
    without migrations would be noise, and the live probe is the thing that can
    actually answer it."""
    assert scan_rls(make_zip({"src/app.ts": "export const x = 1;"})) == []


def test_an_uncertain_table_is_not_reported() -> None:
    """`user_id` alone is not enough — nearly every table in a multi-tenant app
    carries it, public ones included. An unconfident finding in a customer's
    report is worse than no finding."""
    assert scan_rls(make_zip({"supabase/migrations/0001.sql": """
        create table public.entries (id uuid primary key, user_id uuid);
    """})) == []


# --- what it is allowed to say ---------------------------------------------

def test_the_finding_says_it_read_the_repository_not_the_database() -> None:
    """The load-bearing wording. On the only deployment we have checked, this
    method was wrong twice and silent about the case that was true."""
    finding = scan_rls(make_zip(EXPOSED))[0]
    text = finding.explanation.lower()
    assert "not from your database" in text
    assert "check" in text


def test_the_fix_hint_gives_the_one_request_that_settles_it() -> None:
    finding = scan_rls(make_zip(EXPOSED))[0]
    assert "curl" in finding.fix_hint
    assert "/rest/v1/users" in finding.fix_hint


def test_the_fix_hint_warns_that_rls_alone_closes_the_app_out() -> None:
    """The likelier way a customer breaks their own product acting on this."""
    finding = scan_rls(make_zip(EXPOSED))[0]
    assert "without" in finding.fix_hint.lower()
    assert "policy" in finding.fix_hint.lower()


def test_confidence_is_not_stated_as_certainty() -> None:
    """0.9 would claim the repository is the database. It is not."""
    assert scan_rls(make_zip(EXPOSED))[0].confidence <= 0.7


# --- the classification -----------------------------------------------------

def test_public_by_design_is_checked_before_the_column_hints() -> None:
    verdict, why = private_shape("products", ["id", "notes"])
    assert verdict == "no"
    assert "public-by-design" in why


def test_a_model_written_judgement_counts_as_private() -> None:
    """In an AI product the most sensitive rows are what the model concluded
    about someone, not the profile."""
    verdict, _ = private_shape(
        "avatar_interactions", ["id", "user_id", "summary", "sentiment"])
    assert verdict == "yes"


def test_an_auth_users_key_plus_free_text_counts() -> None:
    verdict, why = private_shape(
        "notes_by_user", ["owner", "content"], references_auth_users=True)
    assert verdict == "yes"
    assert "auth.users" in why


def test_an_auth_users_key_alone_does_not_convict_a_join_table() -> None:
    verdict, _ = private_shape(
        "memberships", ["user_id", "team_id"], references_auth_users=True)
    assert verdict != "yes"


# --- wired into the static scan --------------------------------------------

def test_the_static_scan_carries_the_finding_through() -> None:
    """A detector nothing calls is not a detector."""
    result = run_static_scan(make_zip(EXPOSED))
    assert any(f["rule_id"] == RULE_ID for f in result["findings"])
