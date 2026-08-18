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

from app.scan.rls import RULE_ID, WRITE_RULE_ID, private_shape, scan_rls
from app.scan.static import run_static_scan


def make_zip(entries: dict[str, str]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in entries.items():
            zf.writestr(name, body)
    buf.seek(0)
    return buf


def reads(entries: dict[str, str]) -> list:
    """Only the read findings.

    Two rules answer two different questions about the same table, so a test
    about one of them must not be able to pass or fail on the other's output.
    Asserting `scan_rls(...) == []` would now mean "neither rule fired", which
    is not what any of these tests are about.
    """
    return [f for f in scan_rls(make_zip(entries)) if f.rule_id == RULE_ID]


def writes(entries: dict[str, str]) -> list:
    return [f for f in scan_rls(make_zip(entries)) if f.rule_id == WRITE_RULE_ID]


EXPOSED = {"supabase/migrations/0001_init.sql": """
    create table public.users (
      id uuid primary key,
      email text not null
    );
"""}


# --- what it reports --------------------------------------------------------

def test_a_private_table_with_no_rls_is_reported() -> None:
    findings = reads(EXPOSED)
    assert [f.rule_id for f in findings] == [RULE_ID]
    assert "users" in findings[0].title


def test_a_public_by_design_table_is_not_reported() -> None:
    """A catalogue is an API. Reporting it is the `*`-without-credentials
    error in another costume."""
    assert reads({"supabase/migrations/0001.sql": """
        create table public.products (id uuid primary key, title text);
    """}) == []


def test_a_protected_table_is_not_reported() -> None:
    assert reads({"supabase/migrations/0001.sql": """
        create table public.users (id uuid primary key, email text);
        alter table public.users enable row level security;
        create policy p on public.users for select using (auth.uid() = id);
    """}) == []


def test_rls_on_with_no_policy_is_default_deny_and_not_reported() -> None:
    """The most common CORRECT configuration. Reporting it would push the
    customer toward ADDING a policy, i.e. toward opening the table."""
    assert reads({"supabase/migrations/0001.sql": """
        create table public.users (id uuid primary key, email text);
        alter table public.users enable row level security;
    """}) == []


def test_a_repo_with_no_committed_schema_is_silent() -> None:
    """Not "secure" — undetermined. But a scanner that said so on every repo
    without migrations would be noise, and the live probe is the thing that can
    actually answer it."""
    assert scan_rls(make_zip({"src/app.ts": "export const x = 1;"})) == []


def test_an_uncertain_table_is_not_reported() -> None:
    """`user_id` alone is not enough — nearly every table in a multi-tenant app
    carries it, public ones included. An unconfident finding in a customer's
    report is worse than no finding."""
    assert reads({"supabase/migrations/0001.sql": """
        create table public.entries (id uuid primary key, user_id uuid);
    """}) == []


# --- what it is allowed to say ---------------------------------------------

def test_the_finding_says_it_read_the_repository_not_the_database() -> None:
    """The load-bearing wording. On the only deployment we have checked, this
    method was wrong twice and silent about the case that was true."""
    finding = reads(EXPOSED)[0]
    text = finding.explanation.lower()
    assert "not from your database" in text
    assert "check" in text


def test_the_fix_hint_gives_the_one_request_that_settles_it() -> None:
    finding = reads(EXPOSED)[0]
    assert "curl" in finding.fix_hint
    assert "/rest/v1/users" in finding.fix_hint


def test_the_fix_hint_warns_that_rls_alone_closes_the_app_out() -> None:
    """The likelier way a customer breaks their own product acting on this."""
    finding = reads(EXPOSED)[0]
    assert "without" in finding.fix_hint.lower()
    assert "policy" in finding.fix_hint.lower()


def test_confidence_is_not_stated_as_certainty() -> None:
    """0.9 would claim the repository is the database. It is not."""
    assert reads(EXPOSED)[0].confidence <= 0.7


# --- writes -----------------------------------------------------------------
#
# The read rule has to guess whether a table's CONTENTS are private, and the
# public-by-design list is that guess. The write rule has no such list on
# purpose: a catalogue anyone can read is an API, a catalogue anyone can
# rewrite is not a design. So the two rules disagree about the same table, and
# that disagreement is the feature.

def test_a_public_by_design_table_is_still_reported_as_writable() -> None:
    """The contrast case. `products` is deliberately readable and must not be
    reported as a read exposure — but Supabase grants anon insert, update and
    delete on it too, and nothing about a catalogue makes that intended."""
    entries = {"supabase/migrations/0001.sql": """
        create table public.products (id uuid primary key, title text);
    """}
    assert reads(entries) == []
    finding = writes(entries)[0]
    assert "products" in finding.title
    assert finding.severity == "critical"


def test_update_and_delete_are_critical_whatever_the_table_holds() -> None:
    """No shape heuristic runs here. Rewriting somebody else's row is the harm,
    and it does not depend on what the row contains."""
    finding = writes({"supabase/migrations/0001.sql": """
        create table public.entries (id uuid primary key, note text);
    """})[0]
    assert finding.severity == "critical"
    assert "UPDATE" in finding.explanation
    assert "DELETE" in finding.explanation


def test_insert_only_is_not_critical_and_says_a_form_may_be_intended() -> None:
    """A waitlist, a contact form and a feedback box are SUPPOSED to take rows
    from strangers. Calling that critical is how a real finding gets ignored."""
    finding = writes({"supabase/migrations/0001.sql": """
        create table public.waitlist (id uuid primary key, email text);
        alter table public.waitlist enable row level security;
        create policy "anyone_signs_up" on public.waitlist
          for insert with check (true);
    """})[0]
    assert finding.severity == "medium"
    assert "add rows" in finding.title
    assert "intended design" in finding.explanation


def test_rls_on_with_no_write_policy_is_default_deny_and_silent() -> None:
    """Same rule as for reads, and the same reason: reporting it would push the
    customer toward adding a policy, i.e. toward opening the table."""
    assert writes({"supabase/migrations/0001.sql": """
        create table public.users (id uuid primary key, email text);
        alter table public.users enable row level security;
        create policy p on public.users for select using (auth.uid() = id);
    """}) == []


def test_a_policy_scoped_to_authenticated_does_not_open_anon() -> None:
    """`TO authenticated` is the ordinary way to allow logged-in writes. It is
    not a hole, and reporting it would make the rule useless on every real
    project."""
    assert writes({"supabase/migrations/0001.sql": """
        create table public.notes (id uuid primary key, body text);
        alter table public.notes enable row level security;
        create policy "staff_writes" on public.notes
          for all to authenticated using (true) with check (true);
    """}) == []


def test_an_insert_policy_is_judged_on_with_check_not_using() -> None:
    """`FOR INSERT` has no USING clause at all — Postgres does not consult one.
    Judging it on USING reads every insert policy as unconstrained."""
    assert writes({"supabase/migrations/0001.sql": """
        create table public.notes (id uuid primary key, user_id uuid);
        alter table public.notes enable row level security;
        create policy "own_only" on public.notes
          for insert with check ((select auth.uid()) = user_id);
    """}) == []


def test_an_update_policy_is_judged_on_using_not_with_check() -> None:
    """The opposite half, and the one that decides whether a stranger can touch
    somebody ELSE's row. `WITH CHECK (true)` on an update policy only says what
    the row may look like afterwards; USING still picks which rows are visible
    to the update at all."""
    assert writes({"supabase/migrations/0001.sql": """
        create table public.notes (id uuid primary key, user_id uuid);
        alter table public.notes enable row level security;
        create policy "own_only" on public.notes
          for update using ((select auth.uid()) = user_id) with check (true);
    """}) == []


def test_a_permissive_update_policy_is_reported() -> None:
    """The control for the two tests above: without it, a rule that never fired
    on an RLS-enabled table would pass both."""
    finding = writes({"supabase/migrations/0001.sql": """
        create table public.notes (id uuid primary key, user_id uuid);
        alter table public.notes enable row level security;
        create policy "oops" on public.notes for update using (true);
    """})[0]
    assert finding.severity == "critical"
    assert "UPDATE" in finding.explanation


def test_a_table_outside_the_public_schema_is_not_reported() -> None:
    """PostgREST exposes `public` (plus whatever is configured). A table in a
    private schema is not reachable with the anon key at all, and reporting it
    would be a finding about something no request can touch.

    Written because mutation testing said so: deleting this guard left every
    other test green.
    """
    assert writes({"supabase/migrations/0001.sql": """
        create schema internal;
        create table internal.audit_log (id uuid primary key, note text);
    """}) == []


def test_the_write_finding_also_says_it_read_the_repository() -> None:
    """Same constraint as the read rule, for the same measured reason: the
    committed migrations were wrong about the one deployment we checked."""
    destructive = writes({"supabase/migrations/0001.sql":
                          "create table public.entries (id uuid primary key);"})[0]
    insert_only = writes({"supabase/migrations/0001.sql": """
        create table public.waitlist (id uuid primary key);
        alter table public.waitlist enable row level security;
        create policy w on public.waitlist for insert with check (true);
    """})[0]
    for finding in (destructive, insert_only):
        text = finding.explanation.lower()
        assert "from your repository" in text
        assert "not from your database" in text
        assert finding.confidence <= 0.75


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


def test_the_static_scan_carries_the_write_finding_through() -> None:
    result = run_static_scan(make_zip(EXPOSED))
    assert any(f["rule_id"] == WRITE_RULE_ID for f in result["findings"])


def test_read_and_write_findings_about_one_table_both_survive() -> None:
    """They share a file and carry no line, which is what the cross-rubric
    merge keys on. Two rules answering two questions about the same table must
    not collapse into one."""
    rule_ids = [f["rule_id"] for f in run_static_scan(make_zip(EXPOSED))["findings"]]
    assert RULE_ID in rule_ids
    assert WRITE_RULE_ID in rule_ids
