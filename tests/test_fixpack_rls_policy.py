"""The RLS policy generator: what it proposes, and what it refuses to.

This is the highest-risk fix the product can emit — every other one removes
something, this one writes a rule deciding who may read a customer's data. It
can be wrong in two opposite directions, and the second is the likelier:

  too permissive  -> the hole stays open and we said it was closed;
  too restrictive -> the table closes to the APPLICATION, discovered in prod.

The anchor test below is real ground truth: the same schema shape produced, by
hand, the policy that was applied to a live project on 2026-08-18 and verified
before and after — anon went from reading 3 rows to 0 while a match participant
still saw their own 3. The generator has to arrive at that same policy.
"""

from __future__ import annotations

from app.fixpack.rls_policy import (
    PolicyProposal,
    PolicyRefusal,
    propose_read_policy,
)
from app.scan.sql_schema import parse_schema

# The real shape, reduced to what matters: two tables scoped by `match_id`,
# one of them already carrying the project's working read policy.
REAL = """
create table public.founder_profiles (
  id uuid primary key,
  user_id uuid references auth.users(id),
  headline text
);
create table public.matches (
  id uuid primary key,
  founder1_id uuid references founder_profiles(id),
  founder2_id uuid references founder_profiles(id)
);
create table public.messages (
  id uuid primary key,
  match_id uuid not null references matches(id),
  sender_id uuid references founder_profiles(id),
  body text
);
alter table public.messages enable row level security;
create policy "messages_select" on public.messages for select using (
  EXISTS ( SELECT 1 FROM matches m
           WHERE ((m.id = messages.match_id)
             AND ((SELECT auth.uid() AS uid) IN
                  (SELECT founder_profiles.user_id FROM founder_profiles
                   WHERE (founder_profiles.id = ANY (ARRAY[m.founder1_id, m.founder2_id])))))));

create table public.agent_projects (
  match_id uuid references matches(id),
  idea text,
  summary text
);
"""


# --- the anchor -------------------------------------------------------------

def test_it_reproduces_the_policy_that_was_applied_and_verified_live() -> None:
    """Ground truth, not a fixture invented to pass. This is the fix that ran
    against a real deployment: anon went 3 rows -> 0, a match participant kept
    seeing their own."""
    result = propose_read_policy("agent_projects", parse_schema(REAL))
    assert isinstance(result, PolicyProposal)

    assert "agent_projects.match_id" in result.predicate
    assert "messages." not in result.predicate      # retargeted, not copied raw
    assert "founder1_id" in result.predicate        # the whole chain survived
    assert "auth.uid()" in result.predicate
    assert result.precedent_table == "messages"
    assert result.precedent_policy == "messages_select"


def test_the_nested_predicate_is_not_truncated_at_the_first_paren() -> None:
    """A non-greedy `\\((.*?)\\)` stops inside `EXISTS ( SELECT 1 FROM matches m
    WHERE ((m.id = …`, and that fragment would be shipped as a policy. The
    clause is matched by counting parentheses for exactly this reason."""
    result = propose_read_policy("agent_projects", parse_schema(REAL))
    assert isinstance(result, PolicyProposal)
    assert result.predicate.count("(") == result.predicate.count(")")
    assert result.predicate.rstrip().endswith(")")


# --- what it refuses --------------------------------------------------------

def test_it_refuses_when_no_sibling_is_scoped_the_same_way() -> None:
    """A predicate we invented is a guess about their authorisation model
    presented as a fix."""
    schema = parse_schema("""
        create table public.orphan (
          team_id uuid references teams(id),
          notes text
        );
        create table public.teams (id uuid primary key);
    """)
    result = propose_read_policy("orphan", schema)
    assert isinstance(result, PolicyRefusal)
    assert "no other table scoped the same way" in result.reason


def test_it_refuses_when_the_row_has_nothing_to_scope_by() -> None:
    schema = parse_schema("""
        create table public.leads (id uuid primary key, email text);
    """)
    result = propose_read_policy("leads", schema)
    assert isinstance(result, PolicyRefusal)
    assert "no foreign key" in result.reason


def test_it_never_copies_using_true_as_the_fix() -> None:
    """THE WORST THING THIS COULD EMIT. A sibling whose policy is `USING (true)`
    is not a precedent — proposing it would hand back the hole itself, wearing
    the word 'fix'."""
    schema = parse_schema("""
        create table public.matches (id uuid primary key);
        create table public.messages (
          match_id uuid references matches(id), body text
        );
        alter table public.messages enable row level security;
        create policy "open" on public.messages for select using (true);
        create table public.agent_projects (
          match_id uuid references matches(id), summary text
        );
    """)
    result = propose_read_policy("agent_projects", schema)
    assert isinstance(result, PolicyRefusal)


def test_a_table_already_protected_is_left_alone() -> None:
    """RLS on with a predicated read policy is the correct configuration. A fix
    here would be churn at best."""
    schema = parse_schema("""
        create table public.users (id uuid primary key, email text);
        alter table public.users enable row level security;
        create policy p on public.users for select using (auth.uid() = id);
    """)
    result = propose_read_policy("users", schema)
    assert isinstance(result, PolicyRefusal)
    assert "nothing to fix" in result.reason


def test_rls_on_with_no_policy_is_already_closed_and_not_touched() -> None:
    """Default-deny. Not a hole, and adding a policy would OPEN it."""
    schema = parse_schema("""
        create table public.audit_log (id uuid primary key, note text);
        alter table public.audit_log enable row level security;
    """)
    assert isinstance(propose_read_policy("audit_log", schema), PolicyRefusal)


def test_an_unknown_table_is_refused_rather_than_invented() -> None:
    result = propose_read_policy("ghost", parse_schema(REAL))
    assert isinstance(result, PolicyRefusal)


# --- the emitted SQL --------------------------------------------------------

def test_the_migration_never_enables_rls_without_also_adding_a_policy() -> None:
    """The likelier failure: `ENABLE ROW LEVEL SECURITY` alone is default-deny,
    which clears the finding and closes the table to the application. Every
    proposal must carry both halves, and a refusal must carry no SQL at all."""
    result = propose_read_policy("agent_projects", parse_schema(REAL))
    assert isinstance(result, PolicyProposal)
    assert "enable row level security" in result.sql.lower()
    assert "create policy" in result.sql.lower()

    refusal = propose_read_policy("leads", parse_schema(
        "create table public.leads (id uuid primary key, email text);"))
    assert not hasattr(refusal, "sql")


def test_the_migration_is_a_no_op_where_a_read_policy_already_exists() -> None:
    """MEASURED: a real project's committed migrations did not describe its
    deployment — two tables the SQL called exposed were protected. So the SQL
    must be correct whether or not the live state matches the repository."""
    result = propose_read_policy("agent_projects", parse_schema(REAL))
    assert isinstance(result, PolicyProposal)
    lowered = result.sql.lower()
    assert "if not exists" in lowered
    assert "pg_policies" in lowered
    assert "cmd in ('select', 'all')" in lowered


def test_the_migration_never_drops_or_replaces_an_existing_policy() -> None:
    """A policy the customer wrote is theirs. Replacing one to make room for
    ours could widen access, and would do it silently."""
    result = propose_read_policy("agent_projects", parse_schema(REAL))
    assert isinstance(result, PolicyProposal)
    lowered = result.sql.lower()
    assert "drop policy" not in lowered
    assert "or replace" not in lowered
    assert "alter policy" not in lowered


def test_the_sql_says_it_was_written_without_reading_the_database() -> None:
    """The customer is the one who knows their deployment. Anything generated
    from migrations alone has to admit that where they will read it."""
    result = propose_read_policy("agent_projects", parse_schema(REAL))
    assert isinstance(result, PolicyProposal)
    assert "without reading your database" in result.sql


# --- retargeting ------------------------------------------------------------

def test_only_qualified_references_are_rewritten() -> None:
    """`messages.` moves to `agent_projects.`; a bare word could be an alias, a
    column, or part of a string, and rewriting those corrupts SQL that then
    reaches a customer's database."""
    from app.fixpack.rls_policy import _retarget

    out = _retarget("m.id = messages.match_id and note like '%messages%'",
                    "messages", "agent_projects")
    assert "agent_projects.match_id" in out
    assert "'%messages%'" in out          # the literal is untouched


def test_a_predicate_that_never_names_the_source_table_is_not_shipped() -> None:
    """If the substitution cannot be seen to have done anything, the result has
    not been verified and must not be proposed."""
    from app.fixpack.rls_policy import _retarget

    assert _retarget("auth.uid() = owner", "messages", "agent_projects") == ""


# --- scoping preference -----------------------------------------------------

def test_an_identity_key_is_preferred_over_a_grouping_key() -> None:
    """A foreign key into auth.users says the row belongs to one person, which
    is the strongest scoping available."""
    schema = parse_schema("""
        create table public.teams (id uuid primary key);
        create table public.notes (
          user_id uuid references auth.users(id),
          team_id uuid references teams(id),
          body text
        );
        alter table public.notes enable row level security;
        create policy "notes_own" on public.notes for select
          using ((select auth.uid()) = notes.user_id);
        create table public.drafts (
          user_id uuid references auth.users(id),
          team_id uuid references teams(id),
          body text
        );
    """)
    result = propose_read_policy("drafts", schema)
    assert isinstance(result, PolicyProposal)
    assert "drafts.user_id" in result.predicate


def test_an_unconditional_sibling_is_rejected_as_a_precedent_itself() -> None:
    """The end-to-end test above passes for the WRONG REASON and this one
    exists because mutation testing said so.

    Deleting the `is_unconditional` guard left every test green: a `USING
    (true)` policy never names its table, so `_retarget` returns "" and the
    proposal is dropped one line later. The hole was plugged by accident, by a
    guard written for something else.

    So the rule is asserted where it lives. A sibling that is wide open is not
    a precedent, whatever any downstream check happens to do about it.
    """
    from app.fixpack.rls_policy import _precedent_for

    schema = parse_schema("""
        create table public.matches (id uuid primary key);
        create table public.messages (
          match_id uuid references matches(id), body text
        );
        alter table public.messages enable row level security;
        create policy "open" on public.messages for select using (true);
        create table public.agent_projects (
          match_id uuid references matches(id), summary text
        );
    """)
    target = schema["agent_projects"]
    key = target.foreign_keys[0]
    assert _precedent_for(key, target, schema) is None


def test_a_predicated_sibling_IS_accepted_as_a_precedent() -> None:
    """The control for the test above: without it, `_precedent_for` returning
    None unconditionally would also pass."""
    from app.fixpack.rls_policy import _precedent_for

    schema = parse_schema(REAL)
    target = schema["agent_projects"]
    key = target.foreign_keys[0]
    found = _precedent_for(key, target, schema)
    assert found is not None
    sibling, policy = found
    assert sibling.name == "messages"
    assert policy.name == "messages_select"


# --- the table's own policy comes first -------------------------------------
#
# MEASURED 2026-08-19 on a real customer's repository, after a paid Fix Pack.
# `avatar_interactions` already carried
#
#     CREATE POLICY "users see own interactions" ON public.avatar_interactions
#       FOR SELECT USING ((select auth.uid()) = user_id);
#
# and was missing exactly one line: ALTER TABLE … ENABLE ROW LEVEL SECURITY,
# without which a policy does not apply. The generator went straight to the
# sibling search and proposed a policy scoped by `match_id` — readable by BOTH
# participants of a match, on a table holding what a model concluded about one
# founder for the other, `sentiment` among its columns.
#
# The customer was saved by the `if not exists` guard, which saw the existing
# SELECT policy and created nothing. Being right by way of a guard written for
# something else is not being right.

OWN_POLICY = """
create table public.matches (id uuid primary key);
create table public.messages (
  id uuid primary key,
  match_id uuid references matches(id),
  body text
);
alter table public.messages enable row level security;
create policy "messages_select" on public.messages for select using (
  EXISTS (SELECT 1 FROM matches m WHERE m.id = messages.match_id));

create table public.avatar_interactions (
  id uuid primary key,
  user_id uuid not null references auth.users(id),
  match_id uuid not null references public.matches(id),
  summary text,
  sentiment text
);
create policy "users see own interactions" on public.avatar_interactions
  for select using ((select auth.uid()) = user_id);
"""


def test_a_table_with_its_own_policy_only_needs_rls_switched_on() -> None:
    result = propose_read_policy("avatar_interactions", parse_schema(OWN_POLICY))
    assert isinstance(result, PolicyProposal)
    assert result.enables_existing == "users see own interactions"
    assert result.predicate == ""
    assert "create policy" not in result.sql.lower()
    assert "enable row level security" in result.sql.lower()


def test_it_does_not_widen_what_the_author_already_wrote() -> None:
    """THE ONE THAT MATTERS. A sibling scoped by `match_id` is right there and
    would have been copied. Its predicate is wider than the author's own —
    every participant of a match, rather than the row's owner."""
    result = propose_read_policy("avatar_interactions", parse_schema(OWN_POLICY))
    assert isinstance(result, PolicyProposal)
    assert "match_id" not in result.sql
    assert "messages" not in result.sql


def test_an_unconditional_own_policy_does_not_count_as_protection() -> None:
    """`USING (true)` applies to anon too, so switching RLS on beside it
    changes nothing and the table stays open. Those must fall through to the
    sibling search, where a real predicate can come from."""
    schema = parse_schema(OWN_POLICY.replace(
        "using ((select auth.uid()) = user_id)", "using (true)"))
    result = propose_read_policy("avatar_interactions", schema)
    assert isinstance(result, PolicyProposal)
    assert result.enables_existing == ""
    assert "create policy" in result.sql.lower()


def test_a_table_with_rls_already_on_is_not_offered_an_enable() -> None:
    """RLS on with a predicated read policy is the correct configuration, and
    `anon_can_read` refuses it before this branch is reached. The control that
    stops the new path from swallowing the old refusal."""
    schema = parse_schema(OWN_POLICY + """
        alter table public.avatar_interactions enable row level security;
    """)
    assert isinstance(propose_read_policy("avatar_interactions", schema),
                      PolicyRefusal)


def test_the_summary_says_what_it_actually_does() -> None:
    """A Pack whose PR body says "policy copied from messages" while the SQL
    only flips a switch describes a change the customer did not get."""
    result = propose_read_policy("avatar_interactions", parse_schema(OWN_POLICY))
    assert isinstance(result, PolicyProposal)
    assert "existing policy" in result.summary
    assert "users see own interactions" in result.summary


def test_rls_already_on_beside_a_wide_policy_is_not_answered_with_enable() -> None:
    """A table can be reachable WITH RLS on: a `USING (true)` policy leaves it
    open, and a narrow policy sitting beside it changes nothing. Answering
    that with "switch RLS on" proposes a migration that is already applied and
    fixes nothing — the finding would clear and the hole would stay.

    Written because mutation testing said so: deleting the `rls_enabled` guard
    left every other test green, because the branch is only reachable through
    this combination.
    """
    schema = parse_schema(OWN_POLICY + """
        alter table public.avatar_interactions enable row level security;
        create policy "oops_open" on public.avatar_interactions
          for select using (true);
    """)
    result = propose_read_policy("avatar_interactions", schema)
    # Whatever it answers, it must not be "just enable RLS" — that is done.
    if isinstance(result, PolicyProposal):
        assert result.enables_existing == ""
        assert "create policy" in result.sql.lower()
