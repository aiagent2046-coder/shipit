"""Generate an RLS policy for an exposed table — by precedent, or not at all.

This is the highest-risk fix this product can propose. Every other Fix Pack
change removes something (a committed secret, a tracked .env); this one adds a
rule that decides who may read a customer's data, and it can fail in two
opposite directions:

  too permissive  -> the hole stays open and we have told them it is closed;
  too restrictive -> the table closes to the APPLICATION as well, and they
                     find out in production.

The second is the likelier one and the one a naive fix walks straight into:
`ALTER TABLE … ENABLE ROW LEVEL SECURITY` with no policy is default-deny, so it
"fixes" the finding and breaks the product. Supabase's own advisory says not to
apply that unattended, and it is right.

BEFORE ANY OF THAT: LOOK AT THE TABLE ITSELF. MEASURED 2026-08-19 on a real
customer's repository. `avatar_interactions` already carried

    CREATE POLICY "users see own interactions" ON public.avatar_interactions
      FOR SELECT USING ((select auth.uid()) = user_id);

and was missing exactly one line — `ALTER TABLE … ENABLE ROW LEVEL SECURITY`,
without which a policy does not apply. The generator went straight to the
sibling search, found a table scoped by `match_id`, and proposed a policy
readable by BOTH participants of a match. On a table holding what a model
concluded about one founder for another — `sentiment` among the columns —
that is materially wider than what the author had already written.

The customer was saved by the `if not exists` guard, which saw the existing
SELECT policy and created nothing; only the ENABLE applied, which was the
right answer. Being right by way of a guard written for something else is not
being right. So the first question is now "does this table already have a
policy that would work once RLS is on", and the answer to it is a migration
that enables RLS and adds nothing.

THEN THE RULE IS: propose a policy only when the customer's own schema already
contains one for a table scoped the same way, and copy that. `agent_projects`
is keyed by `match_id`; `messages` is keyed by `match_id` and carries a working
policy; the answer is that policy with the table name changed. When there is no
such precedent we refuse and say why, because a predicate we invented would be
a guess about their authorisation model presented as a fix.

WHAT THE EMITTED SQL ASSUMES ABOUT THE LIVE DATABASE: nothing. Measured
2026-08-18, the committed migrations of a real project did not describe its
deployment — two tables the SQL called exposed were protected, and the one that
was actually exposed had no migration at all. So the migration is written to be
correct whether or not the live state matches the repository: enabling RLS is
idempotent, and the policy is created only if the table has no read policy
already. It never drops or replaces one the customer wrote.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.scan.sql_schema import Table

# Foreign keys that scope a row to a person directly rather than through
# another table. A policy keyed on one of these is about ownership, and
# copying it across tables is sound in the same way as copying a match-scoped
# one.
_IDENTITY_TARGETS = frozenset({"auth.users"})


@dataclass(frozen=True)
class PolicyProposal:
    table: str
    sql: str
    predicate: str
    precedent_table: str
    precedent_policy: str
    # Set when the table already carries a workable read policy and the only
    # thing missing is RLS itself. `predicate` is then empty and the migration
    # adds no policy — the customer already wrote the right one.
    enables_existing: str = ""

    @property
    def summary(self) -> str:
        if self.enables_existing:
            return (f"switch Row Level Security on for `{self.table}` so its "
                    f"existing policy `{self.enables_existing}` takes effect")
        return (f"read policy for `{self.table}`, copied from "
                f"`{self.precedent_policy}` on `{self.precedent_table}`")


@dataclass(frozen=True)
class PolicyRefusal:
    table: str
    reason: str


def propose_read_policy(
    table_name: str, schema: dict[str, Table],
) -> PolicyProposal | PolicyRefusal:
    """A migration closing `table_name` to anon, or a reasoned refusal."""
    table = schema.get(table_name.lower())
    if table is None:
        return PolicyRefusal(table_name, "table is not in the committed schema")

    readable, why = table.anon_can_read
    if not readable:
        return PolicyRefusal(
            table_name, f"nothing to fix: {why}")

    # The table's OWN policies come first. A predicated read policy that is
    # not in effect because RLS is off is not a missing policy — it is a
    # missing ALTER TABLE, and proposing a second policy beside it can only be
    # wider than what the author wrote.
    existing = _own_read_policy(table)
    if existing is not None:
        return PolicyProposal(
            table=table.name,
            sql=_enable_only_migration(table, existing.name),
            predicate="",
            precedent_table=table.name,
            precedent_policy=existing.name,
            enables_existing=existing.name,
        )

    scopes = _scoping_keys(table)
    if not scopes:
        return PolicyRefusal(
            table_name,
            "no foreign key to scope the rows by — a policy here would be a "
            "guess about who owns a row")

    for foreign_key in scopes:
        precedent = _precedent_for(foreign_key, table, schema)
        if precedent is None:
            continue
        sibling, policy = precedent
        predicate = _retarget(policy.using, sibling.name, table.name)
        if not predicate:
            continue
        return PolicyProposal(
            table=table.name,
            sql=_migration(table, predicate),
            predicate=predicate,
            precedent_table=sibling.name,
            precedent_policy=policy.name,
        )

    keys = ", ".join(f"`{k.column}` -> {k.target}" for k in scopes)
    return PolicyRefusal(
        table_name,
        f"no other table scoped the same way ({keys}) carries a working read "
        f"policy to copy")


def _own_read_policy(table: Table):
    """A read policy already on this table that would work once RLS is on.

    Only reached when `anon_can_read` said yes, which with RLS off it says for
    every table regardless of its policies — so this is the case where the
    author wrote the rule and never switched the mechanism on.

    An UNCONDITIONAL policy does not count: `USING (true)` applies to anon too,
    so enabling RLS beside it changes nothing and the table stays open. Those
    fall through to the sibling search, which is where a real predicate can
    come from.
    """
    if table.rls_enabled:
        return None
    for policy in table.read_policies:
        if not policy.is_unconditional:
            return policy
    return None


def _enable_only_migration(table: Table, policy_name: str) -> str:
    """RLS on, and nothing else.

    The module docstring warns that a bare ENABLE is default-deny and breaks
    the application. That is true when there is no policy. Here there is one,
    written by the author, and the ENABLE is the only thing standing between it
    and effect — so this is the narrow case where adding nothing IS the fix.
    """
    return f"""\
-- Generated by Drydock from this repository's own migrations. Review before
-- applying: it was written without reading your database.
--
-- `{table.name}` already has the read policy `{policy_name}` in your
-- migrations, and Row Level Security is never switched on for the table — so
-- that policy is not in effect and the anonymous key can read every row.
--
-- This adds no policy. Yours is already the right one; it only needs RLS on.

alter table {table.schema}.{table.name} enable row level security;
"""


def _scoping_keys(table: Table):
    """Foreign keys worth scoping by, identity keys first.

    A key into `auth.users` says the row belongs to one person, which is the
    strongest scoping available; anything else (a match, a team, a project) is
    tried after it.
    """
    identity = [k for k in table.foreign_keys if k.target in _IDENTITY_TARGETS]
    other = [k for k in table.foreign_keys if k.target not in _IDENTITY_TARGETS]
    return identity + other


def _precedent_for(foreign_key, table: Table, schema: dict[str, Table]):
    """A sibling table with the same foreign key and a usable read policy.

    "Usable" excludes an unconditional one. A sibling whose policy is
    `USING (true)` is not a precedent — copying it would propose the hole
    itself as the fix, which is the single worst thing this function could
    emit.
    """
    for other in schema.values():
        if other.name.lower() == table.name.lower():
            continue
        if not any(k.column == foreign_key.column
                   and k.ref_table == foreign_key.ref_table
                   for k in other.foreign_keys):
            continue
        for policy in other.read_policies:
            if policy.is_unconditional or not policy.using:
                continue
            return other, policy
    return None


def _retarget(predicate: str, old_table: str, new_table: str) -> str:
    """Rewrite a predicate copied from `old_table` to be about `new_table`.

    Policy predicates name their own table — `m.id = messages.match_id` — so
    the reference has to move with the policy. Only qualified occurrences
    (`messages.`) are rewritten: a bare word could be an alias, a column, or
    part of a string, and rewriting those would corrupt SQL that then reaches
    a customer's database.

    Returns "" when the predicate never mentions the source table, since then
    the substitution has not been verified to have done anything and the
    result should not be shipped.
    """
    pattern = re.compile(rf"\b{re.escape(old_table)}\s*\.", re.IGNORECASE)
    if not pattern.search(predicate):
        return ""
    return pattern.sub(f"{new_table}.", predicate)


def _migration(table: Table, predicate: str) -> str:
    """Idempotent, non-destructive SQL.

    `ENABLE ROW LEVEL SECURITY` is a no-op when already on. The policy is
    wrapped in a guard that creates it only when the table has no read policy
    at all, so a deployment that has already been fixed by hand — or that never
    matched the migrations in the first place — is left exactly as it is.
    Nothing here drops or replaces a policy the customer wrote.
    """
    name = f"{table.name}_select_scoped"
    return f"""\
-- Generated by Drydock from this repository's own migrations. Review before
-- applying: it was written without reading your database.
--
-- `{table.name}` is readable by the anonymous key according to the committed
-- schema. The predicate below is copied from a policy this repository already
-- uses for a table scoped the same way, so it follows the authorisation model
-- already in place rather than inventing one.

alter table {table.schema}.{table.name} enable row level security;

do $$
begin
  if not exists (
    select 1 from pg_policies
    where schemaname = '{table.schema}'
      and tablename = '{table.name}'
      and cmd in ('SELECT', 'ALL')
  ) then
    create policy "{name}" on {table.schema}.{table.name}
      for select using ({predicate});
  end if;
end
$$;
"""


def migration_filename(table: str, stamp: str) -> str:
    """Supabase orders migrations by filename, so the timestamp leads."""
    return f"supabase/migrations/{stamp}_enable_rls_{table}.sql"
