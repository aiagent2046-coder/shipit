"""Read the RLS-relevant facts out of committed Postgres migrations.

Written for the Fix Pack's policy generator (app/fixpack/rls_policy.py).

scripts/measure_supabase_rls_yield.py still carries its own reader, built
first and layered with the measurement's PII heuristics. So there are two, and
that is the shape of the failure worth naming: two SQL readers drifting apart
is how a measurement and a fix end up disagreeing about the same schema, with
the disagreement surfacing in a customer's pull request.

Until they converge, tests/test_sql_schema_agreement.py holds them to the same
verdicts on the same SQL. A drift test is not as good as one reader; it is
cheaper than destabilising a measurement tool whose numbers are already
recorded, and it fails loudly if either side moves.

NOT A SQL PARSER. It reads Supabase migrations — a narrow, largely generated
dialect — and answers four questions: which tables exist, what they reference,
which have RLS enabled, and what their policies actually say. Anything it
cannot read it reports as absent, never as safe.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_CREATE_TABLE = re.compile(
    r"create\s+table\s+(?P<ine>if\s+not\s+exists\s+)?"
    r'(?:"?(?P<schema>[a-z0-9_]+)"?\s*\.\s*)?"?(?P<name>[a-z0-9_]+)"?\s*\('
    r"(?P<body>.*?)\)\s*;",
    re.IGNORECASE | re.DOTALL,
)

# `ALTER TABLE [IF EXISTS] [ONLY] name ENABLE ROW LEVEL SECURITY`. The optional
# clauses are not decoration: omitting IF EXISTS made every table protected
# that way read as "RLS never enabled", a false exposure in the direction that
# invents findings about a customer's data.
_ENABLE_RLS = re.compile(
    r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?"
    r'(?:"?(?:[a-z0-9_]+)"?\s*\.\s*)?"?(?P<name>[a-z0-9_]+)"?\s+'
    r"enable\s+row\s+level\s+security",
    re.IGNORECASE,
)

# The mirror of _ENABLE_RLS. Without it a table switched off again reads as
# protected — the quiet direction of this error, but still a wrong answer about
# a customer's data.
_DISABLE_RLS = re.compile(
    r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?"
    r'(?:"?(?:[a-z0-9_]+)"?\s*\.\s*)?"?(?P<name>[a-z0-9_]+)"?\s+'
    r"disable\s+row\s+level\s+security",
    re.IGNORECASE,
)

_CREATE_POLICY = re.compile(
    r"create\s+policy\s+(?P<pname>\"[^\"]+\"|'[^']+'|[a-z0-9_]+)\s+on\s+"
    r'(?:"?(?:[a-z0-9_]+)"?\s*\.\s*)?"?(?P<table>[a-z0-9_]+)"?'
    r"(?P<rest>.*?);",
    re.IGNORECASE | re.DOTALL,
)

# MEASURED 2026-08-18, and the reason parse_schema stopped reading statements
# in three independent passes. A real repository's migrations contained
#
#   CREATE POLICY "Allow public to insert KYC documents" ON kyc_documents
#     FOR INSERT TO anon, authenticated WITH CHECK (true);
#
# and, four migrations later, the developer's own fix:
#
#   DROP POLICY IF EXISTS "Allow public to insert KYC documents" ON …;
#
# A reader that knows only CREATE reported the hole its owner had already
# closed — a KYC document table, named in a file inside a directory called
# `archive`. That is the most expensive shape of wrong this product has: not a
# guess that missed, but a confident accusation contradicted by the customer's
# own commit.
_DROP_POLICY = re.compile(
    r"drop\s+policy\s+(?:if\s+exists\s+)?"
    r"(?P<pname>\"[^\"]+\"|'[^']+'|[a-z0-9_]+)\s+on\s+"
    r'(?:"?(?:[a-z0-9_]+)"?\s*\.\s*)?"?(?P<table>[a-z0-9_]+)"?',
    re.IGNORECASE,
)

_FOR_CLAUSE = re.compile(r"\bfor\s+(select|insert|update|delete|all)\b",
                         re.IGNORECASE)
_TO_CLAUSE = re.compile(r"\bto\s+([a-z0-9_,\s\"]+?)(?=\busing\b|\bwith\b|$)",
                        re.IGNORECASE)
_REFERENCES = re.compile(
    r"references\s+(?:\"?(?P<schema>[a-z0-9_]+)\"?\s*\.\s*)?"
    r"\"?(?P<table>[a-z0-9_]+)\"?\s*(?:\(\s*\"?(?P<column>[a-z0-9_]+)\"?\s*\))?",
    re.IGNORECASE,
)


_DOLLAR_TAG = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$")


def _strip_comments(sql: str) -> str:
    """Blank out `--` and `/* */`, replacing them with spaces of equal length.

    MEASURED 2026-08-18. A repository's exported SQL carried the header

        -- CREATE TABLE STATEMENT (generated)

    and the reader produced a table called `statement`. Worse than the phantom:
    the comment's `(` opened a body that ran on until the next `);`, swallowing
    the real CREATE TABLE that followed, so a table the customer actually has
    disappeared from the schema.

    It goes wrong in both directions, which is why this is not cosmetic. A
    commented-out `-- alter table t enable row level security;` counted as
    protection — a real hole we would never report. A commented-out
    `/* create policy p … using (true); */` counted as a hole — a finding
    about a line the developer had already disabled.

    Lengths are preserved because parse_schema orders statements by their
    offset in this text, and shortening it would reorder the migration chain.

    Quoting rules followed: `''` doubling inside single-quoted strings, and
    dollar-quoted bodies passed over whole. Backslash is NOT treated as an
    escape — Postgres ships `standard_conforming_strings = on`, so `'C:\\'` is
    a complete string, and reading the backslash as an escape would run the
    scanner past the closing quote and into live SQL.

    Dollar-quoted bodies are left INTACT rather than skipped. Supabase
    migrations routinely wrap real policies in `DO $$ … END $$;`, and dropping
    those would hide protection that exists — the expensive direction.
    """
    out = list(sql)
    index, end = 0, len(sql)
    while index < end:
        char = sql[index]
        if char == "'":
            index += 1
            while index < end:
                if sql[index] == "'":
                    if index + 1 < end and sql[index + 1] == "'":
                        index += 2
                        continue
                    index += 1
                    break
                index += 1
            continue
        if char == '"':
            index += 1
            while index < end and sql[index] != '"':
                index += 1
            index += 1
            continue
        if char == "$":
            tag = _DOLLAR_TAG.match(sql, index)
            if tag:
                closing = sql.find(tag.group(0), tag.end())
                index = end if closing < 0 else closing + len(tag.group(0))
                continue
        if sql.startswith("--", index):
            stop = sql.find("\n", index)
            stop = end if stop < 0 else stop
            out[index:stop] = " " * (stop - index)
            index = stop
            continue
        if sql.startswith("/*", index):
            depth, cursor = 1, index + 2
            while cursor < end and depth:
                if sql.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif sql.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            for position in range(index, min(cursor, end)):
                if out[position] != "\n":
                    out[position] = " "
            index = cursor
            continue
        index += 1
    return "".join(out)


def _is_constant_true(clause: str) -> bool:
    """An empty clause counts: a policy that constrains nothing constrains
    nothing, and Postgres treats the absent half as permissive."""
    if not clause:
        return True
    return bool(re.fullmatch(r"true|1\s*=\s*1|\(\s*true\s*\)",
                             clause.strip(), re.IGNORECASE))


@dataclass(frozen=True)
class ForeignKey:
    column: str
    ref_schema: str
    ref_table: str
    ref_column: str

    @property
    def target(self) -> str:
        return f"{self.ref_schema}.{self.ref_table}"


@dataclass(frozen=True)
class Policy:
    name: str
    table: str
    command: str                 # select | insert | update | delete | all
    roles: frozenset[str]        # empty means the SQL said nothing, i.e. PUBLIC
    using: str                   # raw predicate, whitespace-normalised
    with_check: str

    @property
    def applies_to_read(self) -> bool:
        return self.command in ("select", "all")

    @property
    def reaches_anon(self) -> bool:
        """No TO clause means PUBLIC, which includes anon."""
        return not self.roles or bool(self.roles & {"public", "anon"})

    def applies_to(self, command: str) -> bool:
        return self.command in (command, "all")

    def opens(self, command: str) -> bool:
        """Does this policy let anon perform `command` on any row?

        WHICH CLAUSE MATTERS DEPENDS ON THE COMMAND, and getting that wrong
        reads a locked table as open or the reverse:

          insert -> WITH CHECK decides what a new row may look like; USING is
                    not consulted at all, so a FOR INSERT policy is judged on
                    WITH CHECK alone.
          update -> USING selects WHICH rows may be touched. That is the half
                    that decides whether anon can rewrite somebody ELSE's row,
                    which is the harm.
          delete -> USING, same reason.

        A FOR ALL policy with only USING applies that expression to WITH CHECK
        too, which is why the insert branch falls back to it.
        """
        if not self.reaches_anon or not self.applies_to(command):
            return False
        if command == "insert":
            clause = self.with_check or self.using
        else:
            clause = self.using
        return _is_constant_true(clause)

    @property
    def is_unconditional(self) -> bool:
        """`USING (true)` and friends — RLS switched on and wide open.

        A missing USING on a read-applicable policy counts too: a FOR ALL
        policy carrying only WITH CHECK constrains writes and leaves reads
        unqualified.
        """
        return _is_constant_true(self.using)


@dataclass
class Table:
    name: str
    schema: str = "public"
    columns: list[str] = field(default_factory=list)
    foreign_keys: list[ForeignKey] = field(default_factory=list)
    rls_enabled: bool = False
    policies: list[Policy] = field(default_factory=list)

    @property
    def qualified(self) -> str:
        return f"{self.schema}.{self.name}"

    @property
    def read_policies(self) -> list[Policy]:
        return [p for p in self.policies if p.applies_to_read]

    def anon_can_write(self) -> tuple[frozenset[str], str]:
        """Which of insert/update/delete the anonymous role can perform.

        Supabase grants all three to `anon` on a public-schema table by
        default, so with RLS off every one of them is live. Measured on a real
        project: the table an anon key could read was also one it could
        UPDATE, TRUNCATE and DELETE, and nothing in the audit said so.

        RLS on with no write policy is default-deny, exactly as for reads.
        """
        if self.schema not in ("public", ""):
            return frozenset(), f"schema `{self.schema}` is not exposed"
        if not self.rls_enabled:
            return frozenset({"insert", "update", "delete"}), "RLS never enabled"
        open_commands = {
            command
            for command in ("insert", "update", "delete")
            for policy in self.policies
            if policy.opens(command)
        }
        if not open_commands:
            return frozenset(), "RLS on, no unconditional write policy"
        return frozenset(open_commands), "permissive write policy"

    @property
    def anon_can_read(self) -> tuple[bool, str]:
        """Can the anonymous role read this table, per the committed SQL?

        RLS off  -> yes, everything.
        RLS on   -> only via a read policy that reaches anon and is
                    unconditional. RLS on with no read policy is default-deny,
                    which is the most common CORRECT configuration and must not
                    be counted as a hole.
        """
        if self.schema not in ("public", ""):
            return False, f"schema `{self.schema}` is not exposed by PostgREST"
        if not self.rls_enabled:
            return True, "RLS never enabled"
        for policy in self.read_policies:
            if policy.reaches_anon and policy.is_unconditional:
                return True, f"permissive policy {policy.name!r}"
        if not self.read_policies:
            return False, "RLS on, no read policy (default deny)"
        return False, "RLS on with a predicated read policy"


def parse_schema(sql: str) -> dict[str, Table]:
    """Tables keyed by lowercased name, with RLS state and policies attached.

    STATEMENTS ARE APPLIED IN THE ORDER THEY APPEAR, which is the whole point.
    Three independent passes — every CREATE TABLE, then every ENABLE, then
    every CREATE POLICY — cannot express a policy being dropped, and a
    migration chain is a sequence of edits rather than a description. The
    caller concatenates files in path order, so for `supabase/migrations/`
    (timestamp-prefixed by convention) text order is migration order.

    It is still not a replay: `sql` is whatever SQL the repository committed,
    which may include drafts and one-off scripts alongside the chain. Reading
    it in order is strictly closer to the truth than reading it as a set, and
    where it cannot be sure the answer must land on "not a finding" — see
    _CREATE_TABLE handling below.
    """
    sql = _strip_comments(sql)
    tables: dict[str, Table] = {}
    events: list[tuple[int, str, re.Match[str]]] = []
    for kind, pattern in (
        ("create_table", _CREATE_TABLE),
        ("enable", _ENABLE_RLS),
        ("disable", _DISABLE_RLS),
        ("create_policy", _CREATE_POLICY),
        ("drop_policy", _DROP_POLICY),
    ):
        events.extend((m.start(), kind, m) for m in pattern.finditer(sql))
    events.sort(key=lambda e: e[0])

    for _, kind, match in events:
        if kind == "create_table":
            _apply_create_table(tables, match)
            continue
        table = tables.get(match.group("name" if kind in ("enable", "disable")
                                      else "table").lower())
        if table is None:
            continue
        if kind == "enable":
            table.rls_enabled = True
        elif kind == "disable":
            table.rls_enabled = False
        elif kind == "create_policy":
            table.policies.append(
                _policy(match.group("pname"), table.name, match.group("rest")))
        else:
            _drop_policy(table, match.group("pname"))

    return tables


def _apply_create_table(tables: dict[str, Table], match: re.Match[str]) -> None:
    """What a REPEATED CREATE TABLE means, which is two different things.

    `CREATE TABLE IF NOT EXISTS` is an idempotent migration whose entire
    purpose is to do nothing when the table is already there. Treating it as a
    fresh declaration threw away the RLS and the policies established earlier
    in the chain, and the table then read as "RLS never enabled" — an exposure
    fabricated by a no-op. So it MERGES: new columns and keys, existing
    protection untouched.

    A plain `CREATE TABLE` repeated is different. Postgres rejects that against
    a live table, so in committed SQL it means the declaration starts over —
    in practice a pg_dump or a squashed baseline restating the whole schema.
    MEASURED: one repository keeps 258 superseded migrations beside a dumped
    baseline, and merging the two left the baseline carrying permissive
    policies from 2025 that it exists to replace. So it RESETS, and everything
    the archive said about that table stops applying at that line.
    """
    name = match.group("name")
    body = match.group("body")
    existing = tables.get(name.lower())
    if existing is None or not match.group("ine"):
        tables[name.lower()] = Table(
            name=name,
            schema=(match.group("schema") or "public").lower(),
            columns=_columns(body),
            foreign_keys=_foreign_keys(body),
        )
        return
    for column in _columns(body):
        if column not in existing.columns:
            existing.columns.append(column)
    known = {(k.column, k.target) for k in existing.foreign_keys}
    for key in _foreign_keys(body):
        if (key.column, key.target) not in known:
            existing.foreign_keys.append(key)


def _drop_policy(table: Table, raw_name: str) -> None:
    """Remove every policy of that name, comparing case-insensitively.

    Postgres treats a quoted identifier as case-sensitive, so this can drop
    slightly more than the database would. That direction is deliberate: an
    over-eager drop makes a table look MORE protected and costs us a finding,
    while an under-eager one reports a hole the customer already closed.
    """
    wanted = raw_name.strip('"').strip("'").lower()
    table.policies[:] = [p for p in table.policies if p.name.lower() != wanted]


def _policy(raw_name: str, table: str, rest: str) -> Policy:
    for_match = _FOR_CLAUSE.search(rest)
    to_match = _TO_CLAUSE.search(rest)
    roles = frozenset()
    if to_match:
        roles = frozenset(
            r.strip().strip('"').lower()
            for r in to_match.group(1).split(",") if r.strip()
        )
    return Policy(
        name=raw_name.strip('"').strip("'"),
        table=table,
        command=(for_match.group(1).lower() if for_match else "all"),
        roles=roles,
        using=_balanced_clause(rest, "using"),
        with_check=_balanced_clause(rest, "with check"),
    )


def _balanced_clause(rest: str, keyword: str) -> str:
    """The text inside `<keyword> ( … )`, matched by counting parentheses.

    A regex cannot do this. Real policies nest — `EXISTS (SELECT 1 FROM
    matches m WHERE ((m.id = messages.match_id) AND (…)))` — and a
    non-greedy `\\((.*?)\\)` stops at the first close paren, returning
    `SELECT 1 FROM matches m WHERE ((m.id = messages.match_id`. That truncated
    text would then be copied verbatim into a policy the Fix Pack proposes to
    a customer.
    """
    lowered = rest.lower()
    start = lowered.find(keyword)
    if start < 0:
        return ""
    index = rest.find("(", start + len(keyword))
    if index < 0:
        return ""
    depth = 0
    for position in range(index, len(rest)):
        char = rest[position]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return " ".join(rest[index + 1:position].split())
    return ""


def _columns(body: str) -> list[str]:
    """Column names from a CREATE TABLE body, skipping table-level
    constraints — they start with a keyword, not an identifier."""
    out: list[str] = []
    skip = {"primary", "foreign", "unique", "check", "constraint", "exclude",
            "like", "partition"}
    for raw in _split_top_level(body):
        token = raw.strip().split()
        if not token:
            continue
        name = token[0].strip('"').strip("`")
        if name.lower() in skip or not re.fullmatch(r"[a-z0-9_]+", name, re.I):
            continue
        out.append(name)
    return out


def _foreign_keys(body: str) -> list[ForeignKey]:
    """Column-level `REFERENCES other(id)` declarations.

    Table-level `FOREIGN KEY (a) REFERENCES b(c)` is deliberately not read: the
    generator uses foreign keys to find a table whose scoping matches a
    sibling's, and a wrong guess there proposes the wrong policy. Reading only
    the unambiguous form keeps the inference honest and lets the rest fall
    through to a refusal.
    """
    out: list[ForeignKey] = []
    for raw in _split_top_level(body):
        token = raw.strip().split()
        if not token:
            continue
        column = token[0].strip('"')
        if not re.fullmatch(r"[a-z0-9_]+", column, re.I):
            continue
        if column.lower() in {"primary", "foreign", "unique", "check",
                              "constraint"}:
            continue
        match = _REFERENCES.search(raw)
        if match:
            out.append(ForeignKey(
                column=column,
                ref_schema=(match.group("schema") or "public").lower(),
                ref_table=match.group("table").lower(),
                ref_column=(match.group("column") or "id").lower(),
            ))
    return out


def _split_top_level(body: str) -> list[str]:
    """Split on commas that are not inside parentheses, so `numeric(10, 2)`
    stays one item."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for char in body:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if char == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts
