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
    r"create\s+table\s+(?:if\s+not\s+exists\s+)?"
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

_CREATE_POLICY = re.compile(
    r"create\s+policy\s+(?P<pname>\"[^\"]+\"|'[^']+'|[a-z0-9_]+)\s+on\s+"
    r'(?:"?(?:[a-z0-9_]+)"?\s*\.\s*)?"?(?P<table>[a-z0-9_]+)"?'
    r"(?P<rest>.*?);",
    re.IGNORECASE | re.DOTALL,
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

    @property
    def is_unconditional(self) -> bool:
        """`USING (true)` and friends — RLS switched on and wide open.

        A missing USING on a read-applicable policy counts too: a FOR ALL
        policy carrying only WITH CHECK constrains writes and leaves reads
        unqualified.
        """
        if not self.using:
            return True
        return bool(re.fullmatch(r"true|1\s*=\s*1|\(\s*true\s*\)",
                                 self.using.strip(), re.IGNORECASE))


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
    """Tables keyed by lowercased name, with RLS state and policies attached."""
    tables: dict[str, Table] = {}

    for match in _CREATE_TABLE.finditer(sql):
        body = match.group("body")
        name = match.group("name")
        tables[name.lower()] = Table(
            name=name,
            schema=(match.group("schema") or "public").lower(),
            columns=_columns(body),
            foreign_keys=_foreign_keys(body),
        )

    for match in _ENABLE_RLS.finditer(sql):
        table = tables.get(match.group("name").lower())
        if table:
            table.rls_enabled = True

    for match in _CREATE_POLICY.finditer(sql):
        table = tables.get(match.group("table").lower())
        if not table:
            continue
        table.policies.append(
            _policy(match.group("pname"), table.name, match.group("rest")))

    return tables


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
