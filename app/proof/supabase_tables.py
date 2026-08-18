"""Which tables a probe should ask about, and in what order.

MEASURED 2026-08-18, and it is why this file exists rather than one request.
PostgREST serves an OpenAPI document at the project root that lists every
table the caller may reach — the obvious way to close the blind spot, since it
needs no schema at all. Supabase refuses it to the anon key:

    HTTP 401 {"message": "Invalid API key",
              "hint": "Only the `service_role` API key can be used for this
                       endpoint."}

The only credential that could enumerate is exactly the one we refuse to send
anywhere (see app/proof/supabase_target.py). So the names have to come from
the repository, and this module is where they come from.

TWO SOURCES, AND THE SECOND IS THE POINT. Committed migrations name tables for
the 68% of Supabase repos that commit any — measured across three strata in
SUPABASE_RLS_YIELD_PLAN.md. For the rest, static analysis is silent by
construction, and that is the population the probe exists for. But a client
that talks to Supabase must NAME its tables to use them:

    supabase.from('profiles').select('*')

Client code is always committed, whether or not the schema is, so it answers
exactly where the migrations do not.

WHAT THIS CANNOT SEE, stated because the probe's wording depends on it: a
table nothing queries. Client code names the tables the application touches,
which is a subset — and, being the subset someone wrote code against, the one
likeliest to hold real rows. A table forgotten in the dashboard stays invisible
here, and no ordering trick recovers it.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass
from typing import BinaryIO

from app.scan.rls import private_shape, read_committed_sql
from app.scan.secrets import _iter_text_files
from app.scan.sql_schema import parse_schema

# `.from('table')` / `.from("table")`, the one call every supabase-js read goes
# through. Deliberately narrow: `.from(` with a variable inside is not a name
# we can resolve, and guessing one would put an invented string into a URL
# aimed at a customer's database.
_FROM_CALL = re.compile(r"\.from\(\s*[\"'`]([a-z_][a-z0-9_]{0,62})[\"'`]\s*\)",
                        re.IGNORECASE)

# The name is interpolated into a request path. rls_probe validates it too;
# validating here as well means a bad name is refused where its origin is still
# known, rather than deep in a request builder.
_TABLE_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$", re.IGNORECASE)

_SOURCE_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte",
                ".py", ".dart", ".kt", ".swift")

# PostgREST reaches these on its own; they are not the customer's tables and
# probing them says nothing about their data.
_NOT_THEIRS = frozenset({
    "rpc", "graphql", "schema_migrations", "supabase_migrations",
})


@dataclass(frozen=True)
class TableCandidate:
    name: str
    source: str          # "migrations" | "client-code" | "both"
    private_shape: str    # "yes" | "uncertain" | "no" — why it is ordered here


def find_probe_tables(fileobj: BinaryIO) -> list[TableCandidate]:
    """Candidate tables, most worth asking about first.

    ORDER IS LOAD-BEARING because the caller caps the number of requests it
    will make against somebody else's project. An arbitrary cap over an
    arbitrary order checks whatever happened to sort first; ordering by whether
    the table LOOKS private puts the requests where an answer would matter.
    The shape heuristic is the read detector's own (app/scan/rls.private_shape)
    rather than a second opinion about the same table names.
    """
    fileobj.seek(0)
    sql, _ = read_committed_sql(fileobj)
    schema = parse_schema(sql) if sql.strip() else {}
    from_sql = {
        table.name.lower(): table
        for table in schema.values()
        if table.schema in ("public", "")
    }

    fileobj.seek(0)
    from_code: set[str] = set()
    with zipfile.ZipFile(fileobj) as zf:
        for name, text in _iter_text_files(zf):
            if not name.lower().endswith(_SOURCE_EXTS):
                continue
            for match in _FROM_CALL.finditer(text):
                from_code.add(match.group(1).lower())

    candidates: list[TableCandidate] = []
    for name in sorted(set(from_sql) | from_code):
        if name in _NOT_THEIRS or not _TABLE_NAME.fullmatch(name):
            continue
        table = from_sql.get(name)
        if table is not None and name in from_code:
            source = "both"
        elif table is not None:
            source = "migrations"
        else:
            source = "client-code"
        # A table known only from client code has no columns to judge, so the
        # shape heuristic sees the name alone. That is weaker evidence, and it
        # is recorded rather than hidden: "uncertain" here means we do not
        # know, not that the table is fine.
        verdict, _why = private_shape(
            name,
            table.columns if table is not None else [],
            any(k.target == "auth.users" for k in table.foreign_keys)
            if table is not None else False,
        )
        candidates.append(TableCandidate(name, source, verdict))

    rank = {"yes": 0, "uncertain": 1, "no": 2}
    return sorted(candidates, key=lambda c: (rank[c.private_shape], c.name))
