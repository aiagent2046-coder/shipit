"""Where a repository names its tables, other than in its migrations.

MOVED HERE, NOT WRITTEN HERE. Every matcher below came out of
app/proof/supabase_tables.py unchanged; that module now imports them. The move
has one reason: a second consumer appeared (app/scan/schema_drift.py), and
this repository has already paid once for the alternative. From
SUPABASE_RLS_YIELD_PLAN.md, about its own measurement script: "The script
carried its own copy of the matcher and drifted from production within the
hour." One matcher, one place, both readers.

TWO SOURCES, AND THEY ARE NOT EQUALLY STRONG. That difference is the whole
reason they are kept apart rather than merged into one set of names:

  client code      `supabase.from('profiles')` proves the APPLICATION EXPECTS
                   the table. It does not prove the table is there. A call left
                   behind after the table was dropped looks exactly the same.

  generated types  A type-shaped declaration names an expected table. This
                   matcher cannot establish which project generated it, or
                   whether it was generated at all. Copied, handwritten and
                   stale declarations have the same shape.

Anything built on top must keep them apart in what it tells a customer, since
one supports a claim about their database and the other does not.

WHAT NEITHER SEES: a table nothing queries and no generated file names. And
because the client matcher takes only literal strings, a `.from(tableName)`
yields nothing at all -- so the extracted list is "tables named literally in
this repository", never "this project's tables".
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from typing import BinaryIO

from app.scan.secrets import _iter_text_files, is_non_production_path

# `.from('table')` / `.from("table")`, the one call every supabase-js read goes
# through. Deliberately narrow: `.from(` with a variable inside is not a name
# we can resolve, and guessing one would put an invented string into a URL
# aimed at a customer's database.
#
# The lookbehind excludes `supabase.storage.from('avatars')`, which is the
# identical call shape against a STORAGE BUCKET. A bucket is not a table:
# probing one says nothing about the customer's rows, and reporting one as a
# missing table is a false claim about their data. Excluded by CALL SITE
# rather than by a list of bucket-ish names, because `documents` and `files`
# are perfectly ordinary table names and a name list would drop the real ones.
_FROM_CALL = re.compile(
    r"(?<!storage)\.from\(\s*[\"'`]([a-z_][a-z0-9_]{0,62})[\"'`]\s*\)",
    re.IGNORECASE)

# A name is interpolated into request paths and into report text. Validating it
# where its origin is still known beats validating it deep in a request builder.
_TABLE_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$", re.IGNORECASE)

# `.from(...)` is not valid Python syntax (`from` is a keyword). Matches
# inside Python files are quoted examples, including this scanner's own
# docstrings, not calls. Python client's `.table(...)` needs its own parser.
_SOURCE_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte",
                ".dart", ".kt", ".swift")

# Every table entry in a generated types file is an identifier whose object
# opens with `Row:`. Matched on that shape rather than on the file's name,
# because the name is a convention and the shape is what the generator emits.
_TYPES_TABLE = re.compile(r"(\w+):\s*\{\s*Row:")

# `Tables: {` scopes the match to the table map. Without it, `Row:` inside
# Insert/Update/Relationships blocks would be matched too -- and, worse, any
# hand-written interface that happens to contain a `Row` field.
_TYPES_MARKER = "Tables: {"

# PostgREST reaches these on its own; they are not the customer's tables and
# reporting them says nothing about their data.
_NOT_THEIRS = frozenset({
    "rpc", "graphql", "schema_migrations", "supabase_migrations",
})

# `.from(` with a non-literal argument. The receiver is captured because
# `.from(` is not a Supabase idiom: `Array.from(new Set(x))` is in half the
# JavaScript ever written, and counting it would make this flag meaningless.
_DYNAMIC_FROM = re.compile(r"([A-Za-z_$][\w$]*)\s*\.from\(\s*(?![\"'`])[A-Za-z_$]")

_NOT_QUERY_BUILDERS = frozenset({
    "array", "object", "buffer", "date", "string", "number", "map", "set",
    "promise", "uint8array", "int8array", "float32array", "json",
})


@dataclass
class NamedTables:
    from_code: set[str] = field(default_factory=set)
    from_types: set[str] = field(default_factory=set)
    # True when a `.from(variable)` was seen. It STRENGTHENS a disclosure that
    # is made either way -- it never gates it. The receiver filter above is a
    # heuristic, and a caller that only disclosed incompleteness when this flag
    # was set would be letting a regex decide whether to claim completeness.
    has_dynamic_from: bool = False


_FROM_IDENT = re.compile(r"\.from\(\s*([A-Za-z_$][\w$]*)\s*\)")
_STRING_BINDING = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
    r"(\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`)"
)


def _resolve_from_idents(text: str) -> str:
    """`.from(tableName)` where the name is an unambiguous local string binding.

    The client matcher takes only literal strings (see above): a `.from(name)`
    names no table to a regex. But a name whose ONLY assignment is a string
    literal one line up is knowable from the file alone -- reading it is
    reading, not guessing. MEASURED: hoisting the literal into a local
    silenced the schema-drift variant of the metamorphic probe. Names with
    zero or several assignments, and template literals with substitutions,
    are left exactly as they were (the dynamic-from floor stays)."""
    counts = {}
    bindings = {}
    for match in _STRING_BINDING.finditer(text):
        name, token = match.group(1), match.group(2)
        counts[name] = counts.get(name, 0) + 1
        if "\\" not in token and "${" not in token:
            bindings[name] = token

    def substitute(match):
        name = match.group(1)
        if counts.get(name) != 1 or name not in bindings:
            return match.group(0)
        return f".from({bindings[name]})"
    return _FROM_IDENT.sub(substitute, text)


def read_named_tables(fileobj: BinaryIO) -> NamedTables:
    """Table names the repository's own code and generated types mention.

    Migrations are NOT read here; that is `app.scan.rls.read_committed_sql`
    plus `app.scan.sql_schema.parse_schema`, and callers combine the two.
    """
    fileobj.seek(0)
    found = NamedTables()
    with zipfile.ZipFile(fileobj) as zf:
        for name, text in _iter_text_files(zf):
            if (not name.lower().endswith(_SOURCE_EXTS)
                    or is_non_production_path(name)):
                continue
            text = _resolve_from_idents(text)
            for match in _FROM_CALL.finditer(text):
                found.from_code.add(match.group(1).lower())
            if _TYPES_MARKER in text:
                for match in _TYPES_TABLE.finditer(text):
                    found.from_types.add(match.group(1).lower())
            if not found.has_dynamic_from:
                for match in _DYNAMIC_FROM.finditer(text):
                    if match.group(1).lower() not in _NOT_QUERY_BUILDERS:
                        found.has_dynamic_from = True
                        break
    return found


def is_reportable(name: str) -> bool:
    """Is this a name worth putting in front of a customer as their table?"""
    return name not in _NOT_THEIRS and bool(_TABLE_NAME.fullmatch(name))
