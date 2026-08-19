"""Tables the repository names, that its migrations never declare.

WHAT THIS IS FOR. A static scan can only judge what the schema describes, so
a table created through the Supabase dashboard is invisible to it -- and the
one table ever found genuinely exposed on the deployment we own, `agent_projects`,
was exactly that. This detector does not find exposure. It finds the GAP: the
tables this repository talks about and its migrations do not, so that the gap
is at least visible to the person who could close it, and so the live probe
(app/proof/rls_probe.py) has names to ask about.

MEASURED 2026-08-19, n=399 repositories drawn from two generators, of which
150 use Supabase and 108 both commit a schema and stay under the reader's cap:

| question                                              | result               |
|-------------------------------------------------------|----------------------|
| commit a schema AND call a table it does not declare  | 50% [41-59] (54/108) |
|   -- Lovable                                          | 51% [38-64] (26/51)  |
|   -- bolt                                             | 49% [37-62] (28/57)  |
| size of the gap                                       | median 3, p90 13, max 67 |
| contain a `.from(variable)`, which names no table     | 72% [63-80]          |
| Supabase repos yielding no literal name at all        | 15% [10-21]          |

An earlier pass over n=40 per stratum put the first number at 62% [46-76];
the full corpus moved it to 50% and the intervals overlap, so the small-sample
figure was the noisier estimate rather than a different world. The wording
below is written against 50%, not 62% -- record at
/home/syndiai/reality-diff-m3.json.

THE 50% IS A FLOOR, NOT A POINT ESTIMATE OF WHAT THIS CODE FINDS. The
measurement dropped bucket-shaped names (`documents`, `files`, `media`, ...)
by NAME; app/scan/table_names.py drops them by CALL SITE, keeping
`supabase.from('documents')` and discarding only
`supabase.storage.from('documents')`. Those are ordinary table names, so this
detector sees a superset of what was counted. Nobody has measured how much
larger, and it is stated here rather than quietly enjoyed.

Independently, #296 measured the generated-types source on a different corpus
(n=226): of 82 repositories carrying both a schema and a types file, 44%
[34-55] have a types file naming a table the SQL does not. The two numbers are
NOT pooled. Different corpora, and a stronger claim on the types side.

TWO SOURCES, TWO CLAIMS, AND THE DIFFERENCE IS THE POINT.

  generated types  `supabase gen types typescript` writes its file FROM THE
                   LIVE PROJECT. A name there is evidence the table EXISTED IN
                   THE DATABASE when the file was generated.

  client code      `supabase.from('x')` is evidence the APPLICATION EXPECTS the
                   table -- nothing more. A call left behind after the table
                   was dropped looks identical to a call against a table
                   created in the dashboard, and this detector cannot tell them
                   apart. So the client-code finding says what the CODE does,
                   never what the DATABASE contains.

SILENT WITH NO SCHEMA, like app/scan/rls.py and for its reason: with nothing
declared there is no drift to measure, only an absence. "Undetermined" is not
"clean", but a finding on every schemaless repository is noise, and the honest
answer for that population is the live probe, which can actually check.
"""

from __future__ import annotations

from typing import BinaryIO

from app.scan.checks import CheckFinding
from app.scan.rls import read_committed_sql
from app.scan.sql_schema import parse_schema
from app.scan.table_names import is_reportable, read_named_tables

RULE_ID = "schema-drift-undeclared-table"

# How many names go in the report before it stops being read. The gap's p90 is
# 13 and its maximum 67; a finding listing 67 tables is a wall, and the point
# of the finding is that somebody acts on it.
_MAX_LISTED = 12

# Views are not missing tables -- they are derived objects a migration may
# legitimately not create with `create table`, and reporting one as an
# undeclared table sends the reader looking for something that was never
# supposed to be there. Leading-underscore names are internal by convention.
_VIEW_SUFFIXES = ("_view", "_viewer")


def _is_missing_table(name: str) -> bool:
    return (is_reportable(name)
            and not name.startswith("_")
            and not name.endswith(_VIEW_SUFFIXES))


def scan_schema_drift(fileobj: BinaryIO) -> list[CheckFinding]:
    """At most one finding: the tables named here that the schema omits."""
    fileobj.seek(0)
    sql, paths = read_committed_sql(fileobj)
    if not sql.strip():
        return []

    schema = parse_schema(sql)
    declared = {
        table.name.lower()
        for table in schema.values()
        if table.schema in ("public", "")
    }
    if not declared:
        return []

    named = read_named_tables(fileobj)
    from_types = {n for n in named.from_types
                  if _is_missing_table(n) and n not in declared}
    from_code = {n for n in named.from_code
                 if _is_missing_table(n) and n not in declared} - from_types
    if not from_types and not from_code:
        return []

    return [CheckFinding(
        rule_id=RULE_ID,
        title="Tables your code uses that your migrations do not describe",
        severity="medium",
        # Below app/scan/rls.py's read rule at 0.6, deliberately. That rule was
        # wrong twice on a real deployment and was lowered for it; this one has
        # never been checked against a database at all. It reports a gap in
        # what the repository documents, which is a fact about the repository
        # and is why the confidence is not lower either.
        confidence=0.6 if from_types else 0.5,
        category="Money & Data",
        file=paths[0] if paths else "",
        explanation=_explain(from_types, from_code, named.has_dynamic_from),
        fix_hint=(
            "Run `supabase db pull` to bring the live schema into a migration, "
            "then check that every table it adds has RLS enabled and a policy. "
            "A table created outside migrations is not reviewed by anything: "
            "not this scan, not a pull request, not your own schema file."
        ),
    )]


def _listed(names: set[str]) -> str:
    shown = sorted(names)[:_MAX_LISTED]
    rest = len(names) - len(shown)
    text = ", ".join(f"`{n}`" for n in shown)
    return f"{text} and {rest} more" if rest else text


def _explain(from_types: set[str], from_code: set[str], dynamic: bool) -> str:
    parts: list[str] = []

    if from_types:
        # The strong claim, and the only one licensed to speak about the
        # database: `supabase gen types typescript` reads the live project.
        parts.append(
            f"Your generated Supabase types name {_listed(from_types)}, which "
            "no migration in this repository creates. That file is generated "
            "from the live project, so these tables were in your database when "
            "it was written -- they exist outside your migrations, which means "
            "no review, no code review and no static scan has ever looked at "
            "their access rules."
        )

    if from_code:
        # The weak claim. It describes the CODE. It must not be read as a
        # statement about the database, because a stale call to a dropped
        # table produces exactly this evidence.
        parts.append(
            f"Your code queries {_listed(from_code)}, and no migration in this "
            "repository creates them. This says what your application expects, "
            "not what your database contains: the same evidence appears if the "
            "table was created in the Supabase dashboard, and if it was dropped "
            "and the call left behind. Either way the table is outside the "
            "schema that gets reviewed."
        )

    caveat = (
        "This list is the tables named literally in your repository. Calls "
        "built from a variable name no table, so a table can be missing from "
        "this list and still be missing from your migrations"
    )
    parts.append(f"{caveat} -- this repository contains such calls."
                 if dynamic else f"{caveat}.")
    return " ".join(parts)
