"""Tables the repository names, that its migrations never declare.

WHAT THIS IS FOR. A static scan can only judge what the schema describes, so
a table created through the Supabase dashboard is invisible to it -- and the
one table ever found genuinely exposed on the deployment we own, `agent_projects`,
was exactly that. This detector does not find exposure. It finds the GAP: the
tables this repository talks about and its migrations do not, so that the gap
is at least visible to the person who could close it, and so the live probe
(app/proof/rls_probe.py) has names to ask about.

AND IT WOULD NOT HAVE FOUND `agent_projects` EITHER. Checked, 2026-08-20: the
string appears nowhere in that repository's archive -- not in the migrations,
not in a `.from()` call, not in a generated types file. This detector reports
tables the repository NAMES; a table nothing names is outside it by
construction, and that is the very table that motivated the module.

So the boundary is narrower than the paragraph above may read. What this
closes is "the code talks about a table the schema does not", which is a real
and common gap (61% below). What it does NOT close is "a table exists in the
database and the repository is silent about it" -- only the live probe can
reach that, and only with the owner's consent and their key. Saying which of
the two a reader is getting is the whole reason this paragraph exists.

MEASURED 2026-08-19 by scripts/measure_schema_drift.py, which runs THIS
detector -- not a copy of its rules -- over 540 candidate repositories in three
strata. 225 use Supabase, 152 of those commit a schema:

| question                                              | result               |
|-------------------------------------------------------|----------------------|
| commit a schema AND name a table it does not declare  | 61% [53-69] (93/152) |
|   -- Lovable                                          | 62% [48-74] (31/50)  |
|   -- bolt                                             | 54% [41-66] (30/56)  |
|   -- no generator marker (control)                    | 70% [55-81] (32/46)  |
| size of the gap                                       | median 3, p25 1, p90 33 |
| commit no schema at all -- invisible to any static scan | 32% (73/225)       |
| carry a generated types file, among those with a schema | 54% (82/152)       |
| contain a `.from(variable)`, which names no table      | 29% [23-35]         |

TWO EARLIER PASSES GOT THIS WRONG IN BOTH DIRECTIONS, and the corrections are
recorded because each one was a real defect and not a rounding:

  62% [46-76]  n=40 per stratum, ad-hoc script. Small sample.
  50% [41-59]  n=108, two strata, ad-hoc script. LOWER because that script
               dropped bucket-shaped names (`documents`, `files`, `media`) BY
               NAME, discarding real tables along with the buckets. This code
               drops them by CALL SITE, so it sees more -- and the 50% was
               written into this docstring as a floor, which is what it was.
  61% [53-69]  n=152, three strata, THIS detector. The control stratum, absent
               from the 50%, is the highest of the three at 70%.

The control being highest matters: the gap is not an artefact of one code
generator. Hand-written Supabase projects drift MORE, and by a wider margin
(median 8 tables against Lovable's 3).

THE DYNAMIC-CALL NUMBER WAS OVERSTATED THREEFOLD, and the fix is in the
measurement rather than the wording. The earlier script's regex counted every
`.from(` with a non-literal argument, so `Array.from(new Set(x))` -- in half
the JavaScript ever written -- was scored as a Supabase call this detector
could not resolve. That produced 63-72%. Filtering by receiver gives 29%
[23-35]. The disclosure in the finding is still unconditional, because 29% of
repositories is not a rare case, and because a detector that admits
incompleteness only when a regex tells it to is claiming completeness the rest
of the time.

Record: batch_reports/schema_drift.json, one row per repository pinned to the
SHA that was read.

Independently, #296 measured the generated-types source on an overlapping
corpus (n=226): of 82 repositories carrying both a schema and a types file, 44%
[34-55] have a types file naming a table the SQL does not. Consistent with the
82/152 counted here.

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

# How many names go in the report before it stops being read. MEASURED: the
# gap's p90 is 33 tables and one repository drifts by 200. A finding listing
# 200 tables is a wall, and the point of a finding is that somebody acts on it.
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
        # Security, NOT "Money & Data". compute_scores(llm_ran=False) excludes
        # LLM_ONLY_CATEGORIES from the mean and app/db.py lists them as
        # `unexamined`, so a static finding filed there would not move the
        # score AND would print under a heading saying nobody looked. The free
        # tier is static-only and is the only thing most visitors ever see.
        # app/scan/rls.py files under Security for the same reason.
        category="Security",
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


def _them(names: set[str]) -> tuple[str, str]:
    """(pronoun, verb) agreeing with the count.

    MEASURED: p25 of the gap is 1 table, so the singular is the common case
    rather than an edge one -- "queries `todos` ... creates them" is what half
    the reports would have said. Customer-facing text that does not agree with
    itself reads as carelessness about the very report it asks them to trust.
    """
    return ("it", "was") if len(names) == 1 else ("them", "were")


def _explain(from_types: set[str], from_code: set[str], dynamic: bool) -> str:
    parts: list[str] = []

    if from_types:
        # The strong claim, and the only one licensed to speak about the
        # database: `supabase gen types typescript` reads the live project.
        pronoun, was = _them(from_types)
        plural = "these tables" if len(from_types) > 1 else "this table"
        parts.append(
            f"Your generated Supabase types name {_listed(from_types)}, which "
            f"no migration in this repository creates. That file is generated "
            f"from the live project, so {plural} {was} in your database when "
            f"it was written -- {pronoun} exists outside your migrations, "
            f"which means no review, no pull request and no static scan has "
            f"ever looked at the access rules."
        )

    if from_code:
        # The weak claim. It describes the CODE. It must not be read as a
        # statement about the database, because a stale call to a dropped
        # table produces exactly this evidence.
        pronoun, _ = _them(from_code)
        parts.append(
            f"Your code queries {_listed(from_code)}, and no migration in this "
            f"repository creates {pronoun}. This says what your application "
            f"expects, not what your database contains: the same evidence "
            f"appears if the table was created in the Supabase dashboard, and "
            f"if it was dropped and the call left behind. Either way the table "
            f"is outside the schema that gets reviewed."
        )

    caveat = (
        "This list is the tables named literally in your repository. Calls "
        "built from a variable name no table, so a table can be missing from "
        "this list and still be missing from your migrations"
    )
    parts.append(f"{caveat} -- this repository contains such calls."
                 if dynamic else f"{caveat}.")
    return " ".join(parts)
