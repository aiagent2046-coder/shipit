# Local report usefulness: Axios and Flask

This pilot compares the source engine at
`f74b23055919fc5d49bd0de252059c25f72423c9` (`2026-09-16-1`) with the
report-usefulness changes (`2026-09-16-2`). It evaluates report usefulness,
not the complete vulnerability set or production safety of either project.

## Reproducible inputs

| Input | Revision |
| --- | --- |
| axios/axios | `ba0f3a0c568e68de5e7d455ae8c566ed43525550` |
| pallets/flask | `d73fa1cdcbd8b1465c151db8924ba58b1dd14e35` |
| Bundled catalog SHA-256 | `b7797220f5cfa16e139be51e5bc17b55c3364e4e7fb820b20ea086b252053dae` |

Both engines scanned clean checkouts with the same catalog and Python 3.12.14,
PyYAML 6.0.3, tree-sitter 0.26.0, tree-sitter-typescript 0.23.2 and pglast 8.4.
During scanning, socket connections and subprocess creation were blocked.
No target dependencies were installed and no target code was executed.
Each engine used a separate private state directory. Text output was rendered
from the same JSON result, without performing another scan.

To repeat after obtaining these revisions, run from each engine checkout:

```bash
python -m app.local_cli --state-dir /absolute/new/private-state \
  scan /absolute/pinned-project --json > report.json
```

The command uses the bundled catalog unless the chosen state already contains
an update. Fresh state directories prevent that difference. The scan itself is
offline; obtaining source and installing the scanner are separate preparation.

## Observed changes

| Observation | Before | After |
| --- | --- | --- |
| Axios total findings | 49 | 49 |
| Axios dependency matches | 7 advisories across 5 packages | Same 7 matches; 5 grouped tasks, all explicitly development |
| Axios other findings | Mixed into the first 20 rows | 42 contextual findings counted separately, expandable |
| Flask total findings | 11 | 8 |
| Flask RLS candidates | 2 critical writes and 1 high read for SQLite tutorial | 0; no Supabase schema context exists |
| Flask dependency task | cryptography 49.0.0 without scope | Same match; development, direct, group `typing` |
| Flask other findings | Mixed rows, including unclassified test dotenv | 1 ignore-coverage review and 6 contextual findings |
| Unknown-source explanation | Unknown plus unaffected called a conflict | Incomplete sources, distinct from opposing verdicts |
| Excluded manifests | Documentation/example/test exclusions silent | Reasons and bounded omission counts visible |

Dependency assessment counts remained identical:

| Project | Affected | Unaffected | Unknown | Entries outside catalog |
| --- | ---: | ---: | ---: | ---: |
| Axios | 7 | 198 | 11 | 593 |
| Flask | 1 | 115 | 4 | 61 |

Affected/unaffected/unknown are advisory assessment counts, not package counts.
Both scans completed with zero unavailable checks and exit 0 under the default
`--fail-on none`; dependency coverage was still partial. Exit 0 is not a safety
verdict. No inference about deployed reachability was added.

## Why the changes are supported

Flask's `examples/tutorial/flaskr/schema.sql` contains SQLite AUTOINCREMENT
tables; `examples/tutorial/flaskr/db.py` uses sqlite3. Treating those tables as
accessible through a Supabase anonymous key was a platform applicability error.
Explicit Supabase histories still produce findings in positive fixtures, while
independent applications no longer share table policy state. Paths now retain
the `examples/` prefix, and findings refer to their table declaration.

Flask's uv root places cryptography in `typing`, outside the main runtime
dependencies. Axios's affected pins carry npm `dev: true`. These facts describe
lockfile ownership; they do not establish that development dependencies are
harmless. All matching advisories remain in JSON and severity gates.

The four Flask documentation/docstring assignments keep their rule IDs and
context but no longer claim to be SQL/PLpgSQL. The noncredential dotenv fixture
is explicitly contextual. Credential-like dotenv values remain critical even
under test paths. Grouping is presentation only: it does not discard findings,
rewrite history, or bypass `--fail-on`.

## Remaining limits

RLS scope covers conventional `supabase/migrations/**`, `supabase/schemas/**`
and `supabase/schema.sql`. Custom layouts and generic PostgREST deployments are
outside this check; no finding there is not proof of authorization safety.
Dependency scope remains unknown when graph provenance is ambiguous, a budget
is exceeded, or a supported scope model is unavailable (including pnpm).
The catalog still has unknown assessments and unlisted dependencies. Advisory
links and ranges support investigation, not a universally safe upgrade version.
