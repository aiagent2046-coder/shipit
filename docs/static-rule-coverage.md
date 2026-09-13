# Bounded source rule coverage

The TLS, unsafe deserialization, outbound URL and path traversal checks record
their actual file coverage in `score.scan_manifest.rule_coverage`. The map uses
the same check names as `static_checks`; each record has `version: 1`.

These records describe each rule's supported source analysis. They do not
measure the coverage of all static rules or establish runtime safety.

- `files_total`: non-directory entries in the submitted archive.
- `excluded_files`: dependency trees, generated build directories, recognized non-production paths and
  unsupported extensions. `exclusion_reasons` records those counts separately.
- `eligible_files`: supported application source before resource limits.
  Oversized application files remain in this denominator.
- `attempted_files`: files for which reading started; the 400-file budget
  applies here.
- `analyzed_files`: files whose supported check finished. A safe negative
  prefilter can complete the check without parsing the file.
- `skipped_files`: eligible files whose check did not finish, including a
  partially analyzed current file. `skip_reasons` records file size, file
  count, finding count, decoding, parsing, syntax or expression-analysis budget
  limits. An expression budget can leave other traces in the same file intact;
  the file still counts as not fully analyzed.
- `partial`: true when any eligible file was not completely analyzed.

The counts satisfy `files_total = eligible_files + excluded_files` and
`eligible_files = analyzed_files + skipped_files`. A finding can come from a
partially analyzed file; its presence does not make that file complete.

The 400-file and 32-finding limits remain in place. Dependencies and build output
are excluded before those budgets. Reaching a limit is shown above the findings in both
HTML and web reports, including when these rules emit no findings. The scan
record contains the per-rule counts and reasons; CLI JSON carries the same
record. SARIF records it in invocation properties as `ruleCoverage`. Unknown
source fields and exception text are excluded from this schema.

Build directories `.next/`, `dist/` and `build/` are recognized as complete path
segments at any depth, including inside a wrapped repository or a workspace.
Their files are recorded as `generated_build`; dependencies take precedence
when a path belongs to both categories. Build files never enter `eligible_files`,
even when oversized or malformed. An archive containing only build output has
zero eligible files, which establishes no coverage of application source.
Names such as `builder/` or `distances/` remain eligible. The session-cookie
check uses the same build exclusion before its file limit; its coverage is
still outside this four-rule measurement.

Secret scanning keeps its existing directory policy, including reading `vendor/`
and `site-packages/`. A committed secret there still matters. Sharing path
categories does not make every scanner exclude the same files.

The RLS recommendation collector and the service-role route check take the same
dependency and build categories before their own limits. MEASURED 2026-09-13:
both read generated output as if the project owned it. The collector walks the
archive in filename order and stops at its 300-file budget, and `.` sorts before
letters, so `web/.next/**` was read before `web/app/**`; with 400 build files it
returned no operations at all and the client-change advice named no target, while
`dist/`/`build/` — which sort after `app/` but before `supabase/` — starved the
migration files instead. The route check matched `.next/server/app/<path>/route.js`,
a compiled copy of a route the project wrote once, and the collapsed row then named
that build artifact as the file holding the key and counted the handler twice.
Vendored paths fired as well once they contained an `app/` segment. Neither check
writes per-rule coverage records; those paths are excluded rather than counted.

These two collectors preserve their previous case-insensitive category matching:
`Vendor/`, `Node_Modules/` and `VENV/` are excluded as well. SQL under those trees
cannot become evidence for the application's policy declarations. The helper
index in the service-role check uses the same policy as its finding loop.

Handler paths need an additional distinction: `app/api/build/route.ts` is the
source of a URL named `/api/build`, while `.next/server/app/api/build/route.js`
is a compiled copy. For conventional Next.js App Router, Pages Router, Nuxt and
SvelteKit (`src/routes`) handlers, the names `build`, `dist`, `vendor` and
`coverage` after the routing root remain eligible. An excluded category before
the routing root still excludes the file; markers such as `.next` and
`node_modules` exclude at any depth. Classification uses the original ZIP path
so stripping a bare `app/` tree as an export wrapper does not lose that context.
This is a path heuristic: custom routing roots and build-directory configuration
are not resolved. The four bounded source checks, cookie check and secret scanner
retain their existing path policies.

Older audits without these measurements show coverage as not recorded. Their
counts are not reconstructed from archive size or another scanner's coverage.
A scan engine version change prevents old cached results from being served as
a newly measured scan.

The scan engine version identifies analysis and cache behavior. Release tags
identify deployed application builds; these are independent version series.
