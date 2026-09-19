# JavaScript SQL source review

Ordinary browser, local and server static scans now pass existing JavaScript/
TypeScript SQL findings through three bounded workers, without an extra command:

1. **Detector** binds the finding's file and line to the archive and file SHA-256.
2. **Researcher** parses the source and examines the query expression. It resolves
   literal fragments, one stable const binding, and a same-file module-local,
   single-return function invoked with literal arguments. Conditional query
   expressions require both arms to be fixed. Unsupported construction remains
   unresolved.
3. **Verifier** checks the typed evidence and source binding, then stores a
   conclusion with hash-linked handoff receipts. Saved reports rebuild those
   receipts before accepting them. Hashes check consistency, not authenticity.

Results appear under **JavaScript SQL source review** in the browser, web report,
offline HTML and JSON (`security_agent.js_sql_review`). Existing Python catalog
observations are separate. This adds source investigation, not a new detector.

- `fixed_sql_fragments`: the query text is made from fixed fragments within this
  bounded analysis. This does not establish SQL semantics, database driver
  identity, authorization, runtime behavior or whole-project safety.
- `dynamic_sql_unresolved`: the construction is still unresolved. This does not
  establish attacker control or an exploitable injection.
- `unavailable`: the source could not be analyzed within the supported scope.

Presence of a second call argument is reported separately; it never proves
correct parameter binding and cannot make an interpolated value safe.
No original finding, severity or score is removed or reduced by this release.
No project code, model, database, helper function or saved task is executed.

## Limits

At most 32 candidates, 400 KB per source, 8 MB aggregate source work, 80,000 AST
nodes per analysis, depth 160 and expression depth 24. Receipts contain at most
32 fragment references and no copied source snippets. Duplicate archive paths,
changed source, parser errors and multiple sinks on one reported line cannot
produce a fixed-fragment conclusion. Detector coverage gaps remain visible.

The helper rule excludes async/generators, default/rest/destructured parameters,
nested or shadowed declarations, nonliteral arguments, calls inside the return,
parameter mutation and dynamic lexical environments. Cross-file builders,
mutable arrays of fragments, sanitizers and database-derived identifiers are
unresolved. The rule does not infer parameterization from a function's name.

## Cumora control

Using archive
`dce64bacef7ffcc5f801d50447f035bd67ec14829a97a79401bb0d0a397e226d`,
all 12 existing SQL findings receive a source review. Three calls in
`server/src/agents/cli.ts` (4795, 4932, 4995) resolve to fixed fragments through
`cliCalendarVisibilityClause(3)` at line 4589. The other nine remain unresolved.
The five source files skipped by the SQL detector are still a coverage gap.
The archive and customer source are not shipped in this repository.

This is a measured reduction in uncertainty for three warnings, not three
proven-safe queries or newly confirmed vulnerabilities.
