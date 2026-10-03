# SQL table claims independent of title phrasing

The October 3 Kristina report (archive SHA-256
`7c19ee818a3cbc4a4fec73c040afc807be847e18460266c43dbbc8c08d877d88`, engine
`2026-10-02-2`) retained six table-interpolation hypotheses separately. The model
used “SQL query” instead of “SQL string”, so full-title matching bypassed both
source grouping and literal-list narrative correction.

## Contract

A model may now supply an optional `operation_claim` selector with exactly
`kind`, `target`, `line_start`, and `line_end`. The supported kind is
`sql_table_interpolation`; the target is the interpolated local variable.
The selector is untrusted routing metadata and carries no verification status.

The scanner still requires one unambiguous cited Python database call containing
one plain table identifier in a supported SELECT f-string. It checks the target
against the AST slot and the selector range against both the finding range and
call. Identities remain keyed by file content hash, operation span and slot span.
An invalid selector does not fall back to title matching. Additional premises,
recognized competing risks, ambiguous calls and unsupported SQL remain separate.

When a valid selector is present, title wording is not a routing key. The
selector is retained in original claim evidence for grouping/replay. Legacy
responses without a selector use a conservative vocabulary-based title adapter;
unknown wording is left ungrouped, not assumed safe. This adapter is not a
universal natural-language classifier. A model must still separate independent
causes; syntactic binding does not establish that its narrative is correct.

Literal-only loop observations still use the existing source traversal and
mutation/alias restrictions. A grouped external-value interpolation remains
unverified and receives no literal-source projection. No new safety verdict or
severity downgrade is introduced; repeated source-operation hypotheses count
once, with all original assumptions and consequences retained.

## Regression evidence

`python_sql_review_paraphrases.json` preserves the six SQL narratives from the
uploaded October 3 report, with original report references. The test remaps source
coordinates to the existing minimized SQL fixtures and supplies their exact source
quotes; it does not represent a fresh model call or full live audit.

Coverage includes six-to-three grouping with literal-list projections, title
paraphrases (including Russian) with explicit selectors, serialization/replay,
invalid targets and ranges, malformed selectors, independent claims, multiple
calls, unsupported SQL and external table lists. Existing SQL identity,
counterevidence and dedup regressions are retained.

Engine version: `2026-10-03-1`. The separate generic-secret false positive in the
PDF wrapping test is outside this change.
