# Bounded source rule coverage

The TLS, unsafe deserialization, outbound URL and path traversal checks record
their actual file coverage in `score.scan_manifest.rule_coverage`. The map uses
the same check names as `static_checks`; each record has `version: 1`.

These records describe each rule's supported source analysis. They do not
measure the coverage of all static rules or establish runtime safety.

- `files_total`: non-directory entries in the submitted archive.
- `excluded_files`: dependency trees, recognized non-production paths and
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

The 400-file and 32-finding limits remain in place. Dependencies are excluded
before those budgets. Reaching a limit is shown above the findings in both
HTML and web reports, including when these rules emit no findings. The scan
record contains the per-rule counts and reasons; CLI JSON carries the same
record. SARIF records it in invocation properties as `ruleCoverage`. Unknown
source fields and exception text are excluded from this schema.

Older audits without these measurements show coverage as not recorded. Their
counts are not reconstructed from archive size or another scanner's coverage.
A scan engine version change prevents old cached results from being served as
a newly measured scan.
