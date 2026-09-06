# Audit evidence contract

The free and paid HTML reports and web result page use the same standard of
evidence. No current source scan independently confirms a finding's runtime
consequence. Severity is potential impact, not proof or a launch verdict.

## Stored findings

- `source`: `static`, `llm`, or `unknown`.
- `verification_status`: currently `unverified`.
- `verification_method`: `source_pattern`, `model_review`, or `not_run`.
- Existing rule ID, source path, line, masked match and explanation remain
  available. Do not persist raw credentials as additional evidence.

The producer sets these fields. The model cannot supply its own confirmation.
Repeated model passes and high confidence do not change verification status.
Older findings with no provenance are displayed conservatively; an `llm-`
rule identifies a model hypothesis, while other legacy records have no
recorded verification. There is deliberately no confirmed-result producer yet.

Numeric score fields remain in JSON for compatibility with existing consumers
and internal measurements. New scores carry `readiness_score_validated: false`.
They are not shown as readiness grades or category verdicts in the result page,
demo or HTML export. Missing validation metadata in old records is not consent
to publish a score.

## Scope

Coverage distinguishes partial source checks, skipped categories, categories
whose findings were filed elsewhere, and missing historical coverage metadata.
It does not claim runtime verification or inspect the live deployment.
An empty finding list does not establish safety.

Nested smoke and example applications are excluded from discovery of the main
React application's error boundaries. Table extraction excludes test/example
paths and Python files: `.from(...)` cannot be a Python call, so those matches
were quoted examples from tests and the scanner itself. Python `.table(...)`
analysis is not implemented by this matcher.

Test/example classification is a source-path heuristic, not deployment proof.
Secrets in these files remain reported. A real credential in a fixture still
requires action; the scanner does not attempt to use it against a provider.

## Regression baseline

`tests/data/audit_truthfulness_cases.json` records six reviewed claims from the
free and paid Drydock reports of commit `28bb61dc8e1064dadb8418858e92333f263959dd`.
The review verdicts are specific to that revision and the described mechanism.
They are not a claim that those components have no other defects.

This file is a calibration set, not a production title blacklist. The current
LLM can still emit a mistaken hypothesis. Regression tests ensure it is not
promoted to confirmation; they do not measure the accuracy of a live model.
Scanner tests separately pair corrected false positives with true positives:
the main app without a boundary and a real call to an undeclared table still
produce findings. Fixture credentials also remain visible.

The next stage is independent, isolated verification of payment replay,
concurrent delivery, crash recovery and user isolation using synthetic data.
Those capabilities are not part of this change.

## Execution limits and source facts (engine 2026-09-06-4)

The headline severity summary counts source observations, excluding the
separately listed tests and examples. Display-only RLS groups carry each
member's original severity, so grouping cannot change the totals.

Both the web page and HTML export show a notice above the findings when model
review was unavailable or limited. Provider billing failures describe the
audit service, not a defect in the submitted project. Missing historical
execution records remain unknown. Cost-cap and input-truncation results use
`static+partial`, keeping them out of the full-audit cache slot.

`scan_manifest.source_facts` is a first, deliberately narrow fact index. It
records Python AST calls whose spelling matches a module-level import of
`hmac.compare_digest` or `secrets.compare_digest`, with import/call locations
and lexical scope. It does not resolve shadowing or imports at runtime, prove
which branch executes, or validate the operands. It never imports or executes
uploaded code, extracts it to disk, or makes a network request. Source string
literals are not included in the index. Tests/vendor files are excluded.

Collection is capped at 500 attempted files, 512 KB per file, 8 MB total and
64 facts; parse failures and exhausted limits are recorded. Free and paid
audits use the same collector. A bounded index is supplied to existing model
requests (at most 16,000 characters and one fifth of the request budget), so
helpers outside the selected source excerpts can be located. This adds no
model calls, but is not a claim that token costs have decreased. The index
itself may be shortened for the prompt; file submission counts still describe
source excerpts, not index entries. Missing facts never establish absence of
protection, and facts do not automatically suppress or confirm findings.

The September 6 regression cases exercise Drydock's own comparison-helper
location, React state across URL changes, the quoted 990.00/990.07 price
examples and the quoted dot-segment ZIP path, using synthetic inputs. These
tests are not general-purpose verifiers for arbitrary customer applications.
Giving the model only findings and evidence for final interpretation remains
a later architectural step; it still reviews selected source excerpts today.
