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
`static+partial`, keeping them out of the full-audit cache slot. The truncation
flag is a token-accounting heuristic, so the notice describes possible
truncation, not an independently confirmed provider action.

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

## Claim evidence contract (engine 2026-09-06-5)

New findings carry `claim_evidence.version: 1` in the existing finding JSON.
It survives persistence, model deduplication and report rendering without a
database migration. Fields separate what the scanner checked from the model's
interpretation:

- `source_check`: the scanner records `quote_match` with the actual source
  window, or `static_rule` when a static rule emitted the observation. Quote
  matching retains the existing two-line tolerance around the cited range.
  A match can be in a comment or literal; it does not establish semantics.
- `observation`: the model's reading of the code, explicitly unverified. It
  is not promoted to a verified fact by a matching quote.
- `required_conditions`: conditions proposed by the model, with
  `conditions_status: not_checked`. Absent, empty or malformed conditions
  remain unknown. They never mean the conditions have been met.
- `consequence_status: not_checked`: no independent consequence verifier has
  run. Repeated model passes cannot change this status.

The scanner constructs this record. Nested evidence/status fields supplied
by the model are ignored. The record does not copy the raw evidence excerpt,
which may contain a credential. Conditions are not silently truncated.
Existing model prose fields (`title`, `explanation`, `fix_hint`) remain for
compatibility; the new fields are additive. The usual JSON response token cap
still applies. No new LLM calls, execution of uploaded code, or live probes are
introduced by the contract.

The web page and HTML export show model conditions before suggested fixes.
Static evidence details can be expanded. Older findings have no retrospective
quote check: both renderers say that the check and conditions were not recorded.
Potential impact remains distinct from evidence strength; severity is still
the producer's estimate, not a validated risk measurement.

Prompt guidance now requests separate observations and conditions, conditional
consequences and verification before fixes. The money rubric requires concrete
inputs for rounding claims and inspection of constraints/recovery before
claiming duplicate grants or permanent loss. It no longer mandates severity
from a missing local guard or invents a year of growth to estimate a hosting
bill. These instructions improve the requested output; they do not guarantee
the correctness of a live model response.

Next: bounded verifiers for specific claim mechanisms, followed by a project
coverage map and interpretation from collected evidence. This contract alone
does not automatically refute public-URL, operator-access or rounding claims,
and the model still receives selected source excerpts.

## Operation context before model review (engine 2026-09-07-2)

The static source index now includes `source_facts.operations` for both free
and paid audits. It records Python calls spelled `subprocess.run`, `call`,
`check_output` or `Popen`, JS/TS calls spelled `fetch`, and Python f-string
expressions shaped as `float(...):.2f`. Records contain file/line, enclosing
function, argument AST shapes, and up to eight same-file caller spellings.
Python records also list earlier direct assignments of the first argument
and up to four preceding top-level if statements containing return/raise.

This is a navigation index, **not** source-to-sink verification. It does not
resolve imports, aliases, reassignment, shadowing or cross-file calls. An
earlier if/return does not prove that a guard dominates a sink or is effective.
Caller arguments are not automatically classified as trusted/untrusted.
`fetch` alone does not establish server execution or SSRF; passing SQL to an
executor alone does not establish SQL injection. No severity or automatic fix
is assigned by this index, and model hypotheses are not silently dismissed.

Source literals are omitted. Numeric records run only four fixed public
examples (490.00, 990.00, 990.07, 333.33) through our built-in float/.2f
expression and record binary exactness separately from formatted output.
They do not evaluate uploaded code, prove the binding of `float`, inspect live
prices, or establish correctness for other values. They are counterexamples
to a universal claim that binary inexactness necessarily changes cents.

The collector parses at most 250 files, 256 KB per file and 8 MB total; it
keeps at most 64 records. Tests, vendor files and symlinks are excluded;
duplicate archive names are ambiguous. Parse failures and budget limits are
reported. Records reach the HTML/web scan record and the existing bounded
model context; prompt truncation is marked in the context, not hidden as a
complete index. Fetch wrappers and subprocess stdin contexts precede numeric
examples and routine tool calls when only a prefix fits. No new model request
is added. The engine bump invalidates
old cache entries; preview history still requires matching engine versions.

Retained preview records now preserve the visible test/example classification.

### Isolated payment observations

The notification tests inject a fault between job creation and payment completion
and overlap concurrent callbacks. The retry must recover with one live job.
YooKassa callbacks now serialize the payment-status read, grant and notification
scheduling with a PostgreSQL transaction-scoped advisory lock. Waiting callbacks
release their pooled connection; a timeout returns HTTP 503 for a retry, never an
unlocked grant. Provider verification happens before the lock and notification
transport still runs after answering. The former strict expected failure is now
a passing regression, with a real-Postgres test using eight concurrent callbacks
and a separate timeout/cancellation test. Provider and message transports are
mocked; no real charge or external message is sent by these tests.

This prevents duplicate scheduling by concurrent YooKassa callbacks. It is not a
durable delivery outbox: a crash after payment completion but before sending can
still lose a notification, and independent operator notification paths are not
serialized by this handler lock. No exactly-once delivery guarantee is claimed.

`JOB_COST_CAP_USD` defaults to 13.00; invalid, nonfinite and nonpositive values
fail both runtime import and production preflight (exit 78). The standalone
preflight remains stdlib-only and reads the specified environment file alone.
The cap is an estimate checked after each model response, so one call can exceed
it. This change does not assert that production was misconfigured.

## Bounded syntax checks (engine 2026-09-07-1)

`claim_evidence.syntax_check` records a scanner-owned result for three narrow
premises. An English title pattern selects the check; it is not the evidence.
Unknown phrasing, other languages and unsupported mechanisms remain
`not_checked`. The fields supplied by the model cannot set this result.

- `react_hook_order`: Tree-sitter parses the complete TypeScript/JSX file.
  For a named component or hook with resolved React imports and direct hook
  statements/initializers, compare calls with returns in that function.
  Nested functions, comments and literals cannot supply its returns. All
  resolved calls before every return contradict the selected premise; a
  direct call after a simple top-level conditional return observes the
  syntax pattern. Custom hooks, indirect aliases, shadowed imports, complex
  control flow and ambiguous locations may remain unknown. React `use` is
  not treated as an order-constrained hook. No renders are executed.
- `sql_update_where`: pglast parses PostgreSQL SQL and binds the cited range
  to one top-level UPDATE. Its own `whereClause` determines presence, not a
  WHERE in a comment, string, CTE, subquery or neighbouring statement.
  Procedural/dynamic SQL, multiple possible UPDATE targets and syntax outside
  this PostgreSQL parser remain unknown. `WHERE true` still has a WHERE; the
  check says nothing about selectivity, intent, authorization or safety.

- `python_completed_notification` (engine 2026-09-07-3): Python AST checks a
  narrowly phrased claim such as "Completed invoice still calls notify_operator".
  In one undecorated module-level function, a top-level completed-status branch
  with an immediate side-effect-free return before every direct notify_operator
  call contradicts that control-flow premise. Nested scopes, cleanup paths,
  decorators, indirect calls and compound claims remain unknown. The displayed
  result specifies the checked branch and does not establish runtime bindings,
  callees' effects, concurrency safety or delivery. The previous broad claim
  about both state writes and notifications is deliberately not dismissed by
  this single-premise check. It appears beside supported findings through the
  existing scanner-owned syntax_check field; no LLM call is added.

All checks read strict UTF-8 from the uploaded archive, with a 256,000-byte file
limit, a 2,000,000-byte aggregate parsing budget and at most 40 selected
checks per audit. Budget exhaustion is recorded as `not_checked`. Source
files are never executed, imported as application code or sent to another
LLM. Parsers and grammars are pinned in both dependency locks.

`observed` means the syntax premise was seen, not that its claimed harm was
verified. Conditions and consequences remain `not_checked`. `contradicted`
means only the displayed syntax premise was contradicted. Those model rows
are retained in storage and in a separate section of both reports, excluded
from unresolved counts and legacy score penalties. Original model advice is
retained as collapsed historical wording. Deduplication cannot merge claims
with differing syntax-check results at the same line. Old audits are not
reinterpreted and have no invented check result.

This is post-processing of model hypotheses, not yet a whole-project syntax
inventory or the planned LLM-only-final-interpretation architecture. It adds
no model calls and does not verify production behaviour. Tests cover the
actual RlsCheck and migration 0035 false claims plus synthetic positive,
negative, ambiguous, malformed, Unicode and budget-limit cases.

## Fix Pack JavaScript/TypeScript syntax gate

Before emitting a secret edit, the planner parses the complete changed file:
JS/JSX/MJS/CJS with the JavaScript grammar, TS with TypeScript, and TSX with
TSX. Both an error node and a missing token cause rejection, even when
Tree-sitter recovered a tree. Files above 256,000 UTF-8 bytes are excluded
from these edits, with a syntax/limit reason in the skipped findings. Other
valid file edits can still be delivered; the rejected file contributes no
successful secret fix or new environment placeholder.

This gate runs locally without LLM calls, executing project code, or reading
production data. It checks syntax only, not types, runtime behaviour or the
meaning of a replacement. Unsupported grammar features can therefore lead
to a skipped edit. Python/JSON parsing and other languages' existing
delimiter checks remain unchanged. A clean parse does not replace the
separate build and verification gates.

## Preserving the free preview in a paid report

Full-depth audit requests also look up the most recent completed
`static+preview` record with the identical content digest and audit engine
version. The URL alone is never sufficient. Older-engine previews and
static-only rows (which do not identify a free model preview) are not
automatically associated. No engine bump is needed: this adds historical
context without changing scanners, prompts, findings or scoring.

`score_json.preview_history` stores the source preview id, content digest,
engine, recorded model, observation counts and original findings that are
not byte-for-byte equivalent as JSON objects to current findings. Object
key ordering does not matter. The preview's access token is never copied.
Exact duplicates are represented by `matched_count`; differences in wording,
evidence, severity, advice or grouped occurrences remain visible as history.

The web page and downloaded HTML render this history separately. Original
evidence and advice survive, but advice is collapsed and historical rows
have no current severity badge. `not_reassessed` means no new assessment was
made of those records: absence in a paid model response is neither a fix nor
an independent contradiction. History does not affect current counts,
coverage, legacy numeric scores or automatic fix eligibility. The current
findings and their evidence remain unchanged, including any independently
recorded syntax contradiction; differing records are not heuristically merged.

Paid workers (including partial/failed model scans), repository deep reviews
and paid intake cache hits share this behaviour. A cached paid analysis can
be enriched without model calls: a new audit snapshot receives a new access
token and `analysis_reused_from` identifies the original analysis. Model
coverage still describes that analysis, not a new run. Original rows stay
unchanged; subsequent cache hits reuse the enriched snapshot. Free cache
lookups remain at free depth and never import paid findings. Reports created
before this change remain unchanged until a new paid request creates an
enriched snapshot. No migration or additional LLM budget is required.


## Function evidence before model review (engine 2026-09-07-4)

`source_facts.functions` indexes module-level Python functions and direct class
methods from full files (512 KB/file, 8 MB total, 300 files, 4,000 functions).
It retains at most 64 evidence records and four cross-file candidates per record.
The collector runs for both free and paid scans before any model response, with
no uploaded code execution and no additional model calls. It also runs when no
supported English finding title is ever produced.

Supported observations are deliberately narrow: SQL lexer tokens in literal
`execute` arguments, direct return comparisons, and the existing completed-status
immediate return premise. SQL comments and string contents cannot supply lock
function names. `WHERE` is only a token observation, not proof of ownership,
selectivity, atomicity or effective authorization. Dynamic SQL is outside scope.

Cross-file matching uses function/method name spelling in the bounded index;
up to three matches are retained as candidates with the match count. More common
names are skipped with ambiguous_name_matches, to avoid presenting arbitrary
repository methods as the implementation of dictionary/environment get calls. These are not
resolved Python bindings. Protocols, wrappers, aliases, inheritance and runtime
objects can make a candidate inapplicable. Missing candidates never establish
missing protection. Source literals are not copied into this inventory.

Callers receive candidate locations, end lines and target observations, including
method bodies beyond the LLM's per-file prefix. Write/lock candidates are preferred
within each record. Return comparisons linked to database reads, completed-status
returns and callers of UPDATE/lock functions get prompt priority. The function
inventory gets at most half of the existing 16,000-character facts prompt; no
prompt budget or model call count is increased. Both inventory and prompt limits
are recorded, and prompt trimming never mutates the stored complete inventory.

The HTML and web scan record display these observations and candidate limitations.
They do not create scored findings, mark model claims verified or rewrite history.
Title-selected syntax counterevidence continues separately for supported claims.

Fixed numeric examples now record input decimal, formatted decimal, amount_changed
and difference_decimal. For 990.07 the result is 990.07, false, 0.00. Binary float
representation error is not used as evidence of changed cents. These are our four
public examples, not tests of uploaded expressions, production prices or all
possible inputs. They are attached automatically to supported float(...):.2f syntax.

## Included free-model report and premise context (engine 2026-09-07-5)

Full-depth worker and repository audits now include `score.free_baseline`: the
complete findings and score/coverage snapshot of the free-model stage, including
observations identical to paid findings. Existing `preview_history` keeps its
prior unmatched-history semantics. No access token is copied into either field.
The web report and HTML export show the baseline separately, without adding its
findings to paid counts, scores or automatic fix eligibility.

A completed preview with identical archive content and engine is reused. When
none exists, one pass using FREE_TIER_MODEL / FREE_TIER_MODEL_BY_KIND and
FREE_TIER_RUBRICS runs inside the full-depth request, after its paid analysis.
It does not use the anonymous quota or anonymous daily-spend gate. This costs
an additional free-model stage only when no reusable baseline exists; the label
"free" describes the product tier, not zero provider cost. Each model's tokens
are recorded separately under the audit job, before report persistence.

The included stage receives the remaining JOB_COST_CAP_USD budget, rather than
a new full budget. This remains a post-response cost estimate: one response can
overshoot, just as in the paid stage. No providers or no remaining budget is
explicitly `unavailable`; provider failure/partial review preserves available
findings and scope as `incomplete`. Failed baseline attempts are not silently
retried on every paid cache hit. Cached full audits lacking a baseline complete
that stage in the worker and produce a new snapshot; old reports are not edited.

Function evidence now skips bare builtin names as cross-file method candidates
(shadowing remains unresolved). Literal UPDATE queries carry a bounded expression
shape for their own WHERE, preserving AND/OR, columns and positional parameters.
Values are redacted except the fixed status labels pending/completed; parameter
bindings and affected rows are not established. A subquery WHERE cannot stand
in for an absent outer UPDATE WHERE.

Supported numeric findings receive adjacent checks of the public examples they
mention, only when the cited source includes float(...):.2f. Unchanged cents are
not proof that arbitrary inputs are safe, nor a reason to suppress a compound
finding. A Python template containing BEGIN, a psql include placeholder and
COMMIT supplies transaction context beside migration claims, explicitly without
claiming the include target, runner binding or runtime execution was verified.
These checks use no model calls and do not execute uploaded source.
