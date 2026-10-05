# Repeated findings and submission severity

The repository Luna pilot completed eight requests with valid JSON, but its
18 model findings contained six repeated pairs. The frontend rubric also told
the model to rate a repeatable message submission as critical solely because
it sends a message. That instruction overstates the consequence and confuses
new input with repeating the same operation.

## Changes

Grouping now recognizes these additional bounded source hypotheses:

| Hypothesis | Source binding |
| --- | --- |
| Header-derived authenticated request | Immutable forwarded-host URL binding and authorized fetch |
| Scheduled retry cleanup | Discarded timer with a direct self-retry callback |
| INSERT membership policy | One PostgreSQL INSERT policy and its related table |
| Cascading deletion | One terminal foreign key and its two-hop cascade path |
| Projected database read bound | One literal projected SELECT and its data binding |
| Network rejection cleanup paraphrases | Existing React handler/state/fetch binding, with bounded request-label and ancillary-file handling |

These are claim identities, not proof of vulnerabilities. They require source
hashes and operation locations; nearby lines and similar titles alone cannot
merge findings. Unsupported wording, ambiguous targets, different mechanisms
or incompatible verification statuses remain separate. Every original finding
is retained in `grouped_originals`, including its conditions, provenance,
confidence and severity. The existing representative priority keeps the most
severe original. Grouping does not mark an interpretation as verified.

The frontend rubric now asks whether the same operation can repeat without
new user input. Severity requires a concrete causal chain and consequence;
an endpoint name or missing in-flight flag does not automatically mean
critical. A handler that consumes a draft before awaiting and requires new
content for another submission needs separate evidence of harm.

The existing empty-input source-context check also accepts this description.
When a wide citation is ambiguous, it can use a unique, single-line verbatim
quote inside the original range. It records the original range and selected
quote anchor. This adds context only: no automatic severity downgrade,
finding dismissal or runtime verification.

## Offline verification

The saved eight Luna answers were replayed through the production scan pipeline
against the original source archive, without a provider connection, OSV client
or SQL executor. The archive SHA-256 was
`ce08ee771d21ba4ef87d90824cfa036c85acef1b84fff6926207bc2be979525b`.

The replay groups 18 accepted model findings into 12 rows: all six duplicate
pairs merge. The chat finding gains source context linking the empty-input
guard, clearing the draft before the first await, and the native button's
disabled binding. Its historical severity remains unchanged.

Synthetic regression fixtures cover these boundaries without committing the
customer archive, raw prompts or raw model report. Negative cases exercise
different source operations, compound claims, status disagreement, malformed
identities, ambiguous quotes and source mutation. No target code is executed.

Replaying saved answers tests processing, not how a model follows the new
prompt. A fresh paid evaluation is a separate step. This change does not
switch the production model or prove that Luna has equivalent recall to
Sonnet. The audit engine version changes so new results do not reuse the
previous analysis cache.
