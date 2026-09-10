# React network-cleanup observation identity

Two model passes can describe the same skipped state reset in different words.
Exact observation matching then leaves two report rows and two score penalties
for one source operation. This change recognizes a bounded subset of those
repeated observations without discarding either interpretation.

## Supported identity

The source collector identifies one React state/setter binding, its enclosing
component and handler, and one directly awaited standard `fetch` between the
raised flag and its reset. File SHA-256 and AST byte spans bind the identity to
the submitted source; the resolver checks the hash against its archive.

A deliberately closed English grammar selects the network-rejection cleanup
claim. It accepts supported paraphrases of the raised flag, rejected request,
skipped reset and disabled control. It does not provide general semantic
matching. Unrecognized or compound prose, another state or UI operation,
ambiguous bindings and unsupported control flow remain separate.

Transport rejection remains distinct from an HTTP error response. A pending
HTTP check request about the same handler is omitted only from the comparison
projection for this narrow identity. The complete original check remains in
stored evidence. Actual HTTP check results, other targets and incompatible
verification or evidence dispositions still prevent grouping.

The identity does not establish an absent guard or prove the claimed UI
consequence. Existing verification statuses and scoring policy remain in force.
Every original observation and its provenance is retained in the group, and
running grouping again is idempotent. The new collector metadata is excluded
from model prompts.

## Verification

The targeted gate passed **358 tests**, including **98 new synthetic cases**.
These cover accepted paraphrases, source mutations, multiple operations and
states, HTTP/JSON/concurrency claims, compound prose, foreign UI labels, literal
grammar-role injection, forged model metadata, incompatible evidence,
malformed saved identities and stale source facts. Repository-wide Ruff passed.
An independent review's concrete counterexamples are included in regression
coverage.

A local replay reconstructed source quotes and citation end positions for
accepted observations from a saved audit. This is not a byte-for-byte replay of
provider responses. It used no real model calls. The private report and source
are not included in this repository; public tests are synthetic.

| Saved-replay measure | Before | After |
| --- | ---: | ---: |
| Pro displayed findings | 49 | 45 |
| Pro Frontend score | 3.8 | 5.1 |
| Pro total | 5.0 | 5.1 |
| Free displayed findings | 12 | 12 |
| Free total | 8.8 | 8.8 |

All 53 accepted model observations and all 59 originals including static
findings survive the replay. Four pairs gain a shared network-cleanup identity;
unrelated categories retain their scores. These numbers describe this saved
input, not a promised count for a future model run.

The audit engine changes to `2026-09-09-1` to prevent old cached grouping from
standing in for new results. Historical Free baselines are not rewritten.
