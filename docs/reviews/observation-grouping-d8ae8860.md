# Repeated observations in audit d8ae8860

## Evidence and scope

Offline review of the saved paid report: 53 accepted model observations,
44 displayed model cards after nine merges. The HTML includes full serialized
Finding payloads for 16 observations in seven existing groups; singleton cards
expose rendered fields, not complete original payloads or raw model responses.
No model calls were made during this review.

The inspected source archive is ai-co-founder-matching commit
`87553a7ab6fcbd2815a2678d6887c0c00ef66829`, SHA-256
`ce08ee771d21ba4ef87d90824cfa036c85acef1b84fff6926207bc2be979525b`.

## Implemented: pagination title variants

Cards 21 and 37 describe the messages GET SELECT at lines 55–59:

- `GET messages endpoint fetches all messages for a match with no pagination limit`
- `Messages GET fetches all messages for a match with no row limit`

Neither previously matched the bounded title grammar. Both now select the
existing `select_pagination_bound` claim scope. The shared subject grammar is
also used to reject unsupported compound titles before legacy mechanism
selection. Source parsing, table hash, unique SELECT selection, quote overlap,
claim screening and verification-status compatibility remain required.

Using the rendered title, observation, conditions and citation against the
exact archive resolves both to byte span `[2392, 2514]` in
`app/api/messages/route.ts`, source SHA-256
`6089194d75e4039898e1964a40a5f7a344e3f08a0d6f92b8cf4ce493b408f1d0`.
This is a partial-input resolver check, not a full replay of those singleton
Findings: missing explanation, fix and evidence fields cannot be inferred.
Consequently this review does not claim a measured new total for all 44 cards.

Synthetic regression tests cover both actual title variants, original-payload
preservation, severity selection without confidence inflation, replay stability,
compound rejection, and rejection of bounded, count-only or ambiguous queries.
The 16 complete saved originals still produce seven groups, retain all 16
originals, and are unchanged by a second deduplication pass.

## Other candidates and boundaries

| Cards | Evidence / next investigation |
| --- | --- |
| 5, 12 | Same service-role source identity, but different `source_assessments`: card 5 requires narrative review of a future identity/filter change; card 12 does not. The distinction is not caused merely by high versus medium severity. Keep separate. |
| 22, 42 | Single network rejection versus a compound network/non-ok HTTP claim. Keep separate; HTTP failure and rejected fetch are distinct. |
| 23, 43; 24, 44; 25, 45 | Similar state-cleanup narratives, but later observations also mention authentication-token acquisition failure. Need operation-specific claim review before expanding network grouping. |
| 27, 48 | Potential repeated-entry hypothesis in onboarding `finish`. Requires a bounded handler/state/control identity; a common line is insufficient. |
| 14, 16, 32; 17, 33 | Auto-reply scheduling candidates require compatible operation identities, conditions and source-review results. Do not infer concurrency outcomes from matching locations. |
| 26, 47 | Non-2xx conditions but a conflicting success-response title. Preserve that disagreement. |
| 15, 34, 35 | Poll/retry and model-version metadata lookup are separate operations; no broad function-level grouping. |

Generic exact-observation matching remains strict when source identity is
unresolved. Grouping does not establish exploitability, verify consequences,
or make repeated model observations independent confirmation. Full singleton
Finding JSON is needed to measure the report-wide change without reconstruction.

Engine version advances to `2026-10-05-3` because grouping can change cached
audit output. Existing saved reports are not rewritten by this code change.

## Follow-up with the full stored JSON

The full database export subsequently supplied all 68 stored Findings,
including 44 LLM cards representing 53 original LLM observations. Replaying
their stored identities alone is unchanged. The complete pagination pair
revealed a second blocker beyond title grammar: the first model check names
the table `messages`, while the second names the local variable `query`.
Both check ranges are 55–65 with source quote ranges 53–67. This means the
title-only change above was insufficient for this actual pair.

The follow-up resolves a direct local SELECT binding from the archive, with
one direct await and only known same-binding filter/order updates. The proof
is independent of the model selector and records an identifier hash and byte
span in identity v2. Escapes, unknown writes, aliases, shadowing, optional
calls, escaped identifier spellings and multiple consumptions abstain. This
is a source identity, not proof of SDK behavior or a missing runtime limit.

Only pending (`not_checked`) premises citing the SELECT can compare a proven
binding target with its table. Observed/contradicted results and other status
fields retain their distinctions. Original targets and all evidence remain
unchanged in `grouped_originals`; v1 identities retain table-only semantics.

Offline verification on the exact archive re-resolved only the two pagination
identities from their saved title, narrative, conditions, quote coordinates
and recorded premise requests, then regrouped all stored Findings:

- total cards: **68 → 67**;
- LLM cards: **44 → 43**;
- original LLM observations: **53 → 53**;
- every original field is retained, apart from the deliberately recomputed
  pagination identities; a second grouping pass is identical;
- only the pagination pair gains a group; other candidates remain separate.

The saved-pair regression fixture retains the two complete Findings and the
source GET handler with its original line numbers. The fixture's source is a
bounded excerpt, so its file hash intentionally differs from the full archive;
the report-wide offline measurement above uses the full archive. No model
responses were regenerated and no production rows were rewritten.

The follow-up engine version is `2026-10-05-4`.

## Fact-count projection grouping

The complete stored Findings 18 and 36 have the same deterministic
`fact_input_count_unbounded` correction: `sanitizeFacts` caps the collection
at 40 items before the recorded renderer. This contradicts the claim that
an uncapped number of facts reaches that renderer, but says nothing about
whether the preceding database read, complete prompt or bill is bounded.
Their original model narratives and required conditions differ; in particular,
36 retains an original condition claiming the helper does not cap fact count.
Those historical statements must not become a shared verified hypothesis.

A separate pass now groups matching **corrected interpretations** after
narrative projection. Each projection is validated against its saved source
binding and wording. All other fields must match exactly, including the full
source assessments, context, pending premise checks, severity, category,
verification status and producer model/rubric. Only confidence, response
number, pending required conditions and superseded model prose may differ.
The highest-confidence representative is retained without increasing its
confidence. Complete projected originals, including all original model prose
and conditions, remain in `grouped_originals` and public HTML/web/SARIF exports.

This pass handles singleton findings only. Existing groups are not flattened
or extended, even if their representative appears identical: one root does not
establish the compatibility of every historical interpretation. Reapplying
this pass is idempotent. Other mechanisms and generic hypothesis grouping
are unchanged. It does not reduce the cost of the model calls already made.

Offline replay starts from the 67-card baseline above (only the two pagination
identities re-resolved against the same archive), then applies the new pass:

- total cards: **67 → 66**;
- LLM cards: **43 → 42**;
- original LLM observations: **53 → 53**, with every field unchanged;
- only the fact-count pair gains a group; existing groups remain untouched.

Both complete saved fact Findings are retained as a regression fixture. A
mocked fresh pipeline test also produces two different model narratives and
verifies the correction, grouping, preservation and accepted/saved counts.
No model calls were made and no production audit rows were rewritten.
Engine version advances to `2026-10-05-5` for the changed cached report output.
