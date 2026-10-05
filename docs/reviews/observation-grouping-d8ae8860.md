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
