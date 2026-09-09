# Model metadata grouping: bounded claim scopes

One model metadata request can support different hypotheses: dynamic version
selection may cause drift, while repeating the lookup may add requests or cost.
The old `model_metadata_request` source identity named only the operation. Equal
source spans therefore allowed different problems to share one scored row.

## Contract

- New model metadata identities use version 2, an explicit `claim_scope`
  (`version_selection` or `repeated_request`) and `claim_qualifiers`.
- The existing bounded AST resolver still supplies the source digest, function
  and operation spans. Model-supplied identity fields cannot supply that binding.
- A small full-match grammar admits only short supported claims. It consumes the
  entire title and nonempty observation/explanation; the fix and conditions also
  need supported forms. Negations, unknown qualifiers, conditional titles,
  compound claims and unsupported prose remain unresolved. A rejected metadata
  title cannot fall through to another source mechanism such as query bounds.
- Semantic grouping requires equal version-2 identities, valid quote-bound
  scanner records, compatible producer metadata and verification dispositions.
  Ancillary prose, recommendations, conditions and evidence are compared in full.
  Only supported title paraphrases may differ; condition paraphrases are not
  assumed equivalent. Paid and extra-request assertions retain distinct
  qualifiers. Grouping does not verify provider billing, harmful consequences,
  missing caching or the safety of a selected model version.
- Stored version-1 metadata identities cannot enable semantic grouping. An exact
  repeated scanner-accepted observation may still group when the entire original
  payload matches except for the producer response number. The identity remains
  part of that payload. This exception is limited to metadata identities and the
  existing unresolved-identity path; it does not alter other source mechanisms.
- Flattening previously grouped input re-evaluates each original. Original titles,
  conditions, status, category and producer records are preserved. A saved mixed
  group splits on replay; overlapping saved history is not counted again.

This is intentionally incomplete semantic detection. Free-form claims, including
version pinning combined with signature verification, may remain exact-only.
There is no attempt to add enough keywords to merge an entire production report.
Other scanner mechanisms are unchanged. The integrated change advances the audit
engine and cache guard to `2026-09-09-7`.

## Regression evidence

The new tests use only generated in-memory source and synthetic observations:

- one operation with a version claim plus two identical cost claims becomes two
  groups, preserving all three observations and scoring the cost once;
- the same result holds for fresh source resolution, unsupported free-form
  prose, and replay of a mixed legacy group, including overlapping saved groups;
- scoped title paraphrases merge only with identical ancillary meaning and
  conditions; mixed mechanisms, changed qualifiers, unsupported conditions and
  conflicting statuses stay separate;
- malformed identities and inconsistent source/producer records fail closed;
- optional fields normalized to null by `model_claim_evidence` remain compatible;
- ambiguous source operations stay unresolved and rejected metadata claims cannot
  reuse another mechanism's fallback.

No private fixtures, provider calls, audit runs or target execution are needed.
