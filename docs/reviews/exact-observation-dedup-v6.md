# Exact observation repeats: v5 regression and v6 correction

The production `v2026.09.08-5` audit contained seven pairs of identical
Frontend observations. Each pair differed
only in scanner-owned `claim_evidence.producer.response` (4 versus 8).
All had `source_issue_identity: null`, which prevented even exact repeats from
grouping. The same 14 model rows produce seven groups under the v4 matcher and
14 under v5. This is a grouping regression, independent of interpretation quality.

## Scope

The correction permits exact repeats of scanner-accepted LLM observations with
an explicit unresolved identity, a valid quote-match window containing the
finding's source line, and recorded model/rubric/response provenance. It compares
every `ScoredFinding` field and the complete evidence payload, ignoring only the
producer response number. Both originals remain available, but the observation
is scored once. Different severities, conditions, recommendations, verification
statuses, source bindings and other producer metadata are not treated as exact
repeats. Invalid or missing bindings do not enable the fallback.

This operation groups observations from one `run_llm_scan` invocation and source
archive. Quote matching is not independent verification of a model's claim, and
does not establish equivalence between different source archives. No new semantic
grouping, source interpretation, static/LLM merging or retrospective rewriting of
stored reports is introduced. Existing source-identity and legacy matching remain
unchanged. Engine `2026-09-08-6` gives newly generated audits a distinct cache key.

## Regression evidence

The fixture `tests/fixtures/exact_observation_repeats.json` contains seven
synthetic model observations and four synthetic static findings. Their penalty
weights reproduce the reported arithmetic, and each model observation has two
response numbers. Paths, text, model names and evidence are written for the test;
no original audit payload, source excerpt, prompt or source-project identifier is
published. The complete original report was replayed separately in the private
workspace to verify that this synthetic regression captures the production bug.

`tests/test_exact_observation_dedup.py` checks:

- Seven exact pairs become seven model representatives: 18 Frontend rows become
  11 including the four unchanged static findings; Frontend changes from 2.9 to 5.5.
- All 14 model originals and their response numbers survive without input mutation.
- Regrouping, overlapping saved groups and a third response preserve multiplicity
  without another score penalty.
- Substantive differences and malformed source/provenance bindings remain separate.
- A real two-pass `run_llm_scan` with canned responses records two received and
  accepted observations, one merged observation and one saved representative.

The fixture replay fails against the deployed v5 matcher (18 rows instead of 11)
and passes with the correction. It does not call a model provider or execute the
audited project.

## Complete saved-report replay

An additional private offline replay used the complete uploaded v5 report.
The source release is `e2876a12f0ea0afa1bad199fac0c6a68f4fcbf0f`; the report
contents are not part of this repository.

| Check | Before | After |
|---|---:|---:|
| Pro displayed rows | 54 | 47 |
| Frontend diagnostic score | 2.9 | 5.5 |
| Total diagnostic score | 4.6 | 4.8 |
| Original observations including static rows | 64 | 64 |
| Free displayed rows | 12 | 12 |

Other category values, all original observations, the source input, the Free
baseline ID, score, findings and its complete embedded HTML were preserved.
Regrouping the result is idempotent. No provider calls were made. These are
diagnostic results for the saved artifact, not a new official audit or a promise
of the number of findings in a future model response.

To run the public regression fixture:

```sh
pytest -q tests/test_exact_observation_dedup.py tests/test_cross_rubric_dedup.py
```
