# Claim wording and repeated SELECT observations

The saved model trial exposed two presentation defects: source checks contradicted
a premise while the public title and explanation still asserted it, and two
paraphrases of one SELECT/pagination hypothesis occupied separate rows.

This change corrects wording only for two scanner-generated, source-bound checks:
`fact_input_count_unbounded` and `retry_callback_scope`. It retains the original
model prose and producer, other conditions, source assessments and severity.
It does not establish runtime outcomes, total prompt bounds or actual charges.

Fresh SHA-256 values come from raw ZIP bytes before prompt decoding. Caller,
helper, consumer and import-resolution configuration bindings must agree.
Missing, stale or malformed bindings leave the existing assessment unchanged.
The order is admission → recommendation preparation → grouping → projection.
Any future regrouping of projected records must apply projection again, because
grouping intentionally restores the retained original interpretations.

`query_read_volume` groups only a supported full-row SELECT and its common
pagination-bound hypothesis. Its identity contains the source hash, function,
operation span and table hash. Different operations, compound mechanisms and
different scanner dispositions remain separate. The representative has neutral
wording; every original condition and claimed consequence remains available.

HTML, web and SARIF use the corrected active wording and retain superseded model
text with provenance. Saved projection metadata is checked for consistency at
display time; displaying a historical report does not recheck current source.
The browser can still import report code without native AST dependencies.

## Offline measurement

Comparison base: `5dfd35882ac60d27b2db7aeab7731ac0bf50d882`.
Changed engine: `2026-09-13-11`.

Inputs were the existing saved trial and its pinned source ZIP, not newly
generated model answers. The customer archive and full responses are not part
of this repository.

| Input | SHA-256 |
| --- | --- |
| Trial JSON | `b64e27bc9bff7e4e3159ea8e2576d933af9dd862269f0997731b38c6911ed971` |
| Source ZIP | `ca820629509eec113b6aad6113387535d0fdc06d95058dccaccb1586747a388e` |

| Measure | DeepSeek | Sonnet |
| --- | ---: | ---: |
| Saved responses replayed | 5, including one failure | 8 |
| Accepted original claims retained | 16 | 54 |
| Saved rows before → after | 16 → 16 | 49 → 48 |
| Corrected active narratives | 0 | 3 |
| Additional repeated-SELECT groups | 0 | 1 |
| Existing score before → after | 5.4 → 5.4 | 4.6 → 4.6 |
| Scan completeness | static+partial | static+llm |

All 13 reconstructed message hashes match their saved requests. Both models keep
their original input budgets. DeepSeek's saved 32,768-token output override is
recorded separately from the product's 8,192-token request parameter. Replaying
those answers measures postprocessing; it does not retest provider limits.

The three Sonnet corrections are the two fact-count assertions (S3.5, S7.4) and
the HTTP-status retry assertion (S7.8). The SELECT group combines S3.7 and S7.6
at `app/api/messages/route.ts:55`, AST span `[2392, 2514]`. All accepted original
texts, conditions and dispositions survive; only these two originals acquire a
new source identity. Static findings are unchanged. JSON, HTML and SARIF checks
confirm active and superseded wording remain distinct.

DeepSeek retains `INCOMPLETE`, the underlying
`REASONING_LIMIT_WITHOUT_ANSWER`, and the original harness failure
`TRIAL_STOPPED_ValueError`. The overall comparison remains incomplete.
These counts and existing scores are not a quality ranking or verified readiness
measurement. No source files from the customer archive were executed.

New network requests: **0**. New provider cost: **0 RUB**.

## Reproduce

From the checkout to measure, with its Python dependencies available:

```bash
PYTHONPATH=. python scripts/replay_saved_trial.py \
  --report /path/to/saved-trial.json \
  --archive /path/to/source.zip \
  --output /path/to/new-replay.json
```

To measure an older checkout, run this script with `PYTHONPATH` set to that
checkout. The script rejects archive/prompt drift, unsaved calls, unconsumed
responses and changed failure/completeness state. HTTPX and socket connections
are blocked, the LLM client returns saved responses, and no OSV client is used.
Token counts and USD estimates inside `scan` belong to the historical responses;
the separate `new_cost_rub` field describes the replay.

Validation covers actual AST-generated evidence, stale helper/config bindings,
uncapped consumers, HTTP checks inside the retry callback, distinct SELECT/count
operations, malformed metadata, repeat/projection idempotence and public exports.

Local checks: 7,865 Python tests passed, 148 skipped and one expected failure;
316 web tests passed; TypeScript, Ruff and whitespace checks passed. The full
Python suite used `FIXPACK_RUN_AS_USER=node:node` for mocked container-command
tests because this workspace cannot chown to numeric UID 1000. Ambient proxy
variables were removed from that test process because HTTPX's SOCKS extra is
not installed. Production defaults and Docker ownership tests were unchanged.
