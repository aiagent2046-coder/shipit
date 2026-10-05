# GPT-6 Luna versus the saved Sonnet 4.6 pilot

This isolated experiment makes no changes to the production model client,
pricing, scan engine, database, or service configuration. It requires no merge
or deployment. Run the script from the pinned experimental checkout using the
active release's Python environment.

## Inputs and comparison boundary

`scripts/evaluate_luna_pilot.py` reads the complete saved
`results-pilot-20261005-093207.json` report. It validates the six expected case
IDs and each `(system + NUL + prompt)` SHA-256 against the matching saved Sonnet
attempt. Those six system/user prompts are reused byte for byte. Historical
Sonnet responses, including invalid answers, are retained without modification;
quote/JSON checks are also reevaluated separately by the current validator.
The baseline file hash and per-file source hashes are saved.

Four additional synthetic controls cover pagination with/without a row limit
and a fact sanitizer with/without its 40-item cap. These are simplified
regressions inspired by the audited application, not extracts of that full
application. They use the saved system prompt and current money rubric. Their
private expectations never enter a model prompt. They have no historical
Sonnet counterpart and must be reported separately from the six paired cases.

The saved Sonnet bill is 73.37 RUB. Reusing it costs nothing. It is not ground
truth, and it is not a current production benchmark. Context selection and
other production behavior have changed since that historical pilot.

## Request and billing contract

- Fixed AITunnel endpoint; only `gpt-6-luna` is requested.
- Explicit `reasoning_effort: medium`, `max_completion_tokens: 8192`, no
  temperature, no tools, no response-format change, and no automatic retry or
  provider fallback. Keeping free-form JSON-array instructions preserves the
  original format test; Structured Outputs can be a separate experiment.
- The 8192 limit includes reasoning and visible output. It matches the old
  nominal Sonnet limit but does not imply equal visible-answer capacity.
- Read/network-operation timeout: 180 seconds (connect: 30 seconds), not an
  absolute wall-clock deadline; at most 10 requests.
- Admission budget: 20 RUB, using known billed spend plus a conservative
  reservation for the next request. The estimate uses UTF-8 byte count plus
  1024 envelope tokens, 25 RUB per million input/cache-write tokens, and
  100 RUB per million output tokens. Prompts above 240,000 bytes plus envelope
  are rejected to stay below the longer-context price tier.
- This is not a provider-enforced invoice ceiling. A changed provider tariff
  or an unknown charge can exceed it. Missing/invalid cost, model mismatch,
  HTTP error, timeout, or interruption stops further requests. Never count an
  unknown charge as zero. A complete invalid JSON or length-limited answer is
  preserved and the next case may run if its cost is known.
- Every attempted request is checkpointed before dispatch, then its successful
  raw response, usage, answer lengths, finish reason, refusal, latency and
  actual cost are saved. Error bodies/exception text and credentials are not
  recorded. Output files are private and atomically updated. Existing output
  paths cannot be overwritten. There is deliberately no resume/retry mode.

Provider references checked on 2026-10-05:

- https://aitunnel.ru/models/gpt-6-luna
- https://aitunnel.ru/docs/reasoning
- https://developers.openai.com/api/docs/models/gpt-6-luna
- https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create

## Run on the server

Use a detached worktree of the published experimental commit. From that
checkout, prepare without reading credentials or contacting a model:

```bash
/srv/shipit/current/.venv/bin/python scripts/evaluate_luna_pilot.py \
  --baseline /root/drydock-model-trial.LtVA8n/results-pilot-20261005-093207.json \
  --output prepared-luna.json
```

Execute the approved pilot into a new file:

```bash
/srv/shipit/current/.venv/bin/python scripts/evaluate_luna_pilot.py \
  --baseline /root/drydock-model-trial.LtVA8n/results-pilot-20261005-093207.json \
  --env /opt/shipit/.env --output results-luna.json --run
```

Only `AITUNNEL_API_KEY` is read from the environment file; it is never sourced
by a shell. Do not rerun into another filename after an uncertain charge
without reviewing the saved attempt first.

## Evaluation

Review both sides against the supplied source and private expectations:
known-mechanism misses, false claims on control cases, faithful source quotes,
complete valid JSON, time, input/output/reasoning/cache usage, and full cost
including failed attempts. A valid quote or more findings is not evidence of
better audit quality. Keep the four Luna-only controls separate. No automatic
judge declares a winner and production remains on Sonnet.

## Completed offline review

The completed Luna report was reviewed against its supplied sources and the
saved Sonnet answers. No additional provider calls were made for this review,
and it changes neither the production model nor production configuration.
Input SHA-256 values identify the private local reports; raw responses, account
balances, and other provider account metadata are not copied into this document.

| Input | SHA-256 |
| --- | --- |
| `results-pilot-20261005-093207.json` | `b08d030b74727ad8218009179ebc0d7419ee7eedfd33baa4777d8f499ff1fced` |
| `results-luna.json` | `b4049bb5601cf10ef685195963280e10a859b779425de5f0112ae10770335d43` |

### Six identical historical prompts

| Measure | Historical Sonnet 4.6 | GPT-6 Luna |
| --- | ---: | ---: |
| Reported spend, RUB | 73.37 | 3.17 |
| Sum of request durations, seconds | 60.276 | 153.771 |
| Strict JSON arrays | 5/6 | 6/6 |

On these attempts Luna cost 23.1 times less and took 2.55 times as long.
Tokenization and cache use differed, so this observed cost ratio is not a
production cost forecast. Equal nominal 8192-token limits do not imply equal
visible-answer capacity when reasoning tokens share the output limit.

All ten Luna requests together cost 3.59 RUB and took 180.663 seconds. All ten
finished with `stop` and returned strict JSON arrays. The four extra requests
are not part of the paired Sonnet comparison.

| Seeded mechanism | Sonnet semantic recognition | Luna semantic recognition | Recall eligibility |
| --- | --- | --- | --- |
| Access token interpolated into SQL | Present | Present | Eligible within this small fixture set |
| ZIP expansion total accumulates compressed bytes | Absent | Present | Eligible within this small fixture set |
| Notification body replaces authenticated payment read-back | Present, but answer is not a strict JSON array | Absent | Excluded: historical rubric conflicts with the seeded expectation |

The payment prompt explicitly asks for failures **without an attacker** and
excludes attacker-driven vulnerabilities, while its private expected mechanism
is forged notification state reaching the grant. Luna's omission is observable,
but is not a fair recall failure under that rubric. Sonnet's answer recognizes
the mechanism, yet adds prose and a fenced block instead of returning the
required JSON array. Reading that prose for semantic assessment does not make
the answer acceptable to the pipeline. No overall recall score or model winner
is inferred from these three seeded mechanisms.

### Additional findings and synthetic controls

Luna's archive finding about the pre-construction entry limit has a small
offline confirmation: on Python 3.12.14, a 280-byte archive declaring one entry
produced three entry objects, and a later cap of two rejected it only after
construction. This demonstrates the early-check limitation on that interpreter;
it is not a production reproduction or a measurement of resource exhaustion.
The separate symlink observation does not establish unsafe extraction: that
downstream behavior was not shown in the supplied source.

Payment read-back failures and unsuccessful grants being acknowledged are
source-supported observations. Lasting loss depends on recovery and transaction
behavior not established by the supplied files. Keep them as conditional,
unverified concerns. Sonnet's retry-storm claim likewise requires evidence
beyond a retryable response and must not count as a confirmed defect.

| Luna-only synthetic case | Offline assessment |
| --- | --- |
| `pagination-control` | Empty answer; no false claim that the explicit 50-row limit is absent. |
| `pagination-unbounded` | Empty answer; the expected source-level missing-limit observation was not reported. Workload, provider defaults, and monetary harm remain unknown. |
| `facts-control` | Recognizes the 40-item rendering cap while raising a separate conditional database-read concern. The cap does not bound the preceding read or fact lengths. |
| `facts-unbounded` | Recognizes that the supplied sanitizer no longer applies a count cap; does not establish an actual paid model call or charges. |

These controls test specific source claims rather than provide bug-free
oracles. Matching quotes validate source text, not the finding's interpretation
or its premise selectors. Manual review records mechanism recognition, strict
JSON, quote acceptance, source-supported observations, contradicted claims, and
unverified conditional concerns separately. Cost and latency include attempts
whose answers are unusable. Production remains on Sonnet pending stronger
quality evidence.

## Prepare a corrected payment comparison offline

`scripts/prepare_payment_model_review.py` prepares two versioned cases:
`payments-security-v1-control` and `payments-security-v1-seeded`. They retain
the saved system prompt and payment sources but use the same explicit
payment-authenticity rubric in both variants. The rubric asks for trust-boundary
review and recognizes that an unsigned notification can be safe when an
authoritative provider lookup supplies the grant decision. Private expectations
remain outside the model prompt.

```bash
/srv/shipit/current/.venv/bin/python scripts/prepare_payment_model_review.py \
  --baseline /root/drydock-model-trial.LtVA8n/results-pilot-20261005-093207.json \
  --output prepared-payment-review.json
```

The output is a private, newly created preparation file with source and prompt
hashes, empty results, and unreviewed manual fields. The script has no execution
mode and makes no requests. Two cases for two models mean four prospective new
answers; historical money-rubric answers cannot serve as results for these new
prompts. A later bounded execution requires its own cost review and user
authorization. Preparing this comparison does not launch it or change production.
