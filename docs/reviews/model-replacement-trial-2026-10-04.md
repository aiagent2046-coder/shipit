# Sonnet replacement: fixture trial

## Second round: context and stability

First round measured Sonnet 10.35 RUB / 31.110 seconds, DeepSeek 1.55 RUB /
41.503 seconds, MiniMax 1.17 RUB / 86.530 seconds. Sonnet reported the target
mechanism in all three risk cases; DeepSeek in YAML only; MiniMax in shell and
YAML. All models returned empty answers for the three controls. One attempt
is not an accuracy estimate. Sonnet also introduced an unsupported authentication
claim in its SQL explanation. No replacement is approved by these results.

```bash
python scripts/evaluate_audit_models.py --suite context --repeats 3 --output /tmp/drydock-round2-plan.json
python scripts/evaluate_audit_models.py --suite context --repeats 3 --run --env /opt/shipit/.env --output /tmp/drydock-round2-results.json
```

This makes up to 90 calls: ten cases, three models, three repetitions. Original
six prompts are preserved. Four additional cases attach identical HTTP callers
to SQL/YAML risk/control helpers. Only user_id has an HTTP source in the SQL
context case; table/owner in the other function remain provenance-unknown.
Router deployment and external reachability remain unproven. Baseline and
context cases must be judged separately. Rotate model order each repetition.
These are ten fixtures repeated, not 90 independent quality samples. Provider
caching and rounding affect measured cost; this is a warm repeated workload.
Costs now use usage.cost_rub first (including zero), falling back to top-level
cost_rub only if absent/null. Missing cost remains unknown. Raw usage is kept.
Results retain repetition numbers and request order, with progress after each
call. Failure stops the run, so partial results must not be compared as if all
models completed equal coverage. There is no automatic retry or resumption.

Candidates: `deepseek-v4-pro-0813`, `minimax-m3`; control: `claude-sonnet-4.6`.
Production configuration is unchanged. This trial does not select a winner automatically.

## Run

Use the project's Python environment, from the repository root:

```bash
python scripts/evaluate_audit_models.py --output /tmp/drydock-models-prepared.json
python scripts/evaluate_audit_models.py --run --env /opt/shipit/.env --output /tmp/drydock-models-results.json
```

The first command makes no API calls. The second makes up to 18 billable calls:
six cases, three models, one attempt per case/model. No automatic retries or
provider fallback. It stops on the first HTTP, malformed or incomplete answer.
Use a new output filename for every run; previous results are not overwritten.
The requested output limit is not a guaranteed monetary cap. No fixed ruble
budget is enforced. Obtain billing totals from AITunnel when missing in usage.

Production system prompt, security rubric, request payload builder and source
quote validator are reused. Every model sees identical source bytes and prompts;
hashes and complete prompts are stored. Fixture paths/expected answers are not
sent. Answers, provider-reported model, finish reason, raw usage (including any
reasoning/cache details), any top-level cost_rub and timing are saved after each
call. A valid empty answer remains distinct from invalid output. Provider model
aliases must be reviewed; differing names alone do not prove wrong routing.

## Manual judgement

* SQL: concatenated arguments versus parameter binding and constant columns.
  This is a pair of mechanisms, not a functionally identical patch. Caller trust
  is absent: do not reward a claim of proven remote exploitation.
* Shell: request input embedded in `bash -c` program text versus a quoted
  positional argument to a constant shell program. A list of arguments does not
  protect the first case, even without `shell=True`.
* YAML: `UnsafeLoader as SafeLoader` versus genuine `SafeLoader as SL`.
  Resolve imports rather than trusting alias spelling. Untrusted provenance is
  not demonstrated in these helper functions.

For each answer, record in manual_verdict: correctly identified target mechanism,
unsupported claims, missed target, and whether its stated conditions are accurate.
Review other findings individually; control does not mean globally safe.
Neither matching quotes nor agreement with Sonnet establishes correctness.

## Decision gate

This tiny sample is a compatibility/semantic screening, not a quality benchmark.
After passing it, compare repeated scans of fixed repository commits with equal
file coverage, including known fixed issues and cross-file flows. Use the paid
production pass count for that stage. Report actual total spend, latency, confirmed
findings, misses, unsupported claims and rejected responses. A proposed acceptance
criterion is at least 3x lower measured cost without losing known serious findings
or increasing unsupported claims on the reviewed sample. No production switch
until those results are reviewed. Small-sample results do not establish parity
across arbitrary repositories.

The existing scripts/compare_models.py compares overlap, not truth, and requires
pricing entries. Do not fabricate fallback dollar prices to make new candidates
pass its model allowlist. The fixture trial keeps actual provider usage instead.

## Resumption after observed reasoning exhaustion

Round 2 stopped at attempt 20: DeepSeek used 4096 completion tokens, all
reported as reasoning, with finish_reason=length and no answer (2.73 RUB).
Use --resume OLD.json --output NEW.json --run --continue-invalid to preserve
all attempts and send only unattempted jobs. Saved failed attempts are never
retried. Prompts, cases, models and token budget must match. Invalid completions
are recorded and the experiment continues; transport/HTTP errors still stop.
Completion with recorded errors is labelled completed_with_errors_needs_review.
An empty valid answer and an exhausted reasoning budget remain distinct.

## MiMo and GLM comparison (2026-10-05)

AITunnel model pages identify `mimo-v2.6-pro` and `glm-5.3`:
https://aitunnel.ru/models/mimo-v2-6-pro and https://aitunnel.ru/models/glm-5-3.
Use a fresh run, preserving the same context suite, three repetitions, 4096
requested output tokens and production payload defaults. Sonnet runs alongside
both candidates. Unknown-model sampling parameters remain omitted; this tests
current client compatibility, not each model's optimally tuned reasoning mode.

```bash
python scripts/evaluate_audit_models.py --models claude-sonnet-4.6 mimo-v2.6-pro glm-5.3 --suite context --repeats 3 --continue-invalid --run --env /opt/shipit/.env --output /tmp/drydock-mimo-glm-results.json
```

Up to 90 paid requests. Prompts and fixture coverage are identical to round 2.
No production model or provider configuration changes. When resuming, the saved
model selection is retained; an explicit different selection/order is rejected.
A length-limited response is a failure under this budget, not proof that the
model can never solve the example. Comparison is conditional on this setup.

## Pinned repository comparison: Sonnet and MiMo

Runner: scripts/evaluate_repository_models.py. Source snapshot:
`c2328e9548bd6b7eb3b06e309386cd53be541f82` (shipit, merged PR 618).
It reads git archive bytes without checking out or executing the scanned code.
Archive SHA256, source commit, scanner revision, prompt hashes, selected paths,
trimmed files, source facts and full original text of selected files are saved.

Uses production source-fact collection, rubric selection and prompt fitting.
Both models intentionally get the Sonnet input budget (advertised MiMo context
is 1M at https://aitunnel.ru/models/mimo-v2-6-pro). This overrides the smaller
unknown-model fallback in production metadata for this experiment only.
No model-specific shrinking or retries: equal submitted content is essential.
Four rubrics x two passes x two models means up to 16 calls. Default output
limit is 8192, read from RUBRIC_MAX_TOKENS exactly as in production code; this
is a code default, not a measurement of the live service environment.

```bash
RUBRIC_MAX_TOKENS=8192 python scripts/evaluate_repository_models.py --revision c2328e9548bd6b7eb3b06e309386cd53be541f82 --output /tmp/repo-model-plan.json
RUBRIC_MAX_TOKENS=8192 python scripts/evaluate_repository_models.py --revision c2328e9548bd6b7eb3b06e309386cd53be541f82 --output /tmp/repo-model-results.json --run --env /opt/shipit/.env
```

Use --resume OLD.json with a NEW --output to skip all saved attempts, including
failures, and retain the same snapshot/prompts/budget. Incomplete output is saved
as an error; HTTP/transport errors stop. All billed raw usage is retained when
returned. No monetary cap is enforced by this runner; the fixture costs are
not estimates for much larger repository prompts. Inspect actual input-token
usage for possible provider truncation before comparing costs or findings.

This is controlled raw LLM comparison, not the full production report pipeline:
no semantic rejection, grouping, deduplication or scoring after quote checks.
A reviewer must assess source-supported mechanisms and reachability against
both the selected files and omitted caller/guard context. No findings is not
proof of safety. Source selection is the existing production selection, not
complete repository coverage. A single repository cannot prove overall parity.

## 2026-10-05: bounded auth comparison and seeded follow-up

The full-repository trial stopped after Sonnet auth (317,169 input tokens,
190.32 RUB, 5.718 s) and MiMo ReadTimeout (180.071 s, cost unknown).
Do not automatically retry or interpret the timeout as zero cost.

The bounded auth trial at snapshot c2328e9548bd6b7eb3b06e309386cd53be541f82
completed both calls. Shared prompt hash:
`b1ac49bb08de512b905ae42cfb4c07683eb9960bfb9fdc3c6a471768385983d8`.
User-supplied results:

| Model | Input tokens | Output tokens | RUB | Seconds | Reported findings |
| --- | ---: | ---: | ---: | ---: | ---: |
| claude-sonnet-4.6 | 53531 | 4 | 32.14 | 2.412 | 0 |
| mimo-v2.6-pro | 56848 | 2863 (2860 reasoning) | 5.45 | 61.441 | 0 |

Both returned valid arrays with stop finish reason; neither used cached tokens.
This is a cost/latency observation, not proof of equal detection quality.

`--scope auth-seeded` now prepares the same scope with exactly two in-memory
line replacements, one call per model, max output 8192 and read timeout 600 s.
The source archive and application files are never modified. Mutation anchors
must match exactly once; oversized prompts fail before provider access.

Expected mechanisms (stored in report metadata, never sent to the models):
1. `account_for_key` falls back to `get_by_id(api_key)`: an existing known UUID
   authenticates as that account without possessing its secret, with configured
   pepper/database. It also persists via cookie plus the existing CSRF header.
2. An authenticated caller chooses the key-rotation target through JSON
   `account_id`, receives the other account's new key and invalidates the old
   one. Validate with the caller's normal authentication independently of #1.

Models must identify the mechanisms and source evidence; knowing a UUID is an
explicit prerequisite, not a proven UUID disclosure. One finding describing both
mechanisms can count as detecting both. Additional claims require separate manual
review. The earlier baseline is reused without another paid call. This small
paired experiment alone does not establish general model equivalence.
