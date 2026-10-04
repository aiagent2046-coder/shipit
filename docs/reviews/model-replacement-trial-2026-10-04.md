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
