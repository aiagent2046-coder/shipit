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
