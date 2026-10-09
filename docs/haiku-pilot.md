# Haiku 5.5 historical Sonnet pilot

This isolated experiment sends six saved prompts to `claude-haiku-5.5` at
AITunnel. It never calls Sonnet, changes production settings, or starts a scan.
It needs Linux and Python 3.10+ standard library only.

## Fixed inputs and bounds

- Baseline: `results-pilot-20261005-093207.json`, SHA-256
  `b08d030b74727ad8218009179ebc0d7419ee7eedfd33baa4777d8f499ff1fced`.
- Exactly six original SQL/files/payments control/seeded prompts, byte-for-byte.
- One request per case; no automatic retry, resume, redirect, proxy or fallback.
- `reasoning: {effort: medium}`, `max_tokens: 8192`, no temperature or cache markers.
- 180-second wall-clock deadline per call. Six calls cap provider time at 18 minutes.
- 20 RUB admission budget. The reviewed baseline reserves 15.0297125 RUB total.
  This is an estimate, not a provider-enforced spending cap.
- Reserve UTF-8 bytes plus 1024 envelope tokens, including cache-write pricing and
  a 10% margin. At up to 100K estimated tokens: 27.5/110 RUB per million input/output;
  above 100K: 137.5/550. Never assume a cache hit. Rates checked 2026-10-09.

Sources: https://aitunnel.ru/models/claude-haiku-5-5,
https://aitunnel.ru/docs/reasoning, https://aitunnel.ru/docs/api-reference.

## Execution

Use a detached worktree of this experimental commit. The original server baseline
is `/root/drydock-model-trial.LtVA8n/results-pilot-20261005-093207.json`.

Prepare without reading credentials or making any network request:

```bash
python3 scripts/evaluate_haiku_pilot.py \
  --baseline /root/drydock-model-trial.LtVA8n/results-pilot-20261005-093207.json \
  --output /root/haiku-plan.json
```

Run once, using a different, new output path:

```bash
python3 scripts/evaluate_haiku_pilot.py \
  --baseline /root/drydock-model-trial.LtVA8n/results-pilot-20261005-093207.json \
  --output /root/results-haiku-pilot.json \
  --env /opt/shipit/.env --run
```

The established deployment env parser reads the key; never source the env file
in a shell. An exported AITUNNEL_API_KEY takes precedence. Existing output paths
are refused. A repeated invocation with another output path starts another paid
experiment; inspect saved attempts before deciding on any new run.

## Evidence and interpretation

Private atomic checkpoints contain the complete prompts, baseline responses,
Haiku response/usage/model, finish reason, duration, response lengths, actual
`cost_rub`, known total and number of unknown charges. An in-flight record is
written before the call. Timeout, unknown cost, wrong served model, refusal,
truncation or invalid answer stops the experiment. Absence of cost is never zero.

Strict JSON and whole-answer Markdown fence removal are recorded separately.
Fence removal is not the production parser: it does not extract JSON surrounded
by prose. A valid array of objects is only a transport/format result, not a
quality pass. Quote validation and correctness require manual source review.
Preserve cache and reasoning token usage for later cost/latency analysis.

Sonnet is a historical comparator, not ground truth. The original payments
rubric excludes attacker scenarios, so those cases cannot establish security
recall. This pilot also does not establish performance on current production
prompts, long repositories, or cached repeat scans. Do not commit raw reports.

## Offline verification

```bash
python3 -m unittest discover -s tests -p test_evaluate_haiku_pilot.py
```

Tests cover admission/actual overruns, unknown charges, model mismatch, timeout,
wall-clock deadline, truncation/refusal/invalid output, baseline tampering,
checkpoint permissions, no resume, and prepare-only credential isolation.
