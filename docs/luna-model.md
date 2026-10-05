# Optional GPT-6 Luna integration

Sonnet remains the default. This change adds an opt-in OpenAI-compatible Luna
configuration; it does not edit a deployed environment or start paid scans.
The free preview keeps its existing model configuration.

## Evidence and scope

The 2026-10-05 pilot reused six saved Sonnet prompts and added four synthetic
controls. All ten Luna answers were strict JSON and cost 3.59 RUB. On the six
paired prompts, costs were Luna 3.17 RUB and historical Sonnet 73.37 RUB.
The old payment rubric excluded attacker-driven failures despite expecting a
forged-payment finding, so that miss was not a fair recall measurement.

A corrected payment-authenticity pair then used identical messages for both
models. Both returned no findings on the control and identified the inserted
read-back defect. Luna returned strict JSON in both answers, costing 1.02 RUB
over 30.384 seconds; Sonnet cost 24.17 RUB over 24.396 seconds and added prose
and Markdown around its seeded finding. The production parser already accepts
an embedded JSON array, so that strict pilot format failure does not establish
a production parsing failure. No parser weakening is part of this integration.
These small, known fixtures do not establish real-repository recall or
run-to-run stability. Raw reports and account balances are not committed.

## Configuration

For an isolated process or a later controlled deployment, retain the existing
AITunnel key and base URL and explicitly select:

```dotenv
AITUNNEL_LLM_MODEL=gpt-6-luna
```

`openai/gpt-6-luna` is also accepted. Prefer the provider-specific variable to
the shared `LLM_MODEL`. If direct Anthropic is configured, keep its supported
model explicit, for example `ANTHROPIC_LLM_MODEL=claude-sonnet-4-6`; Luna cannot
be sent to Anthropic's `/v1/messages`. Preflight diagnoses that configuration,
and the client rejects it before HTTP. Do not add a fallback credential merely
to try Luna. Returning AITUNNEL_LLM_MODEL to the prior Sonnet value restores the
prior model selection after restarting both API and worker.

The Luna request uses `reasoning_effort: medium`, omits temperature and Claude
cache markers, and sends the caller's output allowance as
`max_completion_tokens`. Reasoning and visible output share that allowance;
the audit rubric normally supplies 8192. Existing Sonnet payloads are unchanged.
The context budget stays at the conservative 200K-token configuration, including
the 8192 response reserve; the pilot did not validate million-token code input.

Luna responses require a recognized served-model name, `finish_reason=stop`,
nonempty answer text and no refusal. Truncated or refused `[]` answers must not
become clean audits. Failure retains provider usage and follows the existing
explicit provider chain. This client is not the no-retry pilot runner: existing
transport/5xx retries, fallback and `LLM_READ_TIMEOUT` still apply. The default
read timeout is 120 seconds; an isolated trial can explicitly set 180 seconds.
HTTPX timeouts bound individual operations, not the whole audit's duration.

## Costs and cache identity

The published underlying USD table records Luna at $0.10 input and $0.50 output
per million tokens. Internal USD estimates conservatively use the $0.125 cache-
write input rate because aggregate stats lack the cache split. Above 272,000
aggregate input tokens for a Luna model, estimates use twice the input rate
and 1.5 times the output rate. This can overestimate multiple short requests
or cache hits; it is not an AITunnel invoice or guaranteed billing ceiling.

Actual `cost_rub`, cache reads/writes and reasoning usage are already journaled
per provider attempt. Reasoning is part of completion tokens and is not added
twice. Missing charges remain unknown. USD totals retain each successful served
model's own token totals, so a later Luna response cannot reprice an earlier
Sonnet fallback. Scan caps, persisted estimates and remaining preview budget
use that same breakdown. Historical aggregate-only stats keep their old
estimate. Failed attempts remain outside that legacy successful-completion USD
estimate; their actual/unknown RUB charges remain in the provider journal.

Configured Luna chains receive a separate audit engine/cache identity derived
from non-secret model configuration. The API and worker must use the same
environment and restart together. This prevents a Luna run from reusing a
cached Sonnet report for identical repository content. The static/offline
engine version stays independent of provider configuration.

## Rollout boundary

Review and merge the integration before enabling it on deployed services.
First compare one real repository in a bounded isolated run using this client,
checking provider attempts, served models, costs, incomplete responses and
source-supported findings. Do not infer quality from finding count alone.
Keep Sonnet as the deployed default until that report is reviewed.

Sources checked on 2026-10-05:

- https://developers.openai.com/api/docs/models/gpt-6-luna
- https://aitunnel.ru/models/gpt-6-luna
- https://aitunnel.ru/docs/parameters
