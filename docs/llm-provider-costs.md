# Actual LLM charges and Sonnet prompt caching

## What is measured

`llm_usage.cost_usd` remains the existing internal estimate used by spend limits.
It is not an AITunnel invoice. This change does not alter model selection, prompt
text, number of audit passes, retry policy, scoring, or USD enforcement.

Migration `0040_llm_provider_usage.sql` adds nullable `llm_usage.provider_usage`.
One journal row still belongs to one job attempt. Its JSON contains all HTTP
attempts made by that scan, including retries and fallback calls, with:

- requested/served model, provider kind, rubric, pass and request number;
- reported input/output/reasoning/cache-read/cache-write token counters;
- actual `cost_rub` as a decimal string, or null when absent/invalid;
- elapsed seconds, finish reason, error type/status, and final-answer parse status.

No prompts, answers, credentials, balance, base URLs or full response bodies are
copied to this journal. Provider attempts are excluded from the public `llm`
summary and operator summary alerts. Historical rows retain SQL NULL rather
than receiving invented zero costs. Content-hash audit reuse writes no new usage.

Summary fields:

- `known_cost_rub`: sum of reported prices; null if none were reported. Explicit
  zero is a known price.
- `cost_rub`: total only if every recorded attempt has a price; otherwise null.
- `cost_complete`: whether every recorded attempt has a valid price.
- `unpriced_attempts`: requests whose charge needs reconciliation with the provider.

A timeout may still be billed by the provider. An empty or malformed answer may
already have a charge. Both remain in the journal, even if no completion succeeds.
Token counters retain provider meaning: OpenAI-compatible `prompt_tokens` may
include cache reads, while Anthropic's `input_tokens` is a separate counter. Do
not blindly add/subtract cache or reasoning counters. Missing counters are null.

Writes remain best effort: an unavailable database can still lose accounting.
This is per-scan persistence, not a transaction with the provider; process death
before persistence also requires invoice reconciliation. The legacy USD estimate
still counts returned completions; the new journal separately exposes failed and
unknown attempts and does not silently redefine existing budget enforcement.

## Enable and verify caching

After applying migration 0040 and deploying this code, set:

```dotenv
AITUNNEL_PROMPT_CACHE=1
```

The default is `0` (off). The flag applies only to Sonnet 4.6 on the exact
OpenAI-compatible base URL `https://api.aitunnel.ru/v1`. Other models, custom
endpoints and direct Anthropic requests keep their current payload shape.

The request marks the unchanged system text and user text with explicit
`cache_control: {"type": "ephemeral"}` blocks. The system marker supports
reuse of instructions across rubrics. The user marker supports identical-rubric
repeats. The provider's default TTL is five minutes. No synthetic warm-up calls,
extra retries or session identifiers are introduced.

AITunnel documents a 1024-token minimum for Sonnet 4.6, roughly 1.25x input price
for a five-minute cache write, and a 90% read discount for this model. These are
provider terms, not measured savings for Drydock. Requests can miss because of
different prefixes, expiration or routing. A single-use cached prefix can cost
more. Verify actual `cached_tokens`, `cache_write_tokens` and `cost_rub` before
claiming a saving. Long audits may exceed the TTL before pass two.

References checked 2026-10-05:

- https://aitunnel.ru/docs/caching
- https://aitunnel.ru/models/claude-sonnet-4-6

## Read the journal

Known charges and missing prices for the last 24 hours (existing rows without
telemetry are counted separately, never treated as free):

```sql
SELECT
  count(*) AS journal_rows,
  count(*) FILTER (WHERE provider_usage IS NULL) AS rows_without_provider_usage,
  sum((provider_usage->>'known_cost_rub')::numeric) AS known_cost_rub,
  sum((provider_usage->>'unpriced_attempts')::integer) AS unpriced_attempts
FROM llm_usage
WHERE created_at >= now() - interval '24 hours';
```

Per-request detail, including the rubric and pass that sent a large context:

```sql
SELECT u.id AS journal_id, u.audit_job_id, u.job_id, u.created_at,
       a->>'requested_model' AS requested_model,
       a->>'model' AS served_model,
       a->>'rubric' AS rubric, a->>'pass' AS pass,
       a->>'request' AS request,
       a->>'input_tokens' AS input_tokens,
       a->>'output_tokens' AS output_tokens,
       a->>'cached_tokens' AS cached_tokens,
       a->>'cache_write_tokens' AS cache_write_tokens,
       a->>'cost_rub' AS cost_rub,
       a->>'finish_reason' AS finish_reason,
       a->>'error' AS error
FROM llm_usage u
CROSS JOIN LATERAL jsonb_array_elements(u.provider_usage->'attempts') a
WHERE u.created_at >= now() - interval '24 hours'
ORDER BY u.created_at, u.id, (a->>'request')::integer;
```

## Baseline from the supplied export

The user's export for 2026-10-05 contains 39 Sonnet 4.6 requests from 10:14:54 to
12:40:06 Moscow time, with 589815 input tokens, 11854 output tokens and 389.62 RUB
in the `Cost` column. Cache reads/writes are zero. This is an exported interval,
not a full-day total. One 317169-input-token request costs 190.32 RUB. Its four
output tokens do not establish what the model answered; the CSV lacks audit and
rubric identifiers. The six pilot signatures account for 73.37 RUB; the remaining
requests cannot be classified as production from this export alone.

Do not add the CSV's separate `ToolCost` column to `Cost` without confirming its
meaning. All 39 `Cost` rows match input at 600 RUB/MTok and output at 3000 RUB/MTok
with per-request upward kopeck rounding. No paid optimization trial was run for
this implementation. Prompt compaction is a separate follow-up.
