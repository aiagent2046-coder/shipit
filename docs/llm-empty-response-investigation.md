# Sonnet empty-response investigation, 2026-10-05

This is an offline investigation of audit `e949cf31`, its exported HTML,
the provider CSV `stats-2026-10-05_2026-10-05(3).csv`, and the previously saved
`results-pilot-20261005-093207.json`. No additional model calls were made.

## Observed facts

- The audit HTML records eight Sonnet responses, eight valid empty results,
  zero unreadable responses, zero received entries and zero rejected entries.
  Finding verification and deduplication therefore did not remove these results.
- The eight Sonnet CSV rows at 15:28 Moscow time each report four output tokens
  and zero reasoning tokens. Their input counts repeat across the two passes:
  326,798 / 325,823 / 315,587 / 322,850. The second pass reads almost the entire
  prompt from cache. The CSV has no audit ID or finish reason; attribution to
  this audit is consistent with its timing and response counts, not a direct join.
- The two-pass loop deliberately repeats each rubric prompt. It does not add
  previous answers or different review questions to the second pass. This is
  the existing union-of-N policy, not an accidental network retry.
- The saved pilot used the same 7,471-character system prompt as this deployed
  audit. Sonnet returned a JSON finding for `sql-seeded`, `[]` for
  `files-seeded`, and non-array prose for `payments-seeded`. The four literal
  `[]` answers in that pilot also used four output tokens each.
- Cache enablement changes the message envelope, preserving the prompt text.

## What the available data cannot establish

The legacy `parse_response` extracts from the first `[` to the last `]` before
JSON parsing. Both `{"premises": []}` and `Explanation []` can therefore count
as valid empty results. Four output tokens are consistent with literal `[]`,
but the HTML and CSV do not contain the raw replies or their character counts.
They cannot independently establish the exact response envelope.

Large prompts, test-heavy selections, restrictive instructions and provider
routing are possible contributors; none is proven to be the cause. The system
prompt's instruction to use an empty array for unsupported premises follows the
premise-field description. Its wording may be ambiguous, but the same prompt
also produced a nonempty finding in the pilot. Empty results do not establish
that the reviewed code is safe.

## New metadata

`response_diagnostics` reports answer character and UTF-8 byte lengths, an
envelope classification, and the number of direct-array items. It retains no
answer text, content hash, source paths or credentials. UTF-8 length describes
the decoded text re-encoded as UTF-8, not the provider's HTTP body size.

`json_array` means the whole answer is a JSON array; `fenced_json_array` means
the whole answer is an optional `json` Markdown fence containing an array.
`other_json` describes a whole JSON value of another type. `embedded_array`
describes an array recoverable through the legacy bracket extraction after
whole-answer checks fail. Other replies are `non_json`. `direct_array_items`
is populated only for `json_array`; all other envelopes use null.

This metadata distinguishes direct arrays from recovered arrays without
changing finding admission, adding paid retries or claiming to explain the
model's decision. Existing private usage records supply rubric, pass, finish
reason and token counts for subsequent analysis.
