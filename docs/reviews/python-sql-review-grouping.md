# Python SQL review grouping and JavaScript module coverage

The Kristina audit `d2c2e5ef` contained six model hypotheses about three
table-name interpolations. The static SQL detector already distinguishes
literal-only assembly from unknown input. The model grouping path, however,
only resolved JavaScript/TypeScript operations. Python paraphrases consequently
received separate rows and separate score penalties.

This change gives a narrow Python hypothesis a source identity: archive path,
SHA-256 of the complete source, exact byte range of one database-like method
call, and the range of the one simple name interpolated after `SELECT * FROM`
or `SELECT COUNT(*) FROM`. The identity is derived with Python's AST parser;
uploaded code is never imported or executed. It establishes the same syntax
operation, not database-driver provenance, attacker control, or SQL safety.

The supported title grammar is deliberately limited to table-name interpolation.
Compound or unsupported titles, recognized additional concerns, multiple SQL
calls in a quote, extra interpolation slots, conversions, query suffixes,
invalid source, unsafe archive members and exhausted budgets stay unresolved.
Method spellings include asyncpg's `fetch`, `fetchrow` and `fetchval` for grouping
only; this does not extend the separate static SQL detector.

Compatible observations share one row and one score penalty. Their complete
original narratives, conditions, recommendations, producer metadata and statuses
remain in `grouped_originals`. Verification differences cannot be merged. The
group heading explicitly asks for review; repeated model output does not become
independent confirmation of an injection vulnerability.

The fixture retains the six audit narratives, with minimized source and remapped
coordinates. Regression tests exercise the full two-pass model pipeline with
canned responses, scoring, replay of saved groups, distinct operations,
unsupported syntax, provenance, budgets and archive-member checks.

Separately, `.mjs` and `.cjs` now enter the existing model file-selection path.
This matters for CTT's source modules. Existing relevance ranking, exclusions,
token budgets and quote admission still apply: eligibility is not a promise
that every file is sent or that every deterministic verifier supports it.
Pipeline tests prove that both module formats reach the mock model and can
produce quote-checked findings; generated and dependency files remain excluded.

Engine identity is bumped to `2026-10-02-1`, with the corresponding prompt-surface
fingerprint updated, so older cached results do not impersonate this analysis.

## Remaining work

This patch does not automatically dismiss SQL hypotheses about literal lists.
That needs explicit source-bound counterevidence for the specific value flow,
including reassignment and mutation checks. Static silence is not that evidence.
It also does not suppress a finding merely because its explanation retracts a
sentence: the CORS contradiction in the same audit needs its own bounded source
assessment. Existing title/fix self-cancellation handling remains unchanged.
