# External-operation recommendation prerequisites

`app/scan/paid_operation_recommendations.py` adds two deterministic advice
contracts to `prepare_recommendation`. These are conditional prerequisites,
not source-code verdicts. No uploaded code is executed, no provider is called
and no additional model request is made.

## Duplicate operations

The `external_operation_idempotency` check recognizes English advice about
unique indexes/constraints, upserts, existing-result checks, atomic claims or
idempotency in a concurrent external/LLM-operation context. Supported context
labels include LLM, Claude, Anthropic, OpenAI, Replicate API/predictions,
AI-generated messages/replies/responses, AI auto-replies, AI responses and
explicit paid/billable/external/provider calls. A standalone AI label is not
operation context. This keeps equivalent generation advice independent of
whether a reviewer names a provider. Recognition is textual;
provider bindings and actual interleavings are not resolved. A duplicate
database row without this operation context is outside the check.

A final-result constraint can reject a second insert after both external calls
have already happened. A SELECT followed by a call is also read-then-act.
The replacement therefore requires a durable atomic claim, a scoped operation
identity, confirmation of ownership and claim commit **before dispatch**.
It also calls for persisted operation states, result reuse and recovery after
claim failures, crashes and lost provider responses.

A local lease expiry, timeout or attempted cancellation does not establish
what happened remotely. Advice must account for supported provider idempotency
semantics or reconciliation of uncertain completion before another dispatch.
The template does not promise exactly-once external execution or billing.
Concurrent tests should observe external calls as well as stored rows.

## Retry and elapsed-time budgets

The `external_operation_retry_budget` check recognizes English directives
to change retries, polling, timeouts or deadlines in an explicit external/LLM
operation context. A standalone question about provider billing does not
trigger a retry rewrite. The recognizer does not understand arbitrary prose,
resolve aliases or evaluate source control flow.

The replacement distinguishes retryable failures from ordinary terminal
errors, attempts from retries, per-request timeouts from a shared deadline,
and poll counts from elapsed time. Request duration, setup, sleep and backoff
all matter; changing a loop constant does not prove an overall runtime bound.
An uncertain remote outcome must be reconciled before recreating potentially
paid work. Provider request counts and billing must be established separately.

The check does not compute a timeout from source, prove that a configured
retry branch runs, establish cancellation success or infer charges. It leaves
the finding's title, explanation, severity, confidence, conditions and
verification status intact. Misleading source claims require a separate
evidence check; this contract only makes the recommended action conditional.

## Composition and retained advice

These checks compose with the RLS and `timingSafeEqual` contracts in one
recommendation record. The earliest original and its producer/provenance are
retained as explicitly superseded; intermediate active text is also retained
when replaced. Apparently complete model advice still cannot certify a fix.

Supported complementary goals from the canonical original—rate limiting,
webhooks and explicit billing checks—are retained as conditional follow-ups
under `operational_advice_followups`. For example, adding the crypto contract
does not silently drop a separate rate-limit goal. Original snippets and
unsupported goals remain in the superseded original rather than becoming
unchecked alternative fixes. Webhooks require verification of provider
support and delivery handling; rate limits do not replace atomic claims.

Fresh scanner templates are excluded from subsequent textual recognition;
their mention of retries or idempotency must not recursively create another
check. That exclusion is literal and scanner-owned: an arbitrary stored
replacement or forged marker cannot bypass rewriting. JSON round trips and
repeated preparation preserve the original, active text and checks.

HTML and web rendering use the existing additive recommendation-evidence
shape. Rendering an older stored report does not imply these checks ran.
Synthetic regressions cover final-insert advice, read-then-act, ambiguous
completion, numeric poll/retry assumptions, unrelated advice, complete mixed
contracts, complementary goals, forged/stale metadata, preserved originals,
HTML presentation and one-call model integration. No private audit fixture is
committed.
