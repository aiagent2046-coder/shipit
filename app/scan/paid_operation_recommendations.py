"""Bounded advice contracts for duplicate external operations and retry budgets.

These recognize English recommendation text in an explicit external/LLM
operation context. They do not resolve source bindings, establish a race,
prove billing or certify an apparently correct implementation.
"""
import re


PAID_OPERATION_KIND = "external_operation_idempotency"
RETRY_BUDGET_KIND = "external_operation_retry_budget"
FOLLOWUPS_KIND = "operational_advice_followups"

_EXTERNAL_OPERATION = re.compile(
    r"\b(?:LLM|Claude|Anthropic|OpenAI)\b|"
    r"\bAI(?:[ -]generated\s+(?:messages?|repl(?:y|ies)|responses?)|"
    r"\s+(?:auto[ -]repl(?:y|ies)|responses?))\b|"
    r"\bReplicate\b.{0,60}\b(?:API|prediction|poll|embedding|model|request)\b|"
    r"\b(?:paid|billable|external|provider)\b.{0,50}\b(?:call|request|operation|job|prediction)s?\b",
    re.I,
)
_CONCURRENCY = re.compile(
    r"\b(?:duplicat\w*|dedup\w*|idempoten\w*|concurren\w*|racy|race|twice|double|"
    r"read[ -]then[ -]act|at[ -]most[ -]once)\b", re.I,
)
_DEDUP_ADVICE = re.compile(
    r"\b(?:unique\s+(?:partial\s+)?(?:index|constraint)|upsert|ignoreDuplicates|"
    r"idempoten\w*|dedup\w*|atomic\s+claim|advisory\s+lock)\b|"
    r"\b(?:check|query|select|look)\b.{0,80}\bexisting\b.{0,50}\b(?:reply|message|record|row|result)\b",
    re.I,
)
_RETRY_ADVICE = re.compile(
    r"\b(?:retr(?:y|ies|ied|ying)|maxAttempts|poll(?:ing|s)?|timeout|time[ -]out|"
    r"deadline|maxDuration)\b", re.I,
)
_RETRY_ACTION = re.compile(
    r"\b(?:reduc(?:e|ing)|increas(?:e|ing)|raise|lower|limit|set|add|use|consider|cancel\w*|"
    r"stop|bound|propagate|configure|enforce|apply|change|retry|retrying)\b", re.I,
)

PAID_OPERATION_PREREQUISITES = (
    "Establish the actual concurrent execution paths and logical operation identity, including tenant "
    "and event scope. A duplicate external call or charge has not been verified.",
    "Before the external side effect, acquire a durable atomic claim for that identity and proceed only "
    "as its confirmed owner. Check claim success and commit it before dispatch; a read followed by a "
    "call is not an atomic claim.",
    "A uniqueness constraint or upsert on the final result can limit stored duplicates but cannot undo "
    "external calls already issued. Verify the placement and lifetime of any lock or claim.",
    "Specify in-progress/completed/failed states, ownership, result reuse and recovery after crashes. "
    "A lease expiry or request timeout does not prove that the provider stopped or rejected the work.",
    "If the provider supports idempotency, verify its scope, payload rules and retention and reuse the "
    "same operation key for safe retries. Reconcile uncertain completion before another dispatch; "
    "without such support, do not promise exactly-once external execution or billing.",
    "Test concurrent requests, duplicate deliveries, claim failure, a crash after dispatch and a lost "
    "provider response. Verify both external call counts and persisted outcomes.",
)
PAID_OPERATION_HINT = (
    "First establish the actual concurrent paths and define one logical operation key, including tenant "
    "and event scope. Before issuing the external call, acquire and commit a durable atomic claim; "
    "only its confirmed owner may dispatch the work. Checking for an existing result and then calling "
    "the provider is still read-then-act. A unique constraint or upsert on the final result may prevent "
    "duplicate rows but does not prevent external calls already issued. Specify ownership, in-progress/"
    "completed/failed states, saved result reuse and crash recovery. A lease expiry or timeout is not "
    "proof that the provider did no work. Where supported, verify the provider's idempotency contract "
    "and reuse the same operation key for safe retries; reconcile uncertain completion before another "
    "dispatch. Without that support, do not promise exactly-once external execution or billing. Test "
    "concurrent requests, duplicate deliveries, claim failures, crashes after dispatch and lost "
    "responses, checking external call counts as well as stored results. Neither a duplicate-call "
    "scenario nor a charge has been verified by this advice check."
)

RETRY_BUDGET_PREREQUISITES = (
    "Trace the actual error classifier and call site: distinguish retryable failures from ordinary "
    "terminal errors, and check whether the configured bound counts attempts or retries.",
    "Separate each request's timeout from the overall deadline. Poll counts and sleep intervals do "
    "not bound elapsed time without accounting for request durations and other work.",
    "Include request time, poll waits, backoff and setup in a shared deadline and attempt budget. "
    "Check remaining time before dispatch and propagate cancellation where supported.",
    "A caller timeout or cancellation request does not prove that remote work stopped, that no result "
    "exists or that no charge occurred. Reconcile ambiguous completion and verify provider idempotency "
    "before recreating a potentially paid operation.",
    "Test terminal errors, each supported retryable error, slow polls, deadline exhaustion and an "
    "unknown remote outcome. Verify actual call counts rather than multiplying configuration constants.",
)
RETRY_BUDGET_HINT = (
    "Before changing retry or polling limits, trace the actual retry classifier and its call site: "
    "ordinary terminal errors need not be retried, and a maximum may count attempts rather than retries. "
    "Separate per-request timeouts from the overall deadline. A poll count multiplied by a sleep "
    "interval is not a wall-clock bound; include request durations, setup and backoff. Use a shared "
    "deadline and attempt budget, check remaining time before dispatch and propagate cancellation "
    "where supported. A caller timeout or cancellation request does not establish that remote work "
    "stopped or was unbilled. Reconcile uncertain completion and verify provider idempotency before "
    "creating the operation again. Test terminal and retryable errors, slow requests, exhausted "
    "deadlines and lost responses. Determine actual request counts and billing separately; no numeric "
    "runtime limit, retry multiplier, successful cancellation or charge is verified by this advice check."
)


def _text(raw):
    return " ".join(value for key in ("title", "explanation", "observation", "fix_hint")
                    if isinstance(value := raw.get(key), str))


def needs_operation_idempotency(raw):
    """Require both operation/concurrency context and a relevant advice mechanism."""
    text = _text(raw)
    advice = raw.get("fix_hint")
    return bool(isinstance(advice, str) and _EXTERNAL_OPERATION.search(text)
                and _CONCURRENCY.search(text) and _DEDUP_ADVICE.search(advice))


def needs_retry_budget(raw):
    advice = raw.get("fix_hint")
    return bool(isinstance(advice, str) and _EXTERNAL_OPERATION.search(_text(raw))
                and any(_RETRY_ADVICE.search(part) and _RETRY_ACTION.search(part)
                        for part in re.split(r"[.!?;\n]", advice)))


def operation_idempotency_prerequisites():
    return {
        "kind": PAID_OPERATION_KIND,
        "detail": "External-operation deduplication advice is superseded by conditional prerequisites. "
                  "A read-then-act check or final-result uniqueness does not itself prevent prior external calls.",
        "scope": "English advice mentioning uniqueness, upsert, existing-result checks or idempotency "
                 "in an explicit concurrent external/LLM-operation or AI-generated-message, "
                 "AI-auto-reply or AI-response context. A standalone AI label is outside this check. "
                 "Source bindings, actual "
                 "interleavings, atomicity, provider behavior and billing are not checked.",
        "prerequisites": list(PAID_OPERATION_PREREQUISITES),
        "replacement_fix_hint": PAID_OPERATION_HINT,
    }


def retry_budget_prerequisites():
    return {
        "kind": RETRY_BUDGET_KIND,
        "detail": "External-operation retry, polling or timeout advice is superseded by conditional "
                  "prerequisites. Attempt counts, elapsed time and repeated charges are not interchangeable.",
        "scope": "English advice proposing a change involving retries, polling, timeouts or deadlines in an explicit "
                 "external/LLM-operation context. Error classification, control flow, per-attempt and "
                 "overall limits, provider cancellation and billing are not checked.",
        "prerequisites": list(RETRY_BUDGET_PREREQUISITES),
        "replacement_fix_hint": RETRY_BUDGET_HINT,
    }


def operational_followups(original):
    """Retain bounded complementary goals without reactivating unchecked prose.

    Only canonical original advice is inspected. Generated templates must not
    introduce new checks on the next run. Unrecognized advice remains in the
    superseded original; these goals do not certify any original code example.
    """
    if not isinstance(original, str):
        return None
    conditions = []
    if re.search(r"\brate[ -]limit(?:ing|s)?\b", original, re.I):
        conditions.append(
            "Review rate limiting separately: define the caller/tenant scope, storage and failure "
            "behavior, and apply the limit before expensive work. Rate limiting does not replace "
            "authentication, an atomic operation claim or provider idempotency."
        )
    if re.search(r"\bwebhook\b", original, re.I):
        conditions.append(
            "If replacing polling with a webhook, verify provider support, delivery authentication, "
            "operation correlation, duplicate delivery handling and recovery for missing callbacks. "
            "A webhook alone does not establish exactly-once processing or zero provider cost."
        )
    if re.search(r"\b(?:verif(?:y|ication)|check|confirm|determine)\b.{0,100}"
                 r"\b(?:bill\w*|meter\w*|charg\w*|cost\w*)\b", original, re.I):
        conditions.append(
            "Verify the provider's actual billing terms for creation, polling, cancellation and retries "
            "as applicable; source call counts alone do not establish billable operations."
        )
    if not conditions:
        return None
    return {
        "kind": FOLLOWUPS_KIND,
        "detail": "Supported complementary goals from the original recommendation are retained as "
                  "conditional follow-ups. Original implementations and unsupported advice remain superseded.",
        "scope": "Literal rate-limit, webhook and explicit billing-check goals in original advice only. "
                 "No source behavior, provider capability or proposed implementation is verified.",
        "prerequisites": conditions,
        "replacement_fix_hint": " ".join(conditions),
    }
