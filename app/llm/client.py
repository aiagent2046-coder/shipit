"""LLM client: provider chain with fallback, no vendor SDK.

Order: AITunnel (OpenAI-compatible /chat/completions) if configured,
then direct Anthropic /v1/messages. Direct `httpx` calls — same
pattern proven in production elsewhere. `.env` is the single source
of truth; nothing is hardcoded except API shapes.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
import math
import os
import re
import time
from dataclasses import dataclass, replace
from decimal import Decimal, InvalidOperation

import httpx

# The model we REQUEST when LLM_MODEL is unset. This is Anthropic's canonical
# (dashed) name, correct for the direct Anthropic fallback. AITunnel needs its
# own spelling "claude-sonnet-4.6" (dot) set via LLM_MODEL, or /chat/completions
# 400s (see .env.example). Note the request name and the response data["model"]
# can differ per provider — app/llm/pricing.py keys on the RESPONSE name.
DEFAULT_MODEL = "claude-sonnet-4-6"

# Opt-in OpenAI-compatible model; both names were documented by AITunnel.
# The pilot used medium effort without sampling parameters or tools. Keep
# that request contract rather than inheriting Claude's max_tokens payload.
LUNA_MODELS = frozenset({"gpt-6-luna", "openai/gpt-6-luna"})

# Models that REJECT a non-default `temperature` with a 400, and for which
# thinking is on by default.
#
# Claude 5 and Opus 4.7+ removed the sampling parameters: `temperature`,
# `top_p` and `top_k` are no longer accepted, and a request carrying one is
# rejected outright. This scanner has sent `temperature: 0` on every call
# since it was written, so pointing LLM_MODEL at one of these models without
# this table would 400 EVERY request -- not degrade quality, but fail the
# whole LLM stage on every audit, silently delivering static-only results
# under a paid basis. That is the failure llm_failure_kind exists to alert on,
# and it is better not to cause it.
#
# The same models turn adaptive thinking ON when `thinking` is unset, where
# Sonnet 4.6 ran without it. `max_tokens` bounds thinking AND response text
# together, so at the rubric path's 8192 (app/scan/llm_scan.py sends that, not
# the 4096 default) a long think would eat the budget and truncate the JSON the
# rubric parser needs. We ask these models for the 4.6 behaviour explicitly
# rather than inheriting a new default.
#
# Listed by hand in BOTH provider spellings, exactly as PRICE_TABLE is, and
# for the same reason: AITunnel and the direct Anthropic API name the same
# model differently, and a missed spelling here means a 400 in production
# rather than a wrong number. Add a model's rows here AND in
# app/llm/pricing.py before putting it in rotation.
MODELS_WITHOUT_SAMPLING_PARAMS = frozenset({
    *LUNA_MODELS,
    "claude-sonnet-5",
    "claude-opus-5",
    "claude-fable-5",
    "claude-opus-4-7", "claude-opus-4.7",
    "claude-opus-4-8", "claude-opus-4.8",
})

# ...and the ones that do take it, listed rather than inferred.
#
# The first version of this guard tested `"-5" in name`, which reads as "a
# Claude 5 model" and is not: it matches "claude-haiku-4-5", a model that
# accepts `temperature` perfectly well. Version numbers are not a grammar, and
# guessing from a substring gets a tier wrong in whichever direction happens to
# be worse -- here it would have blamed a working model.
#
# So both sets are explicit, and a test requires every model in
# app/llm/pricing.py's PRICE_TABLE to appear in exactly one of them. Adding a
# model to the price table without deciding which way it goes then fails
# loudly, instead of shipping a default that is a 400 on every request.
MODELS_WITH_SAMPLING_PARAMS = frozenset({
    "claude-sonnet-4.6", "claude-sonnet-4-6",
    "claude-haiku-4.5", "claude-haiku-4-5",
    # Operator report, 2026-09-13: AITunnel accepted a request carrying
    # `temperature` (HTTP 200). This records acceptance, not sampling semantics.
    # Reported completion_tokens=3710 with max_tokens=8 does not establish a
    # reasoning-token breakdown or a hard billing limit for a small probe.
    "grok-4.20-multi-agent",
    # Not a Claude model, and the reason it belongs on this side is measured
    # rather than assumed: AITunnel served it a `temperature: 0` request and
    # answered 200. It IS a reasoning model -- 2,067 of 2,981 completion
    # tokens on the probe were reasoning -- which is a different axis from
    # the sampling parameters, and one the OpenAI-compatible payload has no
    # key for anyway: `thinking` is not part of that wire format, so the
    # provider decides. Watched rather than configured; see MODEL_INPUT_TOKENS
    # below for why it is deliberately not listed there.
    "glm-5.3-flash",
})

# How many input tokens we are willing to build a prompt up to, per model.
#
# MEASURED, and the measurement is why this table exists. tscircuit.com sent
# 3,777,616 characters across four rubric prompts. Sonnet 4.6 reported
# 1,256K input tokens -- 3.0 characters per token, all of it. Haiku 4.5, on
# the SAME bytes (the comparison script fetches the archive once on purpose),
# reported 330K: 11.4 characters per token, about a quarter. It then returned
# 19 findings and a score of 5.3, and nothing anywhere recorded that three
# quarters of the repository had never reached the model.
#
# app/scan/llm_scan.py's MAX_TOTAL_CHARS is 900_000, which its own comment
# calls "~225K tokens" on a 4-chars-per-token assumption. Code is 3.0, so a
# rubric prompt is ~315K tokens -- past the 200K window every current Claude
# model has except with the long-context beta. Sonnet 4.6 is served with it
# and swallowed the prompt; Haiku 4.5 is not, and the provider cut the request
# down to fit without saying so.
#
# That makes this OUR defect and not the provider's. We built a prompt for a
# window we never checked the model had. The difference matters beyond blame:
# when select_files drops a file it drops the least relevant one and marks the
# cut, and the system prompt tells the model that absence inside a truncated
# file proves nothing. When the provider drops it, we do not know what went,
# the model is not told, and its silence about a region it never saw reads
# exactly like a clean bill of health.
#
# An unlisted model gets the SMALL window. A prompt built for 200K on a model
# that has 1M spends less than it could; the reverse reviews a fraction of the
# code and prints a number for the whole of it.
MODEL_INPUT_TOKENS = {
    # Served with the long-context beta: measured accepting ~315K tokens in a
    # single request. The exact ceiling above that is untested -- anything at
    # or over ~400K is equivalent at today's MAX_TOTAL_CHARS.
    "claude-sonnet-4.6": 1_000_000, "claude-sonnet-4-6": 1_000_000,
    # 200K, and the reason this table exists.
    "claude-haiku-4.5": 200_000, "claude-haiku-4-5": 200_000,
}

# Deliberately the standard window, not the largest one. See above: guessing
# high is the failure mode that ships a score for code nobody read.
#
# claude-sonnet-5 is in PRICE_TABLE and absent from MODEL_INPUT_TOKENS, so it
# lands here. That is a real reduction for anyone who switches to it, and it
# is the right default until someone runs scripts/prompt_sizes.py --compare
# against it. Measuring is one $4 audit.
#
# glm-5.3-flash is priced and likewise unlisted, for the same reason and one
# more: nobody here has measured its window, and a number copied from a model
# card would be a guess wearing a measurement's clothes. 200K is what the free
# preview already sends to Haiku, so listing nothing costs the preview nothing
# today. Note also that CHARS_PER_TOKEN is one global constant measured on
# Claude (3.0), while GLM tokenised the same committed JavaScript at 3.94
# chars/token -- so a prompt built for it is about 24% smaller than its budget
# allows. Wasteful, not dangerous, and the safe direction of the two.
DEFAULT_INPUT_TOKENS = 200_000

# Luna deliberately uses the conservative default above. The small pilot did
# not measure its advertised million-token context on repository-sized input.

# Characters per token on the code this scanner sends: 3,777,616 / 1,256,000
# over four real rubric prompts. Not the ~4 that prose gets, which is where
# MAX_TOTAL_CHARS's "~225K tokens" came from and why it was 33% optimistic.
CHARS_PER_TOKEN = 3.0

# Held back from the input budget for the response. The rubric path asks for
# max_tokens=8192, and on models where thinking shares that budget it is the
# whole of it. Providers differ on whether the response competes with the
# input window at all; reserving when it does not costs 8K tokens of prompt.
RESPONSE_RESERVE_TOKENS = 8_192


def input_char_budget(model: str) -> int:
    """Characters one request to `model` may contain, system prompt included."""
    window = MODEL_INPUT_TOKENS.get(model, DEFAULT_INPUT_TOKENS)
    return int(max(0, window - RESPONSE_RESERVE_TOKENS) * CHARS_PER_TOKEN)


def supports_sampling_params(model: str) -> bool:
    """False when `temperature` must be omitted or the request 400s.

    Unknown models get the permissive answer, which is what every model before
    Claude 5 wanted and what the scanner has always sent. That is the right
    default to fail towards: a wrong `temperature` on a model that dropped it
    is a loud 400 on the first call, while omitting it on a model that wants it
    is silent variance in the findings.
    """
    return model not in MODELS_WITHOUT_SAMPLING_PARAMS


# Read timeout for ONE completion request. 120s default: measured enough for
# every non-reasoning provider (claude-haiku-4.5 completed all four rubrics
# of a 1,403-file repo in 75s total, 2026-09-24) and short enough to degrade
# to an honest failed rubric instead of hanging a worker. Reasoning models
# need more: glm-5.3-flash with the output ceiling raised to 32768 stopped
# returning at the length boundary and then outlived this timeout mid-think
# ("The read operation timed out", calls=0, measured 2026-09-24). Such runs
# set LLM_READ_TIMEOUT (seconds) together with RUBRIC_MAX_TOKENS. A bad
# value fails at import, like PAID_AUDIT_PASSES.
try:
    LLM_READ_TIMEOUT = float(os.environ.get("LLM_READ_TIMEOUT", "120"))
except ValueError:
    raise ValueError("LLM_READ_TIMEOUT must be a finite positive number") from None
if not math.isfinite(LLM_READ_TIMEOUT) or LLM_READ_TIMEOUT <= 0:
    raise ValueError("LLM_READ_TIMEOUT must be a finite positive number")
TIMEOUT = httpx.Timeout(LLM_READ_TIMEOUT, connect=10.0)
TRANSIENT_RETRIES = 2      # extra attempts per provider on 5xx/transport errors
RETRY_BACKOFF_S = 2.0      # linear: 2s, then 4s


class LLMError(Exception):
    """All providers failed."""

    def __init__(self, message: str, *, attempts: tuple[dict, ...] = ()):
        super().__init__(message)
        self.attempts = attempts


@dataclass(frozen=True)
class LLMUsage:
    """Token counts for one .complete() call, read from the provider's
    response `usage` block, plus the model the provider says it actually
    served. This is the raw material for cost accounting (app/llm/pricing.py).
    `attempts` also retains reported prices and usage from failed requests;
    absent prices remain unknown, never an invented zero. Missing `usage`
    yields zeros rather than an error — a scan must not fail because a provider
    omitted a bookkeeping field."""

    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    attempts: tuple[dict, ...] = ()


@dataclass(frozen=True)
class Provider:
    kind: str      # "openai_compat" | "anthropic"
    base_url: str
    api_key: str
    model: str


# Where each provider's own spelling of the model name is configured.
#
# The same model is named differently per provider: AITunnel wants
# claude-sonnet-4.6 (dot), the direct Anthropic API wants claude-sonnet-4-6
# (dash), and the wrong one is a 400 on every request. One LLM_MODEL for the
# whole chain therefore cannot be right for both -- it configures the primary
# and mis-configures the fallback, which fails for a reason unrelated to the
# outage the fallback exists to survive. A spare tyre that only fits the car
# you are not driving.
#
# Per-provider variables rather than translating a dot to a dash. A mechanical
# swap is inference about a naming scheme nobody promised to keep, and this
# project has been burned by exactly that: `"-5" in name` read as "a Claude 5
# model" and matched claude-haiku-4-5. Version numbers are not a grammar. Both
# spellings are already listed by hand in PRICE_TABLE, in the sampling-param
# sets and in MODEL_INPUT_TOKENS; this is the same discipline applied to
# configuration.
_MODEL_ENV_BY_KIND = {
    "openai_compat": "AITUNNEL_LLM_MODEL",
    "anthropic": "ANTHROPIC_LLM_MODEL",
}


def model_for_kind(kind: str, fallback: str) -> str:
    """The model name to request from a provider of this kind.

    Falls back to the shared name, so a single-provider deployment -- which is
    every deployment today -- keeps working with LLM_MODEL alone and nothing
    to learn. The per-kind variable only has to be set by an operator who runs
    two providers, which is exactly the operator this exists for.
    """
    return os.environ.get(_MODEL_ENV_BY_KIND.get(kind, ""), "") or fallback


def providers_from_env() -> list[Provider]:
    chain: list[Provider] = []
    model = os.environ.get("LLM_MODEL", DEFAULT_MODEL)

    aitunnel_key = os.environ.get("AITUNNEL_API_KEY")
    aitunnel_url = os.environ.get("AITUNNEL_BASE_URL")  # e.g. https://.../v1
    if aitunnel_key and aitunnel_url:
        chain.append(Provider("openai_compat", aitunnel_url.rstrip("/"),
                              aitunnel_key,
                              model_for_kind("openai_compat", model)))

    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    if anthropic_key:
        chain.append(Provider("anthropic", "https://api.anthropic.com",
                              anthropic_key,
                              model_for_kind("anthropic", model)))
    return chain


def _answer_or_raise(text: object, p: Provider, choice: dict,
                     usage: object) -> str:
    """The completion text, or a ValueError naming why there is none.

    MEASURED, on glm-5.3-flash against a real security rubric: the provider
    answered 200 with `choices[0].message.content` set to null. That reached
    parse_findings as None and the whole scan died on
    `AttributeError: 'NoneType' object has no attribute 'strip'` -- an
    unhandled crash in the worker, not a degraded audit.

    Two ways it can happen and neither is exotic. A reasoning model spends
    `max_tokens` on reasoning and has nothing left for the answer (the rubric
    path asks for 8192, and this model has been seen using 2,067 of 2,981
    completion tokens on thinking alone). A filter or a truncation can also
    return an empty string. Any provider can do this.

    RAISED, not returned as "": an empty answer parses to zero findings, and
    zero findings is the report saying it looked and saw nothing. This scan
    did not look. ValueError is already in complete()'s except clause and is
    NOT treated as transient, which is right -- a model that spent its budget
    thinking will spend it again -- so the chain moves on and the audit ends
    as an honest `failed: ...` rather than a clean bill of health.

    The message carries finish_reason and the token counts and nothing else:
    those diagnose it, and the response body holds the customer's code.
    """
    if isinstance(text, str) and text.strip():
        return text
    counts = usage if isinstance(usage, dict) else {}
    detail = ", ".join(
        f"{k}={counts[k]}" for k in
        ("prompt_tokens", "completion_tokens", "input_tokens", "output_tokens")
        if k in counts
    )
    raise ValueError(
        f"{p.model} returned no answer text "
        f"(finish_reason={choice.get('finish_reason') or choice.get('stop_reason')!r}"
        + (f", {detail}" if detail else "") + ")"
    )


class LLMClient:
    def __init__(self, providers: list[Provider] | None = None,
                 transport: httpx.BaseTransport | None = None):
        self.providers = providers if providers is not None else providers_from_env()
        self._transport = transport  # injectable for tests

    def with_model(self, model: str, *,
                   by_kind: Mapping[str, str] | None = None) -> LLMClient:
        """The same provider chain, asking for a different model.

        The free tier runs a cheaper model than the paid one, and `LLM_MODEL`
        is process-wide: one env var cannot serve two tiers in the same worker.
        Rebuilding the chain per request would re-read the environment and
        could pick up a different set of providers mid-flight, so the chain is
        reused and only the model name is replaced.

        Returns a new client; the original is untouched, which is what keeps a
        preview scan from changing the model of the paid audit running beside
        it. Providers are frozen dataclasses, so the copies cannot alias.

        A shallow copy of self rather than a fresh LLMClient(...). Constructing
        the base class discards whatever the receiver actually was: a subclass
        would silently degrade to the real HTTP path, which is exactly what
        happened the first time this ran against a test double -- the override
        vanished and the "fake" reached out to a real URL and took a 403. In
        production nothing subclasses this today, but a method that quietly
        returns a different type than its receiver is a trap set for later.

        `by_kind` carries the per-provider spellings, the same problem
        providers_from_env solves with AITUNNEL_LLM_MODEL / ANTHROPIC_LLM_MODEL
        and for the same reason: one name stamped onto a chain configures the
        primary and mis-configures the fallback. It is optional because a
        one-provider chain -- every deployment today -- has nothing to
        disambiguate.
        """
        clone = copy.copy(self)
        clone.providers = [
            replace(p, model=(by_kind or {}).get(p.kind, model))
            for p in self.providers
        ]
        return clone

    def input_char_budget(self) -> int:
        """Characters a single request may contain on THIS chain.

        The smallest window in the chain, not the first provider's. A prompt
        is built once and then offered to each provider in turn until one
        answers, so a prompt sized for the primary is the prompt the fallback
        gets -- and a fallback exists to be used on the day the primary is
        down, which is the worst day to start silently reviewing a third of
        the repository. Sizing to the smallest costs coverage only while the
        primary is healthy, and never costs correctness.

        An empty chain answers with the default rather than 0: no request will
        be sent anyway, and returning 0 would make select_files pick nothing
        and the failure look like an empty repository.
        """
        if not self.providers:
            return input_char_budget("")
        return min(input_char_budget(p.model) for p in self.providers)

    def complete(self, system: str, user: str,
                 max_tokens: int = 4096) -> tuple[str, LLMUsage]:
        """Returns (text, usage). `usage` carries the token counts and the
        served model for cost accounting — see LLMUsage. Callers that only want
        the text unpack `text, _ = client.complete(...)`."""
        if not self.providers:
            raise LLMError("no providers configured (check .env)")
        errors: list[str] = []
        attempts: list[dict] = []
        for p in self.providers:
            for attempt in range(1 + TRANSIENT_RETRIES):
                started = time.monotonic()
                try:
                    text, usage = self._call(p, system, user, max_tokens)
                    attempts.extend(usage.attempts or (
                        _attempt_record(p, {}, started),))
                    return text, replace(usage, attempts=tuple(attempts))
                except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
                    attempts.extend(getattr(exc, "attempts", ()) or (
                        _attempt_record(p, {}, started, exc),))
                    # 5xx and transport/timeout errors are transient:
                    # retry the SAME provider with backoff (a single
                    # provider-side 500 killed a whole audit stage in a
                    # real run; the chain is often length 1, so "next
                    # provider" is no safety net). 4xx means OUR request
                    # is wrong — retrying it is spam.
                    transient = isinstance(exc, httpx.TransportError) or (
                        isinstance(exc, httpx.HTTPStatusError)
                        and exc.response.status_code >= 500
                    )
                    if transient and attempt < TRANSIENT_RETRIES:
                        time.sleep(RETRY_BACKOFF_S * (attempt + 1))
                        continue
                    errors.append(f"{p.kind}@{p.base_url}: {_detail(exc)}")
                    break
        raise LLMError("; ".join(errors), attempts=tuple(attempts))

    @staticmethod
    def _payload_anthropic(p: Provider, system: str, user: str,
                           max_tokens: int) -> dict:
        """The /v1/messages body, shaped to what this model accepts.

        Audit pipeline: reproducibility over creativity. On models that take
        it, temperature 0 stays -- an unset temperature is the provider
        default (usually 1.0) and produces finding sets that differ more
        between runs. It was never the whole story even there: the docstring
        of app/scan/pipeline.py:content_digest records that the scan "returns
        a different findings set (and thus a different score) run to run even
        at temperature=0", which is why the content-digest cache, not this
        parameter, is what makes a re-audit reproducible.
        """
        if p.model in LUNA_MODELS:
            raise ValueError("Luna requires an OpenAI-compatible provider; configure ANTHROPIC_LLM_MODEL separately")
        body: dict = {
            "model": p.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        if supports_sampling_params(p.model):
            body["temperature"] = 0
        else:
            # Keep the Sonnet 4.6 behaviour rather than inheriting the new
            # default: max_tokens caps thinking and text together, and a long
            # think would truncate the JSON the rubric parser reads.
            body["thinking"] = {"type": "disabled"}
        return body

    @staticmethod
    def _payload_openai(p: Provider, system: str, user: str,
                        max_tokens: int) -> dict:
        """The /chat/completions body for the OpenAI-compatible provider.

        Luna's completion limit includes reasoning and visible text. Its
        explicit medium effort matches the reviewed pilot. Claude retains its
        existing max_tokens and sampling/cache behavior.
        """
        body: dict = {
            "model": p.model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if p.model in LUNA_MODELS:
            body.pop("max_tokens")
            body["max_completion_tokens"] = max_tokens
            body["reasoning_effort"] = "medium"
        if supports_sampling_params(p.model):
            body["temperature"] = 0
        if (os.environ.get("AITUNNEL_PROMPT_CACHE") == "1"
                and p.kind == "openai_compat"
                and p.base_url == "https://api.aitunnel.ru/v1"
                and p.model in {"claude-sonnet-4.6", "claude-sonnet-4-6"}):
            # Explicit markers use the provider's default five-minute TTL.
            # Preserve every prompt byte; only the content envelope changes.
            for message in body["messages"]:
                message["content"] = [{
                    "type": "text", "text": message["content"],
                    "cache_control": {"type": "ephemeral"},
                }]
        return body

    def _call(self, p: Provider, system: str, user: str,
              max_tokens: int) -> tuple[str, LLMUsage]:
        started = time.monotonic()
        data: dict = {}
        try:
            data = self._request(p, system, user, max_tokens)
            if not isinstance(data, dict):
                data = {}
                raise ValueError("invalid_response_shape")
            if p.kind == "anthropic":
                text = "".join(
                    b["text"] for b in data["content"] if b.get("type") == "text"
                )
                text = _answer_or_raise(text, p, data, data.get("usage"))
                usage = _usage_anthropic(data, p.model)
            else:
                choice = data["choices"][0]
                if p.model in LUNA_MODELS:
                    if data.get("model") not in LUNA_MODELS:
                        raise ValueError("Luna served_model_mismatch")
                    if choice.get("finish_reason") != "stop" or choice["message"].get("refusal"):
                        # Even a parseable [] is not a completed review when
                        # reasoning exhausted the limit or the model refused.
                        # The exception path retains usage and billed cost.
                        raise ValueError("Luna incomplete_or_refused_answer")
                text = _answer_or_raise(choice["message"].get("content"),
                                        p, choice, data.get("usage"))
                usage = _usage_openai(data, p.model)
        except (httpx.HTTPError, KeyError, IndexError, ValueError,
                TypeError, AttributeError) as exc:
            if isinstance(exc, httpx.HTTPStatusError):
                try:
                    error_data = exc.response.json()
                    if isinstance(error_data, dict):
                        data = error_data
                except (ValueError, httpx.HTTPError):
                    pass
            record = _attempt_record(p, data, started, exc)
            # Malformed response shapes should follow the same non-transient
            # fallback as missing fields, without losing received billing.
            if isinstance(exc, (TypeError, AttributeError)):
                converted = ValueError("invalid_response_shape")
                converted.attempts = (record,)
                raise converted from exc
            exc.attempts = (record,)
            raise
        return text, replace(usage, attempts=(_attempt_record(p, data, started),))

    def _request(self, p: Provider, system: str, user: str,
                 max_tokens: int) -> dict:
        with httpx.Client(timeout=TIMEOUT, transport=self._transport) as client:
            if p.kind == "anthropic":
                resp = client.post(
                    f"{p.base_url}/v1/messages",
                    headers={
                        "x-api-key": p.api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json=self._payload_anthropic(p, system, user, max_tokens),
                )
                resp.raise_for_status()
                return resp.json()

            # openai_compat
            resp = client.post(
                f"{p.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {p.api_key}",
                         "content-type": "application/json"},
                json=self._payload_openai(p, system, user, max_tokens),
            )
            resp.raise_for_status()
            return resp.json()


# How much of a provider's error body to keep. Enough for the sentence that
# says what was wrong; short enough that a body echoing part of the request
# cannot put a meaningful amount of a customer's code into a log line.
_DETAIL_CHARS = 200


def _detail(exc: Exception) -> str:
    """The exception, plus what the provider actually said.

    httpx's message for a 4xx is "Client error '400 Bad Request' for url ...",
    which names the status and nothing else. That cost a real diagnosis: a 400
    on a free-tier audit could have been a context window overflow, a model
    name the provider spells differently, or a malformed body, and the three
    have completely different fixes. With the body dropped there was no way to
    tell them apart from the outside, and the caller could only guess.

    A body that cannot be read is not an error worth raising over the error --
    the exception is the message either way.
    """
    if not isinstance(exc, httpx.HTTPStatusError):
        return str(exc)
    try:
        body = " ".join((exc.response.text or "").split())
    except Exception:                       # noqa: BLE001 - never mask the 4xx
        body = ""
    return f"{exc}: {body[:_DETAIL_CHARS]}" if body else str(exc)


def _mapping(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _nonnegative_decimal(value: object) -> Decimal | None:
    if isinstance(value, bool) or not isinstance(value, (int, float, str, Decimal)):
        return None
    try:
        # Bookkeeping must not allocate an unbounded integer or decimal string
        # because a provider accidentally returned an extreme exponent.
        raw = str(value)
        if len(raw) > 128:
            return None
        number = Decimal(raw)
        if not number.is_finite() or number < 0 or abs(number.adjusted()) > 100:
            return None
        return number
    except (ValueError, InvalidOperation):
        return None


def _token_count(value: object) -> int | None:
    number = _nonnegative_decimal(value)
    if number is None or number != number.to_integral_value() or number > 2**63 - 1:
        return None
    return int(number)


def _reported_cost(value: object) -> str | None:
    number = _nonnegative_decimal(value)
    if number is None:
        return None
    if not number:
        return "0"
    text = format(number, "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def _metadata_name(value: object) -> str | None:
    # Identifiers only: never carry arbitrary response text into the ledger.
    if isinstance(value, str) and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._/-]{0,127}", value):
        return value
    return None


def _attempt_record(p: Provider, data: dict, started: float,
                    exc: Exception | None = None) -> dict:
    usage = _mapping(data.get("usage"))
    # Some compatible providers place the billed amount at response level.
    # Only an absent/null nested value falls back; explicit zero is a price,
    # and a malformed nested value must remain unknown rather than be hidden.
    cost = usage.get("cost_rub")
    if cost is None:
        cost = data.get("cost_rub")
    prompt_details = _mapping(usage.get("prompt_tokens_details"))
    completion_details = _mapping(usage.get("completion_tokens_details"))
    if p.kind == "anthropic":
        input_tokens = usage.get("input_tokens")
        output_tokens = usage.get("output_tokens")
        cached = usage.get("cache_read_input_tokens")
        written = usage.get("cache_creation_input_tokens")
        finish = data.get("stop_reason")
    else:
        input_tokens = usage.get("prompt_tokens")
        output_tokens = usage.get("completion_tokens")
        cached = prompt_details.get("cached_tokens")
        written = prompt_details.get("cache_write_tokens")
        choices = data.get("choices")
        choice = _mapping(choices[0]) if isinstance(choices, list) and choices else {}
        finish = choice.get("finish_reason")
    return {
        "provider_kind": _metadata_name(p.kind),
        "requested_model": _metadata_name(p.model),
        "model": _metadata_name(data.get("model")),
        "input_tokens": _token_count(input_tokens),
        "output_tokens": _token_count(output_tokens),
        "cached_tokens": _token_count(cached),
        "cache_write_tokens": _token_count(written),
        "reasoning_tokens": _token_count(completion_details.get("reasoning_tokens")),
        "cost_rub": _reported_cost(cost),
        "finish_reason": _metadata_name(finish),
        "error": (f"http_{exc.response.status_code}"
                  if isinstance(exc, httpx.HTTPStatusError)
                  else type(exc).__name__ if exc is not None else None),
        "seconds": round(max(0.0, time.monotonic() - started), 6),
    }


def _usage_int(usage: object, key: str) -> int:
    """A token count from a provider `usage` block, coerced to a non-negative
    int. A missing key or a non-numeric value degrades to 0 — usage is
    bookkeeping the scan must never fail on."""
    return _token_count(_mapping(usage).get(key)) or 0


def _usage_anthropic(data: dict, requested_model: str) -> LLMUsage:
    usage = data.get("usage") or {}
    return LLMUsage(
        model=(data["model"] if isinstance(data.get("model"), str)
               and data["model"] else requested_model),
        input_tokens=_usage_int(usage, "input_tokens"),
        output_tokens=_usage_int(usage, "output_tokens"),
    )


def _usage_openai(data: dict, requested_model: str) -> LLMUsage:
    usage = data.get("usage") or {}
    return LLMUsage(
        model=(data["model"] if isinstance(data.get("model"), str)
               and data["model"] else requested_model),
        input_tokens=_usage_int(usage, "prompt_tokens"),
        output_tokens=_usage_int(usage, "completion_tokens"),
    )
