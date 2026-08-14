"""LLM client: provider chain with fallback, no vendor SDK.

Order: AITunnel (OpenAI-compatible /chat/completions) if configured,
then direct Anthropic /v1/messages. Direct `httpx` calls — same
pattern proven in production elsewhere. `.env` is the single source
of truth; nothing is hardcoded except API shapes.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, replace

import httpx

# The model we REQUEST when LLM_MODEL is unset. This is Anthropic's canonical
# (dashed) name, correct for the direct Anthropic fallback. AITunnel needs its
# own spelling "claude-sonnet-4.6" (dot) set via LLM_MODEL, or /chat/completions
# 400s (see .env.example). Note the request name and the response data["model"]
# can differ per provider — app/llm/pricing.py keys on the RESPONSE name.
DEFAULT_MODEL = "claude-sonnet-4-6"

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
})


def supports_sampling_params(model: str) -> bool:
    """False when `temperature` must be omitted or the request 400s.

    Unknown models get the permissive answer, which is what every model before
    Claude 5 wanted and what the scanner has always sent. That is the right
    default to fail towards: a wrong `temperature` on a model that dropped it
    is a loud 400 on the first call, while omitting it on a model that wants it
    is silent variance in the findings.
    """
    return model not in MODELS_WITHOUT_SAMPLING_PARAMS


TIMEOUT = httpx.Timeout(120.0, connect=10.0)
TRANSIENT_RETRIES = 2      # extra attempts per provider on 5xx/transport errors
RETRY_BACKOFF_S = 2.0      # linear: 2s, then 4s


class LLMError(Exception):
    """All providers failed."""


@dataclass(frozen=True)
class LLMUsage:
    """Token counts for one .complete() call, read from the provider's
    response `usage` block, plus the model the provider says it actually
    served. This is the raw material for cost accounting (app/llm/pricing.py);
    the provider returns tokens but never a price. A response missing `usage`
    yields zeros rather than an error — a scan must not fail because a provider
    omitted a bookkeeping field."""

    model: str
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass(frozen=True)
class Provider:
    kind: str      # "openai_compat" | "anthropic"
    base_url: str
    api_key: str
    model: str


def providers_from_env() -> list[Provider]:
    chain: list[Provider] = []
    model = os.environ.get("LLM_MODEL", DEFAULT_MODEL)

    aitunnel_key = os.environ.get("AITUNNEL_API_KEY")
    aitunnel_url = os.environ.get("AITUNNEL_BASE_URL")  # e.g. https://.../v1
    if aitunnel_key and aitunnel_url:
        chain.append(Provider("openai_compat", aitunnel_url.rstrip("/"),
                              aitunnel_key, model))

    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    if anthropic_key:
        chain.append(Provider("anthropic", "https://api.anthropic.com",
                              anthropic_key, model))
    return chain


class LLMClient:
    def __init__(self, providers: list[Provider] | None = None,
                 transport: httpx.BaseTransport | None = None):
        self.providers = providers if providers is not None else providers_from_env()
        self._transport = transport  # injectable for tests

    def with_model(self, model: str) -> LLMClient:
        """The same provider chain, asking for a different model.

        The free tier runs a cheaper model than the paid one, and `LLM_MODEL`
        is process-wide: one env var cannot serve two tiers in the same worker.
        Rebuilding the chain per request would re-read the environment and
        could pick up a different set of providers mid-flight, so the chain is
        reused and only the model name is replaced.

        Returns a new client; the original is untouched, which is what keeps a
        preview scan from changing the model of the paid audit running beside
        it. Providers are frozen dataclasses, so the copies cannot alias.
        """
        return LLMClient(
            providers=[replace(p, model=model) for p in self.providers],
            transport=self._transport,
        )

    def complete(self, system: str, user: str,
                 max_tokens: int = 4096) -> tuple[str, LLMUsage]:
        """Returns (text, usage). `usage` carries the token counts and the
        served model for cost accounting — see LLMUsage. Callers that only want
        the text unpack `text, _ = client.complete(...)`."""
        if not self.providers:
            raise LLMError("no providers configured (check .env)")
        errors: list[str] = []
        for p in self.providers:
            for attempt in range(1 + TRANSIENT_RETRIES):
                try:
                    return self._call(p, system, user, max_tokens)
                except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
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
                    errors.append(f"{p.kind}@{p.base_url}: {exc}")
                    break
        raise LLMError("; ".join(errors))

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

        No `thinking` key: it is not part of that wire format, and the
        provider decides. Only the sampling parameter is conditional, for the
        same 400 the Anthropic path avoids.
        """
        body: dict = {
            "model": p.model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if supports_sampling_params(p.model):
            body["temperature"] = 0
        return body

    def _call(self, p: Provider, system: str, user: str,
              max_tokens: int) -> tuple[str, LLMUsage]:
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
                data = resp.json()
                text = "".join(
                    b["text"] for b in data["content"] if b.get("type") == "text"
                )
                return text, _usage_anthropic(data, p.model)

            # openai_compat
            resp = client.post(
                f"{p.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {p.api_key}",
                         "content-type": "application/json"},
                json=self._payload_openai(p, system, user, max_tokens),
            )
            resp.raise_for_status()
            data = resp.json()
            text = data["choices"][0]["message"]["content"]
            return text, _usage_openai(data, p.model)


def _usage_int(usage: dict, key: str) -> int:
    """A token count from a provider `usage` block, coerced to a non-negative
    int. A missing key or a non-numeric value degrades to 0 — usage is
    bookkeeping the scan must never fail on."""
    try:
        return max(0, int(usage.get(key, 0) or 0))
    except (TypeError, ValueError):
        return 0


def _usage_anthropic(data: dict, requested_model: str) -> LLMUsage:
    usage = data.get("usage") or {}
    return LLMUsage(
        model=data.get("model") or requested_model,
        input_tokens=_usage_int(usage, "input_tokens"),
        output_tokens=_usage_int(usage, "output_tokens"),
    )


def _usage_openai(data: dict, requested_model: str) -> LLMUsage:
    usage = data.get("usage") or {}
    return LLMUsage(
        model=data.get("model") or requested_model,
        input_tokens=_usage_int(usage, "prompt_tokens"),
        output_tokens=_usage_int(usage, "completion_tokens"),
    )
