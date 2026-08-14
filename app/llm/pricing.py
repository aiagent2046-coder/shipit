"""LLM price table and cost computation — the money half of Stage 4
accounting (app/llm/client.py records the tokens; this turns them into USD).

There is no reliable programmatic price source: Anthropic's /v1/messages
returns token counts but no price, and the OpenAI-compatible AITunnel
completion body likewise returns only tokens. So the table below is
hand-maintained and MUST be updated by a human when a provider's prices
change or a new model is put into rotation — hence PRICING_LAST_UPDATED,
which is the honesty marker for how stale these numbers might be.

The numbers are Anthropic's published list prices. AITunnel (the primary
provider) resells access and may bill a different amount per token; we
record cost from Anthropic's rate as a consistent internal estimate of the
underlying model cost, not as the exact invoice AITunnel will send.
Reconcile against the real provider invoice roughly quarterly.
"""

from __future__ import annotations

from decimal import Decimal

# The date the prices below were last verified against the providers. Bump it
# whenever PRICE_TABLE changes, so a stale table is visible rather than silent.
PRICING_LAST_UPDATED = "2026-08-14"

_PER_MILLION = Decimal(1_000_000)


# USD per 1,000,000 tokens (MTok), split by input vs output. Keyed by the model
# name the provider reports in the response body (data["model"]) — this is what
# price_for() is handed, and it is PROVIDER-SPECIFIC for the same underlying
# model. AITunnel (the primary provider) returns "claude-sonnet-4.6" (dot);
# the direct Anthropic fallback returns "claude-sonnet-4-6" (dash). See
# .env.example (LLM_MODEL) and README — the same 400-vs-served-name split.
# BOTH spellings must be present, each mapped to the same price, or a served
# model silently falls through to DEFAULT_PRICE (this exact dot/dash miss was
# caught in a live prod run: AITunnel returned the dotted name, the table only
# had the dashed key, and cost was only right by accident because DEFAULT_PRICE
# equalled the single row). Add a row (and bump PRICING_LAST_UPDATED) before
# putting any other model into rotation.
_SONNET_4_6: dict[str, Decimal] = {
    "input": Decimal("3.00"),
    "output": Decimal("15.00"),
}
# Sonnet 5 carries the SAME list price as 4.6 -- but not the same cost per
# audit. It uses the Opus 4.7/4.8 tokenizer, which turns the same repository
# into roughly 30% more tokens, so an audit measured at $0.92 on 4.6 lands
# near $1.20 here. An introductory $2.00/$10.00 runs to 2026-08-31 and is
# deliberately NOT the number below: this table feeds the spend cap and the
# cost accounting, a guard that reads low is worse than one that reads high,
# and a promotional rate that lapses would silently under-count every audit
# after it ends. Billing during the promotion simply comes in under estimate.
#
# There is one spelling because there is one: the dot/dash split existed to
# render "4-6" as "4.6", and a bare "5" has nothing to convert. If a provider
# is ever seen returning another spelling, add it here rather than letting it
# fall through to DEFAULT_PRICE.
_SONNET_5: dict[str, Decimal] = {
    "input": Decimal("3.00"),
    "output": Decimal("15.00"),
}
# The free tier's model. A third of Sonnet's rate per token, which is what
# makes a preview scan affordable to give away -- and a weaker reader, which is
# why a preview publishes findings rather than scores. It is NOT a Claude 5
# model, so it still accepts `temperature` and needs no entry in
# MODELS_WITHOUT_SAMPLING_PARAMS.
#
# Both spellings, for the reason the block above gives: the dashed name is
# Anthropic's and the dotted one is what an OpenAI-compatible reseller returns
# for the same model. A missed spelling here prices a real scan at
# DEFAULT_PRICE -- which reads HIGH, so the failure is a spend cap that trips
# early rather than a bill that arrives unmeasured.
_HAIKU_4_5: dict[str, Decimal] = {
    "input": Decimal("1.00"),
    "output": Decimal("5.00"),
}
PRICE_TABLE: dict[str, dict[str, Decimal]] = {
    "claude-sonnet-4.6": _SONNET_4_6,   # AITunnel / OpenAI-compat response name
    "claude-sonnet-4-6": _SONNET_4_6,   # direct Anthropic response name
    "claude-sonnet-5": _SONNET_5,
    "claude-haiku-4.5": _HAIKU_4_5,
    "claude-haiku-4-5": _HAIKU_4_5,
}

# Fallback for a model not in the table (an unexpected served model, or a new
# one added to the env before this file was updated). Deliberately the most
# expensive KNOWN rates, so an unknown model over-estimates rather than
# under-counts spend — a cost guard that reads low is worse than one that reads
# high. Recomputed from PRICE_TABLE so it can never drift below a real entry.
DEFAULT_PRICE: dict[str, Decimal] = {
    "input": max((p["input"] for p in PRICE_TABLE.values()), default=Decimal("3.00")),
    "output": max((p["output"] for p in PRICE_TABLE.values()), default=Decimal("15.00")),
}


def price_for(model: str) -> dict[str, Decimal]:
    """The (input, output) per-MTok price for a model, or DEFAULT_PRICE when the
    model is unknown (fail-safe high — see DEFAULT_PRICE)."""
    return PRICE_TABLE.get(model, DEFAULT_PRICE)


def cost_usd(model: str, input_tokens: int, output_tokens: int) -> Decimal:
    """Computed USD cost for a job's summed token counts. Decimal throughout so
    money never carries binary-float rounding error; the caller stores it into
    numeric(12,6). Negative/garbage token counts are clamped to 0 so a provider
    returning a nonsense usage block can never produce a negative cost."""
    price = price_for(model)
    inp = Decimal(max(0, int(input_tokens)))
    out = Decimal(max(0, int(output_tokens)))
    return (inp * price["input"] + out * price["output"]) / _PER_MILLION
