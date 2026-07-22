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
PRICING_LAST_UPDATED = "2026-07-22"

_PER_MILLION = Decimal(1_000_000)


# USD per 1,000,000 tokens (MTok), split by input vs output. Keyed by the model
# name the provider reports in the response body (data["model"]), so a served
# model is matched to its own price even when it differs from what we requested.
#
# Only claude-sonnet-4-6 is ever requested today: app/llm/client.py sends a
# single model per provider (DEFAULT_MODEL, overridable by the LLM_MODEL env
# var) and there is no Opus/other model anywhere in the provider chain. Add a
# row here (and bump PRICING_LAST_UPDATED) before putting any other model into
# rotation, or its usage falls back to DEFAULT_PRICE below.
PRICE_TABLE: dict[str, dict[str, Decimal]] = {
    "claude-sonnet-4-6": {
        "input": Decimal("3.00"),
        "output": Decimal("15.00"),
    },
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
