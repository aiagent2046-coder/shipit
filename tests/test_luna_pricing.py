"""Luna budget estimates must cover cache writes and long-context requests."""

from decimal import Decimal

import pytest

from app.llm import pricing


@pytest.mark.parametrize("model", ["gpt-6-luna", "openai/gpt-6-luna"])
def test_luna_published_rates_and_conservative_cache_write_estimate(model):
    assert pricing.price_for(model) == {
        "input": Decimal("0.10"), "output": Decimal("0.50"),
    }
    assert pricing.price_for(model) is not pricing.DEFAULT_PRICE
    # No cache breakdown is available here: estimate every input token as a
    # cache write, while completion tokens already include billed reasoning.
    assert pricing.cost_usd(model, 100_000, 10_000) == Decimal("0.0175")
    assert pricing.cost_usd(model, 1, 1) == Decimal("0.000000625")


@pytest.mark.parametrize("model", ["gpt-6-luna", "openai/gpt-6-luna"])
@pytest.mark.parametrize(
    ("input_tokens", "expected"),
    [
        (271_999, Decimal("0.034999875")),
        (272_000, Decimal("0.035")),
        # Premium applies to the whole request, not merely the excess token.
        (272_001, Decimal("0.06950025")),
    ],
)
def test_luna_long_context_boundary(model, input_tokens, expected):
    assert pricing.cost_usd(model, input_tokens, 2_000) == expected


def test_luna_aggregate_estimate_covers_mixed_short_and_long_requests():
    # The shared API sees a job aggregate. Applying the high rate to this
    # aggregate is conservative for any mix of short and long requests.
    separate_estimates = (
        pricing.cost_usd("gpt-6-luna", 200_000, 10_000)
        + pricing.cost_usd("gpt-6-luna", 300_000, 10_000)
    )
    combined = pricing.cost_usd("gpt-6-luna", 500_000, 20_000)
    assert combined == Decimal("0.14")
    assert combined >= separate_estimates


@pytest.mark.parametrize("input_tokens,output_tokens", [(0, 0), (-5, -5)])
def test_luna_empty_or_negative_usage_has_no_cost(input_tokens, output_tokens):
    assert pricing.cost_usd("gpt-6-luna", input_tokens, output_tokens) == Decimal("0")


@pytest.mark.parametrize(
    "model,expected",
    [
        ("claude-sonnet-4.6", "18.00"),
        ("claude-sonnet-4-6", "18.00"),
        ("claude-sonnet-5", "18.00"),
        ("claude-haiku-4.5", "6.00"),
        ("claude-haiku-4-5", "6.00"),
        ("glm-5.3-flash", "0.33"),
        ("unknown-model", "18.00"),
        ("gpt-6-luna-unknown", "18.00"),
    ],
)
def test_luna_addition_preserves_other_models_and_unknown_aliases(model, expected):
    assert pricing.cost_usd(model, 1_000_000, 1_000_000) == Decimal(expected)
