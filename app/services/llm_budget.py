"""Anonymous LLM spend budget: the daily cap gate for new audits.

Moved from app/main.py during the import-cycles fix phase so the MCP
tools and the worker can share it without either importing the HTTP
entry point. The cap itself stays env-configurable the same way.
"""
from __future__ import annotations

import os
from decimal import Decimal

from app.db import LlmUsageRepository
from app.notify import alerts

DEFAULT_DAILY_SPEND_CAP_USD = Decimal(
    os.environ.get("DEFAULT_DAILY_SPEND_CAP_USD", "20.00"))
_ANON_SPEND_ALERT_FRACTION = Decimal("0.8")


async def _anon_daily_cap_exceeded(llm_usage_repo: LlmUsageRepository) -> bool:
    """True when anonymous traffic has spent at least the daily cap today, so a
    new anonymous audit must degrade to static-only. Fires the 80% operator
    alert as a side effect. A None sum (DATABASE_URL unset) reads as False --
    there is no journal to cap against."""
    spend = await llm_usage_repo.sum_anon_spend_today()
    if spend is None:
        return False
    if spend >= DEFAULT_DAILY_SPEND_CAP_USD * _ANON_SPEND_ALERT_FRACTION:
        await alerts.notify_operator(
            f"Anonymous LLM spend today is ${spend:.2f}, at/over "
            f"{int(_ANON_SPEND_ALERT_FRACTION * 100)}% of the "
            f"${DEFAULT_DAILY_SPEND_CAP_USD:.2f} daily cap.",
            dedupe_key="anon-budget-80",
        )
    return spend >= DEFAULT_DAILY_SPEND_CAP_USD
