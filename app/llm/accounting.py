"""Actual provider charges, separate from the existing estimated USD budget."""
from __future__ import annotations

from decimal import Decimal, InvalidOperation, localcontext


def provider_usage_summary(attempts: list[dict]) -> dict | None:
    """Unknown charges are never zero, even when another attempt has a price.

    Attempts come from the client's whitelist, enriched with scan coordinates.
    Amounts are decimal strings so JSON persistence cannot round money through
    binary floats. The provider's invoice remains authoritative for timeouts.
    """
    if not attempts:
        return None
    if not isinstance(attempts, (list, tuple)) or any(not isinstance(row, dict) for row in attempts):
        raise ValueError("Invalid provider attempt metadata")
    charges = []
    for attempt in attempts:
        value = attempt.get("cost_rub")
        if value is None or isinstance(value, bool):
            continue
        try:
            amount = Decimal(str(value))
        except (InvalidOperation, ValueError):
            continue
        if amount.is_finite() and amount >= 0:
            charges.append(amount)
    known = None
    if charges:
        # Include the entire decimal span plus possible carry digits; the
        # default 28-digit context can round even a single provider charge.
        with localcontext() as context:
            context.prec = max(
                28,
                max(amount.adjusted() for amount in charges)
                - min(amount.as_tuple().exponent for amount in charges)
                + len(str(len(charges))) + 2,
            )
            known = str(sum(charges, Decimal("0")))
    complete = len(charges) == len(attempts)
    return {
        "version": 1,
        "attempt_count": len(attempts),
        "unpriced_attempts": len(attempts) - len(charges),
        "known_cost_rub": known,
        "cost_rub": known if complete else None,
        "cost_complete": complete,
        "attempts": attempts,
    }
