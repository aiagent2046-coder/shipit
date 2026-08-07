"""The paid-LLM kill switch and its short-lived cache.

Extracted from app/main.py verbatim. This is a module rather than a few loose
helpers because the pieces share ONE mutable dict: ``_llm_paid_ops_cache``
holds the last DB read, ``_reset_service_flag_cache`` clears it, and
``_llm_paid_ops_enabled`` populates it. Splitting them across modules would
create two independent caches that silently disagree -- the toggle endpoint
would clear one while the checkout paths kept reading the other.

``_emergency_stop_active`` is the only name here that callers outside this
module need; everything else is the machinery behind it.

``alerts.notify_operator`` is called through its module so the test suite can
patch it on app.alerts, wherever the calling handler ends up living.
"""

from __future__ import annotations

import time

from app import alerts
from app.db import ServiceFlagsRepository


# Emergency-stop flag cache. The kill switch is read on the request path, so it
# is cached for a few seconds to avoid a DB round-trip per request; a pause thus
# takes effect within _FLAG_TTL_S, which is well inside "emergency" tolerance.
_FLAG_TTL_S = 8.0


# How often an engaged emergency stop re-pages the operator. Half an hour, not
# alerts.DEFAULT_THROTTLE_SECONDS (60s): the audit worker consults the stop once
# per loop pass, so the default meant one Telegram message per minute for as
# long as the stop was on.
_PAUSED_ALERT_THROTTLE_S = 1800.0


_llm_paid_ops_cache: dict[str, object] = {"at": 0.0, "enabled": True, "note": None}


def _reset_service_flag_cache() -> None:
    """Force the next _llm_paid_ops_enabled call to re-read the DB. Used by the
    toggle endpoint (so a just-set value is visible immediately) and by tests."""
    _llm_paid_ops_cache["at"] = 0.0


async def _llm_paid_ops_enabled(
    flags_repo: ServiceFlagsRepository,
) -> tuple[bool, str | None]:
    """(enabled, note) for the 'llm_paid_ops' emergency stop, cached for
    _FLAG_TTL_S. A missing row or unconfigured DB reads as enabled (fail-open):
    the kill switch must be an explicit operator action, never the accident of a
    missing table -- an unconfigured dev box must still run scans."""
    now = time.monotonic()
    if now - float(_llm_paid_ops_cache["at"]) < _FLAG_TTL_S:
        return bool(_llm_paid_ops_cache["enabled"]), _llm_paid_ops_cache["note"]  # type: ignore[return-value]
    flag = await flags_repo.get("llm_paid_ops")
    if flag is None:
        enabled, note = True, None
    else:
        enabled, note = bool(flag["enabled"]), flag.get("note")
    _llm_paid_ops_cache.update(at=now, enabled=enabled, note=note)
    return enabled, note


async def _emergency_stop_active(
    flags_repo: ServiceFlagsRepository,
) -> tuple[bool, str | None]:
    """True (with the operator note) when paid LLM ops are paused. Fires the
    mandatory operator alert as a side effect whenever the stop is found engaged;
    notify_operator self-throttles on the dedupe_key, so a burst of blocked
    requests collapses to one alert.

    The window is _PAUSED_ALERT_THROTTLE_S, not the 60s default, because the
    audit worker asks once per loop pass: at the default, an engaged stop paged
    the operator every single minute for as long as it stayed engaged. A
    reminder is wanted -- forgetting the stop is on means silently selling
    nothing -- but one a minute forever is how an operator learns to ignore
    alerts. Deliberately not a per-caller parameter: fifteen tests stub this
    function, so a new keyword would break them all and every future stub would
    have to remember it. One window for one alert is enough."""
    enabled, note = await _llm_paid_ops_enabled(flags_repo)
    if enabled:
        return False, None
    await alerts.notify_operator(
        f"Emergency stop ACTIVE: llm_paid_ops is OFF, rejecting paid LLM ops. "
        f"Note: {note or '(none)'}",
        dedupe_key="llm-paid-ops-paused",
        throttle_seconds=_PAUSED_ALERT_THROTTLE_S,
    )
    return True, note
