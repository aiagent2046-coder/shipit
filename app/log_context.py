"""Ambient correlation ids for log records.

The point of this module is that the ~50 existing `logger.info(...)` calls
never have to change. They already carry the ids we care about (`job_id`,
`audit_id`) as positional `%s` args baked into a sentence, which is fine to
read and useless to query. A ContextVar set once per unit of work, plus the
ContextFilter in app/logging_config.py, puts the same ids on *every* record
emitted underneath it as real fields.

Nothing in this module is wired up yet -- setting the context at the four
places that own a unit of work (HTTP middleware, the audit worker's claim
loop, the Fix Pack processor, the monitoring run loop) is a separate change.
Until then every field reads None and simply doesn't appear in the output.

ContextVars are the right primitive rather than a thread-local or a module
global because the audit worker runs its slots as concurrent asyncio tasks in
one process: each task gets a copied context, so a value set inside one slot
cannot leak into another's log lines.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Iterator

# Distinct from request_id: an HTTP request is one unit of work, but so is a
# queued audit job that no request is waiting on. trace_id is whichever id
# identifies the unit of work in hand (the request id at the edge, the job id
# in a worker) so one filter value follows a piece of work end to end. This is
# deliberately NOT W3C traceparent -- work moves between our processes through
# the audit_jobs table, not over the wire, so there is no span context to
# propagate and nothing to be compatible with.
trace_id: ContextVar[str | None] = ContextVar("shipit_trace_id", default=None)
request_id: ContextVar[str | None] = ContextVar("shipit_request_id", default=None)
job_id: ContextVar[str | None] = ContextVar("shipit_job_id", default=None)
audit_id: ContextVar[str | None] = ContextVar("shipit_audit_id", default=None)
account_id: ContextVar[str | None] = ContextVar("shipit_account_id", default=None)

_VARS: dict[str, ContextVar[str | None]] = {
    "trace_id": trace_id,
    "request_id": request_id,
    "job_id": job_id,
    "audit_id": audit_id,
    "account_id": account_id,
}

# What ContextFilter copies onto each record. `step` and `duration_ms` are
# absent on purpose: they change several times within one job, so they belong
# on the individual call as extra={...}, not in ambient context.
LOG_CONTEXT_FIELDS: tuple[str, ...] = tuple(_VARS)


def current_log_context() -> dict[str, str | None]:
    """Every context field and its value in the calling context."""
    return {name: var.get() for name, var in _VARS.items()}


def set_log_context(**values: str | None) -> dict[str, Token[str | None]]:
    """Set one or more context fields, returning tokens for reset_log_context.

    An unknown field raises rather than being silently ignored: a typo here
    would fail as a permanently missing log field, which is exactly the kind
    of bug that is invisible until an incident.
    """
    unknown = set(values) - set(_VARS)
    if unknown:
        raise ValueError(
            f"unknown log context field(s): {', '.join(sorted(unknown))}"
        )
    return {name: _VARS[name].set(value) for name, value in values.items()}


def reset_log_context(tokens: dict[str, Token[str | None]]) -> None:
    """Restore the values captured in the tokens from set_log_context."""
    for name, token in tokens.items():
        _VARS[name].reset(token)


def clear_log_context() -> None:
    """Drop every field back to None.

    For a process that reuses one context across units of work (and for
    tests). Prefer the log_context() manager, which restores the previous
    values instead of flattening them.
    """
    for var in _VARS.values():
        var.set(None)


@contextmanager
def log_context(**values: str | None) -> Iterator[None]:
    """Scope context fields to a block, restoring the previous values after."""
    tokens = set_log_context(**values)
    try:
        yield
    finally:
        reset_log_context(tokens)
