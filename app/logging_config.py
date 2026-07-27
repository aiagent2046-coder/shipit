"""The one place logging is configured, for every process that has one.

Until now `logging.basicConfig` was called twice with the same literal format
string -- once in app/main.py for the API, once in app/worker/main.py for the
audit worker -- so any change to how we log had to be made in two places and
would silently apply to only one of them. Both now call configure_logging().

`LOG_FORMAT` picks the output shape:

  text (default)  the existing "%(asctime)s %(levelname)s %(name)s %(message)s"
                  line, byte-for-byte. Nothing about the current deployment
                  changes until the variable is set.
  json            one JSON object per line, for `journalctl -o cat | jq`.

Redaction is deliberately NOT a property of the json formatter: it is a filter
on the handler, so a secret is masked in text mode too. A protection that only
works in the format you happen to have enabled is not a protection.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import re
from typing import Any

from app.log_context import LOG_CONTEXT_FIELDS, current_log_context

_VALID_LOG_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}

# The format the API and the worker have both been emitting. Keeping the
# literal here (rather than in two call sites) is most of the point of this
# module; changing it changes every process at once.
TEXT_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"

VALID_LOG_FORMATS = ("text", "json")

# Serialised in this order, and NOTHING else is serialised. An allowlist
# rather than a denylist because the failure modes are not symmetric: a field
# missing from the output is a nuisance, a secret present in it is an
# incident. A future `extra={"payload": <the client's source>}` is dropped
# here without anyone having to have remembered this rule.
ALLOWED_FIELDS: tuple[str, ...] = (
    "ts", "level", "logger", "msg", "module", "line",
    "service", "release", "env", "pid",
    "trace_id", "request_id", "job_id", "audit_id", "account_id",
    "step", "duration_ms", "error_code", "attempt",
    # Metric-as-a-log-event, written by the worker's periodic heartbeat
    # (app/worker/main.py _stats_heartbeat) and read back by
    # `journalctl | jq`. `event` names a KIND of record, where `step` names a
    # phase within one unit of work -- a jq selector needs the former.
    "event", "queue_depth", "oldest_queued_seconds", "active_slots",
    "exc_type", "exc_stack",
)

REDACTED = "[REDACTED]"

# Value-shaped patterns, applied to the fully interpolated message. Matching
# on the shape of the secret rather than the name of the variable holding it
# is what makes this survive a future call site nobody reviewed.
_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    # GitHub: ghp_ (PAT), ghs_ (installation token), gho_/ghu_/ghr_, and the
    # newer fine-grained github_pat_ form.
    (re.compile(r"github_pat_[A-Za-z0-9_]+"), REDACTED),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]+"), REDACTED),
    # A whole PEM block, newlines and all -- the GitHub App private key is the
    # highest-value secret this process holds.
    (re.compile(
        r"-----BEGIN[^-]*PRIVATE KEY-----[\s\S]*?-----END[^-]*PRIVATE KEY-----"
    ), REDACTED),
    # Telegram bot token: <numeric bot id>:<35-char secret>.
    (re.compile(r"\d{6,10}:[A-Za-z0-9_-]{30,40}"), REDACTED),
    # Anthropic / OpenAI style keys.
    (re.compile(r"sk-[A-Za-z0-9_-]{20,}"), REDACTED),
    # Any JWT, which covers the App JWT we mint and any bearer token echoed
    # back to us by an upstream.
    (re.compile(
        r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    ), REDACTED),
    # Postgres DSN: keep the scheme (which is the useful part of the
    # diagnostic) and drop the credentials.
    (re.compile(
        r"(?P<scheme>postgres(?:ql)?://)[^:/?#\s]+:[^@/?#\s]+@"
    ), rf"\g<scheme>{REDACTED}@"),
    # Last resort for a secret whose shape we do not recognise but whose
    # variable name is stated in the message: mask the value, keep the name so
    # the line still says which credential was involved.
    (re.compile(
        r"(?i)\b(token|secret|password|api[_-]?key|pepper)(\s*[=:]\s*)(\S+)"
    ), rf"\1\2{REDACTED}"),
)

_EXC_FORMATTER = logging.Formatter()


def redact(text: str) -> str:
    """Mask every recognised secret in `text`, leaving the rest intact."""
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def service_from_env() -> str:
    """Which process emitted the line, so one query can span several units."""
    return os.environ.get("SHIPIT_SERVICE", "unknown")


def release_from_env() -> str:
    return os.environ.get("SHIPIT_RELEASE", "unknown")


def environment_from_env() -> str:
    return os.environ.get("ENVIRONMENT", "development")


class RedactionFilter(logging.Filter):
    """Mask secrets in the final message text, before any formatter sees it.

    It has to be the *interpolated* message: every existing call site is
    old-style `logger.warning("... %s", value)`, so the secret lives in
    record.args and a filter looking only at record.msg would find the
    template and miss the value. Once redacted the record carries the
    interpolated string with no args, so nothing re-expands it downstream.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 -- a broken format string is the
            # caller's bug; refusing to log it as well would turn a cosmetic
            # problem into a blind spot.
            return True
        redacted = redact(message)
        if redacted != message:
            record.msg = redacted
            record.args = ()

        # A secret can also reach the log through an exception message inside
        # a traceback. Formatting it here (rather than leaving it to the
        # formatter) is what lets both formatters stay unaware of redaction:
        # logging.Formatter reuses a pre-set exc_text verbatim.
        if record.exc_info and not record.exc_text:
            try:
                record.exc_text = redact(
                    _EXC_FORMATTER.formatException(record.exc_info))
            except Exception:  # noqa: BLE001 -- same reasoning as above.
                pass
        return True


class ContextFilter(logging.Filter):
    """Copy the ambient correlation ids (app/log_context.py) onto the record.

    This is the reason no existing logging call had to be touched: a call site
    that knows nothing about any of this still emits job_id/audit_id as long as
    something above it in the call stack set the context.

    An id passed explicitly as extra={"job_id": ...} wins over the ambient one,
    since the caller stating a value is more specific than inheriting it.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        for name, value in current_log_context().items():
            if value is not None and not hasattr(record, name):
                setattr(record, name, value)
        for name in LOG_CONTEXT_FIELDS:
            if not hasattr(record, name):
                setattr(record, name, None)
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line, restricted to ALLOWED_FIELDS.

    Fields that are None are omitted rather than written as null, so a line
    from a process with no request context stays short; `jq 'select(.job_id
    == "x")'` behaves the same either way.
    """

    def format(self, record: logging.LogRecord) -> str:
        computed: dict[str, Any] = {
            "ts": datetime.datetime.fromtimestamp(
                record.created, tz=datetime.timezone.utc
            ).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
            "service": service_from_env(),
            "release": release_from_env(),
            "env": environment_from_env(),
            "pid": record.process,
        }
        if record.exc_info:
            exc_type = record.exc_info[0]
            computed["exc_type"] = exc_type.__name__ if exc_type else None
            # RedactionFilter has normally already written this; format it
            # here too so the formatter is correct on its own.
            computed["exc_stack"] = record.exc_text or redact(
                self.formatException(record.exc_info))

        payload = {}
        for name in ALLOWED_FIELDS:
            value = computed[name] if name in computed else getattr(
                record, name, None)
            if value is not None:
                payload[name] = value
        # default=str so an unexpected non-serialisable value in extra={}
        # degrades to its repr instead of losing the whole line.
        return json.dumps(payload, default=str)


def log_level_from_env() -> str:
    level = (os.environ.get("LOG_LEVEL") or "INFO").upper()
    return level if level in _VALID_LOG_LEVELS else "INFO"


def log_format_from_env() -> str:
    fmt = (os.environ.get("LOG_FORMAT") or "text").strip().lower()
    return fmt if fmt in VALID_LOG_FORMATS else "text"


def build_handler() -> logging.StreamHandler:
    """A stderr handler carrying both filters and the configured formatter."""
    handler = logging.StreamHandler()
    if log_format_from_env() == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(TEXT_FORMAT))
    # Redaction runs first so the context filter (and the formatter) only ever
    # see already-masked text.
    handler.addFilter(RedactionFilter())
    handler.addFilter(ContextFilter())
    return handler


def configure_logging() -> None:
    """Make log level/format explicit instead of inherited-by-accident.

    Before this existed nothing called basicConfig, so app loggers rode on
    Python's last-resort handler (WARNING-only, bare format) -- INFO lines
    never showed and there was no timestamp/level/name prefix to grep in
    journalctl.

    Still routed through basicConfig, and still without force=True, because
    that no-ops when a handler is already installed: it must not fight
    uvicorn's own loggers or double-configure across test app instances.
    """
    logging.basicConfig(level=log_level_from_env(), handlers=[build_handler()])
