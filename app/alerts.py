"""One-shot CLI for operator alerts (`python -m app.alerts "<message>"`),
plus re-exports of the operator-alert workflow.

The workflow itself (notify_operator, the throttle, the admin-chat env)
now lives in `app.notify.operator`, moved there during the import-cycles
fix phase: the notification layering is telegram (transport) <- operator
workflow <- router/selfcheck (what to send), and this module is the
systemd entry point above them. Its invariants (never raises,
self-throttles) are documented there.

This module exists so a systemd `OnFailure=` unit can push a
service-restart/crash alert using the same env and the same Python-side
formatting, without a direct curl to the Bot API and without a new
endpoint or token. See the README.
"""

from __future__ import annotations

import asyncio
import logging
import sys

from app.logging_config import configure_logging
from app.notify.operator import (
    ADMIN_CHAT_ID_ENV, DEFAULT_THROTTLE_SECONDS, _last_sent,
    admin_chat_id_from_env, notify_operator,
)

__all__ = [
    "ADMIN_CHAT_ID_ENV", "DEFAULT_THROTTLE_SECONDS", "_last_sent",
    "admin_chat_id_from_env", "notify_operator",
]

logger = logging.getLogger(__name__)


def _main(argv: list[str]) -> int:
    """`python -m app.alerts "<message>"` — one-shot alert for a systemd
    OnFailure= unit (service crash/restart). Message text (Python-formatted
    by the caller) is joined from argv; exits 0 whether or not a message was
    sent, so it never turns a service failure into a failing OnFailure unit."""
    # The third process entry point (shipit-alert@.service runs `python -m
    # app.alerts`), and the only one that was not configuring logging: without
    # this the line below goes to the root logger's lastResort handler, which
    # drops anything under WARNING, so the one record proving the OnFailure
    # hook ran never reached the journal.
    configure_logging()
    text = " ".join(argv[1:]).strip() or "shipit: service OnFailure alert"
    sent = asyncio.run(notify_operator(text, dedupe_key="systemd-onfailure"))
    logger.info("app.alerts one-shot alert sent=%s", sent)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
