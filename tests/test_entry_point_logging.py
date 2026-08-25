"""Every `python -m` entry point must redact before it logs.

WHAT HAPPENED. app/notify/selfcheck.py called logging.basicConfig, and its
first run on production wrote the Telegram bot token into the journal in full.
httpx logs the request URL at INFO; for the Bot API the token IS the URL; and
RedactionFilter -- which strips exactly that pattern -- lives in
configure_logging(), which basicConfig does not install.

The token had to be revoked. Nothing in the suite noticed, because every other
test process happens to configure logging some other way, and because a leak is
invisible to a test that only checks what a function returns.

WHY A SWEEP AND NOT ONE TEST. app/alerts.py::_main already carries a comment
saying it was "the only one that was not configuring logging" and fixing it.
That comment was true when written and did not stop the next entry point from
repeating it, because a comment guards the file it is in. There were four
entry points; there will be a fifth.

NOT CONFIGURING AT ALL IS NOT A DEFENCE. Records then ride the root logger's
lastResort handler, which applies no filters -- it is quiet only because it
also drops anything below WARNING. One WARNING carrying a token is the whole
distance between that and the journal.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path

import pytest

from app.logging_config import RedactionFilter, redact

REPO_ROOT = Path(__file__).resolve().parents[1]
APP = REPO_ROOT / "app"

# The one file allowed to call basicConfig: it is what configure_logging is
# implemented in terms of.
_MAY_CALL_BASIC_CONFIG = {APP / "logging_config.py"}


def entry_points() -> list[Path]:
    """Every module runnable as `python -m`."""
    found = []
    for path in sorted(APP.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if '__name__ == "__main__"' in text or "__name__ == '__main__'" in text:
            found.append(path)
    return found


def test_the_sweep_is_actually_finding_entry_points() -> None:
    """A sweep that silently matches nothing passes forever."""
    names = {p.name for p in entry_points()}
    assert {"selfcheck.py", "alerts.py"} <= names, names


@pytest.mark.parametrize(
    "path", entry_points(), ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_every_entry_point_configures_logging_through_the_redactor(
    path: Path,
) -> None:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    called = {
        node.func.attr if isinstance(node.func, ast.Attribute)
        else getattr(node.func, "id", "")
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
    }

    assert "configure_logging" in called, (
        f"{path.relative_to(REPO_ROOT)} is runnable as `python -m` and never "
        "calls configure_logging(), so nothing it logs is redacted"
    )
    if path not in _MAY_CALL_BASIC_CONFIG:
        assert "basicConfig" not in called, (
            f"{path.relative_to(REPO_ROOT)} calls logging.basicConfig, which "
            "installs no RedactionFilter; use configure_logging()"
        )


def test_a_bot_token_in_a_url_is_redacted() -> None:
    """The exact shape that reached the journal: httpx's INFO line, whose URL
    carries the credential."""
    leaked = (
        "HTTP Request: POST https://api.telegram.org/"
        "bot8741366601:AAFW6hcjSsYaI5uTwY8tqCjZFVDXauvUwgk/getMe"
    )  # scan-allow: revoked token, kept verbatim as the regression case

    cleaned = redact(leaked)

    assert "AAFW6hcjSsYaI5uTwY8tqCjZFVDXauvUwgk" not in cleaned
    assert "8741366601" not in cleaned
    assert "api.telegram.org" in cleaned, "the useful half must survive"


def test_the_filter_cleans_a_record_the_way_a_handler_would() -> None:
    """redact() being right is not the same as it being reached. This is the
    record path -- message and args -- that a handler actually formats."""
    record = logging.LogRecord(
        name="httpx", level=logging.INFO, pathname=__file__, lineno=1,
        msg="HTTP Request: POST %s",
        args=("https://api.telegram.org/bot8741366601:"
              "AAFW6hcjSsYaI5uTwY8tqCjZFVDXauvUwgk/getMe",),
        exc_info=None,
    )

    RedactionFilter().filter(record)

    assert "AAFW6hcjSsYaI5uTwY8tqCjZFVDXauvUwgk" not in record.getMessage()
