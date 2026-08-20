"""The way we reach a person must not be owned by the way they pay.

WHY THIS IS A TEST AND NOT A COMMENT. The Bot API client grew inside
app/billing/telegram_stars.py, because when it was written the bot's whole
reason to exist was selling Stars. app/alerts.py -- the operator's only alert
channel, the thing that says a Fix Pack job failed -- reached Telegram by
importing that payment provider.

Then the Stars sale was retired, and deleting the provider would have deleted
the only way this product can tell anyone anything. The transport moved to
app/notify/. Nothing stops it drifting back except this file: the next person
who needs `send_message` from inside a billing module will reach for the
import that is already there, and a comment does not fail CI.

The dependency runs ONE WAY. app/billing may import app/notify (a provider
that wants to tell someone something is fine). app/notify may not import
app/billing, because a transport that knows what a payment is has already
become a payment provider again.
"""

from __future__ import annotations

import ast
import pathlib

import httpx
import pytest

from app import alerts
from app.notify import telegram

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _imported_modules(path: pathlib.Path) -> set[str]:
    """Every dotted module name this file imports, however it spells it."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names.add(node.module)
            # `from app.billing import telegram_stars` -- the package is in
            # `module`, the thing imported is in `names`, and only the pair
            # spells out what was reached for.
            names.update(f"{node.module}.{a.name}" for a in node.names)
    return names


def _sources(package: str) -> list[pathlib.Path]:
    found = sorted((ROOT / package.replace(".", "/")).glob("*.py"))
    assert found, f"no modules found under {package} -- did the package move?"
    return found


# --- the boundary ----------------------------------------------------------

@pytest.mark.parametrize("path", _sources("app.notify"), ids=lambda p: p.name)
def test_a_transport_does_not_know_what_a_payment_is(path: pathlib.Path) -> None:
    reached = {n for n in _imported_modules(path) if n.startswith("app.billing")}
    assert not reached, (
        f"{path.name} imports {sorted(reached)}. A notification channel that "
        "imports a payment provider cannot survive that provider being removed "
        "-- which is the exact failure this package was created to end."
    )


def test_the_operator_alert_channel_does_not_go_through_billing() -> None:
    """app/alerts.py is the specific module that was wired this way. It is
    called from the Fix Pack failure path and the 5xx handler: a payment
    provider must not be in that import chain."""
    reached = {n for n in _imported_modules(ROOT / "app" / "alerts.py")
               if n.startswith("app.billing")}
    assert not reached, f"app/alerts.py imports {sorted(reached)}"


# --- and it actually sends -------------------------------------------------

@pytest.mark.anyio
async def test_an_alert_goes_out_over_the_notify_transport(monkeypatch) -> None:
    """Not just an import check: the alert has to leave through the new module.

    The MockTransport is handed to app.notify.telegram's own httpx client, so
    a request arriving here proves the call went through THAT code path and not
    a leftover copy in the billing package."""
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t0ken")
    monkeypatch.setenv("TELEGRAM_ADMIN_CHAT_ID", "4242")
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ok": True, "result": {}})

    sent = await alerts.notify_operator(
        "fixpack job failed", dedupe_key="boundary-test",
        transport=httpx.MockTransport(handler),
    )

    assert sent is True
    assert len(seen) == 1
    assert seen[0].url.path.endswith("/sendMessage")


@pytest.mark.anyio
async def test_the_client_still_raises_on_an_ok_false_reply() -> None:
    """The contract that separates `call` from `best_effort_call` survived the
    move. Losing it would turn a failed pre-checkout answer -- which Telegram
    cancels the charge over -- into a silent success."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": False, "description": "nope"})

    with pytest.raises(telegram.TelegramError):
        await telegram.send_message(
            1, "x", token="t", transport=httpx.MockTransport(handler),
        )


@pytest.mark.anyio
async def test_a_cosmetic_call_swallows_the_same_failure() -> None:
    """The other half of the pair. edit_message_reply_markup runs after the
    grant is committed; raising there would turn a completed payment into a
    5xx, which is the reason best_effort_call exists at all."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"ok": False, "description": "nope"})

    assert await telegram.edit_message_reply_markup(
        chat_id=1, message_id=2, token="t",
        transport=httpx.MockTransport(handler),
    ) is False
