"""Tests for app/alerts.notify_operator — the best-effort operator alert
helper that rides the existing Telegram bot.

No real Telegram: the outbound Bot API call is faked with
httpx.MockTransport (same pattern as tests/test_billing_telegram.py). The
throttle is exercised with an injected `now` so no test sleeps.
"""

from __future__ import annotations

import asyncio
import json

import httpx

from app import alerts


def _transport(calls: list) -> httpx.MockTransport:
    """Records (method, body) and returns ok for every Bot API call."""
    def handler(request: httpx.Request) -> httpx.Response:
        method = request.url.path.rsplit("/", 1)[-1]
        calls.append((method, json.loads(request.content) if request.content else {}))
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 1}})
    return httpx.MockTransport(handler)


def _failing_transport() -> httpx.MockTransport:
    """Every Bot API call comes back as a Telegram error (ok:false), which
    telegram_stars._call turns into a TelegramError."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"ok": False, "description": "bad chat id"})
    return httpx.MockTransport(handler)


def _configured(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "bot-token-xyz")
    monkeypatch.setenv("TELEGRAM_ADMIN_CHAT_ID", "999")
    # Isolate the module-global throttle store between tests.
    alerts._last_sent.clear()


# --- unconfigured => silent no-op -----------------------------------------

def test_noop_when_bot_token_unset(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.setenv("TELEGRAM_ADMIN_CHAT_ID", "999")
    alerts._last_sent.clear()
    calls: list = []
    sent = asyncio.run(alerts.notify_operator("hi", transport=_transport(calls)))
    assert sent is False
    assert calls == []


def test_noop_when_admin_chat_id_unset(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "bot-token-xyz")
    monkeypatch.delenv("TELEGRAM_ADMIN_CHAT_ID", raising=False)
    alerts._last_sent.clear()
    calls: list = []
    sent = asyncio.run(alerts.notify_operator("hi", transport=_transport(calls)))
    assert sent is False
    assert calls == []


# --- happy path ------------------------------------------------------------

def test_sends_expected_sendmessage_body(monkeypatch):
    _configured(monkeypatch)
    calls: list = []
    sent = asyncio.run(
        alerts.notify_operator("service degraded", transport=_transport(calls))
    )
    assert sent is True
    assert len(calls) == 1
    method, body = calls[0]
    assert method == "sendMessage"
    assert body == {"chat_id": "999", "text": "service degraded"}


# --- best-effort: swallows its own errors ----------------------------------

def test_swallows_telegram_error_and_returns_false(monkeypatch):
    _configured(monkeypatch)
    # Must not raise even though the Bot API returns ok:false.
    sent = asyncio.run(
        alerts.notify_operator("boom", transport=_failing_transport())
    )
    assert sent is False


# --- throttle / dedupe -----------------------------------------------------

def test_throttle_suppresses_duplicate_within_window(monkeypatch):
    _configured(monkeypatch)
    calls: list = []
    t = _transport(calls)
    first = asyncio.run(alerts.notify_operator(
        "same", dedupe_key="k", throttle_seconds=60.0, transport=t, now=100.0))
    second = asyncio.run(alerts.notify_operator(
        "same", dedupe_key="k", throttle_seconds=60.0, transport=t, now=130.0))
    assert first is True
    assert second is False          # within the 60s window
    assert len(calls) == 1          # only the first actually sent


def test_throttle_allows_after_window(monkeypatch):
    _configured(monkeypatch)
    calls: list = []
    t = _transport(calls)
    asyncio.run(alerts.notify_operator(
        "same", dedupe_key="k", throttle_seconds=60.0, transport=t, now=100.0))
    again = asyncio.run(alerts.notify_operator(
        "same", dedupe_key="k", throttle_seconds=60.0, transport=t, now=200.0))
    assert again is True            # 100s later, outside the window
    assert len(calls) == 2


def test_distinct_dedupe_keys_do_not_share_window(monkeypatch):
    _configured(monkeypatch)
    calls: list = []
    t = _transport(calls)
    a = asyncio.run(alerts.notify_operator(
        "x", dedupe_key="job-1", throttle_seconds=60.0, transport=t, now=100.0))
    b = asyncio.run(alerts.notify_operator(
        "y", dedupe_key="job-2", throttle_seconds=60.0, transport=t, now=101.0))
    assert a is True and b is True  # different keys, both fire
    assert len(calls) == 2
