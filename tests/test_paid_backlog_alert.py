"""Operator alert when paid Fix Pack backlog is not draining."""

from __future__ import annotations

import app.alerts as alerts
from app.main import (
    PAID_BACKLOG_ALERT_SECONDS,
    _alert_paid_backlog_stale,
)


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def __call__(self, text: str, **kwargs):
        self.calls.append({"text": text, **kwargs})
        return True


async def test_no_alert_when_backlog_empty(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(alerts, "notify_operator", rec)
    await _alert_paid_backlog_stale(backlog=0, oldest_paid_seconds=99999)
    assert rec.calls == []


async def test_no_alert_when_oldest_below_threshold(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(alerts, "notify_operator", rec)
    await _alert_paid_backlog_stale(
        backlog=2,
        oldest_paid_seconds=PAID_BACKLOG_ALERT_SECONDS - 1,
    )
    assert rec.calls == []


async def test_alerts_when_oldest_exceeds_threshold(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(alerts, "notify_operator", rec)
    await _alert_paid_backlog_stale(
        backlog=3,
        oldest_paid_seconds=PAID_BACKLOG_ALERT_SECONDS + 120,
    )
    assert len(rec.calls) == 1
    assert rec.calls[0]["dedupe_key"] == "fixpack-paid-backlog-stale"
    assert "3 job" in rec.calls[0]["text"]
    assert "paid Fix Pack backlog" in rec.calls[0]["text"]
