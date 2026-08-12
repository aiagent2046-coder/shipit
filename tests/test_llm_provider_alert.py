"""A provider failure must reach the operator, not only the log.

The `llm` field has carried "failed: ..." since a 402 mid-run turned a 0.0
into a 9.2. That fixed the diagnosis and not the discovery: the job still
finalises as succeeded, the audit still persists, the API still answers 200,
and the only trace is a WARNING nobody reads until they go looking.

On 2026-08-12 it happened twice inside three minutes. Two paid audits were
delivered at 9.7 with three of six categories quietly unexamined, and it was
found only because someone was running dubinc/dub by hand for an unrelated
reason. Both of those jobs carried an account_id -- this was not the free
tier's static-only-by-design path, it was a paying request served a free
result.

The split into two kinds is not cosmetic. BILLING means "top up the provider
account", it is actionable in a minute, and until it is done EVERY audit
degrades. PROVIDER is an outage, usually transient, usually nothing to do but
wait. One alert for both trains the reader to ignore the one that matters.
"""

from __future__ import annotations

import app.main as main_mod
from app.scan.pipeline import (
    LLM_FAILURE_BILLING,
    LLM_FAILURE_PROVIDER,
    llm_failure_kind,
)

# Verbatim from the production log, 2026-08-12T07:44:59Z.
REAL_402 = (
    "failed: openai_compat@https://api.aitunnel.ru/v1: Client error "
    "'402 Payment Required' for url 'https://api.aitunnel.ru/v1/chat/"
    "completions'\nFor more information check: https://developer.mozilla.org/"
    "en-US/docs/Web/HTTP/Status/402"
)


def test_the_real_402_is_classified_as_billing():
    """The string that actually reached the log, not a paraphrase of it."""
    assert llm_failure_kind(REAL_402) == LLM_FAILURE_BILLING


def test_a_successful_scan_is_not_a_failure():
    """`llm` holds a stats dict on success. Only the failure path writes a
    string, and it always starts with "failed:"."""
    assert llm_failure_kind({"calls": 4, "prompts": 4}) is None
    assert llm_failure_kind(None) is None
    assert llm_failure_kind("") is None
    assert llm_failure_kind({"skipped_reason": "free_tier"}) is None


def test_rate_limiting_and_authorisation_are_not_billing():
    """429 is rate limiting and 403 is authorisation. Calling either of them
    "top up the account" sends the operator to the wrong page, and the alert
    that cries wolf is the one that stops being read."""
    for text in (
        "failed: Client error '429 Too Many Requests' for url '...'",
        "failed: Client error '403 Forbidden' for url '...'",
        "failed: Server error '503 Service Unavailable' for url '...'",
        "failed: all providers failed",
    ):
        assert llm_failure_kind(text) == LLM_FAILURE_PROVIDER, text


def test_other_ways_a_provider_says_out_of_money():
    """Not every provider phrases it as 402."""
    for text in (
        "failed: insufficient funds on the account",
        "failed: insufficient balance",
        "failed: quota exceeded for this billing period",
        "failed: you are out of credit",
    ):
        assert llm_failure_kind(text) == LLM_FAILURE_BILLING, text


class _Recorder:
    def __init__(self):
        self.sent: list[tuple[str, str | None]] = []

    async def __call__(self, text, *, dedupe_key=None, **kwargs):
        self.sent.append((text, dedupe_key))
        return True


async def _alert(monkeypatch, summary) -> _Recorder:
    recorder = _Recorder()
    monkeypatch.setattr(main_mod.alerts, "notify_operator", recorder)
    await main_mod._alert_llm_stage_failed(summary)
    return recorder


async def test_a_billing_failure_tells_the_operator_what_to_do(monkeypatch):
    """The useful thing to know is not that one audit degraded -- it is that
    every audit will keep degrading until someone acts."""
    sent = (await _alert(monkeypatch, REAL_402)).sent

    assert len(sent) == 1
    text, key = sent[0]
    assert "NON-PAYMENT" in text
    assert "Top up" in text
    assert "still returns 200" in text, (
        "the alert has to say the failure looks like a success, or the "
        "reader has no reason to treat it as urgent"
    )
    assert key == "llm-provider-billing"


async def test_a_transient_failure_is_a_different_alert(monkeypatch):
    """Different key, so the throttle windows do not share -- and different
    words, so the operator does not go looking for a payment page."""
    sent = (await _alert(
        monkeypatch, "failed: Server error '503' for url '...'")).sent

    assert len(sent) == 1
    text, key = sent[0]
    assert key == "llm-provider-failure"
    assert "NON-PAYMENT" not in text
    assert "Top up" not in text


async def test_a_healthy_scan_alerts_nobody(monkeypatch):
    """The guard that keeps this from paging on every successful audit."""
    assert (await _alert(monkeypatch, {"calls": 4})).sent == []


def test_both_scan_call_sites_alert():
    """A helper nobody calls is the defect this session shipped twice -- a
    rubric absent from the loop, a filter absent from the loop. Asserted
    against the source of both async callers: the worker, which runs every
    queued audit, and run_repo_audit, which the Fix Pack's deep review uses.
    """
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    for module in ("app/main.py", "app/worker/main.py"):
        source = (root / module).read_text()
        assert '_alert_llm_stage_failed(scan["llm"])' in source, module
