"""Actual charges survive failures without changing the USD budget or public report."""
import io
import json
import zipfile
from decimal import Decimal

import httpx
import pytest

from app.llm.accounting import provider_usage_summary
from app.llm.client import LLMClient, Provider
from app.main import _record_llm_usage
from app.scan.llm_scan import run_llm_scan
from app.scan.pipeline import run_scan


def archive():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app/auth.ts", "export const login = () => verifyToken(token);\n")
    return buf.getvalue()


class Journal:
    def __init__(self):
        self.rows = []

    async def create(self, **kwargs):
        self.rows.append(kwargs)


def client(handler):
    return LLMClient(providers=[Provider("openai_compat", "https://api.aitunnel.ru/v1", "synthetic",
                                         "claude-sonnet-4.6")], transport=httpx.MockTransport(handler))


def response(content="[]", cost="1.25", finish="stop"):
    return httpx.Response(200, json={
        "model": "claude-sonnet-4.6", "usage": {"prompt_tokens": 1000, "completion_tokens": 50,
            "prompt_tokens_details": {"cached_tokens": 900, "cache_write_tokens": 0},
            "cost_rub": cost, "balance": "private"},
        "choices": [{"finish_reason": finish, "message": {"content": content}}],
    })


async def record(stats):
    journal = Journal()
    await _record_llm_usage(journal, job_type="audit", job_id=None, account_id=None, llm_stats=stats)
    return journal.rows


def test_exact_decimal_total_and_unknown_are_distinct_from_zero():
    assert provider_usage_summary([]) is None
    summary = provider_usage_summary([{"cost_rub": "0.10"}, {"cost_rub": "0.20"}])
    assert summary["cost_rub"] == "0.30"
    assert summary["cost_complete"] is True
    assert provider_usage_summary([{"cost_rub": "0"}])["cost_rub"] == "0"
    partial = provider_usage_summary([{"cost_rub": "1.25"}, {"cost_rub": None}])
    assert partial["known_cost_rub"] == "1.25"
    assert partial["cost_rub"] is None
    assert partial["unpriced_attempts"] == 1
    assert partial["cost_complete"] is False


@pytest.mark.parametrize("bad", [None, True, "NaN", "Infinity", "-1", "bad"])
def test_invalid_charge_never_completes_summary(bad):
    summary = provider_usage_summary([{"cost_rub": bad}])
    assert summary["known_cost_rub"] is None
    assert summary["cost_rub"] is None
    assert summary["cost_complete"] is False


async def test_billed_empty_first_answer_is_persisted_with_no_successful_calls():
    llm = client(lambda request: response(None, "4.35", "length"))
    result = run_scan(archive(), llm, llm_rubrics=("auth",))
    assert result["llm_usage"]["calls"] == 0
    assert "provider_attempts" not in result["llm"]
    rows = await record(result["llm_usage"])
    assert len(rows) == 1
    usage = rows[0]["provider_usage"]
    assert usage["cost_rub"] == "4.35"
    assert usage["attempt_count"] == 1
    assert usage["attempts"][0]["rubric"] == "auth"
    assert usage["attempts"][0]["finish_reason"] == "length"
    assert usage["attempts"][0]["error"]
    assert rows[0]["cost_usd"] == Decimal("0")  # The existing estimate remains a separate measure.
    assert "private" not in json.dumps(usage)


async def test_passes_and_syntax_status_are_recorded_without_publishing_billing():
    replies = iter([response("not JSON", "0"), response("[]", "1.25")])
    result = run_scan(archive(), client(lambda request: next(replies)), llm_rubrics=("auth",), llm_passes=2)
    rows = await record(result["llm_usage"])
    assert "provider_attempts" not in result["llm"]
    usage = rows[0]["provider_usage"]
    assert usage["cost_rub"] == "1.25"
    assert [a["pass"] for a in usage["attempts"]] == [1, 2]
    assert [a["answer_status"] for a in usage["attempts"]] == ["invalid_json", "empty_array"]
    assert [a["cached_tokens"] for a in usage["attempts"]] == [900, 900]
    assert rows[0]["calls"] == 2


async def test_timeout_attempts_are_unknown_even_after_retry_succeeds(monkeypatch):
    monkeypatch.setattr("app.llm.client.time.sleep", lambda seconds: None)
    count = 0

    def handle(request):
        nonlocal count
        count += 1
        if count == 1:
            raise httpx.ReadTimeout("synthetic", request=request)
        return response()

    _, stats = run_llm_scan(io.BytesIO(archive()), client(handle), rubrics=("auth",))
    rows = await record(vars(stats))
    usage = rows[0]["provider_usage"]
    assert usage["known_cost_rub"] == "1.25"
    assert usage["cost_rub"] is None
    assert usage["attempt_count"] == 2
    assert usage["unpriced_attempts"] == 1


async def test_oversize_attempt_survives_shrinking():
    count = 0

    def handle(request):
        nonlocal count
        count += 1
        if count == 1:
            return httpx.Response(400, json={"error": {"message": "maximum context length exceeded"}})
        return response()

    _, stats = run_llm_scan(io.BytesIO(archive()), client(handle), rubrics=("auth",))
    assert stats.oversize_retries == 1
    assert [a["request"] for a in stats.provider_attempts] == [1, 2]
    assert (await record(vars(stats)))[0]["provider_usage"]["cost_complete"] is False


async def test_skipped_and_legacy_runs_do_not_invent_ruble_cost():
    assert await record({"calls": 0}) == []
    rows = await record({"calls": 1, "model": "claude-sonnet-4.6", "input_tokens": 1000})
    assert "provider_usage" not in rows[0]


async def test_malformed_telemetry_cannot_fail_the_audit():
    rows = await record({"calls": 1, "input_tokens": 1000, "provider_attempts": [None]})
    assert rows[0]["calls"] == 1
    assert rows[0]["input_tokens"] == 1000
    assert "provider_usage" not in rows[0]
    assert await record({"calls": 0, "provider_attempts": [None]}) == []


def test_summary_preserves_high_precision_provider_charge():
    charge = "0.12345678901234567890123456789"
    assert provider_usage_summary([{"cost_rub": charge}])["cost_rub"] == charge
