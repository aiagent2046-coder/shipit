"""A cheap primary must not reprice the expensive fallback's earlier work."""
import io
import zipfile
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.llm.accounting import estimate_stats_cost
from app.llm.client import LLMClient, LLMUsage, Provider
from app.scan.llm_scan import run_llm_scan


class MixedModels(LLMClient):
    def __init__(self):
        super().__init__([Provider("openai_compat", "https://unused", "unused", "gpt-6-luna")])
        self.calls = 0

    def complete(self, system, user, max_tokens=4096):
        self.calls += 1
        return "[]", LLMUsage(
            "claude-sonnet-4.6" if self.calls == 1 else "gpt-6-luna",
            input_tokens=1_000_000)


def mixed_scan():
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as out:
        out.writestr("app/auth.py", "token = request.headers.get('Authorization')")
    archive.seek(0)
    client = MixedModels()
    _, stats = run_llm_scan(archive, client, rubrics=("auth",), passes=3,
                           cost_cap_usd=Decimal("3.05"))
    return client, stats


def test_scan_cap_retains_sonnet_cost_after_luna_success():
    client, stats = mixed_scan()
    assert client.calls == stats.calls == 2  # Stop before paying for pass three.
    assert stats.model == "gpt-6-luna"
    assert stats.cost_cap_exceeded
    assert estimate_stats_cost(vars(stats)) == Decimal("3.25")


@pytest.mark.parametrize("breakdown", [False, True])
def test_old_aggregate_usage_remains_supported(breakdown):
    stats = {"model": "claude-sonnet-4.6", "input_tokens": 1000, "output_tokens": 200}
    if breakdown:
        stats["successful_model_usage"] = None  # Older test doubles using current dataclass.
    assert estimate_stats_cost(stats) == Decimal("0.006")


@pytest.mark.asyncio
async def test_persisted_usd_uses_each_model_and_keeps_unknown_failed_charge():
    from app.main import _record_llm_usage
    _, stats = mixed_scan()
    usage = vars(stats)
    usage["provider_attempts"] = [{"model": "gpt-6-luna", "error": "ReadTimeout", "cost_rub": None}]
    repo = SimpleNamespace(create=AsyncMock())
    await _record_llm_usage(repo, job_type="audit", job_id=None, account_id=None, llm_stats=usage)
    row = repo.create.call_args.kwargs
    assert row["cost_usd"] == Decimal("3.25")
    assert row["input_tokens"] == 2_000_000
    assert row["provider_usage"]["unpriced_attempts"] == 1
    assert row["provider_usage"]["cost_rub"] is None


@pytest.mark.asyncio
async def test_paid_preview_budget_subtracts_both_models(monkeypatch):
    from app import audit_history
    _, stats = mixed_scan()
    monkeypatch.setattr(audit_history, "score_with_preview_history", AsyncMock(return_value={}))
    monkeypatch.setattr(audit_history, "baseline_is_current", lambda score: False)
    monkeypatch.setattr(audit_history.llm_scan, "JOB_COST_CAP_USD", Decimal("3.05"))
    runner = AsyncMock(return_value={"score": {}, "findings": [], "llm_usage": {}})
    record = AsyncMock()
    client = SimpleNamespace(providers=[1])
    await audit_history.ensure_paid_baseline(
        None, {"score": {}, "findings": [], "llm_usage": vars(stats)}, b"", client,
        "digest", "engine", runner=runner, record_usage=record)
    assert runner.call_args.kwargs["llm_skip_reason"] == "paid_job_cost_cap"
    assert runner.call_args.kwargs["llm_cost_cap"] == 0
    record.assert_awaited_once_with({})
