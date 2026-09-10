"""Offline boundary evidence for the paid report's two spend observations."""

import io
import json
import uuid
import zipfile
from decimal import Decimal

import httpx
import pytest

from app.llm import pricing
from app.llm.client import LLMClient, Provider
from app.main import run_repo_audit
from app.scan import llm_scan
from app.scan.pipeline import BASIS_FULL


def archive(version=1):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("package.json", '{"dependencies":{"next":"15.0.0"}}')
        zf.writestr("app/auth.ts", f"const password = 'fixture-{version}'; // token cors env sql query")
    buf.seek(0)
    return buf


def mocked_client(tokens):
    requests = []

    def answer(request):
        body = json.loads(request.content)
        requests.append(body)
        count = tokens(len(requests))
        return httpx.Response(200, json={
            "model": body["model"], "content": [{"type": "text", "text": "[]"}],
            "usage": {"input_tokens": count, "output_tokens": 0},
        })

    return LLMClient(
        providers=[Provider("anthropic", "https://llm.invalid", "test-key", "claude-sonnet-4.6")],
        transport=httpx.MockTransport(answer),
    ), requests


@pytest.mark.parametrize("cap,calls,spent,tripped", [
    ("0.003", 1, "0.003", True),
    ("0.004", 2, "0.030", True),
    ("0.030", 2, "0.030", True),
    ("0.100", 4, "0.084", False),
])
def test_soft_cap_boundary_through_real_client(cap, calls, spent, tripped):
    """A response may cross the remaining allowance; no later rubric/pass runs."""
    client, requests = mocked_client(lambda n: 1000 if n == 1 else 9000)
    _, stats = llm_scan.run_llm_scan(
        archive(), client, rubrics=("auth", "security"), passes=2,
        cost_cap_usd=Decimal(cap),
    )
    assert len(requests) == stats.calls == calls
    assert pricing.cost_usd(stats.model, stats.input_tokens, stats.output_tokens) == Decimal(spent)
    assert stats.cost_cap_exceeded is tripped
    assert all(request["max_tokens"] == 8192 for request in requests)


class Audits:
    def __init__(self):
        self.rows = []

    async def create(self, **kwargs):
        row = {"id": str(uuid.uuid4()), "status": "completed", "access_token": "test", **kwargs}
        self.rows.append(row)
        return row

    async def get_by_content_hash(self, digest, engine, basis):
        return next((r for r in reversed(self.rows)
                     if r["content_hash"] == digest and r["engine_version"] == engine
                     and r["score_json"]["basis"] == basis), None)


class Usage:
    def __init__(self):
        self.rows = []
        self.daily_reads = 0

    async def create(self, **kwargs):
        self.rows.append(kwargs)

    async def sum_anon_spend_today(self):
        self.daily_reads += 1
        return Decimal("999999")


async def test_monitoring_helper_has_scan_budget_and_cache_but_no_daily_spend_gate(monkeypatch):
    """Exercise the runner reached only after the separate monitoring gates."""
    monkeypatch.setattr(llm_scan, "JOB_COST_CAP_USD", Decimal("0.05"))
    client, requests = mocked_client(lambda n: 5000)
    audits, usage = Audits(), Usage()

    def no_fetch(*args):
        raise AssertionError("the supplied ZIP must avoid network fetches")

    async def audit(version):
        return await run_repo_audit(
            "https://github.com/acme/app", llm_client=client, audit_repo=audits,
            repo_fetcher=no_fetch, llm_usage_repo=usage, job_type="monitoring",
            zip_bytes=archive(version).getvalue(),
        )

    first = await audit(1)
    assert first["basis"] == BASIS_FULL
    calls_before_cache, rows_before_cache = len(requests), len(usage.rows)
    cached = await audit(1)
    assert cached["reused"] is True
    assert (len(requests), len(usage.rows)) == (calls_before_cache, rows_before_cache)

    second = await audit(2)
    assert second["basis"] == BASIS_FULL
    assert len(requests) > calls_before_cache
    costs = [sum((r["cost_usd"] for r in rows), Decimal("0"))
             for rows in (usage.rows[:rows_before_cache], usage.rows[rows_before_cache:])]
    assert all(cost <= llm_scan.JOB_COST_CAP_USD for cost in costs)
    assert sum(costs) > llm_scan.JOB_COST_CAP_USD
    assert usage.daily_reads == 0
    assert all(r["account_id"] is None and r["job_type"] == "monitoring" for r in usage.rows)
