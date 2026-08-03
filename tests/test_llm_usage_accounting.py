"""Stage 4 step 1: LLM cost accounting is observability only.

Covers the write path end to end with fake repos -- through the worker, which
is where the scan (and so the spend) happens since the queue cutover -- plus the
two invariants the accounting must never violate:
  * a real LLM run records exactly ONE row with the summed tokens and the cost
    computed from app/llm/pricing.py;
  * a content-hash cache hit (reused_from_prior_audit) records NOTHING -- a
    reused audit costs $0 and must not double-charge.
No enforcement/blocking is exercised: nothing here caps or rejects a request.
"""

import io
import json
import uuid
import zipfile
from decimal import Decimal

from fastapi.testclient import TestClient

from app.llm.client import LLMClient, LLMUsage, Provider
from app.llm import pricing
from app.main import app, get_audit_repo
from tests.conftest import drain_audit_queue, run_audit_job

client = TestClient(app)

NEXT_PKG = json.dumps({"dependencies": {"next": "15.0.0", "react": "19.0.0"}}).encode()


def make_zip(entries: dict[str, bytes]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    buf.seek(0)
    return buf


class FakeAuditRepo:
    """In-memory AuditRepository keyed by content_hash (mirrors the one in
    tests/test_audit_determinism.py) so the cache-hit branch is reachable."""

    def __init__(self):
        self.rows: list[dict] = []

    async def create(self, *, stack, file_count, score_total, score_json,
                     findings_json, repo_url=None, content_hash=None,
                     engine_version=None):
        row = {
            "id": str(uuid.uuid4()), "stack": stack, "status": "completed",
            "file_count": file_count, "score_total": score_total,
            "score_json": score_json, "findings_json": findings_json,
            "repo_url": repo_url, "content_hash": content_hash,
            "engine_version": engine_version, "access_token": "tok",
        }
        self.rows.append(row)
        return row

    async def get_by_content_hash(self, content_hash, engine_version):
        matches = [r for r in self.rows
                   if r["content_hash"] == content_hash
                   and r["engine_version"] == engine_version
                   and r["status"] == "completed"]
        return matches[-1] if matches else None


class FakeUsageRepo:
    """Captures every llm_usage row create() is asked to write."""

    def __init__(self):
        self.rows: list[dict] = []

    async def create(self, **kwargs):
        self.rows.append(kwargs)
        return {"id": str(uuid.uuid4()), **kwargs}

    async def sum_anon_spend_today(self):
        # Enforcement (Stage 4 step 2) reads this before an anonymous scan.
        # These accounting tests stay well under any cap, so report $0.
        return Decimal("0")


class FakeLLM(LLMClient):
    def __init__(self, response: str):
        super().__init__(providers=[Provider("anthropic", "https://x", "k", "m")])
        self._response = response

    def complete(self, system, user, max_tokens=4096):
        # AITunnel (primary provider) reports the dotted name in data["model"];
        # mirror that here so the accounting is exercised against the real
        # response spelling, not the dashed request name.
        return self._response, LLMUsage(
            model="claude-sonnet-4.6", input_tokens=1000, output_tokens=200)


def _auth_zip() -> io.BytesIO:
    # auth.ts matches the 'auth' rubric so the LLM stage actually runs.
    return make_zip({
        "package.json": NEXT_PKG,
        "app/auth.ts": b"const password = 'x'  // check auth token",
    })


def test_pricing_cost_matches_published_sonnet_rates():
    # Both provider spellings price identically: 1M in @ $3 + 1M out @ $15 = $18.
    for model in ("claude-sonnet-4.6", "claude-sonnet-4-6"):
        assert pricing.cost_usd(model, 1_000_000, 1_000_000) == Decimal("18.00")
        assert pricing.cost_usd(model, 0, 0) == Decimal("0")  # zero tokens -> $0


def test_both_provider_spellings_priced_from_real_row_not_default():
    """The dot/dash regression guard: AITunnel returns "claude-sonnet-4.6" and
    the direct Anthropic fallback "claude-sonnet-4-6" for the same model. Both
    must resolve to the actual table row, not merely coincide with DEFAULT_PRICE.
    Asserting identity with the row (not just an equal number) is what catches a
    key that stopped matching."""
    for name in ("claude-sonnet-4.6", "claude-sonnet-4-6"):
        assert name in pricing.PRICE_TABLE
        assert pricing.price_for(name) is pricing.PRICE_TABLE[name]


def test_price_for_matches_by_key_not_accidental_default(monkeypatch):
    """With two DIFFERENT-priced models in the table, each must resolve to ITS
    OWN row and an unknown model to the (distinct) default. This fails if
    price_for ever silently rode on DEFAULT_PRICE — the failure mode that hid
    the dot/dash miss when the default happened to equal the only row."""
    cheap = {"input": Decimal("1.00"), "output": Decimal("2.00")}
    dear = {"input": Decimal("10.00"), "output": Decimal("40.00")}
    default = {"input": Decimal("99.00"), "output": Decimal("99.00")}
    monkeypatch.setattr(pricing, "PRICE_TABLE",
                        {"cheap-model": cheap, "dear-model": dear})
    monkeypatch.setattr(pricing, "DEFAULT_PRICE", default)

    assert pricing.price_for("cheap-model") is cheap
    assert pricing.price_for("dear-model") is dear
    assert pricing.price_for("unknown-model") is default
    # And the costs are all distinct, proving each matched its own row.
    assert pricing.cost_usd("cheap-model", 1_000_000, 1_000_000) == Decimal("3.00")
    assert pricing.cost_usd("dear-model", 1_000_000, 1_000_000) == Decimal("50.00")
    assert pricing.cost_usd("unknown-model", 1_000_000, 1_000_000) == Decimal("198.00")


def test_pricing_unknown_model_uses_fail_safe_high_default():
    # An unknown model must never under-count: it prices at DEFAULT_PRICE, the
    # most expensive known rates, so cost >= any known model's cost.
    unknown = pricing.cost_usd("some-future-model", 1000, 1000)
    known = pricing.cost_usd("claude-sonnet-4.6", 1000, 1000)
    assert unknown >= known


def test_pricing_negative_tokens_clamped_to_zero():
    assert pricing.cost_usd("claude-sonnet-4.6", -5, -5) == Decimal("0")


async def test_audit_records_one_usage_row_with_cost():
    audit_repo = FakeAuditRepo()
    usage_repo = FakeUsageRepo()
    await run_audit_job(
        _auth_zip().getvalue(), llm_client=FakeLLM("[]"),
        audit_repo=audit_repo, llm_usage_repo=usage_repo,
    )

    assert len(usage_repo.rows) == 1
    row = usage_repo.rows[0]
    assert row["job_type"] == "audit"
    assert row["account_id"] is None            # anonymous caller
    assert row["model"] == "claude-sonnet-4.6"
    # Only the 'auth' rubric matches this content, so one .complete() call.
    assert row["calls"] == 1
    assert row["input_tokens"] == 1000
    assert row["output_tokens"] == 200
    # cost = (1000/1e6)*3 + (200/1e6)*15 = 0.003 + 0.003 = 0.006
    assert row["cost_usd"] == Decimal("0.006")
    # job_id links to the audit that was just persisted.
    assert row["job_id"] == audit_repo.rows[0]["id"]


async def test_cache_hit_records_no_usage_row(audit_queue):
    # Driven through the endpoint, because the cache hit IS an endpoint
    # behaviour: it answers inline, queues no job, and so reaches no scan.
    audit_repo = FakeAuditRepo()
    usage_repo = FakeUsageRepo()
    app.dependency_overrides[get_audit_repo] = lambda: audit_repo
    try:
        r1 = client.post(
            "/v1/audits",
            files={"archive": ("app.zip", _auth_zip(), "application/zip")},
        )
        assert r1.status_code == 202
        await drain_audit_queue(
            audit_queue, audit_repo=audit_repo, llm_client=FakeLLM("[]"),
            llm_usage_repo=usage_repo,
        )
        assert len(usage_repo.rows) == 1

        # Second audit of byte-identical content: cache hit, no LLM call.
        r2 = client.post(
            "/v1/audits",
            files={"archive": ("app.zip", _auth_zip(), "application/zip")},
        )
        assert r2.status_code == 202
        assert r2.json()["llm"] == {"reused_from_prior_audit": True}
    finally:
        app.dependency_overrides.pop(get_audit_repo, None)

    # Still exactly one row: the reused audit recorded nothing.
    assert len(usage_repo.rows) == 1


async def test_no_usage_row_when_llm_stage_skipped():
    # No providers configured -> the stage never runs (calls=0) -> no row,
    # even though the audit itself succeeds.
    usage_repo = FakeUsageRepo()
    row = await run_audit_job(
        _auth_zip().getvalue(), llm_client=LLMClient(providers=[]),
        audit_repo=FakeAuditRepo(), llm_usage_repo=usage_repo,
    )

    assert row["score_json"]["basis"] == "static_only"
    assert usage_repo.rows == []
