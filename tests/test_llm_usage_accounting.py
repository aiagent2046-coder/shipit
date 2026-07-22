"""Stage 4 step 1: LLM cost accounting is observability only.

Covers the write path end to end through /v1/audits with fake repos, plus the
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
from app.main import (
    app,
    get_audit_repo,
    get_llm_client,
    get_llm_usage_repo,
)

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


class FakeLLM(LLMClient):
    def __init__(self, response: str):
        super().__init__(providers=[Provider("anthropic", "https://x", "k", "m")])
        self._response = response

    def complete(self, system, user, max_tokens=4096):
        return self._response, LLMUsage(
            model="claude-sonnet-4-6", input_tokens=1000, output_tokens=200)


def _auth_zip() -> io.BytesIO:
    # auth.ts matches the 'auth' rubric so the LLM stage actually runs.
    return make_zip({
        "package.json": NEXT_PKG,
        "app/auth.ts": b"const password = 'x'  // check auth token",
    })


def _override(audit_repo, usage_repo, llm):
    app.dependency_overrides[get_audit_repo] = lambda: audit_repo
    app.dependency_overrides[get_llm_usage_repo] = lambda: usage_repo
    app.dependency_overrides[get_llm_client] = lambda: llm


def _clear_overrides():
    for dep in (get_audit_repo, get_llm_usage_repo, get_llm_client):
        app.dependency_overrides.pop(dep, None)


def test_pricing_cost_matches_published_sonnet_rates():
    # 1M input @ $3.00 + 1M output @ $15.00 = $18.00 exactly.
    assert pricing.cost_usd("claude-sonnet-4-6", 1_000_000, 1_000_000) == Decimal("18.00")
    # Zero tokens -> zero cost.
    assert pricing.cost_usd("claude-sonnet-4-6", 0, 0) == Decimal("0")


def test_pricing_unknown_model_uses_fail_safe_high_default():
    # An unknown model must never under-count: it prices at DEFAULT_PRICE, the
    # most expensive known rates, so cost >= any known model's cost.
    unknown = pricing.cost_usd("some-future-model", 1000, 1000)
    known = pricing.cost_usd("claude-sonnet-4-6", 1000, 1000)
    assert unknown >= known


def test_pricing_negative_tokens_clamped_to_zero():
    assert pricing.cost_usd("claude-sonnet-4-6", -5, -5) == Decimal("0")


def test_audit_records_one_usage_row_with_cost():
    audit_repo = FakeAuditRepo()
    usage_repo = FakeUsageRepo()
    _override(audit_repo, usage_repo, FakeLLM("[]"))
    try:
        resp = client.post(
            "/v1/audits",
            files={"archive": ("app.zip", _auth_zip(), "application/zip")},
        )
    finally:
        _clear_overrides()

    assert resp.status_code == 202
    assert len(usage_repo.rows) == 1
    row = usage_repo.rows[0]
    assert row["job_type"] == "audit"
    assert row["account_id"] is None            # anonymous caller
    assert row["model"] == "claude-sonnet-4-6"
    # Only the 'auth' rubric matches this content, so one .complete() call.
    assert row["calls"] == 1
    assert row["input_tokens"] == 1000
    assert row["output_tokens"] == 200
    # cost = (1000/1e6)*3 + (200/1e6)*15 = 0.003 + 0.003 = 0.006
    assert row["cost_usd"] == Decimal("0.006")
    # job_id links to the audit that was just persisted.
    assert row["job_id"] == audit_repo.rows[0]["id"]


def test_cache_hit_records_no_usage_row():
    audit_repo = FakeAuditRepo()
    usage_repo = FakeUsageRepo()
    _override(audit_repo, usage_repo, FakeLLM("[]"))
    try:
        # First audit: real run -> one row.
        r1 = client.post(
            "/v1/audits",
            files={"archive": ("app.zip", _auth_zip(), "application/zip")},
        )
        assert r1.status_code == 202
        assert len(usage_repo.rows) == 1

        # Second audit of byte-identical content: cache hit, no LLM call.
        r2 = client.post(
            "/v1/audits",
            files={"archive": ("app.zip", _auth_zip(), "application/zip")},
        )
        assert r2.status_code == 202
        assert r2.json()["llm"] == {"reused_from_prior_audit": True}
    finally:
        _clear_overrides()

    # Still exactly one row: the reused audit recorded nothing.
    assert len(usage_repo.rows) == 1


def test_no_usage_row_when_llm_stage_skipped():
    # No providers configured -> the stage never runs (calls=0) -> no row,
    # even though the audit itself succeeds.
    audit_repo = FakeAuditRepo()
    usage_repo = FakeUsageRepo()
    app.dependency_overrides[get_audit_repo] = lambda: audit_repo
    app.dependency_overrides[get_llm_usage_repo] = lambda: usage_repo
    app.dependency_overrides[get_llm_client] = lambda: LLMClient(providers=[])
    try:
        resp = client.post(
            "/v1/audits",
            files={"archive": ("app.zip", _auth_zip(), "application/zip")},
        )
    finally:
        _clear_overrides()

    assert resp.status_code == 202
    assert resp.json()["llm"]["skipped_reason"] == "no_providers_configured"
    assert usage_repo.rows == []
