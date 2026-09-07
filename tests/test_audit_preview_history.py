"""Preview retention across paid scans, cache hits and report rendering."""

from copy import deepcopy
import io
import json
from unittest.mock import AsyncMock
import uuid

import pytest

from app.audit_history import refresh_cached_preview_history, score_with_preview_history
from app.llm.client import LLMClient
from app.main import app, get_audit_repo, run_repo_audit
from app.report.html import render_report
from app.scan.pipeline import AUDIT_ENGINE_VERSION, content_digest
from app.worker import main as worker
from tests.conftest import run_audit_job
from tests.test_audit_determinism import _post, force_pro_account
from tests.test_audit_llm_wiring import make_zip, NEXT_PKG


STATIC = {"rule_id": "no-dockerfile", "title": "No Dockerfile", "severity": "low",
          "confidence": 0.8, "source": "static", "category": "Deploy"}
PREVIEW = {"rule_id": "llm-security", "title": "Prior hypothesis <script>unsafe()</script>",
           "severity": "high", "confidence": 0.8, "source": "llm", "category": "Security",
           "file": "src/auth.ts", "line": 1, "explanation": "Requires an unchecked condition",
           "fix_hint": "Original advice", "claim_evidence": {"version": 1,
               "source_check": {"kind": "quote_match", "line_start": 1, "line_end": 1},
               "conditions_status": "not_checked", "consequence_status": "not_checked"}}
RAW = make_zip({"package.json": NEXT_PKG, "src/auth.ts": b"const token = 'example';"}).getvalue()
DIGEST = content_digest(RAW)


def row(basis, findings, **kwargs):
    return {"id": str(uuid.uuid4()), "status": "completed", "stack": "nextjs", "file_count": 2,
            "score_total": 7, "score_json": {"total": 7, "categories": {}, "basis": basis,
                "scan_manifest": {"model": "preview-model" if basis == "static+preview" else "paid-model",
                                  "model_calls": 1}},
            "findings_json": deepcopy(findings), "content_hash": DIGEST,
            "engine_version": AUDIT_ENGINE_VERSION, "access_token": "original-private-access-token",
            **kwargs}


class Repo:
    def __init__(self, *rows):
        self.rows = list(rows)

    async def get_by_content_hash(self, digest, engine, basis):
        return next((r for r in reversed(self.rows) if r.get("content_hash") == digest
                     and r.get("engine_version") == engine and r.get("status") == "completed"
                     and r["score_json"]["basis"] == basis), None)

    async def create(self, **fields):
        result = {"id": str(uuid.uuid4()), "status": "completed",
                  "access_token": "new-snapshot-token", **deepcopy(fields)}
        self.rows.append(result)
        return result


@pytest.mark.asyncio
async def test_exact_matches_not_duplicated_and_changed_advice_is_preserved():
    preview = row("static+preview", [STATIC, PREVIEW])
    changed = {**PREVIEW, "fix_hint": "Different advice", "confidence": 0.9}
    paid = row("static+llm", [STATIC, changed])
    original = deepcopy(preview)
    score = await score_with_preview_history(Repo(preview), paid["score_json"],
                                            paid["findings_json"], DIGEST, AUDIT_ENGINE_VERSION)
    history = score["preview_history"]
    assert history["matched_count"] == 1
    assert history["retained_findings"] == [PREVIEW]
    assert history["status"] == "not_reassessed"
    assert history["preview_audit_id"] == preview["id"]
    assert history["model"] == "preview-model"
    assert {k: v for k, v in score.items() if k not in {"preview_history", "free_baseline"}} == paid["score_json"]
    assert preview == original
    assert preview["access_token"] not in json.dumps(score)
    history["retained_findings"][0]["title"] = "changed locally"
    assert preview == original


@pytest.mark.parametrize("overrides", [{"content_hash": "other-content"},
                                     {"engine_version": "old-engine"}, {"status": "failed"}])
@pytest.mark.asyncio
async def test_different_content_engine_or_incomplete_preview_is_not_attached(overrides):
    score = row("static+llm", [STATIC])["score_json"]
    result = await score_with_preview_history(Repo(row("static+preview", [PREVIEW], **overrides)),
                                             score, [STATIC], DIGEST, AUDIT_ENGINE_VERSION)
    assert result is score


@pytest.mark.asyncio
async def test_cached_history_is_a_new_snapshot_and_second_reuse_is_free():
    preview, paid = row("static+preview", [STATIC, PREVIEW]), row("static+llm", [STATIC])
    repo = Repo(preview, paid)
    before = deepcopy(repo.rows)
    enriched = await refresh_cached_preview_history(repo, paid)
    assert enriched["id"] != paid["id"]
    assert enriched["access_token"] != preview["access_token"]
    assert enriched["findings_json"] == paid["findings_json"]
    assert enriched["score_json"]["analysis_reused_from"] == paid["id"]
    assert repo.rows[:2] == before
    assert await refresh_cached_preview_history(repo, enriched) is enriched
    assert len(repo.rows) == 3


@pytest.mark.parametrize("basis", ["static+llm", "static+partial", "static_only"])
@pytest.mark.asyncio
async def test_worker_retains_history_even_when_paid_model_fails(monkeypatch, basis):
    preview = row("static+preview", [STATIC, PREVIEW])
    repo = Repo(preview)
    scan = {"score": row(basis, [STATIC])["score_json"], "findings": [STATIC],
            "llm": {}, "llm_usage": {"calls": 0}}
    runner = AsyncMock(return_value=scan)
    monkeypatch.setattr(worker, "_run_scan_offthread", runner)
    paid = await run_audit_job(RAW, llm_client=LLMClient(providers=[]), audit_repo=repo,
                               account_id="paid-account")
    runner.assert_awaited_once()
    assert paid["score_json"]["basis"] == basis
    assert paid["score_json"]["preview_history"]["retained_findings"] == [PREVIEW]
    assert paid["findings_json"] == [STATIC]
    assert preview["score_json"].get("preview_history") is None


@pytest.mark.asyncio
async def test_worker_cached_paid_audit_adds_history_without_scanning(monkeypatch):
    repo = Repo(row("static+preview", [PREVIEW]), row("static+llm", [STATIC]))
    runner = AsyncMock(side_effect=AssertionError("A cache hit must not scan"))
    monkeypatch.setattr(worker, "_run_scan_offthread", runner)
    result = await run_audit_job(RAW, llm_client=LLMClient(providers=[]), audit_repo=repo,
                                 account_id="paid-account")
    runner.assert_not_awaited()
    assert result["score_json"]["preview_history"]["retained_findings"] == [PREVIEW]


@pytest.mark.asyncio
async def test_free_worker_never_acquires_paid_findings(monkeypatch):
    preview, paid = row("static+preview", [STATIC]), row("static+llm", [PREVIEW])
    repo = Repo(preview, paid)
    runner = AsyncMock(side_effect=AssertionError("A cache hit must not scan"))
    monkeypatch.setattr(worker, "_run_scan_offthread", runner)
    result = await run_audit_job(RAW, llm_client=LLMClient(providers=[]), audit_repo=repo)
    assert result is preview
    assert result["findings_json"] == [STATIC]
    assert "preview_history" not in result["score_json"]


def test_paid_intake_cache_returns_persisted_history_without_queueing(monkeypatch, audit_queue):
    force_pro_account(monkeypatch)
    repo = Repo(row("static+preview", [PREVIEW]), row("static+llm", [STATIC]))
    app.dependency_overrides[get_audit_repo] = lambda: repo
    try:
        response = _post(io.BytesIO(RAW))
    finally:
        app.dependency_overrides.pop(get_audit_repo, None)
    assert response.status_code == 202
    body = response.json()
    assert "job_id" not in body
    assert body["score"]["preview_history"]["retained_findings"] == [PREVIEW]
    assert body["audit_id"] == repo.rows[-1]["id"]
    assert len(repo.rows) == 3


@pytest.mark.asyncio
async def test_repo_review_cache_also_retains_preview_without_model_calls():
    repo = Repo(row("static+preview", [PREVIEW]), row("static+llm", [STATIC]))
    result = await run_repo_audit("https://github.com/acme/app", zip_bytes=RAW,
                                  repo_fetcher=None, audit_repo=repo, llm_client=LLMClient(providers=[]))
    assert result["reused"] is True
    assert result["audit_id"] == repo.rows[-1]["id"]
    assert repo.rows[-1]["score_json"]["preview_history"]["retained_findings"] == [PREVIEW]


@pytest.mark.asyncio
async def test_html_retains_original_evidence_without_recounting_or_unsafe_markup():
    score = await score_with_preview_history(Repo(row("static+preview", [STATIC, PREVIEW])),
                                            row("static+llm", [STATIC])["score_json"],
                                            [STATIC], DIGEST, AUDIT_ENGINE_VERSION)
    html = render_report({"score": score, "findings": [STATIC], "stack": "nextjs"})
    assert "Free audit history" in html
    assert "1 unchanged observations" in html
    assert "1 other preview observations" in html
    assert "Not repeated does not mean fixed, disproved or confirmed" in html
    assert "Original preview suggestion — not reassessed" in html
    assert "&lt;script&gt;unsafe()&lt;/script&gt;" in html
    assert "<script>unsafe()</script>" not in html
    assert "Quoted text matched in source lines 1–1" in html
    assert "Potential high impact" not in html


@pytest.mark.asyncio
async def test_history_lookup_failure_after_scan_still_records_paid_usage(monkeypatch):
    class FailingRepo(Repo):
        async def get_by_content_hash(self, digest, engine, basis):
            if basis == "static+preview":
                raise RuntimeError("history unavailable")
            return None

    scan = {"score": row("static+llm", []) ["score_json"], "findings": [], "llm": {},
            "llm_usage": {"calls": 1}}
    record = AsyncMock()
    monkeypatch.setattr(worker, "_run_scan_offthread", AsyncMock(return_value=scan))
    monkeypatch.setattr(worker, "_record_llm_usage", record)
    with pytest.raises(RuntimeError, match="history unavailable"):
        await run_audit_job(RAW, llm_client=LLMClient(providers=[]), audit_repo=FailingRepo(),
                            account_id="paid-account")
    record.assert_awaited_once()
    assert record.call_args.kwargs["job_id"] is None
    assert record.call_args.kwargs["llm_stats"]["calls"] == 1


@pytest.mark.asyncio
async def test_paid_worker_includes_free_model_when_no_free_audit_exists(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock
    paid_scan = {"score": row("static+llm", [STATIC])["score_json"], "findings": [STATIC],
                 "llm": {}, "llm_usage": {"calls": 1, "model": "claude-sonnet-4.6",
                                            "input_tokens": 100, "output_tokens": 20}}
    free_score = row("static+preview", [STATIC, PREVIEW])["score_json"]
    preview_scan = {"score": free_score, "findings": [STATIC, PREVIEW], "llm": {},
                    "llm_usage": {"calls": 1, "model": "claude-haiku-4.5", "input_tokens": 80, "output_tokens": 10}}
    free_client = object()
    client = SimpleNamespace(providers=[True], with_model=Mock(return_value=free_client))
    runner = AsyncMock(side_effect=[paid_scan, preview_scan])
    record = AsyncMock()
    monkeypatch.setattr(worker, "_run_scan_offthread", runner)
    monkeypatch.setattr(worker, "_record_llm_usage", record)
    repo = Repo()
    result = await run_audit_job(RAW, llm_client=client, audit_repo=repo, account_id="paid-account")
    baseline = result['score_json']['free_baseline']
    assert baseline['status'] == 'completed' and baseline['origin'] == 'included'
    assert baseline['findings'] == [STATIC, PREVIEW]  # Includes even exact paid matches.
    assert baseline['score'] == free_score
    assert runner.await_count == 2
    assert runner.call_args.args[1] is free_client
    assert runner.call_args.kwargs['depth'] == 'static+preview'
    assert runner.call_args.kwargs['llm_passes'] == 1
    assert 0 < runner.call_args.kwargs['llm_cost_cap'] < 13
    assert record.await_count == 2
    assert {c.kwargs['llm_stats']['model'] for c in record.call_args_list} == {
        'claude-sonnet-4.6', 'claude-haiku-4.5'}
    runner.reset_mock()
    again = await run_audit_job(RAW, llm_client=client, audit_repo=repo, account_id="paid-account")
    assert again['id'] == result['id']
    runner.assert_not_awaited()


@pytest.mark.asyncio
async def test_full_free_snapshot_reuses_original_model_and_scope():
    preview = row('static+preview', [STATIC, PREVIEW])
    score = await score_with_preview_history(Repo(preview), row('static+llm', [STATIC])['score_json'],
                                            [STATIC], DIGEST, AUDIT_ENGINE_VERSION)
    baseline = score['free_baseline']
    assert baseline['origin'] == 'reused'
    assert baseline['findings'] == preview['findings_json']
    assert baseline['score'] == preview['score_json']
    assert preview['access_token'] not in json.dumps(baseline)
    html = render_report({'score': score, 'findings': [STATIC], 'stack': 'nextjs'})
    assert 'Included free-model report' in html and 'Full baseline findings and scope' in html


@pytest.mark.asyncio
@pytest.mark.parametrize('reason', ['provider', 'budget'])
async def test_baseline_unavailable_is_visible_and_does_not_call_model(reason):
    from types import SimpleNamespace
    from app.audit_history import ensure_paid_baseline
    scan = {'score': row('static+llm', [])['score_json'], 'findings': [],
            'llm_usage': {'calls': 1, 'model': 'claude-sonnet-4.6',
                          'input_tokens': 100_000_000 if reason == 'budget' else 0, 'output_tokens': 0}}
    runner, record = AsyncMock(), AsyncMock()
    client = SimpleNamespace(providers=[] if reason == 'provider' else [1])
    score = await ensure_paid_baseline(Repo(), scan, RAW, client,
                                      DIGEST, AUDIT_ENGINE_VERSION, runner=runner, record_usage=record)
    assert score['free_baseline']['status'] == 'unavailable'
    assert 'Free-model stage unavailable' in render_report({'score': score, 'findings': [], 'stack': 'nextjs'})
    runner.assert_not_awaited()


@pytest.mark.asyncio
async def test_partial_free_stage_keeps_findings_and_records_usage_before_paid_persistence():
    from types import SimpleNamespace
    from unittest.mock import Mock
    from app.audit_history import ensure_paid_baseline
    preview = {'score': row('static+partial', [PREVIEW])['score_json'], 'findings': [PREVIEW],
               'llm_usage': {'calls': 1}, 'llm': {'failure': 'provider'}}
    record = AsyncMock()
    score = await ensure_paid_baseline(Repo(), {'score': {}, 'findings': [], 'llm_usage': {}}, RAW,
                                      SimpleNamespace(providers=[1], with_model=Mock()), DIGEST, AUDIT_ENGINE_VERSION,
                                      runner=AsyncMock(return_value=preview), record_usage=record)
    assert score['free_baseline']['status'] == 'incomplete'
    assert score['free_baseline']['findings'] == [PREVIEW]
    record.assert_awaited_once_with({'calls': 1})
