"""Real static observations survive preview reuse, JSON storage and paid HTML.

Only the model response and repository storage are simulated. All scanners,
scoring, baseline preservation and rendering run their production code.
"""
from copy import deepcopy
from html import escape
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.audit_history import ensure_paid_baseline
from app.report.html import render_report
from app.scan import pipeline
from app.scan.llm_scan import LLMScanStats
from app.scan.secrets import MAX_SCANNED_FILE_BYTES

from .conftest import clean_nextjs_repo, make_zip


@pytest.mark.asyncio
@pytest.mark.parametrize("paid_keeps_observations", [True, False])
async def test_full_free_result_and_exclusions_survive_paid_json_and_html(monkeypatch, paid_keeps_observations):
    secret = "sk_live_" + "SyntheticCorpusCredential123456789"
    raw = make_zip(clean_nextjs_repo(**{
        "src/payments.ts": f'const key = "{secret}"',
        "tests/payments.test.ts": f'const key = "{secret}"',
        "src/large.ts": "x" * (MAX_SCANNED_FILE_BYTES + 1),
    })).getvalue()
    # A completed empty interpretation: no network client or model is invoked.
    monkeypatch.setattr(pipeline, "run_llm_scan", lambda *a, **k: ([], LLMScanStats(calls=1, rubrics_ran=("auth",))))
    free = pipeline.run_scan(raw, SimpleNamespace(providers=[object()]), depth=pipeline.BASIS_PREVIEW)
    assert {f["context"] for f in free["findings"] if f["rule_id"] == "stripe-live-key"} == {None, "test_file"}
    digest = pipeline.content_digest(raw)
    preview = dict(id="synthetic-preview", status="completed", content_hash=digest,
                   engine_version=pipeline.AUDIT_ENGINE_VERSION,
                   score_json=free["score"], findings_json=free["findings"],
                   access_token="synthetic-private-access-token")
    original = deepcopy(preview)
    repo = SimpleNamespace(get_by_content_hash=AsyncMock(return_value=preview))
    paid = {"score": {"basis": pipeline.BASIS_FULL, "total": 9, "categories": {}},
            "findings": deepcopy(free["findings"]) if paid_keeps_observations else []}
    runner, record = AsyncMock(side_effect=AssertionError("Unexpected model call")), AsyncMock()
    score = await ensure_paid_baseline(repo, paid, raw, SimpleNamespace(providers=[]), digest,
                                      pipeline.AUDIT_ENGINE_VERSION, runner=runner, record_usage=record)
    runner.assert_not_called()
    record.assert_not_called()
    repo.get_by_content_hash.assert_awaited_once_with(digest, pipeline.AUDIT_ENGINE_VERSION, pipeline.BASIS_PREVIEW)
    stored = json.loads(json.dumps({"score": score, "findings": paid["findings"]}))
    baseline = stored["score"]["free_baseline"]
    assert baseline["findings"] == free["findings"]
    assert baseline["score"] == json.loads(json.dumps(free["score"]))
    assert baseline["score"]["scan_manifest"]["secrets_coverage"]["exclusions"] == {"file_size_limit": 1}
    assert preview == original
    assert stored["score"]["total"] == paid["score"]["total"]
    html = render_report(stored)
    section = html.split('<section aria-label="Included free audit">', 1)[1].split('</section>', 1)[0]
    for finding in free["findings"]:
        assert escape(finding["title"]) in section
        assert escape(finding["file"]) in section
        if finding.get("masked"):
            assert escape(finding["masked"]) in section
    assert "over the 1 MiB file limit" in section
    assert "no finding does not establish that excluded content is safe" in section
    assert secret not in html and secret not in json.dumps(stored)
    assert preview["access_token"] not in html and preview["access_token"] not in json.dumps(stored)
