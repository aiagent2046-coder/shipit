"""Exercise model admission, source context, grouping and rendering together."""
from dataclasses import asdict, replace
import json

import pytest

from app.report.evidence import claim_evidence_rows
from app.scan.claim_evidence import partial_contradicted, syntax_contradicted
from app.scan.cross_rubric_dedup import _flatten, dedup_cross_rubric
from app.scan.llm_scan import run_llm_scan
from app.scan.scoring import compute_scores
from tests.test_audit_llm_wiring import make_zip
from tests.test_llm_scan import FakeLLM


SOURCE = '''export async function GET(req) {
  const rawLimit = parseInt(req.nextUrl.searchParams.get('limit') ?? '20', 10);
  const matchCount = Number.isFinite(rawLimit) ? Math.min(100, Math.max(1, rawLimit)) : 20;
  const result = await client.rpc('lookup', { match_count: matchCount });
  return result;
}'''


@pytest.mark.parametrize("passes", [1, 2])
def test_bound_context_survives_model_pipeline_without_certifying_the_claim(passes):
    raw = {
        "file": "app/api/query/route.ts", "line_start": 4, "line_end": 4,
        "evidence": "const result = await client.rpc('lookup', { match_count: matchCount });",
        "title": "Negative limit reaches the RPC without a lower bound",
        "explanation": "The model claims the query count can remain negative.",
        "observation": "The route forwards a count to the RPC.",
        "required_conditions": ["The bound passed to the RPC permits a negative count."],
        "fix_hint": "Review the value passed to the RPC before changing this route.",
        "category": "Security", "severity": "medium", "confidence": 0.8,
        "context_checks": [{"kind": "finite_clamp_rpc_argument", "result": "verified",
                            "source_binding": {"file": "MODEL_METADATA_SENTINEL"}}],
    }
    findings, stats = run_llm_scan(
        make_zip({raw["file"]: SOURCE.encode()}), FakeLLM(json.dumps([raw])),
        rubrics=("security",), passes=passes,
    )
    assert stats.calls == stats.verified == passes
    assert stats.discarded == 0
    assert len(findings) == 1
    originals = list(_flatten(findings[0]))
    assert len(originals) == passes
    for finding in originals:
        assert finding.title == raw["title"]
        assert finding.explanation == raw["explanation"]
        assert finding.severity == raw["severity"]
        assert finding.confidence == raw["confidence"]
        record = finding.claim_evidence
        assert record["required_conditions"] == raw["required_conditions"]
        assert record["conditions_status"] == record["consequence_status"] == "not_checked"
        contexts = [c for c in record["context_checks"] if c["kind"] == "finite_clamp_rpc_argument"]
        assert len(contexts) == 1
        assert contexts[0]["result"] == "observed"
        assert contexts[0]["scope"] == "bounded_source_context"
        # Existing independent premise checks may already refute this clause.
        # Adding observational context must leave that disposition unchanged.
        before_context = {**record, "context_checks": []}
        assert partial_contradicted(record) == partial_contradicted(before_context)
        assert syntax_contradicted(record) == syntax_contradicted(before_context)
        assert "MODEL_METADATA_SENTINEL" not in json.dumps(record)
        without_context = replace(finding, claim_evidence=before_context)
        assert compute_scores([finding]) == compute_scores([without_context])
        rendered = json.dumps(claim_evidence_rows(asdict(finding)))
        assert "Bounded source context" in rendered
        assert "Checked source context binding" in rendered
    assert dedup_cross_rubric(findings) == findings
