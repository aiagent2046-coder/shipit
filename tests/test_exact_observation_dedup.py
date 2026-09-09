"""Exact repetitions must score once without weakening source grouping.

All persisted observations and source metadata in the fixture are synthetic.
The chosen weights reproduce the duplicate-penalty scenario; matching repeated
claims does not verify them. The pipeline test also uses only an in-memory
archive and canned model responses.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from dataclasses import asdict, replace
import io
import json
from pathlib import Path
import zipfile

import pytest

from app.llm.client import LLMClient, LLMUsage
from app.scan.cross_rubric_dedup import dedup_cross_rubric
from app.scan.llm_scan import run_llm_scan
from app.scan.scoring import ScoredFinding, compute_scores


_FIXTURE = Path(__file__).parent / "fixtures" / "exact_observation_repeats.json"


def _fixture():
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


def _observations():
    data = _fixture()
    first = [ScoredFinding(**row) for row in data["frontend_observations"]]
    second = []
    for finding in first:
        evidence = deepcopy(finding.claim_evidence)
        assert evidence["producer"]["response"] == 1
        assert evidence["source_issue_identity"] is None
        evidence["producer"]["response"] = data["second_response"]
        second.append(replace(finding, claim_evidence=evidence))
    return first, second


def _fingerprints(rows):
    return Counter(json.dumps(row, sort_keys=True, ensure_ascii=False) for row in rows)


def _set_path(row, path, value):
    for key in path[:-1]:
        row = row[key]
    row[path[-1]] = value


def test_synthetic_seven_exact_pairs_score_once_and_retain_every_original():
    first, second = _observations()
    static = [ScoredFinding(**row) for row in _fixture()["frontend_static"]]
    raw = static + first + second
    before = [asdict(finding) for finding in raw]

    grouped = dedup_cross_rubric(raw)

    assert len(grouped) == 11  # Four static findings and seven model hypotheses.
    assert grouped[:4] == static  # Static and model observations stay separate.
    assert compute_scores(raw)["categories"]["Frontend"] == 2.9
    assert compute_scores(grouped)["categories"]["Frontend"] == 5.5
    assert compute_scores(grouped) == compute_scores(static + first)
    assert [asdict(finding) for finding in raw] == before

    originals = []
    for finding in grouped[4:]:
        leaves = finding.claim_evidence["grouped_originals"]
        assert len(leaves) == 2
        assert {leaf["claim_evidence"]["producer"]["response"] for leaf in leaves} == {1, 2}
        assert finding.verification_status == "unverified"
        assert finding.claim_evidence["conditions_status"] == "not_checked"
        assert finding.claim_evidence["consequence_status"] == "not_checked"
        assert all("grouped_originals" not in leaf["claim_evidence"] for leaf in leaves)
        originals.extend(leaves)
    assert _fingerprints(originals) == _fingerprints([asdict(f) for f in first + second])


def test_synthetic_exact_groups_are_idempotent_with_overlapping_saved_history():
    first, second = _observations()
    grouped = dedup_cross_rubric(first + second)
    assert dedup_cross_rubric(grouped) == grouped
    for replay in (grouped + first + second, first + grouped + second, grouped + grouped):
        regrouped = dedup_cross_rubric(replay)
        assert len(regrouped) == 7
        assert compute_scores(regrouped) == compute_scores(grouped)
        leaves = [leaf for finding in regrouped
                  for leaf in finding.claim_evidence["grouped_originals"]]
        assert _fingerprints(leaves) == _fingerprints([asdict(f) for f in first + second])
        assert dedup_cross_rubric(regrouped) == regrouped


def test_third_response_is_retained_without_another_score_penalty():
    first, second = _observations()
    prior = dedup_cross_rubric([first[0], second[0]])
    evidence = deepcopy(first[0].claim_evidence)
    evidence["producer"]["response"] = 3
    third = replace(first[0], claim_evidence=evidence)
    grouped = dedup_cross_rubric(prior + [third])
    assert len(grouped) == 1
    leaves = grouped[0].claim_evidence["grouped_originals"]
    assert {row["claim_evidence"]["producer"]["response"] for row in leaves} == {1, 2, 3}
    assert compute_scores(grouped) == compute_scores([first[0]])
    assert dedup_cross_rubric(grouped + [third]) == grouped


@pytest.mark.parametrize(("path", "value"), [
    pytest.param(("file",), "app/other/page.tsx", id="file"),
    pytest.param(("line",), 21, id="source-line"),
    pytest.param(("title",), "Same handler leaves another state stuck", id="claim-title"),
    pytest.param(("explanation",), "A different harmful consequence is asserted.", id="explanation"),
    pytest.param(("fix_hint",), "Disable retries instead of restoring the button.", id="recommendation"),
    pytest.param(("severity",), "high", id="severity"),
    pytest.param(("confidence",), 0.95, id="confidence"),
    pytest.param(("category",), "Auth", id="category"),
    pytest.param(("origin_category",), "Auth", id="origin-category"),
    pytest.param(("rule_id",), "llm-security", id="rule"),
    pytest.param(("context",), "test_fixture", id="eligibility-context"),
    pytest.param(("verification_status",), "observed", id="verification-status"),
    pytest.param(("claim_evidence", "producer", "model"), "different-model", id="model"),
    pytest.param(("claim_evidence", "producer", "rubric"), "security", id="rubric"),
    pytest.param(("claim_evidence", "producer", "request_id"), "another-request", id="other-producer-field"),
    pytest.param(("claim_evidence", "observation"), "A different code property is observed.", id="observation"),
    pytest.param(("claim_evidence", "required_conditions"), ["Only on an HTTP 500 response"], id="conditions"),
    pytest.param(("claim_evidence", "conditions_status"), "contradicted", id="conditions-status"),
    pytest.param(("claim_evidence", "consequence_status"), "observed", id="consequence-status"),
    pytest.param(("claim_evidence", "syntax_check", "result"), "contradicted", id="syntax-status"),
    pytest.param(("claim_evidence", "premise_checks", 0, "result"), "contradicted", id="premise-status"),
    pytest.param(("claim_evidence", "premise_checks", 0, "target"), "anotherResponse", id="premise-target"),
    pytest.param(("claim_evidence", "source_check", "line_end"), 33, id="quote-window"),
    pytest.param(("claim_evidence", "context_checks", 0, "scope"), "OtherComponent.save", id="function-scope"),
    pytest.param(("claim_evidence", "context_checks", 0, "line_end"), 31, id="function-range"),
    pytest.param(("claim_evidence", "context_checks", 0, "file"), "other/page.tsx", id="context-source-file"),
    pytest.param(("claim_evidence", "context_checks", 0, "checks", 0, "state"), "otherState", id="state-binding"),
    pytest.param(("claim_evidence", "recommendation_check"), {"result": "prerequisites_required"},
                 id="recommendation-status"),
])
def test_exact_fallback_keeps_substantive_differences_separate(path, value):
    first, second = _observations()
    changed = asdict(second[0])
    _set_path(changed, path, value)
    assert len(dedup_cross_rubric([first[0], ScoredFinding(**changed)])) == 2


def test_recorded_source_hash_is_not_ignored_even_with_identical_words():
    first, second = _observations()
    left, right = asdict(first[0]), asdict(second[0])
    for row in (left, right):
        row["claim_evidence"]["source_check"]["source_sha256"] = "a" * 64
    assert len(dedup_cross_rubric([ScoredFinding(**left), ScoredFinding(**right)])) == 1
    right["claim_evidence"]["source_check"]["source_sha256"] = "b" * 64
    assert len(dedup_cross_rubric([ScoredFinding(**left), ScoredFinding(**right)])) == 2


@pytest.mark.parametrize(("path", "value"), [
    pytest.param(("source",), "unknown", id="unknown-producer-source"),
    pytest.param(("verification_method",), "not_run", id="no-model-review"),
    pytest.param(("file",), "", id="missing-file"),
    pytest.param(("line",), 0, id="missing-line"),
    pytest.param(("line",), True, id="boolean-line"),
    pytest.param(("claim_evidence", "source_check"), None, id="null-source-check"),
    pytest.param(("claim_evidence", "source_check"), [], id="malformed-source-check"),
    pytest.param(("claim_evidence", "source_check", "kind"), "not_recorded", id="unbound-source"),
    pytest.param(("claim_evidence", "source_check", "line_start"), 0, id="zero-quote-line"),
    pytest.param(("claim_evidence", "source_check", "line_start"), True, id="boolean-quote-line"),
    pytest.param(("claim_evidence", "source_check", "line_start"), 21, id="anchor-before-quote"),
    pytest.param(("claim_evidence", "source_check", "line_end"), 19, id="anchor-after-quote"),
    pytest.param(("claim_evidence", "source_check", "line_end"), 17, id="inverted-quote-window"),
    pytest.param(("claim_evidence", "source_check", "line_end"), "32", id="string-quote-line"),
    pytest.param(("claim_evidence", "producer"), None, id="null-producer"),
    pytest.param(("claim_evidence", "producer"), [], id="malformed-producer"),
    pytest.param(("claim_evidence", "producer", "model"), "", id="missing-model"),
    pytest.param(("claim_evidence", "producer", "rubric"), "", id="missing-rubric"),
    pytest.param(("claim_evidence", "producer", "response"), 0, id="zero-response"),
    pytest.param(("claim_evidence", "producer", "response"), True, id="boolean-response"),
    pytest.param(("claim_evidence", "producer", "response"), "4", id="string-response"),
])
def test_unbound_or_malformed_observations_do_not_gain_exact_fallback(path, value):
    first, _ = _observations()
    row = asdict(first[0])
    _set_path(row, path, value)
    # Both payloads carry the same invalid binding. Equality alone must not
    # turn two unsupported observations into a trusted deduplication group.
    assert len(dedup_cross_rubric([ScoredFinding(**row), ScoredFinding(**deepcopy(row))])) == 2


def test_missing_and_unresolved_identity_are_not_mixed_by_exact_fallback():
    first, second = _observations()
    evidence = deepcopy(second[0].claim_evidence)
    del evidence["source_issue_identity"]
    legacy = replace(second[0], claim_evidence=evidence)
    assert len(dedup_cross_rubric([first[0], legacy])) == 2


def test_distinct_resolved_source_operations_stay_separate_from_exact_fallback():
    first, second = _observations()
    rows = [asdict(first[0]), asdict(second[0])]
    for index, row in enumerate(rows):
        row["claim_evidence"]["source_issue_identity"] = {
            "version": 1, "method": "source_ast", "file": row["file"],
            "source_sha256": "a" * 64, "function_span": [1, 100],
            "operation_span": [10 + index * 20, 20 + index * 20],
            "mechanism": "query_row_bound",
        }
    assert len(dedup_cross_rubric([ScoredFinding(**row) for row in rows])) == 2


class _RepeatedResponse(LLMClient):
    def __init__(self, raw):
        super().__init__(providers=[])
        self.raw = json.dumps([raw])
        self.calls = 0

    def complete(self, system, user, max_tokens=4096):
        self.calls += 1
        return self.raw, LLMUsage(model="fake-model", input_tokens=100, output_tokens=30)


def test_two_pass_scan_accounts_for_exact_unresolved_observation_once():
    source = (
        "import { useState } from 'react';\n"
        "export default function Form() {\n"
        "  const [saving, setSaving] = useState(false);\n"
        "  async function save() {\n"
        "    setSaving(true);\n"
        "    await fetch('/api/profile', { method: 'POST' });\n"
        "    setSaving(false);\n"
        "  }\n"
        "  return <button disabled={saving} onClick={save}>Save</button>;\n"
        "}\n"
    )
    raw = {
        "file": "app/profile/page.tsx", "line_start": 6, "line_end": 6,
        "evidence": "await fetch('/api/profile', { method: 'POST' });",
        "severity": "medium", "confidence": 0.85,
        "title": "Save leaves the button disabled if the request rejects",
        "observation": "The handler resets saving only after the awaited fetch.",
        "explanation": "A rejected fetch skips the reset, preventing another attempt.",
        "required_conditions": ["The fetch rejects before the reset."],
        "fix_hint": "Put the saving reset in a finally block.",
    }
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(raw["file"], source)
    archive.seek(0)
    client = _RepeatedResponse(raw)

    findings, stats = run_llm_scan(archive, client, rubrics=("web",), passes=2)

    assert client.calls == stats.calls == stats.prompts == 2
    assert stats.raw_findings == stats.verified == 2
    assert stats.discarded == 0
    assert len(findings) == 1
    finding = findings[0]
    assert finding.claim_evidence["source_issue_identity"] is None
    assert finding.claim_evidence["source_check"]["kind"] == "quote_match"
    assert finding.verification_status == "unverified"
    leaves = finding.claim_evidence["grouped_originals"]
    assert len(leaves) == 2
    assert {row["claim_evidence"]["producer"]["response"] for row in leaves} == {1, 2}
    assert stats.model_findings[0]["received"] == 2
    assert stats.model_findings[0]["accepted"] == 2
    assert stats.model_findings[0]["rejected"] == 0
    assert stats.model_findings[0]["merged"] == 1
    assert stats.model_findings[0]["saved"] == 1
    assert compute_scores(findings) == compute_scores([ScoredFinding(**leaves[0])])
    assert dedup_cross_rubric(findings) == findings
