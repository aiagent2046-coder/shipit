"""A refreshed free baseline keeps current, retained and reused evidence distinct."""
from copy import deepcopy
from html import escape
import json
from pathlib import Path
import re

import pytest

from app.audit_history import baseline_snapshot
from app.report.html import render_report


CASES = json.loads((Path(__file__).parents[1] / "web/src/lib/fixtures/dependency_snapshot_cases.json").read_text())


def snapshot_finding(title, *, retained=False):
    return {"rule_id": "dependency-cve-match", "title": title, "severity": "high",
            "confidence": .9, "category": "Security", "source": "dependency",
            "verification_method": "package_version_match", "fix_hint": "Review the advisory.",
            "claim_evidence": {"version": 1, "snapshot_sources": [{
                "name": "cvelist", **CASES[0]["coverage"]["sources"]["cvelist"]}],
                **({"snapshot_check_status": "retained_not_reconfirmed"} if retained else {})}}


def paid_result(findings, case):
    free = {"basis": "static+preview", "categories": {}, "scan_manifest": {
        "model_calls": 1, "sca_skipped_reason": "no_client", "dependency_cve": deepcopy(case["coverage"]),
        "dependency_snapshot": deepcopy(case["metadata"]), "limitations": []}}
    return {"score": {"basis": "static+llm", "categories": {},
                      "free_baseline": baseline_snapshot(free, findings, "refreshed", "old-preview")},
            "findings": []}


def test_refreshed_baseline_distinguishes_new_matches_retained_matches_and_reused_model():
    new = snapshot_finding("Newly published advisory match")
    retained = snapshot_finding("Earlier advisory match", retained=True)
    model = {"rule_id": "llm-security", "title": "Original model observation", "source": "llm",
             "category": "Security", "severity": "medium", "confidence": .8, "fix_hint": "Earlier model suggestion"}
    result = paid_result([new, retained, model], next(c for c in CASES if c["name"] == "partial-retained"))
    result["score"]["free_baseline"]["score"]["scan_manifest"]["dependency_snapshot"]["retained_findings"] = 1
    before = deepcopy(result)
    html = render_report(result)
    assert "Free audit with refreshed dependency snapshot" in html
    assert "Static observations and model hypotheses were reused without rerunning their checks." in html
    rows = re.findall(r"<tr>.*?</tr>", html)
    for finding, label, guidance in (
        (new, "Dependency match — checked with refreshed snapshot",
         "Snapshot advisory guidance — reachability unverified"),
        (retained, "Earlier dependency finding — not reconfirmed", "Earlier advisory guidance — not reconfirmed"),
        (model, "Reused free audit observation — not reassessed", "Reused free audit suggestion — not reassessed"),
    ):
        row = next(row for row in rows if finding["title"] in row)
        assert label in row
        assert guidance in row
        assert "Previous preview — not reassessed" not in row
        assert "Potential high impact" not in row
    assert result == before


@pytest.mark.parametrize("case", [c for c in CASES if c["notice_titles"]], ids=lambda c: c["name"])
def test_paid_html_keeps_nested_snapshot_warnings_visible_before_baseline_findings(case):
    result = paid_result([snapshot_finding("Earlier advisory match", retained=True)], case)
    html = render_report(result)
    section = html[html.index('<section aria-label="Included free audit">'):]
    for title in case["notice_titles"]:
        assert section.index(f'aria-label="{escape(title)}"') < section.index("Full baseline findings and scope")
    if "Earlier dependency findings retained" in case["notice_titles"]:
        assert "the current check did not reconfirm them" in section
