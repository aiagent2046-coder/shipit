"""Public outputs keep the corrected premise active and the model original historical."""
from copy import deepcopy
from dataclasses import asdict
from html.parser import HTMLParser
import json
from pathlib import Path

import jsonschema
import pytest

from app.report.evidence import claim_evidence_rows
from app.report.html import _finding_row
from app.report.sarif import build_sarif
from app.scan.claim_narrative import narrative_projection, project_claim_narrative
from tests.test_claim_narrative import FACT_CALLER, fixture

FIXTURES = Path(__file__).parents[1] / "web/src/lib/fixtures/claim_narrative_cases.json"


class VisibleText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.depth = 0
        self.active = []
        self.original = []

    def handle_starttag(self, tag, attrs):
        if tag == "details":
            self.depth += 1

    def handle_endtag(self, tag):
        if tag == "details":
            self.depth -= 1

    def handle_data(self, text):
        (self.original if self.depth else self.active).append(text)


def generated(kind):
    if kind == "configured_facts":
        config = json.dumps({"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["./src/*"]}}})
        finding, hashes = fixture(caller=FACT_CALLER.replace("'./helper'", "'@/helper'"),
                                   extra={"tsconfig.json": config})
    else:
        finding, hashes = fixture(kind)
    return asdict(project_claim_narrative(finding, current_source_hashes=hashes))


def query_group():
    from app.scan.cross_rubric_dedup import dedup_cross_rubric
    from tests.test_query_read_identity import _finding, _raw, TITLES

    findings = [_finding(), _finding(_raw(TITLES[1]), response=7)]
    # The grouping unit fixture omits display-only prose; real scanner records
    # carry it. Supply a complete saved evidence record for renderer coverage.
    for finding in findings:
        finding.claim_evidence["syntax_check"].update(claim="Query pagination", detail="Not assessed by this check.")
        for check in finding.claim_evidence["premise_checks"]:
            check.update(claim="The query has no pagination bound.", detail="The runtime row bound is not checked.")
    return asdict(dedup_cross_rubric(findings)[0])


@pytest.mark.parametrize("kind", ["facts", "retry", "configured_facts"])
def test_browser_fixtures_are_current_scanner_output_and_public_exports_agree(kind):
    finding = generated(kind)
    assert json.loads(FIXTURES.read_text())[kind] == finding
    before = deepcopy(finding)
    projection = narrative_projection(finding)
    assert projection is not None
    parser = VisibleText()
    parser.feed(_finding_row(finding))
    active, original = " ".join(parser.active), " ".join(parser.original)
    for key in ("title", "explanation", "fix_hint"):
        assert finding[key] in active
        assert projection["original"][key] in original
        assert projection["original"][key] not in active
    rows = dict(claim_evidence_rows(finding))
    assert rows["Source interpretation — outcome unverified"] == finding["claim_evidence"]["observation"]
    assert "fixture-model" in rows["Original model provenance — not independent confirmation"]
    assert "Severity and score eligibility are unchanged" in rows["Recorded wording correction"]
    assert "Model interpretation — unverified" not in rows
    sarif = build_sarif([finding], engine_version="fixture")
    result = sarif["runs"][0]["results"][0]
    assert result["message"]["text"] == finding["title"] + ". " + finding["explanation"]
    assert result["level"] == "warning"
    assert result["properties"]["narrativeProjection"] == projection
    assert result["properties"]["requiredConditions"] == finding["claim_evidence"]["required_conditions"]
    assert result["properties"]["verificationStatus"] == "unverified"
    assert sarif["runs"][0]["tool"]["driver"]["rules"][0]["help"]["text"] == finding["fix_hint"]
    schema = json.loads((Path(__file__).parent / "fixtures/sarif-schema-2.1.0.json").read_text())
    jsonschema.validate(sarif, schema, format_checker=jsonschema.FormatChecker())
    assert finding == before


@pytest.mark.parametrize("mutate", [
    lambda f: f.update(title="Every fact reaches the prompt without a limit"),
    lambda f: f.update(source="static"),
    lambda f: f["claim_evidence"]["narrative_projection"].update(source_hashes={}),
    lambda f: f["claim_evidence"]["source_assessments"][0].update(file="elsewhere.ts"),
    lambda f: f["claim_evidence"]["narrative_projection"]["active"].update(title="Arbitrary correction"),
])
def test_marker_does_not_relabel_mismatched_or_static_data_as_corrected(mutate):
    finding = generated("facts")
    mutate(finding)
    assert narrative_projection(finding) is None
    assert "Recorded wording correction" not in dict(claim_evidence_rows(finding))
    assert "Superseded model wording — source premise corrected" not in _finding_row(finding)
    result = build_sarif([finding], engine_version="fixture")["runs"][0]["results"][0]
    assert "properties" not in result


def test_legacy_history_is_not_reassessed_and_saved_projection_preserves_both_wordings():
    original, _ = fixture()
    legacy = asdict(original)
    assert "Superseded model wording" not in _finding_row(legacy, historical=True)
    assert legacy["title"] in _finding_row(legacy, historical=True)
    finding = generated("facts")
    before = deepcopy(finding)
    html = _finding_row(finding, historical=True)
    assert "Recorded verification guidance — not reassessed" in html
    assert "Superseded model wording — source premise corrected" in html
    assert finding["title"] in html
    assert finding == before


def test_original_model_markup_is_escaped():
    finding = generated("facts")
    finding["claim_evidence"]["narrative_projection"]["original"]["title"] = "<script>alert(1)</script>"
    html = _finding_row(finding)
    assert "<script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_query_group_scope_and_originals_survive_public_exports_without_claiming_cost_proof():
    finding = query_group()
    assert json.loads(FIXTURES.read_text())["query_group"] == finding
    rows = dict(claim_evidence_rows(finding))
    assert "claimed costs remain separate and unverified" in rows["Grouped hypothesis scope"]
    assert "Grouped original 1 — not independent confirmation" in rows
    assert "Grouped original 2 — not independent confirmation" in rows
    result = build_sarif([finding], engine_version="fixture")["runs"][0]["results"][0]
    assert result["properties"]["groupedOriginals"] == finding["claim_evidence"]["grouped_originals"]
    assert result["properties"]["verificationStatus"] == "unverified"
    assert result["level"] == "note"
    finding["claim_evidence"]["source_issue_identity"]["file"] = "another.ts"
    assert "Grouped hypothesis scope" not in dict(claim_evidence_rows(finding))
    assert "properties" not in build_sarif([finding], engine_version="fixture")["runs"][0]["results"][0]
