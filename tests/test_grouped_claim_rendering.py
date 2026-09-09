"""Readers see the scope and title disagreement of a grouped hypothesis."""
from copy import deepcopy

from app.report.evidence import claim_evidence_rows
from app.report.html import render_report


def finding():
    return dict(rule_id="llm-web", source="llm", category="Frontend", severity="medium", confidence=.8,
                title="Save cleanup", file="screen.tsx", line=4, claim_evidence={
                    "version": 1, "source_issue_identity": {"handler": "save"},
                    "grouped_originals": [{"title": "Save cleanup"}, {"title": "Wrong send label"}],
                    "grouped_claim_scope": {"mechanism": "react_network_rejection_cleanup",
                        "scope": "ignored model-like text", "consequences": "ignored opaque claim",
                        "title_source_disagreements": [{"original_index": 1,
                            "result": "different_handler_label", "source_handler": "save"}]}})


def test_group_scope_and_mislabeled_original_are_visible_without_changing_the_record():
    f = finding()
    before = deepcopy(f)
    html = render_report(dict(score={"total": 5, "categories": {}}, findings=[f]))
    assert "Grouped hypothesis scope" in html
    assert "Original 2 uses a different handler label. Bound source handler: save." in html
    assert "Wrong send label" in html
    assert "Original conditions and consequences retain their own verification statuses." in html
    assert "ignored model-like text" not in html
    assert "ignored opaque claim" not in html
    assert f == before


def test_unknown_group_scope_does_not_claim_operation_equivalence():
    f = finding()
    f["claim_evidence"]["grouped_claim_scope"]["mechanism"] = "unrecognized"
    rows = dict(claim_evidence_rows(f))
    assert "Grouped hypothesis scope" not in rows
    assert "Handler label needs review" not in rows
    assert "Grouped original 2 — not independent confirmation" in rows


def test_malformed_disagreements_cannot_accuse_an_unrelated_original_or_source_handler():
    f = finding()
    item = f["claim_evidence"]["grouped_claim_scope"]["title_source_disagreements"][0]
    f["claim_evidence"]["grouped_claim_scope"]["title_source_disagreements"] = [
        {**item, "original_index": True}, {**item, "original_index": 99},
        {**item, "source_handler": "otherHandler"}, None]
    rows = dict(claim_evidence_rows(f))
    assert "Grouped hypothesis scope" in rows
    assert "Handler label needs review" not in rows
