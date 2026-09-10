"""Observed source context remains visibly separate from claim refutation."""
from copy import deepcopy

import pytest

from app.report.evidence import claim_evidence_rows
from app.report.html import render_report
from tests.test_consequence_evidence import (
    CLIENT, DISCARD, OAUTH, REACT, check, clicks, discarded, duplicate, oauth, route_files,
)


@pytest.mark.parametrize("source,raw,others", [
    (OAUTH, oauth(), None), (REACT, clicks(), None), (DISCARD, discarded(), None),
    (CLIENT, duplicate(), route_files()),
])
def test_actual_source_context_and_binding_are_visible_without_a_refutation_badge(source, raw, others):
    premises = check(source, raw, others)
    assert any(item["result"] == "observed" for item in premises)
    f = dict(rule_id="llm-web", category="Frontend", source="llm", severity="high", confidence=.8,
             title=raw["title"], explanation=raw["explanation"], file=raw["file"], line=raw["line_start"],
             claim_evidence=dict(version=1, context_checks=premises))
    before = deepcopy(f)
    rows = dict(claim_evidence_rows(f))
    assert "Bounded source context — compare with the model claim" in rows
    assert "Source context only" in rows["Bounded source context — compare with the model claim"]
    assert "source_sha256" in rows["Checked source context binding"]
    html = render_report(dict(score=dict(total=5, categories={}), findings=[f]))
    assert "Bounded source context — compare with the model claim" in html
    assert "Potential high impact" in html
    assert "Assessment needs review" not in html
    assert "Atomic premise contradicted" not in html
    assert "No independent verification recorded." in html
    assert f == before


def test_unknown_context_is_not_rendered_as_observed():
    f = dict(claim_evidence={"version": 1, "context_checks": [{
        "kind": "token_write_return_guard", "scope": "bounded_source_context", "result": "not_checked",
        "claim": "A local return guard", "detail": "Source parsing budget exhausted."}]})
    rows = dict(claim_evidence_rows(f))
    assert "Source context not checked" in rows
    assert "Bounded source context — compare with the model claim" not in rows
    assert "Checked source context binding" not in rows
