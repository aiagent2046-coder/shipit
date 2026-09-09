"""Admission failures stay inspectable without retaining rejected source text."""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import io
import json
import zipfile

import pytest

from app.llm.client import LLMClient, LLMUsage
from app.report.evidence import model_acceptance_notice
from app.report.html import render_report
from app.scan.llm_scan import run_llm_scan, verify_finding
from app.scan.manifest import scan_manifest
from app.scan.rejection_diagnostics import MAX_REJECTION_ITEMS, acceptance_summary, diagnostics_manifest


SOURCE = "export async function login() {\n  return await fetch('/session');\n}\n"
GOOD = dict(file="auth.ts", line_start=2, line_end=2, evidence="return await fetch",
            title="Session response is discarded", explanation="Inspect the HTTP response before using it.",
            severity="low", confidence=.8)


def archive():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as z:
        z.writestr("auth.ts", SOURCE)
    output.seek(0)
    return output


class Responses(LLMClient):
    def __init__(self, *values):
        super().__init__(providers=[])
        self.values = iter(values)
        self.calls = 0

    def complete(self, *args, **kwargs):
        self.calls += 1
        return json.dumps(next(self.values)), LLMUsage(model="fixture", input_tokens=10, output_tokens=10)


def processing(received=11, accepted=1, **reasons):
    reasons = reasons or dict(source_quote_or_location_mismatch=9, self_cancelled=1)
    return [dict(model="fixture", responses=1, invalid_responses=0, empty_responses=0,
                 received=received, accepted=accepted, rejected=received - accepted,
                 saved=accepted, merged=0, rejection_reasons=reasons)]


def test_rejections_have_safe_coordinates_and_distinct_source_reasons_without_changing_admission():
    secret = "PRIVATE-SOURCE-CANARY-DO-NOT-RETAIN"
    candidates = [GOOD, {**GOOD, "file": secret}, {**GOOD, "line_end": 999},
                  {**GOOD, "evidence": ""}, {**GOOD, "evidence": secret},
                  {**GOOD, "fix_hint": "No action needed"}, None]
    client = Responses(candidates)
    findings, stats = run_llm_scan(archive(), client, rubrics=("auth",))
    assert client.calls == 1
    assert len(findings) == 1
    assert findings[0].title == GOOD["title"]
    assert [verify_finding(f, {"auth.ts": SOURCE}) for f in candidates[:-1]] == [
        True, False, False, False, False, True]
    manifest = scan_manifest(archive().getvalue(), "test", {}, asdict(stats), None)
    assert manifest["model_acceptance"] == dict(version=1, state="partially_accepted", received=7,
                                               accepted=1, rejected=6, source_rejected=4,
                                               withdrawn=1, other_rejected=1)
    diagnostics = manifest["rejection_diagnostics"]
    assert diagnostics["omitted"] == 0
    assert [r["detail"] for r in diagnostics["items"]] == [
        "unknown_file", "invalid_line_range", "quote_missing_or_short", "quote_mismatch",
        "self_cancelled", "not_an_object"]
    assert [r["item"] for r in diagnostics["items"]] == [2, 3, 4, 5, 6, 7]
    assert {r["response"] for r in diagnostics["items"]} == {1}
    assert diagnostics["items"][0]["file_ref"] is None
    assert diagnostics["items"][1]["file_ref"] == "sha256:" + hashlib.sha256(b"auth.ts").hexdigest()
    html = render_report(dict(score=dict(total=9.3, categories={}, scan_manifest=manifest), findings=[]))
    assert "Model observations accepted: 1 of 7" in html
    assert html.index("Model observations accepted") < html.index("Rejected observation")
    assert "4 could not be matched to the cited source" in html
    assert "establish project safety" in html
    assert secret not in json.dumps(manifest) + html
    assert GOOD["evidence"] not in json.dumps(diagnostics)


def test_record_cap_is_global_across_responses_but_counts_and_findings_stay_complete():
    bad = {**GOOD, "evidence": "a phrase absent from source"}
    client = Responses([bad] * (MAX_REJECTION_ITEMS - 1), [bad] * 4 + [GOOD])
    findings, stats = run_llm_scan(archive(), client, rubrics=("auth",), passes=2)
    assert client.calls == 2
    assert len(findings) == 1
    assert len(stats.rejected_items) == MAX_REJECTION_ITEMS
    assert stats.rejected_items[-1]["response"] == 2
    assert stats.rejected_items[-1]["item"] == 1
    assert stats.rejected_items_omitted == 3
    summary = acceptance_summary(stats.model_findings)
    assert summary["received"] == MAX_REJECTION_ITEMS + 4
    assert summary["rejected"] == MAX_REJECTION_ITEMS + 3
    assert summary["accepted"] == 1


@pytest.mark.parametrize("patch", [
    {"accepted": -1}, {"received": True}, {"rejected": 0}, {"received": "11"},
    {"rejection_reasons": {}}, {"rejection_reasons": {"self_cancelled": float("nan")}},
    {"received": 2 ** 53}, {"rejection_reasons": []},
])
def test_invalid_accounting_does_not_become_zero_findings_or_a_quality_verdict(patch):
    rows = processing()
    rows[0].update(patch)
    assert acceptance_summary(rows) is None
    assert model_acceptance_notice({"scan_manifest": {"model_findings": rows}}) is None


def test_missing_accounting_empty_response_and_withdrawals_remain_distinct():
    for missing in (None, [], {}, [None]):
        assert acceptance_summary(missing) is None
    no_candidates = processing(received=0, accepted=0)
    no_candidates[0]["rejection_reasons"] = {}
    assert acceptance_summary(no_candidates)["state"] == "no_candidates"
    withdrawn = processing(received=3, accepted=0, self_cancelled=3)
    title, detail = model_acceptance_notice({"scan_manifest": {"model_findings": withdrawn}})
    assert title == "Model observations accepted: 0 of 3"
    assert "3 were withdrawn" in detail
    assert "could not be matched" not in detail
    assert "failed response" not in detail
    all_accepted = processing(received=2, accepted=2)
    all_accepted[0]["rejection_reasons"] = {}
    assert acceptance_summary(all_accepted)["state"] == "all_accepted"
    assert model_acceptance_notice({"scan_manifest": {"model_findings": all_accepted}}) is None


def test_new_summary_never_overrides_canonical_processing_or_free_baseline():
    free = dict(total=9.3, categories={}, basis="static+preview",
                scan_manifest={"model_findings": processing()})
    paid = dict(total=4.9, categories={}, basis="static+llm", scan_manifest={
        "model_findings": processing(received=59, accepted=55, self_cancelled=4),
        "model_acceptance": dict(version=1, received=0, accepted=0, rejected=0)},
        free_baseline=dict(version=1, origin="reused", status="completed", findings=[], score=free))
    before = deepcopy(paid)
    html = render_report(dict(score=paid, findings=[]))
    assert "Model observations accepted: 55 of 59" in html
    assert "Model observations accepted: 1 of 11" in html
    assert paid == before
    assert free["total"] == 9.3 and paid["total"] == 4.9


def test_manifest_projection_drops_arbitrary_model_fields_and_unsafe_reference_strings():
    canary = "<script>private-quote-and-path</script>"
    safe = dict(response=1, item=2, rubric="auth", reason="invalid_text", detail="invalid_text",
                line_start=3, line_end=4, file_ref=canary, evidence=canary, file=canary,
                observation={"unexpected": canary})
    result = diagnostics_manifest({"rejected_items": [safe, {**safe, "reason": []},
                                                     {**safe, "rubric": canary}]})
    assert result["omitted"] == 2
    assert len(result["items"]) == 1
    assert result["items"][0]["file_ref"] is None
    assert canary not in json.dumps(result)
    assert "evidence" not in result["items"][0]
    assert diagnostics_manifest({}) is None


def test_diagnostics_cannot_overflow_the_shared_json_integer_bound():
    result = diagnostics_manifest({"rejected_items": [None], "rejected_items_omitted": 2 ** 53 - 1})
    assert result["omitted"] == 2 ** 53 - 1
