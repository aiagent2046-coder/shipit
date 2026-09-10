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
from app.scan.llm_scan import SYSTEM_PROMPT, build_prompt, run_llm_scan, verify_finding
from app.scan.manifest import scan_manifest
from app.scan.rejection_diagnostics import (
    MAX_DIAGNOSTIC_QUOTE_CHARS, MAX_DIAGNOSTIC_SOURCE_CHARS, MAX_DIAGNOSTIC_WINDOW_CHARS,
    MAX_REJECTION_ITEMS, acceptance_summary, diagnostics_manifest, rejected_item,
)


SOURCE = "export async function login() {\n  return await fetch('/session');\n}\n"
GOOD = dict(file="auth.ts", line_start=2, line_end=2, evidence="return await fetch",
            title="Session response is discarded", explanation="Inspect the HTTP response before using it.",
            severity="low", confidence=.8)


def archive(source=SOURCE):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as z:
        z.writestr("auth.ts", source)
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


def detail(candidate, source=SOURCE):
    return rejected_item(candidate, {"auth.ts": source}, response=1, rubric="auth", item=1,
                         reason="source_quote_or_location_mismatch")["detail"]


@pytest.mark.parametrize(("quote", "expected"), [
    ("2\t  return await fetch('/session');", "quote_prompt_line_prefix"),
    ("2\t  return await fetch('/session');\n3\t}", "quote_prompt_line_prefix"),
    ("return await ...('/session');", "quote_ellipsis_fragments_match"),
    ("return await …('/session');", "quote_ellipsis_fragments_match"),
    ("99\t  return await fetch('/session');", "quote_mismatch"),
    ("2:  return await fetch('/session');", "quote_mismatch"),
    ("2\t  return await fetch('/session');\n4\t}", "quote_mismatch"),
    ("return await fetch...('/session');", "quote_mismatch"),  # No omitted source text.
    ("return await ...('/invented');", "quote_mismatch"),
    ("('/session');...return await", "quote_mismatch"),
    ("...return await fetch('/session');", "quote_mismatch"),
    ("return await fetch(…);", "quote_mismatch"),  # Insufficient literal fragments.
    ("return  await fetch('/session');", "quote_mismatch"),
    ("return await fetch(\"/session\");", "quote_mismatch"),
    ("```return await fetch('/session');```", "quote_mismatch"),
])
def test_format_details_require_literal_support_and_never_admit_the_candidate(quote, expected):
    candidate = {**GOOD, "evidence": quote}
    before = deepcopy(candidate)
    assert not verify_finding(candidate, {"auth.ts": SOURCE})
    assert detail(candidate) == expected
    assert not verify_finding(candidate, {"auth.ts": SOURCE})
    assert candidate == before


def test_outside_window_search_is_literal_file_local_and_preserves_existing_tolerance():
    source = SOURCE + "// filler\n" * 8 + "const token = 'source-canary';\n"
    candidate = {**GOOD, "evidence": "source-canary"}
    assert not verify_finding(candidate, {"auth.ts": source})
    assert detail(candidate, source) == "quote_outside_cited_window"
    # Another file and a paraphrase are not evidence of a bad line coordinate.
    assert detail(candidate) == "quote_mismatch"
    assert detail({**candidate, "evidence": "source canary"}, source) == "quote_mismatch"
    # The existing +/-2 tolerance and multi-line admission remain unchanged.
    for start in (1, 4):
        assert verify_finding({**GOOD, "line_start": start, "line_end": start},
                              {"auth.ts": SOURCE + "// filler\n" * 2})
    assert not verify_finding({**GOOD, "line_start": 5, "line_end": 5},
                              {"auth.ts": SOURCE + "// filler\n" * 2})
    assert verify_finding({**GOOD, "evidence": SOURCE.strip(), "line_start": 1, "line_end": 3},
                          {"auth.ts": SOURCE})


def test_sensitive_rejected_quotes_and_their_hashes_never_reach_stats_manifest_or_html():
    secret = "PRIVATE-CREDENTIAL-CANARY-NOT-TO-BE-SAVED"
    source = f'const token = "{secret}";\n' + "// filler\n" * 8
    candidates = [
        {**GOOD, "line_start": 9, "line_end": 9, "evidence": secret},
        {**GOOD, "line_start": 1, "line_end": 1, "evidence": f'1\tconst token = "{secret}";'},
        {**GOOD, "line_start": 1, "line_end": 1, "evidence": f'const token ... "{secret}";'},
    ]
    client = Responses(candidates)
    findings, stats = run_llm_scan(archive(source), client, rubrics=("auth",))
    assert client.calls == 1 and findings == []
    manifest = scan_manifest(archive(source).getvalue(), "test", {}, asdict(stats), None)
    assert [item["detail"] for item in manifest["rejection_diagnostics"]["items"]] == [
        "quote_outside_cited_window", "quote_prompt_line_prefix", "quote_ellipsis_fragments_match"]
    html = render_report(dict(score=dict(total=0, categories={}, scan_manifest=manifest), findings=[]))
    for code in ("quote_outside_cited_window", "quote_prompt_line_prefix", "quote_ellipsis_fragments_match"):
        assert code in html
    persisted = json.dumps(asdict(stats)) + json.dumps(manifest) + html
    assert secret not in persisted
    for text in [source, secret] + [candidate["evidence"] for candidate in candidates]:
        assert hashlib.sha256(text.encode()).hexdigest() not in persisted
    assert manifest["model_acceptance"]["source_rejected"] == 3
    assert manifest["model_acceptance"]["accepted"] == 0


def test_extra_diagnostics_are_bounded_without_changing_admission():
    class OversizeSource(str):
        def splitlines(self, *args, **kwargs):
            raise AssertionError("Diagnostic must check size before splitting source")

    assert detail(GOOD, OversizeSource("x" * (MAX_DIAGNOSTIC_SOURCE_CHARS + 1))) == "diagnostic_limit_reached"
    assert detail({**GOOD, "evidence": "x" * (MAX_DIAGNOSTIC_QUOTE_CHARS + 1)}) == "diagnostic_limit_reached"
    large_window = "x" * (MAX_DIAGNOSTIC_WINDOW_CHARS + 1) + "\n" + SOURCE
    assert detail({**GOOD, "evidence": "return await ...('/session');"}, large_window) == "diagnostic_limit_reached"
    # Bounds are for additional diagnostics, never a new gate on valid quotes.
    long_quote = "x" * (MAX_DIAGNOSTIC_QUOTE_CHARS + 1)
    assert verify_finding({**GOOD, "line_start": 1, "line_end": 1, "evidence": long_quote},
                          {"auth.ts": long_quote})
    exact_syntax = "const args = [...values];\n"
    assert verify_finding({**GOOD, "line_start": 1, "line_end": 1, "evidence": "[...values]"},
                          {"auth.ts": exact_syntax})


def test_prompt_contract_and_json_escaping_keep_source_separate_from_numbered_gutter():
    source = 'const token = "quoted\\\\path";\n'
    prompt = build_prompt([("auth.ts", source)], "auth")
    assert '1\t' + source.strip() in prompt
    assert "one contiguous verbatim substring" in SYSTEM_PROMPT
    assert "do not copy the gutter's line number and tab" in SYSTEM_PROMPT
    assert "Apply JSON string escaping once" in SYSTEM_PROMPT
    assert "Never insert ellipses" in SYSTEM_PROMPT
    candidate = {**GOOD, "line_start": 1, "line_end": 1, "evidence": source.strip()}
    # Valid JSON encoding is decoded by the scanner; double escaping and copied
    # display prefixes are not silently repaired and do not trigger retries.
    escaped_twice = json.dumps(candidate["evidence"])[1:-1]
    client = Responses([candidate, {**candidate, "evidence": escaped_twice},
                        {**candidate, "evidence": "1\t" + candidate["evidence"]}])
    findings, stats = run_llm_scan(archive(source), client, rubrics=("auth",))
    assert client.calls == 1 and len(findings) == 1
    assert stats.verified == 1 and stats.discarded == 2
    assert [row["detail"] for row in stats.rejected_items] == ["quote_mismatch", "quote_prompt_line_prefix"]
