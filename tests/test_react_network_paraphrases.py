"""Minimized synthetic save claims: source selection, extra scopes and boundaries."""
from copy import deepcopy
from dataclasses import asdict, replace

import pytest

from app.scan.cross_rubric_dedup import dedup_cross_rubric
from app.scan.issue_identity import SourceIssueResolver
from app.scan.react_async_context import collect_react_async_context
from app.scan.react_network_identity import network_cleanup_identity
from tests.test_react_network_identity import archive, row, source


def scene(options="{method: 'POST'}", endpoint="'/api/document'"):
    body = ("setSaving(true);\n"
            f"await fetch({endpoint}, {options});\n"
            "setSaving(false);\n")
    files = {"sample/src/Editor.tsx": source(body), "sample/src/Other.tsx": source()}
    buf = archive(files)
    facts = {"react_async": collect_react_async_context(buf)}
    rec = next(r for r in facts["react_async"]["records"] if r["file"] == "sample/src/Editor.tsx")
    common = {"file": rec["file"], "line_start": rec["line"] - 1, "line_end": rec["line_end"] + 1,
              "severity": "medium", "confidence": .85, "evidence": "setSaving(true)", "fix_hint": "Reset in finally."}
    first = {**common, "title": "A rejected save request can leave the save control stuck",
             "explanation": "If the document POST rejects, execution skips the later setSaving(false) "
                 "and the Save button remains disabled until the page is reloaded. "
                 "The same uncaught-rejection pattern affects other loading controls in `src/Other.tsx`; "
                 "network behavior has not been tested.",
             "observation": "The save handler sets saving before awaiting the request and resets it afterward, "
                 "with no catch or finally in the shown handler.",
             "required_conditions": ["The document POST rejects, for example because the network request fails.",
                                     "The user remains on the page after the rejection."]}
    second = {**common, "title": "Save can remain stuck after a network rejection",
              "explanation": "If this request rejects at the network level, execution skips the lines that clear "
                  "saving, leaving the save button disabled until the page is reloaded. "
                  "I have not checked live network behavior. "
                  "The same pattern also appears in 1 other supplied files: `sample/src/Other.tsx`.",
              "observation": "The save handler sets saving to true, awaits this fetch, and clears saving only "
                  "afterward; there is no catch or finally in the handler.",
              "required_conditions": ["The save request rejects before resolving, "
                                      "for example because of a network failure."]}
    return files, buf, facts, first, second


def identity(finding, facts, buf):
    return network_cleanup_identity(finding, facts, document_loader=SourceIssueResolver(buf, facts)._document)


def test_source_selected_paraphrases_group_with_original_extra_scopes_retained():
    files, buf, facts, first, second = scene()
    one, two = identity(first, facts, buf), identity(second, facts, buf)
    assert one and one == two
    assert one["ancillary_network_files"] == ["sample/src/Other.tsx"]
    rows = [row(f, files, buf, facts, i + 1) for i, f in enumerate((first, second))]
    grouped, = dedup_cross_rubric(rows)
    assert grouped.claim_evidence["grouped_originals"] == [asdict(r) for r in rows]
    assert dedup_cross_rubric([grouped, *rows]) == [grouped]
    assert grouped.verification_status == "unverified"


@pytest.mark.parametrize("options,endpoint", [
    ("{method: 'PUT'}", "'/api/document'"),
    ("{method: 'POST'}", "'/api/another'"),
    ("{method: 'POST', ...options}", "'/api/document'"),
    ("{method: 'POST', method: 'PUT'}", "'/api/document'"),
    ("{[key]: 'POST'}", "'/api/document'"),
    ("{method}", "'/api/document'"),
    ("{method: 'POST'}", "endpoint"),
])
def test_named_request_needs_unambiguous_source_endpoint_and_method(options, endpoint):
    _, buf, facts, first, _ = scene(options, endpoint)
    assert identity(first, facts, buf) is None


def test_endpoint_label_requires_source_document_and_matching_digest():
    _, buf, facts, first, _ = scene()
    assert network_cleanup_identity(first, facts) is None
    changed = deepcopy(facts)
    for rec in changed["react_async"]["records"]:
        rec["source_sha256"] = "a" * 64
    assert identity(first, changed, buf) is None


@pytest.mark.parametrize("extra", [
    " The HTTP response status is unchecked.",
    " When the request succeeds, the save button remains disabled.",
    " The user is charged twice.",
    " The same pattern affects a different operation.",
    " If another request rejects, execution skips the later setSaving(false).",
])
def test_additional_claims_are_not_consumed_by_network_paraphrase(extra):
    _, buf, facts, first, _ = scene()
    first["explanation"] += extra
    assert identity(first, facts, buf) is None


@pytest.mark.parametrize("replacement", [
    "`src/Missing.tsx`", "`../Other.tsx`", "`/src/Other.tsx`",
    "`sample/src/Other.tsx`, and `sample/src/Other.tsx`",
])
def test_unknown_unsafe_or_duplicate_annotation_paths_do_not_disappear(replacement):
    _, buf, facts, first, _ = scene()
    first["explanation"] = first["explanation"].replace("`src/Other.tsx`", replacement)
    assert identity(first, facts, buf) is None


def test_file_annotation_count_and_scope_are_part_of_identity():
    files, buf, facts, first, second = scene()
    second["explanation"] = second["explanation"].replace("1 other", "2 other")
    assert identity(second, facts, buf) is None
    second["explanation"] = second["explanation"].split(" The same pattern")[0]
    one, two = identity(first, facts, buf), identity(second, facts, buf)
    assert one and two and one != two
    assert len(dedup_cross_rubric([row(first, files, buf, facts), row(second, files, buf, facts, 2)])) == 2


def test_different_verification_status_remains_separate():
    files, buf, facts, first, second = scene()
    rows = [row(f, files, buf, facts, i + 1) for i, f in enumerate((first, second))]
    rows[1] = replace(rows[1], verification_status="confirmed")
    assert len(dedup_cross_rubric(rows)) == 2


def test_excerpt_spanning_two_handler_interiors_is_ambiguous():
    _, buf, facts, first, _ = scene()
    original = next(r for r in facts["react_async"]["records"] if r["file"] == first["file"])
    extra = deepcopy(original)
    extra.update(line=first["line_start"], line_end=first["line_start"] + 1, scope="EditorPanel.other")
    facts["react_async"]["records"].append(extra)
    assert identity(first, facts, buf) is None
