"""Incomplete external evidence must not become a clean or fresher audit."""
from copy import deepcopy
import json

import pytest

from app.llm.client import LLMClient
from app.report.evidence import manifest_rows
from app.sca.osv import OsvClient
from app.sca.refresh import inventory_payload, refresh_stale_dependency_audits, refreshed_score
from app.sca.stage import run_sca_stage
from app.scan.pipeline import run_scan
from tests.test_sca_refresh import NOW, StoredRepo, stored_row
from tests.test_sca_stage import FakeTransport, LODASH_ADVISORY, make_zip, repo_with


@pytest.mark.parametrize("results", [
    [], [{}, {}], [None], [{"error": {"code": 503}}],
    [{"vulns": None}], [{"vulns": {}}], [{"vulns": [None]}],
    [{"vulns": [{"id": ""}]}], [{"vulns": [{"id": 12}]}],
    [{"next_page_token": 7}],
])
def test_malformed_batch_answers_are_unavailable_not_clean(results):
    client = OsvClient(transport=FakeTransport([results], {}))
    findings, stats = run_sca_stage(repo_with(), client)
    assert findings == []
    assert stats["skipped_reason"].startswith("osv_unavailable")
    assert stats["asked_at"] is None


def test_pagination_queries_only_pending_packages_and_preserves_original_indexes():
    archive = make_zip({"package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/aaa": {"version": "1.0.0"},
        "node_modules/lodash": {"version": "4.17.4"}}})})
    record_id = LODASH_ADVISORY["id"]
    transport = FakeTransport(
        [[{}, {"next_page_token": "page-2"}], [{"vulns": [{"id": record_id}]}]],
        {record_id: LODASH_ADVISORY})
    findings, stats = run_sca_stage(archive, OsvClient(transport=transport))
    assert len(findings) == 1 and findings[0].title.endswith("lodash 4.17.4")
    assert transport.posts[1]["queries"] == [{
        "package": {"ecosystem": "npm", "name": "lodash"},
        "version": "4.17.4", "page_token": "page-2"}]
    assert stats["skipped_reason"] is None


@pytest.mark.parametrize("max_pages", [1, 3])
def test_unfinished_or_repeating_pagination_does_not_become_clean(max_pages):
    transport = FakeTransport([[{"next_page_token": "same-token"}]], {})
    findings, stats = run_sca_stage(repo_with(), OsvClient(
        transport=transport, max_query_pages=max_pages))
    assert findings == [] and stats["asked_at"] is None
    assert stats["skipped_reason"].startswith("osv_unavailable")
    assert len(transport.posts) <= max_pages


@pytest.mark.parametrize("patch", [
    {"id": "different-id"}, {"aliases": 7}, {"affected": "bad"},
    {"affected": [{"ranges": 1}]},
    {"affected": [{"ranges": [{"events": 7}]}]}, {"references": 7},
])
def test_malformed_advisory_details_are_unavailable_without_crashing(patch):
    record_id = LODASH_ADVISORY["id"]
    transport = FakeTransport([[{"vulns": [{"id": record_id}]}]],
                              {record_id: {**LODASH_ADVISORY, **patch}})
    findings, stats = run_sca_stage(repo_with(), OsvClient(transport=transport))
    assert findings == []
    assert stats["skipped_reason"] == "osv_unavailable: advisory details"
    assert stats["unreadable_advisories"] == 1


def test_malformed_optional_rating_and_url_do_not_crash_or_invent_source_facts():
    record_id = LODASH_ADVISORY["id"]
    record = {**LODASH_ADVISORY, "database_specific": ["HIGH"],
              "references": [{"url": {"bad": "type"}}]}
    findings, stats = run_sca_stage(repo_with(), OsvClient(transport=FakeTransport(
        [[{"vulns": [{"id": record_id}]}]], {record_id: record})))
    assert stats["skipped_reason"] is None
    assert findings[0].severity == "medium" and findings[0].confidence == 0.6
    assert f"https://osv.dev/vulnerability/{record_id}" in findings[0].fix_hint


def test_an_empty_supported_lockfile_is_not_reported_as_absent():
    archive = make_zip({"package-lock.json": '{"lockfileVersion": 3, "packages": {}}'})
    transport = FakeTransport([[{}]], {})
    scan = run_scan(archive, LLMClient(), sca_client=OsvClient(transport=transport))
    assert scan["sca"]["skipped_reason"] == "no_resolved_dependencies"
    assert transport.posts == []
    assert "Supported lockfiles were read" in dict(manifest_rows(scan["score"]))["Dependencies checked"]


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["partial_details", "detail_budget", "bad_batch", "pagination"])
async def test_incomplete_refresh_preserves_confirmed_findings_score_and_age(failure):
    row = stored_row(10)
    before = deepcopy(row)
    record_id = LODASH_ADVISORY["id"]
    another = {**LODASH_ADVISORY, "id": "GHSA-other", "aliases": ["CVE-2026-1234"]}
    details = {record_id: LODASH_ADVISORY, "GHSA-other": another}
    results = [{"vulns": [{"id": record_id}, {"id": "GHSA-other"}]}]
    options = {}
    if failure == "partial_details":
        del details[record_id]
    elif failure == "detail_budget":
        options["max_details"] = 1
    elif failure == "bad_batch":
        results = []
    else:
        results[0]["next_page_token"] = "unread-page"
        options["max_query_pages"] = 1
    repo = StoredRepo([row])
    summary = await refresh_stale_dependency_audits(repo, now=NOW, client_factory=lambda: OsvClient(
        transport=FakeTransport([results], details), **options))
    assert summary["refreshed"] == 0 and summary["unavailable"] == 1
    assert repo.created == []
    assert row == before, "a failed query must not improve severity, score, or freshness"


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["missing_entry", "invalid_line", "unknown_version", "capped", "unsupported"])
async def test_incomplete_stored_inventory_cannot_delete_old_findings(fault):
    row = stored_row(10)
    payload = row["dependency_inventory"]
    if fault == "missing_entry":
        payload["dependencies"].append({"name": "broken"})
    elif fault == "invalid_line":
        payload["dependencies"][0]["line"] = "invalid"
    elif fault == "unknown_version":
        payload["version"] = 999
    elif fault == "capped":
        payload["found"] += 1
    else:
        payload["incomplete_manifests"] = {"go.mod": "unsupported"}
    repo = StoredRepo([row])
    transport = FakeTransport([[{}]], {})
    summary = await refresh_stale_dependency_audits(
        repo, now=NOW, client_factory=lambda: OsvClient(transport=transport))
    assert summary["refreshed"] == 0 and summary["skipped"] == 1
    assert repo.created == [] and transport.posts == []


@pytest.mark.parametrize("bad_file,text", [
    ("poetry.lock", "package = 7\n"),
    ("go.mod", "module example.test/main\nrequire example.test/lib v1.2.3\n"),
])
def test_mixed_supported_and_incomplete_inventory_stays_visible(bad_file, text):
    archive = make_zip({
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/lodash": {"version": "4.17.4"}}}), bad_file: text})
    scan = run_scan(archive, LLMClient(), sca_client=OsvClient(transport=FakeTransport([[{}]], {})))
    manifest = scan["score"]["scan_manifest"]
    assert manifest["sca_dependencies"] == 1 and manifest["sca_asked_at"]
    assert manifest["sca_coverage_incomplete"]
    assert bad_file in manifest["sca_incomplete_lockfiles"]
    assert "dependency_coverage_incomplete" in manifest["limitations"]
    report = dict(manifest_rows(scan["score"]))["Dependencies checked"]
    assert "not a complete repository check" in report
    assert inventory_payload(archive, scan["sca"]["asked_at"])["incomplete_manifests"]


def test_filtered_low_advisories_are_not_reported_as_no_known_vulnerabilities():
    record_id = LODASH_ADVISORY["id"]
    transport = FakeTransport([[{"vulns": [{"id": record_id}]}]],
                              {record_id: {**LODASH_ADVISORY, "database_specific": {"severity": "LOW"}}})
    scan = run_scan(repo_with(), LLMClient(), sca_client=OsvClient(transport=transport))
    report = dict(manifest_rows(scan["score"]))["Dependencies checked"]
    assert "no known vulnerabilities" not in report
    assert "below-threshold advisories" in report


def test_successful_refresh_replaces_old_dependency_limits_and_completeness_fields():
    row = stored_row(10)
    score = row["score_json"]
    score["scan_manifest"].update({"sca_unreadable_advisories": 3,
                                    "sca_coverage_incomplete": True,
                                    "limitations": ["dependency_database_unavailable", "custom_limit"]})
    _findings, stats = run_sca_stage(repo_with(), OsvClient(transport=FakeTransport([[{}]], {})))
    refreshed = refreshed_score(score, [], stats)
    assert refreshed["scan_manifest"]["sca_unreadable_advisories"] == 0
    assert refreshed["scan_manifest"]["sca_coverage_incomplete"] is False
    assert refreshed["scan_manifest"]["limitations"] == ["custom_limit"]
