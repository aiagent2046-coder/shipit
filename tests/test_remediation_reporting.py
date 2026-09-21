"""A saved dependency recipe must survive scans/exports without claiming a repair."""
from copy import deepcopy
import json
import socket

import pytest

from app.llm.client import LLMClient
from app.local_cli import _dependency_task, inspect_project
from app.report.dependency_snapshot import snapshot_finding_rows
from app.report.html import render_report
from app.report.plain_language import plain_fields
from app.scan.browser import scan_archive
from app.scan.cve_match import match_archive
from app.scan.pipeline import BASIS_PREVIEW, run_scan
from app.scan.remediation_catalog import remediation_record
from tests.test_browser_cve import CATALOG, project
from tests.test_remediation_catalog import SOURCES, advisory


def sample():
    catalog = {"schema_version": 2, "source": SOURCES["cvelist"], "sources": SOURCES,
               "packages": {"npm:widget": [advisory()]}}
    return match_archive(project("npm", "widget", "1.0.0"), catalog)["findings"][0]


@pytest.mark.parametrize("ecosystem,package,installed,candidate", [
    ("npm", "@apollo/server", "4.7.2", "5.5.0"),
    ("PyPI", "adyen", "7.0.0", "7.1.0"),
])
def test_offline_recipe_survives_free_browser_local_and_sarif(ecosystem, package, installed, candidate, monkeypatch):
    def reject(*args, **kwargs):
        pytest.fail("Recipe matching must not open a network connection")

    monkeypatch.setattr(socket.socket, "connect", reject)
    monkeypatch.setattr(socket.socket, "connect_ex", reject)
    raw = project(ecosystem, package, installed)
    online = run_scan(raw, LLMClient(providers=[]), depth=BASIS_PREVIEW)
    browser = scan_archive(raw, CATALOG)
    local = inspect_project(raw, {}, CATALOG, {"sources": CATALOG["sources"]})
    views = [online, browser["report"], local]
    found = [[f for f in view["findings"] if f["rule_id"] == "dependency-cve-match"] for view in views]
    assert found[0] == found[1] == found[2]
    assert found[0]
    for finding in found[0]:
        card = remediation_record(finding["claim_evidence"])
        assert card and card["candidate_versions"] == [candidate]
        assert finding["verification_status"] == "unverified"
        assert candidate in plain_fields(finding)[2]
    terminal = _dependency_task(found[2])
    assert terminal["remediation"]["candidate_versions"] == [candidate]
    assert candidate in terminal["action"]
    html = render_report(online)
    assert "Remediation recipe" in html and candidate in html
    sarif = browser["sarif"]
    assert candidate in json.dumps(sarif)
    # Applying the offered version removes this package's known snapshot matches.
    fixed = match_archive(project(ecosystem, package, candidate), CATALOG)
    assert not fixed["findings"]
    assert fixed["coverage"]["status_counts"]["affected"] == 0
    assert fixed["coverage"]["status_counts"]["unknown"] == 0
    # Restoring the old version restores the finding; disappearance was not a disabled rule.
    assert match_archive(raw, CATALOG)["findings"]


@pytest.mark.parametrize("path,value", [
    (("schema_version",), True),
    (("status",), []),
    (("automatic_apply",), True),
    (("runtime_verified",), True),
    (("compatibility",), "verified"),
    (("candidate_versions",), ["0.5.0"]),
    (("candidate_versions",), ["2.0.0", "2.0.0"]),
    (("reason_codes",), ["evaluation_limit"]),
    (("binding", "package"), "other-package"),
    (("binding", "ecosystem"), []),
    (("binding", "sources_sha256"), "0" * 64),
    (("binding", "records_sha256"), "not-a-hash"),
    (("recipe", "revision"), 2),
])
def test_corrupt_or_overclaiming_saved_card_cannot_be_rendered_as_checked(path, value):
    finding = sample()
    target = finding["claim_evidence"]["remediation"]
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    assert remediation_record(finding["claim_evidence"]) is None
    assert not any(label == "Upgrade review" for label, _ in snapshot_finding_rows(finding["claim_evidence"]))


def test_unsupported_ecosystem_without_recipe_does_not_crash_report():
    finding = sample()
    evidence = finding["claim_evidence"]
    card = evidence["remediation"]
    evidence["ecosystem"] = card["binding"]["ecosystem"] = "RubyGems"
    card.update(recipe=None, status="manual_review", candidate_versions=[])
    assert remediation_record(evidence) is None
    rows = snapshot_finding_rows(evidence)
    assert rows
    assert not any(label == "Upgrade review" for label, _ in rows)


def test_missing_manual_record_hash_does_not_crash_report():
    finding = sample()
    card = finding["claim_evidence"]["remediation"]
    card.update(status="manual_review", candidate_versions=[])
    del card["binding"]["records_sha256"]
    assert remediation_record(finding["claim_evidence"]) is None
    assert snapshot_finding_rows(finding["claim_evidence"])


def test_retained_or_unbound_guidance_is_not_promoted_by_grouping_or_export():
    finding = sample()
    before = deepcopy(finding)
    assert remediation_record(finding["claim_evidence"])
    legacy = deepcopy(finding)
    legacy["claim_evidence"].pop("remediation")
    assert "remediation" not in _dependency_task([finding, legacy])
    finding["claim_evidence"]["snapshot_check_status"] = "retained_not_reconfirmed"
    assert remediation_record(finding["claim_evidence"]) is None
    assert "2.0.0" not in plain_fields(finding)[2]
    assert "not been reconfirmed" in plain_fields(finding)[2]
    assert finding["claim_evidence"]["remediation"] == before["claim_evidence"]["remediation"]


def test_recipe_revision_change_invalidates_snapshot_cache(monkeypatch):
    from app.sca import snapshot

    score = {"scan_manifest": {"dependency_snapshot": {
        "version": 1, "mode": "bundled", "fingerprint": snapshot._inputs()[3],
    }}}
    assert snapshot.snapshot_is_current(score)
    monkeypatch.setattr(snapshot, "REMEDIATION_CATALOG_VERSION", "2026-09-22.1")
    assert not snapshot.snapshot_is_current(score)
