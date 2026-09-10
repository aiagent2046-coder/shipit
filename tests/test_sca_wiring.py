"""The dependency stage as the audit uses it: who gets it, what it records, and
what a reader is told when it did not run.

Nothing here opens a socket. The stage's own behaviour is covered by
tests/test_sca_stage.py; this file covers the decisions around it -- the
entitlement boundary, the manifest facts, and the report wording that keeps
"not checked" from reading as "clean".
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from app.llm.client import LLMClient
from app.report.evidence import manifest_rows
from app.sca.osv import OsvClient
from app.sca.stage import (SCA_ENABLED_ENV, RULE_ID, freshness, sca_client_for)
from app.scan.pipeline import AUDIT_ENGINE_VERSION, run_scan
from tests.test_sca_stage import FakeTransport, LODASH_ADVISORY, make_zip


def repo_with_lockfile(version: str = "4.17.4") -> bytes:
    return make_zip({
        "package.json": json.dumps({"dependencies": {"lodash": "^4.17.0"}}),
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/lodash": {"version": version}}}),
    })


def fake_client() -> OsvClient:
    return OsvClient(transport=FakeTransport(
        [[{"vulns": [{"id": "GHSA-35jh-r3h4-6jhm"}]}]],
        {"GHSA-35jh-r3h4-6jhm": LODASH_ADVISORY}))


# -- entitlement ------------------------------------------------------------

def test_a_paid_audit_gets_the_dependency_check(monkeypatch):
    monkeypatch.delenv(SCA_ENABLED_ENV, raising=False)
    assert isinstance(sca_client_for(paid=True), OsvClient)


def test_the_free_tier_does_not_send_a_visitors_dependencies_anywhere(monkeypatch):
    monkeypatch.delenv(SCA_ENABLED_ENV, raising=False)
    assert sca_client_for(paid=False) is None


def test_a_caller_can_decline_the_dependency_check(monkeypatch):
    monkeypatch.delenv(SCA_ENABLED_ENV, raising=False)
    assert sca_client_for(paid=True, opt_out=True) is None


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "FALSE"])
def test_a_deployment_can_forbid_the_outward_call(monkeypatch, value):
    monkeypatch.setenv(SCA_ENABLED_ENV, value)
    assert sca_client_for(paid=True) is None


def test_a_local_caller_can_opt_in_even_where_the_policy_is_off(monkeypatch):
    """The CLI's operator decides per run: the deployment switch is about the
    service, and an explicit request is a decision someone made on purpose."""
    monkeypatch.setenv(SCA_ENABLED_ENV, "0")
    assert isinstance(sca_client_for(paid=True, requested=True), OsvClient)
    assert sca_client_for(paid=True, requested=False) is None


# -- the audit's own facts --------------------------------------------------

def test_a_paid_scan_reports_dependency_findings_and_records_them():
    scan = run_scan(repo_with_lockfile(), LLMClient(), depth="static+preview",
                    sca_client=fake_client())
    dependency_findings = [f for f in scan["findings"] if f["rule_id"] == RULE_ID]
    assert len(dependency_findings) == 1
    assert dependency_findings[0]["severity"] == "high"
    assert dependency_findings[0]["file"] == "package-lock.json"

    manifest = scan["score"]["scan_manifest"]
    assert manifest["sca_checks"] == ["sca_dependencies"]
    assert manifest["sca_dependencies"] == 1
    assert manifest["sca_asked_at"]
    assert manifest["sca_findings"] == 1
    assert manifest["sca_skipped_reason"] is None
    assert manifest["engine_version"] == AUDIT_ENGINE_VERSION
    assert "Lockfiles" in manifest["inventory"]


def test_a_scan_without_a_client_says_the_check_did_not_run():
    scan = run_scan(repo_with_lockfile(), LLMClient(), sca_client=None)
    assert not [f for f in scan["findings"] if f["rule_id"] == RULE_ID]
    manifest = scan["score"]["scan_manifest"]
    assert manifest["sca_skipped_reason"] == "no_client"
    assert manifest["sca_dependencies"] == 1, (
        "the versions were readable; only the lookup did not happen")
    assert "dependency_check_not_run" in manifest["limitations"]


def test_an_archive_without_a_lockfile_is_not_a_limitation():
    scan = run_scan(make_zip({"app/main.py": "print(1)\n"}), LLMClient(), sca_client=None)
    manifest = scan["score"]["scan_manifest"]
    assert manifest["sca_skipped_reason"] == "no_lockfile"
    assert "dependency_check_not_run" not in manifest["limitations"], (
        "there was nothing to check, which is a fact, not a gap")


def test_an_unreachable_database_is_recorded_as_a_degradation():
    class DeadTransport:
        def post(self, url, *, json=None):
            raise ConnectionError("no route to host")

        def get(self, url):
            raise ConnectionError("no route to host")

    scan = run_scan(repo_with_lockfile(), LLMClient(),
                    sca_client=OsvClient(transport=DeadTransport()))
    manifest = scan["score"]["scan_manifest"]
    assert str(manifest["sca_skipped_reason"]).startswith("osv_unavailable")
    assert "dependency_database_unavailable" in manifest["limitations"]
    assert manifest["sca_asked_at"] is None, "nothing was answered, so nothing is dated"


def test_a_failing_dependency_stage_does_not_change_the_basis():
    """The two stages answer different questions: a dependency failure must not
    degrade the audit's claim about the code it read."""
    ok = run_scan(repo_with_lockfile(), LLMClient(), sca_client=None)
    assert ok["score"]["basis"] == "static_only"
    assert ok["llm"]["skipped_reason"] == "no_providers_configured"


# -- what the reader sees ---------------------------------------------------

def test_the_report_says_when_the_dependencies_were_asked_about():
    scan = run_scan(repo_with_lockfile(), LLMClient(), sca_client=fake_client())
    rows = dict(manifest_rows(scan["score"]))
    text = rows["Dependencies checked"]
    assert "OSV database" in text and "1 resolved packages" in text
    assert "1 reported" in text
    assert "was not checked" in text, (
        "a database match is not a reachability proof")


def test_the_report_ages_the_answer_it_serves():
    stale = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(timespec="seconds")
    rows = dict(manifest_rows({"scan_manifest": {
        "archive_sha256": "x", "engine_version": AUDIT_ENGINE_VERSION,
        "archive_files": 1, "sca_dependencies": 1, "sca_dependencies_found": 1,
        "sca_findings": 0, "sca_asked_at": stale}}))
    assert "true of that date" in rows["Dependencies checked"]


def test_the_report_distinguishes_every_reason_the_check_is_missing():
    rows = dict(manifest_rows({"scan_manifest": {
        "archive_sha256": "x", "engine_version": AUDIT_ENGINE_VERSION,
        "archive_files": 1, "sca_skipped_reason": "no_client",
        "sca_dependencies": 3}}))
    assert "Not checked in this audit" in rows["Dependencies checked"]
    assert "3 packages" in rows["Dependencies checked"]

    rows = dict(manifest_rows({"scan_manifest": {
        "archive_sha256": "x", "engine_version": AUDIT_ENGINE_VERSION,
        "archive_files": 1, "sca_skipped_reason": "no_lockfile"}}))
    assert "No lockfile was found" in rows["Dependencies checked"]

    rows = dict(manifest_rows({"scan_manifest": {
        "archive_sha256": "x", "engine_version": AUDIT_ENGINE_VERSION,
        "archive_files": 1, "sca_skipped_reason": "osv_unavailable: HTTP 503"}}))
    assert "could not be reached" in rows["Dependencies checked"]
    assert "not a clean result" in rows["Dependencies checked"]


def test_the_report_says_why_a_lockfile_alone_answered_nothing():
    rows = dict(manifest_rows({"scan_manifest": {
        "archive_sha256": "x", "engine_version": AUDIT_ENGINE_VERSION,
        "archive_files": 1, "sca_skipped_reason": "no_resolvable_lockfile",
        "sca_unusable_lockfiles": ["go.sum"]}}))
    text = rows["Dependencies checked"]
    assert "go.sum" in text and "every module version the build ever verified" in text


def test_the_report_keeps_an_unreadable_lockfile_apart_from_no_lockfile():
    unreadable = dict(manifest_rows({"scan_manifest": {
        "archive_sha256": "x", "engine_version": AUDIT_ENGINE_VERSION,
        "archive_files": 1, "sca_skipped_reason": "lockfile_unreadable: RecursionError"}}))
    assert "could not be read" in unreadable["Dependencies checked"]
    assert "Nothing about the dependencies was established" in unreadable["Dependencies checked"]

    absent = dict(manifest_rows({"scan_manifest": {
        "archive_sha256": "x", "engine_version": AUDIT_ENGINE_VERSION,
        "archive_files": 1, "sca_skipped_reason": "no_lockfile"}}))
    assert "No lockfile was found" in absent["Dependencies checked"]


def test_the_report_admits_when_some_advisory_details_could_not_be_fetched():
    from datetime import datetime as dt
    rows = dict(manifest_rows({"scan_manifest": {
        "archive_sha256": "x", "engine_version": AUDIT_ENGINE_VERSION,
        "archive_files": 1, "sca_dependencies": 2, "sca_dependencies_found": 2,
        "sca_findings": 1, "sca_unreadable_advisories": 1,
        "sca_asked_at": dt.now(timezone.utc).isoformat(timespec="seconds")}}))
    text = rows["Dependencies checked"]
    assert "1 reported" in text
    assert "could not be fetched" in text and "without their details" in text


def test_an_audit_from_before_the_stage_existed_says_so():
    rows = dict(manifest_rows({"scan_manifest": {
        "archive_sha256": "x", "engine_version": "2026-09-09-32",
        "archive_files": 1}}))
    assert rows["Dependencies checked"] == "Not recorded for this audit"


def test_a_truncated_dependency_list_is_visible():
    rows = dict(manifest_rows({"scan_manifest": {
        "archive_sha256": "x", "engine_version": AUDIT_ENGINE_VERSION,
        "archive_files": 1, "sca_dependencies": 2000, "sca_dependencies_found": 2400,
        "sca_findings": 0,
        "sca_asked_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}}))
    assert "2000 of 2400 resolved packages" in rows["Dependencies checked"]


# -- freshness --------------------------------------------------------------

def test_freshness_keeps_unknown_apart_from_stale():
    now = datetime(2026, 9, 10, tzinfo=timezone.utc)
    assert freshness(None, now) == "unknown"
    assert freshness("not a date", now) == "unknown"
    assert freshness((now - timedelta(days=1)).isoformat(), now) == "fresh"
    assert freshness((now - timedelta(days=7)).isoformat(), now) == "stale"
    assert freshness((now - timedelta(days=400)).isoformat(), now) == "stale"


def test_the_dependency_rows_do_not_leak_the_dependency_names():
    """The manifest is public: counts and paths it already lists, never the
    package names a reader could mine."""
    scan = run_scan(repo_with_lockfile(), LLMClient(), sca_client=fake_client())
    text = json.dumps([row for row in manifest_rows(scan["score"])])
    assert "lodash" not in text
