"""Pinned ingestion, full replacement, and honest learning telemetry."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from app.learning.external_cve import external_cve_status
from scripts import build_cve_catalog as pipeline


def git(source: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(source), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


def published(cve_id="CVE-2026-12345"):
    return {
        "dataType": "CVE_RECORD", "dataVersion": "5.1",
        "cveMetadata": {"cveId": cve_id, "state": "PUBLISHED", "dateUpdated": "2026-09-14T00:00:00Z"},
        "containers": {"cna": {"title": "Fixture only", "affected": [{
            "collectionURL": "https://registry.npmjs.org", "packageName": "pipeline-fixture",
            "versions": [{"version": "1.0.0", "status": "affected"}],
        }]}},
    }


def commit(source: Path):
    git(source, "add", ".")
    git(source, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
        "commit", "--quiet", "-m", "CVE fixture")


@pytest.fixture
def source(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    git(source, "init", "--quiet")
    git(source, "remote", "add", "origin", pipeline.OFFICIAL_REPOSITORY + ".git")
    records = source / "cves" / "2026" / "12xxx"
    records.mkdir(parents=True)
    (records / "CVE-2026-12345.json").write_text(json.dumps(published()))
    commit(source)
    return source


def test_rebuild_is_byte_identical_and_digest_links_honest_evidence(source, tmp_path):
    first = pipeline.build_snapshot(source)
    assert pipeline.build_snapshot(source) == first
    catalog, summary = map(json.loads, first)
    assert summary["source"]["commit"] == git(source, "rev-parse", "HEAD")
    assert summary["source"]["generated_at"] == git(source, "show", "-s", "--format=%cI", "HEAD")
    assert summary["stats"]["source_json_files"] == summary["stats"]["seen"] == 1
    assert summary["stats"]["indexed_records"] == 1
    assert summary["catalog_sha256"] == hashlib.sha256(first[0]).hexdigest()
    assert summary["classifier_trained"] is False
    assert summary["customer_outcomes_added"] == 0
    assert list(catalog["packages"]) == ["npm:pipeline-fixture"]

    output = tmp_path / "output" / "cve-catalog.json"
    summary_path = output.parent / "cve-learning.json"
    args = ["--source", str(source), "--output", str(output), "--summary", str(summary_path)]
    assert pipeline.main(args) == pipeline.main([*args, "--check"]) == 0
    assert external_cve_status(output.parent)["status"] == "compiled"
    output.write_text("{}")
    external_cve_status.cache_clear()
    assert external_cve_status(output.parent)["status"] == "invalid"
    assert pipeline.main([*args, "--check"]) == 1


def test_complete_replacement_removes_rejected_and_deleted_advisories(source):
    directory = source / "cves" / "2026" / "12xxx"
    second = directory / "CVE-2026-12346.json"
    second.write_text(json.dumps(published("CVE-2026-12346")))
    commit(source)
    before = json.loads(pipeline.build_snapshot(source)[0])
    assert before["stats"]["indexed_records"] == 2
    second.unlink()
    rejected = published()
    rejected["cveMetadata"]["state"] = "REJECTED"
    (directory / "CVE-2026-12345.json").write_text(json.dumps(rejected))
    commit(source)
    after = json.loads(pipeline.build_snapshot(source)[0])
    assert after["packages"] == {}
    assert after["stats"]["rejected"] == 1
    assert after["stats"]["seen"] == 1


def test_dirty_or_wrong_origin_cannot_be_attributed_to_official_source(source):
    (source / "untracked.json").write_text("{}")
    with pytest.raises(ValueError, match="clean"):
        pipeline.build_snapshot(source)
    (source / "untracked.json").unlink()
    git(source, "remote", "set-url", "origin", "https://example.invalid/cvelistV5.git")
    with pytest.raises(ValueError, match="official"):
        pipeline.build_snapshot(source)


def test_reader_uses_pinned_blobs_even_if_worktree_changes(source):
    revision, _ = pipeline.source_identity(source)
    blobs = pipeline.source_blobs(source, revision)
    (source / blobs[0][0]).write_text("malicious working tree replacement")
    assert list(pipeline.read_records(source, blobs)) == [published()]


def test_delta_indexes_are_counted_separately_from_actual_records(source):
    (source / "cves" / "delta.json").write_text(json.dumps({"new": []}))
    (source / "cves" / "deltaLog.json").write_text(json.dumps([{"fetchTime": "fixture"}]))
    commit(source)
    summary = json.loads(pipeline.build_snapshot(source)[1])
    assert summary["stats"]["source_json_files"] == 3
    assert summary["stats"]["source_record_json_files"] == summary["stats"]["seen"] == 1
    assert summary["stats"]["skipped_source_metadata_files"] == 2


def test_git_replace_cannot_substitute_data_behind_a_pinned_blob_id(source):
    revision, _ = pipeline.source_identity(source)
    blobs = pipeline.source_blobs(source, revision)
    substituted = subprocess.run(
        ["git", "-C", str(source), "hash-object", "-w", "--stdin"],
        input=b'{"substituted":true}', check=True, capture_output=True,
    ).stdout.decode().strip()
    git(source, "replace", blobs[0][1], substituted)
    assert list(pipeline.read_records(source, blobs)) == [published()]


def test_malformed_json_fails_before_replacing_any_outputs(source, tmp_path):
    record = source / "cves" / "2026" / "12xxx" / "CVE-2026-12345.json"
    record.write_text("not JSON")
    commit(source)
    output = tmp_path / "cve-catalog.json"
    output.write_text("previous snapshot")
    assert pipeline.main(["--source", str(source), "--output", str(output),
                          "--summary", str(tmp_path / "cve-learning.json")]) == 1
    assert output.read_text() == "previous snapshot"


def test_source_symlinks_are_not_followed(source):
    record = source / "cves" / "2026" / "12xxx" / "CVE-2026-12345.json"
    record.unlink()
    record.symlink_to("/etc/passwd")
    commit(source)
    with pytest.raises(ValueError, match="regular"):
        pipeline.build_snapshot(source)


def test_missing_summary_is_explicitly_unavailable(tmp_path):
    assert external_cve_status(tmp_path) == {
        "kind": "knowledge_compilation", "classifier_trained": False,
        "customer_outcomes_added": 0, "status": "unavailable",
    }


async def test_operator_adds_external_source_without_inflating_customer_readiness(monkeypatch):
    from decimal import Decimal

    from starlette.requests import Request
    from app.routes import operator

    customer = {"rules": [{"rule_id": "SEC001", "labelled": 3, "ready": False}],
                "rules_ready": 0, "thresholds": {"min_labelled": 20, "min_audits": 5}}
    before = deepcopy(customer)

    class Repository:
        async def backlog_stats(self):
            return {"states": {}, "queued": 0, "oldest_queued_seconds": 0,
                    "backlog": 0, "oldest_paid_seconds": 0}

        async def recent_outcomes(self, **kwargs):
            return {"terminal_total": 0, "failed": 0, "error_rate": None, "top_error_codes": []}

        async def status_counts(self):
            return {}

        async def spend_since(self, **kwargs):
            return {"calls": 0, "cost_usd": Decimal("0")}

        async def learning_readiness(self, **kwargs):
            return customer

    monkeypatch.setenv("AUDIT_JOBS_STATS_TOKEN", "pipeline-fixture")
    monkeypatch.setattr(operator, "external_cve_status", lambda: {
        "status": "compiled", "classifier_trained": False, "customer_outcomes_added": 0})
    request = Request({"type": "http", "headers": [(b"authorization", b"Bearer pipeline-fixture")]})
    repo = Repository()
    result = await operator.internal_stats(request, repo, repo, repo, repo)
    assert customer == before
    assert {k: v for k, v in result["learning"].items() if k != "external_cve"} == before
    assert result["learning"]["external_cve"]["classifier_trained"] is False
