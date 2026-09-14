"""The pinned pipeline imports only the official github-reviewed advisory tree."""
import json
from pathlib import Path
import subprocess

import pytest

from scripts import build_cve_catalog as pipeline

DATE = "2026-09-14T00:00:00Z"
GHSA = "GHSA-2345-6789-cfgh"


def git(source: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(source), *args],
        check=True, capture_output=True, text=True,
    ).stdout.strip()


def commit(source: Path, message: str):
    git(source, "add", ".")
    git(
        source, "-c", "user.name=Test", "-c",
        "user.email=test@example.invalid", "commit", "--quiet", "-m", message,
    )


def cve_record():
    return {
        "dataType": "CVE_RECORD", "dataVersion": "5.1",
        "cveMetadata": {
            "cveId": "CVE-2026-12345", "state": "PUBLISHED",
            "dateUpdated": DATE,
        },
        "containers": {"cna": {"title": "CVE fixture", "affected": [{
            "collectionURL": "https://registry.npmjs.org",
            "packageName": "cve-fixture",
            "versions": [{"version": "1.0.0", "status": "affected"}],
        }]}},
    }


def ghsa_record():
    return {
        "schema_version": "1.4.0", "id": GHSA, "modified": DATE,
        "published": DATE, "aliases": [], "summary": "GHSA fixture",
        "affected": [{
            "package": {"ecosystem": "npm", "name": "ghsa-fixture"},
            "ranges": [{"type": "ECOSYSTEM", "events": [
                {"introduced": "0"}, {"fixed": "2.0.0"},
            ]}],
        }],
        "database_specific": {"github_reviewed": True},
    }


@pytest.fixture
def sources(tmp_path):
    cve = tmp_path / "cve"
    cve.mkdir()
    git(cve, "init", "--quiet")
    git(cve, "remote", "add", "origin", pipeline.OFFICIAL_REPOSITORY + ".git")
    cve_path = cve / "cves" / "2026" / "12xxx"
    cve_path.mkdir(parents=True)
    (cve_path / "CVE-2026-12345.json").write_text(json.dumps(cve_record()))
    commit(cve, "CVE fixture")

    ghsa = tmp_path / "ghsa"
    ghsa.mkdir()
    git(ghsa, "init", "--quiet")
    git(
        ghsa, "remote", "add", "origin",
        pipeline.OFFICIAL_GHSA_REPOSITORY + ".git",
    )
    ghsa_path = (
        ghsa / "advisories" / "github-reviewed" / "2026" / "09" / GHSA
    )
    ghsa_path.mkdir(parents=True)
    (ghsa_path / f"{GHSA}.json").write_text(json.dumps(ghsa_record()))
    commit(ghsa, "GHSA fixture")
    return cve, ghsa


def test_two_pinned_sources_produce_one_digest_linked_catalog(sources):
    cve, ghsa = sources
    first = pipeline.build_snapshot(cve, ghsa)
    assert pipeline.build_snapshot(cve, ghsa) == first
    catalog, summary = map(json.loads, first)
    assert catalog["schema_version"] == 2
    assert set(catalog["packages"]) == {"npm:cve-fixture", "npm:ghsa-fixture"}
    assert catalog["sources"]["cvelist"]["commit"] == git(cve, "rev-parse", "HEAD")
    assert catalog["sources"]["github-reviewed"]["commit"] == git(
        ghsa, "rev-parse", "HEAD"
    )
    assert summary["sources"] == catalog["sources"]
    assert summary["stats"]["source_record_json_files"] == 1
    assert summary["stats"]["ghsa_source_json_files"] == 1
    assert summary["stats"]["ghsa_indexed_records"] == 1
    assert summary["coverage"]["sources"] == ["cvelist", "github-reviewed"]


def test_ghsa_origin_cleanliness_and_reviewed_path_are_required(sources):
    cve, ghsa = sources
    (ghsa / "untracked.json").write_text("{}")
    with pytest.raises(ValueError, match="clean"):
        pipeline.build_snapshot(cve, ghsa)
    (ghsa / "untracked.json").unlink()
    git(ghsa, "remote", "set-url", "origin", "https://example.invalid/advisories")
    with pytest.raises(ValueError, match="official"):
        pipeline.build_snapshot(cve, ghsa)


def test_unexpected_file_in_reviewed_tree_aborts_full_rebuild(sources):
    cve, ghsa = sources
    unexpected = ghsa / "advisories" / "github-reviewed" / "unexpected"
    unexpected.mkdir()
    (unexpected / f"{GHSA}.json").write_text(json.dumps(ghsa_record()))
    commit(ghsa, "Unexpected layout")
    with pytest.raises(ValueError, match="unexpected JSON path"):
        pipeline.build_snapshot(cve, ghsa)
