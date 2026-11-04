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


def kev_feed(cve_id="CVE-2026-12345"):
    return {"title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": "2026.11.03",
            "dateReleased": "2026-11-03T20:00:24.8741Z", "count": 1, "vulnerabilities": [{
                "cveID": cve_id, "vendorProject": "v", "product": "p", "vulnerabilityName": "n",
                "dateAdded": "2026-11-01", "shortDescription": "d", "requiredAction": "a",
                "dueDate": "2026-11-22", "knownRansomwareCampaignUse": "Unknown", "notes": "", "cwes": []}]}


@pytest.fixture
def kev(tmp_path):
    """An inert cisagov/kev-data checkout: the same input scripts/build_kev_catalog.py compiles."""
    source = tmp_path / "kev"
    source.mkdir()
    git(source, "init", "--quiet")
    git(source, "remote", "add", "origin", pipeline.OFFICIAL_KEV_REPOSITORY + ".git")
    (source / pipeline.KEV_SOURCE_FILE).write_bytes(json.dumps(kev_feed()).encode())
    commit(source, "KEV fixture")
    return source


def test_kev_checkout_annotates_the_two_source_snapshot_with_its_pinned_commit(sources, kev, tmp_path):
    cve, ghsa = sources
    first = pipeline.build_snapshot(cve, ghsa, kev)
    assert pipeline.build_snapshot(cve, ghsa, kev) == first
    catalog, summary = map(json.loads, first)
    assert catalog["schema_version"] == 3
    assert catalog["exploitation"]["cisa-kev"]["CVE-2026-12345"]["due_date"] == "2026-11-22"
    # Identity is the Git provenance of the blob, exactly what kev-catalog.json records: no feed URL.
    assert catalog["sources"]["cisa-kev"] == {
        "repository": pipeline.OFFICIAL_KEV_REPOSITORY, "commit": git(kev, "rev-parse", "HEAD"),
        "generated_at": git(kev, "show", "-s", "--format=%cI", "HEAD"), "catalog_version": "2026.11.03",
        "sha256": pipeline.hashlib.sha256((kev / pipeline.KEV_SOURCE_FILE).read_bytes()).hexdigest(),
    }
    assert summary["sources"] == catalog["sources"]
    assert summary["coverage"]["sources"] == ["cisa-kev", "cvelist", "github-reviewed"]
    assert summary["stats"]["kev_in_catalog"] == 1
    assert "CISA KEV" in summary["coverage"]["scope"]
    # The two-source build is unchanged by the option's existence.
    assert json.loads(pipeline.build_snapshot(cve, ghsa)[0])["schema_version"] == 2

    output = tmp_path / "out" / "cve-catalog.json"
    args = ["--source", str(cve), "--ghsa-source", str(ghsa), "--kev-source", str(kev),
            "--output", str(output), "--summary", str(output.parent / "cve-learning.json")]
    assert pipeline.main(args) == pipeline.main([*args, "--check"]) == 0
    (kev / pipeline.KEV_SOURCE_FILE).write_bytes(json.dumps(kev_feed("CVE-2026-12346")).encode())
    # Worktree bytes are not a pinned input; only a committed change is.
    with pytest.raises(ValueError, match="clean"):
        pipeline.build_snapshot(cve, ghsa, kev)
    commit(kev, "KEV update")
    assert pipeline.main([*args, "--check"]) == 1
    with pytest.raises(ValueError, match="requires --ghsa-source"):
        pipeline.build_snapshot(cve, None, kev)


def test_kev_checkout_must_be_official_and_carry_a_regular_json_blob(sources, kev, monkeypatch):
    cve, ghsa = sources
    git(kev, "remote", "set-url", "origin", "https://example.invalid/kev-data.git")
    with pytest.raises(ValueError, match="official"):
        pipeline.build_snapshot(cve, ghsa, kev)
    git(kev, "remote", "set-url", "origin", pipeline.OFFICIAL_KEV_REPOSITORY)
    (kev / pipeline.KEV_SOURCE_FILE).write_bytes(b"not json")
    commit(kev, "Broken KEV")
    with pytest.raises(ValueError, match="invalid JSON"):
        pipeline.build_snapshot(cve, ghsa, kev)
    (kev / pipeline.KEV_SOURCE_FILE).chmod(0o755)
    git(kev, "update-index", "--chmod=+x", pipeline.KEV_SOURCE_FILE)
    git(kev, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--quiet", "-m", "Executable")
    with pytest.raises(ValueError, match="regular"):
        pipeline.build_snapshot(cve, ghsa, kev)
    git(kev, "rm", "--quiet", pipeline.KEV_SOURCE_FILE)
    git(kev, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--quiet", "-m", "Removed")
    with pytest.raises(ValueError, match="regular"):
        pipeline.build_snapshot(cve, ghsa, kev)
    (kev / pipeline.KEV_SOURCE_FILE).write_bytes(json.dumps(kev_feed()).encode())
    commit(kev, "Restored KEV")
    monkeypatch.setattr(pipeline, "MAX_KEV_BYTES", 1)
    with pytest.raises(ValueError, match="size limit"):
        pipeline.build_snapshot(cve, ghsa, kev)


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
