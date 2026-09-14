"""Offline matching proves version membership, including honest unknowns."""
import io
import json
import zipfile
from dataclasses import fields

import pytest

from app.scan import cve_match
from app.scan.cve_match import compare_versions, evaluate_advisory, match_archive
from app.scan.scoring import ScoredFinding


def archive(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    return stream.getvalue()


def npm(version="1.2.3", name="widget"):
    return archive({"package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
        f"node_modules/{name}": {"version": version}}})})


def advisory(**changes):
    return {"id": "CVE-2025-12345", "title": "Example advisory", "default_status": "unaffected",
            "versions": [{"version": "1.0.0", "lessThan": "2.0.0", "status": "affected", "versionType": "semver"}],
            **changes}


def catalog(entries=None, key="npm:widget"):
    return {"schema_version": 1, "source": {
        "repository": "https://github.com/CVEProject/cvelistV5", "commit": "a" * 40,
        "generated_at": "2026-09-14T12:00:00Z"}, "stats": {},
        "packages": {key: entries if entries is not None else [advisory()]}}


@pytest.mark.parametrize("left,right,ecosystem,expected", [
    ("1.9.0", "1.10.0", "npm", -1),
    ("1.0.0-alpha.2", "1.0.0-alpha.10", "npm", -1),
    ("1.0.0-2", "1.0.0-alpha", "npm", -1),
    ("1.0.0-rc.1", "1.0.0", "npm", -1),
    ("1.0.0+one", "v1.0.0+two", "npm", 0),
    ("01.0.0", "1.0.0", "npm", None),
    ("1.0.0-01", "1.0.0", "npm", None),
    ("1.0", "1.0.0", "npm", None),
    ("1.10", "1.9", "PyPI", 1),
    ("1.0.0", "1", "PyPI", 0),
    ("1.0rc1", "1.0", "PyPI", None),
    ("1!1.0", "1.0", "PyPI", None),
    ("1.0+local", "1.0", "PyPI", None),
    ("1.0.0", "1.0.0", "Go", None),
])
def test_ordering_is_explicit(left, right, ecosystem, expected):
    assert compare_versions(left, right, ecosystem) == expected


def test_affected_finding_preserves_source_and_claim_boundary():
    result = match_archive(npm(), catalog())
    finding, = result["findings"]
    assert set(finding) <= {field.name for field in fields(ScoredFinding)}
    assert finding["source"] == "dependency"
    assert finding["verification_status"] == "unverified"
    assert finding["verification_method"] == "package_version_match"
    evidence = finding["claim_evidence"]
    assert evidence["package"] == "widget"
    assert evidence["installed_version"] == "1.2.3"
    assert evidence["manifest"] == "package-lock.json"
    assert evidence["snapshot"]["commit"] == "a" * 40
    assert evidence["matched_ranges"][0]["lessThan"] == "2.0.0"
    assert evidence["reachability"] == "not_assessed"
    assert result["coverage"]["status_counts"]["affected"] == 1


@pytest.mark.parametrize("bound,version,expected", [
    ("lessThan", "1.0.0", "affected"),
    ("lessThan", "2.0.0", "unaffected"),
    ("lessThanOrEqual", "2.0.0", "affected"),
    ("lessThanOrEqual", "2.0.1", "unaffected"),
])
def test_bounds(bound, version, expected):
    entry = advisory(versions=[{"version": "1.0.0", bound: "2.0.0", "status": "affected", "versionType": "semver"}])
    assert evaluate_advisory(version, "npm", entry)["status"] == expected


def test_changes_apply_in_semantic_order_at_inclusive_transition():
    entry = advisory(versions=[{"version": "1.0.0", "lessThan": "*", "status": "affected", "versionType": "semver",
                                "changes": [
        {"at": "1.10.0", "status": "affected"}, {"at": "1.2.0", "status": "unaffected"}]}])
    assert evaluate_advisory("1.2.0", "npm", entry)["status"] == "unaffected"
    assert evaluate_advisory("1.9.0", "npm", entry)["status"] == "unaffected"
    assert evaluate_advisory("1.10.0", "npm", entry)["status"] == "affected"


@pytest.mark.parametrize("row,reason", [
    ({"versionType": "git"}, "unsupported_version_type"),
    ({"versionType": "custom"}, "unsupported_version_type"),
    ({"version": "1.x"}, "unsupported_version"),
    ({"lessThanOrEqual": "2.0.0"}, "conflicting_bounds"),
    ({"lessThan": "0.0.0"}, "invalid_bounds"),
    ({"changes": [{"at": "3.0.0", "status": "affected"}]}, "invalid_changes"),
])
def test_unsupported_ranges_are_unknown(row, reason):
    entry = advisory()
    entry["versions"][0].update(row)
    result = match_archive(npm(), catalog([entry]))
    assert not result["findings"]
    assert result["coverage"]["status_counts"]["unknown"] == 1
    assert result["coverage"]["unresolved_ranges"] >= 1
    assert result["coverage"]["details"][0]["reason"] == reason


def test_conflicting_overlaps_cannot_create_an_affected_match():
    entry = advisory()
    entry["versions"].append({"version": "1.2.3", "status": "unaffected"})
    result = match_archive(npm(), catalog([entry]))
    assert not result["findings"]
    assert result["coverage"]["details"][0]["reason"] == "conflicting_ranges"


def test_default_status_and_explicit_unknown_remain_distinct():
    assert evaluate_advisory("3.0.0", "npm", advisory(default_status="affected"))["status"] == "affected"
    assert evaluate_advisory("3.0.0", "npm", advisory(default_status="unknown"))["status"] == "unknown"
    unknown = advisory(versions=[{"version": "1.2.3", "status": "unknown"}])
    assert evaluate_advisory("1.2.3", "npm", unknown)["status"] == "unknown"


def test_platform_restrictions_remain_unknown():
    result = match_archive(npm(), catalog([advisory(unsupported_applicability=True)]))
    assert not result["findings"]
    assert result["coverage"]["details"][0]["reason"] == "unsupported_applicability"


def test_repeated_affected_objects_are_deduplicated_and_conflicts_unknown():
    assert len(match_archive(npm(), catalog([advisory(), advisory()]))["findings"]) == 1
    second = advisory(versions=[{"version": "1.2.3", "status": "unaffected"}])
    result = match_archive(npm(), catalog([advisory(), second]))
    assert not result["findings"]
    assert result["coverage"]["details"][0]["reason"] == "conflicting_affected_objects"


def test_pypi_identity_normalization_and_unsupported_releases():
    entry = advisory(versions=[{"version": "1.0", "lessThan": "2.0", "status": "affected", "versionType": "pep440"}])
    snapshot = catalog([entry], key="PyPI:foo-bar")
    result = match_archive(archive({"requirements.txt": "Foo_Bar==1.2.3\n"}), snapshot)
    assert result["findings"][0]["claim_evidence"]["ecosystem"] == "PyPI"
    assert result["findings"][0]["line"] == 1
    result = match_archive(archive({"requirements.txt": "Foo_Bar==1.2rc1\n"}), snapshot)
    assert result["coverage"]["status_counts"]["unknown"] == 1


def test_ecosystem_identity_is_never_guessed():
    result = match_archive(npm(), catalog(key="PyPI:widget"))
    assert not result["findings"]
    assert result["coverage"]["status_counts"]["not_in_catalog"] == 1
    assert result["coverage"]["status"] == "partial"


def test_missing_lockfiles_and_partial_inventory_are_visible():
    result = match_archive(archive({"package.json": '{"dependencies":{"widget":"^1.0.0"}}'}), catalog())
    assert result["coverage"]["status"] == "partial"
    assert result["coverage"]["incomplete_manifests"] == {"package.json": "unresolved"}
    assert result["coverage"]["dependencies_found"] == 0
    assert match_archive(archive({"main.py": "print(1)"}), catalog())["coverage"]["status"] == "not_applicable"
    result = match_archive(archive({"requirements.txt": "foo>=1\n", "go.sum": "anything"}), catalog())
    assert result["coverage"]["incomplete_manifests"] == {"go.sum": "unsupported", "requirements.txt": "unresolved"}
    assert result["coverage"]["status"] == "partial"


def test_input_limits_and_invalid_catalog_do_not_look_clean(monkeypatch):
    assert match_archive(b"bad zip", catalog())["coverage"]["status"] == "unavailable"
    bad = catalog()
    bad["source"]["commit"] = "main"
    assert match_archive(npm(), bad)["coverage"]["error"] == "invalid_catalog"
    monkeypatch.setattr(cve_match, "MAX_ARCHIVE_BYTES", 1)
    assert match_archive(npm(), catalog())["coverage"]["status"] == "unavailable"


def test_evaluation_and_finding_caps_are_reported(monkeypatch):
    entries = [advisory(id=f"CVE-2025-{10000 + i}") for i in range(4)]
    monkeypatch.setattr(cve_match, "MAX_EVALUATIONS", 2)
    result = match_archive(npm(), catalog(entries))
    assert result["coverage"]["evaluations_truncated"] > 0
    assert result["coverage"]["advisory_evaluations"] == 2
    assert result["coverage"]["status"] == "partial"
    monkeypatch.setattr(cve_match, "MAX_EVALUATIONS", 20)
    monkeypatch.setattr(cve_match, "MAX_FINDINGS", 1)
    result = match_archive(npm(), catalog(entries))
    assert len(result["findings"]) == 1
    assert result["coverage"]["findings_truncated"] == 3


@pytest.mark.parametrize("manifest", ["yarn.lock", "pnpm-lock.yaml", "Pipfile.lock", "uv.lock", "pyproject.toml"])
def test_other_dependency_metadata_is_an_explicit_gap(manifest):
    result = match_archive(archive({manifest: "irrelevant contents"}), catalog())
    assert result["coverage"]["status"] == "partial"
    assert manifest in result["coverage"]["incomplete_manifests"]


@pytest.mark.parametrize("changes", [{"default_status": []}, {"versions": [{"status": []}]},
                                     {"versions": [{"status": "affected", "versionType": {}}]}])
def test_malformed_catalog_fields_stay_unknown(changes):
    result = match_archive(npm(), catalog([advisory(**changes)]))
    assert result["coverage"]["status_counts"]["unknown"] == 1
