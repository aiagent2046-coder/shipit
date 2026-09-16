"""Coverage diagnostics must explain uncertainty without removing it."""
import io
import json
import zipfile

import pytest

from app.scan import cve_match


def _archive(files, compression=zipfile.ZIP_STORED):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression) as archive:
        for name, text in files.items():
            archive.writestr(name, text)
    return stream.getvalue()


def _catalog(entries):
    source = {"repository": cve_match.SOURCE_REPOSITORY, "commit": "a" * 40,
              "generated_at": "2026-09-16T00:00:00Z"}
    return {"schema_version": 2, "source": source, "sources": {
        "cvelist": source,
        "github-reviewed": {**source, "repository": cve_match.GHSA_REPOSITORY},
    }, "packages": {"npm:undici": entries}}


def _lock():
    return _archive({"package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/undici": {"version": "8.10.2"},
    }})})


def _cna(lower="0"):
    return {"id": "CVE-2026-11525", "default_status": "unaffected", "versions": [
        {"version": lower, "lessThan": "6.26.0", "versionType": "semver", "status": "affected"},
    ]}


def _ghsa(fixed="6.27.0"):
    return {"id": "GHSA-g8m3-5g58-fq7m", "aliases": ["CVE-2026-11525"],
            "source": "github-reviewed", "osv_ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]},
            ], "osv_versions": []}


def test_source_disagreement_exposes_unknown_cna_and_unaffected_ghsa():
    result = cve_match.match_archive(_lock(), _catalog([_cna(), _ghsa()]))
    coverage = result["coverage"]
    assert result["findings"] == []
    assert coverage["status_counts"]["unknown"] == 1
    assert coverage["unknown_reason_counts"] == {"conflicting_advisory_sources": 1}
    detail, = coverage["details"]
    assert detail["assessments"] == [
        {"source": "cvelist", "advisory": "CVE-2026-11525",
         "status": "unknown", "reason": "unsupported_version"},
        {"source": "github-reviewed", "advisory": "GHSA-g8m3-5g58-fq7m",
         "status": "unaffected", "reason": None},
    ]
    assert detail["assessments_truncated"] == 0
    # Exact CNA SemVer removes the parser gap; diagnostics must not invent one.
    resolved = cve_match.match_archive(_lock(), _catalog([_cna("0.0.0"), _ghsa()]))
    assert resolved["coverage"]["status_counts"]["unaffected"] == 1
    assert resolved["coverage"]["unknown_reason_counts"] == {}


def test_actual_affected_unaffected_conflict_still_remains_unknown():
    result = cve_match.match_archive(_lock(), _catalog([_cna("0.0.0"), _ghsa("9.0.0")]))
    coverage = result["coverage"]
    assert result["findings"] == []
    assert coverage["unknown_reason_counts"] == {"conflicting_advisory_sources": 1}
    assert {a["status"] for a in coverage["details"][0]["assessments"]} == {"affected", "unaffected"}


@pytest.mark.parametrize(("ecosystem", "version", "introduced", "fixed"), [
    ("PyPI", "6.0.3", "5.1b7", "5.3.1"),
    ("npm", "16.3.4", "13.0", "14.2.30"),
])
def test_unsupported_pilot_bounds_are_visible_and_never_guessed(ecosystem, version, introduced, fixed):
    snapshot = _catalog([])
    entry = _ghsa(fixed)
    entry["osv_ranges"][0]["events"][0] = {"introduced": introduced}
    snapshot["packages"] = {f"{ecosystem}:widget": [entry]}
    files = {"requirements.txt": f"widget=={version}\n"} if ecosystem == "PyPI" else {
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/widget": {"version": version},
        }}),
    }
    coverage = cve_match.match_archive(_archive(files), snapshot)["coverage"]
    assert coverage["status_counts"]["unknown"] == 1
    assert coverage["unknown_reason_counts"] == {"unsupported_osv_version": 1}
    assert coverage["details"][0]["assessments"][0]["reason"] == "unsupported_osv_version"


def test_reason_counts_remain_complete_past_detail_and_assessment_caps(monkeypatch):
    monkeypatch.setattr(cve_match, "MAX_DETAILS", 1)
    monkeypatch.setattr(cve_match, "MAX_ASSESSMENT_DETAILS", 1)
    coverage = cve_match.match_archive(_lock(), _catalog([
        _cna(), _ghsa(),
        {**_cna(), "id": "CVE-2026-18540"},
        {"id": "not-an-advisory"},
    ]))["coverage"]
    assert coverage["status_counts"]["unknown"] == 3
    assert coverage["unknown_reason_counts"] == {
        "conflicting_advisory_sources": 1, "unsupported_version": 1,
        "invalid_advisory_identity": 1,
    }
    assert len(coverage["details"]) == 1
    assert coverage["details_truncated"] == 2
    group = cve_match.match_archive(_lock(), _catalog([_cna(), _ghsa()]))["coverage"]["details"][0]
    assert len(group["assessments"]) == 1
    assert group["assessments_truncated"] == 1


def test_invalid_package_entries_have_a_manifest_and_count(monkeypatch):
    monkeypatch.setattr(cve_match, "MAX_DETAILS", 0)
    coverage = cve_match.match_archive(_lock(), _catalog([]))["coverage"]
    assert coverage["unknown_reason_counts"] == {"invalid_catalog_entries": 1}
    assert coverage["status_counts"]["unknown"] == 1
    assert coverage["details_truncated"] == 1


def test_evaluation_limit_is_reported_without_a_partial_positive(monkeypatch):
    monkeypatch.setattr(cve_match, "MAX_EVALUATIONS", 1)
    coverage = cve_match.match_archive(_lock(), _catalog([_ghsa("9.0.0"), _cna()]))["coverage"]
    assert coverage["status_counts"]["affected"] == 0
    assert coverage["status_counts"]["unknown"] == 1
    assert coverage["unknown_reason_counts"] == {"evaluation_limit": 1}
    assert coverage["evaluations_truncated"] == 1


@pytest.mark.parametrize(("text", "reason"), [
    ('[project]\ndynamic = ["dependencies"]\n', "dynamic_dependencies_without_lock"),
    ('[project]\ndependencies = ["requests>=2"]\n', "missing_supported_lockfile"),
    ('[project]\ndynamic = [', "invalid_manifest_metadata"),
])
def test_pyproject_gap_explains_metadata_without_resolving_it(text, reason):
    coverage = cve_match.match_archive(_archive({"local/pyproject.toml": text}), _catalog([]))["coverage"]
    assert coverage["incomplete_manifests"] == {"local/pyproject.toml": "unresolved"}
    assert coverage["manifest_gap_reason_counts"] == {reason: 1}
    assert coverage["manifest_gap_details"] == [{
        "manifest": "local/pyproject.toml", "status": "unresolved", "reason": reason,
    }]
    assert coverage["status"] == "partial"


def test_dynamic_metadata_is_not_executed_and_neighboring_pins_are_respected(tmp_path):
    marker = tmp_path / "executed"
    files = {
        "local/pyproject.toml": '[project]\ndynamic = ["dependencies"]\n[build-system]\nbuild-backend = "evil"\n',
        "local/evil.py": f"open({str(marker)!r}, 'w').write('executed')",
    }
    coverage = cve_match.match_archive(_archive(files), _catalog([]))["coverage"]
    assert coverage["manifest_gap_reason_counts"] == {"dynamic_dependencies_without_lock": 1}
    assert not marker.exists()
    files["local/requirements.txt"] = "widget==1.0.0\n"
    pinned = cve_match.match_archive(_archive(files), _catalog([]))["coverage"]
    assert pinned["incomplete_manifests"] == {}
    assert pinned["manifest_gap_reason_counts"] == {}


@pytest.mark.parametrize("damage", ["crc", "encrypted", "deflate"])
@pytest.mark.parametrize(("fixed", "status"), [("9.0.0", "affected"), ("6.27.0", "unaffected")])
def test_unreadable_optional_metadata_preserves_independent_lock_assessments(damage, fixed, status):
    metadata = '[project]\ndynamic = ["dependencies"]\n'
    compression = zipfile.ZIP_DEFLATED if damage == "deflate" else zipfile.ZIP_STORED
    data = bytearray(_archive({
        "local/pyproject.toml": metadata,
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/undici": {"version": "8.10.2"},
        }}),
    }, compression))
    if damage == "crc":
        # Change stored metadata without updating its recorded checksum.
        offset = data.index(metadata.encode())
        data[offset] ^= 1
    elif damage == "encrypted":
        # The first member is metadata; set its encryption bit in both headers.
        data[6] |= 1
        data[data.index(b"PK\x01\x02") + 8] |= 1
    else:
        # The first compressed byte follows a 30-byte header and the filename.
        # Set the reserved DEFLATE block type to force a decompressor error.
        data[30 + len("local/pyproject.toml")] |= 6

    result = cve_match.match_archive(bytes(data), _catalog([_ghsa(fixed)]))
    coverage = result["coverage"]
    assert coverage["status"] == "partial"
    assert coverage["status_counts"][status] == 1
    assert len(result["findings"]) == (1 if status == "affected" else 0)
    if result["findings"]:
        assert result["findings"][0]["file"] == "package-lock.json"
    assert coverage["incomplete_manifests"] == {"local/pyproject.toml": "unresolved"}
    assert coverage["manifest_gap_reason_counts"] == {"invalid_manifest_metadata": 1}
    assert coverage["manifest_gap_details"] == [{
        "manifest": "local/pyproject.toml", "status": "unresolved",
        "reason": "invalid_manifest_metadata",
    }]


def test_manifest_diagnostics_are_bounded_but_counts_cover_all_gaps(monkeypatch):
    monkeypatch.setattr(cve_match, "MAX_DETAILS", 1)
    monkeypatch.setattr(cve_match, "MAX_MANIFEST_METADATA_BYTES", 4)
    files = {"a/pyproject.toml": "[project]\n", "b/package.json": "{}", "c/yarn.lock": ""}
    coverage = cve_match.match_archive(_archive(files), _catalog([]))["coverage"]
    assert coverage["manifest_gap_reason_counts"] == {
        "manifest_metadata_size_limit": 1,
        "missing_supported_lockfile": 1,
        "unsupported_manifest_format": 1,
    }
    assert len(coverage["manifest_gap_details"]) == 1
    assert coverage["manifest_gap_details_truncated"] == 2


def test_oversized_generated_manifest_cannot_disable_source_dependency_checks():
    files = {
        "web/package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/undici": {"version": "8.10.2"},
        }}),
        "web/.next/package.json": " " * 2_000_001,
    }
    coverage = cve_match.match_archive(_archive(files), _catalog([_ghsa()]))["coverage"]
    assert coverage["status"] == "checked"
    assert coverage["status_counts"]["unaffected"] == 1
    assert coverage["excluded_manifests"] == {"web/.next/package.json": "generated_next_build"}
    files["web/package.json"] = files.pop("web/.next/package.json")
    assert cve_match.match_archive(_archive(files), _catalog([_ghsa()]))["coverage"]["status"] == "unavailable"
