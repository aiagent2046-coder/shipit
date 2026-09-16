"""CVE's earliest-version convention must not weaken SemVer validation."""
import io
import json
import zipfile

import pytest

from app.scan.cve_match import evaluate_advisory, match_archive


def _entry(rows):
    return {"id": "CVE-2026-11525", "default_status": "unaffected", "versions": rows}


def _range(**changes):
    return {"version": "0", "lessThan": "1.0.0", "versionType": "semver",
            "status": "affected", **changes}


def _scan(version, entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("package-lock.json", json.dumps({
            "lockfileVersion": 3, "packages": {"node_modules/undici": {"version": version}},
        }))
    source = {"repository": "https://github.com/CVEProject/cvelistV5", "commit": "a" * 40,
              "generated_at": "2026-09-15T10:01:37Z"}
    catalog = {"schema_version": 2, "source": source, "sources": {
        "cvelist": source,
        "github-reviewed": {**source, "repository": "https://github.com/github/advisory-database"},
    }, "packages": {"npm:undici": entries}}
    return match_archive(stream.getvalue(), catalog)


@pytest.mark.parametrize("bound,upper,version,expected", [
    ("lessThan", "1.0.0", "0.0.0-alpha", "affected"),
    ("lessThan", "1.0.0", "0.0.0", "affected"),
    ("lessThan", "1.0.0", "0.9.9", "affected"),
    ("lessThan", "1.0.0", "1.0.0-rc.1", "affected"),
    ("lessThan", "1.0.0", "1.0.0", "unaffected"),
    ("lessThanOrEqual", "1.0.0", "1.0.0", "affected"),
    ("lessThanOrEqual", "1.0.0", "1.0.1", "unaffected"),
    ("lessThan", "0.0.0", "0.0.0-alpha", "affected"),
    ("lessThan", "0.0.0", "0.0.0", "unaffected"),
    ("lessThan", "*", "999.0.0", "affected"),
])
def test_earliest_range_respects_upper_boundary(bound, upper, version, expected):
    row = {"version": "0", bound: upper, "versionType": "semver", "status": "affected"}
    result = evaluate_advisory(version, "npm", _entry([row]))
    assert result["status"] == expected
    assert result["reason"] is None
    assert result["unresolved_ranges"] == 0


@pytest.mark.parametrize("version,expected", [
    ("0.0.0-alpha", "affected"),
    ("0.2.0", "unaffected"),
    ("0.9.0", "unaffected"),
    ("0.10.0", "affected"),
])
def test_earliest_range_preserves_sorted_inclusive_status_changes(version, expected):
    row = _range(changes=[
        {"at": "0.10.0", "status": "affected"},
        {"at": "0.2.0", "status": "unaffected"},
    ])
    result = evaluate_advisory(version, "npm", _entry([row]))
    assert result["status"] == expected
    assert result["reason"] is None


@pytest.mark.parametrize("version,row,reason", [
    ("0", _range(), "unsupported_installed_version"),
    ("13.0", _range(), "unsupported_installed_version"),
    ("01.0.0", _range(), "unsupported_installed_version"),
    ("0.0.0-01", _range(), "unsupported_installed_version"),
    ("0.0.0", {"version": "0", "status": "affected"}, "unsupported_version"),
    ("0.0.0", _range(lessThan="0"), "unsupported_version"),
    ("14.0.0", _range(version="13.0", lessThan="15.0.0"), "unsupported_version"),
    ("0.0.0", _range(version="00"), "unsupported_version"),
    ("0.0.0", _range(version="0.0"), "unsupported_version"),
    ("0.0.0", _range(versionType="custom"), "unsupported_version_type"),
    ("0.0.0", _range(lessThan="not-a-version"), "unsupported_version"),
    ("0.0.0", _range(lessThanOrEqual="1.0.0"), "conflicting_bounds"),
    ("0.0.0", _range(changes=[{"at": "0", "status": "unaffected"}]), "invalid_changes"),
    ("0.0.0", _range(changes=[{"at": "1.0.0", "status": "unaffected"}]), "invalid_changes"),
])
def test_earliest_convention_does_not_hide_invalid_versions_or_ranges(version, row, reason):
    result = evaluate_advisory(version, "npm", _entry([row]))
    assert result["status"] == "unknown"
    assert result["reason"] == reason
    assert result["matched_ranges"] == []


def test_earliest_range_keeps_original_bound_in_finding_evidence():
    row = _range()
    finding, = _scan("0.0.0-alpha", [_entry([row])])["findings"]
    assert finding["claim_evidence"]["installed_version"] == "0.0.0-alpha"
    assert finding["claim_evidence"]["matched_ranges"] == [row]
    assert row["version"] == "0"


# Frozen CNA ranges from cvelistV5 b2d26fd802d80cc5162f8b87c87ecdb08cc5c91a.
# Keep these independent of future catalog corrections and source updates.
@pytest.mark.parametrize("cve,fixed6,fixed7,fixed8", [
    ("CVE-2026-11525", "6.26.0", "7.28.0", "8.5.0"),
    ("CVE-2026-12151", "6.26.0", "7.28.0", "8.5.0"),
    ("CVE-2026-15157", "6.28.0", "7.29.0", "8.9.0"),
    ("CVE-2026-16728", "6.28.0", "7.29.0", "8.9.0"),
    ("CVE-2026-16729", "6.28.0", "7.29.0", "8.9.0"),
    ("CVE-2026-18540", "6.28.1", "7.29.1", "8.10.2"),
    ("CVE-2026-6733", "6.26.0", "7.28.0", "8.5.0"),
    ("CVE-2026-9679", "6.26.0", "7.28.0", "8.5.0"),
])
def test_pilot_undici_cna_ranges_resolve_without_losing_affected_versions(cve, fixed6, fixed7, fixed8):
    rows = []
    for lower, upper in [("0", fixed6), ("7.0.0", fixed7), ("8.0.0", fixed8)]:
        rows.extend([
            _range(version=lower, lessThan=upper),
            {"version": upper, "versionType": "semver", "status": "unaffected"},
        ])
    entry = {**_entry(rows), "id": cve}
    for version in ("0.0.0-alpha", "6.25.0", "7.0.0", "8.0.0"):
        assert evaluate_advisory(version, "npm", entry)["status"] == "affected"
    for version in (fixed6, fixed7, fixed8, "8.10.2"):
        result = evaluate_advisory(version, "npm", entry)
        assert result["status"] == "unaffected"
        assert result["unresolved_ranges"] == 0
        assert result["reason"] is None


def test_earliest_support_preserves_real_cna_ghsa_boundary_disagreement():
    # CVE-2026-11525 says <6.26.0; its reviewed GHSA says <6.27.0.
    cna = _entry([_range(lessThan="6.26.0")])
    ghsa = {"id": "GHSA-g8m3-5g58-fq7m", "aliases": [cna["id"]],
            "source": "github-reviewed", "osv_ranges": [{
                "type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "6.27.0"}],
            }], "osv_versions": []}
    result = _scan("6.26.0", [cna, ghsa])
    assert result["findings"] == []
    coverage = result["coverage"]
    assert coverage["status_counts"]["unknown"] == 1
    assert coverage["unknown_reason_counts"] == {"conflicting_advisory_sources": 1}
    detail, = coverage["details"]
    assert detail["assessments"] == [
        {"source": "cvelist", "advisory": cna["id"], "status": "unaffected", "reason": None},
        {"source": "github-reviewed", "advisory": ghsa["id"], "status": "affected", "reason": None},
    ]
