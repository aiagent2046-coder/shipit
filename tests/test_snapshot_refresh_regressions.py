"""A new snapshot retires only the advisory evidence it actually reassessed."""
from copy import deepcopy
import hashlib
import io
import json
import zipfile

import pytest

from app.sca import lockfiles, snapshot
from app.scan import cve_match
from app.scan.manifest import sca_manifest_fields
from app.scan.pipeline import score_findings


PRIMARY = "GHSA-2345-2345-2345"
SECONDARY = "GHSA-3456-3456-3456"
CVE = "CVE-2026-1234"


def advisory(identifier=PRIMARY, *, range_type="ECOSYSTEM", fixed="2.0.0"):
    return {"id": identifier, "source": "github-reviewed", "osv_ranges": [
        {"type": range_type, "events": [{"introduced": "0"}, {"fixed": fixed}]}]}


@pytest.fixture
def catalog(monkeypatch, tmp_path):
    monkeypatch.setattr(snapshot, "CATALOG_PATH", tmp_path / "catalog.json")
    monkeypatch.setattr(snapshot, "CHECKSUM_PATH", tmp_path / "catalog.sha256")
    source = {"repository": cve_match.SOURCE_REPOSITORY, "commit": "a" * 40,
              "generated_at": "2026-09-17T00:00:00Z"}
    ghsa_source = {"repository": cve_match.GHSA_REPOSITORY, "commit": "b" * 40,
                   "generated_at": "2026-09-17T00:00:00Z"}

    def publish(packages):
        data = {"schema_version": 2, "source": source,
                "sources": {"cvelist": source, "github-reviewed": ghsa_source},
                "packages": packages}
        raw = json.dumps(data).encode()
        snapshot.CATALOG_PATH.write_bytes(raw)
        snapshot.CHECKSUM_PATH.write_text(hashlib.sha256(raw).hexdigest())
        return data

    return publish


def archive(*names):
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w") as zipped:
        zipped.writestr("requirements.txt", "".join(f"{name}==1.0.0\n" for name in names))
    return raw.getvalue()


def scan(raw):
    findings, stats = snapshot.run_snapshot_stage(raw)
    score = {**score_findings(findings, llm_ran=False, llm_categories=frozenset(),
                             incomplete_static=frozenset()),
             "basis": "static_only", "scan_manifest": sca_manifest_fields(stats)}
    return {"score": score, "findings": findings}


@pytest.mark.parametrize("retirement", ["unaffected", "withdrawn"])
@pytest.mark.parametrize("detail_limit", [200, 0])
def test_completed_negative_retires_old_match_despite_unrelated_unknown(
    catalog, monkeypatch, retirement, detail_limit,
):
    raw = archive("adyen", "requests")
    catalog({"PyPI:adyen": [advisory()]})
    initial = scan(raw)
    assert len(initial["findings"]) == 1
    updated = {"PyPI:requests": [advisory(SECONDARY, range_type="GIT")]}
    if retirement == "unaffected":
        updated["PyPI:adyen"] = [advisory(fixed="1.0.0")]
    catalog(updated)
    monkeypatch.setattr(cve_match, "MAX_DETAILS", detail_limit)

    refreshed = snapshot.refresh_snapshot(initial["score"], initial["findings"], raw)

    coverage = refreshed["sca"]["dependency_cve"]
    assert coverage["status"] == "partial"
    assert coverage["status_counts"]["unknown"] == 1
    assert not refreshed["findings"]
    assert "retained_findings" not in refreshed["sca"]["dependency_snapshot"]
    assert refreshed["score"]["total"] > initial["score"]["total"]


def test_new_cve_alias_does_not_duplicate_earlier_ghsa_at_the_finding_limit(catalog, monkeypatch):
    raw = archive("adyen")
    catalog({"PyPI:adyen": [advisory()]})
    initial = scan(raw)
    ghsa = {**advisory(), "aliases": [CVE]}
    cve = {"id": CVE, "source": "cvelist", "aliases": [PRIMARY],
           "versions": [{"version": "0", "lessThan": "2.0.0",
                         "status": "affected", "versionType": "pep440"}],
           "default_status": "unaffected"}
    catalog({"PyPI:adyen": [ghsa, cve, advisory(SECONDARY)]})
    monkeypatch.setattr(cve_match, "MAX_FINDINGS", 1)

    refreshed = snapshot.refresh_snapshot(initial["score"], initial["findings"], raw)

    assert refreshed["sca"]["dependency_cve"]["findings_truncated"] == 1
    assert refreshed["sca"]["dependency_cve"]["status_counts"]["unknown"] == 0
    assert len(refreshed["findings"]) == 1
    evidence = refreshed["findings"][0]["claim_evidence"]
    assert evidence["advisory_id"] == CVE
    assert set(evidence["advisory_ids"]) == {PRIMARY, CVE}
    assert "snapshot_check_status" not in evidence
    assert "retained_findings" not in refreshed["sca"]["dependency_snapshot"]
    assert refreshed["score"]["total"] == initial["score"]["total"]


@pytest.mark.parametrize("gap", ["unknown", "outage", "inventory", "evaluations", "findings"])
def test_unrechecked_match_survives_with_original_provenance_and_a_retained_marker(
    catalog, monkeypatch, gap,
):
    raw = archive("adyen")
    catalog({"PyPI:adyen": [advisory()]})
    initial = scan(raw)
    original = deepcopy(initial)
    if gap == "unknown":
        catalog({"PyPI:adyen": [advisory(range_type="GIT")]})
    elif gap == "outage":
        snapshot.CATALOG_PATH.unlink()
    elif gap == "inventory":
        monkeypatch.setattr(lockfiles, "MAX_DEPENDENCIES", 0)
    else:
        monkeypatch.setattr(cve_match, "MAX_EVALUATIONS" if gap == "evaluations" else "MAX_FINDINGS", 0)

    refreshed = snapshot.refresh_snapshot(initial["score"], initial["findings"], raw)

    assert initial == original
    expected = deepcopy(original["findings"])
    expected[0]["claim_evidence"]["snapshot_check_status"] = "retained_not_reconfirmed"
    assert "not been reconfirmed" in refreshed["findings"][0]["fix_hint"]
    assert "Advisory-fixed upgrade candidates:" not in refreshed["findings"][0]["fix_hint"]
    expected[0]["fix_hint"] = refreshed["findings"][0]["fix_hint"]
    assert refreshed["findings"] == expected
    assert refreshed["score"]["total"] == initial["score"]["total"]
    assert refreshed["sca"]["dependency_snapshot"]["retained_findings"] == 1


def test_a_later_success_reconfirms_an_earlier_retained_match(catalog):
    raw = archive("adyen")
    catalog({"PyPI:adyen": [advisory()]})
    initial = scan(raw)
    snapshot.CATALOG_PATH.unlink()
    retained = snapshot.refresh_snapshot(initial["score"], initial["findings"], raw)
    assert retained["findings"][0]["claim_evidence"]["snapshot_check_status"] == "retained_not_reconfirmed"
    catalog({"PyPI:adyen": [advisory()]})

    refreshed = snapshot.refresh_snapshot(retained["score"], retained["findings"], raw)

    assert refreshed["findings"] == initial["findings"]
    assert "retained_findings" not in refreshed["sca"]["dependency_snapshot"]


def test_internal_assessment_observer_does_not_change_public_matcher_output(catalog):
    raw = archive("adyen", "requests")
    data = catalog({"PyPI:adyen": [advisory()],
                    "PyPI:requests": [advisory(SECONDARY, range_type="GIT")]})
    observed = []

    output = cve_match.match_archive(raw, data, assessment_observer=lambda *args: observed.append(args))

    assert output == cve_match.match_archive(raw, data)
    assert {dep.name for dep, _, _ in observed} == {"adyen", "requests"}
