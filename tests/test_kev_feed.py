"""CISA KEV is an exploitation annotation source; it never creates or removes a package match."""
from copy import deepcopy
import json

import pytest

from app.scan import kev_feed
from app.scan.kev_feed import KEV_REPOSITORY, merge_kev

SHA = "c" * 64
COMMIT = "d" * 40
COMMITTED = "2026-11-03T21:32:24Z"
DATE = "2026-11-03T20:00:24.8741Z"
# The identity the compiler reads from the pinned cisagov/kev-data checkout.
IDENTITY = {"commit": COMMIT, "generated_at": COMMITTED, "sha256": SHA}


def two_source_catalog():
    source = {"repository": "https://github.com/CVEProject/cvelistV5", "commit": "a" * 40,
              "generated_at": "2026-10-24T09:32:38Z"}
    return {
        "schema_version": 2, "source": source,
        "sources": {"cvelist": source, "github-reviewed": {
            "repository": "https://github.com/github/advisory-database", "commit": "b" * 40,
            "generated_at": "2026-10-24T09:36:01Z"}},
        "stats": {"seen": 2},
        "packages": {
            "npm:widget": [{"id": "CVE-2025-12345", "title": "t", "url": "u", "updated_at": None,
                            "default_status": "unaffected", "versions": []}],
            "PyPI:gadget": [{"id": "GHSA-2345-6789-cfgh", "aliases": ["CVE-2024-99999"], "source": "github-reviewed",
                             "title": "t", "url": "u", "updated_at": None, "osv_ranges": [], "osv_versions": []}],
        },
    }


def entry(cve="CVE-2025-12345", **changes):
    return {"cveID": cve, "vendorProject": "Vendor", "product": "Product", "vulnerabilityName": "Name",
            "dateAdded": "2025-03-01", "shortDescription": "d", "requiredAction": "a", "dueDate": "2025-03-22",
            "knownRansomwareCampaignUse": "Known", "notes": "", "cwes": ["CWE-79"], **changes}


def feed(*entries, **changes):
    rows = list(entries) or [entry(), entry("CVE-2024-99999", knownRansomwareCampaignUse="Unknown"),
                             entry("CVE-2020-0001", knownRansomwareCampaignUse="Unknown")]
    return {"title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": "2026.11.03",
            "dateReleased": DATE, "count": len(rows), "vulnerabilities": rows, **changes}


def test_merge_adds_a_third_source_and_an_exploitation_index_without_touching_matches():
    base = two_source_catalog()
    before = deepcopy(base)
    result = merge_kev(base, feed(), **IDENTITY)
    assert base == before
    assert result["schema_version"] == 3
    assert result["packages"] == base["packages"]
    assert result["source"] == base["source"]
    assert set(result["sources"]) == {"cvelist", "github-reviewed", "cisa-kev"}
    # One provenance chain with kev-catalog.json: the pinned commit and upstream blob digest, no feed URL.
    assert result["sources"]["cisa-kev"] == {"repository": KEV_REPOSITORY, "commit": COMMIT,
                                             "generated_at": COMMITTED, "catalog_version": "2026.11.03",
                                             "sha256": SHA}
    assert result["exploitation"] == {"cisa-kev": {
        "CVE-2020-0001": {"date_added": "2025-03-01", "due_date": "2025-03-22", "ransomware": "Unknown"},
        "CVE-2024-99999": {"date_added": "2025-03-01", "due_date": "2025-03-22", "ransomware": "Unknown"},
        "CVE-2025-12345": {"date_added": "2025-03-01", "due_date": "2025-03-22", "ransomware": "Known"},
    }}
    stats = result["stats"]
    assert stats["seen"] == 2
    assert (stats["kev_seen"], stats["kev_indexed"], stats["kev_ransomware_known"]) == (3, 3, 1)
    # Direct CVE id and a GHSA alias both count; the third KEV entry has no package.
    assert stats["kev_in_catalog"] == 2


def test_rebuild_is_deterministic_and_json_sorted():
    first = merge_kev(two_source_catalog(), feed(), **IDENTITY)
    second = merge_kev(two_source_catalog(), json.loads(json.dumps(feed())), **IDENTITY)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


@pytest.mark.parametrize("broken", [
    feed(count=2),
    feed(entry(), entry()),
    feed(entry("CVE-25-1")),
    feed(entry(dateAdded="2025-13-01")),
    feed(entry(dueDate="soon")),
    feed(entry(knownRansomwareCampaignUse="Maybe")),
    feed(entry(cveID=None)),
    feed(catalogVersion="v1"),
    feed(dateReleased="2026-11-03"),
    feed(vulnerabilities="none"),
    {**feed(), "count": None},
    [],
])
def test_malformed_feeds_fail_the_whole_build(broken):
    with pytest.raises(ValueError):
        merge_kev(two_source_catalog(), broken, **IDENTITY)


@pytest.mark.parametrize("broken, message", [
    ({"sha256": "not-a-digest"}, "sha256"),
    ({"commit": "abc123"}, "commit"),
    ({"generated_at": "2026-11-03T21:32:24"}, "generated_at"),
    ({"generated_at": "yesterday"}, "generated_at"),
])
def test_pinned_identity_is_required(broken, message):
    with pytest.raises(ValueError, match=message):
        merge_kev(two_source_catalog(), feed(), **{**IDENTITY, **broken})


def test_base_catalog_must_be_the_two_source_snapshot():
    legacy = two_source_catalog()
    legacy["schema_version"] = 1
    del legacy["sources"]
    with pytest.raises(ValueError, match="two-source"):
        merge_kev(legacy, feed(), **IDENTITY)


def test_record_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(kev_feed, "MAX_RECORDS", 2)
    with pytest.raises(ValueError, match="limit"):
        merge_kev(two_source_catalog(), feed(), **IDENTITY)


def test_unknown_record_fields_are_ignored_but_consumed_fields_are_strict():
    tolerant = merge_kev(two_source_catalog(), feed(entry(forensicTriage="Yes", newField=1)), **IDENTITY)
    assert list(tolerant["exploitation"]["cisa-kev"]) == ["CVE-2025-12345"]
    with pytest.raises(ValueError):
        merge_kev(two_source_catalog(), feed({k: v for k, v in entry().items() if k != "dueDate"}), **IDENTITY)
