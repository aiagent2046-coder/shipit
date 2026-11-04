"""CISA KEV is an exploitation annotation source; it never creates or removes a package match."""
from copy import deepcopy
import json

import pytest

from app.scan import kev_catalog
from app.scan.kev_catalog import KEV_FEED, merge_kev

SHA = "c" * 64
DATE = "2026-11-03T20:00:24.8741Z"


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
    result = merge_kev(base, feed(), feed_sha256=SHA)
    assert base == before
    assert result["schema_version"] == 3
    assert result["packages"] == base["packages"]
    assert result["source"] == base["source"]
    assert set(result["sources"]) == {"cvelist", "github-reviewed", "cisa-kev"}
    assert result["sources"]["cisa-kev"] == {"feed": KEV_FEED, "catalog_version": "2026.11.03",
                                             "generated_at": DATE, "sha256": SHA}
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
    first = merge_kev(two_source_catalog(), feed(), feed_sha256=SHA)
    second = merge_kev(two_source_catalog(), json.loads(json.dumps(feed())), feed_sha256=SHA)
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
        merge_kev(two_source_catalog(), broken, feed_sha256=SHA)


def test_feed_identity_and_base_catalog_are_required():
    with pytest.raises(ValueError, match="sha256"):
        merge_kev(two_source_catalog(), feed(), feed_sha256="not-a-digest")
    legacy = two_source_catalog()
    legacy["schema_version"] = 1
    del legacy["sources"]
    with pytest.raises(ValueError, match="two-source"):
        merge_kev(legacy, feed(), feed_sha256=SHA)


def test_record_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(kev_catalog, "MAX_RECORDS", 2)
    with pytest.raises(ValueError, match="limit"):
        merge_kev(two_source_catalog(), feed(), feed_sha256=SHA)


def test_unknown_record_fields_are_ignored_but_consumed_fields_are_strict():
    tolerant = merge_kev(two_source_catalog(), feed(entry(forensicTriage="Yes", newField=1)), feed_sha256=SHA)
    assert list(tolerant["exploitation"]["cisa-kev"]) == ["CVE-2025-12345"]
    with pytest.raises(ValueError):
        merge_kev(two_source_catalog(), feed({k: v for k, v in entry().items() if k != "dueDate"}),
                  feed_sha256=SHA)
