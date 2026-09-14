"""CVE package identity and offline catalogue trust boundaries."""
from copy import deepcopy
import json

import pytest

from app.scan import cve_catalog

COMMIT = "a" * 40
DATE = "2026-09-14T12:00:00Z"


def product(**kwargs):
    return {"collectionURL": "https://registry.npmjs.org", "packageName": "example",
            "defaultStatus": "unaffected", "versions": [{"version": "1.0.0", "status": "affected",
            "versionType": "semver", "lessThan": "2.0.0"}], **kwargs}


def record(*affected, cve_id="CVE-2026-12345", schema="5.2"):
    return {"dataType": "CVE_RECORD", "dataVersion": schema,
            "cveMetadata": {"cveId": cve_id, "state": "PUBLISHED", "dateUpdated": DATE},
            "containers": {"cna": {"title": "Example vulnerability", "affected": list(affected)}}}


def build(*records):
    return cve_catalog.build_catalog(iter(records), source_commit=COMMIT, generated_at=DATE)


@pytest.mark.parametrize("schema", ["5.0", "5.0.0", "5.1", "5.1.1", "5.2", "5.2.0"])
def test_known_schemas_project_explicit_cna_package_identity(schema):
    source = record(product(), schema=schema)
    source["containers"]["adp"] = [{"affected": [product(packageName="injected")]}]
    before = deepcopy(source)
    result = build(source)
    assert result["source"] == {"repository": cve_catalog.REPOSITORY, "commit": COMMIT, "generated_at": DATE}
    assert list(result["packages"]) == ["npm:example"]
    assert result["packages"]["npm:example"][0] == {
        "id": "CVE-2026-12345", "title": "Example vulnerability",
        "url": "https://www.cve.org/CVERecord?id=CVE-2026-12345", "updated_at": DATE,
        "default_status": "unaffected", "versions": source["containers"]["cna"]["affected"][0]["versions"]}
    assert source == before
    assert result["stats"]["seen"] == result["stats"]["indexed_records"] == 1
    result["packages"]["npm:example"][0]["versions"][0]["version"] = "changed"
    assert source == before


@pytest.mark.parametrize(("identity", "key"), [
    ({"packageURL": "pkg:npm/%40angular/animation"}, "npm:@angular/animation"),
    ({"packageURL": "pkg:npm/example"}, "npm:example"),
    ({"packageURL": "pkg:pypi/Foo_Bar.Baz"}, "PyPI:foo-bar-baz"),
    ({"collectionURL": "https://pypi.org/", "packageName": "Foo_Bar"}, "PyPI:foo-bar"),
    ({"collectionURL": "https://pypi.python.org", "product": "Foo.Bar"}, "PyPI:foo-bar"),
    ({"collectionURL": "https://pypi.org/simple/", "packageName": "Foo--Bar"}, "PyPI:foo-bar"),
    ({"collectionURL": "https://www.npmjs.com", "product": "@scope/package"}, "npm:@scope/package"),
    ({"packageURL": "pkg:pypi/Foo_Bar", "packageName": "foo.bar"}, "PyPI:foo-bar"),
])
def test_explicit_purls_and_official_registry_names(identity, key):
    affected = {"versions": [{"version": "1.0.0", "status": "affected"}], **identity}
    result = build(record(affected))
    assert list(result["packages"]) == [key]
    assert result["packages"][key][0]["default_status"] == "unknown"


@pytest.mark.parametrize("identity", [
    {"vendor": "npm", "product": "example"},
    {"vendor": "pypi", "packageName": "example"},
    {"collectionURL": "https://registry.npmjs.org.evil.test", "packageName": "example"},
    {"collectionURL": "https://registry.npmjs.org@evil.test", "packageName": "example"},
    {"collectionURL": "https://user@registry.npmjs.org", "packageName": "example"},
    {"collectionURL": "https://registry.npmjs.org:443", "packageName": "example"},
    {"collectionURL": "http://registry.npmjs.org", "packageName": "example"},
    {"collectionURL": "https://npm.example.test", "packageName": "example"},
    {"collectionURL": "https://pypi.org/project/example", "packageName": "example"},
    {"collectionURL": "https://pypi.org/?index=custom", "packageName": "example"},
    {"packageURL": "pkg:npm/example?repository_url=https://evil.test"},
    {"packageURL": "pkg:npm/example#subpath"},
    {"packageURL": "pkg:npm/example@1.2.3"},
    {"packageURL": "pkg:npm/%40scope/example@1.2.3"},
    {"packageURL": "pkg:pypi/example@1.2.3"},
    {"packageURL": "pkg:pypi/namespace/example"},
    {"packageURL": "pkg:npm/%2540scope/example"},
    {"packageURL": "pkg:npm/%ZZ"},
    {"packageURL": "pkg:npm/%FF"},
    {"packageURL": "pkg:gem/example"},
    {"packageURL": "pkg:npm/example", "packageName": "different"},
    {"packageURL": "pkg:npm/example", "collectionURL": "https://pypi.org", "packageName": "example"},
    {"packageURL": "pkg:npm/example", "collectionURL": "https://private.test", "packageName": "example"},
    {"collectionURL": "https://registry.npmjs.org", "packageName": "example\n"},
])
def test_no_fuzzy_custom_qualified_or_conflicting_package_identity(identity):
    result = build(record({"defaultStatus": "affected", **identity}))
    assert result["packages"] == {}
    assert result["stats"]["unsupported_packages"] + result["stats"]["invalid_affected"] == 1


def test_unsupported_ranges_and_unsorted_status_changes_are_not_repaired():
    versions = [{"version": "before release 2", "status": "affected", "versionType": "custom",
                 "lessThan": "n/a", "changes": [{"at": "later", "status": "unaffected"},
                                                  {"at": "earlier", "status": "affected"}]},
                {"version": "0", "status": "unknown", "lessThan": "*", "lessThanOrEqual": "3"}]
    result = build(record(product(versions=versions)))
    assert result["packages"]["npm:example"][0]["versions"] == versions


def test_platform_specific_claim_remains_explicitly_unresolved():
    result = build(record(product(platforms=["Windows"])))
    assert result["packages"]["npm:example"][0]["unsupported_applicability"] is True
    assert result["stats"]["unsupported_applicability"] == 1


@pytest.mark.parametrize("reversed_order", [False, True])
def test_duplicate_record_aborts_including_published_then_rejected(reversed_order):
    first = record(product())
    rejected = deepcopy(first)
    rejected["cveMetadata"]["state"] = "REJECTED"
    inputs = [first, rejected]
    if reversed_order:
        inputs.reverse()
    with pytest.raises(ValueError, match="duplicate CVE ID"):
        build(*inputs)
    with pytest.raises(ValueError, match="duplicate CVE ID"):
        build(first, first)


def test_rejected_unsupported_and_malformed_records_have_no_matching_entries():
    rejected = record(product(), cve_id="CVE-2026-12346")
    rejected["cveMetadata"]["state"] = "REJECTED"
    malformed = record(product(), cve_id="CVE-2026-12347")
    malformed["cveMetadata"]["dateUpdated"] = "2026-02-30T00:00:00Z"
    result = build(rejected, record(product(), schema="5.3"), malformed, None)
    assert result["packages"] == {}
    assert result["stats"]["rejected"] == result["stats"]["unsupported_schema"] == 1
    assert result["stats"]["invalid_records"] == 2


@pytest.mark.parametrize("mutation", [
    {"versions": "1.0.0"}, {"versions": [{}]}, {"defaultStatus": "yes"},
    {"versions": [{"version": "1.0.0", "status": "affected", "changes": [{}]}]},
    {"versions": [{"version": "1.0.0", "status": "affected", "versionType": []}]},
    {"versions": [{"version": "1.0.0", "status": "affected", "unexpected": "value"}]},
    {"versions": [{"version": "1" * 1025, "status": "affected"}]},
])
def test_malformed_consumed_fields_do_not_become_evidence(mutation):
    result = build(record(product(**mutation), product(packageName="valid")))
    assert list(result["packages"]) == ["npm:valid"]
    assert result["stats"]["invalid_affected"] == 1


def test_record_and_entry_limits_abort_instead_of_publishing_truncation(monkeypatch):
    monkeypatch.setattr(cve_catalog, "MAX_RECORDS", 1)
    with pytest.raises(ValueError, match="record limit"):
        build(record(product()), record(product(), cve_id="CVE-2026-12346"))
    monkeypatch.setattr(cve_catalog, "MAX_RECORDS", 10)
    monkeypatch.setattr(cve_catalog, "MAX_PACKAGE_ENTRIES", 1)
    with pytest.raises(ValueError, match="entry limit"):
        build(record(product(), product()))


def test_oversized_arrays_are_counted_without_silent_truncation(monkeypatch):
    monkeypatch.setattr(cve_catalog, "MAX_VERSIONS", 1)
    versions = [{"version": "1.0.0", "status": "affected"}] * 2
    result = build(record(product(versions=versions)))
    assert result["stats"]["invalid_affected"] == 1 and not result["packages"]


def test_catalogue_is_deterministic_for_reordered_source_records():
    first = record(product(packageName="z"), product(packageName="a"))
    second = record(product(packageName="a"), cve_id="CVE-2026-12346")
    assert json.dumps(build(first, second)) == json.dumps(build(second, first))


@pytest.mark.parametrize(("commit", "date"), [("main", DATE), ("a" * 39, DATE), ("A" * 40, DATE),
                                             (COMMIT, None), (COMMIT, "yesterday")])
def test_source_metadata_requires_pinned_commit_and_timestamp(commit, date):
    with pytest.raises(ValueError):
        cve_catalog.build_catalog([], source_commit=commit, generated_at=date)
