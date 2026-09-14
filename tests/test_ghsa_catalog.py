"""Reviewed GHSA ingestion keeps OSV evidence bounded and source-specific."""
from copy import deepcopy
import json

import pytest

from app.scan import cve_catalog, ghsa_catalog

COMMIT = "b" * 40
DATE = "2026-09-14T12:00:00Z"
GHSA = "GHSA-2345-6789-cfgh"


def base():
    return cve_catalog.build_catalog([], source_commit="a" * 40, generated_at=DATE)


def affected(ecosystem="npm", name="widget", ranges=None, versions=None):
    return {
        "package": {"ecosystem": ecosystem, "name": name},
        "ranges": ranges if ranges is not None else [{
            "type": "ECOSYSTEM",
            "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
        }],
        **({"versions": versions} if versions is not None else {}),
    }


def advisory(*items, advisory_id=GHSA, reviewed=True, aliases=None, schema="1.4.0"):
    return {
        "schema_version": schema,
        "id": advisory_id,
        "modified": DATE,
        "published": DATE,
        "aliases": aliases if aliases is not None else ["CVE-2026-12345"],
        "summary": " Reviewed   advisory ",
        "affected": list(items) if items else [affected()],
        "database_specific": {"github_reviewed": reviewed},
    }


def merge(*records):
    return ghsa_catalog.merge_reviewed_ghsa(
        base(), records, source_commit=COMMIT, generated_at=DATE
    )


def test_reviewed_npm_and_pypi_records_preserve_osv_evidence_and_provenance():
    source = advisory(
        affected(versions=["1.5.0", "1.5.0"]),
        affected(ranges=[{
            "type": "SEMVER",
            "events": [{"introduced": "3.0.0"}, {"last_affected": "3.1.0"}],
        }]),
        affected("PyPI", "Foo_Bar", [{
            "type": "ECOSYSTEM",
            "events": [{"introduced": "0"}, {"fixed": "4.0"}],
        }]),
        affected("Go", "example.org/module"),
    )
    before = deepcopy(source)
    result = ghsa_catalog.merge_reviewed_ghsa(
        base(), [source], source_commit=COMMIT, generated_at=DATE
    )
    assert source == before
    assert result["schema_version"] == 2
    assert result["source"] == result["sources"]["cvelist"]
    assert result["sources"]["github-reviewed"] == {
        "repository": ghsa_catalog.REPOSITORY,
        "commit": COMMIT,
        "generated_at": DATE,
    }
    assert set(result["packages"]) == {"npm:widget", "PyPI:foo-bar"}
    npm_entry = result["packages"]["npm:widget"][0]
    assert npm_entry["id"] == GHSA
    assert npm_entry["aliases"] == ["CVE-2026-12345"]
    assert npm_entry["title"] == "Reviewed advisory"
    assert npm_entry["url"] == ghsa_catalog.GHSA_PAGE + GHSA
    assert npm_entry["source"] == "github-reviewed"
    assert npm_entry["osv_versions"] == ["1.5.0"]
    assert {row["type"] for row in npm_entry["osv_ranges"]} == {"ECOSYSTEM", "SEMVER"}
    assert result["stats"]["ghsa_indexed_records"] == 1
    assert result["stats"]["ghsa_indexed_entries"] == 2
    assert result["stats"]["ghsa_indexed_packages"] == 2
    assert result["stats"]["ghsa_unsupported_ecosystems"] == 1


def test_only_reviewed_nonwithdrawn_v1_records_are_indexed():
    unreviewed = advisory(reviewed=False, advisory_id="GHSA-2345-6789-cfgj")
    withdrawn = advisory(advisory_id="GHSA-2345-6789-cfgm")
    withdrawn["withdrawn"] = DATE
    invalid_schema = advisory(advisory_id="GHSA-2345-6789-cfgp", schema="2.0.0")
    malformed = advisory(advisory_id="GHSA-2345-6789-cfgq", aliases=[{}])
    result = merge(unreviewed, withdrawn, invalid_schema, malformed, None)
    assert result["packages"] == {}
    assert result["stats"]["ghsa_unreviewed"] == 1
    assert result["stats"]["ghsa_withdrawn"] == 1
    assert result["stats"]["ghsa_unsupported_schema"] == 1
    assert result["stats"]["ghsa_invalid_records"] == 2


@pytest.mark.parametrize("ranges", [
    [{"type": "ECOSYSTEM", "events": [{"fixed": "2.0.0"}]}],
    [{"type": "ECOSYSTEM", "events": [
        {"introduced": "0"}, {"fixed": "2.0.0"}, {"last_affected": "1.9.0"},
    ]}],
    [{"type": "ECOSYSTEM", "events": [{"introduced": "0", "fixed": "2.0.0"}]}],
    [{"type": "ECOSYSTEM", "events": []}],
])
def test_malformed_osv_ranges_never_become_matching_evidence(ranges):
    result = merge(advisory(affected(ranges=ranges)))
    assert result["packages"] == {}
    assert result["stats"]["ghsa_invalid_affected"] == 1



def test_unknown_osv_aliases_are_ignored_without_losing_reviewed_ranges():
    result = merge(advisory(aliases=["PYSEC-2026-1", "CVE-2026-12345"]))
    entry = result["packages"]["npm:widget"][0]
    assert entry["aliases"] == ["CVE-2026-12345"]
    assert result["stats"]["ghsa_unsupported_aliases"] == 1

def test_git_ranges_are_retained_but_counted_as_unsupported_for_offline_matching():
    ranges = [{
        "type": "GIT",
        "repo": "https://example.invalid/repository",
        "events": [{"introduced": "a" * 40}, {"fixed": "b" * 40}],
        "database_specific": {"ignored": True},
    }]
    result = merge(advisory(affected(ranges=ranges)))
    entry = result["packages"]["npm:widget"][0]
    assert entry["osv_ranges"] == [{
        "type": "GIT",
        "events": [{"introduced": "a" * 40}, {"fixed": "b" * 40}],
    }]
    assert result["stats"]["ghsa_unsupported_ranges"] == 1


def test_pypi_semver_ranges_are_retained_but_counted_as_unsupported():
    ranges = [{
        "type": "SEMVER",
        "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
    }]
    result = merge(advisory(affected("PyPI", "widget", ranges=ranges)))
    assert result["packages"]["PyPI:widget"][0]["osv_ranges"] == ranges
    assert result["stats"]["ghsa_unsupported_ranges"] == 1


def test_duplicate_ids_and_global_limits_abort_instead_of_publishing_partial_data(monkeypatch):
    with pytest.raises(ValueError, match="duplicate GHSA ID"):
        merge(advisory(), advisory())
    monkeypatch.setattr(ghsa_catalog, "MAX_RECORDS", 1)
    with pytest.raises(ValueError, match="record limit"):
        merge(advisory(), advisory(advisory_id="GHSA-2345-6789-cfgj"))
    monkeypatch.setattr(ghsa_catalog, "MAX_RECORDS", 10)
    monkeypatch.setattr(ghsa_catalog, "MAX_PACKAGE_ENTRIES", 0)
    with pytest.raises(ValueError, match="entry limit"):
        merge(advisory())


def test_catalog_is_deterministic_and_inputs_are_not_mutated():
    first = advisory(affected(name="z"), advisory_id="GHSA-2345-6789-cfgj")
    second = advisory(affected(name="a"), advisory_id="GHSA-2345-6789-cfgm")
    original = base()
    before = deepcopy(original)
    one = ghsa_catalog.merge_reviewed_ghsa(
        original, [first, second], source_commit=COMMIT, generated_at=DATE
    )
    two = ghsa_catalog.merge_reviewed_ghsa(
        original, [second, first], source_commit=COMMIT, generated_at=DATE
    )
    assert json.dumps(one) == json.dumps(two)
    assert original == before


@pytest.mark.parametrize(("commit", "date"), [
    ("main", DATE), ("B" * 40, DATE), (COMMIT, None), (COMMIT, "yesterday"),
])
def test_source_metadata_requires_pinned_commit_and_timestamp(commit, date):
    with pytest.raises(ValueError):
        ghsa_catalog.merge_reviewed_ghsa(
            base(), [], source_commit=commit, generated_at=date
        )
