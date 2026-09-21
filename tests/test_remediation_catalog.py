"""Upgrade recipes must not promote one advisory boundary into package safety."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from app.scan import remediation_catalog
from app.scan.cve_match import evaluate_advisory
from app.scan.remediation_catalog import UpgradeBudget, plan_dependency_upgrade


SOURCES = {
    "cvelist": {
        "repository": "https://github.com/CVEProject/cvelistV5",
        "commit": "a" * 40,
        "generated_at": "2026-09-17T09:35:47Z",
    },
    "github-reviewed": {
        "repository": "https://github.com/github/advisory-database",
        "commit": "b" * 40,
        "generated_at": "2026-09-17T09:37:27Z",
    },
}


def advisory(events=None, *, advisory_id="GHSA-2345-6789-cfgh", kind="ECOSYSTEM"):
    return {
        "id": advisory_id,
        "aliases": [],
        "source": "github-reviewed",
        "osv_ranges": [{
            "type": kind,
            "events": events or [{"introduced": "0"}, {"fixed": "2.0.0"}],
        }],
        "osv_versions": [],
    }


def plan(entries, *, ecosystem="npm", installed="1.0.0", **kwargs):
    return plan_dependency_upgrade(ecosystem, "widget", installed, entries, SOURCES, **kwargs)


@pytest.mark.parametrize("ecosystem,recipe_id", [
    ("npm", "npm-dependency-upgrade"),
    ("PyPI", "pypi-dependency-upgrade"),
])
def test_fixed_boundary_yields_reviewable_recipe_without_claiming_application_repair(ecosystem, recipe_id):
    result = plan([advisory()], ecosystem=ecosystem)
    assert result["status"] == "candidates_available"
    assert result["candidate_versions"] == ["2.0.0"]
    assert result["schema_version"] == 1
    assert result["recipe"]["id"] == recipe_id
    assert result["recipe"]["revision"] == 1
    assert result["recipe"]["steps"] and result["recipe"]["verification"]
    assert result["automatic_apply"] is False
    assert result["runtime_verified"] is False
    assert result["compatibility"] == "not_assessed"
    assert result["binding"]["ecosystem"] == ecosystem
    assert result["binding"]["package"] == "widget"
    assert result["binding"]["installed_version"] == "1.0.0"


def test_other_advisory_blocks_earlier_fix_even_when_it_did_not_affect_installed_version():
    entries = [advisory(), advisory(
        [{"introduced": "2.0.0"}, {"fixed": "3.0.0"}],
        advisory_id="GHSA-2345-6789-cfgj",
    )]
    assert evaluate_advisory("1.0.0", "npm", entries[1])["status"] == "unaffected"
    result = plan(entries)
    assert result["candidate_versions"] == ["3.0.0"]
    assert result["advisory_count"] == 2


def test_reintroduced_issue_at_another_ranges_fix_is_not_recommended():
    entries = [advisory([
        {"introduced": "0"}, {"fixed": "2.0.0"},
        {"introduced": "2.5.0"}, {"fixed": "4.0.0"},
    ]), advisory(
        [{"introduced": "0"}, {"fixed": "3.0.0"}],
        advisory_id="GHSA-2345-6789-cfgj",
    )]
    assert plan(entries)["candidate_versions"] == ["4.0.0"]


def test_cve_source_disagreement_blocks_ghsa_fixed_boundary():
    entries = [advisory(), {
        "id": "CVE-2026-12345",
        "default_status": "unaffected",
        "versions": [{"version": "0", "lessThan": "3.0.0",
                      "versionType": "semver", "status": "affected"}],
    }]
    entries[0]["aliases"] = ["CVE-2026-12345"]
    result = plan(entries)
    assert result["candidate_versions"] == []
    assert result["status"] == "manual_review"


@pytest.mark.parametrize("entry", [
    advisory(kind="GIT"),
    {"id": "CVE-2026-12345", "default_status": "unknown", "versions": []},
    {"id": "CVE-2026-12345", "unsupported_applicability": True,
     "default_status": "unaffected", "versions": []},
])
def test_unresolved_other_advisory_prevents_candidate(entry):
    result = plan([advisory(), entry])
    assert result["candidate_versions"] == []
    assert result["status"] == "manual_review"
    assert result["reason_codes"]


@pytest.mark.parametrize("events", [
    [{"introduced": "0"}, {"last_affected": "2.0.0"}],
    [{"introduced": "0"}, {"limit": "2.0.0"}],
    [{"introduced": "0"}],
])
def test_never_guesses_a_fixed_release_from_an_affected_or_limit_boundary(events):
    result = plan([advisory(events)])
    assert result["status"] == "manual_review"
    assert result["candidate_versions"] == []


def test_explicit_affected_versions_do_not_supply_upgrade_candidates():
    entry = advisory()
    entry.update(osv_ranges=[], osv_versions=["1.0.0"])
    assert plan([entry])["candidate_versions"] == []


def test_older_fixed_release_is_not_offered_as_a_downgrade():
    entry = advisory([
        {"introduced": "0"}, {"fixed": "1.0.0"}, {"introduced": "2.0.0"},
    ])
    assert plan([entry], installed="2.5.0")["candidate_versions"] == []


@pytest.mark.parametrize("identities_complete,entry", [
    (False, advisory()),
    (True, {**advisory(), "id": "not-an-advisory"}),
    (True, {**advisory(), "source": "untrusted-source"}),
])
def test_incomplete_or_invalid_identities_cannot_produce_a_recipe_candidate(identities_complete, entry):
    result = plan([entry], identities_complete=identities_complete)
    assert result["candidate_versions"] == []
    assert result["status"] == "manual_review"


def test_exhausted_shared_budget_cannot_offer_an_unchecked_candidate():
    budget = UpgradeBudget(remaining=0)
    result = plan([advisory()], budget=budget)
    assert result["candidate_versions"] == []
    assert result["status"] == "manual_review"
    assert result["reason_codes"]
    assert result["evaluations"] == 0
    assert budget.remaining == 0


def test_partial_candidate_evaluation_does_not_create_a_recommendation():
    entries = [advisory(), advisory(advisory_id="GHSA-2345-6789-cfgj")]
    result = plan(entries, budget=UpgradeBudget(remaining=1))
    assert result["candidate_versions"] == []
    assert result["status"] == "manual_review"
    assert result["evaluations"] <= 1


def test_later_budget_exhaustion_retracts_a_partially_computed_candidate_list():
    entry = advisory([
        {"introduced": "0"}, {"fixed": "2.0.0"},
        {"introduced": "3.0.0"}, {"fixed": "4.0.0"},
    ])
    result = plan([entry], budget=UpgradeBudget(remaining=1))
    assert result["candidate_versions"] == []
    assert result["status"] == "manual_review"
    assert result["evaluations"] == 1


@pytest.mark.parametrize("limit,value", [("MAX_CANDIDATES", 1), ("MAX_DISCOVERY_ITEMS", 2)])
def test_discovery_limits_do_not_promote_an_incomplete_set_of_fixed_releases(monkeypatch, limit, value):
    monkeypatch.setattr(remediation_catalog, limit, value)
    entry = advisory([
        {"introduced": "0"}, {"fixed": "2.0.0"},
        {"introduced": "3.0.0"}, {"fixed": "4.0.0"},
    ])
    result = plan([entry])
    assert result["candidate_versions"] == []
    assert result["status"] == "manual_review"
    assert result["reason_codes"]


def test_advisory_limit_does_not_recommend_using_only_the_accepted_prefix(monkeypatch):
    monkeypatch.setattr(remediation_catalog, "MAX_ADVISORIES", 1)
    entries = [advisory(), advisory(
        [{"introduced": "0"}], advisory_id="GHSA-2345-6789-cfgj",
    )]
    result = plan(entries)
    assert result["candidate_versions"] == []
    assert result["status"] == "manual_review"


def test_binding_changes_when_evidence_changes_and_returned_values_do_not_mutate_inputs():
    entries, sources = [advisory()], deepcopy(SOURCES)
    before = deepcopy((entries, sources))
    first = plan_dependency_upgrade("npm", "widget", "1.0.0", entries, sources)
    assert (entries, sources) == before
    original = deepcopy(first)
    first["recipe"]["steps"].clear()
    first["candidate_versions"].clear()
    assert plan_dependency_upgrade("npm", "widget", "1.0.0", entries, sources) == original

    sources["github-reviewed"]["commit"] = "c" * 40
    changed_source = plan_dependency_upgrade("npm", "widget", "1.0.0", entries, sources)
    assert changed_source["binding"]["sources_sha256"] != original["binding"]["sources_sha256"]
    entries[0]["osv_ranges"][0]["events"][1] = {"fixed": "3.0.0"}
    changed_record = plan_dependency_upgrade("npm", "widget", "1.0.0", entries, sources)
    assert changed_record["binding"]["records_sha256"] != original["binding"]["records_sha256"]
    assert changed_record["candidate_versions"] == ["3.0.0"]


def test_restoring_vulnerable_range_removes_previously_available_candidate():
    entries = [advisory()]
    assert plan(entries)["candidate_versions"] == ["2.0.0"]
    entries[0]["osv_ranges"][0]["events"] = [{"introduced": "0"}]
    assert plan(entries)["candidate_versions"] == []


@pytest.mark.parametrize("ecosystem,package,installed,expected", [
    ("npm", "@apollo/server", "4.7.2", ["5.5.0"]),
    ("PyPI", "adyen", "7.0.0", ["7.1.0"]),
])
def test_shipped_advisories_supply_candidates_checked_against_the_whole_package(
    ecosystem, package, installed, expected,
):
    path = Path(__file__).resolve().parents[1] / "app/data/cve-catalog.json"
    catalog = json.loads(path.read_text())
    entries = catalog["packages"][f"{ecosystem}:{package}"]
    assert any(evaluate_advisory(installed, ecosystem, entry)["status"] == "affected"
               for entry in entries)
    result = plan_dependency_upgrade(ecosystem, package, installed, entries, catalog["sources"])
    assert result["candidate_versions"] == expected
    for candidate in result["candidate_versions"]:
        for entry in entries:
            assessment = evaluate_advisory(candidate, ecosystem, entry)
            assert assessment["status"] == "unaffected"
            assert assessment["unresolved_ranges"] == 0
