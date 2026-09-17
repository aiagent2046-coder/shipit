"""Refresh keeps every recorded dependency location without multiplying OSV queries."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json

import pytest

from app.scan.pipeline import BASIS_STATIC_ONLY
from app.sca.lockfiles import (
    MAX_LOCKFILES,
    collect_dependency_inventory,
    dependency_occurrences,
    occurrence_evidence,
)
from app.sca.osv import OsvClient
from app.sca.refresh import (
    dependencies_from_payload,
    inventory_payload,
    refresh_stale_dependency_audits,
)
from app.sca.stage import RULE_ID, DependencyFinding, run_sca_stage
from tests.test_sca_stage import FakeTransport, LODASH_ADVISORY, make_zip

NOW = datetime(2026, 9, 20, 12, tzinfo=timezone.utc)
ASKED = (NOW - timedelta(days=10)).isoformat()


def _monorepo():
    def lock(development):
        return json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/lodash": {"version": "4.17.4", "dev": development},
        }})
    return make_zip({
        "package.json": json.dumps({"devDependencies": {"lodash": "4.17.4"}}),
        "package-lock.json": lock(True),
        "web/package-lock.json": lock(False),
    })


def _client():
    identifier = LODASH_ADVISORY["id"]
    transport = FakeTransport(
        [[{"vulns": [{"id": identifier}]}]], {identifier: LODASH_ADVISORY},
    )
    return OsvClient(transport=transport), transport


def _assert_one_query(transport):
    assert transport.posts == [{"queries": [{
        "package": {"ecosystem": "npm", "name": "lodash"}, "version": "4.17.4",
    }]}]
    assert len(transport.gets) == 1


def _assert_locations(evidence):
    assert evidence["package"] == "lodash"
    assert evidence["installed_version"] == "4.17.4"
    assert evidence["manifest"] == "web/package-lock.json"
    assert evidence["dependency_scope"] == "runtime"
    assert evidence["direct"] is False
    assert evidence["dependency_groups"] == []
    assert evidence["occurrences_recorded"] is True
    assert evidence["occurrences"] == [
        {"manifest": "package-lock.json", "line": 0, "direct": True,
         "dependency_scope": "development", "dependency_groups": ["devDependencies"]},
        {"manifest": "web/package-lock.json", "line": 0, "direct": False,
         "dependency_scope": "runtime", "dependency_groups": []},
    ]


def test_inventory_json_roundtrip_keeps_locations_groups_and_canonical_scope():
    archive = _monorepo()
    payload = json.loads(json.dumps(inventory_payload(archive, ASKED)))
    restored = dependencies_from_payload(payload)
    assert restored == collect_dependency_inventory(archive).dependencies
    assert len(restored) == payload["found"] == 1
    assert payload["version"] == 1
    dep = restored[0]
    assert dep.manifest == "web/package-lock.json"
    assert dep.development is False and dep.direct is False
    assert dep.dependency_groups == ()
    assert [o.manifest for o in dep.occurrences] == ["package-lock.json", "web/package-lock.json"]
    assert dep.occurrences[0].dependency_groups == ("devDependencies",)


def test_online_stage_reports_both_origins_with_one_query_and_one_finding():
    client, transport = _client()
    findings, stats = run_sca_stage(_monorepo(), client)
    _assert_one_query(transport)
    assert len(findings) == stats["findings"] == stats["dependencies"] == stats["dependencies_found"] == 1
    assert stats["packages_reported"] == 1
    finding = findings[0]
    assert isinstance(finding, DependencyFinding)
    _assert_locations(json.loads(json.dumps(vars(finding)))["claim_evidence"])
    assert "package-lock.json (development; direct; groups: devDependencies)" in finding.explanation
    assert "web/package-lock.json (runtime; not marked direct)" in finding.explanation
    assert "representative" in finding.explanation
    assert finding.file == "web/package-lock.json"


class _StoredRepo:
    def __init__(self, payload):
        self.original = {
            "id": "previous-audit", "created_at": NOW - timedelta(days=10),
            "score_json": {"basis": BASIS_STATIC_ONLY, "scan_manifest": {"sca_asked_at": ASKED}},
            "findings_json": [{"rule_id": RULE_ID, "title": "previous dependency evidence",
                               "severity": "high", "category": "Security"}],
            "dependency_inventory": deepcopy(payload),
        }
        self.created = []

    async def stale_dependency_audits(self, **_kwargs):
        return [self.original]

    async def create(self, **fields):
        self.created.append(deepcopy(fields))
        return {"id": "refreshed-audit", **fields}


@pytest.mark.asyncio
async def test_refresh_retains_origins_and_groups_without_requerying_each_manifest():
    payload = inventory_payload(_monorepo(), ASKED)
    repo = _StoredRepo(payload)
    original = deepcopy(repo.original)
    client, transport = _client()
    summary = await refresh_stale_dependency_audits(repo, client_factory=lambda: client, now=NOW)
    assert summary["refreshed"] == 1
    assert repo.original == original
    _assert_one_query(transport)
    assert len(repo.created) == 1
    refreshed = repo.created[0]
    assert refreshed["dependency_inventory"]["dependencies"] == payload["dependencies"]
    assert refreshed["dependency_inventory"]["asked_at"] == NOW.isoformat(timespec="seconds")
    assert len(refreshed["findings_json"]) == 1
    _assert_locations(refreshed["findings_json"][0]["claim_evidence"])
    assert refreshed["score_json"]["scan_manifest"]["sca_dependencies"] == 1


@pytest.mark.asyncio
async def test_legacy_inventory_refresh_does_not_invent_additional_origins():
    # This is a saved v1 row, not a new collector result: several selected
    # lockfiles cannot tell which of them actually contained this package.
    payload = {"version": 1, "asked_at": ASKED, "found": 1,
               "lockfiles": ["package-lock.json", "web/package-lock.json"],
               "dependencies": [{"ecosystem": "npm", "name": "lodash", "version": "4.17.4",
                                 "manifest": "package-lock.json", "line": 0,
                                 "direct": True, "development": True}]}
    dependencies = dependencies_from_payload(payload)
    assert len(dependencies) == 1
    assert dependencies[0].occurrences == ()
    assert [o.manifest for o in dependency_occurrences(dependencies[0])] == ["package-lock.json"]
    repo = _StoredRepo(payload)
    client, transport = _client()
    summary = await refresh_stale_dependency_audits(repo, client_factory=lambda: client, now=NOW)
    assert summary["refreshed"] == 1
    _assert_one_query(transport)
    saved = repo.created[0]
    evidence = saved["findings_json"][0]["claim_evidence"]
    assert evidence["occurrences_recorded"] is False
    assert evidence["occurrences"] == occurrence_evidence(dependencies[0])
    assert "web/package-lock.json" not in saved["findings_json"][0]["explanation"]
    assert "occurrences" not in saved["dependency_inventory"]["dependencies"][0]
    assert dependencies_from_payload(saved["dependency_inventory"])[0].occurrences == ()


@pytest.mark.parametrize("corruption", [
    "empty", "not_a_list", "bad_item", "missing_field", "bool_line", "negative_line",
    "string_direct", "string_development", "string_groups", "bad_group", "duplicate_group",
    "duplicate_manifest", "outside_inventory", "too_many", "mixed_canonical_fields",
])
@pytest.mark.asyncio
async def test_malformed_occurrences_cannot_replace_old_findings(corruption):
    payload = inventory_payload(_monorepo(), ASKED)
    entry = payload["dependencies"][0]
    occurrence = entry["occurrences"][0]
    if corruption == "empty":
        entry["occurrences"] = []
    elif corruption == "not_a_list":
        entry["occurrences"] = {}
    elif corruption == "bad_item":
        entry["occurrences"].append(None)
    elif corruption == "missing_field":
        occurrence.pop("development")
    elif corruption == "bool_line":
        occurrence["line"] = True
    elif corruption == "negative_line":
        occurrence["line"] = -1
    elif corruption == "string_direct":
        occurrence["direct"] = "false"
    elif corruption == "string_development":
        occurrence["development"] = "false"
    elif corruption == "string_groups":
        occurrence["dependency_groups"] = "devDependencies"
    elif corruption == "bad_group":
        occurrence["dependency_groups"] = [None]
    elif corruption == "duplicate_group":
        occurrence["dependency_groups"] *= 2
    elif corruption == "duplicate_manifest":
        entry["occurrences"].append(deepcopy(occurrence))
    elif corruption == "outside_inventory":
        occurrence["manifest"] = "unrecorded/package-lock.json"
    elif corruption == "too_many":
        entry["occurrences"] = [{**occurrence, "manifest": f"p{i}/package-lock.json"}
                                for i in range(MAX_LOCKFILES + 1)]
        payload["lockfiles"] = [o["manifest"] for o in entry["occurrences"]]
    elif corruption == "mixed_canonical_fields":
        entry["dependency_groups"] = ["devDependencies"]
    assert dependencies_from_payload(payload) == []
    repo = _StoredRepo(payload)
    original = deepcopy(repo.original)
    client, transport = _client()
    summary = await refresh_stale_dependency_audits(repo, client_factory=lambda: client, now=NOW)
    assert summary["refreshed"] == 0 and summary["skipped"] == 1
    assert repo.created == []
    assert repo.original == original
    assert transport.posts == transport.gets == []
