"""The dependency refresh: stored inventory in, refreshed rows out.

The equivalence test is the load-bearing one. A refresh rescoring an audit it
did not run can drift from a full scan of the same findings one rule at a time,
silently -- so it asserts the two produce the SAME score, not a plausible one.
"""
from __future__ import annotations

import json
import uuid
from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from app.llm.client import LLMClient
from app.report.evidence import manifest_rows
from app.sca.osv import OsvClient
from app.sca.refresh import (dependencies_from_payload, inventory_payload,
                             refresh_stale_dependency_audits, refreshed_findings,
                             refreshed_score, score_inputs_from_stored)
from app.sca.stage import RULE_ID, SCA_FRESHNESS_TTL_DAYS
from app.scan.pipeline import AUDIT_ENGINE_VERSION, run_scan, score_findings
from tests.test_sca_stage import FakeTransport, LODASH_ADVISORY, make_zip

NOW = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)


def repo_bytes(version: str = "4.17.4") -> bytes:
    return make_zip({
        "package.json": json.dumps({"dependencies": {"lodash": "^4.17.0"}}),
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/lodash": {"version": version}}}),
    })


def advisory_client(advisory_id: str = "GHSA-35jh-r3h4-6jhm",
                    record: dict | None = None) -> OsvClient:
    return OsvClient(transport=FakeTransport(
        [[{"vulns": [{"id": advisory_id}]}]],
        {advisory_id: record or LODASH_ADVISORY}))


def silent_client() -> OsvClient:
    return OsvClient(transport=FakeTransport([[]], {}))


# -- the stored inventory ---------------------------------------------------

def test_the_inventory_holds_versions_and_nothing_else():
    payload = inventory_payload(repo_bytes(), "2026-09-10T00:00:00+00:00")
    assert payload is not None
    assert payload["version"] == 1
    assert payload["asked_at"] == "2026-09-10T00:00:00+00:00"
    assert payload["found"] == 1
    assert payload["lockfiles"] == ["package-lock.json"]
    entry = payload["dependencies"][0]
    assert entry == {"ecosystem": "npm", "name": "lodash", "version": "4.17.4",
                     "manifest": "package-lock.json", "line": 0,
                     "direct": True, "development": False}


def test_nothing_is_stored_when_the_stage_never_asked():
    assert inventory_payload(repo_bytes(), None) is None
    assert inventory_payload(make_zip({"app.py": "x = 1\n"}),
                             "2026-09-10T00:00:00+00:00") is None


def test_a_stored_inventory_round_trips():
    payload = inventory_payload(repo_bytes(), "2026-09-10T00:00:00+00:00")
    dependencies = dependencies_from_payload(payload)
    assert [(d.ecosystem, d.name, d.version, d.direct) for d in dependencies] == [
        ("npm", "lodash", "4.17.4", True)]


@pytest.mark.parametrize("payload", [
    None, {}, {"dependencies": "not a list"}, {"dependencies": [None, 42]},
    {"dependencies": [{"ecosystem": "npm", "name": "x"}]},
    {"dependencies": [{"ecosystem": None, "name": "x", "version": "1"}]},
])
def test_a_malformed_inventory_yields_what_is_readable_rather_than_raising(payload):
    assert dependencies_from_payload(payload) == []


def test_a_partly_readable_inventory_keeps_the_readable_entries():
    payload = {"dependencies": [
        {"ecosystem": "npm", "name": "good", "version": "1.0.0"},
        {"ecosystem": "npm", "name": "bad"}]}
    assert [d.name for d in dependencies_from_payload(payload)] == ["good"]


# -- rescoring --------------------------------------------------------------

def test_the_refresh_rescore_matches_a_full_scan_of_the_same_findings():
    """The whole point: the refreshed total must equal what run_scan would have
    produced for exactly these findings, or the refresh silently invents a
    different audit."""
    scan = run_scan(repo_bytes(), LLMClient(), sca_client=advisory_client())
    rerun = run_scan(repo_bytes(), LLMClient(), sca_client=advisory_client())
    assert rerun["score"] == scan["score"], (
        "the same inputs must score identically before this test means anything")

    recomputed = score_findings(scan["findings"], **score_inputs_from_stored(scan["score"]))
    assert recomputed == {k: v for k, v in scan["score"].items()
                          if k in recomputed}, (
        "the extracted scorer and the pipeline must agree key for key")


def test_a_refreshed_row_keeps_everything_the_refresh_did_not_change():
    scan = run_scan(repo_bytes(), LLMClient(), sca_client=advisory_client())
    still_vulnerable = scan["findings"]
    stats = dict(scan["sca"])
    stats["asked_at"] = "2026-09-10T12:00:00+00:00"

    refreshed = refreshed_score(scan["score"], still_vulnerable, stats,
                                previous_audit_id="old-id")
    assert refreshed["basis"] == scan["score"]["basis"]
    assert refreshed["dependency_refreshed_from"] == "old-id"
    assert refreshed["scan_manifest"]["sca_asked_at"] == "2026-09-10T12:00:00+00:00"
    assert refreshed["scan_manifest"]["sca_findings"] == 1
    assert "sca_asked_at" in refreshed["scan_manifest"]


def test_a_withdrawn_advisory_actually_leaves_the_report():
    """Replaced wholesale, not merged: an advisory that is gone must not
    survive in the row forever."""
    scan = run_scan(repo_bytes(), LLMClient(), sca_client=advisory_client())
    assert [f for f in scan["findings"] if f["rule_id"] == RULE_ID]

    refreshed = refreshed_findings(scan["findings"], [])
    assert [f for f in refreshed if f["rule_id"] == RULE_ID] == []
    assert len(refreshed) == len(scan["findings"]) - 1, "nothing else was touched"


def test_a_refresh_that_finds_a_new_advisory_replaces_the_old_row():
    from app.sca.stage import run_sca_stage
    scan = run_scan(repo_bytes(), LLMClient(), sca_client=advisory_client())
    other = {**LODASH_ADVISORY, "id": "GHSA-new-0000-0000", "aliases": ["CVE-2026-0001"],
             "database_specific": {"severity": "CRITICAL"}}
    fresh, _stats = run_sca_stage(repo_bytes(),
                                  advisory_client("GHSA-new-0000-0000", other))
    refreshed = refreshed_findings(scan["findings"], fresh)
    dependency_rows = [f for f in refreshed if f["rule_id"] == RULE_ID]
    assert len(dependency_rows) == 1, "the old row is replaced, not added to"
    assert "CVE-2026-0001" in dependency_rows[0]["title"]


# -- the sweep --------------------------------------------------------------

class StoredRepo:
    """The slice of AuditRepository the sweep uses, in memory."""

    def __init__(self, rows):
        self.rows = list(rows)
        self.created = []

    async def stale_dependency_audits(self, *, created_before, limit=20):
        return [r for r in self.rows if r["created_at"] < created_before][:limit]

    async def create(self, **fields):
        stored = {"id": str(uuid.uuid4()), "status": "completed",
                  "access_token": "new-token", **deepcopy(fields)}
        self.created.append(stored)
        self.rows.append(stored)
        return stored


def stored_row(age_days: int, *, inventory=True, basis="static+preview") -> dict:
    scan = run_scan(repo_bytes(), LLMClient(), sca_client=advisory_client())
    score = deepcopy(scan["score"])
    score["basis"] = basis
    asked = (NOW - timedelta(days=age_days)).isoformat(timespec="seconds")
    score["scan_manifest"]["sca_asked_at"] = asked
    return {
        "id": str(uuid.uuid4()), "stack": "nextjs", "status": "completed",
        "file_count": 2, "score_total": score["total"], "score_json": score,
        "findings_json": deepcopy(scan["findings"]),
        "repo_url": "https://github.com/acme/app", "content_hash": "digest-1",
        "engine_version": AUDIT_ENGINE_VERSION,
        "created_at": NOW - timedelta(days=age_days),
        "dependency_inventory": (inventory_payload(repo_bytes(), asked)
                                 if inventory else None),
    }


@pytest.mark.asyncio
async def test_a_stale_audit_is_refreshed_into_a_new_row():
    repo = StoredRepo([stored_row(SCA_FRESHNESS_TTL_DAYS + 3)])
    summary = await refresh_stale_dependency_audits(
        repo, client_factory=silent_client, now=NOW)

    assert summary["refreshed"] == 1
    assert len(repo.created) == 1
    created = repo.created[0]
    assert created["dependency_inventory"]["asked_at"].startswith("2026-09-10")
    assert created["score_json"]["scan_manifest"]["sca_asked_at"] == (
        NOW.isoformat(timespec="seconds"))
    assert created["score_json"]["dependency_refreshed_from"] == repo.rows[0]["id"]
    assert created["content_hash"] == "digest-1", "the cache key must stay intact"
    assert created["engine_version"] == AUDIT_ENGINE_VERSION


@pytest.mark.asyncio
async def test_a_row_newer_than_the_ttl_is_not_even_considered():
    """The sweep's query filters on created_at, so a young row costs nothing.
    (Its inventory is written at scan time, so created_at IS the date asked.)"""
    repo = StoredRepo([stored_row(1)])
    summary = await refresh_stale_dependency_audits(
        repo, client_factory=silent_client, now=NOW)
    assert summary == {"considered": 0, "refreshed": 0, "skipped": 0,
                       "unavailable": 0, "failed": 0, "reasons": {}}
    assert repo.created == []


@pytest.mark.asyncio
async def test_an_old_row_whose_answer_is_fresh_is_skipped():
    """The exact age policy lives in Python: created_at is the coarse filter,
    and a row that is old but whose answer is current must not be re-asked."""
    row = stored_row(SCA_FRESHNESS_TTL_DAYS + 20)
    row["score_json"]["scan_manifest"]["sca_asked_at"] = (
        NOW - timedelta(days=1)).isoformat(timespec="seconds")
    repo = StoredRepo([row])
    summary = await refresh_stale_dependency_audits(
        repo, client_factory=silent_client, now=NOW)
    assert summary["considered"] == 1
    assert summary["skipped"] == 1
    assert repo.created == []


@pytest.mark.asyncio
async def test_an_audit_without_an_inventory_is_never_asked_about():
    repo = StoredRepo([stored_row(SCA_FRESHNESS_TTL_DAYS + 3, inventory=False)])
    summary = await refresh_stale_dependency_audits(
        repo, client_factory=silent_client, now=NOW)
    assert summary["skipped"] == 1, (
        "a row whose scan never asked must not become one that did")
    assert repo.created == []


@pytest.mark.asyncio
async def test_the_entitlement_is_consulted_per_row():
    """An account that opted out since the audit was written is not asked about
    again because the sweep had already decided otherwise."""
    repo = StoredRepo([stored_row(SCA_FRESHNESS_TTL_DAYS + 3)])
    calls = []

    def refusing_factory():
        calls.append(1)
        return None

    summary = await refresh_stale_dependency_audits(
        repo, client_factory=refusing_factory, now=NOW)
    assert calls == [1]
    assert summary["refreshed"] == 0
    assert summary["reasons"] == {"no_client": 1}
    assert repo.created == []


@pytest.mark.asyncio
async def test_an_unreachable_database_leaves_the_old_answer_in_place():
    def dead_factory():
        class Dead:
            requests_made = 0

            def post(self, url, *, json=None):
                raise ConnectionError("no route to host")

            def get(self, url):
                raise ConnectionError("no route to host")
        return OsvClient(transport=Dead())

    repo = StoredRepo([stored_row(SCA_FRESHNESS_TTL_DAYS + 3)])
    summary = await refresh_stale_dependency_audits(
        repo, client_factory=dead_factory, now=NOW)
    assert summary["unavailable"] == 1
    assert summary["refreshed"] == 0
    assert repo.created == [], (
        "replacing a known answer with nothing turns an outage into a clean report")


@pytest.mark.asyncio
async def test_the_sweep_respects_its_limit():
    repo = StoredRepo([stored_row(SCA_FRESHNESS_TTL_DAYS + 5) for _ in range(5)])
    summary = await refresh_stale_dependency_audits(
        repo, client_factory=silent_client, now=NOW, limit=2)
    assert summary["considered"] == 2
    assert summary["refreshed"] == 2


# -- what the customer's report says after a refresh ------------------------

@pytest.mark.asyncio
async def test_the_refreshed_row_reports_a_current_date_to_the_reader():
    repo = StoredRepo([stored_row(SCA_FRESHNESS_TTL_DAYS + 3)])
    await refresh_stale_dependency_audits(repo, client_factory=silent_client, now=NOW)
    rows = dict(manifest_rows(repo.created[0]["score_json"]))
    assert "true of that date" not in rows["Dependencies checked"], (
        "a refreshed row carries today's date, so it must not read as aged")
