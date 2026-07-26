"""The queue side of POST /v1/audits, after the Stage 2 cutover.

tests/test_ingest_api.py owns intake *validation* (what is accepted and with
what reason it is refused). This file owns what happens to a submission that
gets past it: which job row is written, when the archive reaches the spool,
what a repeat submission does, and how a staging failure ends. Plus the two
operational reads that exist because the work now happens out of band --
/readyz and /internal/audit-jobs/stats.

Everything here uses FakeAuditQueue (tests/conftest.py), which models the two
behaviours the endpoint's correctness rests on: the live-state partial unique
index on idempotency_key, and the 'created' -> 'queued' transition. The SQL
those model is covered against real Postgres in tests/test_audit_jobs_repo.py.
"""

from __future__ import annotations

import io
import json
import uuid
import zipfile

import pytest
from fastapi.testclient import TestClient

import app.audit_spool as spool_mod
import app.ops_endpoints as ops_mod
from app.audit_spool import SpoolFull
from app.main import app, get_audit_job_repo, get_audit_repo, get_repo_fetcher

client = TestClient(app)

NEXT_PKG = json.dumps({"dependencies": {"next": "15.0.0", "react": "19.0.0"}}).encode()


def make_zip(entries: dict[str, bytes]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    buf.seek(0)
    return buf


def _post_zip(entries=None, **kwargs):
    buf = make_zip(entries or {"package.json": NEXT_PKG})
    return client.post(
        "/v1/audits",
        files={"archive": ("app.zip", buf, "application/zip")},
        **kwargs,
    )


# --- staging: the payload has to outlive the request ---

def test_zip_job_is_queued_only_after_its_archive_is_on_disk(audit_queue,
                                                             audit_spool_dir):
    resp = _post_zip()
    assert resp.status_code == 202
    job = audit_queue.only

    # The insert went in as 'created' and only became claimable once the bytes
    # were written -- the ordering migration 0022 exists for. A worker that
    # claimed the row in between would find source_ref empty.
    assert audit_queue.enqueued[0]["initial_state"] == "created"
    assert audit_queue.enqueued[0]["source_ref"] is None
    assert job["state"] == "queued"
    assert job["source_ref"] == str(audit_spool_dir / f"{job['id']}.zip")


def test_repo_url_job_never_touches_the_spool(audit_queue, audit_spool_dir):
    app.dependency_overrides[get_repo_fetcher] = lambda: (
        lambda owner, repo, **kw: make_zip({"package.json": NEXT_PKG}).getvalue()
    )
    try:
        resp = client.post(
            "/v1/audits", data={"repo_url": "https://github.com/acme/app"})
    finally:
        app.dependency_overrides.pop(get_repo_fetcher, None)

    assert resp.status_code == 202
    # Its entire payload is the URL, which is already in the row, so it is
    # claimable the moment it is inserted -- no 'created' hop, no file.
    assert audit_queue.enqueued[0]["initial_state"] == "queued"
    assert list(audit_spool_dir.glob("*.zip")) == []


def test_spool_full_dead_letters_the_created_row_and_503s(audit_queue,
                                                          monkeypatch):
    def boom(job_id, raw):
        raise SpoolFull("spool is at capacity")

    monkeypatch.setattr("app.main.stage_archive", boom)

    resp = _post_zip()
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "spool_full"
    # Left in 'created' the row would be unclaimable AND would still hold this
    # submission's idempotency key, so the caller's retry would be turned away
    # too. It is marked terminal instead, which frees the key.
    assert audit_queue.abandoned == [
        {"job_id": audit_queue.only["id"], "error_code": "spool_full"}]
    assert audit_queue.only["state"] == "dead_letter"


def test_staging_oserror_dead_letters_the_created_row_and_503s(audit_queue,
                                                               monkeypatch):
    def boom(job_id, raw):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("app.main.stage_archive", boom)

    resp = _post_zip()
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "staging_failed"
    assert audit_queue.abandoned[0]["error_code"] == "staging_failed"


def test_retry_after_a_staging_failure_is_accepted(audit_queue, monkeypatch):
    """The point of dead-lettering rather than abandoning: the second attempt
    at the same bytes must not collide with the first one's freed key."""
    calls = {"n": 0}
    real_stage = spool_mod.stage_archive

    def flaky(job_id, raw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError(28, "No space left on device")
        return real_stage(job_id, raw)

    monkeypatch.setattr("app.main.stage_archive", flaky)

    assert _post_zip().status_code == 503
    assert _post_zip().status_code == 202


# --- idempotency: a repeat submission joins the job already running ---

def test_double_submission_of_identical_content_joins_the_same_job(audit_queue):
    first = _post_zip()
    second = _post_zip()

    assert first.status_code == 202 and second.status_code == 202
    # A double-clicked upload must not queue the same scan twice.
    assert second.json()["job_id"] == first.json()["job_id"]
    assert len(audit_queue.rows) == 1
    # ...and the collision must not rewrite the payload underneath a worker
    # that may already be reading it.
    assert len(audit_queue.enqueued) == 2


def test_different_content_gets_its_own_job(audit_queue):
    first = _post_zip({"package.json": NEXT_PKG, "a.ts": b"const x=1\n"})
    second = _post_zip({"package.json": NEXT_PKG, "a.ts": b"const x=2\n"})

    assert first.json()["job_id"] != second.json()["job_id"]
    assert len(audit_queue.rows) == 2


def test_explicit_idempotency_key_header_overrides_the_derived_one(audit_queue):
    # Two DIFFERENT payloads under one client-chosen key: the second joins the
    # first, which the content-derived default would never have done. That is
    # the header doing the work, not the digest.
    first = _post_zip({"package.json": NEXT_PKG, "a.ts": b"const x=1\n"},
                      headers={"Idempotency-Key": "client-chosen-key-1"})
    second = _post_zip({"package.json": NEXT_PKG, "a.ts": b"const x=2\n"},
                       headers={"Idempotency-Key": "client-chosen-key-1"})

    assert second.json()["job_id"] == first.json()["job_id"]
    assert len(audit_queue.rows) == 1
    assert audit_queue.enqueued[0]["idempotency_key"] == "client-chosen-key-1"


def test_derived_idempotency_key_is_scoped_to_content_and_engine(audit_queue):
    from app.main import _audit_idempotency_key

    a = _audit_idempotency_key("digest-a", None)
    assert a != _audit_idempotency_key("digest-b", None)
    # Two callers submitting the same bytes stay independent: separate quotas,
    # and one job going terminal must not decide the other's outcome.
    assert a != _audit_idempotency_key("digest-a", "acct-1")


# --- the cache hit short-circuits the queue entirely ---

class CachedAuditRepo:
    """AuditRepository whose content-hash lookup always hits."""

    def __init__(self, row):
        self.row = row

    async def get_by_content_hash(self, content_hash, engine_version):
        return self.row

    async def create(self, **fields):  # pragma: no cover - must never be called
        raise AssertionError("a cache hit must not persist a new audit")


def test_cache_hit_answers_inline_and_queues_nothing(audit_queue,
                                                     audit_spool_dir):
    cached = {
        "id": str(uuid.uuid4()), "access_token": "fake-audit-token-not-a-secret",
        "stack": "nextjs", "file_count": 1, "score_json": {"total": 9.0},
        "findings_json": [], "repo_url": None,
    }
    app.dependency_overrides[get_audit_repo] = lambda: CachedAuditRepo(cached)
    try:
        resp = _post_zip()
    finally:
        app.dependency_overrides.pop(get_audit_repo, None)

    assert resp.status_code == 202
    body = resp.json()
    assert body["reused"] is True
    assert body["audit_id"] == cached["id"]
    # The check sits before the enqueue, so a repeat costs neither a worker
    # slot nor a spool file -- and the caller gets the result without polling.
    assert audit_queue.rows == {}
    assert list(audit_spool_dir.glob("*.zip")) == []


# --- operational reads ---

class FakeBacklogRepo:
    def __init__(self, stats):
        self._stats = stats

    async def backlog_stats(self):
        return self._stats


async def test_readyz_reports_the_audit_backlog(monkeypatch):
    monkeypatch.setattr(ops_mod, "_fixpack_repo", FakeBacklogRepo(
        {"backlog": 0, "oldest_paid_seconds": None}))
    monkeypatch.setattr(ops_mod, "_audit_job_repo", FakeBacklogRepo(
        {"states": {"queued": 7}, "queued": 7, "oldest_queued_seconds": 412.5}))

    resp = client.get("/readyz")
    body = resp.json()

    # A backlog is the worker being behind, not this API process being unfit to
    # serve -- it is reported, and readiness stays green.
    assert resp.status_code == 200 and body["status"] == "ready"
    assert body["audit_backlog"] == 7
    assert body["oldest_audit_queued_seconds"] == 412.5


async def test_readyz_survives_an_audit_backlog_query_that_fails(monkeypatch):
    class Exploding:
        async def backlog_stats(self):
            raise RuntimeError("connection reset")

    monkeypatch.setattr(ops_mod, "_fixpack_repo", FakeBacklogRepo(
        {"backlog": 0, "oldest_paid_seconds": None}))
    monkeypatch.setattr(ops_mod, "_audit_job_repo", Exploding())

    resp = client.get("/readyz")
    # The audit numbers are supplementary: losing them must not take the
    # process out of service, but they must not be reported as zero either.
    assert resp.status_code == 200
    assert resp.json()["audit_backlog"] is None


STATS_TOKEN = "fake-stats-token-not-a-real-secret"


@pytest.fixture
def stats_token(monkeypatch):
    monkeypatch.setenv("AUDIT_JOBS_STATS_TOKEN", STATS_TOKEN)
    return {"Authorization": f"Bearer {STATS_TOKEN}"}


def test_audit_jobs_stats_requires_the_operator_token(stats_token):
    assert client.get("/internal/audit-jobs/stats").status_code == 401
    bad = client.get("/internal/audit-jobs/stats",
                     headers={"Authorization": "Bearer wrong"})
    assert bad.status_code == 401


def test_audit_jobs_stats_503s_when_the_token_is_not_configured(monkeypatch):
    monkeypatch.delenv("AUDIT_JOBS_STATS_TOKEN", raising=False)
    resp = client.get("/internal/audit-jobs/stats",
                      headers={"Authorization": f"Bearer {STATS_TOKEN}"})
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "audit_jobs_stats_not_configured"


def test_audit_jobs_stats_returns_the_state_histogram(stats_token):
    stats = {"states": {"queued": 3, "running": 1, "dead_letter": 2},
             "queued": 3, "oldest_queued_seconds": 12.0}
    app.dependency_overrides[get_audit_job_repo] = lambda: FakeBacklogRepo(stats)
    try:
        resp = client.get("/internal/audit-jobs/stats", headers=stats_token)
    finally:
        app.dependency_overrides.pop(get_audit_job_repo, None)

    assert resp.status_code == 200
    body = resp.json()
    assert body["states"] == stats["states"]
    assert body["queued"] == 3
    assert body["oldest_queued_seconds"] == 12.0
    # Surfaced at the top level because it is the number an operator watches:
    # the worker alerts on each new dead_letter, this confirms a pattern.
    assert body["dead_letter"] == 2


def test_audit_jobs_stats_503s_without_a_database(stats_token):
    app.dependency_overrides[get_audit_job_repo] = lambda: FakeBacklogRepo(None)
    try:
        resp = client.get("/internal/audit-jobs/stats", headers=stats_token)
    finally:
        app.dependency_overrides.pop(get_audit_job_repo, None)

    # Zeros from a queue you cannot see would read as "healthy and empty".
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "not_configured"
    # The queue_unavailable counterpart on the write side lives in
    # tests/test_persistence_wiring.py, where the old inline contract was.
