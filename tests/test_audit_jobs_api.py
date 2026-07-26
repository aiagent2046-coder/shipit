"""GET /v1/audit-jobs/{job_id}: the poll endpoint's ownership gate and shape.

The queue itself is covered against real Postgres in tests/test_audit_jobs_repo.py.
What matters here is the boundary: that the endpoint asks get_authorized the
question the caller asked, answers a flat 404 to everything that does not match,
and never lets access_token out.
"""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from app.main import app, get_audit_job_repo

client = TestClient(app)


class FakeAuditJobRepo:
    """get_authorized with the real contract: the token is the only key, and
    anything that does not match is None."""

    def __init__(self, row=None):
        self._row = row
        self.calls: list[tuple[str, str | None]] = []

    async def get_authorized(self, *, job_id, access_token):
        self.calls.append((job_id, access_token))
        if self._row is None:
            return None
        if not access_token or access_token != self._row["access_token"]:
            return None
        if job_id != self._row["id"]:
            return None
        # The real method never selects access_token; mirror that here so the
        # test cannot pass by accident on a repo that leaks it.
        return {k: v for k, v in self._row.items() if k != "access_token"}


def _row(**overrides):
    row = {
        "id": str(uuid.uuid4()),
        "access_token": "fake-token-not-a-real-secret",
        "state": "queued",
        "source_kind": "repo_url",
        "source_ref": "https://github.com/acme/app",
        "error_code": None,
        "error_message": None,
        "audit_id": None,
        "attempts": 0,
        "max_attempts": 3,
        "claimed_by": None,
        "lease_expires_at": None,
        "created_at": "2026-07-01T10:00:00+00:00",
        "completed_at": None,
    }
    row.update(overrides)
    return row


def _with_repo(repo):
    app.dependency_overrides[get_audit_job_repo] = lambda: repo


def _clear():
    app.dependency_overrides.pop(get_audit_job_repo, None)


def test_the_right_token_returns_the_job():
    row = _row()
    _with_repo(FakeAuditJobRepo(row))
    try:
        resp = client.get(
            f"/v1/audit-jobs/{row['id']}",
            params={"token": row["access_token"]},
        )
    finally:
        _clear()

    assert resp.status_code == 200
    assert resp.json() == {
        "id": row["id"],
        "state": "queued",
        "error_code": None,
        "audit_id": None,
        "created_at": row["created_at"],
        "completed_at": None,
    }


def test_a_succeeded_job_points_at_its_audit():
    # The whole reason a client polls: audit_id is the handle for
    # GET /v1/audits/{id}, and it is null until exactly this moment.
    audit_id = str(uuid.uuid4())
    row = _row(state="succeeded", audit_id=audit_id,
               completed_at="2026-07-01T10:04:00+00:00")
    _with_repo(FakeAuditJobRepo(row))
    try:
        resp = client.get(f"/v1/audit-jobs/{row['id']}",
                          params={"token": row["access_token"]})
    finally:
        _clear()

    body = resp.json()
    assert body["state"] == "succeeded"
    assert body["audit_id"] == audit_id
    assert body["completed_at"] == "2026-07-01T10:04:00+00:00"


def test_a_dead_lettered_job_reports_its_error_code():
    row = _row(state="dead_letter", error_code="zip_bomb",
               error_message="1000x compression ratio",
               completed_at="2026-07-01T10:01:00+00:00")
    _with_repo(FakeAuditJobRepo(row))
    try:
        resp = client.get(f"/v1/audit-jobs/{row['id']}",
                          params={"token": row["access_token"]})
    finally:
        _clear()

    body = resp.json()
    assert body["error_code"] == "zip_bomb"
    assert body["audit_id"] is None


def test_the_response_carries_no_internals_and_no_token():
    # error_message is free text written by a worker, and claimed_by /
    # lease_expires_at / attempts are queue mechanics; none of it is a caller's
    # business, and access_token leaking would hand ownership to a log reader.
    row = _row(state="running", claimed_by="host/123/0", attempts=2,
               error_message="internal detail")
    _with_repo(FakeAuditJobRepo(row))
    try:
        body = client.get(f"/v1/audit-jobs/{row['id']}",
                          params={"token": row["access_token"]}).json()
    finally:
        _clear()

    assert set(body) == {
        "id", "state", "error_code", "audit_id", "created_at", "completed_at"}


def test_a_wrong_token_is_a_flat_404():
    row = _row()
    _with_repo(FakeAuditJobRepo(row))
    try:
        resp = client.get(f"/v1/audit-jobs/{row['id']}",
                          params={"token": "wrong-token"})
    finally:
        _clear()

    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "not_found"


def test_no_token_at_all_is_a_404_not_a_422():
    # The endpoint must not distinguish "you forgot the token" from "that job
    # is not yours" -- both answers confirm the id exists.
    row = _row()
    _with_repo(FakeAuditJobRepo(row))
    try:
        resp = client.get(f"/v1/audit-jobs/{row['id']}")
    finally:
        _clear()

    assert resp.status_code == 404


def test_an_unknown_id_is_the_same_404_as_a_wrong_token():
    # Byte-identical bodies: a caller probing for valid ids learns nothing.
    row = _row()
    _with_repo(FakeAuditJobRepo(row))
    try:
        wrong_token = client.get(f"/v1/audit-jobs/{row['id']}",
                                 params={"token": "nope"})
        unknown_id = client.get(f"/v1/audit-jobs/{uuid.uuid4()}",
                                params={"token": row["access_token"]})
    finally:
        _clear()

    assert wrong_token.status_code == unknown_id.status_code == 404
    assert wrong_token.json() == unknown_id.json()


def test_a_malformed_id_is_a_404_rather_than_a_crash():
    # job_id is a path string, so a non-uuid reaches the repository, which
    # answers None for it.
    _with_repo(FakeAuditJobRepo(None))
    try:
        resp = client.get("/v1/audit-jobs/not-a-uuid", params={"token": "x"})
    finally:
        _clear()

    assert resp.status_code == 404


def test_an_unconfigured_database_is_a_404_not_a_500():
    # The house not-configured contract: the repository answers None when
    # DATABASE_URL is unset, and the endpoint must degrade to 404.
    _with_repo(FakeAuditJobRepo(None))
    try:
        resp = client.get(f"/v1/audit-jobs/{uuid.uuid4()}",
                          params={"token": "any"})
    finally:
        _clear()

    assert resp.status_code == 404
