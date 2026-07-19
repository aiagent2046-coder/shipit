"""API-level tests for the persistence wiring in main.py: GET
/v1/audits/{id}, GET /v1/fixpacks/{id}, and the create endpoints
persisting through AuditRepository / FixpackJobRepository.

Uses fake in-memory repos via dependency_overrides (same pattern as
FakePreviewRegistry in test_fixpack_api.py) -- no real Postgres
involved here. See tests/test_db.py for the repository layer itself,
and scripts/verify_db_locally.py for real-Postgres proof.
"""

import io
import json
import uuid
import zipfile

from fastapi.testclient import TestClient

from app.deploypack.delivery import PullRequestResult
from app.main import (
    app,
    get_audit_repo,
    get_fixpack_repo,
    get_pr_opener,
    get_repo_fetcher,
)
import app.deploypack.pipeline as pipeline_mod
from app.deploypack.sandbox import SandboxResult

client = TestClient(app)

FASTAPI_ZIP = {
    "requirements.txt": b"fastapi\nuvicorn\n",
    "app/main.py": b"from fastapi import FastAPI\napp = FastAPI()\n",
}


def make_zip(entries: dict[str, bytes]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    buf.seek(0)
    return buf


class FakeAuditRepo:
    def __init__(self):
        self.rows: dict[str, dict] = {}
        self.create_calls = []

    async def create(self, **fields):
        self.create_calls.append(fields)
        row_id = str(uuid.uuid4())
        # Mint a per-row token like the real DB default (migration 0010).
        row = {"id": row_id, "status": "completed",
               "access_token": f"tok-{row_id}", **fields}
        self.rows[row_id] = row
        return row

    async def get(self, audit_id):
        return self.rows.get(audit_id)

    async def get_authorized(self, audit_id, access_token):
        # Mirrors AuditRepository.get_authorized: only returns the row when the
        # token matches; unknown id or missing/wrong token -> None (-> 404).
        # Like the real SQL, the returned row does NOT carry access_token
        # (it's matched in the query, never selected), so it can't leak out.
        row = self.rows.get(audit_id)
        if row is None or not access_token:
            return None
        if access_token != row.get("access_token"):
            return None
        return {k: v for k, v in row.items() if k != "access_token"}

    async def get_by_content_hash(self, content_hash):
        return None


class FakeFixpackRepo:
    def __init__(self):
        self.rows: dict[str, dict] = {}
        self.create_calls = []
        self.delivered = {}

    async def create(self, **fields):
        self.create_calls.append(fields)
        row_id = str(uuid.uuid4())
        # Mint a per-row token like the real DB default (migration 0012).
        row = {"id": row_id, "pr_url": None, "pr_delivered": False,
               "access_token": f"tok-{row_id}", **fields}
        self.rows[row_id] = row
        return row

    async def get(self, job_id):
        return self.rows.get(job_id)

    async def get_authorized(self, job_id, access_token):
        # Mirrors FixpackJobRepository.get_authorized: only returns the row when
        # the token matches; unknown id or missing/wrong token -> None (-> 404).
        # Like the real SQL, the returned row does NOT carry access_token
        # (it's matched in the query, never selected), so it can't leak out.
        row = self.rows.get(job_id)
        if row is None or not access_token:
            return None
        if access_token != row.get("access_token"):
            return None
        return {k: v for k, v in row.items() if k != "access_token"}

    async def mark_delivered(self, job_id, pr_url):
        self.delivered[job_id] = pr_url
        if job_id in self.rows:
            self.rows[job_id]["pr_url"] = pr_url
            self.rows[job_id]["pr_delivered"] = True


def test_get_audit_404_when_not_found():
    resp = client.get(f"/v1/audits/{uuid.uuid4()}?token=whatever")
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "not_found"


def test_get_fixpack_404_when_not_found():
    resp = client.get(f"/v1/fixpacks/{uuid.uuid4()}")
    assert resp.status_code == 404


def test_create_audit_persists_and_returns_persisted_true():
    fake = FakeAuditRepo()
    app.dependency_overrides[get_audit_repo] = lambda: fake
    try:
        resp = client.post(
            "/v1/audits",
            files={"archive": ("app.zip", make_zip(FASTAPI_ZIP), "application/zip")},
        )
    finally:
        app.dependency_overrides.pop(get_audit_repo, None)

    assert resp.status_code == 202
    body = resp.json()
    assert body["persisted"] is True
    assert body["audit_id"] in fake.rows
    assert fake.create_calls[0]["stack"] == "fastapi"


def test_create_audit_from_upload_stores_null_repo_url():
    fake = FakeAuditRepo()
    app.dependency_overrides[get_audit_repo] = lambda: fake
    try:
        client.post(
            "/v1/audits",
            files={"archive": ("app.zip", make_zip(FASTAPI_ZIP), "application/zip")},
        )
    finally:
        app.dependency_overrides.pop(get_audit_repo, None)

    assert fake.create_calls[0]["repo_url"] is None


def test_create_audit_from_github_url_persists_repo_url():
    fake = FakeAuditRepo()

    def fake_fetch(owner, repo, **kwargs):
        return make_zip(FASTAPI_ZIP).getvalue()

    app.dependency_overrides[get_audit_repo] = lambda: fake
    app.dependency_overrides[get_repo_fetcher] = lambda: fake_fetch
    try:
        resp = client.post(
            "/v1/audits", data={"repo_url": "https://github.com/acme/app"}
        )
    finally:
        app.dependency_overrides.pop(get_audit_repo, None)
        app.dependency_overrides.pop(get_repo_fetcher, None)

    assert resp.status_code == 202
    assert fake.create_calls[0]["repo_url"] == "https://github.com/acme/app"


def test_create_audit_without_database_still_works_unpersisted():
    # real, unmocked AuditRepository -- no DATABASE_URL in this test env
    resp = client.post(
        "/v1/audits",
        files={"archive": ("app.zip", make_zip(FASTAPI_ZIP), "application/zip")},
    )
    body = resp.json()
    assert body["persisted"] is False
    uuid.UUID(body["audit_id"])  # still a valid random id, just not stored


def test_create_audit_returns_access_token():
    fake = FakeAuditRepo()
    app.dependency_overrides[get_audit_repo] = lambda: fake
    try:
        resp = client.post(
            "/v1/audits",
            files={"archive": ("app.zip", make_zip(FASTAPI_ZIP), "application/zip")},
        )
    finally:
        app.dependency_overrides.pop(get_audit_repo, None)

    body = resp.json()
    audit_id = body["audit_id"]
    assert body["access_token"] == fake.rows[audit_id]["access_token"]


def test_get_audit_after_create_round_trips():
    fake = FakeAuditRepo()
    app.dependency_overrides[get_audit_repo] = lambda: fake
    try:
        create_resp = client.post(
            "/v1/audits",
            files={"archive": ("app.zip", make_zip(FASTAPI_ZIP), "application/zip")},
        )
        created = create_resp.json()
        audit_id = created["audit_id"]
        token = created["access_token"]
        get_resp = client.get(f"/v1/audits/{audit_id}?token={token}")
    finally:
        app.dependency_overrides.pop(get_audit_repo, None)

    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == audit_id
    # The ownership token is never echoed back in the audit body.
    assert "access_token" not in get_resp.json()


def test_get_audit_without_token_is_404():
    fake = FakeAuditRepo()
    app.dependency_overrides[get_audit_repo] = lambda: fake
    try:
        create_resp = client.post(
            "/v1/audits",
            files={"archive": ("app.zip", make_zip(FASTAPI_ZIP), "application/zip")},
        )
        audit_id = create_resp.json()["audit_id"]
        # A caller who knows only the id (leaked UUID) gets 404, not the report.
        no_token = client.get(f"/v1/audits/{audit_id}")
        wrong_token = client.get(f"/v1/audits/{audit_id}?token=not-the-token")
    finally:
        app.dependency_overrides.pop(get_audit_repo, None)

    assert no_token.status_code == 404
    assert wrong_token.status_code == 404


def test_fixpack_bad_audit_id_is_422():
    resp = client.post(
        "/v1/fixpacks",
        files={"archive": ("app.zip", make_zip(FASTAPI_ZIP), "application/zip")},
        data={"audit_id": "not-a-uuid"},
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "bad_audit_id"


def test_create_fixpack_persists_job_and_links_audit_id(monkeypatch):
    monkeypatch.setattr(
        pipeline_mod, "verify_deploy_pack",
        lambda *a, **k: SandboxResult(ok=True, detail="HTTP 200 on /"),
    )
    fake = FakeFixpackRepo()
    real_audit_id = str(uuid.uuid4())
    app.dependency_overrides[get_fixpack_repo] = lambda: fake
    try:
        resp = client.post(
            "/v1/fixpacks",
            files={"archive": ("app.zip", make_zip(FASTAPI_ZIP), "application/zip")},
            data={"audit_id": real_audit_id},
        )
    finally:
        app.dependency_overrides.pop(get_fixpack_repo, None)

    body = resp.json()
    assert body["persisted"] is True
    assert body["fixpack_id"] in fake.rows
    assert fake.create_calls[0]["audit_id"] == real_audit_id
    assert fake.create_calls[0]["verified"] is True


def test_create_fixpack_marks_delivered_after_real_pr_open(monkeypatch):
    monkeypatch.setattr(
        pipeline_mod, "verify_deploy_pack",
        lambda *a, **k: SandboxResult(ok=True, detail="HTTP 200 on /"),
    )
    fake_repo = FakeFixpackRepo()

    def fake_opener(owner, repo, files, **kwargs):
        return PullRequestResult(html_url="https://github.com/acme/app/pull/42",
                                  branch="shipit/deploy-pack-xyz")

    app.dependency_overrides[get_fixpack_repo] = lambda: fake_repo
    app.dependency_overrides[get_pr_opener] = lambda: fake_opener
    try:
        resp = client.post(
            "/v1/fixpacks",
            files={"archive": ("app.zip", make_zip(FASTAPI_ZIP), "application/zip")},
            data={"deliver_to": "acme/app"},
        )
    finally:
        app.dependency_overrides.pop(get_fixpack_repo, None)
        app.dependency_overrides.pop(get_pr_opener, None)

    body = resp.json()
    job_id = body["fixpack_id"]
    assert fake_repo.delivered[job_id] == "https://github.com/acme/app/pull/42"
    assert fake_repo.rows[job_id]["pr_delivered"] is True


def test_create_fixpack_returns_access_token(monkeypatch):
    monkeypatch.setattr(
        pipeline_mod, "verify_deploy_pack",
        lambda *a, **k: SandboxResult(ok=True, detail="HTTP 200 on /"),
    )
    fake = FakeFixpackRepo()
    app.dependency_overrides[get_fixpack_repo] = lambda: fake
    try:
        resp = client.post(
            "/v1/fixpacks",
            files={"archive": ("app.zip", make_zip(FASTAPI_ZIP), "application/zip")},
        )
    finally:
        app.dependency_overrides.pop(get_fixpack_repo, None)

    body = resp.json()
    job_id = body["fixpack_id"]
    assert body["access_token"] == fake.rows[job_id]["access_token"]


def test_get_fixpack_after_create_round_trips(monkeypatch):
    monkeypatch.setattr(
        pipeline_mod, "verify_deploy_pack",
        lambda *a, **k: SandboxResult(ok=True, detail="HTTP 200 on /"),
    )
    fake = FakeFixpackRepo()
    app.dependency_overrides[get_fixpack_repo] = lambda: fake
    try:
        create_resp = client.post(
            "/v1/fixpacks",
            files={"archive": ("app.zip", make_zip(FASTAPI_ZIP), "application/zip")},
        )
        created = create_resp.json()
        job_id = created["fixpack_id"]
        token = created["access_token"]
        get_resp = client.get(f"/v1/fixpacks/{job_id}?token={token}")
    finally:
        app.dependency_overrides.pop(get_fixpack_repo, None)

    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == job_id
    # The ownership token is never echoed back in the job body.
    assert "access_token" not in get_resp.json()


def test_get_fixpack_without_token_is_404(monkeypatch):
    monkeypatch.setattr(
        pipeline_mod, "verify_deploy_pack",
        lambda *a, **k: SandboxResult(ok=True, detail="HTTP 200 on /"),
    )
    fake = FakeFixpackRepo()
    app.dependency_overrides[get_fixpack_repo] = lambda: fake
    try:
        create_resp = client.post(
            "/v1/fixpacks",
            files={"archive": ("app.zip", make_zip(FASTAPI_ZIP), "application/zip")},
        )
        job_id = create_resp.json()["fixpack_id"]
        # A caller who knows only the id (leaked UUID) gets 404, not the job.
        no_token = client.get(f"/v1/fixpacks/{job_id}")
        wrong_token = client.get(f"/v1/fixpacks/{job_id}?token=not-the-token")
    finally:
        app.dependency_overrides.pop(get_fixpack_repo, None)

    assert no_token.status_code == 404
    assert wrong_token.status_code == 404
