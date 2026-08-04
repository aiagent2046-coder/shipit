"""API-level tests for the persistence wiring in main.py: GET
/v1/audits/{id}, GET /v1/fixpacks/{id}, and the create endpoints
persisting through AuditRepository / FixpackJobRepository.

Uses fake in-memory repos via dependency_overrides (same pattern as
FakePreviewRegistry in test_fixpack_api.py) -- no real Postgres
involved here. See tests/test_db.py for the repository layer itself,
and scripts/verify_db_locally.py for real-Postgres proof.

Since the queue cutover the audits row is written by the worker, not by
POST /v1/audits, so the audit half of this file is POST -> drain_audit_queue
-> assert. What is being tested is unchanged -- that the row lands with the
right stack/repo_url and that its access_token gates reads -- only the
process that writes it moved. Fixpacks are still synchronous and untouched.
"""

import io
import json
import uuid
import zipfile

from fastapi.testclient import TestClient

from app.deploypack.delivery import PullRequestResult
from app.llm.client import LLMClient
from app.main import (
    app,
    get_audit_job_repo,
    get_audit_repo,
    get_fixpack_repo,
    get_pr_opener,
    get_repo_fetcher,
)
import app.deploypack.pipeline as pipeline_mod
import app.worker.main as worker_mod
from app.deploypack.sandbox import SandboxResult
from tests.conftest import FakeAuditQueue, drain_audit_queue

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

    async def get_by_content_hash(self, content_hash, engine_version, basis):
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


async def _post_and_run(audit_queue, audit_repo, **post_kwargs) -> tuple:
    """POST an audit, then run the queued job through the real worker.

    Returns (response, audit_id). The two halves are inseparable for these
    tests: the endpoint decides what gets queued, the worker decides what gets
    persisted, and every assertion below is about the persisted row."""
    app.dependency_overrides[get_audit_repo] = lambda: audit_repo
    try:
        resp = client.post("/v1/audits", **post_kwargs)
        audit_ids = await drain_audit_queue(
            audit_queue, audit_repo=audit_repo, llm_client=LLMClient(providers=[]),
        )
    finally:
        app.dependency_overrides.pop(get_audit_repo, None)
    return resp, (audit_ids[0] if audit_ids else None)


async def test_create_audit_queues_a_job_the_worker_persists(audit_queue):
    fake = FakeAuditRepo()
    resp, audit_id = await _post_and_run(
        audit_queue, fake,
        files={"archive": ("app.zip", make_zip(FASTAPI_ZIP), "application/zip")},
    )

    assert resp.status_code == 202
    # The 202 hands back a job to poll, not a result: the row does not exist
    # yet at the moment the response is written.
    assert set(resp.json()) == {"job_id", "access_token", "state"}
    assert audit_id in fake.rows
    assert fake.create_calls[0]["stack"] == "fastapi"


async def test_create_audit_from_upload_stores_null_repo_url(audit_queue):
    fake = FakeAuditRepo()
    await _post_and_run(
        audit_queue, fake,
        files={"archive": ("app.zip", make_zip(FASTAPI_ZIP), "application/zip")},
    )
    assert fake.create_calls[0]["repo_url"] is None


async def test_create_audit_from_github_url_persists_repo_url(audit_queue,
                                                              monkeypatch):
    fake = FakeAuditRepo()

    def fake_fetch(owner, repo, **kwargs):
        return make_zip(FASTAPI_ZIP).getvalue()

    # Two fetches, two stubs: intake validates and detects the stack from its
    # own download (get_repo_fetcher), and the worker re-fetches when it runs
    # the job (app.worker.main.fetch_repo_zip, called directly, not injected).
    app.dependency_overrides[get_repo_fetcher] = lambda: fake_fetch
    monkeypatch.setattr(worker_mod, "fetch_repo_zip", fake_fetch)
    try:
        resp, _ = await _post_and_run(
            audit_queue, fake, data={"repo_url": "https://github.com/acme/app"},
        )
    finally:
        app.dependency_overrides.pop(get_repo_fetcher, None)

    assert resp.status_code == 202
    assert fake.create_calls[0]["repo_url"] == "https://github.com/acme/app"


def test_create_audit_without_a_queue_is_503():
    # Behaviour change from the cutover. This used to answer 200 with
    # persisted=false: the scan ran inline and the result was simply never
    # stored. With no inline scan left there is nothing to return, so a
    # deployment without DATABASE_URL now refuses the submission outright
    # rather than pretending to have done the work.
    app.dependency_overrides[get_audit_job_repo] = lambda: FakeAuditQueue(
        unavailable=True)
    try:
        resp = client.post(
            "/v1/audits",
            files={"archive": ("app.zip", make_zip(FASTAPI_ZIP), "application/zip")},
        )
    finally:
        app.dependency_overrides.pop(get_audit_job_repo, None)

    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "queue_unavailable"


async def test_get_audit_after_create_round_trips(audit_queue):
    fake = FakeAuditRepo()
    _resp, audit_id = await _post_and_run(
        audit_queue, fake,
        files={"archive": ("app.zip", make_zip(FASTAPI_ZIP), "application/zip")},
    )
    # The audits row still mints its own access_token, distinct from the job's;
    # GET /v1/audit-jobs/{id} is what hands it to the submitter once the job
    # succeeds (tests/test_audit_jobs_api.py).
    token = fake.rows[audit_id]["access_token"]

    app.dependency_overrides[get_audit_repo] = lambda: fake
    try:
        get_resp = client.get(f"/v1/audits/{audit_id}?token={token}")
    finally:
        app.dependency_overrides.pop(get_audit_repo, None)

    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == audit_id
    # The ownership token is never echoed back in the audit body.
    assert "access_token" not in get_resp.json()


async def test_get_audit_without_token_is_404(audit_queue):
    fake = FakeAuditRepo()
    _resp, audit_id = await _post_and_run(
        audit_queue, fake,
        files={"archive": ("app.zip", make_zip(FASTAPI_ZIP), "application/zip")},
    )

    app.dependency_overrides[get_audit_repo] = lambda: fake
    try:
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
