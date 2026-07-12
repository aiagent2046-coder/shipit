"""API-level tests for POST /v1/fixpacks.

The "docker unavailable" path is forced deterministically by
monkeypatching `sandbox_mod.docker_available` — the suite must not
depend on whether the host happens to have a `docker` binary (it
didn't in the original dev sandbox, it does on the production VPS;
same isolation principle as the ambient DATABASE_URL fix in
conftest.py). One test monkeypatches the sandbox call to also prove
the API correctly reports verified=True when the sandbox succeeds.
"""

import io
import json
import zipfile

from fastapi.testclient import TestClient

import app.deploypack.pipeline as pipeline_mod
import app.deploypack.sandbox as sandbox_mod
import app.main as main_mod
from app.deploypack.delivery import DeliveryError, PullRequestResult
from app.deploypack.github_app import GitHubAppError
from app.deploypack.preview import PreviewResult
from app.deploypack.sandbox import SandboxResult
from app.main import app, get_pr_opener, get_preview_registry

client = TestClient(app)

FASTAPI_ZIP = {
    "requirements.txt": b"fastapi\nuvicorn\n",
    "app/main.py": b"from fastapi import FastAPI\napp = FastAPI()\n",
}

VITE_ZIP = {
    "package.json": json.dumps(
        {"dependencies": {"react": "18.0.0", "vite": "5.0.0"}}
    ).encode(),
    "vite.config.ts": b"export default {}\n",
    "src/App.tsx": b"export default function App() { return null }\n",
}

NEXTJS_ZIP = {
    "package.json": json.dumps({"dependencies": {"next": "15.0.0"}}).encode(),
}


def make_zip(entries: dict[str, bytes]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    buf.seek(0)
    return buf


def post_fixpack(
    entries: dict[str, bytes],
    deliver_to: str | None = None,
    want_preview: bool = False,
):
    data = {}
    if deliver_to:
        data["deliver_to"] = deliver_to
    if want_preview:
        data["want_preview"] = "true"
    return client.post(
        "/v1/fixpacks",
        files={"archive": ("app.zip", make_zip(entries), "application/zip")},
        data=data,
    )


class FakePreviewRegistry:
    """Stub for the DI override — no real docker involved, mirrors the
    get_pr_opener override pattern above."""

    def __init__(self, result: PreviewResult):
        self._result = result
        self.reap_calls = 0

    def start(self, *args, **kwargs):
        return self._result

    def reap_expired(self, *args, **kwargs):
        self.reap_calls += 1
        return 0


def test_fastapi_pack_generated_but_unverified_without_docker(monkeypatch):
    monkeypatch.setattr(sandbox_mod, "docker_available", lambda: False)
    resp = post_fixpack(FASTAPI_ZIP)
    assert resp.status_code == 202
    body = resp.json()
    assert body["stack"] == "fastapi"
    assert body["verified"] is None
    assert "docker binary not found" in body["detail"]
    assert "Dockerfile" in body["files"]
    assert "docker-compose.yml" in body["files"]


def test_vite_react_pack_generated_but_unverified_without_docker(monkeypatch):
    monkeypatch.setattr(sandbox_mod, "docker_available", lambda: False)
    resp = post_fixpack(VITE_ZIP)
    assert resp.status_code == 202
    body = resp.json()
    assert body["stack"] == "vite-react"
    assert body["verified"] is None
    assert "nginx.conf" in body["files"]


def test_nextjs_is_not_supported_for_deploy_pack_even_though_audit_supports_it():
    resp = post_fixpack(NEXTJS_ZIP)
    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "unsupported_stack"


def test_verified_true_when_sandbox_actually_succeeds(monkeypatch):
    monkeypatch.setattr(
        pipeline_mod, "verify_deploy_pack",
        lambda *a, **k: SandboxResult(ok=True, detail="HTTP 200 on /"),
    )
    resp = post_fixpack(FASTAPI_ZIP)
    assert resp.status_code == 202
    body = resp.json()
    assert body["verified"] is True
    assert body["detail"] == "HTTP 200 on /"
    assert body["pr"] is None  # no deliver_to was passed


def test_deliver_to_skipped_when_not_verified(monkeypatch):
    # forced no-docker path, so verified=None
    monkeypatch.setattr(sandbox_mod, "docker_available", lambda: False)
    resp = post_fixpack(FASTAPI_ZIP, deliver_to="acme/app")
    assert resp.status_code == 202
    body = resp.json()
    assert body["verified"] is None
    assert body["pr"] == {"delivered": False, "reason": "not verified, refusing to open a PR"}


def test_deliver_to_bad_format_when_verified(monkeypatch):
    monkeypatch.setattr(
        pipeline_mod, "verify_deploy_pack",
        lambda *a, **k: SandboxResult(ok=True, detail="HTTP 200 on /"),
    )
    resp = post_fixpack(FASTAPI_ZIP, deliver_to="not-a-repo-slug")
    body = resp.json()
    assert body["pr"]["delivered"] is False
    assert "owner/repo" in body["pr"]["reason"]


def test_deliver_to_opens_pr_when_verified(monkeypatch):
    monkeypatch.setattr(
        pipeline_mod, "verify_deploy_pack",
        lambda *a, **k: SandboxResult(ok=True, detail="HTTP 200 on /"),
    )
    captured = {}

    def fake_opener(owner, repo, files, **kwargs):
        captured["owner"] = owner
        captured["repo"] = repo
        captured["files"] = files
        return PullRequestResult(html_url="https://github.com/acme/app/pull/7",
                                  branch="shipit/deploy-pack-abc123")

    app.dependency_overrides[get_pr_opener] = lambda: fake_opener
    try:
        resp = post_fixpack(FASTAPI_ZIP, deliver_to="acme/app")
    finally:
        app.dependency_overrides.pop(get_pr_opener, None)

    body = resp.json()
    assert body["pr"] == {
        "delivered": True,
        "url": "https://github.com/acme/app/pull/7",
        "branch": "shipit/deploy-pack-abc123",
    }
    assert captured["owner"] == "acme"
    assert captured["repo"] == "app"
    assert "Dockerfile" in captured["files"]


def test_default_request_has_no_preview_field():
    resp = post_fixpack(FASTAPI_ZIP)
    assert resp.json()["preview"] is None


def test_want_preview_false_never_touches_the_registry():
    fake = FakePreviewRegistry(PreviewResult(ok=True, detail="unused"))
    app.dependency_overrides[get_preview_registry] = lambda: fake
    try:
        post_fixpack(FASTAPI_ZIP, want_preview=False)
    finally:
        app.dependency_overrides.pop(get_preview_registry, None)
    assert fake.reap_calls == 0


def test_want_preview_true_returns_local_url_when_verified():
    fake = FakePreviewRegistry(PreviewResult(
        ok=True, detail="HTTP 200 on /",
        local_url="http://localhost:20123/", expires_at=1_999_999_999.0,
        job_id="shipit-verify-abc123-run",
    ))
    app.dependency_overrides[get_preview_registry] = lambda: fake
    try:
        resp = post_fixpack(FASTAPI_ZIP, want_preview=True)
    finally:
        app.dependency_overrides.pop(get_preview_registry, None)

    body = resp.json()
    assert body["verified"] is True
    assert body["preview"] == {
        "local_url": "http://localhost:20123/",
        "expires_at": 1_999_999_999.0,
    }
    assert fake.reap_calls == 1  # reaped before starting a new one


def test_want_preview_true_but_not_verified_returns_preview_none(monkeypatch):
    # forced no-docker path: verify fails, so preview is never started
    monkeypatch.setattr(sandbox_mod, "docker_available", lambda: False)
    resp = post_fixpack(FASTAPI_ZIP, want_preview=True)
    body = resp.json()
    assert body["verified"] is None
    assert body["preview"] is None


def test_deliver_to_uses_github_app_token_when_configured(monkeypatch):
    monkeypatch.setattr(
        pipeline_mod, "verify_deploy_pack",
        lambda *a, **k: SandboxResult(ok=True, detail="HTTP 200 on /"),
    )
    monkeypatch.setattr(main_mod, "app_credentials_from_env",
                         lambda: ("999", "fake-pem"))
    monkeypatch.setattr(main_mod, "installation_token_for_repo",
                         lambda owner, repo, **k: "ghs_app_token")
    captured = {}

    def fake_opener(owner, repo, files, token=None, **kwargs):
        captured["token"] = token
        return PullRequestResult(html_url="https://github.com/acme/app/pull/9",
                                  branch="shipit/deploy-pack-def456")

    app.dependency_overrides[get_pr_opener] = lambda: fake_opener
    try:
        resp = post_fixpack(FASTAPI_ZIP, deliver_to="acme/app")
    finally:
        app.dependency_overrides.pop(get_pr_opener, None)

    assert resp.json()["pr"]["delivered"] is True
    assert captured["token"] == "ghs_app_token"


def test_deliver_to_falls_back_to_pat_when_app_not_configured(monkeypatch):
    monkeypatch.setattr(
        pipeline_mod, "verify_deploy_pack",
        lambda *a, **k: SandboxResult(ok=True, detail="HTTP 200 on /"),
    )
    monkeypatch.setattr(main_mod, "app_credentials_from_env", lambda: None)
    captured = {}

    def fake_opener(owner, repo, files, token=None, **kwargs):
        captured["token"] = token
        return PullRequestResult(html_url="https://github.com/acme/app/pull/10",
                                  branch="shipit/deploy-pack-ghi789")

    app.dependency_overrides[get_pr_opener] = lambda: fake_opener
    try:
        resp = post_fixpack(FASTAPI_ZIP, deliver_to="acme/app")
    finally:
        app.dependency_overrides.pop(get_pr_opener, None)

    assert resp.json()["pr"]["delivered"] is True
    assert captured["token"] is None  # fake_opener would fall back to GITHUB_PR_TOKEN


def test_deliver_to_reports_github_app_not_installed(monkeypatch):
    monkeypatch.setattr(
        pipeline_mod, "verify_deploy_pack",
        lambda *a, **k: SandboxResult(ok=True, detail="HTTP 200 on /"),
    )
    monkeypatch.setattr(main_mod, "app_credentials_from_env",
                         lambda: ("999", "fake-pem"))

    def raise_not_installed(owner, repo, **k):
        raise GitHubAppError(f"GitHub App is not installed on {owner}/{repo}")

    monkeypatch.setattr(main_mod, "installation_token_for_repo", raise_not_installed)

    resp = post_fixpack(FASTAPI_ZIP, deliver_to="acme/app")
    body = resp.json()
    assert body["pr"]["delivered"] is False
    assert "not installed on acme/app" in body["pr"]["reason"]


def test_deliver_to_reports_delivery_error(monkeypatch):
    monkeypatch.setattr(
        pipeline_mod, "verify_deploy_pack",
        lambda *a, **k: SandboxResult(ok=True, detail="HTTP 200 on /"),
    )

    def failing_opener(owner, repo, files, **kwargs):
        raise DeliveryError("create branch failed: 422 already exists")

    app.dependency_overrides[get_pr_opener] = lambda: failing_opener
    try:
        resp = post_fixpack(FASTAPI_ZIP, deliver_to="acme/app")
    finally:
        app.dependency_overrides.pop(get_pr_opener, None)

    body = resp.json()
    assert body["pr"]["delivered"] is False
    assert "already exists" in body["pr"]["reason"]
