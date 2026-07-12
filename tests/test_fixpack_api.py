"""API-level tests for POST /v1/fixpacks.

This sandbox has no `docker` binary at all (see
app/deploypack/sandbox.py's module docstring), so most tests here
exercise the real, unmocked "docker unavailable" path — that's a
genuine, honest outcome, not a workaround. One test monkeypatches the
sandbox call to also prove the API correctly reports verified=True
when the sandbox does succeed.
"""

import io
import json
import zipfile

from fastapi.testclient import TestClient

import app.deploypack.pipeline as pipeline_mod
from app.deploypack.sandbox import SandboxResult
from app.main import app

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


def post_fixpack(entries: dict[str, bytes]):
    return client.post(
        "/v1/fixpacks",
        files={"archive": ("app.zip", make_zip(entries), "application/zip")},
    )


def test_fastapi_pack_generated_but_unverified_without_docker():
    resp = post_fixpack(FASTAPI_ZIP)
    assert resp.status_code == 202
    body = resp.json()
    assert body["stack"] == "fastapi"
    assert body["verified"] is None
    assert "docker binary not found" in body["detail"]
    assert "Dockerfile" in body["files"]
    assert "docker-compose.yml" in body["files"]


def test_vite_react_pack_generated_but_unverified_without_docker():
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
