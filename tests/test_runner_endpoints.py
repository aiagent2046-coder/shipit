"""Unit tests for the sandbox-runner FastAPI app (app.runner.main).

These exercise auth, request parsing and the marshalling into the real
implementation seams — WITHOUT real docker. Each docker-touching function
(verify_deploy_pack, run_suite, minimal_check, reconcile_previews, and the
subprocess calls) is monkeypatched in the runner's namespace, so we assert the
service reconstructs the right inputs and shapes the right JSON reply. The full
real-docker path is covered separately by the end-to-end workflow.
"""

import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

import app.runner.auth as auth
import app.runner.main as runner_main
from app.deploypack.sandbox import SandboxResult
from app.fixpack.semantic_check import RunResult

client = TestClient(runner_main.app)

TOKEN = "test-token"


@pytest.fixture(autouse=True)
def _set_token(monkeypatch):
    # Default: a configured token so most tests can authenticate. Individual
    # tests override to "" to prove the unconfigured-runner 503 path.
    monkeypatch.setattr(auth, "SANDBOX_RUNNER_TOKEN", TOKEN)


def _auth_headers(extra=None):
    h = {"Authorization": f"Bearer {TOKEN}"}
    if extra:
        h.update(extra)
    return h


def _manifest_header(manifest):
    return {"X-Sandbox-Request": json.dumps(manifest)}


def _zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


# --- auth ------------------------------------------------------------------

def test_endpoint_refuses_when_token_unset(monkeypatch):
    monkeypatch.setattr(auth, "SANDBOX_RUNNER_TOKEN", "")
    resp = client.post("/deploypack/reconcile",
                       headers=_manifest_header({"now": None}))
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "runner_not_configured"


def test_endpoint_rejects_wrong_token():
    resp = client.post(
        "/deploypack/reconcile",
        headers={"Authorization": "Bearer wrong",
                 **_manifest_header({"now": None})},
    )
    assert resp.status_code == 401


def test_endpoint_accepts_correct_token(monkeypatch):
    monkeypatch.setattr(runner_main, "reconcile_previews",
                        lambda now=None: {"docker": True, "checked": 0,
                                          "removed": []})
    resp = client.post("/deploypack/reconcile",
                       headers=_auth_headers(_manifest_header({"now": 1.0})))
    assert resp.status_code == 200
    assert resp.json() == {"docker": True, "checked": 0, "removed": []}


# --- healthz (no auth) -----------------------------------------------------

def test_healthz_reports_docker_version(monkeypatch):
    import subprocess

    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout="29.6.1\n", stderr="")

    monkeypatch.setattr(runner_main.subprocess, "run", fake_run)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"ok": True, "docker": True, "docker_version": "29.6.1"}


def test_healthz_reports_dead_docker(monkeypatch):
    import subprocess

    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="cannot connect")

    monkeypatch.setattr(runner_main.subprocess, "run", fake_run)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False and body["docker"] is False


# --- deploypack/verify parsing --------------------------------------------

def test_verify_reconstructs_build_dir_and_manifest(monkeypatch):
    captured = {}

    def fake_verify(build_dir, host_port, container_port, *, path="/",
                    build_timeout_s=300, boot_timeout_s=60, poll_interval_s=1.0,
                    keep_alive_on_success=False, memory_limit=None, labels=None):
        captured["files"] = sorted(
            p.relative_to(build_dir).as_posix()
            for p in build_dir.rglob("*") if p.is_file()
        )
        captured["host_port"] = host_port
        captured["container_port"] = container_port
        captured["path"] = path
        captured["keep_alive_on_success"] = keep_alive_on_success
        captured["memory_limit"] = memory_limit
        captured["labels"] = labels
        return SandboxResult(ok=True, detail="HTTP 200 on /", build_log="b",
                             container="c1", image_tag="i1")

    monkeypatch.setattr(runner_main, "verify_deploy_pack", fake_verify)

    manifest = {
        "host_port": 20010, "container_port": 8000, "path": "/health",
        "keep_alive_on_success": True, "memory_limit": "256m",
        "labels": {"shipit.preview": "true"},
    }
    body = _zip({"Dockerfile": b"FROM scratch\n", "app/main.py": b"x = 1\n"})
    resp = client.post("/deploypack/verify", content=body,
                       headers=_auth_headers(_manifest_header(manifest)))

    assert resp.status_code == 200
    assert resp.json() == {
        "ok": True, "detail": "HTTP 200 on /", "build_log": "b",
        "container": "c1", "image_tag": "i1",
    }
    assert captured["files"] == ["Dockerfile", "app/main.py"]
    assert captured["host_port"] == 20010
    assert captured["container_port"] == 8000
    assert captured["path"] == "/health"
    assert captured["keep_alive_on_success"] is True
    assert captured["memory_limit"] == "256m"
    assert captured["labels"] == {"shipit.preview": "true"}


# --- preview/stop ----------------------------------------------------------

def test_preview_stop_execs_docker_stop_and_rmi(monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        import subprocess
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(runner_main.subprocess, "run", fake_run)
    resp = client.post(
        "/deploypack/preview/stop",
        headers=_auth_headers(_manifest_header(
            {"container": "cont-1", "image_tag": "img-1"})),
    )
    assert resp.status_code == 200 and resp.json() == {"ok": True}
    assert ["docker", "stop", "cont-1"] in calls
    assert ["docker", "rmi", "-f", "img-1"] in calls


# --- fixpack/run-suite -----------------------------------------------------

def test_run_suite_rebuilds_runner_and_passes_zip(monkeypatch):
    captured = {}

    def fake_run_suite(raw, runner):
        captured["raw"] = raw
        captured["runner"] = runner
        return RunResult(passed=3, failed=1, timed_out=False, error=None)

    monkeypatch.setattr(runner_main, "run_suite", fake_run_suite)

    manifest = {"runner": {
        "ecosystem": "node", "image": "node:20",
        "install_script": "npm ci", "test_script": "npm test",
    }}
    resp = client.post("/fixpack/run-suite", content=b"ZIPB",
                       headers=_auth_headers(_manifest_header(manifest)))

    assert resp.status_code == 200
    assert resp.json() == {"passed": 3, "failed": 1, "timed_out": False,
                           "error": None}
    assert captured["raw"] == b"ZIPB"
    r = captured["runner"]
    assert (r.ecosystem, r.image, r.install_script, r.test_script) == (
        "node", "node:20", "npm ci", "npm test")


# --- fixpack/minimal-check -------------------------------------------------

def test_minimal_check_rebuilds_plan_from_json_body(monkeypatch):
    captured = {}

    def fake_minimal_check(plan):
        captured["files"] = dict(plan.files)
        captured["deletions"] = list(plan.deletions)
        return RunResult(passed=1, failed=0, timed_out=False, error=None)

    monkeypatch.setattr(runner_main, "minimal_check", fake_minimal_check)

    resp = client.post(
        "/fixpack/minimal-check",
        json={"files": {"a.js": "const x = 1;"}, "deletions": ["old.js"]},
        headers=_auth_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["passed"] == 1
    assert captured["files"] == {"a.js": "const x = 1;"}
    assert captured["deletions"] == ["old.js"]


def test_run_verification_rebuilds_profile_and_passes_zip(
    monkeypatch,
):
    from app.fixpack.verification import (
        VerificationStage,
    )

    captured = {}

    def fake_run_verification(
        raw,
        profile,
    ):
        captured["raw"] = raw
        captured["profile"] = profile

        return (
            VerificationStage(
                name="install",
                status="passed",
                command=profile.install_command,
                exit_code=0,
                duration_ms=10,
            ),
            VerificationStage(
                name="build",
                status="passed",
                command=profile.steps[0].command,
                exit_code=0,
                duration_ms=20,
            ),
        )

    monkeypatch.setattr(
        runner_main,
        "run_verification_profile",
        fake_run_verification,
    )

    manifest = {
        "profile": {
            "ecosystem": "node",
            "framework": "vite",
            "image": "node:20-slim",
            "install_command": (
                "npm ci --no-audit --no-fund"
            ),
            "steps": [
                {
                    "name": "build",
                    "command": "npm run build",
                    "required": True,
                }
            ],
        }
    }

    resp = client.post(
        "/fixpack/run-verification",
        content=b"ZIP-VERIFICATION",
        headers=_auth_headers(
            _manifest_header(manifest)
        ),
    )

    assert resp.status_code == 200

    assert resp.json() == {
        "stages": [
            {
                "name": "install",
                "status": "passed",
                "command": (
                    "npm ci --no-audit --no-fund"
                ),
                "exit_code": 0,
                "duration_ms": 10,
                "detail": None,
            },
            {
                "name": "build",
                "status": "passed",
                "command": "npm run build",
                "exit_code": 0,
                "duration_ms": 20,
                "detail": None,
            },
        ]
    }

    assert captured["raw"] == b"ZIP-VERIFICATION"

    profile = captured["profile"]

    assert profile.ecosystem == "node"
    assert profile.framework == "vite"
    assert profile.image == "node:20-slim"
    assert profile.steps[0].name == "build"
    assert profile.steps[0].required is True
