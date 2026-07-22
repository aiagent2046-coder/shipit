"""Unit tests for app.sandbox_client — the backend→runner HTTP boundary.

No real runner, no real docker: an httpx.MockTransport stands in for the
sandbox-runner so we can assert exactly what goes on the wire (request path,
X-Sandbox-Request manifest, octet-stream body, JSON body) and how the runner's
JSON reply is marshalled back into the shared result types. The degradation
contract (connection error / 5xx / 4xx) is exercised the same way.
"""

import io
import json
import zipfile

import httpx
import pytest

import app.sandbox_client as sc
from app.fixpack.generate import FixpackPlan
from app.fixpack.semantic_check import TestRunner


def _install(monkeypatch, handler):
    """Point sandbox_client._client at an httpx.Client backed by a
    MockTransport running `handler`, so no socket/runner is touched."""
    def factory():
        headers = {}
        if sc.SANDBOX_RUNNER_TOKEN:
            headers["Authorization"] = f"Bearer {sc.SANDBOX_RUNNER_TOKEN}"
        return httpx.Client(
            base_url="http://sandbox-runner", headers=headers,
            transport=httpx.MockTransport(handler), timeout=5,
        )
    monkeypatch.setattr(sc, "_client", factory)


# --- _client() header / base_url logic (no transport) ----------------------

def test_client_sets_bearer_header_when_token_present(monkeypatch):
    monkeypatch.setattr(sc, "SANDBOX_RUNNER_TOKEN", "s3cret")
    monkeypatch.setattr(sc, "SANDBOX_RUNNER_URL", "")
    with sc._client() as c:
        assert c.headers["authorization"] == "Bearer s3cret"
        assert str(c.base_url) == "http://sandbox-runner"


def test_client_no_auth_header_when_token_unset(monkeypatch):
    monkeypatch.setattr(sc, "SANDBOX_RUNNER_TOKEN", "")
    monkeypatch.setattr(sc, "SANDBOX_RUNNER_URL", "")
    with sc._client() as c:
        assert "authorization" not in c.headers


def test_client_uses_tcp_base_url_when_configured(monkeypatch):
    monkeypatch.setattr(sc, "SANDBOX_RUNNER_URL", "http://127.0.0.1:9999")
    with sc._client() as c:
        assert str(c.base_url) == "http://127.0.0.1:9999"


# --- verify_deploy_pack marshalling ----------------------------------------

def test_verify_deploy_pack_marshals_manifest_and_zips_body(tmp_path, monkeypatch):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    sub = tmp_path / "app"
    sub.mkdir()
    (sub / "main.py").write_text("x = 1\n")

    seen = {}

    def handler(request):
        seen["path"] = request.url.path
        seen["content_type"] = request.headers.get("content-type")
        seen["manifest"] = json.loads(request.headers["x-sandbox-request"])
        seen["body"] = request.content
        return httpx.Response(200, json={
            "ok": True, "detail": "HTTP 200 on /", "build_log": "built",
            "container": "job-1", "image_tag": "img-1",
        })

    _install(monkeypatch, handler)

    result = sc.verify_deploy_pack(
        tmp_path, 20001, 8000, path="/health",
        keep_alive_on_success=True, memory_limit="256m",
        labels={"shipit.preview": "true"},
    )

    assert seen["path"] == "/deploypack/verify"
    assert seen["content_type"] == "application/octet-stream"
    m = seen["manifest"]
    assert m["host_port"] == 20001
    assert m["container_port"] == 8000
    assert m["path"] == "/health"
    assert m["keep_alive_on_success"] is True
    assert m["memory_limit"] == "256m"
    assert m["labels"] == {"shipit.preview": "true"}

    # the body is a real zip carrying the build dir's files, posix-relative
    with zipfile.ZipFile(io.BytesIO(seen["body"])) as zf:
        names = set(zf.namelist())
    assert {"Dockerfile", "app/main.py"} <= names

    # runner JSON mapped back into a SandboxResult
    assert result.ok is True
    assert result.detail == "HTTP 200 on /"
    assert result.build_log == "built"
    assert result.container == "job-1"
    assert result.image_tag == "img-1"


def test_verify_deploy_pack_maps_failure_result(tmp_path, monkeypatch):
    def handler(request):
        return httpx.Response(200, json={
            "ok": False, "detail": "boot check failed", "build_log": "trace",
            "container": None, "image_tag": None,
        })

    _install(monkeypatch, handler)
    result = sc.verify_deploy_pack(tmp_path, 20002, 8000)
    assert result.ok is False
    assert result.detail == "boot check failed"
    assert result.container is None


# --- preview_stop / reconcile ----------------------------------------------

def test_preview_stop_marshals_container_and_image(monkeypatch):
    seen = {}

    def handler(request):
        seen["path"] = request.url.path
        seen["manifest"] = json.loads(request.headers["x-sandbox-request"])
        return httpx.Response(200, json={"ok": True})

    _install(monkeypatch, handler)
    sc.preview_stop("cont-9", "img-9")

    assert seen["path"] == "/deploypack/preview/stop"
    assert seen["manifest"] == {"container": "cont-9", "image_tag": "img-9"}


def test_reconcile_previews_passes_now_and_returns_summary(monkeypatch):
    seen = {}

    def handler(request):
        seen["path"] = request.url.path
        seen["manifest"] = json.loads(request.headers["x-sandbox-request"])
        return httpx.Response(200, json={
            "docker": True, "checked": 2, "removed": [{"container": "c"}],
        })

    _install(monkeypatch, handler)
    out = sc.reconcile_previews(now=1234.0)

    assert seen["path"] == "/deploypack/reconcile"
    assert seen["manifest"] == {"now": 1234.0}
    assert out == {"docker": True, "checked": 2, "removed": [{"container": "c"}]}


# --- fixpack run_suite / minimal_check -------------------------------------

def test_run_suite_marshals_runner_and_zip(monkeypatch):
    seen = {}

    def handler(request):
        seen["path"] = request.url.path
        seen["manifest"] = json.loads(request.headers["x-sandbox-request"])
        seen["body"] = request.content
        return httpx.Response(200, json={
            "passed": 5, "failed": 0, "timed_out": False, "error": None,
        })

    _install(monkeypatch, handler)
    runner = TestRunner(ecosystem="node", image="node:20",
                        install_script="npm ci", test_script="npm test")
    result = sc.run_suite(b"ZIPBYTES", runner)

    assert seen["path"] == "/fixpack/run-suite"
    assert seen["body"] == b"ZIPBYTES"
    assert seen["manifest"]["runner"] == {
        "ecosystem": "node", "image": "node:20",
        "install_script": "npm ci", "test_script": "npm test",
    }
    assert (result.passed, result.failed, result.timed_out, result.error) == (
        5, 0, False, None)


def test_minimal_check_posts_json_body(monkeypatch):
    seen = {}

    def handler(request):
        seen["path"] = request.url.path
        seen["content_type"] = request.headers.get("content-type")
        seen["json"] = json.loads(request.content)
        return httpx.Response(200, json={
            "passed": 1, "failed": 0, "timed_out": False, "error": None,
        })

    _install(monkeypatch, handler)
    plan = FixpackPlan(files={"a.js": "const x = 1;"}, deletions=["old.js"])
    result = sc.minimal_check(plan)

    assert seen["path"] == "/fixpack/minimal-check"
    assert seen["content_type"].startswith("application/json")
    assert seen["json"] == {"files": {"a.js": "const x = 1;"},
                            "deletions": ["old.js"]}
    assert result.passed == 1


# --- degradation contract --------------------------------------------------

def test_verify_raises_unavailable_on_connection_error(tmp_path, monkeypatch):
    def handler(request):
        raise httpx.ConnectError("refused", request=request)

    _install(monkeypatch, handler)
    with pytest.raises(sc.SandboxRunnerUnavailable):
        sc.verify_deploy_pack(tmp_path, 20003, 8000)


def test_verify_raises_unavailable_on_5xx(tmp_path, monkeypatch):
    _install(monkeypatch, lambda request: httpx.Response(502, text="bad gw"))
    with pytest.raises(sc.SandboxRunnerUnavailable):
        sc.verify_deploy_pack(tmp_path, 20004, 8000)


def test_verify_raises_unavailable_on_4xx(tmp_path, monkeypatch):
    _install(monkeypatch, lambda request: httpx.Response(401, text="nope"))
    with pytest.raises(sc.SandboxRunnerUnavailable):
        sc.verify_deploy_pack(tmp_path, 20005, 8000)


def test_run_suite_returns_error_result_on_outage(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("refused", request=request)

    _install(monkeypatch, handler)
    runner = TestRunner(ecosystem="node", image="node:20",
                        install_script="npm ci", test_script="npm test")
    result = sc.run_suite(b"z", runner)
    # symmetric non-regression: error set, not an exception
    assert result.error and "sandbox runner unavailable" in result.error
    assert (result.passed, result.failed) == (0, 0)


def test_minimal_check_returns_error_result_on_outage(monkeypatch):
    _install(monkeypatch, lambda request: httpx.Response(500, text="boom"))
    plan = FixpackPlan(files={"a.js": "const x = 1;"}, deletions=[])
    result = sc.minimal_check(plan)
    assert result.error and "sandbox runner unavailable" in result.error
