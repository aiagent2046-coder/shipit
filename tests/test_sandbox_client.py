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
    def factory(timeout=None):
        headers = {}
        if sc.SANDBOX_RUNNER_TOKEN:
            headers["Authorization"] = f"Bearer {sc.SANDBOX_RUNNER_TOKEN}"
        return httpx.Client(
            base_url="http://sandbox-runner", headers=headers,
            transport=httpx.MockTransport(handler), timeout=timeout or 5,
        )
    monkeypatch.setattr(sc, "_client", factory)


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch):
    """Record the connect-retry backoff instead of actually sleeping it.

    _post now retries connect-level failures with real 1s/3s delays; without
    this every ConnectError test in this file would sit idle for 4s. Tests that
    care about the pattern assert against the returned list."""
    slept = []
    monkeypatch.setattr(sc, "_sleep", slept.append)
    return slept


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


# --- connect-level retries -------------------------------------------------

def _flaky(fail_times, exc_factory=httpx.ConnectError):
    """Handler that fails the first `fail_times` attempts, then succeeds."""
    attempts = []

    def handler(request):
        attempts.append(request.url.path)
        if len(attempts) <= fail_times:
            raise exc_factory("no socket", request=request)
        return httpx.Response(200, json={
            "passed": 3, "failed": 0, "timed_out": False, "error": None,
        })

    return handler, attempts


def test_connect_error_retries_and_succeeds_on_second_attempt(monkeypatch,
                                                              _no_real_sleep):
    handler, attempts = _flaky(1)
    _install(monkeypatch, handler)
    result = sc.minimal_check(FixpackPlan(files={"a.js": "1;"}, deletions=[]))
    assert result.error is None and result.passed == 3
    assert len(attempts) == 2
    assert _no_real_sleep == [1.0]


def test_connect_timeout_retries_and_succeeds_on_third_attempt(monkeypatch,
                                                               _no_real_sleep):
    handler, attempts = _flaky(2, exc_factory=httpx.ConnectTimeout)
    _install(monkeypatch, handler)
    result = sc.minimal_check(FixpackPlan(files={"a.js": "1;"}, deletions=[]))
    assert result.error is None
    assert len(attempts) == 3
    assert _no_real_sleep == [1.0, 3.0]


def test_connect_error_exhausts_attempts_then_raises_transport_error(
        tmp_path, monkeypatch, _no_real_sleep):
    attempts = []

    def handler(request):
        attempts.append(1)
        raise httpx.ConnectError("refused", request=request)

    _install(monkeypatch, handler)
    with pytest.raises(sc.SandboxRunnerTransportError) as exc_info:
        sc.verify_deploy_pack(tmp_path, 20006, 8000)

    # one attempt per delay, plus the final one
    assert len(attempts) == len(sc.SANDBOX_RUNNER_RETRY_DELAYS_S) + 1 == 3
    assert _no_real_sleep == [1.0, 3.0]
    # the final message survives the retries and still names the cause
    assert "unreachable" in str(exc_info.value)
    assert "ConnectError" in str(exc_info.value)
    assert exc_info.value.retryable is True
    # back-compat: existing `except SandboxRunnerUnavailable` sites still catch it
    assert isinstance(exc_info.value, sc.SandboxRunnerUnavailable)


def test_read_timeout_is_not_retried(tmp_path, monkeypatch, _no_real_sleep):
    attempts = []

    def handler(request):
        attempts.append(1)
        raise httpx.ReadTimeout("still building", request=request)

    _install(monkeypatch, handler)
    with pytest.raises(sc.SandboxRunnerUnavailable) as exc_info:
        sc.verify_deploy_pack(tmp_path, 20007, 8000)

    assert len(attempts) == 1
    assert _no_real_sleep == []
    # a read timeout means the runner is alive — not the retryable flavour
    assert not isinstance(exc_info.value, sc.SandboxRunnerTransportError)
    assert exc_info.value.retryable is False
    assert "ReadTimeout" in str(exc_info.value)


def test_4xx_is_not_retried(tmp_path, monkeypatch, _no_real_sleep):
    attempts = []

    def handler(request):
        attempts.append(1)
        return httpx.Response(401, text="bad token")

    _install(monkeypatch, handler)
    with pytest.raises(sc.SandboxRunnerUnavailable) as exc_info:
        sc.verify_deploy_pack(tmp_path, 20008, 8000)

    assert len(attempts) == 1
    assert _no_real_sleep == []
    assert exc_info.value.retryable is False
    assert "401" in str(exc_info.value)


def test_5xx_is_not_retried(tmp_path, monkeypatch, _no_real_sleep):
    attempts = []

    def handler(request):
        attempts.append(1)
        return httpx.Response(503, text="busy")

    _install(monkeypatch, handler)
    with pytest.raises(sc.SandboxRunnerUnavailable):
        sc.verify_deploy_pack(tmp_path, 20009, 8000)

    assert len(attempts) == 1
    assert _no_real_sleep == []


def test_run_suite_outage_result_reports_exhausted_retries(monkeypatch,
                                                           _no_real_sleep):
    attempts = []

    def handler(request):
        attempts.append(1)
        raise httpx.ConnectError("refused", request=request)

    _install(monkeypatch, handler)
    runner = TestRunner(ecosystem="node", image="node:20",
                        install_script="npm ci", test_script="npm test")
    result = sc.run_suite(b"z", runner)
    # unchanged degradation contract, now only after the retries are spent
    assert result.error and "sandbox runner unavailable" in result.error
    assert len(attempts) == 3


# --- runner_healthy() ------------------------------------------------------

def test_runner_healthy_true_when_docker_reachable(monkeypatch, _no_real_sleep):
    seen = {}

    def handler(request):
        seen["path"] = request.url.path
        seen["method"] = request.method
        return httpx.Response(200, json={
            "ok": True, "docker": True, "docker_version": "24.0.7",
        })

    _install(monkeypatch, handler)
    assert sc.runner_healthy() is True
    assert (seen["method"], seen["path"]) == ("GET", "/healthz")
    assert _no_real_sleep == []


def test_runner_healthy_false_when_runner_up_but_docker_dead(monkeypatch):
    _install(monkeypatch, lambda request: httpx.Response(
        200, json={"ok": False, "docker": False, "detail": "CalledProcessError"}))
    assert sc.runner_healthy() is False


def test_runner_healthy_false_on_connect_error_without_retrying(monkeypatch,
                                                                _no_real_sleep):
    attempts = []

    def handler(request):
        attempts.append(1)
        raise httpx.ConnectError("refused", request=request)

    _install(monkeypatch, handler)
    assert sc.runner_healthy() is False
    assert len(attempts) == 1, "the readiness probe must not retry"
    assert _no_real_sleep == []


def test_runner_healthy_false_on_non_200(monkeypatch):
    _install(monkeypatch, lambda request: httpx.Response(503, text="starting"))
    assert sc.runner_healthy() is False


def test_runner_healthy_false_on_unparseable_body(monkeypatch):
    _install(monkeypatch, lambda request: httpx.Response(200, text="not json"))
    assert sc.runner_healthy() is False


def test_runner_healthy_uses_short_timeout(monkeypatch):
    seen = {}

    def factory(timeout=None):
        seen["timeout"] = timeout
        return httpx.Client(
            base_url="http://sandbox-runner", timeout=timeout or 5,
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={"ok": True,
                                                          "docker": True})),
        )

    monkeypatch.setattr(sc, "_client", factory)
    assert sc.runner_healthy() is True
    assert seen["timeout"] == sc.SANDBOX_RUNNER_HEALTH_TIMEOUT_S
    assert seen["timeout"] < sc.SANDBOX_RUNNER_TIMEOUT_S
