"""Tests for the sandbox verification orchestration, with a fake
subprocess runner — no real Docker involved. See module docstring in
app/deploypack/sandbox.py for why the real docker path is untested."""

import subprocess

import app.deploypack.sandbox as sandbox
from app.deploypack.sandbox import verify_deploy_pack


class FakeRunner:
    """Programmable stand-in for subprocess.run. `script` maps the
    first argv token ("docker"/"curl") to a queue of results; pops one
    per matching call so a sequence of curl polls can be scripted."""

    def __init__(self, script: dict):
        self.script = {k: list(v) for k, v in script.items()}
        self.calls: list[list[str]] = []

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        key = argv[0] if argv[0] != "docker" else f"docker:{argv[1]}"
        queue = self.script.get(key, [])
        if not queue:
            raise AssertionError(f"no scripted result left for {key}: {argv}")
        result = queue.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def cp(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def test_docker_missing_short_circuits_without_calling_run(monkeypatch):
    monkeypatch.setattr(sandbox, "docker_available", lambda: False)
    runner = FakeRunner({})
    result = verify_deploy_pack(".", 8000, 8000, run=runner)
    assert result.ok is False
    assert "docker binary not found" in result.detail
    assert runner.calls == []


def test_build_failure_stops_before_run(monkeypatch):
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    runner = FakeRunner({
        "docker:build": [cp(returncode=1, stderr="Dockerfile: syntax error")],
    })
    result = verify_deploy_pack(".", 8000, 8000, run=runner)
    assert result.ok is False
    assert "build failed" in result.detail
    assert "syntax error" in result.build_log
    assert not any(c[:2] == ["docker", "run"] for c in runner.calls)


def test_run_failure_returns_error(monkeypatch):
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    runner = FakeRunner({
        "docker:build": [cp(returncode=0)],
        "docker:run": [subprocess.CalledProcessError(1, ["docker", "run"], stderr="port in use")],
        "docker:rmi": [cp(returncode=0)],
    })
    result = verify_deploy_pack(".", 8000, 8000, run=runner)
    assert result.ok is False
    assert "run failed" in result.detail
    # image was built even though `run` failed — must still be cleaned up
    assert any(c[:2] == ["docker", "rmi"] for c in runner.calls)
    assert not any(c[:2] == ["docker", "stop"] for c in runner.calls)


def test_success_on_first_probe(monkeypatch):
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    runner = FakeRunner({
        "docker:build": [cp(returncode=0)],
        "docker:run": [cp(returncode=0)],
        "curl": [cp(stdout="200")],
        "docker:stop": [cp(returncode=0)],
        "docker:rmi": [cp(returncode=0)],
    })
    result = verify_deploy_pack(".", 8000, 8000, poll_interval_s=0.01, run=runner)
    assert result.ok is True
    assert "200" in result.detail
    assert any(c[:2] == ["docker", "stop"] for c in runner.calls)
    assert any(c[:2] == ["docker", "rmi"] for c in runner.calls)


def test_success_after_a_few_slow_probes(monkeypatch):
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    runner = FakeRunner({
        "docker:build": [cp(returncode=0)],
        "docker:run": [cp(returncode=0)],
        "curl": [cp(stdout="000"), cp(stdout="502"), cp(stdout="200")],
        "docker:stop": [cp(returncode=0)],
        "docker:rmi": [cp(returncode=0)],
    })
    result = verify_deploy_pack(".", 8000, 8000, poll_interval_s=0.01, run=runner)
    assert result.ok is True


def test_keep_alive_on_success_skips_stop_and_rmi(monkeypatch):
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    runner = FakeRunner({
        "docker:build": [cp(returncode=0)],
        "docker:run": [cp(returncode=0)],
        "curl": [cp(stdout="200")],
    })
    result = verify_deploy_pack(
        ".", 8000, 8000, poll_interval_s=0.01,
        keep_alive_on_success=True, run=runner,
    )
    assert result.ok is True
    assert result.container is not None
    assert result.image_tag is not None
    assert not any(c[:2] == ["docker", "stop"] for c in runner.calls)
    assert not any(c[:2] == ["docker", "rmi"] for c in runner.calls)


def test_keep_alive_does_not_apply_to_failed_boots(monkeypatch):
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    runner = FakeRunner({
        "docker:build": [cp(returncode=0)],
        "docker:run": [cp(returncode=0)],
        "curl": [cp(stdout="000")] * 3,
        "docker:logs": [cp(stdout="crash")],
        "docker:stop": [cp(returncode=0)],
        "docker:rmi": [cp(returncode=0)],
    })
    result = verify_deploy_pack(
        ".", 8000, 8000, boot_timeout_s=0.02, poll_interval_s=0.01,
        keep_alive_on_success=True, run=runner,
    )
    assert result.ok is False
    # never booted, so keep_alive_on_success must not suppress cleanup
    assert any(c[:2] == ["docker", "stop"] for c in runner.calls)
    assert any(c[:2] == ["docker", "rmi"] for c in runner.calls)


def test_memory_limit_is_passed_to_docker_run(monkeypatch):
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    runner = FakeRunner({
        "docker:build": [cp(returncode=0)],
        "docker:run": [cp(returncode=0)],
        "curl": [cp(stdout="200")],
        "docker:stop": [cp(returncode=0)],
        "docker:rmi": [cp(returncode=0)],
    })
    verify_deploy_pack(
        ".", 8000, 8000, poll_interval_s=0.01, memory_limit="256m", run=runner,
    )
    run_call = next(c for c in runner.calls if c[:2] == ["docker", "run"])
    assert "--memory" in run_call and "256m" in run_call


def test_published_port_is_bound_to_loopback_only(monkeypatch):
    # Security: the preview must not be reachable from other interfaces.
    # The -p arg has to carry the 127.0.0.1: prefix, not a bare host:container
    # (which Docker binds on 0.0.0.0).
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    runner = FakeRunner({
        "docker:build": [cp(returncode=0)],
        "docker:run": [cp(returncode=0)],
        "curl": [cp(stdout="200")],
        "docker:stop": [cp(returncode=0)],
        "docker:rmi": [cp(returncode=0)],
    })
    verify_deploy_pack(".", 8000, 8080, poll_interval_s=0.01, run=runner)
    run_call = next(c for c in runner.calls if c[:2] == ["docker", "run"])
    assert "-p" in run_call
    pub = run_call[run_call.index("-p") + 1]
    assert pub == "127.0.0.1:8000:8080"
    assert not pub.startswith("8000:")  # never a bare 0.0.0.0 bind


def test_run_applies_resource_and_privilege_limits(monkeypatch):
    # Security: the preview container runs untrusted client code, so the
    # run command must carry the fork-bomb / CPU / privilege guards.
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    runner = FakeRunner({
        "docker:build": [cp(returncode=0)],
        "docker:run": [cp(returncode=0)],
        "curl": [cp(stdout="200")],
        "docker:stop": [cp(returncode=0)],
        "docker:rmi": [cp(returncode=0)],
    })
    verify_deploy_pack(".", 8000, 8000, poll_interval_s=0.01, run=runner)
    run_call = next(c for c in runner.calls if c[:2] == ["docker", "run"])
    assert "--pids-limit=256" in run_call
    assert "--cpus=1" in run_call
    assert "--security-opt=no-new-privileges" in run_call
    assert "--cap-drop=ALL" in run_call


def test_no_host_env_is_injected_into_the_preview_container(monkeypatch):
    # `docker run` doesn't forward host env into the container without -e/--env.
    # We never pass one, so host secrets can't reach untrusted client code;
    # guard against a future -e leak.
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    runner = FakeRunner({
        "docker:build": [cp(returncode=0)],
        "docker:run": [cp(returncode=0)],
        "curl": [cp(stdout="200")],
        "docker:stop": [cp(returncode=0)],
        "docker:rmi": [cp(returncode=0)],
    })
    verify_deploy_pack(".", 8000, 8000, poll_interval_s=0.01, run=runner)
    run_call = next(c for c in runner.calls if c[:2] == ["docker", "run"])
    assert "-e" not in run_call
    assert not any(a.startswith("--env") for a in run_call)


def _run_call_for(monkeypatch, **verify_kwargs):
    """Drive verify_deploy_pack through a happy-path fake runner and return the
    `docker run` argv (the container-launch command)."""
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    runner = FakeRunner({
        "docker:build": [cp(returncode=0)],
        "docker:run": [cp(returncode=0)],
        "curl": [cp(stdout="200")],
        "docker:stop": [cp(returncode=0)],
        "docker:rmi": [cp(returncode=0)],
    })
    verify_deploy_pack(".", 8000, 8000, poll_interval_s=0.01, run=runner,
                       **verify_kwargs)
    return runner, next(c for c in runner.calls if c[:2] == ["docker", "run"])


def test_preview_run_is_on_isolated_network_by_default(monkeypatch):
    # 3.5: the running preview must not reach the internet — it is attached to
    # the configured no-egress network, not the default bridge.
    monkeypatch.setattr(sandbox, "DEPLOYPACK_ALLOW_RUNTIME_NETWORK", False)
    monkeypatch.setattr(sandbox, "DEPLOYPACK_PREVIEW_NETWORK", "shipit-preview")
    _, run_call = _run_call_for(monkeypatch)
    assert "--network" in run_call
    assert run_call[run_call.index("--network") + 1] == "shipit-preview"


def test_runtime_network_opt_in_uses_open_bridge(monkeypatch):
    # The rare app that genuinely needs runtime network opts in explicitly;
    # then we emit no --network (default bridge).
    monkeypatch.setattr(sandbox, "DEPLOYPACK_ALLOW_RUNTIME_NETWORK", True)
    _, run_call = _run_call_for(monkeypatch)
    assert "--network" not in run_call


def test_empty_network_name_disables_isolation(monkeypatch):
    monkeypatch.setattr(sandbox, "DEPLOYPACK_ALLOW_RUNTIME_NETWORK", False)
    monkeypatch.setattr(sandbox, "DEPLOYPACK_PREVIEW_NETWORK", "")
    _, run_call = _run_call_for(monkeypatch)
    assert "--network" not in run_call


def test_build_routes_egress_through_the_proxy(monkeypatch):
    # 3.5: docker build's RUN steps (pip/npm/apt) go through the host's
    # allowlisting forward proxy, not the open internet.
    monkeypatch.setattr(sandbox, "DEPLOYPACK_BUILD_PROXY_URL", "http://host.docker.internal:3128")
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    runner = FakeRunner({
        "docker:build": [cp(returncode=0)],
        "docker:run": [cp(returncode=0)],
        "curl": [cp(stdout="200")],
        "docker:stop": [cp(returncode=0)],
        "docker:rmi": [cp(returncode=0)],
    })
    verify_deploy_pack(".", 8000, 8000, poll_interval_s=0.01, run=runner)
    build_call = next(c for c in runner.calls if c[:2] == ["docker", "build"])
    assert "--add-host=host.docker.internal:host-gateway" in build_call
    args = {build_call[i + 1] for i, t in enumerate(build_call) if t == "--build-arg"}
    assert "HTTP_PROXY=http://host.docker.internal:3128" in args
    assert "HTTPS_PROXY=http://host.docker.internal:3128" in args


def test_build_proxy_can_be_disabled(monkeypatch):
    monkeypatch.setattr(sandbox, "DEPLOYPACK_BUILD_PROXY_URL", "")
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    runner = FakeRunner({
        "docker:build": [cp(returncode=0)],
        "docker:run": [cp(returncode=0)],
        "curl": [cp(stdout="200")],
        "docker:stop": [cp(returncode=0)],
        "docker:rmi": [cp(returncode=0)],
    })
    verify_deploy_pack(".", 8000, 8000, poll_interval_s=0.01, run=runner)
    build_call = next(c for c in runner.calls if c[:2] == ["docker", "build"])
    assert not any(a.startswith("--build-arg") for a in build_call)
    assert not any(a.startswith("--add-host") for a in build_call)


def test_preview_run_is_read_only_with_tmpfs_by_default(monkeypatch):
    monkeypatch.setattr(sandbox, "DEPLOYPACK_READONLY_ROOTFS", True)
    _, run_call = _run_call_for(monkeypatch)
    assert "--read-only" in run_call
    assert "--tmpfs" in run_call
    assert run_call[run_call.index("--tmpfs") + 1] == "/tmp"


def test_read_only_can_be_disabled_by_env(monkeypatch):
    monkeypatch.setattr(sandbox, "DEPLOYPACK_READONLY_ROOTFS", False)
    _, run_call = _run_call_for(monkeypatch)
    assert "--read-only" not in run_call


def test_user_is_off_by_default_and_opt_in(monkeypatch):
    # OFF by default (a generated app may need root for a low port / rootfs).
    monkeypatch.setattr(sandbox, "DEPLOYPACK_RUN_AS_USER", "")
    _, run_call = _run_call_for(monkeypatch)
    assert "--user" not in run_call
    # Opt in by setting the env.
    monkeypatch.setattr(sandbox, "DEPLOYPACK_RUN_AS_USER", "1000:1000")
    _, run_call = _run_call_for(monkeypatch)
    assert "--user" in run_call and run_call[run_call.index("--user") + 1] == "1000:1000"


def test_preview_run_carries_fd_and_fsize_ulimits(monkeypatch):
    _, run_call = _run_call_for(monkeypatch)
    ulimits = {run_call[i + 1] for i, t in enumerate(run_call) if t == "--ulimit"}
    assert any(u.startswith("nofile=") for u in ulimits)
    assert any(u.startswith("fsize=") for u in ulimits)


def test_no_docker_socket_or_host_mount_in_run(monkeypatch):
    # 3.4: the preview run must never mount the docker socket or any host path.
    _, run_call = _run_call_for(monkeypatch)
    joined = " ".join(run_call)
    assert "docker.sock" not in joined
    assert "-v" not in run_call and "--volume" not in run_call


def test_build_log_is_truncated(monkeypatch):
    # 3.4: an adversarial Dockerfile RUN can print unboundedly; the persisted
    # build_log is clipped.
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    huge = "x" * (sandbox.MAX_BUILD_LOG_BYTES * 3)
    runner = FakeRunner({"docker:build": [cp(returncode=1, stderr=huge)]})
    result = verify_deploy_pack(".", 8000, 8000, run=runner)
    assert result.ok is False
    assert len(result.build_log) < len(huge)
    assert "truncated" in result.build_log


def test_never_boots_reports_failure_and_still_stops_container(monkeypatch):
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    runner = FakeRunner({
        "docker:build": [cp(returncode=0)],
        "docker:run": [cp(returncode=0)],
        "curl": [cp(stdout="000")] * 5,
        "docker:logs": [cp(stdout="app crashed on boot")],
        "docker:stop": [cp(returncode=0)],
        "docker:rmi": [cp(returncode=0)],
    })
    result = verify_deploy_pack(
        ".", 8000, 8000, boot_timeout_s=0.03, poll_interval_s=0.01, run=runner,
    )
    assert result.ok is False
    assert "never returned 200" in result.detail
    assert "app crashed on boot" in result.build_log
    assert any(c[:2] == ["docker", "stop"] for c in runner.calls)
    assert any(c[:2] == ["docker", "rmi"] for c in runner.calls)
