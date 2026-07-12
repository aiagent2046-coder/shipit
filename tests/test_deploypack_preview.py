"""Tests for the preview registry, with a fake docker runner — no real
Docker involved. See app/deploypack/sandbox.py and preview.py
docstrings for what's genuinely real vs. what needs a real host."""

import subprocess

import app.deploypack.sandbox as sandbox
from app.deploypack.preview import PreviewRegistry


class FakeRunner:
    """Same pattern as tests/test_deploypack_sandbox.py's FakeRunner."""

    def __init__(self, script: dict):
        self.script = {k: list(v) for k, v in script.items()}
        self.calls: list[list[str]] = []

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        key = argv[0] if argv[0] != "docker" else f"docker:{argv[1]}"
        queue = self.script.get(key, [])
        if not queue:
            raise AssertionError(f"no scripted result left for {key}: {argv}")
        return queue.pop(0)


def cp(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def base_script(**overrides):
    script = {
        "docker:build": [cp(returncode=0)],
        "docker:run": [cp(returncode=0)],
        "curl": [cp(stdout="200")],
    }
    script.update(overrides)
    return script


def test_start_returns_local_url_and_registers(monkeypatch):
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    runner = FakeRunner(base_script())
    registry = PreviewRegistry(run=runner)

    result = registry.start(".", 8000, owner_key="1.2.3.4")

    assert result.ok is True
    assert result.local_url.startswith("http://localhost:")
    assert result.expires_at is not None
    assert registry.active_count() == 1
    # keep_alive: no stop/rmi on a successful preview boot
    assert not any(c[:2] == ["docker", "stop"] for c in runner.calls)


def test_failed_boot_registers_nothing():
    runner = FakeRunner({
        "docker:build": [cp(returncode=1, stderr="boom")],
    })
    registry = PreviewRegistry(run=runner)

    result = registry.start(".", 8000, owner_key="1.2.3.4")

    assert result.ok is False
    assert registry.active_count() == 0


def test_second_preview_for_same_owner_replaces_the_first(monkeypatch):
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    runner = FakeRunner(base_script(
        **{
            "docker:build": [cp(returncode=0), cp(returncode=0)],
            "docker:run": [cp(returncode=0), cp(returncode=0)],
            "curl": [cp(stdout="200"), cp(stdout="200")],
            "docker:stop": [cp(returncode=0)],
            "docker:rmi": [cp(returncode=0)],
        }
    ))
    registry = PreviewRegistry(run=runner)

    first = registry.start(".", 8000, owner_key="owner-a")
    second = registry.start(".", 8000, owner_key="owner-a")

    assert first.ok and second.ok
    assert registry.active_count() == 1  # replaced, not accumulated
    assert any(c[:2] == ["docker", "stop"] for c in runner.calls)


def test_two_different_owners_get_different_ports(monkeypatch):
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    runner = FakeRunner(base_script(
        **{
            "docker:build": [cp(returncode=0), cp(returncode=0)],
            "docker:run": [cp(returncode=0), cp(returncode=0)],
            "curl": [cp(stdout="200"), cp(stdout="200")],
        }
    ))
    registry = PreviewRegistry(run=runner)

    a = registry.start(".", 8000, owner_key="owner-a")
    b = registry.start(".", 8000, owner_key="owner-b")

    assert registry.active_count() == 2
    assert a.local_url != b.local_url


def test_reap_expired_with_controlled_clock(monkeypatch):
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    runner = FakeRunner(base_script(
        **{
            "docker:build": [cp(returncode=0), cp(returncode=0)],
            "docker:run": [cp(returncode=0), cp(returncode=0)],
            "curl": [cp(stdout="200"), cp(stdout="200")],
            "docker:stop": [cp(returncode=0)],
            "docker:rmi": [cp(returncode=0)],
        }
    ))
    registry = PreviewRegistry(run=runner)
    registry.start(".", 8000, owner_key="stale-owner", ttl_seconds=10)
    registry.start(".", 8000, owner_key="fresh-owner", ttl_seconds=10_000)

    import time
    reaped = registry.reap_expired(now=time.time() + 20)  # only ttl=10 has expired
    assert reaped == 1
    assert registry.active_count() == 1
