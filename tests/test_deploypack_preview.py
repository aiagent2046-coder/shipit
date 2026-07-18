"""Tests for the preview registry, with a fake docker runner — no real
Docker involved. See app/deploypack/sandbox.py and preview.py
docstrings for what's genuinely real vs. what needs a real host."""

import datetime
import subprocess
import threading

import pytest

import app.deploypack.preview as preview
import app.deploypack.sandbox as sandbox
from app.deploypack.preview import PreviewRegistry, reconcile_previews


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


def _port_of(result) -> int:
    return int(result.local_url.split(":")[-1].rstrip("/"))


def test_in_flight_port_reservation_survives_a_concurrent_start(monkeypatch):
    # The bug: a port picked by one start() wasn't recorded anywhere until
    # AFTER its slow build finished, so a concurrent start() for a
    # different owner could be handed the same port mid-build. Shrink the
    # range to exactly two ports so the collision is forced, not luck: the
    # reservation must make the second owner take the OTHER port.
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    monkeypatch.setattr(preview, "PORT_RANGE", range(20000, 20002))

    build_started = threading.Event()
    release_build = threading.Event()

    class BlockingRunner:
        """First build blocks (owner-a, held mid-build); later ones don't."""

        def __init__(self):
            self.calls: list[list[str]] = []
            self._builds = 0

        def __call__(self, argv, **kwargs):
            self.calls.append(argv)
            key = argv[0] if argv[0] != "docker" else f"docker:{argv[1]}"
            if key == "docker:build":
                self._builds += 1
                if self._builds == 1:
                    build_started.set()
                    release_build.wait(timeout=5)
                return cp(returncode=0)
            if key == "curl":
                return cp(stdout="200")
            return cp(returncode=0)

    registry = PreviewRegistry(run=BlockingRunner())

    result_a: dict = {}

    def run_a():
        result_a["r"] = registry.start(".", 8000, owner_key="owner-a")

    ta = threading.Thread(target=run_a)
    ta.start()
    assert build_started.wait(timeout=5)  # owner-a is mid-build, port reserved

    b = registry.start(".", 8000, owner_key="owner-b")  # concurrent, different owner

    release_build.set()
    ta.join(timeout=5)
    a = result_a["r"]

    assert a.ok is True and b.ok is True
    assert _port_of(a) != _port_of(b)     # not handed the same port
    assert registry._reserved == set()    # both reservations cleared


def test_reservation_released_after_failed_build(monkeypatch):
    # A build that fails must not leak its port reservation forever.
    # One port in range: if the failed start() leaked it, the next start()
    # would find no free port; instead it reuses the freed one.
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    monkeypatch.setattr(preview, "PORT_RANGE", range(20000, 20001))
    runner = FakeRunner({
        "docker:build": [cp(returncode=1, stderr="boom"), cp(returncode=0)],
        "docker:run": [cp(returncode=0)],
        "curl": [cp(stdout="200")],
    })
    registry = PreviewRegistry(run=runner)

    first = registry.start(".", 8000, owner_key="owner-a")
    assert first.ok is False
    assert registry._reserved == set()  # released, not leaked

    second = registry.start(".", 8000, owner_key="owner-b")
    assert second.ok is True
    assert second.local_url.endswith(":20000/")
    assert registry._reserved == set()


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


# --- preview labels stamped at creation ------------------------------------

def test_start_stamps_preview_labels_on_the_container(monkeypatch):
    # The Docker-truth reconciler can only find/age-out orphans if every
    # preview container carries shipit.preview / shipit.expires_at labels.
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    runner = FakeRunner(base_script())
    registry = PreviewRegistry(run=runner)

    registry.start(".", 8000, owner_key="1.2.3.4", ttl_seconds=3600)

    run_call = next(c for c in runner.calls if c[:2] == ["docker", "run"])
    labels = [run_call[i + 1] for i, a in enumerate(run_call) if a == "--label"]
    assert "shipit.preview=true" in labels
    assert any(l.startswith("shipit.job_id=") for l in labels)
    expires = next(l for l in labels if l.startswith("shipit.expires_at="))
    # The stamped value must be a parseable ISO-8601 UTC timestamp.
    _, _, raw = expires.partition("=")
    assert preview._parse_iso_utc(raw) is not None


# --- reconcile_previews (Docker-truth orphan reaper) -----------------------

def _iso(offset_s: float, now: float) -> str:
    return datetime.datetime.fromtimestamp(
        now + offset_s, tz=datetime.timezone.utc
    ).isoformat()


def _ps_line(container_id, job_id, expires_iso):
    return f"{container_id}\t{job_id}\t{expires_iso}"


def test_reconcile_removes_expired_orphan(monkeypatch):
    monkeypatch.setattr(preview, "docker_available", lambda: True)
    now = 1_000_000.0
    runner = FakeRunner({
        "docker:ps": [cp(stdout=_ps_line("abc123", "job-a", _iso(-60, now)))],
        "docker:rm": [cp(returncode=0)],
    })

    result = reconcile_previews(run=runner, now=now)

    assert result["docker"] is True
    assert result["checked"] == 1
    assert [r["container"] for r in result["removed"]] == ["abc123"]
    assert any(c[:3] == ["docker", "rm", "-f"] for c in runner.calls)


def test_reconcile_leaves_future_container_running(monkeypatch):
    monkeypatch.setattr(preview, "docker_available", lambda: True)
    now = 1_000_000.0
    runner = FakeRunner({
        "docker:ps": [cp(stdout=_ps_line("fresh1", "job-b", _iso(3600, now)))],
    })

    result = reconcile_previews(run=runner, now=now)

    assert result["checked"] == 1
    assert result["removed"] == []
    assert not any(c[:2] == ["docker", "rm"] for c in runner.calls)


def test_reconcile_leaves_container_with_no_valid_expiry_label(monkeypatch):
    # A preview-labelled container whose expires_at is missing/unparseable
    # must NOT be guessed-and-killed — leave it for a human to look at.
    monkeypatch.setattr(preview, "docker_available", lambda: True)
    now = 1_000_000.0
    runner = FakeRunner({
        "docker:ps": [cp(stdout=_ps_line("weird1", "job-c", ""))],
    })

    result = reconcile_previews(run=runner, now=now)

    assert result["checked"] == 1
    assert result["removed"] == []
    assert not any(c[:2] == ["docker", "rm"] for c in runner.calls)


def test_reconcile_short_circuits_when_docker_missing(monkeypatch):
    monkeypatch.setattr(preview, "docker_available", lambda: False)

    def boom(*a, **k):
        raise AssertionError("docker must not be invoked when unavailable")

    result = reconcile_previews(run=boom, now=1_000_000.0)
    assert result == {"docker": False, "checked": 0, "removed": []}


def test_reconcile_handles_mixed_batch(monkeypatch):
    monkeypatch.setattr(preview, "docker_available", lambda: True)
    now = 1_000_000.0
    stdout = "\n".join([
        _ps_line("expired1", "job-1", _iso(-10, now)),
        _ps_line("fresh1", "job-2", _iso(600, now)),
        _ps_line("expired2", "job-3", _iso(-1, now)),
        "",  # blank line must be skipped
    ])
    runner = FakeRunner({
        "docker:ps": [cp(stdout=stdout)],
        "docker:rm": [cp(returncode=0), cp(returncode=0)],
    })

    result = reconcile_previews(run=runner, now=now)

    assert result["checked"] == 3
    removed_ids = {r["container"] for r in result["removed"]}
    assert removed_ids == {"expired1", "expired2"}
    rm_targets = [c[3] for c in runner.calls if c[:3] == ["docker", "rm", "-f"]]
    assert set(rm_targets) == {"expired1", "expired2"}
