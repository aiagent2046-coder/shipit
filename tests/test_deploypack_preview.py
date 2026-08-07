"""Tests for the preview registry, with a fake docker runner — no real
Docker involved. See app/deploypack/sandbox.py and preview.py
docstrings for what's genuinely real vs. what needs a real host."""

import datetime
import subprocess
import threading


import app.deploypack.preview as preview
from app.deploypack.preview import PreviewRegistry, reconcile_previews
from app.deploypack.sandbox import SandboxResult


class FakeVerifier:
    """Stands in for sandbox_client.verify_deploy_pack (the backend→runner
    HTTP seam). Records every call — including the labels dict the preview
    layer stamps — and returns a scripted SandboxResult. No docker, no HTTP."""

    def __init__(self, results):
        self._results = list(results)
        self.calls: list[dict] = []

    def __call__(self, build_dir, host_port, container_port, *, path="/",
                 keep_alive_on_success=True, memory_limit=None, labels=None):
        self.calls.append({
            "build_dir": build_dir,
            "host_port": host_port,
            "container_port": container_port,
            "path": path,
            "keep_alive_on_success": keep_alive_on_success,
            "memory_limit": memory_limit,
            "labels": dict(labels or {}),
        })
        if not self._results:
            raise AssertionError("no scripted verify result left")
        return self._results.pop(0)


class FakeStopper:
    """Stands in for sandbox_client.preview_stop. Records (container, image)."""

    def __init__(self):
        self.calls: list[tuple] = []

    def __call__(self, container, image_tag):
        self.calls.append((container, image_tag))


def _ok(container="job-x", image_tag="img-x", detail="verified"):
    return SandboxResult(ok=True, detail=detail, build_log="",
                         container=container, image_tag=image_tag)


def _fail(detail="boot failed"):
    return SandboxResult(ok=False, detail=detail, build_log="boom",
                         container=None, image_tag=None)


def cp(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class FakeRunner:
    """Docker-CLI fake, used only by the reconcile_previews tests below
    (that module-level function still shells docker directly)."""

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


def test_start_returns_local_url_and_registers():
    verifier = FakeVerifier([_ok()])
    stopper = FakeStopper()
    registry = PreviewRegistry(verifier=verifier, stopper=stopper)

    result = registry.start(".", 8000, owner_key="1.2.3.4")

    assert result.ok is True
    assert result.local_url.startswith("http://localhost:")
    assert result.expires_at is not None
    assert registry.active_count() == 1
    # keep_alive: the preview layer asks the runner to keep the container up
    assert verifier.calls[0]["keep_alive_on_success"] is True
    # a successful boot never stops the container it just started
    assert stopper.calls == []


def test_failed_boot_registers_nothing():
    verifier = FakeVerifier([_fail()])
    stopper = FakeStopper()
    registry = PreviewRegistry(verifier=verifier, stopper=stopper)

    result = registry.start(".", 8000, owner_key="1.2.3.4")

    assert result.ok is False
    assert registry.active_count() == 0
    assert stopper.calls == []


def test_second_preview_for_same_owner_replaces_the_first():
    verifier = FakeVerifier([_ok(container="c1", image_tag="i1"),
                             _ok(container="c2", image_tag="i2")])
    stopper = FakeStopper()
    registry = PreviewRegistry(verifier=verifier, stopper=stopper)

    first = registry.start(".", 8000, owner_key="owner-a")
    second = registry.start(".", 8000, owner_key="owner-a")

    assert first.ok and second.ok
    assert registry.active_count() == 1  # replaced, not accumulated
    # the first container was stopped before the second was registered
    assert stopper.calls == [("c1", "i1")]


def test_two_different_owners_get_different_ports():
    verifier = FakeVerifier([_ok(container="c1"), _ok(container="c2")])
    stopper = FakeStopper()
    registry = PreviewRegistry(verifier=verifier, stopper=stopper)

    a = registry.start(".", 8000, owner_key="owner-a")
    b = registry.start(".", 8000, owner_key="owner-b")

    assert registry.active_count() == 2
    assert a.local_url != b.local_url
    # each got a distinct host port handed to the verifier
    assert verifier.calls[0]["host_port"] != verifier.calls[1]["host_port"]


def _port_of(result) -> int:
    return int(result.local_url.split(":")[-1].rstrip("/"))


def test_in_flight_port_reservation_survives_a_concurrent_start(monkeypatch):
    # The bug: a port picked by one start() wasn't recorded anywhere until
    # AFTER its slow build finished, so a concurrent start() for a
    # different owner could be handed the same port mid-build. Shrink the
    # range to exactly two ports so the collision is forced, not luck: the
    # reservation must make the second owner take the OTHER port.
    monkeypatch.setattr(preview, "PORT_RANGE", range(20000, 20002))

    build_started = threading.Event()
    release_build = threading.Event()

    class BlockingVerifier:
        """First verify blocks (owner-a, held mid-build); later ones don't."""

        def __init__(self):
            self.calls: list[dict] = []
            self._n = 0

        def __call__(self, build_dir, host_port, container_port, *,
                     path="/", keep_alive_on_success=True,
                     memory_limit=None, labels=None):
            self.calls.append({"host_port": host_port})
            self._n += 1
            if self._n == 1:
                build_started.set()
                release_build.wait(timeout=5)
            return _ok(container=f"c{self._n}")

    verifier = BlockingVerifier()
    registry = PreviewRegistry(verifier=verifier, stopper=FakeStopper())

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
    monkeypatch.setattr(preview, "PORT_RANGE", range(20000, 20001))
    verifier = FakeVerifier([_fail(), _ok()])
    registry = PreviewRegistry(verifier=verifier, stopper=FakeStopper())

    first = registry.start(".", 8000, owner_key="owner-a")
    assert first.ok is False
    assert registry._reserved == set()  # released, not leaked

    second = registry.start(".", 8000, owner_key="owner-b")
    assert second.ok is True
    assert second.local_url.endswith(":20000/")
    assert registry._reserved == set()


def test_reap_expired_with_controlled_clock():
    verifier = FakeVerifier([_ok(container="stale"), _ok(container="fresh")])
    stopper = FakeStopper()
    registry = PreviewRegistry(verifier=verifier, stopper=stopper)
    registry.start(".", 8000, owner_key="stale-owner", ttl_seconds=10)
    registry.start(".", 8000, owner_key="fresh-owner", ttl_seconds=10_000)

    import time
    reaped = registry.reap_expired(now=time.time() + 20)  # only ttl=10 has expired
    assert reaped == 1
    assert registry.active_count() == 1
    assert stopper.calls == [("stale", "img-x")]


def test_start_reaps_already_expired_previews_in_process():
    # In-process fallback: even if the external reap timer never fires, the
    # next start() opportunistically reaps anything already past its TTL, so
    # a stale different-owner preview is torn down without waiting.
    verifier = FakeVerifier([_ok(container="stale"), _ok(container="fresh")])
    stopper = FakeStopper()
    registry = PreviewRegistry(verifier=verifier, stopper=stopper)
    # Register an already-expired preview (TTL in the past).
    registry.start(".", 8000, owner_key="stale-owner", ttl_seconds=-1)
    assert registry.active_count() == 1

    # A fresh start() for a different owner must sweep the expired one first.
    registry.start(".", 8000, owner_key="fresh-owner", ttl_seconds=10_000)
    assert registry.active_count() == 1
    assert [i.owner_key for i in registry.list_active()] == ["fresh-owner"]
    assert stopper.calls == [("stale", "img-x")]


# --- preview labels stamped at creation ------------------------------------

def test_start_stamps_preview_labels_passed_to_the_verifier():
    # The Docker-truth reconciler can only find/age-out orphans if every
    # preview container carries shipit.preview / shipit.expires_at labels.
    # The preview layer hands those to the verifier; the runner/sandbox then
    # adds shipit.job_id and applies them as docker --label args.
    verifier = FakeVerifier([_ok()])
    registry = PreviewRegistry(verifier=verifier, stopper=FakeStopper())

    registry.start(".", 8000, owner_key="1.2.3.4", ttl_seconds=3600)

    labels = verifier.calls[0]["labels"]
    assert labels.get(preview.PREVIEW_LABEL) == "true"
    raw = labels.get(preview.EXPIRES_LABEL)
    # The stamped value must be a parseable ISO-8601 UTC timestamp.
    assert raw is not None and preview._parse_iso_utc(raw) is not None


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
