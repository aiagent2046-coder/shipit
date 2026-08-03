"""Guards on the shipped sandbox-runner systemd unit.

Regression cover for a real prod incident: the unit once carried a
process-global ``UMask=0117`` (intended only to tighten the socket). systemd
applies ``UMask=`` to EVERY file the process creates, so the runner's
``tempfile.mkdtemp()`` build dirs became 0600 — a directory without its execute
bit — and every deploy/fixpack run died with ``PermissionError`` when it tried
to extract a client zip into its own build dir.

These are cheap, no-systemd checks that run in the normal suite. The behavioural
proof (actually running under the sandbox directives) lives in
``scripts/check_runner_build_dir_perms.py`` and the e2e workflow.
"""

from __future__ import annotations

import configparser
from pathlib import Path

UNIT = Path(__file__).resolve().parent.parent / "deploy" / "sandbox-runner" / "sandbox-runner.service"


def _service_section() -> dict[str, str]:
    # systemd units are INI-ish; allow duplicate keys, keep the [Service] block.
    cp = configparser.RawConfigParser(strict=False)
    cp.optionxform = str  # preserve case (UMask, not umask)
    cp.read_string(UNIT.read_text())
    assert cp.has_section("Service"), "unit is missing a [Service] section"
    return dict(cp.items("Service"))


def _environment_value(name: str) -> str | None:
    """Value of an ``Environment=NAME=VALUE`` assignment in [Service]. Parsed
    from raw text because the unit has several ``Environment=`` lines (configparser
    would collapse the duplicate key to just the last one)."""
    in_service = False
    found: str | None = None
    for line in UNIT.read_text().splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            in_service = s == "[Service]"
            continue
        if not in_service or s.startswith("#") or not s.startswith("Environment="):
            continue
        for assignment in s[len("Environment="):].split():
            if assignment.startswith(name + "="):
                found = assignment.split("=", 1)[1]
    return found


def test_unit_sets_no_process_global_umask() -> None:
    """A process-global UMask strips the execute bit off mkdtemp build dirs and
    breaks the runner. Access to the socket is gated by RuntimeDirectoryMode
    instead — never reintroduce UMask here."""
    service = _service_section()
    assert "UMask" not in service, (
        "sandbox-runner.service must not set a process-global UMask — it applies "
        "to the runner's mkdtemp build dirs and breaks zip extraction (EACCES). "
        "Gate the socket via RuntimeDirectoryMode instead."
    )


def test_unit_keeps_the_runtime_dir_gate() -> None:
    """The 0710 runtime dir (owner + group traverse, world cannot) is what
    actually gates socket access, so it must stay."""
    service = _service_section()
    assert service.get("RuntimeDirectory") == "shipit-runner"
    assert service.get("RuntimeDirectoryMode") == "0710"


def test_scratch_dir_lives_outside_tmp() -> None:
    """PrivateTmp gives the runner a private /tmp invisible to dockerd, so the
    mkdtemp build dir it bind-mounts into fixpack containers MUST live outside
    /tmp (via StateDirectory + TMPDIR) or /work mounts empty and every install
    fails. The behavioural proof is scripts/check_runner_bindmount_namespace.py;
    this is the cheap always-run guard."""
    service = _service_section()
    # PrivateTmp stays on (defence for other /tmp ops); that is precisely why the
    # scratch dir cannot live under /tmp.
    assert service.get("PrivateTmp") == "true"
    assert service.get("StateDirectory"), (
        "unit must set StateDirectory so systemd provides a writable scratch area "
        "OUTSIDE /tmp (a build dir under /tmp is invisible to dockerd across the "
        "PrivateTmp mount namespace)."
    )
    tmpdir = _environment_value("TMPDIR")
    assert tmpdir, "unit must set Environment=TMPDIR so mkdtemp builds outside /tmp"
    assert not tmpdir.startswith("/tmp"), (
        f"TMPDIR={tmpdir!r} is under /tmp — with PrivateTmp on, the runner's "
        "bind-mounted build dir would be invisible to dockerd and /work would "
        "mount empty. Point TMPDIR at a non-/tmp path (e.g. the StateDirectory)."
    )
    # The StateDirectory (relative to /var/lib) should be where TMPDIR points.
    assert tmpdir == f"/var/lib/{service['StateDirectory']}", (
        "TMPDIR should point at the StateDirectory systemd creates "
        f"(/var/lib/{service['StateDirectory']}), got {tmpdir!r}."
    )
