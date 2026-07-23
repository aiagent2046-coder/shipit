"""Behavioural regression guard for the sandbox-runner build-dir permission bug.

Background (real prod incident): the systemd unit once set a process-global
``UMask=0117``. systemd applies ``UMask=`` to EVERY file the process creates, so
``tempfile.mkdtemp()`` (0700) became 0600 — a directory without its execute
(search) bit — and the runner could not create files inside its own build dir.
Every deploy/fixpack run died with::

    PermissionError: [Errno 13] Permission denied: '/tmp/shipit-runner-build-XXXX/.env.example'

The unit-file guard (tests/test_runner_service_unit.py) asserts no ``UMask=`` is
present. THIS script proves the behaviour for real: it runs the exact filesystem
operations the runner performs (mkdtemp + a top-level file + a nested dir/file,
mimicking zip extraction) under the SAME sandbox directives the shipped unit
uses, via ``systemd-run``.

Two runs:
  * POSITIVE — the shipped directives as-is: must SUCCEED. If someone reintroduces
    ``UMask=0117`` (or anything that strips the dir execute bit) into the unit,
    this run inherits it and FAILS, turning the incident into a red CI check.
  * NEGATIVE (teeth) — the shipped directives PLUS ``UMask=0117``: must FAIL, so a
    probe that silently stopped reproducing the condition can't pass unnoticed.

If systemd/systemd-run is unavailable (not a systemd host), the check SKIPs with
a clear message rather than false-failing.
"""

from __future__ import annotations

import os
import pwd
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
UNIT = REPO_ROOT / "deploy" / "sandbox-runner" / "sandbox-runner.service"

# The bug only bites a NON-root process: root has CAP_DAC_OVERRIDE and can write
# into a 0600 dir regardless of the missing execute bit, so a root probe would
# never reproduce it (and prod runs as shipit-runner, never root). Run the probe
# under a dedicated unprivileged user — the CI job creates it; override with env.
PROBE_USER = os.environ.get("RUNNER_PROBE_USER", "shipit-runner")

# Use the system interpreter: it must be executable by PROBE_USER, and the probe
# only needs the stdlib (the prod runner uses its own venv python, likewise owned
# by / readable to shipit-runner).
_PROBE_PYTHON = "/usr/bin/python3" if Path("/usr/bin/python3").exists() else sys.executable

# The exec-sandbox directives from the unit that are (a) meaningful to the
# filesystem behaviour we're reproducing and (b) safe to pass to a transient
# systemd-run scope without a pre-existing user/checkout. We deliberately drop
# User/Group/EnvironmentFile/ExecStart/WorkingDirectory/RuntimeDirectory — the
# bug is uid-independent (proven on prod) and about /tmp build dirs.
_SANDBOX_KEYS = {
    "UMask",
    "ProtectSystem",
    "ProtectHome",
    "PrivateTmp",
    "ProtectKernelTunables",
    "ProtectKernelModules",
    "ProtectControlGroups",
    "RestrictSUIDSGID",
    "LockPersonality",
    "NoNewPrivileges",
    "DevicePolicy",
}

# Mimics app/runner/main.py: mkdtemp build dir + extract a top-level file
# (.env.example was the exact prod failure) and a nested dir/file (zip wrappers).
_PROBE = (
    "import os, tempfile;"
    "d = tempfile.mkdtemp(prefix='shipit-runner-build-');"
    "open(os.path.join(d, '.env.example'), 'wb').close();"
    "nd = os.path.join(d, 'app', 'sub');"
    "os.makedirs(nd);"
    "open(os.path.join(nd, 'main.py'), 'wb').close();"
    "print('BUILD_DIR_OK', d)"
)


def _shipped_sandbox_props() -> list[str]:
    props: list[str] = []
    in_service = False
    for line in UNIT.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_service = stripped == "[Service]"
            continue
        if not in_service or stripped.startswith("#") or "=" not in stripped:
            continue
        key = stripped.split("=", 1)[0].strip()
        if key in _SANDBOX_KEYS:
            props.append(stripped)
    return props


def _run_under_systemd(props: list[str]) -> subprocess.CompletedProcess:
    # Run the scope AS the unprivileged probe user (never root) so DAC bits are
    # actually enforced — the whole point of the reproduction.
    cmd = ["sudo", "systemd-run", "--wait", "--pipe", "--quiet", "--collect",
           "-p", f"User={PROBE_USER}", "-p", f"Group={PROBE_USER}"]
    for p in props:
        cmd += ["-p", p]
    cmd += ["--", _PROBE_PYTHON, "-c", _PROBE]
    print("  $ " + " ".join(cmd), flush=True)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)


def main() -> int:
    if shutil.which("systemd-run") is None:
        print("SKIP: systemd-run not available on this host — cannot run the "
              "behavioural guard (the unit-file guard still runs in pytest).")
        return 0
    try:
        pwd.getpwnam(PROBE_USER)
    except KeyError:
        print(f"SKIP: probe user {PROBE_USER!r} does not exist on this host — the "
              f"CI job creates it; set RUNNER_PROBE_USER to reproduce locally.")
        return 0

    shipped = _shipped_sandbox_props()
    print(f"shipped sandbox directives: {shipped or '(none)'}", flush=True)

    print("\n=== POSITIVE: runner build dir under the shipped unit directives ===",
          flush=True)
    pos = _run_under_systemd(shipped)
    print(pos.stdout, end="", flush=True)
    if pos.returncode != 0 or "BUILD_DIR_OK" not in pos.stdout:
        print("FAIL: the shipped sandbox directives prevent the runner from "
              "creating files in its own mkdtemp build dir.", file=sys.stderr)
        print(pos.stderr, file=sys.stderr)
        print("If a UMask= (or similar) was added to sandbox-runner.service, "
              "remove it — see the unit's warning comment.", file=sys.stderr)
        return 1
    print("OK: build dir usable under the shipped directives.", flush=True)

    print("\n=== NEGATIVE (teeth): same directives + UMask=0117 must FAIL ===",
          flush=True)
    neg = _run_under_systemd([p for p in shipped if not p.startswith("UMask=")]
                             + ["UMask=0117"])
    print(neg.stdout, end="", flush=True)
    if neg.returncode == 0 and "BUILD_DIR_OK" in neg.stdout:
        print("FAIL: probe unexpectedly SUCCEEDED with UMask=0117 — the guard no "
              "longer reproduces the bug and would not catch a regression.",
              file=sys.stderr)
        return 1
    print("OK: UMask=0117 reproduces the failure (guard has teeth).", flush=True)

    print("\nPASS: build-dir permission guard verified both ways.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
