"""Behavioural regression guard for the sandbox-runner bind-mount namespace bug.

Background (real prod incident, distinct from the UMask one): the runner unit
keeps ``PrivateTmp=true``, which gives the runner a PRIVATE ``/tmp`` in its own
mount namespace — invisible to dockerd, which lives in the HOST mount namespace.
The runner extracts each client zip into a ``tempfile.mkdtemp()`` dir and then
bind-mounts it into the fixpack install/test containers
(``docker run -v <dir>:/work``). If that dir is under ``/tmp``, the daemon
resolves a path that does not exist in ITS namespace and mounts an EMPTY
``/work`` (docker silently auto-creates the missing bind source), so every
fixpack run died with::

    RunResult(error='dependency install failed (exit 2)')

…because ``/work/requirements.txt`` "did not exist" — even though the file was
right there in the runner's own private ``/tmp``.

The fix: the unit sets ``StateDirectory=shipit-runner`` +
``Environment=TMPDIR=/var/lib/shipit-runner``, so ``mkdtemp`` builds OUTSIDE
``/tmp`` (a path both the runner and dockerd resolve to the same inode).

This script proves the behaviour for real — it runs the exact operation the
runner performs (mkdtemp under the SHIPPED ``TMPDIR`` + a real
``docker run -v <dir>:/work``) under the SHIPPED ``PrivateTmp``/``StateDirectory``
directives, via ``systemd-run``, and checks the container actually SEES the file:

  * POSITIVE — shipped directives (PrivateTmp + StateDirectory + TMPDIR): the
    container must read back the sentinel we wrote. If someone drops ``TMPDIR``
    (or repoints it at ``/tmp``) while ``PrivateTmp`` stays on, mkdtemp falls
    back to the private ``/tmp`` and the container sees an EMPTY ``/work`` — this
    run FAILS, turning the incident into a red CI check.
  * NEGATIVE (teeth) — force ``TMPDIR=/tmp`` under ``PrivateTmp=true``: the
    container MUST see an empty ``/work``, so a probe that silently stopped
    reproducing the namespace split can't pass unnoticed.

The bug is uid-INDEPENDENT (unlike the UMask/DAC one): PrivateTmp remaps ``/tmp``
for every uid, so the probe runs as root (systemd-run's default) and talks to the
real docker socket directly — the daemon resolves the bind source in its own
namespace regardless of who asked or whether a proxy is in the path.

SKIPs cleanly (rc 0) when systemd-run or docker is unavailable.
"""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
UNIT = REPO_ROOT / "deploy" / "sandbox-runner" / "sandbox-runner.service"

_PROBE_PYTHON = "/usr/bin/python3" if Path("/usr/bin/python3").exists() else sys.executable

# A tiny always-present image is enough — we only need `cat` inside a container
# that has our dir bind-mounted at /work.
PROBE_IMAGE = os.environ.get("BINDMOUNT_PROBE_IMAGE", "busybox")

# The probe: mkdtemp (honours TMPDIR), write a sentinel + a nested
# requirements.txt (mirroring a real client zip), then bind-mount that dir into a
# container and print what the container sees. The parent checks the sentinel
# round-trips. `os.environ['SENTINEL']` and `TMPDIR` are injected via systemd-run.
_PROBE = (
    "import os, tempfile, subprocess, sys;"
    "tok = os.environ['SENTINEL'];"
    "d = tempfile.mkdtemp(prefix='shipit-runner-build-');"
    "open(os.path.join(d, 'requirements.txt'), 'w').write('six\\n');"
    "open(os.path.join(d, 'sentinel'), 'w').write(tok);"
    "sys.stderr.write('host build dir: %s (TMPDIR=%s)\\n' % (d, os.environ.get('TMPDIR')));"
    "p = subprocess.run(["
    "  'docker', 'run', '--rm', '-v', d + ':/work', '" + PROBE_IMAGE + "',"
    "  'sh', '-c', 'cat /work/sentinel 2>/dev/null; echo; echo FILES=; ls -1 /work 2>/dev/null'"
    "], capture_output=True, text=True, timeout=120);"
    "sys.stdout.write('<<<CONTAINER\\n' + p.stdout + '\\nCONTAINER>>>\\n');"
    "sys.stderr.write(p.stderr);"
    "sys.exit(0 if p.returncode == 0 else 3)"
)


def _shipped(key: str) -> str | None:
    """Return the value of a [Service] key in the shipped unit (last wins), or
    None. Handles the two forms we care about: ``Key=Value`` and, for
    ``Environment=``, ``Environment=NAME=VALUE`` (we resolve NAME=key)."""
    in_service = False
    found: str | None = None
    for line in UNIT.read_text().splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            in_service = s == "[Service]"
            continue
        if not in_service or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        if k.strip() == key:
            found = v.strip()
    return found


def _shipped_env(name: str) -> str | None:
    """Value of an ``Environment=NAME=VALUE`` assignment in the unit."""
    in_service = False
    found: str | None = None
    for line in UNIT.read_text().splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            in_service = s == "[Service]"
            continue
        if not in_service or s.startswith("#") or not s.startswith("Environment="):
            continue
        # systemd allows several space-separated NAME=VALUE per Environment= line
        for assignment in s[len("Environment="):].split():
            if assignment.startswith(name + "="):
                found = assignment.split("=", 1)[1]
    return found


def _run(props: list[str], sentinel: str) -> subprocess.CompletedProcess:
    cmd = ["sudo", "systemd-run", "--wait", "--pipe", "--quiet", "--collect"]
    for p in props:
        cmd += ["-p", p]
    cmd += ["-p", f"Environment=SENTINEL={sentinel}",
            "--", _PROBE_PYTHON, "-c", _PROBE]
    print("  $ " + " ".join(cmd), flush=True)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=180)


def _container_view(stdout: str) -> str:
    start = stdout.find("<<<CONTAINER\n")
    end = stdout.find("\nCONTAINER>>>")
    if start == -1 or end == -1:
        return ""
    return stdout[start + len("<<<CONTAINER\n"):end]


def main() -> int:
    if shutil.which("systemd-run") is None:
        print("SKIP: systemd-run not available — cannot run the namespace guard.")
        return 0
    if shutil.which("docker") is None:
        print("SKIP: docker not available — cannot run the namespace guard.")
        return 0

    private_tmp = _shipped("PrivateTmp") or "true"
    state_dir = _shipped("StateDirectory")
    tmpdir = _shipped_env("TMPDIR")
    print(f"shipped: PrivateTmp={private_tmp} StateDirectory={state_dir!r} "
          f"TMPDIR={tmpdir!r}", flush=True)

    if not state_dir or not tmpdir:
        print("FAIL: the shipped unit must set StateDirectory= and "
              "Environment=TMPDIR= (a scratch dir OUTSIDE /tmp) so fixpack build "
              "dirs are visible to dockerd across the PrivateTmp namespace. See "
              "the unit comment.", file=sys.stderr)
        return 1

    # ---- POSITIVE: the shipped directives must let the container see the file.
    print("\n=== POSITIVE: docker -v <mkdtemp under shipped TMPDIR> sees the file ===",
          flush=True)
    tok = secrets.token_hex(16)
    pos = _run(
        [f"PrivateTmp={private_tmp}",
         f"StateDirectory={state_dir}",
         f"Environment=TMPDIR={tmpdir}"],
        tok,
    )
    print(pos.stdout, end="", flush=True)
    if pos.stderr:
        print(pos.stderr, end="", file=sys.stderr, flush=True)
    view = _container_view(pos.stdout)
    if pos.returncode != 0 or tok not in view:
        print("\nFAIL: the container did NOT see the file the runner wrote — its "
              "bind-mounted /work is empty. The scratch dir is not visible to "
              "dockerd across the PrivateTmp mount namespace. Ensure the unit sets "
              "StateDirectory + Environment=TMPDIR to a path OUTSIDE /tmp.",
              file=sys.stderr)
        return 1
    print("OK: container read back the sentinel — bind mount crosses the namespace.",
          flush=True)

    # ---- NEGATIVE (teeth): TMPDIR=/tmp under PrivateTmp MUST break the mount.
    print("\n=== NEGATIVE (teeth): TMPDIR=/tmp under PrivateTmp must mount EMPTY ===",
          flush=True)
    tok2 = secrets.token_hex(16)
    neg = _run([f"PrivateTmp={private_tmp}", "Environment=TMPDIR=/tmp"], tok2)
    print(neg.stdout, end="", flush=True)
    if neg.stderr:
        print(neg.stderr, end="", file=sys.stderr, flush=True)
    view2 = _container_view(neg.stdout)
    if tok2 in view2:
        print("\nFAIL: with TMPDIR=/tmp under PrivateTmp the container UNEXPECTEDLY "
              "saw the file — the guard no longer reproduces the namespace split "
              "and would not catch a regression.", file=sys.stderr)
        return 1
    print("OK: /tmp under PrivateTmp gives the container an empty /work "
          "(bug reproduced — guard has teeth).", flush=True)

    print("\nPASS: bind-mount namespace guard verified both ways.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
