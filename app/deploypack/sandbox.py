"""Sandbox verification: docker build + docker run + curl, for real.

This is the whole point of the plan's rule "not done if it doesn't
boot": a generated Dockerfile is worthless if nobody ever confirms it
actually builds and serves a 200. This module does that confirmation
with real subprocess calls — no LLM, no agents, just docker and curl.

`run` is injectable (defaults to subprocess.run) so tests can exercise
the orchestration — timeouts, cleanup-on-failure, retry/poll loop —
without a real Docker daemon. See tests/test_deploypack_sandbox.py.

Known gap: this was developed and unit-tested in a sandbox that has no
`docker` binary at all, so the real build+run+curl path has NOT been
exercised end-to-end against a real generated Dockerfile yet. It needs
to be run once on a host with Docker (a dev machine or a CI runner)
before anyone trusts "verified" as a real signal.
"""

from __future__ import annotations

import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

Runner = Callable[..., subprocess.CompletedProcess]


@dataclass
class SandboxResult:
    ok: bool
    detail: str
    build_log: str = ""


def docker_available() -> bool:
    return shutil.which("docker") is not None


def verify_deploy_pack(
    build_dir: Path,
    host_port: int,
    container_port: int,
    path: str = "/",
    build_timeout_s: int = 300,
    boot_timeout_s: int = 60,
    poll_interval_s: float = 1.0,
    run: Runner = subprocess.run,
) -> SandboxResult:
    """Build the image in `build_dir`, run it, poll `path` until it
    answers 200 or `boot_timeout_s` elapses. Always tears the container
    down, even on failure.
    """
    if not docker_available():
        return SandboxResult(
            ok=False,
            detail="docker binary not found on this host — cannot verify",
        )

    tag = f"shipit-verify-{uuid.uuid4().hex[:12]}"
    build = run(
        ["docker", "build", "-t", tag, str(build_dir)],
        capture_output=True, text=True, timeout=build_timeout_s,
    )
    if build.returncode != 0:
        return SandboxResult(
            ok=False, detail="docker build failed",
            build_log=(build.stdout or "") + (build.stderr or ""),
        )

    # Past this point the image exists on disk regardless of outcome —
    # every exit path below must go through the outer `finally` so a
    # free, unpaid Pack run never leaks a built image.
    container = f"{tag}-run"
    container_started = False
    try:
        try:
            run(
                ["docker", "run", "-d", "--rm", "--name", container,
                 "-p", f"{host_port}:{container_port}", tag],
                capture_output=True, text=True, timeout=30, check=True,
            )
            container_started = True
        except subprocess.CalledProcessError as exc:
            return SandboxResult(
                ok=False, detail="docker run failed",
                build_log=(exc.stdout or "") + (exc.stderr or ""),
            )

        deadline = time.monotonic() + boot_timeout_s
        url = f"http://localhost:{host_port}{path}"
        last_code = None
        while time.monotonic() < deadline:
            probe = run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", url],
                capture_output=True, text=True, timeout=10,
            )
            last_code = probe.stdout.strip()
            if last_code == "200":
                return SandboxResult(ok=True, detail="HTTP 200 on " + path)
            time.sleep(poll_interval_s)

        logs = run(
            ["docker", "logs", container],
            capture_output=True, text=True, timeout=10,
        )
        return SandboxResult(
            ok=False,
            detail=f"never returned 200 on {path} within {boot_timeout_s}s "
                   f"(last: {last_code!r})",
            build_log=(logs.stdout or "") + (logs.stderr or ""),
        )
    finally:
        if container_started:
            run(["docker", "stop", container], capture_output=True, text=True, timeout=15)
        # --rm on the container handles the container itself; the image
        # we built is not auto-removed and would otherwise accumulate on
        # disk with every free, unpaid Pack run.
        run(["docker", "rmi", "-f", tag], capture_output=True, text=True, timeout=15)
