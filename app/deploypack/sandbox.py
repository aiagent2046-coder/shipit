"""Sandbox verification: docker build + docker run + curl, for real.

This is the whole point of the plan's rule "not done if it doesn't
boot": a generated Dockerfile is worthless if nobody ever confirms it
actually builds and serves a 200. This module does that confirmation
with real subprocess calls — no LLM, no agents, just docker and curl.

`run` is injectable (defaults to subprocess.run) so tests can exercise
the orchestration — timeouts, cleanup-on-failure, retry/poll loop —
without a real Docker daemon. See tests/test_deploypack_sandbox.py.

Confirmed for real on a GitHub Actions runner (this dev sandbox has
no `docker` binary itself) — see .github/workflows/smoke-deploy-pack.yml.
The `keep_alive_on_success` path (for preview hosting) is unit-tested
with a fake runner but not yet re-confirmed the same way — do that
before trusting a kept-alive container in production.
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
    # Populated whenever a container actually started, success or not,
    # so a caller that wants to keep it alive (previews) can find it.
    container: str | None = None
    image_tag: str | None = None


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
    keep_alive_on_success: bool = False,
    memory_limit: str | None = None,
    run: Runner = subprocess.run,
) -> SandboxResult:
    """Build the image in `build_dir`, run it, poll `path` until it
    answers 200 or `boot_timeout_s` elapses.

    Tears the container and image down in every case EXCEPT: it booted
    successfully AND `keep_alive_on_success=True` (used by preview
    hosting, which needs the container to keep running after this
    returns). The caller then owns stopping it — see app/deploypack/preview.py.
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
            image_tag=tag,
        )

    # Past this point the image exists on disk regardless of outcome —
    # every exit path below must go through the outer `finally` so a
    # free, unpaid Pack run never leaks a built image. Exception: a
    # successful boot when the caller asked us to keep it alive
    # (previews) — `keep_container` decides that below.
    container = f"{tag}-run"
    container_started = False
    keep_container = False
    try:
        # Bind the published port to loopback only. Docker's default
        # `-p host:container` binds 0.0.0.0 (every interface), which would
        # expose an unpaid preview of untrusted client code to the whole
        # network despite the `local_url` naming — pin it to 127.0.0.1 so it
        # is reachable only from the host running this process.
        run_cmd = ["docker", "run", "-d", "--rm", "--name", container,
                   "-p", f"127.0.0.1:{host_port}:{container_port}"]
        if memory_limit:
            run_cmd += ["--memory", memory_limit]
        run_cmd.append(tag)
        try:
            run(run_cmd, capture_output=True, text=True, timeout=30, check=True)
            container_started = True
        except subprocess.CalledProcessError as exc:
            return SandboxResult(
                ok=False, detail="docker run failed",
                build_log=(exc.stdout or "") + (exc.stderr or ""),
                container=container, image_tag=tag,
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
                keep_container = keep_alive_on_success
                return SandboxResult(ok=True, detail="HTTP 200 on " + path,
                                      container=container, image_tag=tag)
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
            container=container, image_tag=tag,
        )
    finally:
        if container_started and not keep_container:
            run(["docker", "stop", container], capture_output=True, text=True, timeout=15)
        # --rm on the container handles the container itself; the image
        # we built is not auto-removed and would otherwise accumulate on
        # disk with every free, unpaid Pack run. Kept-alive previews
        # keep their image too, obviously — the container needs it.
        if not keep_container:
            run(["docker", "rmi", "-f", tag], capture_output=True, text=True, timeout=15)
