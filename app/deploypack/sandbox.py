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

import os
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

Runner = Callable[..., subprocess.CompletedProcess]

# Hardening flags for the container running untrusted client code, on top
# of --memory:
#   --pids-limit=256                 fork-bomb guard (cap process count)
#   --cpus=1                         one CPU max, so a client can't peg the host
#   --security-opt=no-new-privileges block setuid privilege escalation inside
#   --cap-drop=ALL                   drop all Linux capabilities
#   --ulimit nofile / fsize          cap open descriptors and max file size so a
#                                    client can't exhaust host FDs or fill disk
# --read-only / --user / --network are applied separately (conditional on env
# toggles) — see _readonly_argv / _user_argv / _network_argv.
_RUN_HARDENING = [
    "--pids-limit=256",
    "--cpus=1",
    "--security-opt=no-new-privileges",
    "--cap-drop=ALL",
    "--ulimit", "nofile=1024:1024",
    "--ulimit", "fsize=1073741824",
]

# Cap how much build output we keep in memory / persist (an adversarial
# Dockerfile RUN step can print unboundedly).
MAX_BUILD_LOG_BYTES = 64 * 1024

# Read-only rootfs for the preview/boot container (requirement 3.3). The app
# is baked into the image; at runtime it should only need scratch in /tmp.
# Toggle off (DEPLOYPACK_READONLY_ROOTFS=0) for a stack that must write to its
# own rootfs (e.g. a build cache), rather than deleting the flag in code.
DEPLOYPACK_READONLY_ROOTFS = (
    os.environ.get("DEPLOYPACK_READONLY_ROOTFS", "1").lower() not in ("0", "false", "")
)

# Optional non-root user for the preview container. OFF by default: a generated
# app may bind a low port (e.g. Vite serves on container :80, which needs root)
# or write to its own rootfs, so forcing a uid would break legitimate apps. Set
# DEPLOYPACK_RUN_AS_USER ("1000:1000") to opt in where the image allows it.
DEPLOYPACK_RUN_AS_USER = os.environ.get("DEPLOYPACK_RUN_AS_USER", "")

# Isolated no-egress network for the running preview (requirement 3.5). The
# preview serves untrusted client code for up to 24h; by default it must not be
# able to make outbound connections. This names a Docker network that MUST be
# created at deploy time as internal (no gateway to the internet), e.g.
#   docker network create --internal shipit-preview
# mirroring how the fixpack egress proxy (Squid) is host-configured, not built
# here. Published ports still reach the container from the host (loopback bind).
# Set empty to disable (open bridge). Runtime internet is opt-in via
# DEPLOYPACK_ALLOW_RUNTIME_NETWORK for the rare app that needs it at run time.
DEPLOYPACK_PREVIEW_NETWORK = os.environ.get("DEPLOYPACK_PREVIEW_NETWORK", "shipit-preview")
DEPLOYPACK_ALLOW_RUNTIME_NETWORK = (
    os.environ.get("DEPLOYPACK_ALLOW_RUNTIME_NETWORK", "0").lower() in ("1", "true")
)

# Egress-allowlist proxy for the BUILD step (docker build RUN pip/npm/apt).
# Same intent as the fixpack install proxy: package registries only, not the
# open internet. Defaults to the fixpack proxy URL so one host Squid covers
# both; empty disables (open build). Applied to docker build via predefined
# proxy build-args + --add-host (see _build_proxy_argv).
DEPLOYPACK_BUILD_PROXY_URL = os.environ.get(
    "DEPLOYPACK_BUILD_PROXY_URL",
    os.environ.get("FIXPACK_INSTALL_PROXY_URL", "http://host.docker.internal:3128"),
)


def _clip_build_log(text: str) -> str:
    """Bound a build log to MAX_BUILD_LOG_BYTES, keeping head+tail."""
    if len(text) <= MAX_BUILD_LOG_BYTES:
        return text
    keep = MAX_BUILD_LOG_BYTES // 2
    dropped = len(text) - 2 * keep
    return f"{text[:keep]}\n...[truncated {dropped} chars]...\n{text[-keep:]}"


def _readonly_argv() -> list[str]:
    """--read-only rootfs + a writable /tmp tmpfs for the preview container.
    Empty when DEPLOYPACK_READONLY_ROOTFS is disabled."""
    if not DEPLOYPACK_READONLY_ROOTFS:
        return []
    return ["--read-only", "--tmpfs", "/tmp"]


def _user_argv() -> list[str]:
    """--user <uid:gid> for the preview container, or empty (image default)."""
    return ["--user", DEPLOYPACK_RUN_AS_USER] if DEPLOYPACK_RUN_AS_USER else []


def _network_argv() -> list[str]:
    """--network <isolated> so the preview cannot reach the internet at run
    time. Empty when runtime network is explicitly allowed or no isolated
    network is configured (open bridge — the pre-hardening behaviour)."""
    if DEPLOYPACK_ALLOW_RUNTIME_NETWORK or not DEPLOYPACK_PREVIEW_NETWORK:
        return []
    return ["--network", DEPLOYPACK_PREVIEW_NETWORK]


def _build_proxy_argv() -> list[str]:
    """docker build flags routing the build's egress through the host's
    allowlisting forward proxy (registries only). Empty when the proxy URL is
    cleared, so a host without a proxy still builds (open network)."""
    proxy = DEPLOYPACK_BUILD_PROXY_URL
    if not proxy:
        return []
    no_proxy = "localhost,127.0.0.1"
    return [
        "--add-host=host.docker.internal:host-gateway",
        "--build-arg", f"HTTP_PROXY={proxy}",
        "--build-arg", f"HTTPS_PROXY={proxy}",
        "--build-arg", f"NO_PROXY={no_proxy}",
        "--build-arg", f"http_proxy={proxy}",
        "--build-arg", f"https_proxy={proxy}",
        "--build-arg", f"no_proxy={no_proxy}",
    ]


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
    labels: dict[str, str] | None = None,
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
        ["docker", "build", *_build_proxy_argv(), "-t", tag, str(build_dir)],
        capture_output=True, text=True, timeout=build_timeout_s,
    )
    if build.returncode != 0:
        return SandboxResult(
            ok=False, detail="docker build failed",
            build_log=_clip_build_log((build.stdout or "") + (build.stderr or "")),
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
                   "-p", f"127.0.0.1:{host_port}:{container_port}",
                   *_network_argv(), *_user_argv(), *_readonly_argv(),
                   *_RUN_HARDENING]
        if memory_limit:
            run_cmd += ["--memory", memory_limit]
        if labels:
            # The container's own name IS its job identity, so always stamp
            # it as shipit.job_id (caller may override). These labels are how
            # reconcile_previews finds and ages out orphan containers from
            # Docker itself after a process restart — see preview.py.
            for key, value in {"shipit.job_id": container, **labels}.items():
                run_cmd += ["--label", f"{key}={value}"]
        run_cmd.append(tag)
        try:
            run(run_cmd, capture_output=True, text=True, timeout=30, check=True)
            container_started = True
        except subprocess.CalledProcessError as exc:
            return SandboxResult(
                ok=False, detail="docker run failed",
                build_log=_clip_build_log((exc.stdout or "") + (exc.stderr or "")),
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
            build_log=_clip_build_log((logs.stdout or "") + (logs.stderr or "")),
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
