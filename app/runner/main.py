"""sandbox-runner — the out-of-process docker executor (Stage-3 Variant A).

Runs as an unprivileged system user (``shipit-runner``) with its OWN reduced
EnvironmentFile that holds NO prod secrets, and talks to dockerd only through a
docker-socket-proxy (``DOCKER_HOST=tcp://…``), so the backend process — which
holds DATABASE_URL / billing / pepper / Telegram / admin tokens — never shells
docker itself. See app/sandbox_client.py for the backend side and
deploy/sandbox-runner/ for the systemd + proxy wiring.

Each endpoint imports and calls the UNCHANGED real implementation
(app/deploypack/sandbox.py, app/deploypack/preview.py,
app/fixpack/semantic_check.py), so the §5 container hardening is identical here —
this service only changes *which process/user* runs docker, not *what flags* it
runs with.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import subprocess
import tempfile
import zipfile
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from starlette.concurrency import run_in_threadpool

from app.deploypack.preview import reconcile_previews
from app.deploypack.sandbox import verify_deploy_pack
from app.fixpack.generate import FixpackPlan
from app.fixpack.semantic_check import RunResult, TestRunner, minimal_check, run_suite
from app.fixpack.semantic_check import run_verification_profile
from app.fixpack.verification import (
    verification_profile_from_wire,
    verification_stage_to_wire,
)
from app.proof.cors_probe import run_cors_probe
from app.runner.auth import require_sandbox_token

app = FastAPI(title="shipit-sandbox-runner", version="0.1.0")

# O3: bound concurrent docker builds/runs independently of the backend's
# threadpool. Default 2 == the prod VPS vCPU count, so N simultaneous 1-CPU
# builds can't oversubscribe the host. Each guarded endpoint acquires this
# before doing blocking docker work.
SANDBOX_RUNNER_CONCURRENCY = int(os.environ.get("SANDBOX_RUNNER_CONCURRENCY", "2"))
_docker_semaphore = asyncio.Semaphore(SANDBOX_RUNNER_CONCURRENCY)


def _manifest(request: Request) -> dict:
    raw = request.headers.get("x-sandbox-request", "")
    return json.loads(raw) if raw else {}


async def _guarded(fn, *args, **kwargs):
    """Run a blocking docker operation off the event loop, under the
    concurrency semaphore."""
    async with _docker_semaphore:
        return await run_in_threadpool(fn, *args, **kwargs)


def _extract_zip(raw: bytes, dest: Path) -> None:
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        zf.extractall(dest)


@app.get("/healthz")
async def healthz() -> dict:
    """Liveness + a real docker-daemon reachability check (O2): `docker version`
    round-trips through the socket-proxy to dockerd. Cheap — no container is
    started. Returns the daemon's server version so the backend can tell a live
    runner from a live-runner-but-dead-docker."""
    try:
        proc = await run_in_threadpool(
            subprocess.run,
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "docker": False, "detail": type(exc).__name__}
    if proc.returncode != 0:
        return {"ok": False, "docker": False,
                "detail": (proc.stderr or "").strip()[:200]}
    return {"ok": True, "docker": True, "docker_version": proc.stdout.strip()}


@app.post("/deploypack/verify")
async def deploypack_verify(
    request: Request, _: None = Depends(require_sandbox_token)
) -> dict:
    """Reconstruct the build context zip on the runner's own filesystem, then
    run the real verify_deploy_pack (build + run + curl boot-check)."""
    raw = await request.body()
    m = _manifest(request)

    def _do() -> dict:
        build_dir = Path(tempfile.mkdtemp(prefix="shipit-runner-build-"))
        try:
            _extract_zip(raw, build_dir)
            result = verify_deploy_pack(
                build_dir,
                m["host_port"], m["container_port"],
                path=m.get("path", "/"),
                build_timeout_s=m.get("build_timeout_s", 300),
                boot_timeout_s=m.get("boot_timeout_s", 60),
                poll_interval_s=m.get("poll_interval_s", 1.0),
                keep_alive_on_success=m.get("keep_alive_on_success", False),
                memory_limit=m.get("memory_limit"),
                labels=m.get("labels"),
            )
            return {
                "ok": result.ok, "detail": result.detail,
                "build_log": result.build_log,
                "container": result.container, "image_tag": result.image_tag,
            }
        finally:
            # The image is baked; a kept-alive container no longer reads the
            # build dir, so it is always safe to drop here.
            import shutil
            shutil.rmtree(build_dir, ignore_errors=True)

    return await _guarded(_do)


@app.post("/deploypack/preview/stop")
async def deploypack_preview_stop(
    request: Request, _: None = Depends(require_sandbox_token)
) -> dict:
    """Stop + force-remove a kept-alive preview container and its image."""
    m = _manifest(request)
    container = m.get("container")
    image_tag = m.get("image_tag")

    def _do() -> dict:
        if container:
            subprocess.run(["docker", "stop", container],
                           capture_output=True, text=True, timeout=15)
        if image_tag:
            subprocess.run(["docker", "rmi", "-f", image_tag],
                           capture_output=True, text=True, timeout=15)
        return {"ok": True}

    return await _guarded(_do)


@app.post("/deploypack/reconcile")
async def deploypack_reconcile(
    request: Request, _: None = Depends(require_sandbox_token)
) -> dict:
    """Docker-truth orphan reaper for expired preview containers."""
    m = _manifest(request)
    return await _guarded(reconcile_previews, now=m.get("now"))


@app.post("/fixpack/run-suite")
async def fixpack_run_suite(
    request: Request, _: None = Depends(require_sandbox_token)
) -> dict:
    """Install (net on via proxy) + test (net off) one version; return counts."""
    raw = await request.body()
    r = _manifest(request)["runner"]
    runner = TestRunner(
        ecosystem=r["ecosystem"], image=r["image"],
        install_script=r["install_script"], test_script=r["test_script"],
    )
    result: RunResult = await _guarded(run_suite, raw, runner)
    return {"passed": result.passed, "failed": result.failed,
            "timed_out": result.timed_out, "error": result.error}


@app.post("/fixpack/run-verification")
async def fixpack_run_verification(
    request: Request,
    _: None = Depends(require_sandbox_token),
) -> dict:
    """Run one structured verification profile against one ZIP."""

    raw = await request.body()
    manifest = _manifest(request)

    profile = verification_profile_from_wire(
        manifest["profile"]
    )

    stages = await _guarded(
        run_verification_profile,
        raw,
        profile,
    )

    return {
        "stages": [
            verification_stage_to_wire(stage)
            for stage in stages
        ]
    }


@app.post("/proof/cors-probe")
async def proof_cors_probe(
    request: Request, _: None = Depends(require_sandbox_token)
) -> dict:
    """Boot ONE workspace, send a real cross-origin request, judge the answer.

    One workspace per call: the caller runs it twice (original, patched) and
    compares with app.proof.compare. See app/proof/cors_probe.py for why the
    probe lives on this side of the boundary — the container publishes on the
    runner's loopback, so nothing in the API process can reach it.
    """
    raw = await request.body()
    m = _manifest(request)

    def _do() -> dict:
        build_dir = Path(tempfile.mkdtemp(prefix="shipit-runner-cors-"))
        try:
            _extract_zip(raw, build_dir)
            diagnostics: dict = {}
            attempt = run_cors_probe(
                build_dir,
                diagnostics=diagnostics,
                host_port=m["host_port"],
                container_port=m["container_port"],
                path=m.get("path", "/"),
                build_timeout_s=m.get("build_timeout_s", 300),
                boot_timeout_s=m.get("boot_timeout_s", 60),
                memory_limit=m.get("memory_limit"),
            )
            return {
                "template_id": attempt.template_id,
                "status": attempt.status,
                "success": attempt.success,
                "detail": attempt.detail,
                "evidence": attempt.evidence,
                "duration_ms": attempt.duration_ms,
                # Beside the attempt, never inside it: build output is the
                # customer's and must not reach proof_json (app/proof/types.py).
                "diagnostics": diagnostics,
            }
        finally:
            import shutil
            shutil.rmtree(build_dir, ignore_errors=True)

    return await _guarded(_do)


@app.post("/fixpack/minimal-check")
async def fixpack_minimal_check(
    request: Request, _: None = Depends(require_sandbox_token)
) -> dict:
    """Dependency-free `node --check` over the changed JS files in the plan."""
    body = await request.json()
    plan = FixpackPlan(files=dict(body.get("files", {})),
                       deletions=list(body.get("deletions", [])))
    result: RunResult = await _guarded(minimal_check, plan)
    return {"passed": result.passed, "failed": result.failed,
            "timed_out": result.timed_out, "error": result.error}
