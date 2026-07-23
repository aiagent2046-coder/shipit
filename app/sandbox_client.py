"""Backend-side HTTP client for the out-of-process ``sandbox-runner``.

Stage-3 Variant A: the backend no longer shells ``docker`` itself. Every
docker-touching operation (deploy-pack build/run/boot-check, preview
keep-alive/stop/reconcile, fixpack install+test) is executed by a separate
``sandbox-runner`` process running as an unprivileged user with its own
reduced env (no prod secrets) — see ``app/runner/main.py`` and
``deploy/sandbox-runner/``.

This module exposes functions with the SAME names, signatures and return
types as the local implementations they replace, so the call sites
(``pipeline.py``, ``preview.py``, the fixpack path) barely change: they
import these instead of the real ones. The real ones still live in
``app/deploypack/sandbox.py`` and ``app/fixpack/semantic_check.py`` — the
runner imports THOSE and does the actual docker work.

Transport (decisions O4/O5 from the Variant-A plan):
  * a Unix-domain socket (default ``/run/shipit-runner/sandbox.sock``), so
    access is gated by filesystem permissions rather than a promise to bind
    loopback; a bearer token is kept as a second line of defence.
  * the (possibly multi-MB) workspace zip is the raw request body
    (``application/octet-stream``) — never base64 (which would inflate ~30%)
    or multipart; small control metadata rides in the ``X-Sandbox-Request``
    JSON header.

Degradation contract when the runner is unreachable:
  * deploy-pack *verify* / *preview* / *stop* / *reconcile* raise
    ``SandboxRunnerUnavailable`` — the caller decides (verify → "could not
    verify"; preview → 503).
  * fixpack ``run_suite`` / ``minimal_check`` return a ``RunResult`` with
    ``error`` set instead of raising, so ``is_regression`` treats a runner
    outage as "could not verify", never a false regression — identical to the
    existing "docker CLI not available" behaviour.
"""

from __future__ import annotations

import io
import json
import os
import zipfile
from pathlib import Path

import httpx

from app.deploypack.sandbox import SandboxResult
from app.fixpack.semantic_check import Runner, RunResult

# Unix socket the runner listens on. A TCP fallback (SANDBOX_RUNNER_URL) is
# supported for environments without a UDS, but UDS is the default and the
# recommended prod transport.
SANDBOX_RUNNER_UDS = os.environ.get(
    "SANDBOX_RUNNER_UDS", "/run/shipit-runner/sandbox.sock"
)
SANDBOX_RUNNER_URL = os.environ.get("SANDBOX_RUNNER_URL", "")
SANDBOX_RUNNER_TOKEN = os.environ.get("SANDBOX_RUNNER_TOKEN", "")

# Client read timeout must comfortably exceed the runner's own build+boot
# budget, or the backend gives up while the runner is still building.
SANDBOX_RUNNER_TIMEOUT_S = float(os.environ.get("SANDBOX_RUNNER_TIMEOUT_S", "600"))


class SandboxRunnerUnavailable(RuntimeError):
    """Raised when the sandbox-runner cannot be reached or errored at the
    transport level (connection refused, timeout, 5xx). Callers translate this
    into their own degraded outcome."""


def _client() -> httpx.Client:
    headers = {}
    if SANDBOX_RUNNER_TOKEN:
        headers["Authorization"] = f"Bearer {SANDBOX_RUNNER_TOKEN}"
    if SANDBOX_RUNNER_URL:
        return httpx.Client(
            base_url=SANDBOX_RUNNER_URL, headers=headers,
            timeout=SANDBOX_RUNNER_TIMEOUT_S,
        )
    transport = httpx.HTTPTransport(uds=SANDBOX_RUNNER_UDS)
    # base_url host is arbitrary for a UDS connection but required by httpx.
    return httpx.Client(
        base_url="http://sandbox-runner", headers=headers,
        transport=transport, timeout=SANDBOX_RUNNER_TIMEOUT_S,
    )


def _post(path: str, *, content: bytes | None = None,
          manifest: dict | None = None, json_body: dict | None = None) -> dict:
    """POST to the runner and return the parsed JSON, or raise
    SandboxRunnerUnavailable on any transport-level failure."""
    headers = {}
    if manifest is not None:
        headers["X-Sandbox-Request"] = json.dumps(manifest)
    try:
        with _client() as client:
            if json_body is not None:
                resp = client.post(path, json=json_body, headers=headers)
            else:
                headers.setdefault("Content-Type", "application/octet-stream")
                resp = client.post(path, content=content or b"", headers=headers)
    except httpx.HTTPError as exc:
        raise SandboxRunnerUnavailable(
            f"sandbox-runner unreachable ({type(exc).__name__})"
        ) from exc
    if resp.status_code >= 500:
        raise SandboxRunnerUnavailable(
            f"sandbox-runner returned {resp.status_code}"
        )
    if resp.status_code != 200:
        # 4xx is a real, deterministic rejection (bad request / auth) — surface
        # it as unavailable too rather than pretend a result; the detail helps.
        raise SandboxRunnerUnavailable(
            f"sandbox-runner rejected request: {resp.status_code} {resp.text[:200]}"
        )
    return resp.json()


def _zip_dir(build_dir: Path) -> bytes:
    """Zip a build directory (repo + generated Pack files) into a byte string
    the runner can reconstruct on its own filesystem."""
    buf = io.BytesIO()
    build_dir = Path(build_dir)
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(build_dir.rglob("*")):
            if p.is_file():
                zf.write(p, p.relative_to(build_dir).as_posix())
    return buf.getvalue()


# --- deploy-pack -----------------------------------------------------------

def verify_deploy_pack(
    build_dir,
    host_port: int,
    container_port: int,
    path: str = "/",
    build_timeout_s: int = 300,
    boot_timeout_s: int = 60,
    poll_interval_s: float = 1.0,
    keep_alive_on_success: bool = False,
    memory_limit: str | None = None,
    labels: dict | None = None,
    run=None,  # accepted for signature parity; the runner uses real subprocess
) -> SandboxResult:
    """Signature-compatible with sandbox.verify_deploy_pack, but the build/run/
    boot-check happens in the runner process. Raises SandboxRunnerUnavailable
    if the runner can't be reached."""
    manifest = {
        "host_port": host_port,
        "container_port": container_port,
        "path": path,
        "build_timeout_s": build_timeout_s,
        "boot_timeout_s": boot_timeout_s,
        "poll_interval_s": poll_interval_s,
        "keep_alive_on_success": keep_alive_on_success,
        "memory_limit": memory_limit,
        "labels": labels,
    }
    data = _post("/deploypack/verify", content=_zip_dir(Path(build_dir)),
                 manifest=manifest)
    return SandboxResult(
        ok=data["ok"], detail=data["detail"], build_log=data.get("build_log", ""),
        container=data.get("container"), image_tag=data.get("image_tag"),
    )


def preview_stop(container: str, image_tag: str | None) -> None:
    """Stop + remove a kept-alive preview container via the runner. Best-effort:
    a runner outage is logged upstream, not fatal to reaping."""
    _post("/deploypack/preview/stop",
          manifest={"container": container, "image_tag": image_tag}, content=b"")


def reconcile_previews(run=None, now: float | None = None) -> dict:
    """Docker-truth orphan reaper, executed in the runner. Signature-compatible
    with preview.reconcile_previews."""
    return _post("/deploypack/reconcile", manifest={"now": now}, content=b"")


# --- fixpack ---------------------------------------------------------------

def run_suite(zip_bytes: bytes, runner: Runner) -> RunResult:
    """Install (net on, via proxy) + test (net off) one version, in the runner.
    Returns a RunResult with `error` set on a runner outage (symmetric across
    original/patched → treated as 'could not verify', never a regression)."""
    manifest = {
        "runner": {
            "ecosystem": runner.ecosystem,
            "image": runner.image,
            "install_script": runner.install_script,
            "test_script": runner.test_script,
        }
    }
    try:
        data = _post("/fixpack/run-suite", content=zip_bytes, manifest=manifest)
    except SandboxRunnerUnavailable as exc:
        return RunResult(0, 0, False, f"sandbox runner unavailable: {exc}")
    return RunResult(
        passed=data["passed"], failed=data["failed"],
        timed_out=data["timed_out"], error=data["error"],
    )


def minimal_check(plan) -> RunResult:
    """Dependency-free `node --check` over changed JS files, in the runner.
    Same symmetric-error contract as run_suite on a runner outage."""
    body = {"files": dict(plan.files), "deletions": list(plan.deletions)}
    try:
        data = _post("/fixpack/minimal-check", json_body=body)
    except SandboxRunnerUnavailable as exc:
        return RunResult(0, 0, False, f"sandbox runner unavailable: {exc}")
    return RunResult(
        passed=data["passed"], failed=data["failed"],
        timed_out=data["timed_out"], error=data["error"],
    )
