"""Manual smoke test: REAL docker build + docker run, kept alive.

Same rationale as scripts/smoke_verify_deploy_pack.py: run only where
Docker actually exists (a GitHub Actions runner via workflow_dispatch,
not the regular pytest suite). Proves the parts of Ephemeral Preview
Hosting that are actually real in this codebase:

1. run_deploy_pack(..., preview=registry) keeps a container running
   after returning, instead of tearing it down.
2. The returned local_url is genuinely curlable — this is not the
   contained container's internal state, it's an actual host port.
3. --memory 256m is accepted by real docker run (not just a fake-runner
   assertion).
4. reap_expired() genuinely stops and removes the container.

Does NOT and cannot prove: a public `{job_id}.preview.shipit.app` URL
routing through Caddy \u2014 that needs a real domain + real public server,
which this CI runner does not have. See app/deploypack/preview.py's
module docstring.
"""

from __future__ import annotations

import io
import subprocess
import sys
import time
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from app.deploypack.pipeline import run_deploy_pack
from app.deploypack.preview import PreviewRegistry
from app.ingest.stack_detect import detect_stack


def zip_dir(root: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                zf.write(path, arcname=str(path.relative_to(root.parent)))
    return buf.getvalue()


def container_is_running(name: str) -> bool:
    out = subprocess.run(
        ["docker", "ps", "-q", "-f", f"name={name}"],
        capture_output=True, text=True, timeout=10,
        check=False,
    )
    return bool(out.stdout.strip())


def main() -> int:
    root = REPO_ROOT / "smoke" / "fastapi_sample"
    raw = zip_dir(root)
    stack = detect_stack(io.BytesIO(raw))
    print(f"=== preview smoke: fastapi_sample (stack: {stack.value}) ===", flush=True)

    registry = PreviewRegistry()
    result = run_deploy_pack(raw, stack, preview=registry, owner_key="smoke-test")
    print(f"verified={result['verified']!r}  detail={result['detail']}")
    if result["build_log"]:
        print("--- build_log (tail, 4000 chars) ---")
        print(result["build_log"][-4000:])

    if result["verified"] is not True or not result["preview"]:
        print("FAIL: expected a verified preview, got none")
        return 1

    local_url = result["preview"]["local_url"]
    print(f"preview local_url={local_url} expires_at={result['preview']['expires_at']}")

    curl = subprocess.run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", local_url],
        capture_output=True, text=True, timeout=10,
        check=False,
    )
    if curl.stdout.strip() != "200":
        print(f"FAIL: local_url did not return 200 after run_deploy_pack returned "
              f"(got {curl.stdout.strip()!r}) \u2014 the container did not really stay alive")
        return 1
    print("OK: local_url is genuinely curlable after the request finished")

    # Prove the container really is still running via `docker ps`, not
    # just "curl happened not to fail yet".
    info = registry.list_active()[0]
    if not container_is_running(info.container):
        print("FAIL: docker ps shows the container is not running")
        return 1
    print(f"OK: docker ps confirms {info.container} is running")

    reaped = registry.reap_expired(now=time.time() + 999999)
    if reaped != 1 or registry.active_count() != 0:
        print(f"FAIL: reap_expired did not clean up (reaped={reaped}, "
              f"active={registry.active_count()})")
        return 1
    if container_is_running(info.container):
        print("FAIL: container still running after reap_expired")
        return 1
    print("OK: reap_expired genuinely stopped and removed the container")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
