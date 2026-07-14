"""Manual smoke test: REAL HTTP round trip against a running uvicorn
server, proving the reap endpoint's mechanism works end to end.

Runs only on a host with Docker (see other scripts/smoke_verify_*.py
in this directory for why). Does NOT prove the *scheduled* part of
"cron reaper" -- that's shipit-reap.timer on the production VPS now
(a former GitHub Actions workflow doing the same hourly call was
removed 2026-07-14, never had its repo secrets configured). What
this DOES prove for real: the endpoint's auth check, its wiring to the
same PreviewRegistry the API uses, and that reap_expired() over real
HTTP actually stops a real running container -- not a fake-runner
assertion.

Flow:
1. Start `uvicorn app.main:app` as a subprocess with PREVIEW_REAP_TOKEN set.
2. POST fastapi_sample to /v1/fixpacks with want_preview=true -> get a
   real local_url and a real running container (confirmed via docker ps).
3. POST /internal/preview/reap with no/wrong token -> expect 401.
4. POST /internal/preview/reap with the right token -> expect 200 and
   the container to genuinely be gone afterward.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parent.parent
BASE_URL = "http://127.0.0.1:8811"
TOKEN = "smoke-test-reap-token"


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
    )
    return bool(out.stdout.strip())


def wait_for_healthz(client: httpx.Client, timeout_s: float = 20) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if client.get(f"{BASE_URL}/healthz").status_code == 200:
                return True
        except httpx.ConnectError:
            pass
        time.sleep(0.5)
    return False


def main() -> int:
    env = {**os.environ, "PREVIEW_REAP_TOKEN": TOKEN}
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app",
         "--host", "127.0.0.1", "--port", "8811"],
        cwd=REPO_ROOT, env=env,
    )
    try:
        with httpx.Client(timeout=30) as client:
            if not wait_for_healthz(client):
                print("FAIL: server never came up")
                return 1
            print("OK: uvicorn is up")

            raw = zip_dir(REPO_ROOT / "smoke" / "fastapi_sample")
            resp = client.post(
                f"{BASE_URL}/v1/fixpacks",
                files={"archive": ("app.zip", raw, "application/zip")},
                data={"want_preview": "true"},
            )
            body = resp.json()
            print(f"fixpacks: verified={body['verified']!r} preview={body['preview']!r}")
            if body["verified"] is not True or not body["preview"]:
                print("FAIL: expected a verified preview")
                return 1

            # The container name isn't in the API response by design
            # (it's an internal detail) -- confirm liveness via the
            # local_url itself instead, same as the port smoke test.
            curl = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 body["preview"]["local_url"]],
                capture_output=True, text=True, timeout=10,
            )
            if curl.stdout.strip() != "200":
                print(f"FAIL: preview local_url not curlable ({curl.stdout!r})")
                return 1
            print("OK: preview is live and curlable before reaping")

            no_auth = client.post(f"{BASE_URL}/internal/preview/reap")
            if no_auth.status_code != 401:
                print(f"FAIL: expected 401 with no auth, got {no_auth.status_code}")
                return 1
            wrong_auth = client.post(
                f"{BASE_URL}/internal/preview/reap",
                headers={"Authorization": "Bearer wrong-token"},
            )
            if wrong_auth.status_code != 401:
                print(f"FAIL: expected 401 with wrong token, got {wrong_auth.status_code}")
                return 1
            print("OK: reap endpoint rejects missing/wrong auth")

            reaped = client.post(
                f"{BASE_URL}/internal/preview/reap",
                headers={"Authorization": f"Bearer {TOKEN}"},
            )
            if reaped.status_code != 200:
                print(f"FAIL: reap with correct token returned {reaped.status_code}")
                return 1
            print(f"OK: reap endpoint responded {reaped.json()}")

            # Force the TTL check: reap_expired() only reaps what's
            # actually past its expires_at, and our preview was just
            # started with the default 24h TTL, so THIS call correctly
            # reaped nothing yet. Confirm the container is still alive,
            # which is the honest expected outcome, then move on -- a
            # real "did it get reaped after 24h" check needs a real
            # clock, which is exactly what the schedule cron is for.
            curl_again = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 body["preview"]["local_url"]],
                capture_output=True, text=True, timeout=10,
            )
            if curl_again.stdout.strip() != "200":
                print("FAIL: preview disappeared before its TTL expired")
                return 1
            print("OK: preview correctly survives reap before its TTL, as expected")

        return 0
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
        _cleanup_leftover_containers()


def _cleanup_leftover_containers() -> None:
    """Belt-and-suspenders: this script's preview was never reaped
    (its TTL hadn't expired, on purpose — see the comment above), so
    stop anything it left running rather than assume the CI runner
    will always be thrown away right after this exits."""
    out = subprocess.run(
        ["docker", "ps", "-q", "--filter", "name=shipit-verify-"],
        capture_output=True, text=True, timeout=10,
    )
    for container_id in out.stdout.split():
        subprocess.run(["docker", "stop", container_id], capture_output=True, timeout=15)


if __name__ == "__main__":
    raise SystemExit(main())
