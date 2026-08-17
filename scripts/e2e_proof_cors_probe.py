"""End-to-end: the runtime CORS probe through the FULL runner chain.

backend client (app.sandbox_client.run_cors_probe) → HTTP over the runner's
Unix socket → app.runner.main → app.proof.cors_probe → real docker build +
run → a real cross-origin request → app.proof.cors_oracle.

THIS IS THE FIRST REAL BOOT. Every other test of this feature drives injected
doubles, because the environment it was written in has no docker. Until this
script has been run green on a host with a runner, the probe's behaviour
against an actual container is unverified — the plan says so, the P1 commit
says so, and nothing in the product routes to it (PROOF_RUNTIME_CORS is off
by default).

It builds two tiny FastAPI apps:

  VULNERABLE — CORSMiddleware with allow_origins=["*"] AND
               allow_credentials=True, which Starlette turns into origin
               REFLECTION **for a credentialed request**: it echoes back
               whatever Origin it was handed. That is the shape the oracle
               calls exploitable, and it is worth knowing that the framework's
               own behaviour, not our regex, produces it.
  PATCHED    — the same app with the origin pinned to one host.

FIRST RUN, 2026-08-17: this script failed, and the failure was real. The
vulnerable app answered a bare `*` and the probe reported "not exploitable".
Cause: Starlette 0.40 (what fastapi==0.115.0 pulls) reflects only
`if self.allow_all_origins and has_cookie`, and the probe was sending no
Cookie — so an app a browser session could read cross-origin was being
judged safe. Fixed in app/proof/cors_probe.py (PROBE_COOKIE). Starlette 1.6
keys the same branch off allow_credentials instead, so the two versions
disagree about an identical application; the oracle judges headers rather
than frameworks, which is why only the probe needed changing.

Expected: the first probe returns status=success (credentialed reflection),
the second returns status=failure (the pinned origin is not ours). Any other
pair means the probe, the oracle or the assumption about Starlette is wrong,
and the script says which.

Env expected (same as the other e2e scripts, set by the workflow):
    SANDBOX_RUNNER_UDS   path to the runner's Unix socket
    SANDBOX_RUNNER_TOKEN shared secret

Usage on a host that has the runner and docker:
    python3 scripts/e2e_proof_cors_probe.py
"""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import sandbox_client  # noqa: E402
from app.proof.cors_oracle import PROBE_ORIGIN  # noqa: E402

_DOCKERFILE = """\
FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi==0.115.0 uvicorn==0.30.6
COPY main.py /app/main.py
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
"""

_APP = """\
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[{origins}],
    allow_credentials={credentials},
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {{"ok": True}}
"""


def _zip(origins: str, credentials: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Dockerfile", _DOCKERFILE)
        zf.writestr("main.py", _APP.format(origins=origins,
                                           credentials=credentials))
    return buf.getvalue()


def main() -> int:
    print(f"probe origin: {PROBE_ORIGIN}")

    print("\n[1/2] vulnerable app (allow_origins=['*'], credentials=True)")
    vulnerable = sandbox_client.run_cors_probe(
        _zip('"*"', "True"), host_port=31111, container_port=8000,
    )
    print(f"  status   : {vulnerable.status}")
    print(f"  success  : {vulnerable.success}")
    print(f"  detail   : {vulnerable.detail}")
    print(f"  evidence : {vulnerable.evidence}")

    print("\n[2/2] patched app (origin pinned)")
    patched = sandbox_client.run_cors_probe(
        _zip('"https://app.example.com"', "True"),
        host_port=31112, container_port=8000,
    )
    print(f"  status   : {patched.status}")
    print(f"  success  : {patched.success}")
    print(f"  detail   : {patched.detail}")
    print(f"  evidence : {patched.evidence}")

    problems: list[str] = []
    if vulnerable.status != "success":
        problems.append(
            f"expected the vulnerable app to reproduce (success), got "
            f"{vulnerable.status}: {vulnerable.detail}"
        )
    if patched.status != "failure":
        problems.append(
            f"expected the patched app to refuse (failure), got "
            f"{patched.status}: {patched.detail}"
        )

    if problems:
        print("\nFAILED:")
        for line in problems:
            print(f"  - {line}")
        # An `error` on either side is the interesting failure: it means the
        # stand did not come up, which is exactly the case the status table
        # keeps separate from "the app is safe".
        return 1

    print("\nOK: reproduced before the fix, refused after it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
