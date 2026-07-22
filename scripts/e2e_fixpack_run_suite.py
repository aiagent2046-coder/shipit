"""End-to-end: fixpack run_suite through the FULL Variant-A chain.

backend client (app.sandbox_client.run_suite) → HTTP over the runner's Unix
socket → app.runner.main → real app.fixpack.semantic_check.run_suite → docker
(via the socket-proxy) → install + test containers.

This is the fixpack half of the e2e workflow (the deploy-pack half reuses
scripts/smoke_verify_deploy_pack.py with the same env). It builds a tiny,
network-free Node project whose single test passes using Node 20's built-in
`node --test` runner, so no package registry is needed. A green run proves the
whole HTTP→runner→proxy→docker path executes real containers and the counts
round-trip back to the backend.

Env expected (set by the workflow before this process starts, so
app.sandbox_client picks them up at import):
  SANDBOX_RUNNER_UDS, SANDBOX_RUNNER_TOKEN
"""

from __future__ import annotations

import io
import os
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Imported AFTER sys.path fix; sandbox_client reads SANDBOX_RUNNER_* at import,
# and the workflow sets them in the environment before invoking python.
from app.fixpack.semantic_check import TestRunner  # noqa: E402
from app.sandbox_client import run_suite  # noqa: E402


def _project_zip() -> bytes:
    """A minimal Node project with one passing built-in test, no deps."""
    test_js = (
        "const test = require('node:test');\n"
        "const assert = require('node:assert');\n"
        "test('adds', () => { assert.strictEqual(1 + 1, 2); });\n"
    )
    pkg = '{"name":"e2e-sample","version":"1.0.0"}\n'
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # single wrapper dir, matching real exports / _extract_repo_relative
        zf.writestr("e2e-sample/package.json", pkg)
        zf.writestr("e2e-sample/test/add.test.js", test_js)
    return buf.getvalue()


def main() -> int:
    if not os.environ.get("SANDBOX_RUNNER_TOKEN"):
        print("FAIL: SANDBOX_RUNNER_TOKEN not set — runner auth would 503", flush=True)
        return 1

    runner = TestRunner(
        ecosystem="node",
        image="node:20-slim",
        # No dependencies: keep the install step network-free and deterministic.
        install_script="true",
        # Node 20 built-in runner emits TAP '# pass N' / '# fail N'.
        test_script="node --test",
    )

    print("=== fixpack run_suite over backend→runner→proxy→docker ===", flush=True)
    result = run_suite(_project_zip(), runner)
    print(f"passed={result.passed} failed={result.failed} "
          f"timed_out={result.timed_out} error={result.error!r}", flush=True)

    if result.error:
        print(f"FAIL: runner returned an error: {result.error}", flush=True)
        return 1
    if result.timed_out:
        print("FAIL: suite timed out", flush=True)
        return 1
    if result.passed < 1 or result.failed != 0:
        print("FAIL: expected >=1 passed and 0 failed", flush=True)
        return 1

    print("OK: fixpack suite ran real containers through the full chain", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
