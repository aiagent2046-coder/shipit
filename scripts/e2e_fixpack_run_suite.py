"""End-to-end: fixpack run_suite through the FULL Variant-A chain.

backend client (app.sandbox_client.run_suite) → HTTP over the runner's Unix
socket → app.runner.main → real app.fixpack.semantic_check.run_suite → docker
(via the socket-proxy) → install + test containers.

This is the fixpack half of the e2e workflow (the deploy-pack half reuses
scripts/smoke_verify_deploy_pack.py with the same env).

It builds a tiny **Python** project with a NON-EMPTY ``requirements.txt`` naming
a real package (``six``) and a test that imports it. This is deliberate: the
install step does ``pip install -r /work/requirements.txt`` with NO ``[ -f ]``
guard, so if the runner's build dir is not actually visible to dockerd inside the
container (the PrivateTmp mount-namespace bug — see
scripts/check_runner_bindmount_namespace.py and the unit comment), ``/work`` mounts
EMPTY, the requirements file "does not exist", and install fails loudly here. A
green run therefore proves not just that containers ran, but that the bind-mounted
workspace really carried the client's files across the namespace boundary — which
a no-dependency ``install_script='true'`` could never catch.

The workflow starts the runner UNDER ``PrivateTmp`` (via systemd-run) so this
reproduces the prod mount-namespace conditions, not a bare uvicorn process.

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

# A real, tiny, pure-Python package pinned for determinism. It must be fetched
# from PyPI during the (network-on) install step, then imported offline in the
# test step from the deps persisted on the bind-mounted /work.
_REQUIREMENT = "six==1.16.0"
_DEPS_DIR = "/work/.deps"


def _project_zip() -> bytes:
    """A minimal Python project: one real dependency + one test that imports it."""
    requirements = f"{_REQUIREMENT}\n"
    test_py = (
        "import six\n"
        "def test_imports_installed_dependency():\n"
        "    assert six.PY3\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # single wrapper dir, matching real exports / _extract_repo_relative
        zf.writestr("e2e-sample/requirements.txt", requirements)
        zf.writestr("e2e-sample/tests/test_dep.py", test_py)
    return buf.getvalue()


def main() -> int:
    if not os.environ.get("SANDBOX_RUNNER_TOKEN"):
        print("FAIL: SANDBOX_RUNNER_TOKEN not set — runner auth would 503", flush=True)
        return 1

    # HOME/XDG under /tmp: the install container runs --read-only with a writable
    # tmpfs /tmp, as a non-root uid with no home dir; pip needs a writable HOME.
    # No `[ -f ]` guard on the requirements install — an empty /work MUST fail.
    install = (
        f"HOME=/tmp XDG_CACHE_HOME=/tmp "
        f"pip install --no-cache-dir --target={_DEPS_DIR} pytest && "
        f"HOME=/tmp XDG_CACHE_HOME=/tmp "
        f"pip install --no-cache-dir --target={_DEPS_DIR} -r /work/requirements.txt"
    )
    test = (
        f"PYTHONPATH={_DEPS_DIR} "
        f"python -m pytest -q --no-header -p no:cacheprovider"
    )
    runner = TestRunner(
        ecosystem="python",
        image="python:3.12-slim",
        install_script=install,
        test_script=test,
    )

    print("=== fixpack run_suite over backend→runner→proxy→docker ===", flush=True)
    print(f"(real dependency install: {_REQUIREMENT}; empty /work would fail here)",
          flush=True)
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

    print("OK: fixpack install(+real dep)+test ran through the full chain; the "
          "bind-mounted workspace was visible to dockerd", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
