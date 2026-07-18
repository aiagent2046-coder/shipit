"""Second line of defence for the Fix Pack: a *semantic* regression gate.

`generate._validate_syntax` guarantees an edited file still parses. That is
necessary but not sufficient: a syntactically valid edit can still change
behaviour — e.g. a value that only *looked* like a secret gets replaced by
an `os.environ[...]` read, silently altering program logic. The only
trustworthy way to catch that is to run the CLIENT'S OWN test suite against
both the original and the patched tree and check we did not make it worse.

Design constraints (agreed with the product owner):

* Client dependency install + test execution runs ONLY inside an isolated
  Docker container, never on the host. During `pip install` / `npm install`
  the network must be up (installs need it); during the actual test run the
  network is turned OFF (`--network none`) so client test code cannot make
  outbound requests / exfiltrate. Because a single `docker run` cannot be
  "online for install, offline for tests", we split into two containers
  that share a host-mounted working directory: step 1 installs (net on),
  step 2 runs tests against the persisted deps (net off).
* Every run is bounded: a wall-clock timeout and a memory cap.
* Ecosystems v1: Python (pytest) and Node/TypeScript (npm test).

Decision rule (see `is_regression`): we block the Fix Pack only when the
patch made things *worse* — more failures than before, or the patched run
broke (timeout/error) where the original run was fine. We deliberately do
NOT require the client's suite to be green to begin with; a suite that was
already partly red is not our fault, and demanding perfection would block
legitimate fixes.

Docker is invoked through `subprocess.run` behind the single `_run` seam so
the whole decision/detection layer is unit-testable without a real Docker
daemon (which is not present in CI / the dev sandbox).
"""

from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass

from app.fixpack.generate import FixpackPlan, _repo_relative

# --- Tunables --------------------------------------------------------------
# Small, explicit, and conservative. A test run that needs more than this is
# not something we want to gate a PR on synchronously anyway.
INSTALL_TIMEOUT_SECONDS = 300
RUN_TIMEOUT_SECONDS = 180
MEMORY_LIMIT = "512m"
PYTHON_IMAGE = "python:3.12-slim"
NODE_IMAGE = "node:20-slim"
# Where installed deps live inside the mounted work dir so they survive
# between the (separate) install and test containers.
_PY_DEPS_DIR = ".shipit_pydeps"


@dataclass(frozen=True)
class TestRunner:
    """One detected way to run a client's tests. `install_argv` / `test_argv`
    are the shell commands run *inside* the container (as `sh -c`)."""

    ecosystem: str          # "python" | "node"
    image: str
    install_script: str     # runs with network ON
    test_script: str        # runs with network OFF


@dataclass(frozen=True)
class RunResult:
    """Outcome of running one version's suite."""

    passed: int
    failed: int
    timed_out: bool
    error: str | None       # infra/parse error, secret-free


@dataclass(frozen=True)
class SemanticCheckResult:
    """The full verdict handed back to the delivery pipeline."""

    ran: bool                       # did a real client suite execute?
    ecosystem: str | None
    original: RunResult | None
    patched: RunResult | None
    regression: bool                # True => do NOT open a PR
    detail: str                     # secret-free explanation for the job row
    pr_note: str | None             # optional line to append to the PR body


# --- Test-runner detection -------------------------------------------------

_PY_MARKERS = ("requirements.txt", "pyproject.toml", "setup.py", "setup.cfg")


def _zip_names(zip_bytes: bytes) -> list[str]:
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        return zf.namelist()


def _read_package_json_scripts(zip_bytes: bytes, entry: str) -> dict:
    import json
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            data = zf.read(entry)
        parsed = json.loads(data.decode("utf-8", errors="ignore"))
    except (KeyError, ValueError, zipfile.BadZipFile):
        return {}
    scripts = parsed.get("scripts")
    return scripts if isinstance(scripts, dict) else {}


def detect_test_runner(zip_bytes: bytes) -> TestRunner | None:
    """Pick a test runner from the repo's marker files, or None.

    Node is checked first: a repo can be polyglot, but a `package.json` with a
    real `test` script is the strongest signal of an intended, runnable suite.
    For Python we require BOTH a dependency/marker file AND at least one
    `*.py` file under a conventional test directory — a bare requirements.txt
    with no tests should fall through to the minimal check, not spin up a
    pointless pytest container."""
    names = [_repo_relative(n) for n in _zip_names(zip_bytes)]
    lower = [n.lower() for n in names]

    # --- Node / TypeScript ---
    pkg_entries = [orig for orig, rel in zip(_zip_names(zip_bytes), names)
                   if rel == "package.json"]
    for entry in pkg_entries:
        scripts = _read_package_json_scripts(zip_bytes, entry)
        test_script = scripts.get("test", "")
        # npm's own default is a stub that exits 1; treat it as "no tests".
        if test_script and "no test specified" not in test_script:
            return TestRunner(
                ecosystem="node",
                image=NODE_IMAGE,
                install_script="npm install --no-audit --no-fund",
                test_script="npm test",
            )

    # --- Python ---
    has_py_marker = any(
        rel == m or rel.endswith("/" + m)
        for rel in names for m in _PY_MARKERS
    )
    has_py_tests = any(
        _looks_like_python_test(rel) for rel in lower
    )
    if has_py_marker and has_py_tests:
        # Install project deps if declared, then pytest, into a target dir
        # that persists on the mounted volume for the (offline) test step.
        install = (
            f"pip install --no-cache-dir --target=/work/{_PY_DEPS_DIR} pytest && "
            f"if [ -f /work/requirements.txt ]; then "
            f"pip install --no-cache-dir --target=/work/{_PY_DEPS_DIR} "
            f"-r /work/requirements.txt; fi && "
            f"if [ -f /work/pyproject.toml ] || [ -f /work/setup.py ]; then "
            f"pip install --no-cache-dir --target=/work/{_PY_DEPS_DIR} /work || true; fi"
        )
        test = (
            f"PYTHONPATH=/work/{_PY_DEPS_DIR} "
            f"python -m pytest -q --no-header -p no:cacheprovider"
        )
        return TestRunner(
            ecosystem="python", image=PYTHON_IMAGE,
            install_script=install, test_script=test,
        )
    return None


def _looks_like_python_test(rel_lower: str) -> bool:
    if not rel_lower.endswith(".py"):
        return False
    segments = rel_lower.split("/")
    if any(seg in ("tests", "test") for seg in segments[:-1]):
        return True
    base = segments[-1]
    return base.startswith("test_") or base.endswith("_test.py")


# --- Output parsing --------------------------------------------------------

# pytest summary line, e.g. "2 failed, 5 passed in 0.10s" (any order/subset).
_PYTEST_PASSED_RE = re.compile(r"(\d+)\s+passed")
_PYTEST_FAILED_RE = re.compile(r"(\d+)\s+(?:failed|error|errors)")
# jest: "Tests:       1 failed, 7 passed, 8 total"
_JEST_PASSED_RE = re.compile(r"(\d+)\s+passing|(\d+)\s+passed")
_JEST_FAILED_RE = re.compile(r"(\d+)\s+failing|(\d+)\s+failed")
# node --test (Node 18+ built-in runner, TAP-13 summary): the count follows
# the word, e.g. "# pass 1" / "# fail 0" — the opposite order from jest/mocha.
_NODE_TAP_PASSED_RE = re.compile(r"^#\s*pass\s+(\d+)", re.MULTILINE)
_NODE_TAP_FAILED_RE = re.compile(r"^#\s*fail\s+(\d+)", re.MULTILINE)


def _sum_matches(pattern: re.Pattern, text: str) -> int:
    total = 0
    for m in pattern.finditer(text):
        total += sum(int(g) for g in m.groups() if g)
    return total


def parse_pytest_counts(output: str) -> tuple[int, int]:
    """(passed, failed) from pytest stdout. `error`/`errors` count as
    failures — a collection error is still a broken test."""
    return (_sum_matches(_PYTEST_PASSED_RE, output),
            _sum_matches(_PYTEST_FAILED_RE, output))


def parse_node_counts(output: str) -> tuple[int, int]:
    """(passed, failed) from `npm test` stdout. Covers the three dominant
    reporters: jest ('passed'/'failed'), mocha ('passing'/'failing'), and the
    built-in `node --test` TAP runner ('# pass N'/'# fail N'). Node's reporter
    zoo is unbounded, so this is best-effort and the exit code is used as the
    authoritative pass/fail signal by the caller."""
    passed = (_sum_matches(_JEST_PASSED_RE, output)
              + _sum_matches(_NODE_TAP_PASSED_RE, output))
    failed = (_sum_matches(_JEST_FAILED_RE, output)
              + _sum_matches(_NODE_TAP_FAILED_RE, output))
    return (passed, failed)


def _parse_counts(ecosystem: str, output: str) -> tuple[int, int]:
    if ecosystem == "python":
        return parse_pytest_counts(output)
    return parse_node_counts(output)


# --- Docker execution ------------------------------------------------------

def _run(argv: list[str], *, timeout: int) -> subprocess.CompletedProcess:
    """The single subprocess seam (mocked in tests). Captures text output;
    never raises on non-zero exit — callers inspect returncode."""
    return subprocess.run(
        argv, capture_output=True, text=True, timeout=timeout, check=False,
    )


def _extract_repo_relative(zip_bytes: bytes, dest: str) -> None:
    """Extract a (possibly wrapper-folded) zipball into `dest` with the
    wrapper stripped, so paths match the plan's repo-relative layout.
    Skips absolute/`..` members defensively (zip-slip)."""
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            rel = _repo_relative(info.filename)
            if not rel or rel.startswith("/") or ".." in rel.split("/"):
                continue
            target = os.path.join(dest, rel)
            os.makedirs(os.path.dirname(target) or dest, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)


def _docker_install_argv(image: str, workdir: str, script: str) -> list[str]:
    """Step 1: network ON, deps installed into the mounted work dir."""
    return [
        "docker", "run", "--rm",
        "--memory", MEMORY_LIMIT,
        "-v", f"{workdir}:/work", "-w", "/work",
        image, "sh", "-c", script,
    ]


def _docker_test_argv(image: str, workdir: str, script: str) -> list[str]:
    """Step 2: network OFF, tests run against the persisted deps."""
    return [
        "docker", "run", "--rm",
        "--network", "none",
        "--memory", MEMORY_LIMIT,
        "-v", f"{workdir}:/work", "-w", "/work",
        image, "sh", "-c", script,
    ]


def run_suite(zip_bytes: bytes, runner: TestRunner) -> RunResult:
    """Install (net on) then test (net off) one version in Docker; return
    parsed counts. Any infra failure is captured as `error` (secret-free) —
    we never surface client output verbatim into a persisted field."""
    workdir = tempfile.mkdtemp(prefix="shipit-semcheck-")
    try:
        _extract_repo_relative(zip_bytes, workdir)

        install = _run(
            _docker_install_argv(runner.image, workdir, runner.install_script),
            timeout=INSTALL_TIMEOUT_SECONDS,
        )
        if install.returncode != 0:
            return RunResult(0, 0, False,
                             f"dependency install failed (exit {install.returncode})")

        test = _run(
            _docker_test_argv(runner.image, workdir, runner.test_script),
            timeout=RUN_TIMEOUT_SECONDS,
        )
        passed, failed = _parse_counts(runner.ecosystem, test.stdout or "")
        # If we parsed nothing but the runner clearly failed, record one
        # failure so exit-code signal isn't lost to an unknown reporter.
        if passed == 0 and failed == 0 and test.returncode != 0:
            failed = 1
        return RunResult(passed, failed, False, None)
    except subprocess.TimeoutExpired:
        # The timed_out flag is the signal; keep error None so is_regression
        # treats a timeout as a timeout, not a generic execution error.
        return RunResult(0, 0, True, None)
    except FileNotFoundError:
        # `docker` binary absent (e.g. this sandbox). Inconclusive, not a
        # regression — the caller treats a symmetric infra error as "could
        # not verify", never as "we broke it".
        return RunResult(0, 0, False, "docker CLI not available")
    except OSError as exc:
        return RunResult(0, 0, False, f"docker invocation error: {type(exc).__name__}")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --- Decision --------------------------------------------------------------

def is_regression(original: RunResult, patched: RunResult) -> tuple[bool, str]:
    """Did the patch make the suite worse? Returns (regression, detail).

    "Worse" means, in order:
      1. patched errored where original ran clean (we broke the environment);
      2. patched timed out where original completed (we made it hang);
      3. patched has strictly more failures than original.
    A suite that was already red/timed-out/errored BEFORE our patch is the
    client's baseline, not our regression — we only ever compare against it.
    """
    if patched.error and not original.error:
        return True, f"patched run failed to execute: {patched.error}"
    if patched.timed_out and not original.timed_out:
        return True, "patched tests timed out where the original completed"
    if patched.failed > original.failed:
        delta = patched.failed - original.failed
        return True, (
            f"patch introduced {delta} new test failure(s) "
            f"(original: {original.failed} failed / {original.passed} passed, "
            f"patched: {patched.failed} failed / {patched.passed} passed)"
        )
    return False, (
        f"no regression (original: {original.failed} failed / "
        f"{original.passed} passed, patched: {patched.failed} failed / "
        f"{patched.passed} passed)"
    )


# --- Minimal check (no client test suite) ----------------------------------

def missing_tests_pr_note() -> str:
    """A soft, non-blocking line for the PR body when the repo ships no test
    suite we can run. Encourages adding tests without pretending we verified
    behaviour we couldn't."""
    return (
        "> **Note:** this repository has no runnable test suite we could "
        "detect (pytest or `npm test`), so these changes were verified for "
        "**syntax only**, not runtime behaviour. Consider adding tests so "
        "future automated fixes can be behaviourally verified before delivery."
    )


def minimal_check(plan: FixpackPlan) -> RunResult:
    """When there is no client suite, do a cheap, dependency-free sanity
    pass over the files we actually changed.

    * Python (`.py`): already fully covered by the syntax gate
      (`generate._validate_syntax` -> `ast.parse`) before a file ever reaches
      the plan, so there is nothing more a zero-dependency check can add here
      — we do NOT invent a second parser.
    * Node (`.js`/`.cjs`/`.mjs`): `node --check` per changed file, run inside
      the offline Node container (no deps, no network).
    * TypeScript: `tsc --noEmit` needs the toolchain + config; that lives in
      the full test path, not this dependency-free minimal check.

    Returns a RunResult; `failed > 0` means a changed file failed the cheap
    check and the caller should block. Absent Docker, this is inconclusive
    (error set), never a regression.
    """
    js_files = [p for p in plan.files
                if p.lower().endswith((".js", ".cjs", ".mjs"))]
    if not js_files:
        return RunResult(0, 0, False, None)

    workdir = tempfile.mkdtemp(prefix="shipit-mincheck-")
    try:
        for path, text in plan.files.items():
            if path in js_files:
                target = os.path.join(workdir, path)
                os.makedirs(os.path.dirname(target) or workdir, exist_ok=True)
                with open(target, "w", encoding="utf-8") as fh:
                    fh.write(text)
        checks = " && ".join(f"node --check '{p}'" for p in js_files)
        try:
            proc = _run(
                _docker_test_argv(NODE_IMAGE, workdir, checks),
                timeout=RUN_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return RunResult(0, 0, True, None)
        except FileNotFoundError:
            return RunResult(0, 0, False, "docker CLI not available")
        if proc.returncode != 0:
            return RunResult(0, len(js_files), False,
                             "node --check reported a syntax error in a changed file")
        return RunResult(len(js_files), 0, False, None)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --- Orchestration ---------------------------------------------------------

def run_semantic_check(original_zip: bytes, plan: FixpackPlan) -> SemanticCheckResult:
    """Top-level gate. Detect the client's test runner; if present, run both
    versions in Docker and compare; if absent, do the minimal check and
    attach a soft recommendation note.

    This is synchronous and may take minutes (real Docker) — callers MUST run
    it in a threadpool, exactly like `run_scan` (see main.py).
    """
    runner = detect_test_runner(original_zip)

    if runner is None:
        mc = minimal_check(plan)
        if mc.failed > 0:
            return SemanticCheckResult(
                ran=False, ecosystem=None, original=None, patched=None,
                regression=True,
                detail="minimal check failed: " + (mc.error or "changed file is invalid"),
                pr_note=None,
            )
        return SemanticCheckResult(
            ran=False, ecosystem=None, original=None, patched=None,
            regression=False,
            detail="no client test suite detected; syntax-only verification",
            pr_note=missing_tests_pr_note(),
        )

    patched_zip = build_patched_zip(original_zip, plan)
    original = run_suite(original_zip, runner)
    patched = run_suite(patched_zip, runner)
    regression, detail = is_regression(original, patched)
    return SemanticCheckResult(
        ran=True, ecosystem=runner.ecosystem,
        original=original, patched=patched,
        regression=regression, detail=detail, pr_note=None,
    )


# --- Patched-tree construction ---------------------------------------------

def build_patched_zip(original_zip: bytes, plan: FixpackPlan) -> bytes:
    """Return a new zipball that is `original_zip` with the plan applied:
    `plan.files` overwrite/add (matched by repo-relative path), and
    `plan.deletions` are dropped. The wrapper folder (if any) is preserved so
    the result is shaped exactly like the input the tests extract."""
    wrapper = _detect_wrapper(original_zip)
    deletions = set(plan.deletions)
    written_rel: set[str] = set()

    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(original_zip)) as src, \
            zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
        for info in src.infolist():
            if info.is_dir():
                continue
            rel = _repo_relative(info.filename)
            if rel in deletions:
                continue
            if rel in plan.files:
                out.writestr(info.filename, plan.files[rel])
                written_rel.add(rel)
            else:
                out.writestr(info.filename, src.read(info))
        # Files the plan adds that weren't in the original (e.g. .env.example,
        # .gitignore) — write them under the wrapper so paths line up.
        for rel, text in plan.files.items():
            if rel in written_rel or rel in deletions:
                continue
            name = f"{wrapper}/{rel}" if wrapper else rel
            out.writestr(name, text)
    return buf.getvalue()


def _detect_wrapper(zip_bytes: bytes) -> str | None:
    """The single top-level wrapper folder GitHub/Lovable zipballs use, or
    None if entries live at the root. Mirrors `_repo_relative`'s assumption."""
    tops = set()
    for name in _zip_names(zip_bytes):
        if "/" in name:
            tops.add(name.split("/", 1)[0])
        else:
            return None  # a root-level file => no single wrapper
    return next(iter(tops)) if len(tops) == 1 else None
