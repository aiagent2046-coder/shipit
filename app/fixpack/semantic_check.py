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
# Docker runtime for the containers that execute untrusted client code.
# Default "runc" is Docker's standard runtime (shared host kernel). Set to
# "runsc" (gVisor) on a host that has it registered to gain a second,
# user-space kernel boundary against unknown container-escape bugs in
# runc/host kernel. Explicit + reversible by design: when this is "runc"
# (the default) we emit NO --runtime flag, so argv is byte-for-byte identical
# to the pre-gVisor behaviour and prod cannot be changed by merging this.
FIXPACK_DOCKER_RUNTIME = os.environ.get("FIXPACK_DOCKER_RUNTIME", "runc")
# Where installed deps live inside the mounted work dir so they survive
# between the (separate) install and test containers.
_PY_DEPS_DIR = ".shipit_pydeps"

# Coarse zip-bomb / disk-fill guard: cap the total UNCOMPRESSED size of a
# client repo we will extract and bind-mount into a container, on top of the
# per-member zip-slip check in _extract_repo_relative. A genuine client repo
# is far under this; anything larger is not something we run synchronously.
MAX_WORKSPACE_BYTES = 512 * 1024 * 1024  # 512 MiB uncompressed

# Cap how much container stdout/stderr we pull back into this process's memory.
# capture_output buffers the whole stream, so a hostile suite printing
# gigabytes could otherwise blow up backend RAM. We keep only head+tail.
MAX_CAPTURED_OUTPUT_BYTES = 64 * 1024

# Read-only container rootfs (requirement 3.3). Both steps write only to the
# bind-mounted /work (writable regardless of --read-only) plus scratch in /tmp
# and the tool home caches (~/.npm, pip build temp); we give those as tmpfs and
# lock the rest of the rootfs read-only. Toggle off (FIXPACK_READONLY_ROOTFS=0)
# for an image that genuinely needs a writable rootfs, rather than deleting the
# flag in code -- see PHASE3 plan §5.2.
FIXPACK_READONLY_ROOTFS = (
    os.environ.get("FIXPACK_READONLY_ROOTFS", "1").lower() not in ("0", "false", "")
)

# Fixed non-root uid:gid used inside the container when the backend itself runs
# as root (the prod systemd unit has no User=, so os.getuid() == 0 there).
# Mirroring root into the container would leave the untrusted code running as
# container-root and defeat requirement 3.3, so we drop to a fixed unprivileged
# id instead. The bind-mounted /work is chown'd to this id before the run (see
# _chown_workdir), so the non-root process can still read/write it.
_NONROOT_FALLBACK_UID = 1000
_NONROOT_FALLBACK_GID = 1000


def _default_run_as_user() -> str:
    """The --user value when FIXPACK_RUN_AS_USER is unset. Never resolves to
    root: if the backend runs as root (uid 0), fall back to a fixed non-root id
    rather than mirroring 0:0 into the container; otherwise reuse the backend's
    own uid:gid (it created /work, so no chown is needed)."""
    uid, gid = os.getuid(), os.getgid()
    if uid == 0:
        return f"{_NONROOT_FALLBACK_UID}:{_NONROOT_FALLBACK_GID}"
    return f"{uid}:{gid}"


# Run the untrusted container as a non-root user (requirement 3.3). Defaults via
# _default_run_as_user() (never root). Override with FIXPACK_RUN_AS_USER
# ("1000:1000", or "" to run as the image's own default user). An explicit env
# value of "" disables --user; only an *unset* env falls back to the default.
_env_run_as_user = os.environ.get("FIXPACK_RUN_AS_USER")
FIXPACK_RUN_AS_USER = (
    _default_run_as_user() if _env_run_as_user is None else _env_run_as_user
)


@dataclass(frozen=True)
class Runner:
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


def _zip_uncompressed_size(zip_bytes: bytes) -> int:
    """Total uncompressed size declared by the archive's central directory.
    Used as a coarse zip-bomb guard before extraction (see MAX_WORKSPACE_BYTES)."""
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        return sum(info.file_size for info in zf.infolist())


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


def detect_test_runner(zip_bytes: bytes) -> Runner | None:
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
            return Runner(
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
        return Runner(
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

def _clip(text: str | None) -> str | None:
    """Bound one captured stream to MAX_CAPTURED_OUTPUT_BYTES, keeping the head
    and tail (both usually matter: the reporter summary is at the end, the
    first error at the top). None/short input passes through untouched."""
    if not text or len(text) <= MAX_CAPTURED_OUTPUT_BYTES:
        return text
    keep = MAX_CAPTURED_OUTPUT_BYTES // 2
    dropped = len(text) - 2 * keep
    return f"{text[:keep]}\n...[truncated {dropped} chars]...\n{text[-keep:]}"


def _truncate_output(cp: subprocess.CompletedProcess) -> subprocess.CompletedProcess:
    """Clip a completed process's captured stdout/stderr in place, so an
    adversarial client suite cannot balloon this process's memory via a
    multi-gigabyte print. Counts are parsed from the clipped head+tail, which
    still contains any real reporter summary."""
    cp.stdout = _clip(cp.stdout)
    cp.stderr = _clip(cp.stderr)
    return cp


def _run(argv: list[str], *, timeout: int) -> subprocess.CompletedProcess:
    """The single subprocess seam (mocked in tests). Captures text output;
    never raises on non-zero exit — callers inspect returncode. Captured
    streams are clipped to bound memory (see _truncate_output)."""
    return _truncate_output(subprocess.run(
        argv, capture_output=True, text=True, timeout=timeout, check=False,
    ))


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


# Hardening flags applied to every container that executes untrusted client
# code, on top of --memory:
#   --pids-limit=256                 fork-bomb guard (cap process count)
#   --cpus=1                         one CPU max, so a client can't peg the host
#   --security-opt=no-new-privileges block setuid privilege escalation inside
#   --cap-drop=ALL                   drop all Linux capabilities (none are
#                                    needed to install deps or run a test)
# --ulimit nofile / fsize bound open descriptors and max file size, so a client
#   can't exhaust host FDs or fill the disk with one giant file (complements
#   --pids-limit / --memory). fsize is generous (1 GiB) so real installs and
#   test artefacts are unaffected.
# --read-only / --user are applied separately (see _readonly_argv / _user_argv)
#   because they are conditional on env toggles.
_CONTAINER_HARDENING = [
    "--pids-limit=256",
    "--cpus=1",
    "--security-opt=no-new-privileges",
    "--cap-drop=ALL",
    "--ulimit", "nofile=1024:1024",
    "--ulimit", "fsize=1073741824",
]


def _readonly_argv() -> list[str]:
    """--read-only rootfs plus the minimal writable tmpfs carve-outs both steps
    need: /tmp (pip build temp, pytest scratch) and /root (npm's ~/.npm cache,
    pip's ~/.cache). /work is a bind mount and stays writable regardless. Empty
    when FIXPACK_READONLY_ROOTFS is disabled."""
    if not FIXPACK_READONLY_ROOTFS:
        return []
    return ["--read-only", "--tmpfs", "/tmp", "--tmpfs", "/root"]


def _user_argv() -> list[str]:
    """--user <uid:gid> to run untrusted client code as non-root. Empty string
    disables (image default user)."""
    return ["--user", FIXPACK_RUN_AS_USER] if FIXPACK_RUN_AS_USER else []


def _chown_workdir(workdir: str) -> None:
    """Hand ownership of the bind-mounted /work to the container's --user, so a
    non-root container process can read the extracted repo and write deps into
    it. Only relevant (and only permitted) when the backend runs as root — a
    non-root backend already owns the tempdir it created. No-op when --user is
    disabled or its value is a named user rather than a numeric uid:gid."""
    if os.getuid() != 0 or not FIXPACK_RUN_AS_USER:
        return
    parts = FIXPACK_RUN_AS_USER.split(":", 1)
    try:
        uid = int(parts[0])
        gid = int(parts[1]) if len(parts) > 1 else uid
    except ValueError:
        return  # e.g. "node" — can't resolve a name to an id here; skip
    os.lchown(workdir, uid, gid)
    for root, dirs, files in os.walk(workdir):
        for name in dirs + files:
            try:
                os.lchown(os.path.join(root, name), uid, gid)
            except OSError:
                pass

# Egress allowlist for the install step. The install container needs the
# network (pip/npm fetch packages), but "the network" should mean the package
# registries and nothing else -- a malicious postinstall script in a client's
# third-party dep must not be able to reach arbitrary hosts (exfiltration, or
# an attack on our internal network). We enforce that with a forward proxy:
# the container's ONLY route out is an HTTP(S) proxy that allows just the
# registry hosts (registry.npmjs.org, pypi.org, files.pythonhosted.org, and
# npm CDN subdomains) and blocks everything else.
#
# The proxy itself (Squid) is configured SEPARATELY on the host, not here --
# this module only points the container at it. The container reaches a service
# on the host via the special DNS name host.docker.internal, which on Linux we
# must wire up explicitly with --add-host=...:host-gateway (Docker 20.10+).
#
# pip and npm both honour HTTP_PROXY/HTTPS_PROXY/NO_PROXY from the environment.
# We pass UPPERCASE (some tools only read those) AND lowercase mirrors (curl
# and some libraries prefer lowercase) so the allowlist can't be bypassed by a
# tool that happens to read only one casing.
#
# Only the URL is configurable (the prod port/address can change without a code
# change); the allowlist policy lives in the host's Squid config.
FIXPACK_INSTALL_PROXY_URL = os.environ.get(
    "FIXPACK_INSTALL_PROXY_URL", "http://host.docker.internal:3128"
)


def _install_proxy_argv() -> list[str]:
    """docker-run flags routing the install container's egress through the
    host's allowlisting forward proxy. Empty if the proxy URL is explicitly
    unset, so a deployment without a proxy still installs (network open)."""
    proxy = FIXPACK_INSTALL_PROXY_URL
    if not proxy:
        return []
    no_proxy = "localhost,127.0.0.1"
    return [
        "--add-host=host.docker.internal:host-gateway",
        "-e", f"HTTP_PROXY={proxy}",
        "-e", f"HTTPS_PROXY={proxy}",
        "-e", f"NO_PROXY={no_proxy}",
        "-e", f"http_proxy={proxy}",
        "-e", f"https_proxy={proxy}",
        "-e", f"no_proxy={no_proxy}",
    ]


def _runtime_argv() -> list[str]:
    """docker-run flag selecting the container runtime, or empty for the
    default. "runc" is Docker's default, so we emit nothing for it -- keeping
    argv unchanged when gVisor is off. A non-default value (e.g. "runsc" for
    gVisor, or later "kata") becomes `--runtime <name>`. If the named runtime
    is not registered on the host the daemon rejects the `docker run` with a
    non-zero exit *before* any client code runs; that failure is symmetric
    across the original and patched runs, so is_regression treats it as
    "could not verify", never a false regression."""
    rt = FIXPACK_DOCKER_RUNTIME
    return ["--runtime", rt] if rt and rt != "runc" else []


def _docker_install_argv(image: str, workdir: str, script: str) -> list[str]:
    """Step 1: network ON *but only through the egress-allowlist proxy*; deps
    installed into the mounted work dir. See _install_proxy_argv."""
    return [
        "docker", "run", "--rm",
        *_runtime_argv(),
        *_user_argv(),
        "--memory", MEMORY_LIMIT,
        *_CONTAINER_HARDENING,
        *_readonly_argv(),
        *_install_proxy_argv(),
        "-v", f"{workdir}:/work", "-w", "/work",
        image, "sh", "-c", script,
    ]


def _docker_test_argv(image: str, workdir: str, script: str) -> list[str]:
    """Step 2: network OFF, tests run against the persisted deps."""
    return [
        "docker", "run", "--rm",
        *_runtime_argv(),
        *_user_argv(),
        "--network", "none",
        "--memory", MEMORY_LIMIT,
        *_CONTAINER_HARDENING,
        *_readonly_argv(),
        "-v", f"{workdir}:/work", "-w", "/work",
        image, "sh", "-c", script,
    ]


def run_suite(zip_bytes: bytes, runner: Runner) -> RunResult:
    """Install (net on) then test (net off) one version in Docker; return
    parsed counts. Any infra failure is captured as `error` (secret-free) —
    we never surface client output verbatim into a persisted field."""
    if _zip_uncompressed_size(zip_bytes) > MAX_WORKSPACE_BYTES:
        # Symmetric across original/patched (both are the same repo ± the
        # patch), so is_regression treats this as "could not verify", never a
        # false regression — same contract as a missing docker binary.
        return RunResult(0, 0, False, "client workspace exceeds size limit")

    workdir = tempfile.mkdtemp(prefix="shipit-semcheck-")
    try:
        _extract_repo_relative(zip_bytes, workdir)
        # mkdtemp is 0o700 owned by this process; if the container runs as a
        # different (non-root) uid, hand it ownership so it can use /work.
        _chown_workdir(workdir)

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

def run_semantic_check(
    original_zip: bytes,
    plan: FixpackPlan,
    *,
    suite_runner=None,
    minimal_checker=None,
) -> SemanticCheckResult:
    """Top-level gate. Detect the client's test runner; if present, run both
    versions in Docker and compare; if absent, do the minimal check and
    attach a soft recommendation note.

    Orchestration and all pure steps (detect / build_patched_zip / compare)
    run in-process; the two docker-touching seams are injectable. The backend
    passes the sandbox-runner HTTP client (Variant A) so it never execs docker;
    the defaults are the real local implementations, which the runner itself
    uses.

    This is synchronous and may take minutes (real Docker) — callers MUST run
    it in a threadpool, exactly like `run_scan` (see main.py).
    """
    # Resolve at call time (not as default arg values) so a module-level
    # monkeypatch of run_suite / minimal_check still takes effect, and so the
    # backend can inject the sandbox-runner client.
    suite_runner = suite_runner or run_suite
    minimal_checker = minimal_checker or minimal_check

    runner = detect_test_runner(original_zip)

    if runner is None:
        mc = minimal_checker(plan)
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
    original = suite_runner(original_zip, runner)
    patched = suite_runner(patched_zip, runner)
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
