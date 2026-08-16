"""Unit tests for app/fixpack/semantic_check.

No real Docker: the single subprocess seam `semantic_check._run` is
monkeypatched, so detection, output parsing, the regression decision, the
minimal (no-suite) fallback, the recommendation note, and patched-tree
construction are all exercised deterministically. See scripts / a manual
run for real-Docker proof; the daemon is absent in CI and this sandbox.
"""

import io
import os
import subprocess
import zipfile

import app.fixpack.semantic_check as sc
from app.fixpack.generate import FixpackPlan
from app.fixpack.semantic_check import (
    RunResult,
    _docker_install_argv,
    _docker_test_argv,
    build_patched_zip,
    detect_test_runner,
    is_regression,
    minimal_check,
    missing_tests_pr_note,
    parse_node_counts,
    parse_pytest_counts,
    run_semantic_check,
    run_suite,
)


def make_zip(entries: dict[str, str]) -> bytes:
    """GitHub-style zipball: everything under one wrapper folder."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, text in entries.items():
            zf.writestr(f"acme-app-deadbeef/{name}", text)
    return buf.getvalue()


def completed(argv, code=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(argv, code, stdout, stderr)


# --- detect_test_runner ----------------------------------------------------

def test_detect_python_pytest_from_requirements_and_tests():
    zip_bytes = make_zip({
        "requirements.txt": "pytest\n",
        "tests/test_app.py": "def test_ok():\n    assert 1\n",
        "app.py": "x = 1\n",
    })
    runner = detect_test_runner(zip_bytes)
    assert runner is not None
    assert runner.ecosystem == "python"
    assert "pytest" in runner.test_script


def test_detect_python_from_pyproject_and_nested_test_file():
    zip_bytes = make_zip({
        "pyproject.toml": "[project]\nname='x'\n",
        "src/foo_test.py": "def test_x():\n    assert True\n",
    })
    runner = detect_test_runner(zip_bytes)
    assert runner is not None and runner.ecosystem == "python"


def test_detect_node_from_package_json_test_script():
    zip_bytes = make_zip({
        "package.json": '{"scripts": {"test": "jest"}}',
        "index.js": "module.exports = 1;\n",
    })
    runner = detect_test_runner(zip_bytes)
    assert runner is not None
    assert runner.ecosystem == "node"
    assert runner.test_script == "npm test"


def test_node_default_stub_test_script_is_not_a_runner():
    # npm init's placeholder must not be treated as a real suite.
    zip_bytes = make_zip({
        "package.json":
            '{"scripts": {"test": "echo \\"Error: no test specified\\" && exit 1"}}',
    })
    assert detect_test_runner(zip_bytes) is None


def test_python_markers_without_tests_is_not_a_runner():
    zip_bytes = make_zip({"requirements.txt": "flask\n", "app.py": "x=1\n"})
    assert detect_test_runner(zip_bytes) is None


def test_no_markers_at_all_returns_none():
    zip_bytes = make_zip({"index.html": "<h1>hi</h1>\n"})
    assert detect_test_runner(zip_bytes) is None


# --- output parsing --------------------------------------------------------

def test_parse_pytest_counts_various():
    assert parse_pytest_counts("5 passed in 0.10s") == (5, 0)
    assert parse_pytest_counts("2 failed, 5 passed in 0.2s") == (5, 2)
    assert parse_pytest_counts("1 error, 3 passed") == (3, 1)
    assert parse_pytest_counts("nothing here") == (0, 0)


def test_parse_node_counts_jest_and_mocha():
    assert parse_node_counts("Tests: 1 failed, 7 passed, 8 total") == (7, 1)
    assert parse_node_counts("  10 passing\n  2 failing") == (10, 2)


# Real, verbatim `node --test` output (Node 20 TAP-13 reporter, the format
# emitted by node:20-slim / NODE_IMAGE). Captured live: `npm test` with
# {"scripts":{"test":"node --test"}} and a single test file. The summary uses
# "# pass N" / "# fail N" — count AFTER the word — which the jest/mocha
# regexes miss, hence the production bug where a passing suite parsed as
# passed=0. See tests below pinning both the passing and failing shapes.
NODE_TEST_PASSING_OUTPUT = """\

> test
> node --test

TAP version 13
# Subtest: one plus one
ok 1 - one plus one
  ---
  duration_ms: 1.189812
  ...
1..1
# tests 1
# suites 0
# pass 1
# fail 0
# cancelled 0
# skipped 0
# todo 0
# duration_ms 51.418485
"""

NODE_TEST_FAILING_OUTPUT = """\

> test
> node --test

TAP version 13
# Subtest: one plus one wrong
not ok 1 - one plus one wrong
  ---
  duration_ms: 2.135618
  location: '/tmp/nodetest/test/sample.test.js:3:1'
  failureType: 'testCodeFailure'
  error: |-
    Expected values to be strictly equal:

    2 !== 3

  code: 'ERR_ASSERTION'
  name: 'AssertionError'
  expected: 3
  actual: 2
  operator: 'strictEqual'
  ...
1..1
# tests 1
# suites 0
# pass 0
# fail 1
# cancelled 0
# skipped 0
# todo 0
# duration_ms 46.244892
"""


def test_parse_node_counts_node_test_runner_passing():
    # Regression: `node --test` TAP summary is "# pass 1" / "# fail 0";
    # a fully-passing suite must parse as (1, 0), not (0, 0).
    assert parse_node_counts(NODE_TEST_PASSING_OUTPUT) == (1, 0)


def test_parse_node_counts_node_test_runner_failing():
    assert parse_node_counts(NODE_TEST_FAILING_OUTPUT) == (0, 1)


# --- is_regression decision ------------------------------------------------

def test_regression_when_patched_has_more_failures():
    reg, detail, unavailable = is_regression(RunResult(5, 0, False, None),
                                             RunResult(3, 2, False, None))
    assert reg is True
    assert "2 new test failure" in detail
    assert unavailable is False


def test_no_regression_when_failures_equal_even_if_already_red():
    # Suite was already red before us; same count after => not our fault.
    reg, detail, unavailable = is_regression(RunResult(4, 3, False, None),
                                             RunResult(4, 3, False, None))
    assert reg is False
    assert unavailable is False


def test_no_regression_when_patched_fixed_some():
    reg, _, unavailable = is_regression(RunResult(3, 2, False, None),
                                        RunResult(5, 0, False, None))
    assert reg is False
    assert unavailable is False


def test_regression_when_patched_errors_but_original_clean():
    reg, detail, unavailable = is_regression(
        RunResult(5, 0, False, None),
        RunResult(0, 0, False, "install failed"))
    assert reg is True
    assert "failed to execute" in detail
    assert unavailable is False


def test_symmetric_error_is_not_a_regression():
    # docker absent for BOTH runs => inconclusive, not "we broke it".
    reg, _, unavailable = is_regression(
        RunResult(0, 0, False, "docker CLI not available"),
        RunResult(0, 0, False, "docker CLI not available"))
    assert reg is False
    # An error the runner *reported* is not transport unavailability: this stays
    # a plain non-regression, exactly as before.
    assert unavailable is False


def test_regression_when_patched_times_out_but_original_completed():
    reg, detail, unavailable = is_regression(RunResult(5, 0, False, None),
                                             RunResult(0, 0, True, None))
    assert reg is True
    assert "timed out" in detail
    assert unavailable is False


# --- is_regression: runner unavailable (nothing ran) -----------------------

def _unavailable(msg="sandbox runner unavailable: refused"):
    return RunResult(0, 0, False, msg, unavailable=True)


def test_symmetric_unavailable_is_neither_clean_nor_regression():
    reg, detail, unavailable = is_regression(_unavailable(), _unavailable())
    assert unavailable is True
    # crucially NOT a regression -> the caller must not block; and the caller
    # must not read `regression is False` as "verified clean" either.
    assert reg is False
    assert "could not verify" in detail
    assert "neither run" in detail


def test_patched_unavailable_is_not_reported_as_a_regression():
    # The pre-fix bug: patched.error set => "patched run failed to execute" =>
    # blocked => the customer told their fix broke tests that never ran.
    reg, detail, unavailable = is_regression(RunResult(5, 0, False, None),
                                             _unavailable())
    assert unavailable is True
    assert reg is False
    assert "could not verify" in detail
    assert "the patched run" in detail
    assert "failed to execute" not in detail


def test_original_unavailable_is_not_a_silent_pass():
    # Baseline never ran, so original.failed == 0 means "nothing ran", not
    # "green" -- comparing against it would be a coin flip.
    reg, detail, unavailable = is_regression(_unavailable(),
                                             RunResult(0, 3, False, None))
    assert unavailable is True
    assert reg is False
    assert "the original run" in detail


def test_unavailable_wins_over_a_would_be_regression():
    # patched has more failures AND is unavailable: unavailable is checked
    # first, because a suite that never ran cannot have "more failures".
    reg, _, unavailable = is_regression(RunResult(5, 0, False, None),
                                        RunResult(0, 9, False, "x",
                                                  unavailable=True))
    assert (reg, unavailable) == (False, True)


# --- run_suite (mocked docker) ---------------------------------------------

def _python_zip():
    return make_zip({
        "requirements.txt": "\n",
        "tests/test_app.py": "def test_ok():\n    assert 1\n",
    })


def test_run_suite_parses_counts_from_offline_test_step(monkeypatch):
    def fake_run(argv, *, timeout):
        if "--network" in argv:            # the offline test step
            return completed(argv, 0, "5 passed in 0.1s")
        return completed(argv, 0, "installed ok")  # the install step
    monkeypatch.setattr(sc, "_run", fake_run)

    runner = detect_test_runner(_python_zip())
    res = run_suite(_python_zip(), runner)
    assert res == RunResult(5, 0, False, None)


def test_run_suite_reports_install_failure(monkeypatch):
    def fake_run(argv, *, timeout):
        if "--network" in argv:
            raise AssertionError("test step must not run if install failed")
        return completed(argv, 1, "", "could not resolve deps")
    monkeypatch.setattr(sc, "_run", fake_run)

    res = run_suite(_python_zip(), detect_test_runner(_python_zip()))
    assert res.error is not None and "install failed" in res.error


def test_run_suite_timeout_sets_flag(monkeypatch):
    def fake_run(argv, *, timeout):
        if "--network" in argv:
            raise subprocess.TimeoutExpired(cmd=argv, timeout=timeout)
        return completed(argv, 0, "ok")
    monkeypatch.setattr(sc, "_run", fake_run)

    res = run_suite(_python_zip(), detect_test_runner(_python_zip()))
    assert res.timed_out is True


def test_run_suite_missing_docker_is_error_not_crash(monkeypatch):
    def fake_run(argv, *, timeout):
        raise FileNotFoundError("docker")
    monkeypatch.setattr(sc, "_run", fake_run)

    res = run_suite(_python_zip(), detect_test_runner(_python_zip()))
    assert res.error == "docker CLI not available"
    assert res.timed_out is False


def test_run_suite_unknown_reporter_falls_back_to_exit_code(monkeypatch):
    def fake_run(argv, *, timeout):
        if "--network" in argv:
            return completed(argv, 1, "weird custom reporter output")
        return completed(argv, 0, "ok")
    monkeypatch.setattr(sc, "_run", fake_run)

    res = run_suite(_python_zip(), detect_test_runner(_python_zip()))
    assert res.failed == 1  # exit-code signal preserved


# --- container hardening flags ---------------------------------------------

_HARDENING = {
    "--pids-limit=256",
    "--cpus=1",
    "--security-opt=no-new-privileges",
    "--cap-drop=ALL",
}


def test_install_argv_has_resource_and_privilege_limits():
    argv = _docker_install_argv("python:3.12-slim", "/tmp/work", "pip install x")
    assert _HARDENING.issubset(set(argv))
    assert "--memory" in argv          # existing cap kept


def test_test_argv_has_resource_and_privilege_limits():
    argv = _docker_test_argv("node:20-slim", "/tmp/work", "npm test")
    assert _HARDENING.issubset(set(argv))
    assert "--network" in argv and "none" in argv   # existing net-off kept


# --- read-only rootfs, non-root user, ulimits (3.3) ------------------------

def test_both_builders_are_read_only_with_tmpfs_by_default():
    # 3.3: rootfs read-only, with the minimal writable tmpfs carve-outs the
    # install/test steps need (/tmp scratch, /root for ~/.npm & pip cache).
    for argv in (
        _docker_install_argv("python:3.12-slim", "/tmp/work", "pip install x"),
        _docker_test_argv("node:20-slim", "/tmp/work", "npm test"),
    ):
        assert "--read-only" in argv
        # each --tmpfs is followed by its mountpoint
        tmpfs_targets = {argv[i + 1] for i, t in enumerate(argv) if t == "--tmpfs"}
        assert {"/tmp", "/root"}.issubset(tmpfs_targets)


def test_read_only_can_be_disabled_by_env(monkeypatch):
    monkeypatch.setattr(sc, "FIXPACK_READONLY_ROOTFS", False)
    argv = _docker_install_argv("python:3.12-slim", "/tmp/work", "pip install x")
    assert "--read-only" not in argv
    assert "--tmpfs" not in argv


def test_both_builders_run_as_non_root_user_by_default():
    # 3.3: --user <uid:gid> so untrusted client code is not container-root.
    # Default never resolves to root (see _default_run_as_user); /work is
    # chown'd to this id when the backend runs as root.
    for argv in (
        _docker_install_argv("python:3.12-slim", "/tmp/work", "pip install x"),
        _docker_test_argv("node:20-slim", "/tmp/work", "npm test"),
    ):
        assert "--user" in argv
        user = argv[argv.index("--user") + 1]
        assert user == sc.FIXPACK_RUN_AS_USER and ":" in user


def test_user_can_be_disabled_by_env(monkeypatch):
    monkeypatch.setattr(sc, "FIXPACK_RUN_AS_USER", "")
    argv = _docker_test_argv("node:20-slim", "/tmp/work", "npm test")
    assert "--user" not in argv


def test_default_user_is_never_root_even_when_backend_runs_as_root(monkeypatch):
    # On the prod VPS the systemd unit has no User=, so the backend is root
    # (uid 0). Mirroring that into the container (--user 0:0) would leave the
    # untrusted code as container-root and defeat requirement 3.3, so the
    # default must fall back to a fixed non-root id instead.
    monkeypatch.setattr(sc.os, "getuid", lambda: 0)
    monkeypatch.setattr(sc.os, "getgid", lambda: 0)
    default = sc._default_run_as_user()
    assert default != "0:0"
    assert default.split(":")[0] != "0"
    assert default == f"{sc._NONROOT_FALLBACK_UID}:{sc._NONROOT_FALLBACK_GID}"


def test_default_user_reuses_backend_id_when_non_root(monkeypatch):
    # A non-root backend already owns the tempdir it creates, so reuse its
    # uid:gid (no chown needed).
    monkeypatch.setattr(sc.os, "getuid", lambda: 1234)
    monkeypatch.setattr(sc.os, "getgid", lambda: 5678)
    assert sc._default_run_as_user() == "1234:5678"


def test_chown_workdir_gives_container_user_ownership_when_root(monkeypatch, tmp_path):
    # When the backend is root, /work (mkdtemp'd 0o700, root-owned) must be
    # chown'd to the non-root container uid so the container can read/write it.
    monkeypatch.setattr(sc.os, "getuid", lambda: 0)
    monkeypatch.setattr(sc, "FIXPACK_RUN_AS_USER", "1000:1000")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "f.txt").write_text("x")
    chowned: list[tuple[str, int, int]] = []
    monkeypatch.setattr(
        sc.os, "lchown",
        lambda p, uid, gid: chowned.append((str(p), uid, gid)),
    )
    sc._chown_workdir(str(tmp_path))
    assert (str(tmp_path), 1000, 1000) in chowned
    # recurses into contents so the extracted repo is reachable too
    assert any(p.endswith("f.txt") and (uid, gid) == (1000, 1000)
               for p, uid, gid in chowned)


def test_chown_workdir_is_noop_when_backend_non_root(monkeypatch, tmp_path):
    # A non-root backend can't chown to another uid and doesn't need to.
    monkeypatch.setattr(sc.os, "getuid", lambda: 1000)
    monkeypatch.setattr(sc, "FIXPACK_RUN_AS_USER", "1000:1000")
    called = False

    def _fail(*a, **k):
        nonlocal called
        called = True

    monkeypatch.setattr(sc.os, "lchown", _fail)
    sc._chown_workdir(str(tmp_path))
    assert called is False


def test_both_builders_carry_fd_and_fsize_ulimits():
    # 3.3: cap open descriptors and max file size (complements --pids/--memory).
    for argv in (
        _docker_install_argv("python:3.12-slim", "/tmp/work", "pip install x"),
        _docker_test_argv("node:20-slim", "/tmp/work", "npm test"),
    ):
        ulimits = {argv[i + 1] for i, t in enumerate(argv) if t == "--ulimit"}
        assert any(u.startswith("nofile=") for u in ulimits)
        assert any(u.startswith("fsize=") for u in ulimits)


def test_install_argv_routes_egress_through_the_proxy():
    # The install step needs the network, but only via the host's allowlisting
    # forward proxy. Assert the container is pointed at host.docker.internal
    # and every proxy env var (both casings) carries the configured URL.
    argv = _docker_install_argv("python:3.12-slim", "/tmp/work", "pip install x")
    assert "--add-host=host.docker.internal:host-gateway" in argv
    proxy = sc.FIXPACK_INSTALL_PROXY_URL
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        assert f"{var}={proxy}" in argv
    for var in ("NO_PROXY", "no_proxy"):
        assert f"{var}=localhost,127.0.0.1" in argv


def test_test_argv_has_no_proxy_and_stays_offline():
    # The test step is fully offline (--network none); a proxy is neither
    # needed nor reachable there, so it must carry none of the proxy plumbing.
    argv = _docker_test_argv("node:20-slim", "/tmp/work", "npm test")
    assert "--network" in argv and "none" in argv
    assert not any(a.startswith("--add-host") for a in argv)
    assert not any("PROXY" in a or "proxy" in a for a in argv)
    # Non-proxy environment variables such as HOME and cache locations are
    # required for read-only, non-root containers. What must be absent here
    # are specifically the proxy environment variables.
    assert not any(
        "PROXY=" in argument.upper()
        for argument in argv
    )
    assert "--env" not in argv


def test_no_host_env_is_forwarded_into_the_container():
    # `docker run` only forwards an env var when -e NAME (no '=') is given;
    # -e NAME=VALUE sets a literal value instead. Host secrets like
    # GITHUB_APP_PRIVATE_KEY_B64 must never reach untrusted client code, so
    # every -e we pass MUST be a literal assignment (contains '='), never a
    # bare passthrough. The install step legitimately sets the proxy vars this
    # way; the test step passes no -e at all.
    for argv in (
        _docker_install_argv("python:3.12-slim", "/tmp/work", "pip install x"),
        _docker_test_argv("node:20-slim", "/tmp/work", "npm test"),
    ):
        assert not any(a.startswith("--env") for a in argv)
        for i, tok in enumerate(argv):
            if tok == "-e":
                assert "=" in argv[i + 1], f"bare host-env passthrough: {argv[i + 1]}"


def test_install_proxy_is_configurable_and_optional(monkeypatch):
    # The URL is env-configurable so prod can change the port/address without a
    # code edit; explicitly clearing it disables the proxy (network stays open).
    monkeypatch.setattr(sc, "FIXPACK_INSTALL_PROXY_URL", "http://proxy.example:9999")
    argv = _docker_install_argv("python:3.12-slim", "/tmp/work", "pip install x")
    assert "HTTP_PROXY=http://proxy.example:9999" in argv

    monkeypatch.setattr(sc, "FIXPACK_INSTALL_PROXY_URL", "")
    argv = _docker_install_argv("python:3.12-slim", "/tmp/work", "pip install x")
    assert not any(a.startswith("--add-host") for a in argv)
    # Non-proxy environment variables such as HOME and cache locations are
    # required for read-only, non-root containers. What must be absent here
    # are specifically the proxy environment variables.
    assert not any(
        "PROXY=" in argument.upper()
        for argument in argv
    )


# --- container runtime selection (gVisor opt-in) ---------------------------

def test_default_runtime_emits_no_runtime_flag():
    # Default "runc" is Docker's own default -> we emit NO --runtime flag, so
    # argv is byte-for-byte identical to the pre-gVisor behaviour. Merging the
    # capability cannot change prod until FIXPACK_DOCKER_RUNTIME is set.
    assert sc.FIXPACK_DOCKER_RUNTIME == "runc"
    for argv in (
        _docker_install_argv("python:3.12-slim", "/tmp/work", "pip install x"),
        _docker_test_argv("node:20-slim", "/tmp/work", "npm test"),
    ):
        assert "--runtime" not in argv
        assert sc._runtime_argv() == []


def test_runsc_runtime_flag_present_in_both_builders(monkeypatch):
    monkeypatch.setattr(sc, "FIXPACK_DOCKER_RUNTIME", "runsc")
    for argv in (
        _docker_install_argv("python:3.12-slim", "/tmp/work", "pip install x"),
        _docker_test_argv("node:20-slim", "/tmp/work", "npm test"),
    ):
        # exact "--runtime" "runsc" pair, and it comes right after "docker run"
        assert argv[:3] == ["docker", "run", "--rm"]
        assert argv[3:5] == ["--runtime", "runsc"]
        # existing flags still present -- runtime is additive, not a rewrite
        assert _HARDENING.issubset(set(argv))
        assert "--memory" in argv


def test_test_builder_keeps_network_none_under_runsc(monkeypatch):
    # gVisor must not disturb the offline test step's --network none.
    monkeypatch.setattr(sc, "FIXPACK_DOCKER_RUNTIME", "runsc")
    argv = _docker_test_argv("node:20-slim", "/tmp/work", "npm test")
    assert "--network" in argv and "none" in argv


def test_empty_runtime_is_treated_as_default(monkeypatch):
    # An empty value must not produce a broken `--runtime ` with no name.
    monkeypatch.setattr(sc, "FIXPACK_DOCKER_RUNTIME", "")
    assert sc._runtime_argv() == []
    argv = _docker_install_argv("python:3.12-slim", "/tmp/work", "pip install x")
    assert "--runtime" not in argv


# --- workspace size limit (3.4) --------------------------------------------

def test_run_suite_rejects_oversized_workspace(monkeypatch):
    # A zip whose declared uncompressed size exceeds the cap is refused before
    # extraction/docker — returned as a secret-free error, never a regression.
    monkeypatch.setattr(sc, "MAX_WORKSPACE_BYTES", 10)

    def boom(*a, **k):
        raise AssertionError("docker must not run for an oversized workspace")
    monkeypatch.setattr(sc, "_run", boom)

    res = run_suite(_python_zip(), detect_test_runner(_python_zip()))
    assert res.error is not None and "size limit" in res.error


def test_zip_uncompressed_size_sums_members():
    z = make_zip({"a.txt": "x" * 100, "b.txt": "y" * 50})
    assert sc._zip_uncompressed_size(z) == 150


# --- captured-output truncation (3.4) --------------------------------------

def test_clip_leaves_short_output_untouched():
    assert sc._clip("short") == "short"
    assert sc._clip(None) is None


def test_clip_truncates_and_keeps_head_and_tail():
    big = "H" * 10 + "M" * 200_000 + "T" * 10
    cap = sc.MAX_CAPTURED_OUTPUT_BYTES
    clipped = sc._clip(big)
    assert len(clipped) < len(big)
    assert clipped.startswith("H")           # head kept
    assert clipped.endswith("T")             # tail kept
    assert "truncated" in clipped
    assert len(clipped) <= cap + 64          # ~cap plus the marker line


def test_truncate_output_clips_both_streams():
    huge = "x" * (sc.MAX_CAPTURED_OUTPUT_BYTES * 3)
    cp = completed(["docker"], 0, stdout=huge, stderr=huge)
    out = sc._truncate_output(cp)
    assert len(out.stdout) < len(huge)
    assert len(out.stderr) < len(huge)


# --- docker socket / host-mount regression guard (3.4) ---------------------

def _all_fixpack_argvs():
    return [
        _docker_install_argv("python:3.12-slim", "/tmp/work", "pip install x"),
        _docker_test_argv("node:20-slim", "/tmp/work", "npm test"),
    ]


def test_no_docker_socket_is_ever_mounted():
    for argv in _all_fixpack_argvs():
        joined = " ".join(argv)
        assert "docker.sock" not in joined
        assert "/var/run/docker" not in joined


def test_only_the_workspace_is_bind_mounted():
    # Every -v must mount exactly the caller's workdir at /work and nothing
    # else — no arbitrary host paths reach the untrusted container.
    for argv in _all_fixpack_argvs():
        mounts = [argv[i + 1] for i, t in enumerate(argv) if t == "-v"]
        assert mounts == ["/tmp/work:/work"]


# --- build_patched_zip -----------------------------------------------------

def test_build_patched_zip_applies_files_deletions_and_additions():
    original = make_zip({
        "config.py": "API_KEY = 'x'\n",
        ".env": "SECRET=1\n",
        "keep.py": "y = 2\n",
    })
    plan = FixpackPlan(
        files={"config.py": "API_KEY = os.environ['K']\n",
               ".env.example": "SECRET=changeme\n"},
        deletions=[".env"],
    )
    patched = build_patched_zip(original, plan)

    names = {n for n in zipfile.ZipFile(io.BytesIO(patched)).namelist()}
    # wrapper preserved
    assert all(n.startswith("acme-app-deadbeef/") for n in names)
    rel = {n.split("/", 1)[1] for n in names}
    assert "config.py" in rel and ".env.example" in rel and "keep.py" in rel
    assert ".env" not in rel  # deleted

    contents = {}
    with zipfile.ZipFile(io.BytesIO(patched)) as zf:
        for n in names:
            contents[n.split("/", 1)[1]] = zf.read(n).decode()
    assert contents["config.py"] == "API_KEY = os.environ['K']\n"
    assert contents["keep.py"] == "y = 2\n"
    assert contents[".env.example"] == "SECRET=changeme\n"


# --- minimal_check + note (no client suite) --------------------------------

def test_minimal_check_no_js_is_clean_without_docker(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("docker must not be invoked with no JS files")
    monkeypatch.setattr(sc, "_run", boom)

    plan = FixpackPlan(files={"config.py": "x = 1\n"})
    res = minimal_check(plan)
    assert res == RunResult(0, 0, False, None)


def test_minimal_check_flags_broken_js(monkeypatch):
    monkeypatch.setattr(sc, "_run",
                        lambda argv, *, timeout: completed(argv, 1, "", "SyntaxError"))
    plan = FixpackPlan(files={"app.js": "const x = (\n"})
    res = minimal_check(plan)
    assert res.failed == 1


def test_minimal_check_passes_valid_js(monkeypatch):
    monkeypatch.setattr(sc, "_run",
                        lambda argv, *, timeout: completed(argv, 0, ""))
    plan = FixpackPlan(files={"app.js": "const x = 1;\n"})
    res = minimal_check(plan)
    assert res.passed == 1 and res.failed == 0


# --- minimal_check builds shell source out of client filenames --------------
#
# The script minimal_check assembles is handed to `docker run ... sh -c`, and
# the only client-controlled pieces in it are the names of the changed .js
# files. These tests do not inspect that string for quote characters -- they
# hand it to a real /bin/sh with a fake `node` on PATH, because the question
# is what sh does with it, and only sh can answer that.


def _script_for(monkeypatch, files: dict[str, str]) -> tuple[str, list[str]]:
    """(the `sh -c` script minimal_check built, the paths it named)."""
    seen: list[list[str]] = []

    def capture(argv, *, timeout):
        seen.append(argv)
        return completed(argv, 0, "")

    monkeypatch.setattr(sc, "_run", capture)
    minimal_check(FixpackPlan(files=files))
    if not seen:
        return "", []
    return seen[0][-1], seen[0]


def _sh(script: str, cwd) -> int:
    """Run `script` through a real sh with a `node` that checks nothing but
    its argument's contents -- exit 1 if the named file starts with BROKEN.

    A stub rather than the real node so the test does not need a toolchain,
    and so a file that does not exist is a hard failure rather than a
    MODULE_NOT_FOUND the assertion might mistake for a syntax verdict.
    """
    bin_dir = cwd / "fakebin"
    bin_dir.mkdir()
    node = bin_dir / "node"
    node.write_text(
        '#!/bin/sh\n'
        'shift\n'                                  # drop --check
        'case "$1" in -*) exit 9;; esac\n'         # real node reads this as a flag
        '[ -f "$1" ] || exit 9\n'                  # named a file that is not there
        'head -c 6 "$1" | grep -q BROKEN && exit 1\n'
        'exit 0\n'
    )
    node.chmod(0o755)
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}")
    return subprocess.run(["sh", "-c", script], cwd=cwd, env=env).returncode


def test_an_apostrophe_in_a_filename_does_not_fail_its_own_fix_pack(
        monkeypatch, tmp_path):
    """Measured before the fix: `node --check 'don't.js'` is "Unterminated
    quoted string", sh exits 2, and minimal_check reports the file as a
    syntax error -- blocking a correct Fix Pack over a legal filename."""
    name = "don't.js"
    script, _ = _script_for(monkeypatch, {name: "var a = 1;\n"})
    (tmp_path / name).write_text("var a = 1;\n")

    assert _sh(script, tmp_path) == 0


def test_a_filename_cannot_smuggle_a_command_into_the_check(
        monkeypatch, tmp_path):
    """The quieter direction. `b' ; true '.js` made the old template read
    `node --check 'b' ; true '.js'`, which exits 0 whatever the file holds --
    we ship a file the record says we checked.

    The payload writes a file rather than merely exiting 0, so the assertion
    is about whether sh ran a second command at all, not about an exit code
    that could be right for the wrong reason.
    """
    name = "b' ; touch pwned ; '.js"
    script, _ = _script_for(monkeypatch, {name: "BROKEN(\n"})
    (tmp_path / name).write_text("BROKEN(\n")

    code = _sh(script, tmp_path)

    assert not (tmp_path / "pwned").exists(), "sh ran a smuggled command"
    assert code != 0, "the broken file passed the check"


def test_a_filename_that_looks_like_a_flag_is_still_a_filename(
        monkeypatch, tmp_path):
    """Quoting and `./` fix two different things. Quoting stops sh splitting
    the word; it does nothing about node reading `-e.js` as --eval and never
    looking at the file. The check would report a pass on a file it never
    opened."""
    name = "-e.js"
    script, _ = _script_for(monkeypatch, {name: "var a = 1;\n"})
    (tmp_path / name).write_text("var a = 1;\n")

    assert _sh(script, tmp_path) == 0


def test_a_path_that_leaves_the_workdir_is_never_written(
        monkeypatch, tmp_path):
    """minimal_check writes plan.files onto the HOST with
    os.path.join(workdir, path); _extract_repo_relative has guarded this
    shape for as long as it has existed and this one did not."""
    for escape in ("../pwned.js", "/tmp/pwned.js"):
        script, argv = _script_for(monkeypatch, {escape: "var a = 1;\n"})

        assert argv == [], f"{escape} reached docker"


def test_an_ordinary_path_still_reaches_node(monkeypatch, tmp_path):
    """The guard rejects a shape, not every path -- without this the previous
    test passes on a minimal_check that checks nothing at all."""
    script, argv = _script_for(monkeypatch, {"src/app.js": "var a = 1;\n"})
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.js").write_text("var a = 1;\n")

    assert argv, "an ordinary changed file never reached docker"
    assert _sh(script, tmp_path) == 0


def test_recommendation_note_is_soft_and_mentions_tests():
    note = missing_tests_pr_note()
    assert "test" in note.lower()
    assert note.startswith(">")  # markdown blockquote, non-blocking tone


# --- run_semantic_check orchestration --------------------------------------

def test_run_semantic_check_blocks_on_regression(monkeypatch):
    results = iter([RunResult(5, 0, False, None),   # original
                    RunResult(3, 2, False, None)])  # patched
    monkeypatch.setattr(sc, "run_suite", lambda z, r: next(results))

    plan = FixpackPlan(files={"app.py": "x = 1\n"})
    verdict = run_semantic_check(_python_zip(), plan)
    assert verdict.ran is True
    assert verdict.ecosystem == "python"
    assert verdict.regression is True
    assert "new test failure" in verdict.detail
    assert verdict.pr_note is None


def test_run_semantic_check_passes_when_no_new_failures(monkeypatch):
    results = iter([RunResult(4, 1, False, None),   # already 1 red
                    RunResult(4, 1, False, None)])  # same after patch
    monkeypatch.setattr(sc, "run_suite", lambda z, r: next(results))

    verdict = run_semantic_check(_python_zip(), FixpackPlan(files={"a.py": "x=1\n"}))
    assert verdict.ran is True and verdict.regression is False


def test_run_semantic_check_no_runner_adds_note(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("no docker when there are no JS files / no suite")
    monkeypatch.setattr(sc, "_run", boom)

    zip_bytes = make_zip({"index.html": "<h1>hi</h1>\n"})
    plan = FixpackPlan(files={"config.py": "x = 1\n"})
    verdict = run_semantic_check(zip_bytes, plan)
    assert verdict.ran is False
    assert verdict.regression is False
    assert verdict.pr_note is not None and "test" in verdict.pr_note.lower()


def test_run_semantic_check_no_runner_blocks_on_broken_js(monkeypatch):
    monkeypatch.setattr(sc, "_run",
                        lambda argv, *, timeout: completed(argv, 1, "", "SyntaxError"))
    zip_bytes = make_zip({"index.html": "<h1>hi</h1>\n"})  # no runner
    plan = FixpackPlan(files={"app.js": "const x = (\n"})
    verdict = run_semantic_check(zip_bytes, plan)
    assert verdict.ran is False
    assert verdict.regression is True


# --- run_semantic_check: sandbox runner unavailable -------------------------

def test_run_semantic_check_defers_when_runner_unavailable(monkeypatch):
    verdict = run_semantic_check(
        _python_zip(), FixpackPlan(files={"a.py": "x=1\n"}),
        suite_runner=lambda z, r: _unavailable(),
    )
    assert verdict.verification_unavailable is True
    assert verdict.regression is False
    # `ran` must not claim a suite executed just because one was detected.
    assert verdict.ran is False
    assert "could not verify" in verdict.detail


def test_run_semantic_check_defers_when_only_patched_run_unavailable(monkeypatch):
    results = iter([RunResult(5, 0, False, None), _unavailable()])
    verdict = run_semantic_check(
        _python_zip(), FixpackPlan(files={"a.py": "x=1\n"}),
        suite_runner=lambda z, r: next(results),
    )
    assert verdict.verification_unavailable is True
    assert verdict.regression is False


def test_run_semantic_check_real_regression_is_untouched_by_the_new_flag():
    results = iter([RunResult(5, 0, False, None), RunResult(3, 2, False, None)])
    verdict = run_semantic_check(
        _python_zip(), FixpackPlan(files={"a.py": "x=1\n"}),
        suite_runner=lambda z, r: next(results),
    )
    assert (verdict.regression, verdict.verification_unavailable,
            verdict.ran) == (True, False, True)


def test_run_semantic_check_symmetric_install_failure_is_untouched():
    # The runner answered; the client's repo genuinely can't install deps. An
    # honest baseline fact, so: not a regression, and NOT "unavailable".
    err = RunResult(0, 0, False, "dependency install failed (exit 1)")
    verdict = run_semantic_check(
        _python_zip(), FixpackPlan(files={"a.py": "x=1\n"}),
        suite_runner=lambda z, r: err,
    )
    assert (verdict.regression, verdict.verification_unavailable,
            verdict.ran) == (False, False, True)


def test_run_semantic_check_minimal_check_unavailable_is_not_a_clean_pass():
    zip_bytes = make_zip({"index.html": "<h1>hi</h1>\n"})  # no test runner
    verdict = run_semantic_check(
        zip_bytes, FixpackPlan(files={"app.js": "const x = 1;\n"}),
        minimal_checker=lambda plan: _unavailable(),
    )
    assert verdict.verification_unavailable is True
    assert verdict.regression is False
    assert verdict.ran is False
    assert "could not verify" in verdict.detail
    # must not read as "there just weren't any tests, all good"
    assert "syntax-only verification" not in verdict.detail
    assert verdict.pr_note is None


def test_run_semantic_check_minimal_check_clean_path_is_untouched():
    zip_bytes = make_zip({"index.html": "<h1>hi</h1>\n"})
    verdict = run_semantic_check(
        zip_bytes, FixpackPlan(files={"app.js": "const x = 1;\n"}),
        minimal_checker=lambda plan: RunResult(1, 0, False, None),
    )
    assert verdict.verification_unavailable is False
    assert verdict.regression is False
    assert "syntax-only verification" in verdict.detail
