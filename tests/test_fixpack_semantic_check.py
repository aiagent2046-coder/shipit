"""Unit tests for app/fixpack/semantic_check.

No real Docker: the single subprocess seam `semantic_check._run` is
monkeypatched, so detection, output parsing, the regression decision, the
minimal (no-suite) fallback, the recommendation note, and patched-tree
construction are all exercised deterministically. See scripts / a manual
run for real-Docker proof; the daemon is absent in CI and this sandbox.
"""

import io
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
    reg, detail = is_regression(RunResult(5, 0, False, None),
                                RunResult(3, 2, False, None))
    assert reg is True
    assert "2 new test failure" in detail


def test_no_regression_when_failures_equal_even_if_already_red():
    # Suite was already red before us; same count after => not our fault.
    reg, detail = is_regression(RunResult(4, 3, False, None),
                                RunResult(4, 3, False, None))
    assert reg is False


def test_no_regression_when_patched_fixed_some():
    reg, _ = is_regression(RunResult(3, 2, False, None),
                           RunResult(5, 0, False, None))
    assert reg is False


def test_regression_when_patched_errors_but_original_clean():
    reg, detail = is_regression(RunResult(5, 0, False, None),
                                RunResult(0, 0, False, "install failed"))
    assert reg is True
    assert "failed to execute" in detail


def test_symmetric_error_is_not_a_regression():
    # docker absent for BOTH runs => inconclusive, not "we broke it".
    reg, _ = is_regression(RunResult(0, 0, False, "docker CLI not available"),
                           RunResult(0, 0, False, "docker CLI not available"))
    assert reg is False


def test_regression_when_patched_times_out_but_original_completed():
    reg, detail = is_regression(RunResult(5, 0, False, None),
                                RunResult(0, 0, True, None))
    assert reg is True
    assert "timed out" in detail


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
    # --read-only would break pip/npm writes; must NOT be present (see NOTE).
    assert "--read-only" not in argv


def test_test_argv_has_resource_and_privilege_limits():
    argv = _docker_test_argv("node:20-slim", "/tmp/work", "npm test")
    assert _HARDENING.issubset(set(argv))
    assert "--network" in argv and "none" in argv   # existing net-off kept
    assert "--read-only" not in argv


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
    assert "-e" not in argv
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
    assert "-e" not in argv


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
