"""deploy-production.sh's rollback path, run for real against stubs.

Until now this script was covered by `bash -n` in CI, which checks syntax and
nothing else. It would never have caught what it was hiding: because the
rollback function is invoked from a conditional context, bash disables errexit
for its entire body, so every step ran regardless of the previous one failing
and the success line printed unconditionally. A deployment that never switched
the symlink and never passed a health check reported "Automatic rollback
completed" and looked fine in the operator's terminal.

The harness runs the actual script with `systemctl` and `python3` replaced by
stubs on PATH and every SHIPIT_* path pointed at a tmpdir. Each stub reads a
rules file saying which invocation should fail, which is what lets one test
fail the migration gate on the rollback path while another fails the second
`systemctl restart` -- the script issues several of both, and a stub that could
only match on a substring would fail the wrong one and quietly test nothing.

Deliberately not a unit test of a shell function: extracting the function into
a sourceable file to test it in isolation would test a copy of the arrangement,
and the arrangement -- being called under `||` -- IS the bug.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[1] / "deploy" / "scripts" / "deploy-production.sh"
)

ROLLBACK_SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "scripts"
    / "rollback-production.sh"
)

# The rolled-back-to release is only ever a directory name and the target of
# `current`, so a synthetic hex string is fine. The DEPLOYED one is not: the
# script resolves it with `git rev-parse --verify`, so it has to be a real
# commit in the control checkout, discovered after that repo is created.
OLD_SHA = "a" * 40

SYNC_SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "scripts"
    / "sync-release-systemd-unit.sh"
)
FIXPACK_TIMER = "shipit-fixpack.timer"


def _unit_text(sha: str) -> str:
    return f"""\
[Unit]
Description=Fix Pack processor for {sha}

[Service]
Type=oneshot
ExecStart=/bin/true
"""

# Failing the deployment's own health check is how every rollback test gets the
# script into the rollback branch in the first place. Occurrence 1 because the
# rollback runs the identical command afterwards, and that one must pass.
DEPLOYMENT_FAILS = {"patterns": ["health_gate.py", "127.0.0.1:8000"], "occurrence": 1}


def _write(path: Path, body: str, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body).lstrip())
    if executable:
        path.chmod(0o755)


def _stub_bin(tmp: Path, rules: list[dict]) -> Path:
    """PATH stubs for the two external commands the script drives.

    Written in Python against the real interpreter's absolute path, because the
    stub has to shadow `python3` on PATH and cannot then use it for itself.

    A rule matches when ALL its patterns appear in the joined argv, and fails
    the run only on its `occurrence`-th match. Both halves are load-bearing:
    the script runs the health gate twice with identical arguments (deployment,
    then rollback), and runs the migration gate against two different releases.

    Every invocation is appended to calls.log, which assertions read to prove a
    step was skipped rather than merely unreported.
    """
    bin_dir = tmp / "bin"
    rules_file = tmp / "rules.json"
    rules_file.write_text(json.dumps(rules))

    stub = f"""
        #!{sys.executable}
        import json, os, subprocess, sys
        from pathlib import Path

        tmp = Path({str(tmp)!r})
        name = Path(sys.argv[0]).name
        argv = " ".join(sys.argv[1:])
        with (tmp / "calls.log").open("a") as fh:
            fh.write(f"{{name}} {{argv}}\\n")

        rules = json.loads((tmp / "rules.json").read_text())
        state_path = tmp / "counts.json"
        state = json.loads(state_path.read_text()) if state_path.exists() else {{}}
        # Every matching rule's counter advances before any of them decides.
        # Short-circuiting on the first match instead would leave a second rule
        # over the same command a call behind, so "fail the 1st and the 2nd
        # health check" would silently fail only the 1st.
        should_fail = False
        for i, rule in enumerate(rules):
            if all(p in argv for p in rule["patterns"]):
                n = state.get(str(i), 0) + 1
                state[str(i)] = n
                if n == rule["occurrence"]:
                    should_fail = True
        state_path.write_text(json.dumps(state))
        if should_fail:
            print(f"stub: {{name}} failing on purpose", file=sys.stderr)
            sys.exit(1)

        # `activate` moves the symlink for real, so a test can tell a rollback
        # that happened from one that was only claimed.
        if "activate" in sys.argv:
            sha = sys.argv[sys.argv.index("--sha") + 1]
            link = tmp / "srv" / "current"
            if link.is_symlink():
                link.unlink()
            link.symlink_to(tmp / "srv" / "releases" / sha)
        sys.exit(0)
    """
    for name in ("python3", "systemctl", "systemd-analyze"):
        _write(bin_dir / name, stub, executable=True)

    for name in ("flock", "git", "readlink", "basename", "mkdir", "ln", "dirname",
                 "bash", "cat"):
        real = shutil.which(name)
        if real:
            (bin_dir / name).symlink_to(real)
    return bin_dir


def _layout(tmp: Path) -> tuple[dict[str, str], str]:
    """A control checkout and two releases: enough for the script to clear its
    preflight checks and reach the deployment. Returns the environment and the
    real SHA to deploy."""
    control = tmp / "opt"
    srv = tmp / "srv"

    for name in ("release_manager.py", "check_release_migrations.py",
                 "health_gate.py"):
        _write(control / "deploy" / "scripts" / name, "")
    _write(control / ".env", "X=1\n")

    sync_script = (
        control / "deploy" / "scripts" / "sync-release-systemd-unit.sh"
    )
    shutil.copy2(SYNC_SCRIPT, sync_script)
    sync_script.chmod(0o755)

    subprocess.run(["git", "init", "-q", str(control)], check=True)
    subprocess.run(["git", "-C", str(control), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(control), "-c", "user.email=t@t", "-c", "user.name=t",
         "commit", "-qm", "x"], check=True)
    new_sha = subprocess.run(
        ["git", "-C", str(control), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True).stdout.strip()

    for sha in (OLD_SHA, new_sha):
        rel = srv / "releases" / sha
        (rel / ".venv" / "bin").mkdir(parents=True, exist_ok=True)
        _write(rel / ".venv" / "bin" / "python", "#!/usr/bin/env bash\nexit 0\n",
               executable=True)
        _write(rel / "deploy" / "scripts" / "validate-production-env.py", "")
        _write(
            rel / "deploy" / "systemd" / "shipit-fixpack.service",
            _unit_text(sha),
        )

    unit_dest = (
        tmp / "etc" / "systemd" / "system" / "shipit-fixpack.service"
    )
    _write(unit_dest, _unit_text(OLD_SHA))

    (srv / "current").symlink_to(srv / "releases" / OLD_SHA)

    return {
        "SHIPIT_CONTROL_ROOT": str(control),
        "SHIPIT_RELEASE_ROOT": str(srv),
        "SHIPIT_ENV_FILE": str(control / ".env"),
        "SHIPIT_RELEASE_ENV": str(control / ".release-env"),
        "SHIPIT_SERVICE": "stub.service",
        "SHIPIT_FIXPACK_TIMER": FIXPACK_TIMER,
        "SHIPIT_FIXPACK_UNIT_DEST": str(unit_dest),
        "SHIPIT_DEPLOY_LOCK": str(tmp / "deploy.lock"),
    }, new_sha


def _run(tmp: Path, rules: list[dict] | None = None,
         *, drop_current: bool = False) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    layout, new_sha = _layout(tmp)
    env.update(layout)
    if drop_current:
        (Path(layout["SHIPIT_RELEASE_ROOT"]) / "current").unlink()
    env["PATH"] = f"{_stub_bin(tmp, rules or [])}:{env['PATH']}"

    # The script refuses to run as anyone but root. EUID cannot be faked from
    # outside, so that guard is neutralised for the harness -- it is a
    # precondition, not part of the behaviour under test.
    src = SCRIPT.read_text().replace('if [[ "$EUID" -ne 0 ]]; then', "if false; then")
    harness = tmp / "deploy-under-test.sh"
    _write(harness, src, executable=True)
    return subprocess.run(
        ["bash", str(harness), "--revision", new_sha, "--skip-fetch"],
        capture_output=True, text=True, env=env, timeout=120,
    )


@pytest.fixture()
def tmp(tmp_path: Path) -> Path:
    return tmp_path


def _calls(tmp: Path) -> str:
    log = tmp / "calls.log"
    return log.read_text() if log.exists() else ""


def test_healthy_deployment_needs_no_rollback(tmp: Path):
    """Baseline: with nothing failing the script reports success and never
    enters the rollback function."""
    r = _run(tmp)
    assert r.returncode == 0, r.stderr
    assert "Production deployment: PASSED" in r.stdout
    assert "rollback" not in r.stdout.lower()


def test_failed_deployment_rolls_back_and_still_exits_non_zero(tmp: Path):
    """The happy path of the unhappy path: the deployment fails, the rollback
    works, and the script still exits 1 -- the DEPLOYMENT failed either way,
    and a zero exit here would tell CI the release went out."""
    r = _run(tmp, [DEPLOYMENT_FAILS])
    assert r.returncode == 1
    assert "Automatic rollback completed" in r.stdout
    assert "rolled back to" in r.stderr
    assert "ROLLBACK FAILED" not in r.stderr


def test_rollback_blocked_by_the_migration_gate_is_reported(tmp: Path):
    """THE regression. The gate refuses when the schema is ahead of the release
    being restored -- true for every deployment that carried a migration, which
    is exactly when a rollback matters most. This used to print "Automatic
    rollback completed" and exit as though the host were fine."""
    r = _run(tmp, [
        DEPLOYMENT_FAILS,
        # Only the gate on the rollback path, identified by the release it is
        # pointed at; the pre-deployment gate must still pass.
        {"patterns": ["check_release_migrations.py", OLD_SHA], "occurrence": 1},
    ])
    assert r.returncode == 1
    assert "Automatic rollback completed" not in r.stdout
    assert "ROLLBACK FAILED at step 'migration gate'" in r.stderr
    assert "FAILED, AND ROLLBACK FAILED" in r.stderr
    # It stopped there rather than restarting on top of a refused gate.
    assert f"activate --sha {OLD_SHA}" not in _calls(tmp)


def test_rollback_stops_when_the_service_will_not_restart(tmp: Path):
    """Second step, same contract: named, non-zero, and the health check that
    would have declared the service healthy is never reached."""
    r = _run(tmp, [
        DEPLOYMENT_FAILS,
        # Occurrence 2: the restart during the rollback, not the deployment's.
        {"patterns": ["restart", "stub.service"], "occurrence": 2},
    ])
    assert r.returncode == 1
    assert "Automatic rollback completed" not in r.stdout
    assert "ROLLBACK FAILED at step 'restart'" in r.stderr
    assert "FAILED, AND ROLLBACK FAILED" in r.stderr


def test_rollback_stops_when_the_restored_release_is_unhealthy(tmp: Path):
    """Both health checks fail: the new release AND the one being restored.
    That is an outage, and the operator has to be told in those words rather
    than read a success line."""
    r = _run(tmp, [
        {"patterns": ["health_gate.py", "127.0.0.1:8000"], "occurrence": 1},
        {"patterns": ["health_gate.py", "127.0.0.1:8000"], "occurrence": 2},
    ])
    assert r.returncode == 1
    assert "Automatic rollback completed" not in r.stdout
    assert "ROLLBACK FAILED at step 'local health'" in r.stderr
    assert "this is an outage" in r.stderr


def test_first_ever_deployment_has_nothing_to_roll_back_to(tmp: Path):
    """A different situation from a rollback that broke, and it reads
    differently: there is no previous release, not a failed restore."""
    r = _run(tmp, [DEPLOYMENT_FAILS], drop_current=True)
    assert r.returncode == 1
    assert "no previous release exists" in r.stderr
    assert "Automatic rollback completed" not in r.stdout


# --- the audit worker ---
#
# The scan runs in shipit-audit-worker.service, a long-lived process out of
# the `current` symlink. Swapping the symlink leaves it on the old code, and
# nothing here used to restart it: an engine fix could ship, pass both health
# gates, print PASSED, and never reach a single audit.

WORKER = "shipit-audit-worker.service"


def test_successful_deployment_restarts_the_audit_worker(tmp: Path):
    r = _run(tmp)
    assert r.returncode == 0, r.stderr
    assert f"systemctl restart {WORKER}" in _calls(tmp)


def test_worker_restarts_after_the_health_gates_not_before(tmp: Path):
    """Order matters: if the release is bad we roll back without ever having
    pointed the worker at it."""
    calls = _run(tmp) and _calls(tmp)
    lines = calls.splitlines()
    gate = max(i for i, ln in enumerate(lines) if "health_gate" in ln)
    worker = next(i for i, ln in enumerate(lines) if f"restart {WORKER}" in ln)
    assert worker > gate, f"worker restarted before the last health gate:\n{calls}"


def test_failed_deployment_never_touches_the_worker(tmp: Path):
    """Rolled back means the worker was never pointed at the bad release, so
    the rollback path has nothing to undo -- and must not pretend otherwise."""
    r = _run(tmp, [DEPLOYMENT_FAILS])
    assert r.returncode == 1
    assert f"restart {WORKER}" not in _calls(tmp)


def test_worker_that_will_not_restart_fails_the_run_without_rolling_back(tmp: Path):
    """The release itself is fine -- both gates passed. Undoing it would trade
    a working API for a broken one. Exit non-zero so the operator sees it."""
    r = _run(tmp, [{"patterns": ["restart", WORKER], "occurrence": 1}])
    assert r.returncode == 1
    assert "did not restart" in r.stderr
    assert "NOT rolled back" in r.stderr
    assert "Automatic rollback completed" not in r.stdout


def test_absent_worker_unit_is_reported_not_fatal(tmp: Path):
    """A host that does not run the scanner still deploys, but silence is how
    this bug survived, so it says so."""
    r = _run(tmp, [{"patterns": ["cat", WORKER], "occurrence": 1}])
    assert r.returncode == 0, r.stderr
    assert "is not installed here" in r.stdout
    assert "Production deployment: PASSED" in r.stdout
    assert f"restart {WORKER}" not in _calls(tmp)



# --- release-owned Fix Pack systemd unit ---


def _installed_fixpack_unit(tmp: Path) -> Path:
    return (
        tmp / "etc" / "systemd" / "system" / "shipit-fixpack.service"
    )


def test_successful_deployment_installs_target_fixpack_unit(tmp: Path):
    r = _run(tmp)

    assert r.returncode == 0, r.stderr

    active_sha = (tmp / "srv" / "current").resolve().name
    assert active_sha != OLD_SHA
    assert _installed_fixpack_unit(tmp).read_text() == _unit_text(active_sha)

    calls = _calls(tmp)
    assert "systemd-analyze verify" in calls
    assert "systemctl daemon-reload" in calls


def test_deployment_quiesces_fixpack_timer_until_health_passes(tmp: Path):
    r = _run(tmp)

    assert r.returncode == 0, r.stderr

    calls = _calls(tmp)
    lines = calls.splitlines()

    stop_timer = next(
        i for i, line in enumerate(lines)
        if f"systemctl stop {FIXPACK_TIMER}" in line
    )
    verify_unit = next(
        i for i, line in enumerate(lines)
        if "systemd-analyze verify" in line
    )
    restart_api = next(
        i for i, line in enumerate(lines)
        if "systemctl restart stub.service" in line
    )
    last_health = max(
        i for i, line in enumerate(lines)
        if "health_gate.py" in line
    )
    start_timer = next(
        i for i, line in enumerate(lines)
        if f"systemctl start {FIXPACK_TIMER}" in line
    )

    assert stop_timer < verify_unit < restart_api
    assert restart_api < last_health < start_timer


def test_failed_deployment_restores_previous_fixpack_unit_and_timer(
    tmp: Path,
):
    r = _run(tmp, [DEPLOYMENT_FAILS])

    assert r.returncode == 1
    assert "Automatic rollback completed" in r.stdout
    assert (tmp / "srv" / "current").resolve().name == OLD_SHA
    assert _installed_fixpack_unit(tmp).read_text() == _unit_text(OLD_SHA)

    lines = _calls(tmp).splitlines()

    stop_timer = next(
        i for i, line in enumerate(lines)
        if f"systemctl stop {FIXPACK_TIMER}" in line
    )
    start_timer = next(
        i for i, line in enumerate(lines)
        if f"systemctl start {FIXPACK_TIMER}" in line
    )
    verifies = [
        i for i, line in enumerate(lines)
        if "systemd-analyze verify" in line
    ]
    restarts = [
        i for i, line in enumerate(lines)
        if "systemctl restart stub.service" in line
    ]
    health_checks = [
        i for i, line in enumerate(lines)
        if "health_gate.py" in line
    ]

    assert len(verifies) == 2
    assert len(restarts) == 2
    assert len(health_checks) == 2

    # Target unit is installed before the failed target startup.
    assert stop_timer < verifies[0] < restarts[0] < health_checks[0]

    # Previous unit is restored before the old API restarts, and the timer
    # returns only after the restored release passes its health check.
    rollback_activation = next(
        i for i, line in enumerate(lines)
        if f"activate --sha {OLD_SHA}" in line
    )

    assert (
        health_checks[0]
        < verifies[1]
        < rollback_activation
        < restarts[1]
        < health_checks[1]
        < start_timer
    )


def test_failed_rollback_unit_sync_is_loud_and_keeps_timer_stopped(
    tmp: Path,
):
    r = _run(
        tmp,
        [
            DEPLOYMENT_FAILS,
            {
                "patterns": ["verify", OLD_SHA],
                "occurrence": 1,
            },
        ],
    )

    assert r.returncode == 1
    assert "Automatic rollback completed" not in r.stdout
    assert "ROLLBACK FAILED at step 'systemd unit'" in r.stderr
    assert "FAILED, AND ROLLBACK FAILED" in r.stderr

    # Unit verification failed before activation, so the active symlink and
    # installed unit must both remain on the failed deployment target.
    active_sha = (tmp / "srv" / "current").resolve().name
    assert active_sha != OLD_SHA

    calls = _calls(tmp)
    assert calls.count("systemctl restart stub.service") == 1
    assert f"systemctl start {FIXPACK_TIMER}" not in calls
    assert _installed_fixpack_unit(tmp).read_text() == _unit_text(active_sha)


# --- manual rollback release-owned unit ---


def _run_manual_rollback(
    tmp: Path,
    rules: list[dict] | None = None,
    public_base_url: str | None = None,
) -> tuple[subprocess.CompletedProcess, str]:
    env = dict(os.environ)
    layout, current_sha = _layout(tmp)
    env.update(layout)

    release_root = Path(layout["SHIPIT_RELEASE_ROOT"])
    current_link = release_root / "current"

    current_link.unlink()
    current_link.symlink_to(release_root / "releases" / current_sha)

    _installed_fixpack_unit(tmp).write_text(_unit_text(current_sha))

    env["PATH"] = f"{_stub_bin(tmp, rules or [])}:{env['PATH']}"

    src = ROLLBACK_SCRIPT.read_text().replace(
        'if [[ "$EUID" -ne 0 ]]; then',
        "if false; then",
    )

    harness = tmp / "rollback-under-test.sh"
    _write(harness, src, executable=True)

    command = [
        "bash",
        str(harness),
        "--sha",
        OLD_SHA,
    ]

    if public_base_url is not None:
        command.extend(["--public-base-url", public_base_url])

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )

    return result, current_sha


def test_manual_rollback_installs_target_unit_and_resumes_timer_after_health(
    tmp: Path,
):
    result, current_sha = _run_manual_rollback(tmp)

    assert result.returncode == 0, result.stderr
    assert current_sha != OLD_SHA
    assert (tmp / "srv" / "current").resolve().name == OLD_SHA
    assert _installed_fixpack_unit(tmp).read_text() == _unit_text(OLD_SHA)

    lines = _calls(tmp).splitlines()

    stop_timer = next(
        i for i, line in enumerate(lines)
        if f"systemctl stop {FIXPACK_TIMER}" in line
    )
    verify_target = next(
        i for i, line in enumerate(lines)
        if "systemd-analyze verify" in line
    )
    activate_target = next(
        i for i, line in enumerate(lines)
        if f"activate --sha {OLD_SHA}" in line
    )
    restart_api = next(
        i for i, line in enumerate(lines)
        if "systemctl restart stub.service" in line
    )
    health = next(
        i for i, line in enumerate(lines)
        if "health_gate.py" in line
    )
    start_timer = next(
        i for i, line in enumerate(lines)
        if f"systemctl start {FIXPACK_TIMER}" in line
    )

    assert (
        stop_timer
        < verify_target
        < activate_target
        < restart_api
        < health
        < start_timer
    )


def test_failed_manual_rollback_restores_current_unit_and_timer(
    tmp: Path,
):
    public_url = "https://rollback.example"

    result, current_sha = _run_manual_rollback(
        tmp,
        [
            {
                "patterns": ["health_gate.py", "127.0.0.1:8000"],
                "occurrence": 1,
            },
        ],
        public_base_url=public_url,
    )

    assert result.returncode == 1
    assert (tmp / "srv" / "current").resolve().name == current_sha
    assert _installed_fixpack_unit(tmp).read_text() == _unit_text(current_sha)

    lines = _calls(tmp).splitlines()

    verifies = [
        i for i, line in enumerate(lines)
        if "systemd-analyze verify" in line
    ]
    activations = [
        i for i, line in enumerate(lines)
        if "activate --sha" in line
    ]
    restarts = [
        i for i, line in enumerate(lines)
        if "systemctl restart stub.service" in line
    ]
    health_checks = [
        i for i, line in enumerate(lines)
        if "health_gate.py" in line
    ]
    start_timer = next(
        i for i, line in enumerate(lines)
        if f"systemctl start {FIXPACK_TIMER}" in line
    )

    assert len(verifies) == 2
    assert len(activations) == 2
    assert len(restarts) == 2
    assert len(health_checks) == 3

    assert "127.0.0.1:8000" in lines[health_checks[1]]
    assert public_url in lines[health_checks[2]]

    assert (
        verifies[0]
        < activations[0]
        < restarts[0]
        < health_checks[0]
        < verifies[1]
        < activations[1]
        < restarts[1]
        < health_checks[1]
        < health_checks[2]
        < start_timer
    )


def test_failed_deployment_activation_restores_previous_unit_and_timer(
    tmp: Path,
):
    result = _run(
        tmp,
        [
            {
                "patterns": ["release_manager.py", "activate"],
                "occurrence": 1,
            },
        ],
    )

    assert result.returncode == 1
    assert (tmp / "srv" / "current").resolve().name == OLD_SHA
    assert _installed_fixpack_unit(tmp).read_text() == _unit_text(OLD_SHA)

    calls = _calls(tmp)

    assert calls.count("systemd-analyze verify") == 2
    assert f"systemctl start {FIXPACK_TIMER}" in calls
    assert "Automatic rollback completed" in result.stdout


def test_failed_manual_rollback_activation_restores_current_unit_and_timer(
    tmp: Path,
):
    public_url = "https://rollback.example"

    result, current_sha = _run_manual_rollback(
        tmp,
        [
            {
                "patterns": ["release_manager.py", "activate"],
                "occurrence": 1,
            },
        ],
        public_base_url=public_url,
    )

    assert result.returncode == 1
    assert (tmp / "srv" / "current").resolve().name == current_sha
    assert _installed_fixpack_unit(tmp).read_text() == _unit_text(current_sha)

    calls = _calls(tmp)
    lines = calls.splitlines()

    health_checks = [
        i for i, line in enumerate(lines)
        if "health_gate.py" in line
    ]
    start_timer = next(
        i for i, line in enumerate(lines)
        if f"systemctl start {FIXPACK_TIMER}" in line
    )

    assert calls.count("systemd-analyze verify") == 2
    assert len(health_checks) == 2
    assert "127.0.0.1:8000" in lines[health_checks[0]]
    assert public_url in lines[health_checks[1]]
    assert health_checks[0] < health_checks[1] < start_timer
    assert "failed to activate rollback target" in result.stderr
