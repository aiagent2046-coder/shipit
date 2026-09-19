"""Lifecycle failures must stop further variants and clean owned resources."""

import json
import os
from pathlib import Path
import signal
import sys
import threading
import time

import pytest

from scripts.cumora_experiment import execute, run
from scripts.cumora_experiment.process import Cancelled, bounded, cancellation_signals


def test_timeout_kills_descendant_even_when_parent_exits_on_term(tmp_path):
    if not Path("/proc").exists():
        pytest.skip("Linux process state required")
    child = "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)"
    parent = (
        "import subprocess,sys,time; "
        f'p=subprocess.Popen([sys.executable,"-c",{child!r}]); '
        "print(p.pid,flush=True); time.sleep(60)"
    )
    log = tmp_path / "process.log"
    assert bounded([sys.executable, "-c", parent], 0.5, log, grace=0.2) == 124
    pid = int(log.read_text().strip())
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            state = Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1].split()[0]
        except FileNotFoundError:
            return
        if state == "Z":
            return
        time.sleep(0.01)
    pytest.fail("Descendant survived process group timeout")


def test_sigterm_propagates_cancellation_instead_of_timeout(tmp_path):
    timer = threading.Timer(0.2, lambda: os.kill(os.getpid(), signal.SIGTERM))
    try:
        with cancellation_signals(), pytest.raises(Cancelled):
            timer.start()
            bounded([sys.executable, "-c", "import time; time.sleep(60)"], 30, tmp_path / "cancel.log", grace=0.2)
    finally:
        timer.cancel()
        timer.join()


def fake_prepare(args, output):
    if args[3] == "plan":
        work = Path(args[5])
        plan = {
            "variants": {
                v: {"run_id": f"12345678-1234-4234-8234-{i:012d}"}
                for i, v in enumerate(("baseline", "mutant", "restored"))
            }
        }
        for variant in plan["variants"]:
            (work / variant).mkdir(parents=True)
            (work / variant / "compose.yaml").write_text("services: {}\n")
        (output / "plan.json").write_text(json.dumps(plan))


def test_prepare_only_never_calls_docker_and_preserves_trees(tmp_path, monkeypatch):
    output = tmp_path / "results"
    calls = []

    def command(args, seconds, path, **kwargs):
        calls.append(args)
        assert args[0] == sys.executable
        assert args[2] == "scripts.cumora_experiment.prepare"
        fake_prepare(args, output)
        Path(path).write_text("prepared\n")
        return 0

    monkeypatch.setattr(run, "bounded", command)
    assert run.main([str(tmp_path / "archive.zip"), "--output", str(output), "--prepare-only"]) == 0
    report = json.loads((output / "experiment.json").read_text())
    assert report["cycle_status"] == "prepared"
    assert report["runtime_executed"] is False
    assert report["controlled_restoration_verified"] is False
    assert all((output / "work" / name).is_dir() for name in ("baseline", "mutant", "restored"))
    assert len(calls) == 2


@pytest.mark.parametrize("cleanup_code", [0, 124])
def test_coordinator_cancel_stops_variants_and_performs_targeted_cleanup(tmp_path, monkeypatch, cleanup_code):
    output = tmp_path / "results"
    work = tmp_path / "temporary-work"
    work.mkdir()
    monkeypatch.setattr(run.tempfile, "mkdtemp", lambda **kwargs: str(work))
    calls = []

    def command(args, seconds, path, **kwargs):
        calls.append(args)
        if args[0] == sys.executable:
            if args[2].endswith(".prepare"):
                fake_prepare(args, output)
            elif args[2].endswith(".execute"):
                raise Cancelled("operator cancelled")
            else:
                pytest.fail("Verifier ran after cancellation")
        Path(path).write_text("")
        return cleanup_code if "down" in args else 0

    monkeypatch.setattr(run, "bounded", command)
    assert run.main([str(tmp_path / "archive.zip"), "--output", str(output)]) == 2
    executions = [c for c in calls if len(c) > 2 and c[2] == "scripts.cumora_experiment.execute"]
    assert len(executions) == 1
    assert executions[0][5] == "baseline"
    cleanup = [c for c in calls if "down" in c]
    assert len(cleanup) == 1
    assert cleanup[0][3] == "cumora-restore-12345678-baseline"
    assert work.exists() is bool(cleanup_code)
    assert (output / "exit-code.txt").read_text() == "2\n"


def test_experimenter_cleans_up_after_cancellation(tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    output = tmp_path / "output"
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"variants": {"baseline": {"run_id": "12345678-1234-4234-8234-123456789012"}}}))
    calls = []

    def command(args, seconds, path, **kwargs):
        calls.append(args)
        if "pull" in args:
            raise Cancelled("operator cancelled")
        Path(path).write_text("")
        return 0

    monkeypatch.setattr(execute, "bounded", command)
    assert execute.execute(work, output, "baseline", plan) == 2
    assert ["pull", "logs", "down"] == [next(s for s in ("pull", "logs", "down") if s in c) for c in calls]
    receipt = json.loads((output / "execution.json").read_text())
    assert receipt["status"] == "unavailable"
    assert receipt["cleanup_exit"] == 0
