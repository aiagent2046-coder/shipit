#!/usr/bin/env python3
"""Run the pinned, opt-in Cumora restoration experiment without model calls."""

import argparse
import datetime
import json
from pathlib import Path
import shutil
import sys
import tempfile

from .execute import bounded
from .process import cancellation_signals


def emergency_cleanup(work, out, variant, run_id):
    """Remove only this coordinator's disposable Compose project."""
    directory = out / variant
    directory.mkdir(exist_ok=True)
    compose_file = work / variant / "compose.yaml"
    # No Docker command can run until execute has copied its Compose file.
    if not compose_file.exists():
        return True
    project = "cumora-restore-" + run_id[:8] + "-" + variant
    args = [
        "docker",
        "compose",
        "--project-name",
        project,
        "--project-directory",
        str(work / variant),
        "-f",
        str(compose_file),
        "down",
        "--volumes",
        "--remove-orphans",
        "--rmi",
        "local",
    ]
    try:
        code = bounded(args, 90, directory / "emergency-cleanup.log")
    except OSError as error:
        (directory / "emergency-cleanup.log").write_text(str(error) + "\n")
        code = 125
    (directory / "emergency-cleanup-exit.txt").write_text(str(code) + "\n")
    return code == 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--prepare-only",
        action="store_true",
        help="Prepare and retain three source trees; do not invoke Docker or execute client code",
    )
    args = parser.parse_args(argv)
    repo = Path(__file__).resolve().parents[2]
    archive = args.archive.expanduser().resolve()
    out = (
        args.output
        or Path.cwd() / datetime.datetime.now(datetime.timezone.utc).strftime("cumora-restoration-%Y%m%dT%H%M%SZ")
    ).resolve()
    out.mkdir(parents=True, exist_ok=False)
    work = out / "work" if args.prepare_only else Path(tempfile.mkdtemp(prefix="cumora-restoration-"))
    work.mkdir(exist_ok=True)
    print(f"Результаты: {out}", flush=True)
    status = 2
    started = []
    plan = None

    def stage(module, arguments, seconds, logfile, *, grace=3):
        print(f"[{module}] Журнал: {out / logfile}; таймаут {seconds} с", flush=True)
        code = bounded(
            [sys.executable, "-m", "scripts.cumora_experiment." + module, *map(str, arguments)],
            seconds,
            out / logfile,
            cwd=repo,
            grace=grace,
        )
        if code:
            raise RuntimeError(f"{module} failed (exit {code}); see {out / logfile}")

    with cancellation_signals():
        try:
            if not args.prepare_only:
                if bounded(["docker", "version", "--format", "{{json .}}"], 15, out / "docker-version.json"):
                    raise RuntimeError("Docker unavailable")
                if bounded(["docker", "compose", "version"], 15, out / "compose-version.txt"):
                    raise RuntimeError("Compose unavailable")
            print("[detector] Анализирую архив и выбираю поддерживаемый сценарий...", flush=True)
            stage("prepare", ["detect", archive, out], 60, "detector.log")
            print("[researcher] Готовлю исходную, изменённую и восстановленную версии...", flush=True)
            # Two extractions each have a 120-second budget, plus hashing and copying.
            stage("prepare", ["plan", archive, work, out], 360, "researcher.log")
            plan = json.loads((out / "plan.json").read_text())
            if args.prepare_only:
                prepared = {
                    "schema_version": 1,
                    "cycle_status": "prepared",
                    "runtime_executed": False,
                    "llm_calls": 0,
                    "work_directory": str(work),
                    "customer_project_verified": False,
                    "controlled_restoration_verified": False,
                    "vulnerability_remediation_verified": False,
                    "automatic_patch": False,
                }
                (out / "experiment.json").write_text(json.dumps(prepared, indent=2) + "\n")
            else:
                for variant in ("baseline", "mutant", "restored"):
                    print(f"[experimenter] Вариант {variant}", flush=True)
                    started.append(variant)
                    # Covers every stage budget, with additional grace for cleanup on cancellation.
                    stage(
                        "execute",
                        [work / variant, out / variant, variant, out / "plan.json"],
                        2400,
                        variant + "-experimenter.log",
                        grace=125,
                    )
                print("[verifier] Сравниваю фактические результаты...", flush=True)
                stage("compare", [out], 30, "experiment.json")
            print((out / "experiment.json").read_text(), flush=True)
            status = 0
        except (OSError, ValueError, RuntimeError, KeyboardInterrupt) as error:
            (out / "coordinator-error.txt").write_text(str(error) + "\n")
            print(f"Эксперимент не завершён: {error}", file=sys.stderr)
        finally:
            # Cancellation must not interrupt the bounded cleanup of our own resources.
            with cancellation_signals(ignore=True):
                clean = True
                for variant in started:
                    try:
                        receipt = json.loads((out / variant / "execution.json").read_text())
                        cleaned = type(receipt.get("cleanup_exit")) is int and receipt["cleanup_exit"] == 0
                    except (OSError, ValueError):
                        cleaned = False
                    if not cleaned:
                        cleaned = emergency_cleanup(work, out, variant, plan["variants"][variant]["run_id"])
                    clean = clean and cleaned
                if not clean:
                    status = 2
                    print(f"Очистка не завершена; рабочие Compose-файлы: {work}", file=sys.stderr)
                elif not args.prepare_only:
                    shutil.rmtree(work)
                (out / "exit-code.txt").write_text(str(status) + "\n")
                print(f"Evidence: {out} (exit {status})", flush=True)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
