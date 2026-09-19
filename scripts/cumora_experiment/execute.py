"""Experimenter process: execute one prepared variant and preserve raw evidence."""

import argparse
import json
from pathlib import Path
import shutil
import time
import uuid

from .process import bounded, cancellation_signals
from .prepare import digest, encoded, tree_entries

ARCHIVE = "dce64bacef7ffcc5f801d50447f035bd67ec14829a97a79401bb0d0a397e226d"


def bind_source(work, output, binding):
    """Check the complete prepared source before making its build manifest."""
    entries = tree_entries(work / "source")
    manifest = encoded(entries)
    if not entries or digest(manifest) != binding["tree_sha256"]:
        raise ValueError("prepared_source_tree_changed")
    (work / "source-manifest.json").write_bytes(manifest)
    (output / "source-manifest.json").write_bytes(manifest)


def execute(work, output, label, plan_path):
    kit = Path(__file__).resolve().parent
    output.mkdir(parents=True, exist_ok=False)
    plan = json.loads(plan_path.read_text())
    run_id = plan["variants"][label]["run_id"]
    if str(uuid.UUID(run_id)) != run_id:
        raise ValueError("invalid run ID")
    project = "cumora-restore-" + run_id[:8] + "-" + label
    compose = [
        "docker",
        "compose",
        "--project-name",
        project,
        "--project-directory",
        str(work),
        "-f",
        str(work / "compose.yaml"),
    ]
    container = project + "-app-1"
    (output / "run-id.txt").write_text(run_id + "\n")
    (output / "archive.txt").write_text("archive_sha256=" + ARCHIVE + "\n")
    for name in ["Dockerfile", "compose.yaml", "boot.sh", "probe.mjs", "scenario.mjs", "verify-source.mjs"]:
        shutil.copyfile(kit / name, work / name)
    shutil.copyfile(kit / "scenario.mjs", output / "scenario.mjs")
    result = {
        "variant": label,
        "run_id": run_id,
        "status": "unavailable",
        "project": project,
        "scenario_exit": None,
        "cleanup_exit": None,
        "readiness": False,
    }
    start = time.monotonic()
    try:
        for stage, args, seconds in [
            ("pull", compose + ["pull", "postgres", "redis"], 300),
            ("build", compose + ["build", "--progress", "plain"], 1200),
            ("start", compose + ["up", "-d"], 120),
        ]:
            if stage == "build":
                bind_source(work, output, plan["variants"][label])
            print(f"[{label}] {stage}...", flush=True)
            code = bounded(args, seconds, output / (stage + ".log"))
            if code:
                raise RuntimeError(f"{stage}_exit_{code}")
        print(f"[{label}] HTTP readiness...", flush=True)
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            code = bounded(
                ["docker", "exec", container, "timeout", "--kill-after=2s", "15s", "node", "/control/probe.mjs"],
                20,
                output / "probe-attempt.log",
            )
            if code == 0:
                # Probe writes JSON only on success. Parse before accepting readiness.
                probe = json.loads((output / "probe-attempt.log").read_text())
                if probe.get("status") == "passed":
                    (output / "probe.json").write_text(json.dumps(probe, indent=2) + "\n")
                    result["readiness"] = True
                    break
            print(f"[{label}] readiness pending (exit {code})", flush=True)
            time.sleep(2)
        if not result["readiness"]:
            raise RuntimeError("readiness_unavailable")
        inspect = bounded(["docker", "inspect", "--format", "{{.Image}}", container], 15, output / "image-id.txt")
        if inspect:
            raise RuntimeError("image_identity_unavailable")
        hash_script = (
            "process.stdout.write(require('node:crypto').createHash('sha256')"
            ".update(require('node:fs').readFileSync('/app/server/src/api/router.ts'))"
            ".digest('hex')+'\\n')"
        )
        code = bounded(
            ["docker", "exec", container, "node", "-e", hash_script], 15, output / "observed-router-sha256.txt"
        )
        if code:
            raise RuntimeError("source_identity_unavailable")
        code = bounded(
            [
                "docker", "exec", container, "node", "/control/verify-source.mjs",
                "/app", "/control/source-manifest.json", plan["variants"][label]["tree_sha256"],
            ],
            30,
            output / "observed-tree-sha256.txt",
            output / "source-verification.log",
        )
        if code or (output / "observed-tree-sha256.txt").read_text().strip() != plan["variants"][label]["tree_sha256"]:
            raise RuntimeError("executed_source_tree_mismatch")
        print(f"[{label}] preparing identical disposable database fixtures...", flush=True)
        code = bounded(
            [
                "docker",
                "exec",
                project + "-postgres-1",
                "psql",
                "-U",
                "control",
                "-d",
                "cumora_control",
                "-qAt",
                "-v",
                "ON_ERROR_STOP=1",
                "-c",
                "DELETE FROM projects; SELECT count(*) FROM projects;",
            ],
            15,
            output / "fixture-reset.log",
        )
        if code or (output / "fixture-reset.log").read_text().strip() != "0":
            raise RuntimeError("fixture_preparation_failed")
        print(f"[{label}] executing same API/DB scenario...", flush=True)
        # The scenario has no expected-variant flag: it only measures actual behavior.
        code = bounded(
            [
                "docker",
                "exec",
                "-e",
                "CONTROL_RUN_ID=" + run_id,
                "-e",
                "CONTROL_ARCHIVE_SHA256=" + ARCHIVE,
                container,
                "timeout",
                "--kill-after=3s",
                "90",
                "node",
                "/app/control-scenario.mjs",
            ],
            100,
            output / "scenario.json",
            output / "scenario.log",
        )
        result["scenario_exit"] = code
        (output / "scenario-exit.txt").write_text(str(code) + "\n")
        result["status"] = "executed" if code in (0, 1) else "unavailable"
    except (OSError, ValueError, RuntimeError, KeyboardInterrupt) as error:
        result["error"] = str(error)
        print(f"[{label}] unavailable: {error}", flush=True)
    finally:
        print(f"[{label}] collecting logs and cleaning up...", flush=True)
        try:
            with cancellation_signals(ignore=True):
                bounded(compose + ["logs", "--no-color"], 20, output / "containers.log")
                cleanup = bounded(
                    compose + ["down", "--volumes", "--remove-orphans", "--rmi", "local"], 90, output / "cleanup.log"
                )
        except OSError:
            cleanup = 125
        result["cleanup_exit"] = cleanup
        if cleanup:
            result["status"] = "unavailable"
        (output / "cleanup-exit.txt").write_text(str(cleanup) + "\n")
        result["elapsed_seconds"] = round(time.monotonic() - start, 3)
        (output / "execution.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if result["status"] == "executed" else 2


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("work", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("variant", choices=["baseline", "mutant", "restored"])
    p.add_argument("plan", type=Path)
    a = p.parse_args()
    with cancellation_signals():
        raise SystemExit(execute(a.work.resolve(), a.output.resolve(), a.variant, a.plan.resolve()))
