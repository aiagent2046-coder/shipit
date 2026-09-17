"""Check that selected security properties reject six concrete regressions.

This is a bounded sensitivity check, not a repository-wide mutation score.
Only temporary copies of app/ and tests/ are modified. A clean baseline must
pass first; collection errors, skipped tests, timeouts and non-assertion
failures never count as detecting a mutation. Logs and JUnit XML are retained.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
SEED = "20260917"


@dataclass(frozen=True)
class Mutation:
    name: str
    path: str
    before: str
    after: str
    target: str
    postgres: bool = False


MUTATIONS = (
    Mutation(
        "cve-exclusive-upper-bound", "app/scan/cve_match.py",
        "upper_relation > 0 or (exclusive is not None and upper_relation == 0)",
        "upper_relation > 0",
        "tests/test_cve_properties.py::test_generated_cve_and_osv_bounds_follow_integer_interval",
    ),
    Mutation(
        "cve-uncertainty-reported-unaffected", "app/scan/cve_match.py",
        'status = next(iter(statuses)) if len(statuses) == 1 and not truncated else "unknown"',
        'status = next(iter(statuses)) if len(statuses) == 1 and not truncated else "unaffected"',
        "tests/test_cve_properties.py::test_source_uncertainty_and_evidence_survive_source_reordering",
    ),
    Mutation(
        "dependency-second-origin-dropped", "app/sca/lockfiles.py",
        "occurrences=occurrences,",
        "occurrences=occurrences[:1],",
        "tests/test_dependency_occurrence_properties.py::"
        "test_two_manifests_retain_both_origins_without_duplicate_assessments",
    ),
    Mutation(
        "malformed-manifest-gap-hidden", "app/sca/lockfiles.py",
        "incomplete[manifest] = reason",
        "pass  # deliberately lose a selected manifest's failure",
        "tests/test_manifest_fuzz_integration.py::"
        "test_malformed_lockfile_cannot_report_success_with_retained_positive",
    ),
    Mutation(
        "rls-ownership-bypassed", "app/routes/rls_check.py",
        "audit = await audit_repo.get_authorized(audit_id, token)",
        "audit = await audit_repo.get(audit_id)",
        "tests/test_authorization_properties.py::test_rejected_rls_capabilities_do_not_fetch_write_or_spend_owner_budget",
    ),
    Mutation(
        "payment-valid-replay-refused", "app/db.py",
        'if row is None or row["tier"] != TIER_PRO:',
        'if row is None or row["tier"] == TIER_PRO:',
        "tests/test_billing_properties_postgres.py::test_reordered_replays_preserve_independent_grants",
        postgres=True,
    ),
)


def classify(returncode: int, report: Path, *, mutated: bool) -> str:
    """A failed assertion is evidence; an unavailable check is not."""
    try:
        root = ET.parse(report).getroot()
    except (OSError, ET.ParseError):
        return "invalid"
    cases = list(root.iter("testcase"))
    if not cases or any(case.find("error") is not None or case.find("skipped") is not None for case in cases):
        return "invalid"
    failures = [failure for case in cases for failure in case.findall("failure")]
    if not mutated:
        return "passed" if returncode == 0 and not failures else "invalid"
    if returncode == 0 and not failures:
        return "survived"
    # Hypothesis may combine an assertion with an unrelated exception in one
    # ExceptionGroup. Its traceback mentions AssertionError, but the probe
    # did not complete cleanly. Only the top-level exception is evidence.
    if returncode == 1 and failures and all(
        failure.get("message", "") == "AssertionError"
        or failure.get("message", "").startswith(("AssertionError:", "assert "))
        for failure in failures
    ):
        return "detected"
    return "invalid"


def run_tests(workspace: Path, output: Path, name: str, targets: list[str], *, mutated: bool) -> dict:
    report = output / f"{name}.xml"
    command = [sys.executable, "-m", "pytest", "-q", "--tb=short",
               f"--hypothesis-seed={SEED}", f"--junitxml={report}", *targets]
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
           "HYPOTHESIS_STORAGE_DIRECTORY": str(workspace / ".hypothesis")}
    try:
        run = subprocess.run(command, cwd=workspace, env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, timeout=180)
        log, code = run.stdout, run.returncode
        status = classify(code, report, mutated=mutated)
    except subprocess.TimeoutExpired as exc:
        raw = exc.stdout or b""
        log = raw.decode(errors="replace") if isinstance(raw, bytes) else raw
        log += "\nMutation probe timed out; this is not evidence of a detected regression.\n"
        code, status = None, "invalid"
    (output / f"{name}.log").write_text(log, encoding="utf-8")
    print(f"{name}: {status}", flush=True)
    return {"name": name, "status": status, "exit_code": code, "targets": targets, "seed": SEED}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--with-postgres", action="store_true", help="Include real-DB payment properties")
    parser.add_argument("--output-dir", type=Path, required=True, help="New directory for logs and JUnit evidence")
    args = parser.parse_args()
    if args.with_postgres and not os.environ.get("DATABASE_URL"):
        parser.error("--with-postgres requires DATABASE_URL for an already migrated disposable PostgreSQL")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    selected = [mutation for mutation in MUTATIONS if args.with_postgres or not mutation.postgres]
    results = []
    with tempfile.TemporaryDirectory(prefix="drydock-security-mutations-") as temporary:
        workspace = Path(temporary)
        for directory in ("app", "tests"):
            shutil.copytree(ROOT / directory, workspace / directory,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copy2(ROOT / "pyproject.toml", workspace / "pyproject.toml")
        targets = sorted({mutation.target.split("::")[0] for mutation in selected})
        baseline = run_tests(workspace, output, "baseline", targets, mutated=False)
        results.append(baseline)
        if baseline["status"] == "passed":
            for mutation in selected:
                path = workspace / mutation.path
                original = path.read_text(encoding="utf-8")
                if original.count(mutation.before) != 1:
                    raise RuntimeError(f"{mutation.name}: mutation anchor must match exactly once")
                changed = original.replace(mutation.before, mutation.after, 1)
                try:
                    path.write_text(changed, encoding="utf-8")
                    result = run_tests(workspace, output, mutation.name, [mutation.target], mutated=True)
                    result.update({"source": mutation.path,
                                   "original_sha256": hashlib.sha256(original.encode()).hexdigest(),
                                   "mutated_sha256": hashlib.sha256(changed.encode()).hexdigest()})
                    results.append(result)
                finally:
                    path.write_text(original, encoding="utf-8")
    (output / "summary.json").write_text(json.dumps({"with_postgres": args.with_postgres, "results": results},
                                                  indent=2) + "\n", encoding="utf-8")
    return 0 if len(results) == len(selected) + 1 and all(
        result["status"] == ("passed" if index == 0 else "detected") for index, result in enumerate(results)
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
