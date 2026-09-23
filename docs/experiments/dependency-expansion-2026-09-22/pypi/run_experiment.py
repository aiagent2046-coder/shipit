"""Run pinned VTEX / Requests remediation evidence; only this reviewed repository."""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from source_guards import export_tracked_snapshot, prepare_scanner_snapshot

parser = argparse.ArgumentParser()
parser.add_argument("--scanner", type=Path, required=True)
parser.add_argument("--project", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
a = parser.parse_args()
a.scanner = a.scanner.resolve()
a.project = a.project.resolve()
a.output = a.output.resolve()
a.output.mkdir(parents=True, exist_ok=False)
PIN = "c957049c51b7e070e6c91f6212ade5216f7343cb"
SCANNER = "0b5c981412ad0a9ab62ad4a7a6da1b90a0acd67b"

# Export Git objects before importing scanner or project code. No checkout-local
# conftest, shadow modules, ignored files or bytecode can enter either snapshot.
a.scanner = prepare_scanner_snapshot(a.scanner, a.output / "scanner", SCANNER)
a.project = export_tracked_snapshot(a.project, a.output / "project", PIN)
sys.path.insert(0, str(a.scanner / "scripts"))
from verify_dependency_remediation import (  # noqa: E402
    Case,
    execution_env,
    remediation_record,
    scan,
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def run(args, log, *, cwd=a.project, env=None):
    p = subprocess.run(
        [str(v) for v in args],
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=180,
        check=False,
    )
    (a.output / log).write_text(p.stdout)
    if p.returncode:
        raise RuntimeError(f"{log}: exit {p.returncode}")
    return p.stdout


catalog_raw = (a.scanner / "app/data/cve-catalog.json").read_bytes()
assert sha(catalog_raw) == "e8cc8c6a60e29331c42f0c50bbdb57484766b947d377afc966c723ec7b3347af"
catalog = json.loads(catalog_raw)
case = Case("PyPI", "requests", "2.31.0", "2.33.0", "vtex", "0.2.0", 7)
manifest = a.project / "requirements.txt"
original = manifest.read_bytes()
source_files = sorted(str(path.relative_to(a.project)) for path in a.project.rglob("*") if path.is_file())
source_hashes = {name: sha((a.project / name).read_bytes()) for name in source_files if name}
source_digest = sha(json.dumps(source_hashes, sort_keys=True).encode())
home = a.output / "home"
home.mkdir(exist_ok=True)
env = execution_env(home)
env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
for k in ("ALL_PROXY", "all_proxy"):
    env.pop(k, None)
versions = []
stages = []
try:
    for stage, version in [("before", "2.31.0"), ("after", "2.33.0"), ("restore", "2.31.0")]:
        raw = original.replace(b"requests==2.31.0", f"requests=={version}".encode())
        manifest.write_bytes(raw)
        report = scan({"requirements.txt": raw}, case, catalog)
        targets = [f for f in report["findings"] if f["claim_evidence"]["package"] == "requests"]
        assessments = report["target_entry_assessments"]
        target_inventory = [r for r in report["inventory"] if r["package"] == "requests"]
        assert target_inventory and all(r["complete"] and r["version"] == version for r in target_inventory)
        assert len(assessments) == 8 and all(
            not e["unresolved_ranges"] and e["status"] in ("affected", "unaffected") for e in assessments
        )
        if stage == "after":
            assert not targets and all(e["status"] == "unaffected" for e in assessments)
        else:
            assert len(targets) == 3
            assert all(
                version != "2.33.0" and "2.33.0" in remediation_record(f["claim_evidence"])["candidate_versions"]
                for f in targets
            )
        venv = a.output / f"venv-{stage}"
        run(["uv", "venv", venv, "--python", sys.executable], f"{stage}-venv.log", env=env)
        py = venv / "bin/python"
        if stage == "before":
            run(
                [
                    "uv",
                    "pip",
                    "install",
                    "--python",
                    py,
                    "--only-binary",
                    ":all:",
                    "-r",
                    manifest,
                    "-c",
                    Path(__file__).with_name("environment-before.txt"),
                ],
                f"{stage}-install.log",
                env=env,
            )
        else:
            lock = "\n".join(x.replace("requests==2.31.0", f"requests=={version}") for x in versions) + "\n"
            lockpath = a.output / f"{stage}-environment.txt"
            lockpath.write_text(lock)
            run(
                ["uv", "pip", "install", "--python", py, "--only-binary", ":all:", "--no-deps", "-r", lockpath],
                f"{stage}-install.log",
                env=env,
            )
        run(["uv", "pip", "check", "--python", py], f"{stage}-pip-check.log", env=env)
        origin = json.loads(
            run(
                [
                    py,
                    "-c",
                    'import requests,sys,json; '
                    'print(json.dumps({"prefix":sys.prefix,"requests_file":requests.__file__}))',
                ],
                f"{stage}-import-origin.json",
                env=env,
            )
        )
        assert Path(origin["requests_file"]).is_relative_to(venv)
        frozen = (
            run(
                [
                    py,
                    "-c",
                    'import importlib.metadata as m; '
                'print("\\n".join(sorted(d.metadata["Name"].lower()+"=="+d.version for d in m.distributions())))',
                ],
                f"{stage}-freeze.txt",
                env=env,
            )
            .strip()
            .splitlines()
        )
        if stage == "before":
            versions = frozen
            (a.output / "before-environment.txt").write_text("\n".join(frozen) + "\n")
        assert frozen == sorted(x.replace("requests==2.31.0", f"requests=={version}") for x in versions)
        unit = run(
            [py, "-m", "pytest", "-q", "tests/unit_tests", f"--junitxml={a.output / (stage + '-upstream.xml')}"],
            f"{stage}-upstream.log",
            env=env,
        )
        assert "2 passed" in unit
        probe = json.loads(
            run([py, Path(__file__).with_name("probe.py"), a.project], f"{stage}-consumer.json", env=env)
        )
        assert probe["installed_version"] == version and probe["consumer_checks_count"] == 7
        assert probe["upstream_regression"]["credential_misbinding_observed"] is (stage != "after")
        (a.output / f"{stage}-scan.json").write_text(json.dumps(report, indent=2) + "\n")
        (a.output / f"{stage}-requirements.txt").write_bytes(raw)
        stages.append(
            {
                "stage": stage,
                "manifest_sha256": sha(raw),
                "target_findings": len(targets),
                "target_entry_statuses": [r["status"] for r in assessments],
                "coverage": report["coverage"]["status_counts"],
                "installed_inventory": frozen,
                "import_origin": origin,
                "upstream_tests": {"passed": 2, "scope": "unit import smoke tests only"},
                "consumer": probe,
            }
        )
finally:
    manifest.write_bytes(original)
assert all(sha((a.project / name).read_bytes()) == value for name, value in source_hashes.items())
assert stages[0]["manifest_sha256"] == stages[2]["manifest_sha256"]
assert stages[0]["installed_inventory"] == stages[2]["installed_inventory"]
assert sha(catalog_raw) == sha((a.scanner / "app/data/cve-catalog.json").read_bytes())
evidence = {
    "status": "passed",
    "scope": "pinned_project_dependency_experiment",
    "automatic_patch": False,
    "application_exploitability_verified": False,
    "whole_project_verified": False,
    "upstream_repository": "https://github.com/lmeilibr/vtex",
    "upstream_commit": PIN,
    "scanner_commit": SCANNER,
    "source_files_sha256": source_hashes,
    "source_digest": source_digest,
    "catalog_sha256": sha(catalog_raw),
    "target": "PyPI:requests",
    "candidate": "2.33.0",
    "unrelated_dependency_changes": [],
    "stages": stages,
    "limitations": [
        "Upstream unit tests are only two import smoke tests.",
        "VTEX live integration tests require a real account and were not run.",
        "Seven added consumer checks use the actual VTEX client with an in-memory HTTP adapter.",
        "The Requests security regression is offline dependency behavior, not proven application exploitability.",
        "The source manifest has no complete transitive lock; the recorded resolved inventory is experiment-specific.",
        "Pytest advisory CVE-2025-71176 remains unknown due to incomplete advisory sources in this catalog.",
        "No claim that the whole project is clean or that all Requests advisories were exercised dynamically.",
    ],
}
(a.output / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
print(
    json.dumps(
        {"status": "passed", "findings": [s["target_findings"] for s in stages], "catalog_sha256": sha(catalog_raw)}
    )
)
