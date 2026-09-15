#!/usr/bin/env python3
"""Exercise an installed local wheel; reference mode runs the same shared engine.

Clean environment: python -I scripts/verify_local_package.py --reference report.json
Source reference: PYTHONPATH=. python scripts/verify_local_package.py \
    --module app --write-reference report.json
Only the harness uses subprocesses; scanning must not use the network or execute code.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack, closing, redirect_stdout
import importlib
import importlib.metadata
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
from unittest.mock import patch
import urllib.request


CAMEL_ROUTES = '''from fastapi import APIRouter, Depends
router = APIRouter()
@router.get("/audits/{auditId}")
async def detail_(auditId, authToken, auditRepo_=Depends(getAuditRepo_)):
    return await auditRepo_.getAuthorized(auditId, authToken)
@router.get("/audits/{auditId}/status")
async def status_(auditId, auditRepo_=Depends(getAuditRepo_)):
    return await auditRepo_.get(auditId)
'''
JAVASCRIPT = '''export function issue(res, token, html, supabase) {
  const resetToken = Math.random();
  res.cookie("session", token, { httpOnly: false });
  document.body.innerHTML = html;
  return supabase.from("private_users").select("id");
}
'''
MIGRATION = '''CREATE TABLE public.private_users (id int, email text);
ALTER TABLE public.private_users ENABLE ROW LEVEL SECURITY;
CREATE POLICY read_users ON public.private_users FOR SELECT TO authenticated USING (true);
'''
DEPENDENCIES = {"pyyaml", "tree-sitter", "tree-sitter-typescript", "pglast"}
SERVER_DISTRIBUTIONS = {"fastapi", "httpx", "psycopg", "redis", "uvicorn", "shipit"}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def fixture(root: Path):
    files = {
        "routes.py": CAMEL_ROUTES,
        "src/server.ts": JAVASCRIPT,
        "migrations/001_users.sql": MIGRATION,
        "requirements.txt": "langflow==1.0.12\n",
        # This marker is relative and stable for cross-directory report parity.
        "canary.py": 'from pathlib import Path\nPath("EXECUTED").write_text("project code ran")\n'
                     'raise RuntimeError("Project source must never execute")\n',
    }
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    write_pnpm(root, "4.17.23")


def write_pnpm(root, version):
    # JSON is valid YAML; exercise the real pnpm parser without a harness dependency.
    (root / "pnpm-lock.yaml").write_text(json.dumps({
        "lockfileVersion": "9.0", "importers": {".": {"dependencies": {
            "lodash": {"specifier": "^4", "version": version}}}},
        "packages": {f"lodash@{version}": {"resolution": {"integrity": "sha512-example"}}},
        "snapshots": {f"lodash@{version}": {}},
    }), encoding="utf-8")


def normalized(report):
    # Strip only wall-clock fields; compare complete engine findings and coverage.
    value = json.loads(json.dumps(report))
    value.pop("created_at")
    value["catalog"].pop("age_days")
    value["catalog"].pop("stale")
    value["findings"].sort(key=lambda item: json.dumps(item, sort_keys=True))
    return value


def ids(report):
    result = set()
    for finding in report["findings"]:
        evidence = finding.get("claim_evidence", {})
        for name in ("cve_id", "advisory_id"):
            if evidence.get(name):
                result.add(evidence[name])
        result.update(evidence.get("aliases", []))
    return result


def captured_main(cli, arguments):
    output = io.StringIO()
    with redirect_stdout(output):
        status = cli.main(arguments)
    return status, json.loads(output.getvalue())


def installed_metadata():
    installed = {re.sub(r"[-_.]+", "-", item.metadata["Name"]).lower()
                 for item in importlib.metadata.distributions()}
    require(not (SERVER_DISTRIBUTIONS & installed), "Server dependencies installed in acceptance environment")
    require(importlib.util.find_spec("app") is None, "The installed wheel exposes or can see shared app namespace")
    distribution = importlib.metadata.distribution("drydock-local")
    requirements = {re.split(r"[\s<>=!~;\[]", item, maxsplit=1)[0].lower()
                    for item in distribution.requires or []}
    require(requirements == DEPENDENCIES, f"Unexpected standalone requirements: {requirements}")
    entrypoints = [entry for entry in distribution.entry_points
                   if entry.group == "console_scripts" and entry.name == "drydock-local"]
    require(len(entrypoints) == 1 and entrypoints[0].value == "drydock_local.local_cli:main",
            "Missing or incorrect installed console entry point")
    for name in ("yaml", "tree_sitter", "tree_sitter_typescript", "pglast"):
        importlib.import_module(name)
    return distribution.version


def exercise(namespace, temporary):
    root = temporary / "project"
    root.mkdir()
    fixture(root)
    cli = importlib.import_module(f"{namespace}.local_cli")
    store = importlib.import_module(f"{namespace}.local_store")
    state = temporary / "state"
    attempts = []

    def forbidden(*args, **kwargs):
        attempts.append("network_or_subprocess")
        raise AssertionError("Offline scanning attempted network access or execution")

    with ExitStack() as stack:
        for owner, name in ((socket.socket, "connect"), (socket.socket, "connect_ex"),
                            (socket, "create_connection"), (subprocess, "Popen"), (urllib.request, "urlopen")):
            stack.enter_context(patch.object(owner, name, forbidden))
        db = stack.enter_context(closing(store.connect(state)))
        key, first = cli.poll_project(db, root, state)
        require(first["runtime_verified"] is False, "Local report claims runtime verification")
        require(cli.exit_status(first, "none") == 0, "Fixture scan has unavailable or incomplete checks")
        rules = {item["rule_id"] for item in first["findings"]}
        require({"python-route-read-auth-consistency", "insecure-randomness", "xss-unsafe-html-injection"} <= rules,
                f"Lost Python/camelCase/JavaScript coverage: {rules}")
        require(any("cookie" in name for name in rules), "Native cookie check did not execute")
        require({"CVE-2026-2950", "CVE-2024-7297", "GHSA-56m6-4mhw-h3g5"} <= ids(first),
                "Pinned npm/PyPI CVE/GHSA positive boundaries did not match")
        require(first["dependency_cve"]["dependencies_checked"] == 2, "pnpm/Python inventory not fully checked")
        require(cli.poll_project(db, root, state, key)[1] is None, "Unchanged watch poll rescanned")

        # Actual SQL+JS cross-file collector must parse both halves, not merely import pglast.
        collector = importlib.import_module(f"{namespace}.scan.rls_recommendations")
        raw, _ = cli.snapshot(root, state)
        sql = collector.collect_rls_recommendations(io.BytesIO(raw))
        require(sql["migration_files"] == 1 and sql["records"], "SQL/JS policy context unavailable")
        require(sql["records"][0]["commands_in_declared_sequence"] == ["SELECT"],
                "SQL policy evidence was lost")

        requirement = root / "requirements.txt"
        before = requirement.stat()
        requirement.write_text("langflow==1.0.13\n", encoding="utf-8")
        os.utime(requirement, ns=(before.st_atime_ns, before.st_mtime_ns))
        second_key, second = cli.poll_project(db, root, state, key)
        require(second_key != key and second is not None, "Watcher missed equal-size/mtime content mutation")
        require(not ({"CVE-2024-7297", "GHSA-56m6-4mhw-h3g5"} & ids(second)),
                "PyPI fixed boundary still matches the targeted advisories")
        require(second["changes"]["no_longer_reported"] and second["changes"]["same_engine_and_catalog"],
                "Comparable watch history delta missing")
        write_pnpm(root, "4.18.0")
        _, third = cli.poll_project(db, root, state, second_key)
        require("CVE-2026-2950" not in ids(third), "npm fixed boundary still matches targeted CVE")
        require(third["dependency_cve"]["dependencies_checked"] == 2, "Mutation lost dependency coverage")

        status, history = captured_main(cli, ["--state-dir", str(state), "history", str(root)])
        require(status == 0 and len(history) == 3, "Persistent history did not record three scans")
        status, scan = captured_main(cli, ["--state-dir", str(state), "scan", str(root), "--json"])
        require(status == 0 and scan["mode"] == "local_offline", "CLI scan failed")
        # One watch iteration, then deterministic user interruption; no timer delay.
        with patch.object(cli.time, "sleep", side_effect=KeyboardInterrupt):
            status, watch = captured_main(cli, ["--state-dir", str(state), "watch", str(root), "--json"])
        require(status == 130 and watch["mode"] == "local_offline", "CLI watch did not stop cleanly")
    require(not attempts, "Scanner swallowed a forbidden network/process attempt")
    require(not (root / "EXECUTED").exists() and not (Path.cwd() / "EXECUTED").exists(),
            "Scanner executed the project canary")
    require(not any(name == "app" or name.startswith("app.") for name in sys.modules)
            if namespace != "app" else True, "Standalone runtime imported the shared app namespace")
    return {"first": normalized(first), "python_fixed": normalized(second), "npm_fixed": normalized(third)}, root


def console_check(root, temporary):
    executable = Path(sys.executable).parent / "drydock-local"
    require(executable.is_file(), "Console script was not installed in this venv")
    state = temporary / "console-state"
    environment = {key: value for key, value in os.environ.items() if key not in {"PYTHONPATH", "PYTHONHOME"}}
    for command in ([str(executable), "--help"],
                    [str(executable), "--state-dir", str(state), "scan", str(root), "--json"],
                    [str(executable), "--state-dir", str(state), "history", str(root)]):
        result = subprocess.run(command, cwd=temporary, env=environment, capture_output=True, text=True, timeout=60)
        require(result.returncode == 0, f"Installed console script failed: {result.stderr}")
        if command[-1] != "--help":
            json.loads(result.stdout)
    require(not (temporary / "EXECUTED").exists() and not (root / "EXECUTED").exists(),
            "Installed console script executed project source")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", choices=("app", "drydock_local"), default="drydock_local")
    parser.add_argument("--reference", type=Path)
    parser.add_argument("--write-reference", type=Path)
    args = parser.parse_args()
    version = installed_metadata() if args.module == "drydock_local" else "source-reference"
    with tempfile.TemporaryDirectory(prefix="drydock-installed-") as name:
        temporary = Path(name)
        reports, root = exercise(args.module, temporary)
        if args.module == "drydock_local":
            console_check(root, temporary)
        if args.reference:
            require(reports == json.loads(args.reference.read_text(encoding="utf-8")),
                    "Installed reports differ from the shared source engine")
        if args.write_reference:
            args.write_reference.write_text(json.dumps(reports, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "passed", "module": args.module, "version": version,
                      "findings": len(reports["first"]["findings"]), "dependency_boundaries": "npm_and_pypi",
                      "offline_scan": True, "watch_and_history": True, "native_sql_js": True,
                      "source_parity": bool(args.reference), "console_entry": args.module == "drydock_local"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
