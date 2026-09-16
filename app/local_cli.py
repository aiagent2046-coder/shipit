"""Offline folder scan/watch with the shipped deterministic engine and catalog."""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import io
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import sys
import time
import zipfile

from app.ingest.validators import ArchiveValidationError
from app.local_store import connect, default_state_dir, load_catalog, update_catalog
from app.logging_config import configure_logging
from app.scan.browser import ScanSession
from app.scan.secrets import NON_PRODUCTION_CONTEXTS
from app.scan.version import AUDIT_ENGINE_VERSION

# Keep local archives within both the static and offline dependency matcher budgets.
MAX_FILES = 20_000
MAX_BYTES = 40_000_000
MAX_ENTRIES = 50_000
EXCLUDED_DIRS = frozenset({".git", "node_modules", ".venv", "venv", "__pycache__", ".drydock"})
SEVERITY_RANKS = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def snapshot(root: Path, state_dir: Path) -> tuple[bytes, dict]:
    """Bounded snapshot; descriptor-relative opens never follow file symlinks.

    Deliberately does not apply .gitignore: ignored .env/config files can matter.
    Unreadable or concurrently edited files fail the scan instead of disappearing.
    """
    if not root.is_dir():
        raise ValueError("project must be an existing directory")
    if root == state_dir or root.is_relative_to(state_dir):
        raise ValueError("project must not be inside the state directory")
    buf = io.BytesIO()
    counts = Counter()
    excluded = Counter()
    fingerprint = hashlib.sha256()

    def walk_error(error):
        raise error

    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for directory, dirs, files, directory_fd in os.fwalk(root, follow_symlinks=False, onerror=walk_error):
            relative = Path(directory).relative_to(root)
            counts["entries_seen"] += len(dirs) + len(files)
            if counts["entries_seen"] > MAX_ENTRIES:
                raise ValueError("project exceeds traversal limit")
            kept = []
            for name in sorted(dirs):
                path = Path(directory) / name
                mode = os.stat(name, dir_fd=directory_fd, follow_symlinks=False).st_mode
                if stat.S_ISLNK(mode):
                    excluded["symlinks"] += 1
                elif name in EXCLUDED_DIRS or path == state_dir:
                    excluded["directories"] += 1
                else:
                    kept.append(name)
            dirs[:] = kept
            for name in sorted(files):
                if name == ".git":  # Git worktrees use a metadata file instead of a directory.
                    excluded["git_metadata_files"] += 1
                    continue
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode):
                    excluded["symlinks" if stat.S_ISLNK(info.st_mode) else "special_files"] += 1
                    continue
                if counts["files"] >= MAX_FILES or counts["bytes"] + info.st_size > MAX_BYTES:
                    raise ValueError("project exceeds local scan budget (20,000 files / 40 MB)")
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
                with os.fdopen(fd, "rb") as handle:
                    before = os.fstat(handle.fileno())
                    if not stat.S_ISREG(before.st_mode):
                        raise ValueError("project changed during snapshot; retry")
                    body = handle.read(MAX_BYTES - counts["bytes"] + 1)
                    after = os.fstat(handle.fileno())
                if (before.st_mtime_ns, before.st_ctime_ns, before.st_size) != (
                        after.st_mtime_ns, after.st_ctime_ns, after.st_size):
                    raise ValueError("project changed during snapshot; retry")
                if len(body) + counts["bytes"] > MAX_BYTES:
                    raise ValueError("project exceeds local byte budget")
                path = (relative / name).as_posix()
                archive.writestr(path, body)
                fingerprint.update(path.encode() + b"\0" + hashlib.sha256(body).digest())
                counts["files"] += 1
                counts["bytes"] += len(body)
    # A change in exclusions is observable even when included source is unchanged.
    fingerprint.update(json.dumps(excluded, sort_keys=True).encode())
    return buf.getvalue(), {**counts, "excluded": dict(excluded),
                            "excluded_directory_names": sorted(EXCLUDED_DIRS),
                            "sha256": fingerprint.hexdigest()}


def _identity(finding: dict) -> str:
    evidence = finding.get("claim_evidence") or {}
    fields = [finding.get("rule_id"), finding.get("file"), finding.get("line"),
              evidence.get("advisory_id") or evidence.get("cve_id"), evidence.get("ecosystem"),
              evidence.get("package"), evidence.get("installed_version")]
    return hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()


def record(db: sqlite3.Connection, root: Path, report: dict) -> dict:
    identities = sorted({_identity(f) for f in report["findings"]})
    with db:
        previous = db.execute("SELECT summary, identities FROM scans WHERE root = ? ORDER BY id DESC LIMIT 1",
                              (str(root),)).fetchone()
        prior = set(json.loads(previous[1])) if previous else set()
        comparable = bool(previous and json.loads(previous[0])["catalog_sha256"] == report["catalog"]["sha256"]
                          and json.loads(previous[0])["engine_version"] == report["engine_version"])
        changes = {"baseline": previous is None, "new": sorted(set(identities) - prior),
                   "no_longer_reported": sorted(prior - set(identities)),
                   "same_engine_and_catalog": comparable,
                   "note": "Disappearance is not proof of a fix; inspect coverage and source changes."}
        summary = {"created_at": report["created_at"], "engine_version": report["engine_version"],
                   "catalog_sha256": report["catalog"]["sha256"], "findings": len(report["findings"]),
                   "checks_not_run": len(report["checks_not_run"]), "changes": changes}
        db.execute("INSERT INTO scans(root, created_at, summary, identities) VALUES (?, ?, ?, ?)",
                   (str(root), report["created_at"], json.dumps(summary), json.dumps(identities)))
        db.execute("DELETE FROM scans WHERE root = ? AND id NOT IN "
                   "(SELECT id FROM scans WHERE root = ? ORDER BY id DESC LIMIT 100)", (str(root), str(root)))
    return changes


def inspect_project(raw: bytes, scope: dict, catalog: dict, metadata: dict) -> dict:
    session = ScanSession(raw, catalog)
    result = session.result()
    # Resume supported bounded checks using the exact browser continuation map.
    for _ in range(128):
        if not result["can_continue"]:
            break
        result = session.continue_scan()
    report = result["report"]
    now = datetime.now(timezone.utc)
    ages = {name: max(0, (now - datetime.fromisoformat(source["generated_at"].replace("Z", "+00:00"))).days)
            for name, source in metadata["sources"].items()}
    report.update(created_at=now.isoformat(), mode="local_offline", snapshot=scope,
                  catalog={**metadata, "age_days": ages, "stale": any(age > 7 for age in ages.values())},
                  can_continue=result["can_continue"])
    report["limitations"] = list(dict.fromkeys([*report["limitations"], "selected_folder_only",
                                               "filesystem_snapshot_not_atomic"]))
    return report


def poll_project(db: sqlite3.Connection, root: Path, state_dir: Path,
                 previous_key: tuple | None = None) -> tuple[tuple, dict | None]:
    catalog, metadata = load_catalog(db)
    raw, scope = snapshot(root, state_dir)
    key = (scope["sha256"], metadata["sha256"], AUDIT_ENGINE_VERSION, datetime.now(timezone.utc).date().isoformat())
    if key == previous_key:
        return key, None
    report = inspect_project(raw, scope, catalog, metadata)
    report["changes"] = record(db, root, report)
    return key, report


def exit_status(report: dict, threshold: str) -> int:
    # 2 signals unavailable/incomplete execution; 1 is the requested finding gate.
    coverage = report.get("dependency_cve", {})
    if (report["checks_not_run"] or report["can_continue"]
            or any(any(row.get("skip_reasons", {}).values()) for row in report.get("rule_coverage", {}).values())
            or coverage.get("status") == "unavailable" or coverage.get("incomplete_manifests")
            or any(coverage.get(k) for k in ("inventory_truncated", "findings_truncated", "evaluations_truncated"))):
        return 2
    if threshold != "none" and any(SEVERITY_RANKS.get(f.get("severity"), -1) >= SEVERITY_RANKS[threshold]
                                   for f in report["findings"]):
        return 1
    return 0


def display(report: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report, ensure_ascii=False), flush=True)
        return
    changes = report["changes"]
    change_summary = "baseline recorded" if changes.get("baseline") else f"{len(changes['new'])} newly reported"
    print(f"Drydock local: {len(report['findings'])} findings; {change_summary}; "
          f"{len(report['checks_not_run'])} checks unavailable.")
    severity_counts = Counter(finding.get("severity", "unknown") for finding in report["findings"])
    print("Findings by severity: " + json.dumps(dict(sorted(
        severity_counts.items(), key=lambda row: (-SEVERITY_RANKS.get(row[0], -1), row[0])))))
    print(f"Catalog {report['catalog']['sha256'][:12]} — "
          f"{'STALE' if report['catalog']['stale'] else 'within 7-day freshness window'}; "
          f"source age in days: {json.dumps(report['catalog']['age_days'])}")
    dependency = report.get("dependency_cve", {})
    print("Dependency coverage: " + json.dumps({k: dependency.get(k) for k in
                                               ("status", "status_counts", "incomplete_manifests")}))
    if dependency.get("status_counts"):
        print("Dependency counts: affected/unaffected/unknown are assessment counts; "
              "not_in_catalog counts unlisted dependency entries.")
    if dependency.get("unknown_reason_counts"):
        print("Unknown dependency reasons: " + json.dumps(dependency["unknown_reason_counts"]))
        details = dependency.get("details", [])
        for detail in details[:5]:
            print("Unknown dependency: " + json.dumps({k: detail.get(k) for k in
                  ("package", "version", "manifest", "advisory", "reason")}))
        omitted = max(0, len(details) - 5) + dependency.get("details_truncated", 0)
        if omitted:
            print(f"{omitted} additional unknown assessments not shown.")
        print("Unknown is not confirmed affected or unaffected; --json includes per-source assessments.")
    for detail in dependency.get("manifest_gap_details", [])[:5]:
        print("Manifest coverage gap: " + json.dumps(detail))
    gap_omitted = (max(0, len(dependency.get("manifest_gap_details", [])) - 5)
                   + dependency.get("manifest_gap_details_truncated", 0))
    if gap_omitted:
        print(f"{gap_omitted} additional manifest gaps not shown; use --json for coverage details.")
    excluded = dependency.get("excluded_manifests", {})
    excluded_omitted = max(0, len(excluded) - 5) + dependency.get("excluded_manifests_truncated", 0)
    if excluded or excluded_omitted:
        print("Dependency manifest exclusions: " + json.dumps({
            "examples": dict(list(excluded.items())[:5]), "additional": excluded_omitted,
        }))
    print("Folder exclusions: " + json.dumps(report["snapshot"]["excluded"]))
    gaps = {name: row["skip_reasons"] for name, row in report.get("rule_coverage", {}).items()
            if any(row.get("skip_reasons", {}).values())}
    if gaps or report["checks_not_run"] or report["can_continue"]:
        print("Incomplete checks: " + json.dumps({"unavailable": report["checks_not_run"],
                                                 "rule_skips": gaps, "can_continue": report["can_continue"]}))
    # Presentation only: keep the complete report, identities, history and gates intact.
    prioritized = sorted(report["findings"], key=lambda finding: (
        -SEVERITY_RANKS.get(finding.get("severity"), -1),
        finding.get("context") in NON_PRODUCTION_CONTEXTS,
    ))
    for finding in prioritized[:20]:
        # JSON escaping prevents project-controlled paths/titles emitting terminal controls.
        print(json.dumps({k: finding.get(k) for k in ('severity', 'rule_id', 'file', 'line', 'title', 'context')}))
    if len(report['findings']) > 20:
        print("Showing 20 findings by severity (production context first within each severity); "
              "use --json for the complete report.")
    print("Coverage limitations: " + json.dumps(report['limitations']))
    print("No findings is not proof of safety. Runtime tests and reachability were not checked.", flush=True)


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=default_state_dir())
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("scan", "watch", "history"):
        command = commands.add_parser(name)
        command.add_argument("project", type=Path)
        if name != "history":
            command.add_argument("--json", action="store_true", help="complete JSON report (JSON Lines for watch)")
        if name == "scan":
            command.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"], default="none")
        if name == "watch":
            command.add_argument("--interval", type=float, default=10)
    update = commands.add_parser("update")
    update.add_argument("--revision", required=True, help="full Shipit commit SHA; this command uses the network")
    args = parser.parse_args(argv)
    if args.command == "watch" and (not math.isfinite(args.interval) or args.interval < 1):
        parser.error("interval must be finite and at least one second")
    if os.name != "posix":
        parser.error("this first release requires Linux or macOS (Windows users: WSL)")
    try:
        state_dir = args.state_dir.expanduser().absolute()
        root = args.project.expanduser().resolve(strict=True) if args.command != "update" else None
        if root is not None and (root == state_dir.resolve() or root.is_relative_to(state_dir.resolve())):
            raise ValueError("project must not be inside the state directory")
        with closing(connect(state_dir)) as db:
            if args.command == "update":
                print(json.dumps(update_catalog(db, args.revision)))
                return 0
            state_dir = state_dir.resolve()
            if args.command == "history":
                rows = db.execute("SELECT summary FROM scans WHERE root = ? ORDER BY id DESC LIMIT 100", (str(root),))
                print(json.dumps([json.loads(row[0]) for row in rows]))
                return 0
            key = None
            while True:
                try:
                    key, report = poll_project(db, root, state_dir, key)
                except (OSError, ValueError, sqlite3.Error, ArchiveValidationError, RecursionError) as exc:
                    if args.command != "watch":
                        raise
                    print(json.dumps({"error": type(exc).__name__, "detail": str(exc)}), file=sys.stderr, flush=True)
                    time.sleep(args.interval)
                    continue
                if report is not None:
                    display(report, args.json)
                if args.command == "scan":
                    return exit_status(report, args.fail_on)
                time.sleep(args.interval)
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, sqlite3.Error, ArchiveValidationError, RecursionError) as exc:
        print(json.dumps({"error": type(exc).__name__, "detail": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
