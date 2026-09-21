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
from app.report.plain_language import plain_fields
from app.scan.browser import ScanSession
from app.scan.secrets import NON_PRODUCTION_CONTEXTS
from app.scan.security_agent import agent_record
from app.scan.version import AUDIT_ENGINE_VERSION
from app.scan.remediation_catalog import remediation_hint, remediation_record

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
                # Stable metadata keeps the archive/evidence identity tied to
                # included paths and bytes rather than the scan's wall clock.
                entry = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
                entry.create_system = 3
                entry.external_attr = 0o600 << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(entry, body)
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
    if finding.get("rule_id") == "dependency-cve-match" and evidence.get("occurrences"):
        # Adding/removing a remediation location is a report change even when
        # the package/advisory assessment and its representative stay the same.
        fields.append(sorted(json.dumps(row, sort_keys=True) for row in evidence["occurrences"]))
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
        if agent := agent_record(report.get("security_agent")):
            summary["pattern_review"] = {
                "status": agent["status"], "catalog": agent["catalog"],
                "observations": len(agent["observations"]), "stop_reason": agent["stop_reason"],
            }
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
    agent = agent_record(report.get("security_agent"))
    if agent and agent["status"] in {"partial", "unavailable"}:
        return 2
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


def _short(value: object, limit: int = 280) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[:limit] + "... [see --json]"


def _range_preview(row: dict) -> dict:
    """Show source boundaries without inferring a universally safe upgrade."""
    result = {key: _short(row[key], 128) for key in
              ("type", "version", "versionType", "status", "lessThan", "lessThanOrEqual") if key in row}
    events = row.get("events", [])
    if events:
        result["events"] = [{key: _short(value, 128) for key, value in event.items()}
                            for event in events[:6]]
        if len(events) > 6:
            result["additional_events"] = len(events) - 6
    changes = row.get("changes", [])
    if changes:
        result["changes"] = [{key: _short(change.get(key), 128) for key in ("at", "status")}
                             for change in changes[:6]]
        if len(changes) > 6:
            result["additional_changes"] = len(changes) - 6
    return result


def _dependency_task(findings: list[dict]) -> dict:
    evidence = findings[0]["claim_evidence"]
    cards = [remediation_record(f.get("claim_evidence")) for f in findings]
    # A grouped task must not promote one member's plan over missing or different evidence.
    remediation = cards[0] if cards and cards[0] is not None and all(c == cards[0] for c in cards) else None
    occurrences = {json.dumps(row, sort_keys=True): row for finding in findings
                   for row in finding["claim_evidence"].get("occurrences", []) if isinstance(row, dict)}
    locations = [occurrences[key] for key in sorted(occurrences)]
    scope_rows = locations or [f["claim_evidence"] for f in findings]
    scopes = {row.get("dependency_scope", "unknown") for row in scope_rows}
    scope = next(iter(scopes)) if len(scopes) == 1 else "unknown"
    if scope not in {"development", "runtime"}:
        scope = "unknown"
    direct = {row.get("direct") for row in scope_rows}
    groups = sorted({group for row in scope_rows for group in row.get("dependency_groups", [])})
    advisory_ids = sorted({item for f in findings for item in
                           [f["claim_evidence"].get("advisory_id"),
                            *f["claim_evidence"].get("advisory_ids", [])] if item})
    advisories = []
    for finding in findings[:5]:
        detail = finding["claim_evidence"]
        ranges = detail.get("matched_ranges", [])
        versions = detail.get("matched_versions", [])
        advisories.append({
            "id": _short(detail.get("advisory_id"), 128), "url": _short(detail.get("url"), 400),
            "matched_ranges": [_range_preview(row) for row in ranges[:2]],
            "additional_ranges": max(0, len(ranges) - 2),
            "matched_versions": [_short(version, 128) for version in versions[:3]],
            "additional_versions": max(0, len(versions) - 3),
            "default_status_used": bool(detail.get("default_status_used")),
        })
    return {
        "severity": max((f.get("severity", "unknown") for f in findings),
                        key=lambda severity: SEVERITY_RANKS.get(severity, -1)),
        "rule_id": "dependency-cve-match", "file": _short(evidence["manifest"]),
        "ecosystem": _short(evidence["ecosystem"], 32), "package": _short(evidence["package"], 160),
        "version": _short(evidence["installed_version"], 128), "dependency_scope": scope,
        "direct": next(iter(direct)) if len(direct) == 1 else None,
        "dependency_groups": [_short(group, 80) for group in groups[:5]],
        "additional_groups": max(0, len(groups) - 5),
        **({"occurrences": [
            {"manifest": _short(row.get("manifest")), "line": row.get("line", 0),
             "dependency_scope": row.get("dependency_scope", "unknown"), "direct": row.get("direct"),
             "dependency_groups": [_short(group, 80) for group in row.get("dependency_groups", [])[:5]],
             "additional_groups": max(0, len(row.get("dependency_groups", [])) - 5)}
            for row in locations[:6]],
            "additional_occurrences": max(0, len(locations) - 6),
            "occurrences_recorded": all(f["claim_evidence"].get("occurrences_recorded") is True
                                        for f in findings)} if locations else {}),
        "advisory_findings": len(findings), "advisory_ids": [_short(item, 128) for item in advisory_ids[:8]],
        "additional_advisory_ids": max(0, len(advisory_ids) - 8),
        "advisories": advisories, "additional_advisory_details": max(0, len(findings) - 5),
        "explanation": "The locked version matches these catalog advisories; reachability is not assessed.",
        **({"remediation": remediation} if remediation is not None else {}),
        "action": (remediation_hint(remediation) if remediation is not None else
                   "Review the linked advisories and their individual ranges; update the dependency and lockfile. "
                   "A fixed boundary for one advisory is not a safe version for all advisories. "
                   + ("Development scope can still affect builds and CI." if scope == "development"
                      else "Verify where the affected functionality runs.")),
    }


def _terminal_tasks(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    """Presentation only; no finding mutation, deduplication or gate suppression."""
    groups = {}
    entries = []
    for index, finding in enumerate(findings):
        evidence = finding.get("claim_evidence") or {}
        key = tuple(evidence.get(field) for field in ("ecosystem", "package", "installed_version", "manifest"))
        if finding.get("rule_id") == "dependency-cve-match" and all(isinstance(item, str) and item for item in key):
            if key not in groups:
                groups[key] = []
                entries.append((index, groups[key]))
            groups[key].append(finding)
        else:
            entries.append((index, [finding]))
    priority, contextual = [], []
    for index, members in entries:
        finding = members[0]
        evidence = finding.get("claim_evidence") or {}
        if finding.get("rule_id") == "dependency-cve-match" and all(
                evidence.get(field) for field in ("ecosystem", "package", "installed_version", "manifest")):
            row = _dependency_task(members)
        else:
            _, explanation, action = plain_fields(finding)
            row = {key: _short(finding.get(key)) for key in ("severity", "rule_id", "file", "title")}
            row.update(line=finding.get("line"), context=finding.get("context") or "unknown",
                       explanation=_short(explanation), action=_short(action))
        rank = SEVERITY_RANKS.get(row["severity"], -1)
        context = finding.get("context")
        secondary = rank < SEVERITY_RANKS["high"] and (
            context in NON_PRODUCTION_CONTEXTS or finding.get("rule_id") == "no-dockerfile")
        if secondary:
            row["context"] = context or "optional_deployment_hygiene"
        (contextual if secondary else priority).append((rank, index, row))
    return tuple([row for _, _, row in sorted(section, key=lambda item: (-item[0], item[1]))]
                 for section in (priority, contextual))


def display(report: dict, as_json: bool, show_contextual: bool = False) -> None:
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
              "not_in_catalog counts unlisted unique package/version entries. "
              "Repeated manifest locations do not multiply assessments.")
    if dependency.get("unknown_reason_counts"):
        print("Unknown dependency reasons: " + json.dumps(dependency["unknown_reason_counts"]))
        details = dependency.get("details", [])
        for detail in details[:5]:
            print("Unknown dependency: " + json.dumps({k: detail.get(k) for k in
                  ("package", "version", "manifest", "advisory", "reason", "occurrences",
                   "occurrences_recorded")}))
        omitted = max(0, len(details) - 5) + dependency.get("details_truncated", 0)
        if omitted:
            print(f"{omitted} additional unknown assessments not shown.")
        print("Unknown is not confirmed affected or unaffected; --json includes per-source assessments.")
        if dependency["unknown_reason_counts"].get("incomplete_advisory_sources"):
            print("Incomplete advisory sources: at least one source could not be evaluated; "
                  "this is not an affected/unaffected disagreement.")
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
    if agent := agent_record(report.get("security_agent")):
        print("Pattern review: " + json.dumps({
            "status": agent["status"], "catalog": agent["catalog"], "budget": agent["budget"],
            "stop_reason": agent["stop_reason"],
        }))
        for observation in agent["observations"][:10]:
            print("Review action: " + json.dumps({key: observation[key] for key in (
                "pattern_id", "weaknesses", "file", "line", "evidence", "missing_evidence", "next_action",
            )}))
        if len(agent["observations"]) > 10:
            print("Additional pattern observations are available in --json.")
        print("Pattern review classifies static observations; recipe applicability still needs evidence.")
    gaps = {name: row["skip_reasons"] for name, row in report.get("rule_coverage", {}).items()
            if any(row.get("skip_reasons", {}).values())}
    if gaps or report["checks_not_run"] or report["can_continue"]:
        print("Incomplete checks: " + json.dumps({"unavailable": report["checks_not_run"],
                                                 "rule_skips": gaps, "can_continue": report["can_continue"]}))
    priority, contextual = _terminal_tasks(report["findings"])
    print(f"Priority review: {len(priority)} tasks (dependency advisories grouped by package/version/manifest).")
    print("Context unknown does not establish production use. High/critical test and example findings remain here.")
    for row in priority[:20]:
        # Escape paths, explanations, URLs, ranges and every other project-controlled value.
        print(json.dumps(row))
    if len(priority) > 20:
        print(f"{len(priority) - 20} additional priority tasks not shown; use --json for the complete report.")
    if contextual:
        print("Contextual review: " + json.dumps({
            "findings": len(contextual), "by_context": dict(Counter(row["context"] for row in contextual)),
            "by_severity": dict(Counter(row["severity"] for row in contextual)),
        }))
        print("Test/example/comment and optional hygiene findings remain in counts, history and --fail-on. "
              "Use --show-contextual to expand; --json includes every finding.")
        if show_contextual:
            for row in contextual[:20]:
                print(json.dumps(row))
            if len(contextual) > 20:
                print(f"{len(contextual) - 20} additional contextual findings not shown; use --json.")
    print("Coverage limitations: " + json.dumps(report['limitations']))
    print("No findings is not proof of safety. Runtime tests and reachability were not checked.", flush=True)


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=default_state_dir())
    commands = parser.add_subparsers(dest="command", required=True)
    patterns = commands.add_parser("patterns", help="show the bundled weakness and verification cards")
    patterns.add_argument("--json", action="store_true", help="complete machine-readable pattern catalog")
    recipes = commands.add_parser("recipes", help="show the bundled advisory-backed upgrade recipes")
    recipes.add_argument("--json", action="store_true", help="complete machine-readable recipe catalog")
    for name in ("scan", "watch", "history"):
        command = commands.add_parser(name)
        command.add_argument("project", type=Path)
        if name != "history":
            command.add_argument("--json", action="store_true", help="complete JSON report (JSON Lines for watch)")
            command.add_argument("--show-contextual", action="store_true",
                                 help="expand test/example/comment and optional hygiene findings in text output")
        if name == "scan":
            command.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"], default="none")
        if name == "watch":
            command.add_argument("--interval", type=float, default=10)
    update = commands.add_parser("update")
    update.add_argument("--revision", required=True, help="full Shipit commit SHA; this command uses the network")
    args = parser.parse_args(argv)
    if args.command == "recipes":
        from app.scan.remediation_catalog import recipe_catalog
        catalog = recipe_catalog()
        if args.json:
            print(json.dumps(catalog, ensure_ascii=False))
        else:
            print(f"Drydock remediation catalog {catalog['catalog_version']}; review plans, no automatic updates")
            for recipe in catalog["recipes"]:
                print(json.dumps(recipe))
        return 0
    if args.command == "patterns":
        from app.scan.pattern_catalog import catalog_manifest
        catalog = catalog_manifest()
        if args.json:
            print(json.dumps(catalog, ensure_ascii=False))
        else:
            print(f"Drydock pattern catalog {catalog['catalog_version']} ({catalog['catalog_sha256'][:12]})")
            for card in catalog["cards"]:
                print(json.dumps({key: card[key] for key in (
                    "id", "revision", "title", "weaknesses", "detection", "recipe",
                )}))
        return 0
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
                    display(report, args.json, args.show_contextual)
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
