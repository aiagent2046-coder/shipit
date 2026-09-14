"""Offline CVE snapshot matching of resolved registry dependencies.

This intentionally supports a small, auditable ordering subset: npm SemVer
and numeric PyPI releases. Unsupported syntax and ambiguous records stay
unknown; neither absent packages nor unmatched records establish global safety.
Only standard-library imports are used so this module runs inside Pyodide.
"""
from __future__ import annotations

import io
from itertools import islice
import re
import zipfile
from datetime import datetime

from app.sca.lockfiles import collect_dependency_inventory, normalize_pypi, _vendored
from app.scan.secrets import is_non_production_path

RULE_ID = "dependency-cve-match"
MAX_ARCHIVE_BYTES = 50_000_000
MAX_ARCHIVE_MEMBERS = 20_000
MAX_EXPANDED_BYTES = 100_000_000
MAX_EVALUATIONS = 20_000
MAX_FINDINGS = 500
MAX_RANGES = 256
MAX_DETAILS = 200
SOURCE_REPOSITORY = "https://github.com/CVEProject/cvelistV5"
CVE_PAGE = "https://www.cve.org/CVERecord?id="
_STATUSES = {"affected", "unaffected", "unknown"}
_SEMVER = re.compile(
    r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\Z")
_CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z")


def _version(value: object, ecosystem: str) -> tuple | None:
    if not isinstance(value, str) or not value or len(value) > 128:
        return None
    if ecosystem == "PyPI":
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", value):
            return None
        release = tuple(int(part) for part in value.split("."))
        while len(release) > 1 and release[-1] == 0:
            release = release[:-1]
        return release
    if ecosystem != "npm":
        return None
    match = _SEMVER.fullmatch(value)
    if not match:
        return None
    prerelease = match[4]
    identifiers = []
    if prerelease is not None:
        for part in prerelease.split("."):
            if part.isdigit():
                if len(part) > 1 and part.startswith("0"):
                    return None
                identifiers.append((0, int(part)))
            else:
                identifiers.append((1, part))
    return (int(match[1]), int(match[2]), int(match[3]),
            1 if prerelease is None else 0, tuple(identifiers))


def compare_versions(left: str, right: str, ecosystem: str) -> int | None:
    """Return -1/0/1, or None when ordering is outside the supported subset."""
    a, b = _version(left, ecosystem), _version(right, ecosystem)
    if a is None or b is None:
        return None
    return (a > b) - (a < b)


def _range_status(version: str, ecosystem: str, row: object) -> tuple[str | None, str | None]:
    if not isinstance(row, dict) or not isinstance(row.get("status"), str) or row["status"] not in _STATUSES:
        return "unknown", "invalid_range"
    lower = row.get("version")
    exclusive, inclusive = row.get("lessThan"), row.get("lessThanOrEqual")
    ranged = exclusive is not None or inclusive is not None
    kind = row.get("versionType")
    supported = {"semver"} if ecosystem == "npm" else {"pep440", "python"}
    if (not isinstance(kind, str) or kind not in supported) and not (kind is None and not ranged):
        return "unknown", "unsupported_version_type"
    relation = compare_versions(version, lower, ecosystem)
    if relation is None:
        return "unknown", "unsupported_version"
    changes = row.get("changes", [])
    if not isinstance(changes, list) or len(changes) > MAX_RANGES:
        return "unknown", "invalid_changes"
    if not ranged:
        if changes:
            return "unknown", "changes_without_range"
        return (row["status"] if relation == 0 else None), None
    if exclusive is not None and inclusive is not None:
        return "unknown", "conflicting_bounds"
    upper = exclusive if exclusive is not None else inclusive
    upper_relation = None if upper == "*" else compare_versions(version, upper, ecosystem)
    bounds = None if upper == "*" else compare_versions(lower, upper, ecosystem)
    if upper != "*" and (upper_relation is None or bounds is None):
        return "unknown", "unsupported_version"
    if bounds is not None and (bounds > 0 or (bounds == 0 and exclusive is not None)):
        return "unknown", "invalid_bounds"
    parsed_changes: dict[tuple, str] = {}
    for change in changes:
        if (not isinstance(change, dict) or not isinstance(change.get("status"), str)
                or change["status"] not in _STATUSES):
            return "unknown", "invalid_changes"
        at = change.get("at")
        key = _version(at, ecosystem)
        low = compare_versions(at, lower, ecosystem)
        high = None if upper == "*" else compare_versions(at, upper, ecosystem)
        if key is None or low is None or low < 0 or (upper != "*" and
                (high is None or high > 0 or (high == 0 and exclusive is not None))):
            return "unknown", "invalid_changes"
        if key in parsed_changes and parsed_changes[key] != change["status"]:
            return "unknown", "conflicting_changes"
        parsed_changes[key] = change["status"]
    if relation < 0 or (upper_relation is not None and
                       (upper_relation > 0 or (exclusive is not None and upper_relation == 0))):
        return None, None
    status = row["status"]
    target = _version(version, ecosystem)
    for at, changed_status in sorted(parsed_changes.items()):
        if at <= target:
            status = changed_status
    return status, None


def evaluate_advisory(version: str, ecosystem: str, advisory: object) -> dict:
    """Evaluate one CVE affected object, preserving unsupported/overlap gaps."""
    result = {"status": "unknown", "reason": None, "unresolved_ranges": 0, "matched_ranges": []}
    if not isinstance(advisory, dict):
        return {**result, "reason": "invalid_advisory", "unresolved_ranges": 1}
    if advisory.get("unsupported_applicability"):
        return {**result, "reason": "unsupported_applicability", "unresolved_ranges": 1}
    if _version(version, ecosystem) is None:
        return {**result, "reason": "unsupported_installed_version", "unresolved_ranges": 1}
    rows, default = advisory.get("versions"), advisory.get("default_status", "unknown")
    if (not isinstance(rows, list) or len(rows) > MAX_RANGES
            or not isinstance(default, str) or default not in _STATUSES):
        return {**result, "reason": "invalid_or_oversized_ranges", "unresolved_ranges": 1}
    statuses = set()
    for row in rows:
        status, reason = _range_status(version, ecosystem, row)
        if reason:
            result["unresolved_ranges"] += 1
            result["reason"] = result["reason"] or reason
        if status is not None:
            statuses.add(status)
            if reason is None:
                result["matched_ranges"].append(row)
    if len(statuses) > 1:
        result["reason"] = result["reason"] or "conflicting_ranges"
        result["unresolved_ranges"] += 1
    elif len(statuses) == 1:
        result["status"] = next(iter(statuses))
    else:
        result["status"] = default
    if result["status"] == "unknown" and result["reason"] is None:
        result["reason"] = "unknown_status"
    return result


def _source(catalog: object) -> dict | None:
    if (not isinstance(catalog, dict) or type(catalog.get("schema_version")) is not int
            or catalog["schema_version"] != 1):
        return None
    source = catalog.get("source")
    if not isinstance(source, dict) or source.get("repository") != SOURCE_REPOSITORY:
        return None
    commit, date = source.get("commit"), source.get("generated_at")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        return None
    if not isinstance(date, str) or len(date) > 64:
        return None
    try:
        parsed_date = datetime.fromisoformat(date.replace("Z", "+00:00"))
        if parsed_date.tzinfo is None:
            return None
    except ValueError:
        return None
    return {"repository": SOURCE_REPOSITORY, "commit": commit, "generated_at": date}


def _archive_inventory(data: bytes):
    if not isinstance(data, bytes) or len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError("archive_size_limit")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = archive.infolist()
        if len(members) > MAX_ARCHIVE_MEMBERS or sum(i.file_size for i in members) > MAX_EXPANDED_BYTES:
            raise ValueError("archive_expansion_limit")
        if len({info.filename for info in members}) != len(members):
            raise ValueError("duplicate_archive_members")
        # The shared parser uses a neighboring package.json for directness.
        if any(i.file_size > 2_000_000 and i.filename.rsplit("/", 1)[-1] == "package.json" for i in members):
            raise ValueError("manifest_size_limit")
        paths = {i.filename for i in members if not i.is_dir()
                 and not is_non_production_path(i.filename) and not _vendored(i.filename)}
        gaps = {}
        unsupported = {"yarn.lock", "pnpm-lock.yaml", "Pipfile.lock", "uv.lock",
                       "Cargo.lock", "Gemfile.lock", "composer.lock", "packages.lock.json"}
        for path in paths:
            directory, _, basename = path.rpartition("/")
            prefix = directory + "/" if directory else ""
            if basename in unsupported:
                gaps[path] = "unsupported"
            elif basename == "package.json" and prefix + "package-lock.json" not in paths:
                gaps[path] = "unresolved"
            elif basename in {"pyproject.toml", "Pipfile", "setup.py", "setup.cfg"} and not any(
                    prefix + name in paths for name in ("poetry.lock", "requirements.txt")):
                gaps[path] = "unresolved"
    inventory = collect_dependency_inventory(data)
    inventory.incomplete_manifests.update(gaps)
    return inventory


def match_archive(data: bytes, catalog: dict) -> dict:
    """Match ZIP lockfile pins against an identified, offline CVE snapshot."""
    coverage = {
        "status": "partial", "status_counts": dict.fromkeys((*sorted(_STATUSES), "not_in_catalog"), 0),
        "dependencies_found": 0, "dependencies_checked": 0, "packages_in_catalog": 0,
        "advisory_evaluations": 0, "unresolved_ranges": 0, "manifests": [],
        "incomplete_manifests": {}, "inventory_truncated": 0, "findings_truncated": 0,
        "evaluations_truncated": 0, "source": _source(catalog), "details": [],
        "catalog_stats": {},
        "limitations": [
            "Only exact registry package versions in supported lockfiles are compared with this snapshot.",
            "A package/version match does not establish reachable or exploitable application code.",
            "Absence from the snapshot, unsupported ranges, and no matches do not establish a clean or safe project.",
            "PyPI comparisons support numeric releases only; npm comparisons support SemVer.",
        ],
    }
    findings = []
    result = {"findings": findings, "coverage": coverage}
    packages = catalog.get("packages") if isinstance(catalog, dict) else None
    if coverage["source"] is None or not isinstance(packages, dict):
        coverage.update(status="unavailable", error="invalid_catalog")
        return result
    stats = catalog.get("stats", {})
    if isinstance(stats, dict):
        for key, value in islice(stats.items(), 100):
            if isinstance(key, str) and len(key) <= 128 and type(value) is int and value >= 0:
                coverage["catalog_stats"][key] = value
    try:
        inventory = _archive_inventory(data)
    except (ValueError, OSError, RuntimeError, zipfile.BadZipFile, OverflowError):
        coverage.update(status="unavailable", error="invalid_or_oversized_archive")
        return result
    coverage.update(dependencies_found=inventory.found, manifests=inventory.manifests,
                    incomplete_manifests=inventory.incomplete_manifests,
                    inventory_truncated=max(0, inventory.found - len(inventory.dependencies)))
    for dep in inventory.dependencies:
        name = normalize_pypi(dep.name) if dep.ecosystem == "PyPI" else dep.name
        key = dep.ecosystem + ":" + name
        entries = packages.get(key)
        coverage["dependencies_checked"] += 1
        if entries is None:
            coverage["status_counts"]["not_in_catalog"] += 1
            continue
        coverage["packages_in_catalog"] += 1
        if not isinstance(entries, list) or not entries:
            coverage["status_counts"]["unknown"] += 1
            coverage["unresolved_ranges"] += 1
            if len(coverage["details"]) < MAX_DETAILS:
                coverage["details"].append({"package": key, "version": dep.version,
                                            "reason": "invalid_catalog_entries"})
            continue
        grouped: dict[str, list[tuple[dict, dict]]] = {}
        for entry_index, entry in enumerate(entries):
            if coverage["advisory_evaluations"] >= MAX_EVALUATIONS:
                coverage["evaluations_truncated"] += len(entries) - entry_index
                break
            coverage["advisory_evaluations"] += 1
            cve_id = entry.get("id") if isinstance(entry, dict) else None
            if not isinstance(cve_id, str) or not _CVE_ID.fullmatch(cve_id):
                coverage["status_counts"]["unknown"] += 1
                coverage["unresolved_ranges"] += 1
                continue
            assessment = evaluate_advisory(dep.version, dep.ecosystem, entry)
            coverage["unresolved_ranges"] += assessment["unresolved_ranges"]
            grouped.setdefault(cve_id, []).append((entry, assessment))
        # If the cap cut across repeated affected objects, their interpretation
        # is incomplete; never emit a positive based on that partial group.
        truncated = coverage["advisory_evaluations"] >= MAX_EVALUATIONS and coverage["evaluations_truncated"] > 0
        for cve_id, group in grouped.items():
            statuses = {assessment["status"] for _, assessment in group}
            status = next(iter(statuses)) if len(statuses) == 1 and not truncated else "unknown"
            coverage["status_counts"][status] += 1
            if status == "unknown":
                if len(statuses) > 1:
                    coverage["unresolved_ranges"] += 1
                reason = ("evaluation_limit" if truncated else "conflicting_affected_objects" if len(statuses) > 1 else
                          next((a["reason"] for _, a in group if a["reason"]), "unknown_status"))
                if len(coverage["details"]) < MAX_DETAILS:
                    coverage["details"].append({"package": key, "version": dep.version, "manifest": dep.manifest,
                                                "cve": cve_id, "reason": reason})
                continue
            if status != "affected":
                continue
            if len(findings) >= MAX_FINDINGS:
                coverage["findings_truncated"] += 1
                continue
            entry, assessment = group[0]
            evidence = {"version": 1, "package": name, "ecosystem": dep.ecosystem,
                        "installed_version": dep.version, "manifest": dep.manifest,
                        "cve_id": cve_id, "url": CVE_PAGE + cve_id, "snapshot": coverage["source"],
                        "matched_ranges": [r for _, a in group for r in a["matched_ranges"]],
                        "default_status_used": not any(a["matched_ranges"] for _, a in group),
                        "reachability": "not_assessed"}
            findings.append({"rule_id": RULE_ID, "title": f"{name} {dep.version} matches {cve_id}",
                             "severity": "high", "confidence": 0.9, "category": "Security",
                             "file": dep.manifest, "line": dep.line,
                             "explanation": (f"The resolved {dep.ecosystem} package version is listed as affected "
                                             f"by {cve_id} in the bundled CVE snapshot. Application reachability "
                                             "and exploitability have not been verified."),
                             "fix_hint": ("Review the CVE affected range and upgrade to a supported fixed version; "
                                          "verify whether the affected functionality is used."),
                             "source": "dependency", "verification_status": "unverified",
                             "verification_method": "package_version_match", "claim_evidence": evidence})
    gaps = (coverage["incomplete_manifests"] or coverage["inventory_truncated"] or
            coverage["findings_truncated"] or coverage["evaluations_truncated"] or
            coverage["status_counts"]["unknown"] or coverage["status_counts"]["not_in_catalog"])
    coverage["status"] = "partial" if gaps else "checked" if inventory.dependencies else "not_applicable"
    return result
