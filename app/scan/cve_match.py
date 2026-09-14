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
MAX_EVENTS = 512
MAX_DETAILS = 200
SOURCE_REPOSITORY = "https://github.com/CVEProject/cvelistV5"
GHSA_REPOSITORY = "https://github.com/github/advisory-database"
CVE_PAGE = "https://www.cve.org/CVERecord?id="
GHSA_PAGE = "https://github.com/advisories/"
_STATUSES = {"affected", "unaffected", "unknown"}
_SEMVER = re.compile(
    r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\Z")
_CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z")
_GHSA_ID = re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\Z")


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


def _osv_range_status(version: str, ecosystem: str, row: object) -> tuple[str, str | None]:
    """Evaluate one OSV timeline without guessing unsupported ordering."""
    if not isinstance(row, dict):
        return "unknown", "invalid_osv_range"
    kind, events = row.get("type"), row.get("events")
    supported = (ecosystem == "npm" and kind in {"SEMVER", "ECOSYSTEM"}
                 or ecosystem == "PyPI" and kind == "ECOSYSTEM")
    if not supported:
        return "unknown", "unsupported_osv_range_type"
    if not isinstance(events, list) or not events or len(events) > MAX_EVENTS:
        return "unknown", "invalid_osv_events"
    target = _version(version, ecosystem)
    if target is None:
        return "unknown", "unsupported_installed_version"

    parsed = []
    limits = []
    event_kinds = set()
    points: dict[tuple, set[str]] = {}
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            return "unknown", "invalid_osv_event"
        event_kind, value = next(iter(event.items()))
        if event_kind not in {"introduced", "fixed", "last_affected", "limit"}:
            return "unknown", "invalid_osv_event"
        if (not isinstance(value, str) or not value or len(value) > 128
                or any(ord(char) < 32 or ord(char) == 127 for char in value)):
            return "unknown", "invalid_osv_event"
        event_kinds.add(event_kind)
        if event_kind == "limit":
            limits.append(value)
            continue
        point = (-1,) if event_kind == "introduced" and value == "0" else _version(value, ecosystem)
        if point is None:
            return "unknown", "unsupported_osv_version"
        points.setdefault(point, set()).add(event_kind)
        if len(points[point]) > 1:
            return "unknown", "conflicting_osv_events"
        parsed.append((point, event_kind))
    if "introduced" not in event_kinds:
        return "unknown", "osv_range_without_introduced"
    if {"fixed", "last_affected"} <= event_kinds:
        return "unknown", "conflicting_osv_events"

    if limits:
        before_a_limit = False
        for limit in limits:
            if "*" in limit:
                before_a_limit = True
                continue
            relation = compare_versions(version, limit, ecosystem)
            if relation is None:
                return "unknown", "unsupported_osv_version"
            before_a_limit = before_a_limit or relation < 0
        if not before_a_limit:
            return "unaffected", None

    vulnerable = False
    for point, event_kind in sorted(parsed):
        if point > target:
            continue
        if event_kind == "introduced":
            vulnerable = True
        elif event_kind == "fixed":
            vulnerable = False
        elif point < target:  # last_affected is inclusive at the boundary.
            vulnerable = False
    return ("affected" if vulnerable else "unaffected"), None


def _evaluate_osv(version: str, ecosystem: str, advisory: dict) -> dict:
    result = {
        "status": "unknown", "reason": None, "unresolved_ranges": 0,
        "matched_ranges": [], "matched_versions": [],
    }
    if _version(version, ecosystem) is None:
        return {**result, "reason": "unsupported_installed_version", "unresolved_ranges": 1}
    ranges, versions = advisory.get("osv_ranges", []), advisory.get("osv_versions", [])
    if (not isinstance(ranges, list) or len(ranges) > MAX_RANGES
            or not isinstance(versions, list) or len(versions) > MAX_RANGES * 16
            or not ranges and not versions):
        return {**result, "reason": "invalid_or_oversized_osv_ranges", "unresolved_ranges": 1}

    exact = False
    for item in versions:
        if (not isinstance(item, str) or not item or len(item) > 128
                or any(ord(char) < 32 or ord(char) == 127 for char in item)):
            result["unresolved_ranges"] += 1
            result["reason"] = result["reason"] or "invalid_osv_version"
        elif item == version:
            exact = True
            result["matched_versions"].append(item)

    for row in ranges:
        status, reason = _osv_range_status(version, ecosystem, row)
        if reason:
            result["unresolved_ranges"] += 1
            result["reason"] = result["reason"] or reason
        elif status == "affected":
            result["matched_ranges"].append(row)

    if exact or result["matched_ranges"]:
        result["status"] = "affected"
        result["reason"] = None
    elif result["unresolved_ranges"]:
        result["status"] = "unknown"
    else:
        result["status"] = "unaffected"
    return result


def evaluate_advisory(version: str, ecosystem: str, advisory: object) -> dict:
    """Evaluate one CVE affected object, preserving unsupported/overlap gaps."""
    result = {"status": "unknown", "reason": None, "unresolved_ranges": 0, "matched_ranges": []}
    if not isinstance(advisory, dict):
        return {**result, "reason": "invalid_advisory", "unresolved_ranges": 1}
    if "osv_ranges" in advisory or "osv_versions" in advisory:
        return _evaluate_osv(version, ecosystem, advisory)
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


def _valid_source(value: object, repository: str) -> dict | None:
    if not isinstance(value, dict) or value.get("repository") != repository:
        return None
    commit, date = value.get("commit"), value.get("generated_at")
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
    return {"repository": repository, "commit": commit, "generated_at": date}


def _sources(catalog: object) -> dict[str, dict] | None:
    if not isinstance(catalog, dict) or type(catalog.get("schema_version")) is not int:
        return None
    schema = catalog["schema_version"]
    primary = _valid_source(catalog.get("source"), SOURCE_REPOSITORY)
    if primary is None:
        return None
    if schema == 1:
        return {"cvelist": primary}
    if schema != 2:
        return None
    sources = catalog.get("sources")
    if not isinstance(sources, dict) or set(sources) != {"cvelist", "github-reviewed"}:
        return None
    cvelist = _valid_source(sources.get("cvelist"), SOURCE_REPOSITORY)
    github = _valid_source(sources.get("github-reviewed"), GHSA_REPOSITORY)
    if cvelist != primary or github is None:
        return None
    return {"cvelist": cvelist, "github-reviewed": github}


def _source(catalog: object) -> dict | None:
    sources = _sources(catalog)
    return sources.get("cvelist") if sources else None


def _entry_identity(entry: object, sources: dict[str, dict]) -> tuple[str, list[str], str] | None:
    if not isinstance(entry, dict):
        return None
    advisory_id = entry.get("id")
    if not isinstance(advisory_id, str) or not (
            _CVE_ID.fullmatch(advisory_id) or _GHSA_ID.fullmatch(advisory_id)):
        return None
    aliases = entry.get("aliases", [])
    if (not isinstance(aliases, list) or len(aliases) > 256
            or any(not isinstance(alias, str) or not (
                _CVE_ID.fullmatch(alias) or _GHSA_ID.fullmatch(alias)
            ) for alias in aliases)):
        return None
    default_source = "cvelist" if _CVE_ID.fullmatch(advisory_id) else None
    source_key = entry.get("source", default_source)
    if source_key not in sources:
        return None
    if _GHSA_ID.fullmatch(advisory_id) and source_key != "github-reviewed":
        return None
    return advisory_id, sorted(set(aliases)), source_key


def _advisory_url(advisory_id: str) -> str:
    return (CVE_PAGE if _CVE_ID.fullmatch(advisory_id) else GHSA_PAGE) + advisory_id

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
        unsupported = {"yarn.lock", "Pipfile.lock",
                       "Cargo.lock", "Gemfile.lock", "composer.lock", "packages.lock.json"}
        for path in paths:
            directory, _, basename = path.rpartition("/")
            prefix = directory + "/" if directory else ""
            if basename in unsupported:
                gaps[path] = "unsupported"
            elif basename == "package.json" and not any(
                    prefix + name in paths for name in ("package-lock.json", "pnpm-lock.yaml")):
                gaps[path] = "unresolved"
            elif basename in {"pyproject.toml", "Pipfile", "setup.py", "setup.cfg"} and not any(
                    prefix + name in paths for name in ("poetry.lock", "requirements.txt", "uv.lock")):
                gaps[path] = "unresolved"
    inventory = collect_dependency_inventory(data)
    inventory.incomplete_manifests.update(gaps)
    return inventory


def match_archive(data: bytes, catalog: dict) -> dict:
    """Match ZIP lockfile pins against an identified, offline advisory snapshot."""
    sources = _sources(catalog)
    coverage = {
        "status": "partial", "status_counts": dict.fromkeys((*sorted(_STATUSES), "not_in_catalog"), 0),
        "dependencies_found": 0, "dependencies_checked": 0, "packages_in_catalog": 0,
        "advisory_evaluations": 0, "unresolved_ranges": 0, "manifests": [],
        "incomplete_manifests": {}, "inventory_truncated": 0, "findings_truncated": 0,
        "evaluations_truncated": 0,
        "source": sources.get("cvelist") if sources else None,
        "sources": sources or {}, "details": [], "catalog_stats": {},
        "limitations": [
            "Only exact registry package versions in supported lockfiles are compared with this snapshot.",
            "Locked platform, optional and development variants are included; runtime selection is not evaluated.",
            "A package/version match does not establish reachable or exploitable application code.",
            "Absence from the snapshot, unsupported ranges, and no matches do not establish a clean or safe project.",
            "PyPI comparisons support numeric releases only; npm comparisons support SemVer.",
        ],
    }
    findings = []
    result = {"findings": findings, "coverage": coverage}
    packages = catalog.get("packages") if isinstance(catalog, dict) else None
    if sources is None or not isinstance(packages, dict):
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
        grouped: dict[str, list[tuple[dict, dict, str]]] = {}
        for entry_index, entry in enumerate(entries):
            if coverage["advisory_evaluations"] >= MAX_EVALUATIONS:
                coverage["evaluations_truncated"] += len(entries) - entry_index
                break
            coverage["advisory_evaluations"] += 1
            identity = _entry_identity(entry, sources)
            if identity is None:
                coverage["status_counts"]["unknown"] += 1
                coverage["unresolved_ranges"] += 1
                continue
            entry_id, aliases, source_key = identity
            group_id = next((item for item in (entry_id, *aliases) if _CVE_ID.fullmatch(item)), entry_id)
            assessment = evaluate_advisory(dep.version, dep.ecosystem, entry)
            coverage["unresolved_ranges"] += assessment["unresolved_ranges"]
            grouped.setdefault(group_id, []).append((entry, assessment, source_key))
        # If the cap cut across repeated affected objects, their interpretation
        # is incomplete; never emit a positive based on that partial group.
        truncated = coverage["advisory_evaluations"] >= MAX_EVALUATIONS and coverage["evaluations_truncated"] > 0
        for group_id, group in grouped.items():
            statuses = {assessment["status"] for _, assessment, _ in group}
            status = next(iter(statuses)) if len(statuses) == 1 and not truncated else "unknown"
            coverage["status_counts"][status] += 1
            if status == "unknown":
                if len(statuses) > 1:
                    coverage["unresolved_ranges"] += 1
                if truncated:
                    reason = "evaluation_limit"
                elif len(statuses) > 1:
                    source_keys = {source_key for _, _, source_key in group}
                    reason = (
                        "conflicting_advisory_sources" if len(source_keys) > 1
                        else "conflicting_affected_objects"
                    )
                else:
                    reason = next(
                        (assessment["reason"] for _, assessment, _ in group
                         if assessment["reason"]),
                        "unknown_status",
                    )
                if len(coverage["details"]) < MAX_DETAILS:
                    coverage["details"].append({"package": key, "version": dep.version, "manifest": dep.manifest,
                                                "advisory": group_id, "reason": reason})
                continue
            if status != "affected":
                continue
            if len(findings) >= MAX_FINDINGS:
                coverage["findings_truncated"] += 1
                continue
            entry_ids = sorted({entry["id"] for entry, _, _ in group})
            all_ids = sorted({item for entry, _, _ in group
                              for item in (entry["id"], *entry.get("aliases", []))})
            cve_id = next((item for item in entry_ids if _CVE_ID.fullmatch(item)), None)
            ghsa_id = next((item for item in entry_ids if _GHSA_ID.fullmatch(item)), None)
            advisory_id = cve_id or ghsa_id or group_id
            source_keys = sorted({source_key for _, _, source_key in group})
            evidence = {
                "version": 1, "package": name, "ecosystem": dep.ecosystem,
                "installed_version": dep.version, "manifest": dep.manifest,
                "advisory_id": advisory_id, "advisory_ids": all_ids,
                "url": _advisory_url(advisory_id), "snapshot": coverage["source"],
                "snapshot_sources": [
                    {"name": source_key, **sources[source_key]} for source_key in source_keys
                ],
                "matched_ranges": [
                    row for _, assessment, _ in group for row in assessment["matched_ranges"]
                ],
                "matched_versions": [
                    item for _, assessment, _ in group
                    for item in assessment.get("matched_versions", [])
                ],
                "default_status_used": not any(
                    assessment["matched_ranges"] for _, assessment, _ in group
                ) and not any(
                    assessment.get("matched_versions", []) for _, assessment, _ in group
                ),
                "reachability": "not_assessed",
            }
            if cve_id:
                evidence["cve_id"] = cve_id
            if ghsa_id:
                evidence["ghsa_id"] = ghsa_id
            findings.append({
                "rule_id": RULE_ID,
                "title": f"{name} {dep.version} matches {advisory_id}",
                "severity": "high", "confidence": 0.9, "category": "Security",
                "file": dep.manifest, "line": dep.line,
                "explanation": (
                    f"The resolved {dep.ecosystem} package version is listed as affected "
                    f"by {advisory_id} in the bundled advisory snapshot. Application "
                    "reachability and exploitability have not been verified."
                ),
                "fix_hint": (
                    "Review the advisory's affected range and upgrade to a supported "
                    "fixed version; verify whether the affected functionality is used."
                ),
                "source": "dependency", "verification_status": "unverified",
                "verification_method": "package_version_match",
                "claim_evidence": evidence,
            })
    gaps = (coverage["incomplete_manifests"] or coverage["inventory_truncated"] or
            coverage["findings_truncated"] or coverage["evaluations_truncated"] or
            coverage["status_counts"]["unknown"] or coverage["status_counts"]["not_in_catalog"])
    coverage["status"] = "partial" if gaps else "checked" if inventory.dependencies else "not_applicable"
    return result
