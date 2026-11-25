"""Advisory evaluation core: version comparison, range status, source
validation and entry identity.

What both the archive matcher (cve_match) and the upgrade planner
(remediation_catalog) evaluate advisories with. Extracted verbatim during
the import-cycles fix phase: the planner needs evaluation to choose fixed
versions while the matcher needs the planner to attach fix hints, so the
shared evaluation core is the bottom layer that breaks the tangle.
"""
from __future__ import annotations

import re
from datetime import datetime


SOURCE_REPOSITORY = "https://github.com/CVEProject/cvelistV5"

GHSA_REPOSITORY = "https://github.com/github/advisory-database"

MAX_RANGES = 256

MAX_EVENTS = 512

_STATUSES = {"affected", "unaffected", "unknown"}

_SEMVER = re.compile(
    r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\Z")

_PYPI_VERSION = re.compile(r"([0-9]+(?:\.[0-9]+)*)(?:(a|b|rc)([0-9]+))?\Z")

_CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z")

_GHSA_ID = re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\Z")


def _version(value: object, ecosystem: str) -> tuple | None:
    if not isinstance(value, str) or not value or len(value) > 128:
        return None
    if ecosystem == "PyPI":
        match = _PYPI_VERSION.fullmatch(value)
        if not match:
            return None
        release = tuple(int(part) for part in match[1].split("."))
        while len(release) > 1 and release[-1] == 0:
            release = release[:-1]
        # PEP 440: a < b < rc < final within the same zero-padded release.
        # Epoch zero keeps OSV's (-1,) start sentinel before even 0a0.
        phase = {"a": 0, "b": 1, "rc": 2, None: 3}[match[2]]
        return (0, release, phase, int(match[3] or "0"))
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
    # CVE defines lower version="0" as the earliest possible version of a
    # range, not the literal SemVer 0.0.0 (which excludes its prereleases).
    # Exact versions, upper bounds and installed versions remain strict.
    earliest = ranged and lower == "0"
    relation = 1 if earliest else compare_versions(version, lower, ecosystem)
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
    bounds = None if upper == "*" else -1 if earliest else compare_versions(lower, upper, ecosystem)
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
        low = 1 if earliest and key is not None else compare_versions(at, lower, ecosystem)
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
        elif ecosystem == "PyPI":
            relation = compare_versions(version, item, ecosystem)
            if relation is None:
                result["unresolved_ranges"] += 1
                result["reason"] = result["reason"] or "unsupported_osv_version"
            elif relation == 0:
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
