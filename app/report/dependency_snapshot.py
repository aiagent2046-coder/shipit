"""Bounded presentation of offline advisory coverage, independent of live OSV."""
from __future__ import annotations

from datetime import datetime
import re


SCOPE_REASONS = {"dependency_snapshot_scope", "dependency_runtime_reachability_not_checked"}
SOURCE_REPOSITORIES = {
    "cvelist": "https://github.com/CVEProject/cvelistV5",
    "github-reviewed": "https://github.com/github/advisory-database",
}
SOURCE_LABELS = {"cvelist": "CVE Program", "github-reviewed": "GitHub-reviewed GHSA"}
SCOPE = ("Exact npm/PyPI lockfile versions are compared with a bundled advisory snapshot. "
         "A match does not establish reachable or exploitable application code. "
         "Unknown assessments and packages absent from the snapshot are not safe results.")


def _count(value: object) -> bool:
    return type(value) is int and 0 <= value <= 9_007_199_254_740_991


def _date(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 64 or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})", value):
        return None
    if value[-6] in {"+", "-"} and (int(value[-5:-3]) >= 24 or int(value[-2:]) >= 60):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def snapshot_metadata(value: object) -> dict | None:
    """Public fields only; cache fingerprints and unknown fields are not exported."""
    if (not isinstance(value, dict) or type(value.get("version")) is not int or value["version"] != 1
            or value.get("mode") != "bundled"):
        return None
    digest, checked = value.get("catalog_sha256"), value.get("checked_at")
    if digest is not None and (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
        return None
    if checked is not None and _date(checked) is None:
        return None
    result = {"version": 1, "mode": "bundled", "catalog_sha256": digest, "checked_at": checked}
    if "retained_findings" in value:
        if not _count(value["retained_findings"]):
            return None
        result["retained_findings"] = value["retained_findings"]
    return result


def _reasons(value: object) -> dict | None:
    if (not isinstance(value, dict) or len(value) > 200
            or any(not isinstance(k, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", k)
                   or not _count(v) for k, v in value.items())):
        return None
    return {k: v for k, v in sorted(value.items()) if v}


def snapshot_coverage(value: object) -> dict | None:
    if not isinstance(value, dict) or not isinstance(value.get("status"), str) or value["status"] not in {
            "checked", "partial", "not_applicable", "unavailable"}:
        return None
    if value["status"] == "unavailable":
        return {"status": "unavailable"}
    counts = value.get("status_counts")
    if (not isinstance(counts, dict)
            or not all(_count(counts.get(k)) for k in ("affected", "unaffected", "unknown", "not_in_catalog"))
            or not all(_count(value.get(k)) for k in ("dependencies_found", "dependencies_checked"))):
        return None
    sources = value.get("sources")
    if not isinstance(sources, dict) or not sources or not set(sources) <= set(SOURCE_REPOSITORIES):
        return None
    cleaned_sources = {}
    for name in SOURCE_REPOSITORIES:
        if name not in sources:
            continue
        source = sources[name]
        if (not isinstance(source, dict) or source.get("repository") != SOURCE_REPOSITORIES[name]
                or not isinstance(source.get("commit"), str)
                or not re.fullmatch(r"[0-9a-f]{40}", source["commit"])
                or _date(source.get("generated_at")) is None):
            return None
        cleaned_sources[name] = {key: source[key] for key in ("repository", "commit", "generated_at")}
    result = {"status": value["status"], "sources": cleaned_sources, "status_counts": {
        key: counts[key] for key in ("affected", "unaffected", "unknown", "not_in_catalog")},
        **{key: value[key] for key in ("dependencies_found", "dependencies_checked")}}
    for key in ("unknown_reason_counts", "manifest_gap_reason_counts"):
        result[key] = _reasons(value.get(key, {}))
        if result[key] is None:
            return None
    for key in ("inventory_truncated", "findings_truncated", "evaluations_truncated"):
        if not _count(value.get(key, 0)):
            return None
        result[key] = value.get(key, 0)
    manifests = value.get("incomplete_manifests", {})
    if not isinstance(manifests, dict):
        return None
    result["incomplete_manifest_count"] = len(manifests)
    has_gaps = (counts["unknown"] or counts["not_in_catalog"] or manifests
                or any(result[key] for key in ("inventory_truncated", "findings_truncated", "evaluations_truncated"))
                or result["unknown_reason_counts"] or result["manifest_gap_reason_counts"])
    if value["status"] in {"checked", "not_applicable"} and has_gaps:
        return None
    return result


def _freshness(coverage: dict, metadata: dict | None) -> str:
    checked = _date(metadata.get("checked_at")) if metadata else None
    if checked is None:
        return "Unknown; check time is not recorded."
    ages = {name: int((checked - _date(source["generated_at"])).total_seconds() // 86_400)
            for name, source in coverage["sources"].items()}
    if any(age < 0 for age in ages.values()):
        return "Unknown; a source timestamp is later than the recorded check."
    state = "Stale" if any(age >= 7 for age in ages.values()) else "Within the 7-day freshness window"
    return (f"{state} at the recorded check; source age in days: "
            + ", ".join(f"{name}: {age}" for name, age in ages.items()) + ".")


def snapshot_rows(value: object, metadata_value: object = None) -> list[tuple[str, str]]:
    if value is None and metadata_value is None:
        return []
    coverage, metadata = snapshot_coverage(value), snapshot_metadata(metadata_value)
    if coverage is None:
        return [("Dependency snapshot", "Coverage not recorded or unreadable; no complete result established.")]
    rows = [("Dependency snapshot", coverage["status"]),
            ("Snapshot SHA-256", (metadata or {}).get("catalog_sha256") or "Not recorded"),
            ("Snapshot checked at", (metadata or {}).get("checked_at") or "Not recorded"),
            ("Snapshot scope", SCOPE)]
    if coverage["status"] == "unavailable":
        return rows
    rows.append(("Snapshot freshness", _freshness(coverage, metadata)))
    for name, source in coverage["sources"].items():
        rows.append((f"Snapshot source: {SOURCE_LABELS[name]}",
                     f"{source['repository']}; commit: {source['commit']}; generated: {source['generated_at']}."))
    counts = coverage["status_counts"]
    rows += [("Snapshot dependency coverage",
              f"{coverage['dependencies_checked']} of {coverage['dependencies_found']} dependency versions checked. "
              f"Advisory assessments: {counts['affected']} affected; {counts['unaffected']} unaffected; "
              f"{counts['unknown']} unknown. {counts['not_in_catalog']} unique package/version entries absent "
              "from the snapshot. Assessment counts are not unique dependency counts.")]
    for key, label in (("unknown_reason_counts", "Snapshot unknown reasons"),
                       ("manifest_gap_reason_counts", "Snapshot manifest gaps")):
        reasons = coverage[key]
        rows.append((label, ", ".join(f"{reason.replace('_', ' ')}: {count}"
                                     for reason, count in reasons.items()) or "None recorded"))
    rows.append(("Snapshot processing gaps",
                 f"Incomplete manifests: {coverage['incomplete_manifest_count']}; "
                 f"inventory omitted: {coverage['inventory_truncated']}; "
                 f"findings omitted: {coverage['findings_truncated']}; "
                 f"evaluations omitted: {coverage['evaluations_truncated']}."))
    return rows


def snapshot_notices(value: object, metadata_value: object = None) -> list[tuple[str, str]]:
    if value is None and metadata_value is None:
        return []
    coverage, metadata = snapshot_coverage(value), snapshot_metadata(metadata_value)
    if coverage is None:
        notices = [("Dependency snapshot unreadable", "Snapshot coverage could not be validated. " + SCOPE)]
    elif coverage["status"] == "unavailable":
        notices = [("Dependency snapshot unavailable", "The bundled catalog could not be checked. " + SCOPE)]
    elif coverage["status"] == "partial":
        counts = coverage["status_counts"]
        notices = [("Dependency snapshot incomplete",
                    f"{counts['unknown']} unknown advisory assessments; {counts['not_in_catalog']} package/version "
                    f"entries absent from the snapshot; {coverage['incomplete_manifest_count']} incomplete manifests. "
                    "Review the recorded reasons and processing limits. " + SCOPE)]
    else:
        notices = []
    if coverage and coverage["status"] != "unavailable":
        freshness = _freshness(coverage, metadata)
        if freshness.startswith("Stale"):
            notices.append(("Dependency snapshot stale", freshness + " Newer advisories may be absent."))
        elif freshness.startswith("Unknown"):
            notices.append(("Dependency snapshot freshness unknown", freshness))
    if metadata and metadata.get("retained_findings"):
        notices.append(("Earlier dependency findings retained",
                        f"{metadata['retained_findings']} earlier snapshot findings retained because the current "
                        "snapshot check was incomplete. Their original source provenance still applies; "
                        "the current check did not reconfirm them."))
    return notices


def snapshot_finding_rows(value: object) -> list[tuple[str, str]]:
    """Each retained finding keeps its own provenance, not the current catalog's."""
    if not isinstance(value, dict):
        return []
    rows = []
    sources = value.get("snapshot_sources")
    for source in sources[:2] if isinstance(sources, list) else []:
        if not isinstance(source, dict):
            continue
        name = source.get("name")
        if (not isinstance(name, str) or name not in SOURCE_REPOSITORIES
                or source.get("repository") != SOURCE_REPOSITORIES[name]
                or not isinstance(source.get("commit"), str)
                or not re.fullmatch(r"[0-9a-f]{40}", source["commit"])
                or _date(source.get("generated_at")) is None):
            continue
        rows.append((f"Finding snapshot source: {SOURCE_LABELS[name]}",
                     f"{source['repository']}; commit: {source['commit']}; generated: {source['generated_at']}."))
    return rows or [("Finding snapshot source", "Not recorded or unreadable for this finding.")]
