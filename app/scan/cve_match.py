"""Offline CVE snapshot matching of resolved registry dependencies.

This intentionally supports a small, auditable ordering subset: npm SemVer
and numeric PyPI releases with canonical a/b/rc prereleases. Unsupported syntax
and ambiguous records stay unknown; neither absent packages nor unmatched
records establish global safety.
Only standard-library imports are used so this module runs inside Pyodide.
"""
from __future__ import annotations

import io
import re
import tomllib
import zipfile
import zlib
from itertools import islice

from app.foundation.lockfiles import (
    collect_dependency_inventory,
    dependency_exclusion_reason,
    normalize_pypi,
    occurrence_evidence,
    occurrence_summary,
)
from app.scan.advisory_evaluation import (  # evaluation core lives below
    _CVE_ID,
    _GHSA_ID,
    _STATUSES,
    GHSA_REPOSITORY,
    SOURCE_REPOSITORY,
    _entry_identity,
    _valid_source,
    evaluate_advisory,
)
from app.scan.kev_feed import KEV_REPOSITORY
from app.scan.kev_feed import SOURCE_NAME as KEV_SOURCE
from app.scan.remediation_catalog import UpgradeBudget, plan_dependency_upgrade, remediation_hint

RULE_ID = "dependency-cve-match"
MAX_EXPLOITATION_RECORDS = 100_000
ADVISORY_SOURCES = ("cvelist", "github-reviewed")
MAX_ARCHIVE_BYTES = 50_000_000
MAX_ARCHIVE_MEMBERS = 20_000
MAX_EXPANDED_BYTES = 100_000_000
MAX_EVALUATIONS = 20_000
MAX_FINDINGS = 500
MAX_DETAILS = 200
MAX_ASSESSMENT_DETAILS = 16
MAX_MANIFEST_METADATA_BYTES = 2_000_000
CVE_PAGE = "https://www.cve.org/CVERecord?id="
GHSA_PAGE = "https://github.com/advisories/"


def _valid_kev_source(value: object) -> dict | None:
    """A pinned repository source like the others, plus the upstream catalog version and blob digest."""
    pinned = _valid_source(value, KEV_REPOSITORY)
    if pinned is None:
        return None
    version, digest = value.get("catalog_version"), value.get("sha256")
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]{4}\.[0-9]{2}\.[0-9]{2}", version):
        return None
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        return None
    return {**pinned, "catalog_version": version, "sha256": digest}


def _sources(catalog: object) -> dict[str, dict] | None:
    if not isinstance(catalog, dict) or type(catalog.get("schema_version")) is not int:
        return None
    schema = catalog["schema_version"]
    primary = _valid_source(catalog.get("source"), SOURCE_REPOSITORY)
    if primary is None:
        return None
    if schema == 1:
        return {"cvelist": primary}
    if schema not in (2, 3):
        return None
    expected = {"cvelist", "github-reviewed"} | ({KEV_SOURCE} if schema == 3 else set())
    sources = catalog.get("sources")
    if not isinstance(sources, dict) or set(sources) != expected:
        return None
    cvelist = _valid_source(sources.get("cvelist"), SOURCE_REPOSITORY)
    github = _valid_source(sources.get("github-reviewed"), GHSA_REPOSITORY)
    if cvelist != primary or github is None:
        return None
    result = {"cvelist": cvelist, "github-reviewed": github}
    if schema == 3:
        kev = _valid_kev_source(sources.get(KEV_SOURCE))
        if kev is None:
            return None
        result[KEV_SOURCE] = kev
    return result


def _exploitation_index(catalog: dict, sources: dict[str, dict]) -> dict[str, dict] | None:
    """CVE ID -> KEV record, or None when the snapshot carries no exploitation source.

    A schema-3 catalog whose index is malformed raises: silently dropping the
    index would downgrade known-exploited matches to ordinary ones.
    """
    if KEV_SOURCE not in sources:
        if "exploitation" in catalog:
            raise ValueError("exploitation index without a source")
        return None
    container = catalog.get("exploitation")
    if not isinstance(container, dict) or set(container) != {KEV_SOURCE}:
        raise ValueError("invalid exploitation index")
    index = container[KEV_SOURCE]
    if not isinstance(index, dict) or len(index) > MAX_EXPLOITATION_RECORDS:
        raise ValueError("invalid exploitation index")
    for cve_id, record in index.items():
        if (not isinstance(cve_id, str) or not _CVE_ID.fullmatch(cve_id) or not isinstance(record, dict)
                or set(record) != {"date_added", "due_date", "ransomware"}
                or record["ransomware"] not in ("Known", "Unknown")
                or any(not isinstance(record[key], str)
                       or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", record[key])
                       for key in ("date_added", "due_date"))):
            raise ValueError("invalid exploitation record")
    return index


def _source(catalog: object) -> dict | None:
    sources = _sources(catalog)
    return sources.get("cvelist") if sources else None


def _advisory_url(advisory_id: str) -> str:
    return (CVE_PAGE if _CVE_ID.fullmatch(advisory_id) else GHSA_PAGE) + advisory_id


def _missing_lock_reason(archive: zipfile.ZipFile, path: str) -> str:
    """Explain missing pins without evaluating project build metadata."""
    if path.rsplit("/", 1)[-1] != "pyproject.toml":
        return "missing_supported_lockfile"
    if archive.getinfo(path).file_size > MAX_MANIFEST_METADATA_BYTES:
        return "manifest_metadata_size_limit"
    try:
        metadata = tomllib.loads(archive.read(path).decode("utf-8"))
    except (ValueError, OSError, RuntimeError, EOFError, zipfile.BadZipFile, zlib.error):
        # Optional metadata must not discard findings from independent locks.
        return "invalid_manifest_metadata"
    project = metadata.get("project", {})
    dynamic = project.get("dynamic", []) if isinstance(project, dict) else []
    if isinstance(dynamic, list) and "dependencies" in dynamic:
        return "dynamic_dependencies_without_lock"
    return "missing_supported_lockfile"


def _record_unknown(coverage: dict, detail: dict) -> None:
    """Count every unknown outcome even when its display details are capped."""
    reason = detail["reason"]
    counts = coverage["unknown_reason_counts"]
    counts[reason] = counts.get(reason, 0) + 1
    if len(coverage["details"]) < MAX_DETAILS:
        coverage["details"].append(detail)
    else:
        coverage["details_truncated"] += 1


def _archive_inventory(data: bytes):
    if not isinstance(data, bytes) or len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError("archive_size_limit")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = archive.infolist()
        if len(members) > MAX_ARCHIVE_MEMBERS or sum(i.file_size for i in members) > MAX_EXPANDED_BYTES:
            raise ValueError("archive_expansion_limit")
        if len({info.filename for info in members}) != len(members):
            raise ValueError("duplicate_archive_members")
        paths = {i.filename for i in members if not i.is_dir()
                 and not dependency_exclusion_reason(i.filename)}
        gaps = {}
        gap_reasons = {}
        unsupported = {"yarn.lock", "Pipfile.lock",
                       "Cargo.lock", "Gemfile.lock", "composer.lock", "packages.lock.json"}
        for path in sorted(paths):
            directory, _, basename = path.rpartition("/")
            prefix = directory + "/" if directory else ""
            if basename == "package.json" and archive.getinfo(path).file_size > MAX_MANIFEST_METADATA_BYTES:
                # A metadata file cannot discard findings from independent
                # locks; the shared reader also bounds it before reading.
                gaps[path] = "oversized"
                gap_reasons[path] = "manifest_metadata_size_limit"
            elif basename in unsupported:
                gaps[path] = "unsupported"
            elif basename == "bun.lockb" and prefix + "bun.lock" not in paths:
                gap_reasons[path] = "unsupported_bun_binary_lockfile"
            elif basename == "package.json" and not any(
                    prefix + name in paths for name in (
                        "package-lock.json", "pnpm-lock.yaml", "bun.lock", "bun.lockb")):
                gaps[path] = "unresolved"
            elif basename in {"pyproject.toml", "Pipfile", "setup.py", "setup.cfg"} and not any(
                    prefix + name in paths for name in ("poetry.lock", "requirements.txt", "uv.lock")):
                gaps[path] = "unresolved"
            if gaps.get(path) == "unresolved":
                gap_reasons[path] = _missing_lock_reason(archive, path)
    inventory = collect_dependency_inventory(data)
    for path, status in gaps.items():
        if path in inventory.incomplete_manifests:
            # Keep a specific shared-reader metadata failure instead of the
            # generic missing-sibling-lock explanation collected above.
            if gap_reasons.get(path) == "missing_supported_lockfile":
                gap_reasons.pop(path, None)
        elif (path in inventory.covered_workspace_manifests
              and gap_reasons.get(path) == "missing_supported_lockfile"):
            gap_reasons.pop(path, None)
        else:
            inventory.incomplete_manifests[path] = status
    return inventory, gap_reasons


def match_archive(data: bytes, catalog: dict, *, assessment_observer=None) -> dict:
    """Match ZIP lockfile pins against an identified, offline advisory snapshot.

    The optional internal observer receives each inventoried dependency's
    assessments and whether all advisory identities were examined. It lets a
    server refresh distinguish a withdrawn match from one we could not recheck
    without exporting an unbounded assessment log or repeating the evaluation.
    Observer work is bounded by the same inventory and evaluation limits.
    """
    sources = _sources(catalog)
    coverage = {
        "status": "partial", "status_counts": dict.fromkeys((*sorted(_STATUSES), "not_in_catalog"), 0),
        "dependencies_found": 0, "dependencies_checked": 0, "packages_in_catalog": 0,
        "advisory_evaluations": 0, "unresolved_ranges": 0, "kev_listed_findings": 0, "manifests": [],
        "incomplete_manifests": {}, "inventory_truncated": 0, "findings_truncated": 0,
        "evaluations_truncated": 0,
        "unknown_reason_counts": {}, "details_truncated": 0,
        "manifest_gap_reason_counts": {}, "manifest_gap_details": [],
        "manifest_gap_details_truncated": 0,
        "excluded_manifests": {}, "excluded_manifests_truncated": 0,
        "source": sources.get("cvelist") if sources else None,
        "sources": sources or {}, "details": [], "catalog_stats": {},
        "limitations": [
            "Only exact registry package versions in supported lockfiles are compared with this snapshot.",
            "Locked platform, optional and development variants are included; runtime selection is not evaluated.",
            "A package/version match does not establish reachable or exploitable application code.",
            "Absence from the snapshot, unsupported ranges, and no matches do not establish a clean or safe project.",
            "PyPI comparisons support numeric releases and canonical a/b/rc prereleases; "
            "epochs, post/dev/local versions and other spellings remain unsupported. "
            "npm comparisons require SemVer; CVE range lower bound '0' means the earliest version.",
            "CISA KEV annotates matched CVEs with known exploitation elsewhere. Listing does not establish "
            "exploitation of this application; absence from KEV does not establish that a vulnerability "
            "is unexploited.",
        ],
    }
    findings = []
    remediation_budget = UpgradeBudget()
    result = {"findings": findings, "coverage": coverage}
    packages = catalog.get("packages") if isinstance(catalog, dict) else None
    if sources is None or not isinstance(packages, dict):
        coverage.update(status="unavailable", error="invalid_catalog")
        return result
    try:
        kev_index = _exploitation_index(catalog, sources)
    except ValueError:
        coverage.update(status="unavailable", error="invalid_catalog")
        return result
    # The upgrade recipe binds to advisory provenance only; KEV never changes a candidate version.
    advisory_sources = {name: sources[name] for name in ADVISORY_SOURCES if name in sources}
    stats = catalog.get("stats", {})
    if isinstance(stats, dict):
        for key, value in islice(stats.items(), 100):
            if isinstance(key, str) and len(key) <= 128 and type(value) is int and value >= 0:
                coverage["catalog_stats"][key] = value
    try:
        inventory, gap_reasons = _archive_inventory(data)
    except (ValueError, OSError, RuntimeError, zipfile.BadZipFile, OverflowError):
        coverage.update(status="unavailable", error="invalid_or_oversized_archive")
        return result
    coverage.update(dependencies_found=inventory.found, manifests=inventory.manifests,
                    incomplete_manifests=inventory.incomplete_manifests,
                    excluded_manifests=inventory.excluded_manifests,
                    excluded_manifests_truncated=inventory.excluded_manifests_truncated,
                    inventory_truncated=max(0, inventory.found - len(inventory.dependencies)))
    for manifest, status in sorted(inventory.incomplete_manifests.items()):
        reason = gap_reasons.get(manifest, {
            "unresolved": "unresolved_dependency_versions",
            "unsupported": "unsupported_manifest_format",
            "malformed": "malformed_lockfile",
            "oversized": "lockfile_size_limit",
            "truncated": "lockfile_inventory_limit",
        }.get(status, status))
        counts = coverage["manifest_gap_reason_counts"]
        counts[reason] = counts.get(reason, 0) + 1
        if len(coverage["manifest_gap_details"]) < MAX_DETAILS:
            coverage["manifest_gap_details"].append({
                "manifest": manifest, "status": status, "reason": reason,
            })
        else:
            coverage["manifest_gap_details_truncated"] += 1
    for dep in inventory.dependencies:
        locations = {"occurrences": occurrence_evidence(dep),
                     "occurrences_recorded": bool(dep.occurrences)}
        name = normalize_pypi(dep.name) if dep.ecosystem == "PyPI" else dep.name
        key = dep.ecosystem + ":" + name
        entries = packages.get(key)
        coverage["dependencies_checked"] += 1
        if entries is None:
            coverage["status_counts"]["not_in_catalog"] += 1
            if assessment_observer is not None:
                assessment_observer(dep, [], True)
            continue
        coverage["packages_in_catalog"] += 1
        if not isinstance(entries, list) or not entries:
            coverage["status_counts"]["unknown"] += 1
            coverage["unresolved_ranges"] += 1
            _record_unknown(coverage, {"package": key, "version": dep.version,
                                      "manifest": dep.manifest, **locations,
                                      "reason": "invalid_catalog_entries"})
            if assessment_observer is not None:
                assessment_observer(dep, [], False)
            continue
        grouped: dict[str, list[tuple[dict, dict, str]]] = {}
        identities_complete = True
        for entry_index, entry in enumerate(entries):
            if coverage["advisory_evaluations"] >= MAX_EVALUATIONS:
                coverage["evaluations_truncated"] += len(entries) - entry_index
                identities_complete = False
                break
            coverage["advisory_evaluations"] += 1
            identity = _entry_identity(entry, sources)
            if identity is None:
                identities_complete = False
                coverage["status_counts"]["unknown"] += 1
                coverage["unresolved_ranges"] += 1
                _record_unknown(coverage, {"package": key, "version": dep.version,
                                          "manifest": dep.manifest, **locations,
                                          "reason": "invalid_advisory_identity"})
                continue
            entry_id, aliases, source_key = identity
            group_id = next((item for item in (entry_id, *aliases) if _CVE_ID.fullmatch(item)), entry_id)
            assessment = evaluate_advisory(dep.version, dep.ecosystem, entry)
            coverage["unresolved_ranges"] += assessment["unresolved_ranges"]
            grouped.setdefault(group_id, []).append((entry, assessment, source_key))
        # If the cap cut across repeated affected objects, their interpretation
        # is incomplete; never emit a positive based on that partial group.
        truncated = coverage["advisory_evaluations"] >= MAX_EVALUATIONS and coverage["evaluations_truncated"] > 0
        assessments = []
        remediation = None
        for group_id, group in grouped.items():
            statuses = {assessment["status"] for _, assessment, _ in group}
            status = next(iter(statuses)) if len(statuses) == 1 and not truncated else "unknown"
            all_ids = sorted({item for entry, _, _ in group
                              for item in (entry["id"], *entry.get("aliases", []))})
            if assessment_observer is not None:
                assessments.append({
                    "advisory_ids": frozenset(all_ids), "status": status,
                    "reported": status == "affected" and len(findings) < MAX_FINDINGS,
                })
            coverage["status_counts"][status] += 1
            if status == "unknown":
                if len(statuses) > 1:
                    coverage["unresolved_ranges"] += 1
                if truncated:
                    reason = "evaluation_limit"
                elif len(statuses) > 1:
                    source_keys = {source_key for _, _, source_key in group}
                    if {"affected", "unaffected"} <= statuses:
                        reason = ("conflicting_advisory_sources" if len(source_keys) > 1
                                  else "conflicting_affected_objects")
                    else:
                        reason = ("incomplete_advisory_sources" if len(source_keys) > 1
                                  else "incomplete_affected_objects")
                else:
                    reason = next(
                        (assessment["reason"] for _, assessment, _ in group
                         if assessment["reason"]),
                        "unknown_status",
                    )
                _record_unknown(coverage, {
                    "package": key, "version": dep.version, "manifest": dep.manifest, **locations,
                    "advisory": group_id, "reason": reason,
                    "assessments": [
                        {"source": source_key, "advisory": entry["id"],
                         "status": assessment["status"], "reason": assessment["reason"]}
                        for entry, assessment, source_key in group[:MAX_ASSESSMENT_DETAILS]
                    ],
                    "assessments_truncated": max(0, len(group) - MAX_ASSESSMENT_DETAILS),
                })
                continue
            if status != "affected":
                continue
            if len(findings) >= MAX_FINDINGS:
                coverage["findings_truncated"] += 1
                continue
            entry_ids = sorted({entry["id"] for entry, _, _ in group})
            cve_id = next((item for item in entry_ids if _CVE_ID.fullmatch(item)), None)
            ghsa_id = next((item for item in entry_ids if _GHSA_ID.fullmatch(item)), None)
            advisory_id = cve_id or ghsa_id or group_id
            source_keys = sorted({source_key for _, _, source_key in group})
            # KEV is keyed by CVE; a GHSA-only group is looked up through its CVE aliases.
            kev_hits = [item for item in all_ids if kev_index is not None and item in kev_index]
            if kev_index is None:
                exploitation = {"status": "not_assessed"}
            elif kev_hits:
                exploitation = {"status": "listed", "source": KEV_SOURCE, "cve_id": kev_hits[0],
                                **kev_index[kev_hits[0]], "snapshot": sources[KEV_SOURCE]}
                coverage["kev_listed_findings"] += 1
            else:
                exploitation = {"status": "not_listed", "source": KEV_SOURCE, "snapshot": sources[KEV_SOURCE]}
            evidence = {
                "version": 1, "package": name, "ecosystem": dep.ecosystem,
                "installed_version": dep.version, "manifest": dep.manifest,
                "dependency_scope": ("development" if dep.development is True else
                                     "runtime" if dep.development is False else "unknown"),
                "direct": dep.direct, "dependency_groups": list(dep.dependency_groups),
                **locations,
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
                "exploitation": exploitation,
                "reachability": "not_assessed",
            }
            if cve_id:
                evidence["cve_id"] = cve_id
            if ghsa_id:
                evidence["ghsa_id"] = ghsa_id
            if remediation is None:
                remediation = plan_dependency_upgrade(
                    dep.ecosystem, name, dep.version, entries, advisory_sources,
                    identities_complete=identities_complete and not truncated, budget=remediation_budget,
                )
            # Persist the recipe with its source binding, including honest manual-review outcomes.
            evidence["remediation"] = remediation
            listed = exploitation["status"] == "listed"
            findings.append({
                "rule_id": RULE_ID,
                "title": f"{name} {dep.version} matches {advisory_id}" + (" (CISA KEV)" if listed else ""),
                # Known exploitation elsewhere is the "fix first" signal; it is not a reachability claim.
                "severity": "critical" if listed else "high", "confidence": 0.9, "category": "Security",
                "file": dep.manifest, "line": dep.line,
                "explanation": (
                    f"The resolved {dep.ecosystem} package version is listed as affected "
                    f"by {advisory_id} in the bundled advisory snapshot. "
                    + (f"CISA lists {exploitation['cve_id']} in the Known Exploited Vulnerabilities catalog "
                       f"(added {exploitation['date_added']}; known ransomware campaign use: "
                       f"{exploitation['ransomware']}). Exploitation elsewhere does not establish "
                       "exploitation of this application. " if listed else "")
                    + "Application reachability and exploitability have not been verified. "
                    + occurrence_summary(dep)
                ),
                "fix_hint": remediation_hint(remediation),
                "source": "dependency", "verification_status": "unverified",
                "verification_method": "package_version_match",
                "claim_evidence": evidence,
            })
        if assessment_observer is not None:
            assessment_observer(dep, assessments, identities_complete)
    gaps = (coverage["incomplete_manifests"] or coverage["inventory_truncated"] or
            coverage["findings_truncated"] or coverage["evaluations_truncated"] or
            coverage["status_counts"]["unknown"] or coverage["status_counts"]["not_in_catalog"])
    coverage["status"] = "partial" if gaps else "checked" if inventory.dependencies else "not_applicable"
    return result
