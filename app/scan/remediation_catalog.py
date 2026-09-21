"""Reusable, offline upgrade recipes backed by explicit advisory fix events.

Cards are review plans, not applied patches or runtime evidence. A candidate
must clear every advisory entry for this exact package in the supplied snapshot.
No releases, compatibility constraints, or fixes are inferred from prose.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from functools import cmp_to_key
import hashlib
import json
import re

CATALOG_VERSION = "2026-09-21.1"
MAX_ADVISORIES = 256
MAX_CANDIDATES = 16
MAX_DISCOVERY_ITEMS = 4096

_VERIFICATION = [
    "Regenerate the resolved dependency file and confirm every affected installation was updated.",
    "Repeat the advisory scan; preserve unknown or incomplete results as unresolved.",
    "Run the application's build and regression tests, including the affected feature when available.",
]
_RECIPES = {
    "npm": {
        "id": "npm-dependency-upgrade", "revision": 1,
        "steps": [
            "Review the advisory and release notes for a listed candidate and check application compatibility.",
            "Update the dependency declaration or the parent dependency that brings in a transitive package.",
            "Regenerate the lockfile with the project's existing package-manager workflow; do not hand-edit it.",
        ],
        "verification": _VERIFICATION,
    },
    "PyPI": {
        "id": "pypi-dependency-upgrade", "revision": 1,
        "steps": [
            "Review the advisory and release notes for a listed candidate and check Python/API compatibility.",
            "Update the requirement or the parent dependency that brings in a transitive package.",
            "Regenerate resolved requirements or the lockfile with the project's existing dependency workflow.",
        ],
        "verification": _VERIFICATION,
    },
}


@dataclass
class UpgradeBudget:
    """Shared across one archive; exhaustion never changes detection results."""

    remaining: int = 4096


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode()).hexdigest()


def recipe_catalog() -> dict:
    return {"schema_version": 1, "catalog_version": CATALOG_VERSION,
            "recipes": deepcopy(list(_RECIPES.values()))}


def plan_dependency_upgrade(ecosystem: str, package: str, installed_version: str,
                            entries: list[dict], sources: dict, *,
                            identities_complete: bool = True, budget: UpgradeBudget | None = None) -> dict:
    # Delay imports to keep the matcher and the portable recipe registry independent at import time.
    from app.scan.cve_match import _entry_identity, compare_versions, evaluate_advisory

    if ecosystem not in _RECIPES:
        raise ValueError("Unsupported remediation ecosystem")
    if budget is None:
        budget = UpgradeBudget()
    card = {
        "schema_version": 1, "catalog_version": CATALOG_VERSION,
        "recipe": deepcopy(_RECIPES[ecosystem]),
        "binding": {"ecosystem": ecosystem, "package": package, "installed_version": installed_version,
                    "sources": deepcopy(sources), "sources_sha256": _digest(sources), "records_sha256": None},
        "status": "manual_review", "candidate_versions": [], "reason_codes": [],
        "automatic_apply": False, "runtime_verified": False, "compatibility": "not_assessed",
        "advisory_count": len(entries), "evaluations": 0,
    }

    def stop(reason):
        card["reason_codes"] = [reason]
        return card

    if not identities_complete:
        return stop("incomplete_advisory_identities")
    if not entries or len(entries) > MAX_ADVISORIES:
        return stop("advisory_limit" if entries else "no_advisories")
    if compare_versions(installed_version, installed_version, ecosystem) is None:
        return stop("unsupported_installed_version")
    if any(_entry_identity(entry, sources) is None for entry in entries):
        return stop("invalid_advisory_identity")
    card["binding"]["records_sha256"] = _digest(sorted(entries, key=_digest))
    candidates: set[str] = set()
    discovery_items = 0
    for entry in entries:
        # Only the reviewed OSV source explicitly identifies a fixed release.
        # CVE lessThan, OSV limit and last_affected are not release/fix evidence.
        if entry.get("source") != "github-reviewed":
            continue
        ranges = entry.get("osv_ranges", [])
        if not isinstance(ranges, list):
            return stop("invalid_advisory_ranges")
        for row in ranges:
            discovery_items += 1
            if discovery_items > MAX_DISCOVERY_ITEMS:
                return stop("discovery_limit")
            if not isinstance(row, dict):
                return stop("invalid_advisory_ranges")
            supported = {"SEMVER", "ECOSYSTEM"} if ecosystem == "npm" else {"ECOSYSTEM"}
            if row.get("type") not in supported:
                continue
            events = row.get("events")
            if not isinstance(events, list):
                return stop("invalid_advisory_ranges")
            for event in events:
                discovery_items += 1
                if discovery_items > MAX_DISCOVERY_ITEMS:
                    return stop("discovery_limit")
                if not isinstance(event, dict) or set(event) != {"fixed"}:
                    continue
                version = event["fixed"]
                if compare_versions(version, installed_version, ecosystem) == 1:
                    candidates.add(version)
                    if len(candidates) > MAX_CANDIDATES:
                        return stop("candidate_limit")
    if not candidates:
        return stop("no_supported_fixed_release")
    reasons = set()
    for version in sorted(candidates, key=cmp_to_key(
            lambda a, b: compare_versions(a, b, ecosystem) or ((a > b) - (a < b)))):
        accepted = True
        for entry in entries:
            if budget.remaining <= 0:
                # No partial list is promoted when this card's review is incomplete.
                card["candidate_versions"] = []
                return stop("evaluation_limit")
            budget.remaining -= 1
            card["evaluations"] += 1
            assessment = evaluate_advisory(version, ecosystem, entry)
            if assessment["status"] != "unaffected" or assessment["unresolved_ranges"]:
                accepted = False
                reasons.add("candidate_still_affected" if assessment["status"] == "affected"
                            else "candidate_assessment_unknown")
                if assessment["unresolved_ranges"]:
                    reasons.add("candidate_assessment_unknown")
                break
        if accepted:
            card["candidate_versions"].append(version)
    card["reason_codes"] = sorted(reasons)
    if card["candidate_versions"]:
        card["status"] = "candidates_available"
    return card


def remediation_record(evidence: object) -> dict | None:
    """Validate a saved plan and its finding binding; never recompute old advice."""
    try:
        return _remediation_record(evidence)
    except (KeyError, TypeError, ValueError, RecursionError):
        # Malformed historical evidence must not prevent the original finding from rendering.
        return None


def _remediation_record(evidence: object) -> dict | None:
    from app.scan.cve_match import SOURCE_REPOSITORY, GHSA_REPOSITORY, _valid_source, compare_versions

    if not isinstance(evidence, dict) or evidence.get("snapshot_check_status") == "retained_not_reconfirmed":
        return None
    card = evidence.get("remediation")
    if not isinstance(card, dict) or type(card.get("schema_version")) is not int or card["schema_version"] != 1:
        return None
    binding = card.get("binding")
    if (not isinstance(binding, dict) or any(not isinstance(binding.get(key), str)
            or binding.get(key) != evidence.get(key) or not binding.get(key)
            for key in ("ecosystem", "package", "installed_version"))):
        return None
    if (not isinstance(card.get("catalog_version"), str)
            or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\.[0-9]+", card["catalog_version"])
            or "records_sha256" not in binding):
        return None
    recipe = card.get("recipe")
    if recipe != _RECIPES.get(binding["ecosystem"]):
        return None
    if (card.get("automatic_apply") is not False or card.get("runtime_verified") is not False
            or card.get("compatibility") != "not_assessed"
            or card.get("status") not in {"candidates_available", "manual_review"}):
        return None
    sources = binding.get("sources")
    if not isinstance(sources, dict) or _digest(sources) != binding.get("sources_sha256"):
        return None
    if set(sources) not in ({"cvelist"}, {"cvelist", "github-reviewed"}):
        return None
    for name, source in sources.items():
        repository = SOURCE_REPOSITORY if name == "cvelist" else GHSA_REPOSITORY
        if _valid_source(source, repository) != source:
            return None
    finding_sources = evidence.get("snapshot_sources")
    if not isinstance(finding_sources, list) or not finding_sources:
        return None
    for source in finding_sources:
        if (not isinstance(source, dict) or sources.get(source.get("name")) !=
                {key: value for key, value in source.items() if key != "name"}):
            return None
    versions = card.get("candidate_versions")
    if (not isinstance(versions, list) or len(versions) > MAX_CANDIDATES
            or any(not isinstance(v, str) or not re.fullmatch(r"[0-9A-Za-z.+-]{1,128}", v) for v in versions)
            or len(versions) != len(set(versions))
            or bool(versions) != (card["status"] == "candidates_available")):
        return None
    if any(compare_versions(v, binding["installed_version"], binding["ecosystem"]) != 1 for v in versions):
        return None
    for key in ("advisory_count", "evaluations"):
        if type(card.get(key)) is not int or card[key] < 0:
            return None
    if versions and (not isinstance(binding.get("records_sha256"), str)
                     or not re.fullmatch(r"[0-9a-f]{64}", binding["records_sha256"])
                     or not 1 <= card["advisory_count"] <= MAX_ADVISORIES
                     or card["evaluations"] < card["advisory_count"] * len(versions)):
        return None
    reasons = card.get("reason_codes")
    if (not isinstance(reasons, list) or len(reasons) > 16
            or any(not isinstance(r, str) or not re.fullmatch(r"[a-z_]{1,64}", r) for r in reasons)):
        return None
    if versions and set(reasons) - {"candidate_still_affected", "candidate_assessment_unknown"}:
        return None
    return deepcopy(card)


def remediation_hint(card: dict) -> str:
    if card["status"] == "candidates_available":
        return ("Advisory-fixed upgrade candidates: " + ", ".join(card["candidate_versions"]) + ". "
                "These versions were checked against all recorded advisories for this package in this snapshot. "
                "Review compatibility, update the dependency and resolved lockfile, then repeat the scan and "
                "application tests. No update has been applied or runtime-verified.")
    return ("No upgrade candidate could be established from the available advisory records. "
            "Review the linked advisories and package release notes before choosing an update; "
            "compatibility and runtime behavior remain unverified.")
