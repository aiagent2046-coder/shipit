"""Compile reviewed GitHub Security Advisories into the offline package index.

Only OSV records selected from the official github-reviewed tree by the pinned
ingestion pipeline are accepted. The compiler additionally requires GitHub's
review flag, exact npm/PyPI package identity, and bounded OSV applicability
fields. Unsupported range types are retained so matching reports unknown rather
than turning missing semantics into safety.
"""
from __future__ import annotations

from copy import deepcopy
from collections.abc import Iterable
import json
import re

from app.scan.cve_evidence import _date
from app.sca.lockfiles import normalize_pypi

REPOSITORY = "https://github.com/github/advisory-database"
GHSA_PAGE = "https://github.com/advisories/"
MAX_RECORDS = 500_000
MAX_AFFECTED = 1024
MAX_RANGES = 256
MAX_EVENTS = 512
MAX_VERSIONS = 4096
MAX_ALIASES = 256
MAX_ENTRIES = 500_000
MAX_PACKAGE_ENTRIES = 4096
_GHSA_ID = re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\Z")
_CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z")
_SCHEMA = re.compile(r"1\.[0-9]+\.[0-9]+\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_NPM = re.compile(r"(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+\Z")
_PYPI = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\Z")
_EVENTS = frozenset({"introduced", "fixed", "last_affected", "limit"})


class _Invalid(ValueError):
    pass


def _string(value: object, limit: int = 2048) -> str:
    if (not isinstance(value, str) or not value or len(value) > limit
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise _Invalid("invalid string")
    return value


def _name(ecosystem: str, value: object) -> str:
    name = _string(value, 214 if ecosystem == "npm" else 512)
    pattern = _NPM if ecosystem == "npm" else _PYPI
    if not pattern.fullmatch(name) or name in {".", ".."}:
        raise _Invalid("invalid package name")
    return normalize_pypi(name) if ecosystem == "PyPI" else name


def _aliases(value: object) -> tuple[list[str], int]:
    if not isinstance(value, list) or len(value) > MAX_ALIASES:
        raise _Invalid("invalid aliases")
    aliases = []
    unsupported = 0
    for item in value:
        alias = _string(item, 64)
        if _CVE_ID.fullmatch(alias) or _GHSA_ID.fullmatch(alias):
            aliases.append(alias)
        else:
            unsupported += 1
    return sorted(set(aliases)), unsupported


def _versions(value: object) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_VERSIONS:
        raise _Invalid("invalid affected versions")
    return sorted({_string(item, 128) for item in value})


def _ranges(value: object) -> list[dict]:
    if not isinstance(value, list) or len(value) > MAX_RANGES:
        raise _Invalid("invalid OSV ranges")
    result = []
    for item in value:
        if not isinstance(item, dict):
            raise _Invalid("invalid OSV range")
        kind = _string(item.get("type"), 32)
        events = item.get("events")
        if not isinstance(events, list) or not events or len(events) > MAX_EVENTS:
            raise _Invalid("invalid OSV events")
        projected = []
        event_kinds = set()
        for event in events:
            if not isinstance(event, dict) or len(event) != 1:
                raise _Invalid("invalid OSV event")
            event_kind, event_version = next(iter(event.items()))
            if event_kind not in _EVENTS:
                raise _Invalid("unsupported OSV event")
            projected.append({event_kind: _string(event_version, 128)})
            event_kinds.add(event_kind)
        if "introduced" not in event_kinds:
            raise _Invalid("OSV range has no introduced event")
        if {"fixed", "last_affected"} <= event_kinds:
            raise _Invalid("OSV range mixes fixed and last_affected")
        result.append({"type": kind, "events": projected})
    return result


def merge_reviewed_ghsa(catalog: dict, records: Iterable[dict], *,
                        source_commit: str, generated_at: str) -> dict:
    """Return a deterministic two-source catalog without mutating the CVE input."""
    if not isinstance(source_commit, str) or not _COMMIT.fullmatch(source_commit):
        raise ValueError("source_commit must be a full lowercase Git commit SHA")
    if generated_at is None or _date(generated_at) is None:
        raise ValueError("generated_at must be an ISO timestamp")
    if (not isinstance(catalog, dict) or catalog.get("schema_version") != 1
            or not isinstance(catalog.get("source"), dict)
            or not isinstance(catalog.get("packages"), dict)
            or not isinstance(catalog.get("stats"), dict)):
        raise ValueError("base CVE catalog is invalid")

    result = deepcopy(catalog)
    packages = result["packages"]
    existing_entries = 0
    for key, entries in packages.items():
        if not isinstance(key, str) or not isinstance(entries, list):
            raise ValueError("base CVE package index is invalid")
        existing_entries += len(entries)
    if existing_entries > MAX_ENTRIES:
        raise ValueError("catalogue entry limit exceeded")

    names = (
        "ghsa_seen", "ghsa_reviewed", "ghsa_withdrawn", "ghsa_unreviewed",
        "ghsa_unsupported_schema", "ghsa_invalid_records", "ghsa_unsupported_aliases", "ghsa_affected_seen",
        "ghsa_unsupported_ecosystems", "ghsa_invalid_affected",
        "ghsa_unsupported_ranges", "ghsa_indexed_records", "ghsa_indexed_entries",
        "ghsa_indexed_packages",
    )
    stats = dict.fromkeys(names, 0)
    seen_ids: set[str] = set()
    ghsa_packages: set[str] = set()

    for record in records:
        stats["ghsa_seen"] += 1
        if stats["ghsa_seen"] > MAX_RECORDS:
            raise ValueError("GHSA record limit exceeded")
        if not isinstance(record, dict):
            stats["ghsa_invalid_records"] += 1
            continue
        advisory_id = record.get("id")
        if not isinstance(advisory_id, str) or not _GHSA_ID.fullmatch(advisory_id):
            stats["ghsa_invalid_records"] += 1
            continue
        if advisory_id in seen_ids:
            raise ValueError(f"duplicate GHSA ID: {advisory_id}")
        seen_ids.add(advisory_id)
        schema = record.get("schema_version", "1.0.0")
        if not isinstance(schema, str) or not _SCHEMA.fullmatch(schema):
            stats["ghsa_unsupported_schema"] += 1
            continue
        database = record.get("database_specific")
        if not isinstance(database, dict):
            stats["ghsa_invalid_records"] += 1
            continue
        if database.get("github_reviewed") is not True:
            stats["ghsa_unreviewed"] += 1
            continue
        stats["ghsa_reviewed"] += 1
        try:
            modified = _date(record.get("modified"))
            if modified is None:
                raise _Invalid("invalid modified timestamp")
            if "withdrawn" in record:
                if _date(record["withdrawn"]) is None:
                    raise _Invalid("invalid withdrawn timestamp")
                stats["ghsa_withdrawn"] += 1
                continue
            aliases, unsupported_aliases = _aliases(record.get("aliases", []))
            stats["ghsa_unsupported_aliases"] += unsupported_aliases
            title = record.get("summary", "")
            if not isinstance(title, str) or len(title) > 4096:
                raise _Invalid("invalid summary")
            title = " ".join(title.split())[:256]
            affected_list = record.get("affected")
            if not isinstance(affected_list, list) or len(affected_list) > MAX_AFFECTED:
                raise _Invalid("invalid affected array")
        except ValueError:
            stats["ghsa_invalid_records"] += 1
            continue

        pending: dict[str, dict] = {}
        invalid_keys: set[str] = set()
        for affected in affected_list:
            stats["ghsa_affected_seen"] += 1
            try:
                if not isinstance(affected, dict):
                    raise _Invalid("invalid affected object")
                package = affected.get("package")
                if not isinstance(package, dict):
                    raise _Invalid("invalid package")
                ecosystem = package.get("ecosystem")
                if ecosystem not in {"npm", "PyPI"}:
                    stats["ghsa_unsupported_ecosystems"] += 1
                    continue
                name = _name(ecosystem, package.get("name"))
                ranges = _ranges(affected.get("ranges", []))
                versions = _versions(affected.get("versions", []))
                if not ranges and not versions:
                    raise _Invalid("missing OSV applicability")
                supported_types = (
                    {"SEMVER", "ECOSYSTEM"} if ecosystem == "npm" else {"ECOSYSTEM"}
                )
                stats["ghsa_unsupported_ranges"] += sum(
                    row["type"] not in supported_types for row in ranges
                )
            except ValueError:
                stats["ghsa_invalid_affected"] += 1
                continue

            key = ecosystem + ":" + name
            if key in invalid_keys:
                continue
            entry = pending.get(key)
            if entry is None:
                entry = {
                    "id": advisory_id, "aliases": aliases, "title": title,
                    "url": GHSA_PAGE + advisory_id, "updated_at": modified,
                    "source": "github-reviewed", "osv_ranges": [],
                    "osv_versions": [],
                }
                pending[key] = entry
            if len(entry["osv_ranges"]) + len(ranges) > MAX_RANGES:
                stats["ghsa_invalid_affected"] += 1
                pending.pop(key, None)
                invalid_keys.add(key)
                continue
            if len(entry["osv_versions"]) + len(versions) > MAX_VERSIONS:
                stats["ghsa_invalid_affected"] += 1
                pending.pop(key, None)
                invalid_keys.add(key)
                continue
            entry["osv_ranges"].extend(ranges)
            entry["osv_versions"].extend(versions)

        if pending:
            stats["ghsa_indexed_records"] += 1
        for key, entry in pending.items():
            entry["osv_ranges"] = sorted(
                entry["osv_ranges"], key=lambda row: json.dumps(row, sort_keys=True)
            )
            entry["osv_versions"] = sorted(set(entry["osv_versions"]))
            bucket = packages.setdefault(key, [])
            if existing_entries >= MAX_ENTRIES or len(bucket) >= MAX_PACKAGE_ENTRIES:
                raise ValueError("catalogue entry limit exceeded")
            bucket.append(entry)
            existing_entries += 1
            stats["ghsa_indexed_entries"] += 1
            ghsa_packages.add(key)

    stats["ghsa_indexed_packages"] = len(ghsa_packages)
    for key in packages:
        packages[key] = sorted(
            packages[key], key=lambda row: (
                row.get("id", "") if isinstance(row, dict) else "",
                json.dumps(row, sort_keys=True),
            )
        )
    result["schema_version"] = 2
    result["sources"] = {
        "cvelist": result["source"],
        "github-reviewed": {
            "repository": REPOSITORY,
            "commit": source_commit,
            "generated_at": generated_at,
        },
    }
    result["stats"].update(stats)
    result["stats"]["indexed_entries_total"] = existing_entries
    result["stats"]["indexed_packages_total"] = len(packages)
    result["packages"] = {key: packages[key] for key in sorted(packages)}
    return result
