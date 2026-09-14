"""Compile an explicit package index from a pinned cvelistV5 checkout.

This is a bounded projection of consumed CVE 5.0/5.1/5.2 fields, not a full
JSON Schema validator. It never reads files, URLs, advisory code, or ADP
affected claims. Registry declarations establish identity; product/vendor
similarity does not. Unsupported version semantics survive for the matcher.

Source format: https://github.com/CVEProject/cve-schema/blob/main/schema/CVE_Record_Format.json
"""
from __future__ import annotations

from collections.abc import Iterable
import json
import re
from urllib.parse import unquote, urlsplit

from app.scan.cve_evidence import CVE_PAGE, _ID, _VERSION, _date

REPOSITORY = "https://github.com/CVEProject/cvelistV5"
MAX_RECORDS = 1_000_000
MAX_AFFECTED = 1024
MAX_VERSIONS = 256
MAX_CHANGES = 256
MAX_ENTRIES = 500_000
MAX_PACKAGE_ENTRIES = 4096
_STATUSES = frozenset({"affected", "unaffected", "unknown"})
_NPM = re.compile(r"(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+\Z")
_PYPI = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_VERSION_FIELDS = frozenset({"version", "status", "versionType", "lessThan", "lessThanOrEqual", "changes"})


class _Invalid(ValueError):
    pass


def _string(value: object, limit: int = 2048) -> str:
    if (not isinstance(value, str) or not value or len(value) > limit
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise _Invalid("invalid string")
    return value


def _status(value: object) -> str:
    if not isinstance(value, str) or value not in _STATUSES:
        raise _Invalid("invalid status")
    return value


def _name(ecosystem: str, value: object) -> str:
    name = _string(value, 214 if ecosystem == "npm" else 512)
    pattern = _NPM if ecosystem == "npm" else _PYPI
    if not pattern.fullmatch(name) or name in {".", ".."}:
        raise _Invalid("invalid package name")
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "PyPI" else name


def _registry(value: object) -> str | None:
    raw = _string(value)
    try:
        url = urlsplit(raw)
    except ValueError:
        return None
    # Exact authorities only: credentials, ports, suffix hosts, arbitrary
    # paths and query parameters cannot masquerade as a public registry.
    if url.scheme != "https" or url.query or url.fragment:
        return None
    host, path = url.netloc.lower(), url.path.rstrip("/")
    if host in {"registry.npmjs.org", "www.npmjs.com", "npmjs.com"} and path == "":
        return "npm"
    if host in {"pypi.org", "www.pypi.org", "pypi.python.org"} and path in {"", "/simple", "/pypi"}:
        return "PyPI"
    return None


def _purl(value: object) -> tuple[str, str] | None:
    raw = _string(value)
    if "?" in raw or "#" in raw:
        return None
    if raw.startswith("pkg:npm/"):
        ecosystem, raw_name = "npm", raw[8:]
    elif raw.startswith("pkg:pypi/"):
        ecosystem, raw_name = "PyPI", raw[9:]
    else:
        return None
    # CVE packageURL MUST NOT contain a version. Decode exactly once; reject
    # malformed escapes and residual percent signs rather than reinterpret.
    if re.search(r"%(?![0-9A-Fa-f]{2})", raw_name):
        return None
    try:
        name = unquote(raw_name, errors="strict")
    except UnicodeDecodeError:
        return None
    if "@" in name[1:] or (ecosystem == "PyPI" and "@" in name):
        return None
    return ecosystem, _name(ecosystem, name)


def _identity(affected: dict) -> tuple[str, str] | None:
    purl = _purl(affected["packageURL"]) if "packageURL" in affected else None
    if "packageURL" in affected and purl is None:
        return None
    collection = _registry(affected["collectionURL"]) if "collectionURL" in affected else None
    if "collectionURL" in affected and collection is None:
        return None
    if collection:
        value = affected.get("packageName", affected.get("product"))
        declared = (collection, _name(collection, value))
        return declared if purl is None or purl == declared else None
    if purl and "packageName" in affected and _name(purl[0], affected["packageName"]) != purl[1]:
        return None
    return purl


def _versions(value: object) -> list[dict]:
    if not isinstance(value, list) or len(value) > MAX_VERSIONS:
        raise _Invalid("invalid versions")
    result = []
    for item in value:
        if not isinstance(item, dict) or not item.keys() <= _VERSION_FIELDS:
            raise _Invalid("invalid version entry")
        entry = {"version": _string(item.get("version"), 1024), "status": _status(item.get("status"))}
        for key in ("versionType", "lessThan", "lessThanOrEqual"):
            if key in item:
                entry[key] = _string(item[key], 128 if key == "versionType" else 1024)
        if "changes" in item:
            changes = item["changes"]
            if not isinstance(changes, list) or len(changes) > MAX_CHANGES:
                raise _Invalid("invalid changes")
            entry["changes"] = []
            for change in changes:
                if not isinstance(change, dict) or set(change) != {"at", "status"}:
                    raise _Invalid("invalid change")
                entry["changes"].append({"at": _string(change["at"], 1024), "status": _status(change["status"])})
        # Do not repair conflicting bounds, missing versionType, unknown
        # version schemes, or prose versions into supposedly precise ranges.
        result.append(entry)
    return result


def build_catalog(records: Iterable[dict], *, source_commit: str, generated_at: str) -> dict:
    """Return a deterministic, JSON-compatible index with explicit gap counts.

    Duplicate IDs and global capacity overflow abort the build with ValueError;
    a caller must not publish a partial or stale catalogue after such failure.
    Bad individual records/products are omitted and counted, never guessed.
    The caller supplies a verified checkout commit; this pure compiler does not
    authenticate a source or claim that arbitrary input came from that commit.
    """
    if not isinstance(source_commit, str) or not _COMMIT.fullmatch(source_commit):
        raise ValueError("source_commit must be a full lowercase Git commit SHA")
    if generated_at is None or _date(generated_at) is None:
        raise ValueError("generated_at must be an ISO timestamp")
    stats = dict.fromkeys(("seen", "published", "rejected", "unsupported_schema", "invalid_records",
                          "affected_seen", "unsupported_packages", "invalid_affected", "unsupported_applicability",
                          "indexed_records", "indexed_entries", "indexed_packages"), 0)
    packages: dict[str, list[dict]] = {}
    seen_ids: set[str] = set()
    for record in records:
        stats["seen"] += 1
        if stats["seen"] > MAX_RECORDS:
            raise ValueError("CVE record limit exceeded")
        metadata = record.get("cveMetadata") if isinstance(record, dict) else None
        cve_id = metadata.get("cveId") if isinstance(metadata, dict) else None
        if not isinstance(cve_id, str) or not _ID.fullmatch(cve_id):
            stats["invalid_records"] += 1
            continue
        if cve_id in seen_ids:
            raise ValueError(f"duplicate CVE ID: {cve_id}")
        seen_ids.add(cve_id)
        if record.get("dataType") != "CVE_RECORD":
            stats["invalid_records"] += 1
            continue
        version = record.get("dataVersion")
        if not isinstance(version, str) or len(version) > 32 or not _VERSION.fullmatch(version):
            stats["unsupported_schema"] += 1
            continue
        state = metadata.get("state")
        if state == "REJECTED":
            stats["rejected"] += 1
            continue
        if state != "PUBLISHED":
            stats["invalid_records"] += 1
            continue
        stats["published"] += 1
        try:
            containers = record.get("containers")
            cna = containers.get("cna") if isinstance(containers, dict) else None
            if not isinstance(cna, dict):
                raise _Invalid("invalid CNA")
            title = cna.get("title", "")
            if not isinstance(title, str) or len(title) > 4096:
                raise _Invalid("invalid title")
            # Titles are display context, not identity or version evidence.
            title = " ".join(title.split())[:256]
            updated_at = _date(metadata.get("dateUpdated"))
            affected_list = cna.get("affected")
            if not isinstance(affected_list, list) or len(affected_list) > MAX_AFFECTED:
                raise _Invalid("invalid affected array")
        except ValueError:
            stats["invalid_records"] += 1
            continue
        indexed = False
        for affected in affected_list:
            stats["affected_seen"] += 1
            try:
                if not isinstance(affected, dict):
                    raise _Invalid("invalid affected object")
                identity = _identity(affected)
                if identity is None:
                    stats["unsupported_packages"] += 1
                    continue
                if "versions" not in affected and "defaultStatus" not in affected:
                    raise _Invalid("missing version status")
                entry = {"id": cve_id, "title": title, "url": CVE_PAGE + cve_id,
                         "updated_at": updated_at, "default_status": _status(affected.get("defaultStatus", "unknown")),
                         "versions": _versions(affected.get("versions", []))}
                restrictions = ("platforms", "modules", "programFiles", "programRoutines")
                for field in restrictions:
                    if field in affected and (not isinstance(affected[field], list) or len(affected[field]) > 256):
                        raise _Invalid("invalid applicability")
                if any(affected.get(field) for field in restrictions) or cna.get("cpeApplicability"):
                    entry["unsupported_applicability"] = True
                    stats["unsupported_applicability"] += 1
            except ValueError:
                stats["invalid_affected"] += 1
                continue
            key = ":".join(identity)
            bucket = packages.setdefault(key, [])
            if stats["indexed_entries"] >= MAX_ENTRIES or len(bucket) >= MAX_PACKAGE_ENTRIES:
                raise ValueError("CVE catalogue entry limit exceeded")
            bucket.append(entry)
            stats["indexed_entries"] += 1
            indexed = True
        stats["indexed_records"] += int(indexed)
    stats["indexed_packages"] = len(packages)
    return {"schema_version": 1,
            "source": {"repository": REPOSITORY, "commit": source_commit, "generated_at": generated_at},
            "stats": stats,
            "packages": {key: sorted(packages[key], key=lambda row: (row["id"], json.dumps(row, sort_keys=True)))
                         for key in sorted(packages)}}
