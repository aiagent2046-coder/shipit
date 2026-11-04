"""Compile the CISA Known Exploited Vulnerabilities feed into the offline snapshot.

KEV is an annotation source, not an advisory source: it says that CISA has
evidence of exploitation in the wild for a CVE, nothing about which package
versions are affected. The index is therefore keyed by CVE ID and consulted
only after a package/version match already exists. Absence from KEV never
means "not exploited"; presence never means this application was exploited.

The feed is a single moving file without version history, so the snapshot
records its catalogVersion, release time and SHA-256 instead of a commit.
Source format: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""
from __future__ import annotations

from copy import deepcopy
from datetime import date, datetime
import re

KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SOURCE_NAME = "cisa-kev"
MAX_RECORDS = 100_000
_CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z")
_CATALOG_VERSION = re.compile(r"[0-9]{4}\.[0-9]{2}\.[0-9]{2}\Z")
_DAY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
_RELEASED = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z\Z")
_RANSOMWARE = frozenset({"Known", "Unknown"})


class _Invalid(ValueError):
    pass


def _day(value: object) -> str:
    if not isinstance(value, str) or not _DAY.fullmatch(value):
        raise _Invalid("invalid KEV date")
    try:
        date.fromisoformat(value)
    except ValueError as exc:
        raise _Invalid("invalid KEV date") from exc
    return value


def _released(value: object) -> str:
    if not isinstance(value, str) or not _RELEASED.fullmatch(value):
        raise _Invalid("invalid KEV dateReleased")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _Invalid("invalid KEV dateReleased") from exc
    return value


def _record(value: object) -> tuple[str, dict]:
    if not isinstance(value, dict):
        raise _Invalid("KEV record must be an object")
    cve_id = value.get("cveID")
    if not isinstance(cve_id, str) or not _CVE_ID.fullmatch(cve_id):
        raise _Invalid("invalid KEV cveID")
    ransomware = value.get("knownRansomwareCampaignUse")
    if ransomware not in _RANSOMWARE:
        raise _Invalid("invalid KEV knownRansomwareCampaignUse")
    # Only the fields the matcher reports are projected; vendor prose and
    # required-action text stay upstream. Unknown fields are tolerated.
    return cve_id, {"date_added": _day(value.get("dateAdded")), "due_date": _day(value.get("dueDate")),
                    "ransomware": ransomware}


def merge_kev(catalog: dict, feed: object, *, feed_sha256: str) -> dict:
    """Return a deterministic three-source catalog without mutating the input.

    Any malformed feed aborts the build with ValueError: a partial exploitation
    index would silently downgrade known-exploited matches to ordinary ones.
    """
    if not isinstance(feed_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", feed_sha256):
        raise ValueError("feed_sha256 must be the lowercase SHA-256 of the feed bytes")
    if (not isinstance(catalog, dict) or catalog.get("schema_version") != 2
            or not isinstance(catalog.get("sources"), dict)
            or set(catalog["sources"]) != {"cvelist", "github-reviewed"}
            or not isinstance(catalog.get("packages"), dict)
            or not isinstance(catalog.get("stats"), dict)):
        raise ValueError("base catalog must be the two-source CVE/GHSA snapshot")
    if not isinstance(feed, dict) or not isinstance(feed.get("vulnerabilities"), list):
        raise ValueError("KEV feed must be an object with a vulnerabilities array")
    version = feed.get("catalogVersion")
    if not isinstance(version, str) or not _CATALOG_VERSION.fullmatch(version):
        raise ValueError("invalid KEV catalogVersion")
    released = _released(feed.get("dateReleased"))
    rows = feed["vulnerabilities"]
    if type(feed.get("count")) is not int or feed["count"] != len(rows):
        raise ValueError("KEV count does not match the vulnerabilities array")
    if len(rows) > MAX_RECORDS:
        raise ValueError("KEV record limit exceeded")

    index: dict[str, dict] = {}
    stats = {"kev_seen": 0, "kev_indexed": 0, "kev_ransomware_known": 0, "kev_in_catalog": 0}
    for row in rows:
        stats["kev_seen"] += 1
        cve_id, record = _record(row)
        if cve_id in index:
            raise ValueError(f"duplicate KEV cveID: {cve_id}")
        index[cve_id] = record
        stats["kev_indexed"] += 1
        stats["kev_ransomware_known"] += record["ransomware"] == "Known"

    result = deepcopy(catalog)
    referenced: set[str] = set()
    for entries in result["packages"].values():
        if not isinstance(entries, list):
            raise ValueError("base CVE package index is invalid")
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("base CVE package index is invalid")
            aliases = entry.get("aliases", [])
            for item in (entry.get("id"), *(aliases if isinstance(aliases, list) else [])):
                if isinstance(item, str) and item in index:
                    referenced.add(item)
    stats["kev_in_catalog"] = len(referenced)

    result["schema_version"] = 3
    result["sources"][SOURCE_NAME] = {"feed": KEV_FEED, "catalog_version": version,
                                      "generated_at": released, "sha256": feed_sha256}
    result["exploitation"] = {SOURCE_NAME: {cve_id: index[cve_id] for cve_id in sorted(index)}}
    result["stats"].update(stats)
    return result
