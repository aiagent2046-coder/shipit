"""Bounded threat-intelligence presentation; no vulnerability or scoring decisions."""
from __future__ import annotations

from datetime import date, datetime
import re

REPOSITORY = "https://github.com/cisagov/kev-data"
LABEL = "CISA KEV threat context"
SCOPE = (
    "Known exploitation concerns this CVE in the wild; compromise of this project is not established. "
    "Priority is separate from severity and finding confidence. Absence from KEV is not evidence of safety."
)


def _text(value, maximum=1024):
    return (isinstance(value, str) and 0 < len(value) <= maximum and bool(value.strip())
            and not any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value))


def _hash(value, length=64):
    return isinstance(value, str) and re.fullmatch(f"[0-9a-f]{{{length}}}", value) is not None


def _count(value):
    return type(value) is int and 0 <= value <= 9_007_199_254_740_991


def _date(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value):
        return False
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return False
    return True


def threat_context_record(value: object) -> dict:
    """An invalid optional context never hides independent source/binary evidence."""
    invalid = {"schema": 1, "status": "unavailable", "reason": "invalid_threat_context", "runtime_verified": False}
    if (not isinstance(value, dict) or type(value.get("schema")) is not int or value["schema"] != 1
            or value.get("status") not in ("completed", "partial", "stale", "unavailable")
            or value.get("runtime_verified") is not False or not _date(value.get("as_of"))
            or not _hash(value.get("fingerprint"))
            or any(not _count(value.get(key)) for key in ("matched_cves", "eligible_findings", "unmapped_findings"))):
        return invalid
    source, matches, limitations = (value.get(key) for key in ("source", "matches", "limitations"))
    if (not isinstance(matches, list) or len(matches) > 256 or value["matched_cves"] != len(matches)
            or not isinstance(limitations, list) or len(limitations) > 32
            or any(not _text(item) for item in limitations)
            or (value["status"] == "unavailable" and matches)
            or (source is None and value["status"] != "unavailable")):
        return invalid
    clean_source = None
    if source is not None:
        if (not isinstance(source, dict) or source.get("repository") != REPOSITORY
                or not _hash(source.get("commit"), 40)
                or not all(_hash(source.get(key)) for key in ("upstream_sha256", "catalog_sha256"))
                or not all(_timestamp(source.get(key)) for key in ("source_committed_at", "date_released"))
                or not _text(source.get("catalog_version"), 80)):
            return invalid
        clean_source = {key: source[key] for key in (
            "repository", "commit", "source_committed_at", "upstream_sha256", "catalog_version",
            "date_released", "catalog_sha256",
        )}
    clean_matches, seen = [], set()
    for item in matches:
        if (not isinstance(item, dict) or not isinstance(item.get("cve_id"), str)
                or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", item["cve_id"]) or item["cve_id"] in seen
                or item.get("priority") != "expedited" or item.get("reason") != "known_exploitation"
                or not _date(item.get("date_added")) or not _date(item.get("cisa_due_date"))
                or not _text(item.get("required_action"), 4096)
                or item.get("known_ransomware_campaign_use") not in ("Known", "Unknown")
                or not isinstance(item.get("finding_refs"), list) or not 1 <= len(item["finding_refs"]) <= 64):
            return invalid
        refs = []
        for reference in item["finding_refs"]:
            if (not isinstance(reference, dict)
                    or reference.get("rule_id") not in ("dependency-cve-match", "dependency-known-vulnerability")
                    or not _count(reference.get("line")) or not _text(reference.get("file"), 1024)
                    or not _text(reference.get("package"), 256) or not _text(reference.get("ecosystem"), 80)
                    or not _text(reference.get("installed_version"), 256)):
                return invalid
            refs.append({key: reference[key] for key in (
                "rule_id", "file", "line", "package", "ecosystem", "installed_version",
            )})
        seen.add(item["cve_id"])
        clean = {key: item[key] for key in (
            "cve_id", "priority", "reason", "date_added", "required_action", "cisa_due_date",
            "known_ransomware_campaign_use",
        )}
        clean_matches.append({**clean, "finding_refs": refs})
    return {
        "schema": 1, "status": value["status"], "as_of": value["as_of"], "runtime_verified": False,
        "source": clean_source, "fingerprint": value["fingerprint"],
        **{key: value[key] for key in ("matched_cves", "eligible_findings", "unmapped_findings")},
        "matches": clean_matches, "limitations": limitations[:],
    }


def threat_context_rows(value: object) -> list[tuple[str, str]]:
    record = threat_context_record(value)
    if record.get("reason") == "invalid_threat_context":
        return [(LABEL, "Unavailable: invalid recorded threat context; no prioritization established.")]
    priority = ("prioritization unavailable" if record["status"] == "unavailable"
                else f"CVEs for expedited review: {record['matched_cves']}")
    rows = [(LABEL, f"{record['status']}; as of {record['as_of']}; {priority}. "
             f"Eligible findings: {record['eligible_findings']}; unmapped: {record['unmapped_findings']}. "
             "Project compromise is not established.")]
    rows.append(("Threat context scope", SCOPE))
    source = record["source"]
    if source:
        rows.extend([
            ("KEV source", f"{source['repository']}; commit: {source['commit']}; "
             f"committed: {source['source_committed_at']}; released: {source['date_released']}; "
             f"catalog version: {source['catalog_version']}."),
            ("KEV catalog SHA-256", source["catalog_sha256"]),
            ("KEV upstream SHA-256", source["upstream_sha256"]),
        ])
    for item in record["matches"]:
        targets = "; ".join(f"{ref['ecosystem']}:{ref['package']} {ref['installed_version']} "
                            f"({ref['file']}:{ref['line']})" for ref in item["finding_refs"])
        rows.append((f"KEV {item['cve_id']}", f"Expedited review; listed {item['date_added']}. "
                     f"Affected findings: {targets}. CISA action: {item['required_action']}"))
    rows.extend((f"Threat limitation {index}", item) for index, item in enumerate(record["limitations"], 1))
    return rows
