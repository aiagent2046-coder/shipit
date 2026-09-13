"""Validated CVE lookup evidence shared by online reports and offline exports.

Only standard-library imports: browser/WASM bundles must not load HTTP clients.
"""
from __future__ import annotations

from datetime import datetime
import re

CVE_API = "https://cveawg.mitre.org/api/cve/"
CVE_PAGE = "https://www.cve.org/CVERecord?id="
_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z")
_CWE = re.compile(r"CWE-[1-9][0-9]{0,4}\Z")
# Production records use both short ('5.1', '5.2') and release ('5.2.0') forms.
# Future minor versions need an explicit compatibility review.
_VERSION = re.compile(r"5\.[012](?:\.(?:0|[1-9][0-9]*))?\Z")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
                   r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})?\Z")
_STATUSES = {"complete", "partial", "unavailable", "not_applicable", "disabled", "not_run"}
_REASONS = {"invalid_record", "unsupported_schema", "http_error", "not_found",
            "rate_limited", "timeout", "network_error", "response_too_large", "time_budget"}
_COUNTS = ("requested", "attempted", "resolved", "unavailable", "not_requested", "rejected")
_MAX_PUBLIC_RECORDS = 1000


class _Unreadable(ValueError):
    pass


def _text(value: object, limit: int) -> str:
    if not isinstance(value, str):
        raise _Unreadable("invalid_record")
    return value[:limit]


def _date(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 64 or not _DATE.fullmatch(value):
        raise _Unreadable("invalid_record")
    try:
        datetime.fromisoformat(value)
    except ValueError as exc:
        raise _Unreadable("invalid_record") from exc
    return value


def empty_cve_summary(status: str = "not_applicable") -> dict:
    """A stable, explicit envelope for disabled or inapplicable enrichment."""
    if status not in _STATUSES:
        raise ValueError("invalid CVE summary status")
    return {"version": 1, "source": "CVE Program", "status": status, "checked_at": None,
            **dict.fromkeys(_COUNTS, 0), "records": [], "errors": []}


def normalize_cve_summary(value: object) -> dict | None:
    """Validate persisted/public context, including accounting and fixed URLs.

    This validates only the fields this feature consumes, not the entire CVE
    schema. Malformed or contradictory coverage must not look complete.
    """
    if not isinstance(value, dict) or type(value.get("version")) is not int or value["version"] != 1:
        return None
    status = value.get("status")
    if value.get("source") != "CVE Program" or not isinstance(status, str) or status not in _STATUSES:
        return None
    if any(type(value.get(key)) is not int or value[key] < 0 for key in _COUNTS):
        return None
    records, errors = value.get("records"), value.get("errors")
    if (not isinstance(records, list) or not isinstance(errors, list)
            or len(records) + len(errors) > _MAX_PUBLIC_RECORDS):
        return None
    result = empty_cve_summary(status)
    result.update({key: value[key] for key in _COUNTS})
    seen: set[str] = set()
    try:
        result["checked_at"] = _date(value.get("checked_at"))
        for record in records:
            if not isinstance(record, dict):
                return None
            cve_id = record.get("id")
            state, cwes = record.get("state"), record.get("cwes")
            if (not isinstance(cve_id, str) or not _ID.fullmatch(cve_id) or cve_id in seen
                    or state not in ("PUBLISHED", "REJECTED")
                    or record.get("url") != CVE_PAGE + cve_id or record.get("record_url") != CVE_API + cve_id
                    or not isinstance(cwes, list) or len(cwes) > 20
                    or any(not isinstance(cwe, str) or not _CWE.fullmatch(cwe) for cwe in cwes)
                    or len(set(cwes)) != len(cwes) or (state == "REJECTED" and cwes)):
                return None
            version = record.get("data_version")
            if not isinstance(version, str) or len(version) > 32 or not _VERSION.fullmatch(version):
                return None
            normalized = {"id": cve_id, "state": state,
                          **{key: _text(record.get(key), limit) for key, limit in
                             (("title", 256), ("description", 4096), ("provider", 32))},
                          "published_at": _date(record.get("published_at")),
                          "updated_at": _date(record.get("updated_at")), "cwes": list(cwes),
                          "url": CVE_PAGE + cve_id, "record_url": CVE_API + cve_id, "data_version": version}
            if not normalized["description"].strip() or (state == "REJECTED" and normalized["title"]):
                return None
            result["records"].append(normalized)
            seen.add(cve_id)
        for error in errors:
            if not isinstance(error, dict):
                return None
            cve_id, reason = error.get("id"), error.get("reason")
            if (not isinstance(cve_id, str) or not _ID.fullmatch(cve_id) or cve_id in seen
                    or not isinstance(reason, str) or reason not in _REASONS):
                return None
            seen.add(cve_id)
            result["errors"].append({"id": cve_id, "reason": reason})
    except _Unreadable:
        return None
    if (result["resolved"] != len(records) or result["unavailable"] != len(errors)
            or result["attempted"] != result["resolved"] + result["unavailable"]
            or result["requested"] != result["attempted"] + result["not_requested"]
            or result["rejected"] != sum(record["state"] == "REJECTED" for record in records)
            or bool(result["attempted"]) != bool(result["checked_at"])):
        return None
    expected = ("not_applicable" if not result["requested"] else
                "complete" if result["resolved"] == result["requested"] else
                "partial" if result["resolved"] else "unavailable")
    if status in ("disabled", "not_run"):
        if result["requested"]:
            return None
    elif status != expected:
        return None
    return result
