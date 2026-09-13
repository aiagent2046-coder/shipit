"""Bounded, read-only CVE Program context for CVE IDs already found by OSV.

The public CVE Services GET /cve/{id} returns published or rejected CVE 5.x
records without credentials. This client never discovers affected packages,
matches versions, follows advisory links, or changes vulnerability scoring.
Source: https://github.com/CVEProject/cve-services/blob/dev/api-docs/openapi.json
Format: https://github.com/CVEProject/cve-schema/blob/main/schema/CVE_Record_Format.json
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import math
import time

import httpx

from app.scan.cve_evidence import (
    CVE_API, CVE_PAGE, _ID, _CWE, _VERSION, _MAX_PUBLIC_RECORDS,
    _Unreadable, _date, _text, empty_cve_summary, normalize_cve_summary,
)

__all__ = ["CveClient", "empty_cve_summary", "normalize_cve_summary"]


def _english(value: object) -> str:
    if not isinstance(value, list) or not value:
        raise _Unreadable("invalid_record")
    chosen = None
    for entry in value:
        if not isinstance(entry, dict):
            raise _Unreadable("invalid_record")
        lang = _text(entry.get("lang"), 64).lower().replace("_", "-")
        text = _text(entry.get("value"), 4096)
        if chosen is None and (lang == "en" or lang.startswith("en-")) and text.strip():
            chosen = text
    if chosen is None:
        raise _Unreadable("invalid_record")
    return chosen


def _record(value: object, cve_id: str) -> dict:
    if not isinstance(value, dict) or value.get("dataType") != "CVE_RECORD":
        raise _Unreadable("invalid_record")
    version = value.get("dataVersion")
    if not isinstance(version, str) or len(version) > 32 or not _VERSION.fullmatch(version):
        raise _Unreadable("unsupported_schema")
    metadata = value.get("cveMetadata")
    containers = value.get("containers")
    if not isinstance(metadata, dict) or not isinstance(containers, dict):
        raise _Unreadable("invalid_record")
    state = metadata.get("state")
    cna = containers.get("cna")
    if metadata.get("cveId") != cve_id or state not in ("PUBLISHED", "REJECTED") or not isinstance(cna, dict):
        raise _Unreadable("invalid_record")
    provider = cna.get("providerMetadata")
    if not isinstance(provider, dict):
        raise _Unreadable("invalid_record")
    cwes: list[str] = []
    if state == "PUBLISHED":
        problem_types = cna.get("problemTypes", [])
        if not isinstance(problem_types, list):
            raise _Unreadable("invalid_record")
        for problem in problem_types:
            if not isinstance(problem, dict) or not isinstance(problem.get("descriptions"), list):
                raise _Unreadable("invalid_record")
            for item in problem["descriptions"]:
                if not isinstance(item, dict):
                    raise _Unreadable("invalid_record")
                cwe = item.get("cweId")
                if cwe is not None and not isinstance(cwe, str):
                    raise _Unreadable("invalid_record")
                if isinstance(cwe, str) and _CWE.fullmatch(cwe) and cwe not in cwes and len(cwes) < 20:
                    cwes.append(cwe)
    return {
        "id": cve_id, "state": state,
        "title": _text(cna.get("title", ""), 256) if state == "PUBLISHED" else "",
        "description": _english(cna.get("descriptions" if state == "PUBLISHED" else "rejectedReasons")),
        "published_at": _date(metadata.get("datePublished")),
        "updated_at": _date(metadata.get("dateUpdated")),
        "cwes": cwes, "url": CVE_PAGE + cve_id, "record_url": CVE_API + cve_id,
        "data_version": version, "provider": _text(provider.get("shortName", ""), 32),
    }




@dataclass
class CveClient:
    transport: httpx.BaseTransport | None = None
    timeout: float = 3.0
    max_records: int = 20
    time_budget: float = 10.0
    max_response_bytes: int = 1_000_000

    def __post_init__(self) -> None:
        if (isinstance(self.timeout, bool) or not isinstance(self.timeout, (int, float))
                or not math.isfinite(self.timeout) or self.timeout <= 0
                or isinstance(self.time_budget, bool) or not isinstance(self.time_budget, (int, float))
                or not math.isfinite(self.time_budget) or self.time_budget < 0
                or type(self.max_records) is not int or not 0 <= self.max_records <= _MAX_PUBLIC_RECORDS
                or type(self.max_response_bytes) is not int or self.max_response_bytes <= 0):
            raise ValueError("invalid CVE client bounds")

    def lookup(self, ids: list[str]) -> dict:
        unique = list(dict.fromkeys(item for item in ids if isinstance(item, str) and _ID.fullmatch(item)))
        result = empty_cve_summary()
        result["requested"] = len(unique)
        if not unique:
            return result
        deadline = time.monotonic() + self.time_budget
        with httpx.Client(transport=self.transport, follow_redirects=False, trust_env=False,
                          headers={"Accept": "application/json", "Accept-Encoding": "identity",
                                   "User-Agent": "Drydock-CVE/1.0"}) as client:
            for cve_id in unique[:self.max_records]:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if result["checked_at"] is None:
                    result["checked_at"] = datetime.now(timezone.utc).isoformat()
                result["attempted"] += 1
                reason = None
                try:
                    with client.stream("GET", CVE_API + cve_id, timeout=min(self.timeout, remaining)) as response:
                        if response.status_code == 429:
                            raise _Unreadable("rate_limited")
                        if response.status_code == 404:
                            raise _Unreadable("not_found")
                        if response.status_code != 200:
                            raise _Unreadable("http_error")
                        # Request identity and reject unsolicited compression before
                        # decoding, so the byte bound also covers decompression bombs.
                        if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                            raise _Unreadable("invalid_record")
                        content = bytearray()
                        # Do not aggregate small network chunks: otherwise a
                        # slow stream could hide deadline checks in the buffer.
                        for chunk in response.iter_bytes():
                            if time.monotonic() >= deadline:
                                raise _Unreadable("time_budget")
                            if len(content) + len(chunk) > self.max_response_bytes:
                                raise _Unreadable("response_too_large")
                            content.extend(chunk)
                        if time.monotonic() >= deadline:
                            raise _Unreadable("time_budget")
                        record = _record(json.loads(content), cve_id)
                        if time.monotonic() >= deadline:
                            raise _Unreadable("time_budget")
                    result["records"].append(record)
                except _Unreadable as exc:
                    reason = str(exc)
                except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
                    reason = "invalid_record"
                except (httpx.TimeoutException, TimeoutError):
                    reason = "timeout"
                except (httpx.HTTPError, OSError):
                    reason = "network_error"
                if reason is not None:
                    result["errors"].append({"id": cve_id, "reason": reason})
                if reason in ("rate_limited", "time_budget"):
                    break
        result["resolved"] = len(result["records"])
        result["unavailable"] = result["attempted"] - result["resolved"]
        result["not_requested"] = result["requested"] - result["attempted"]
        result["rejected"] = sum(record["state"] == "REJECTED" for record in result["records"])
        result["status"] = ("complete" if result["resolved"] == result["requested"]
                            else "partial" if result["resolved"] else "unavailable")
        return result
