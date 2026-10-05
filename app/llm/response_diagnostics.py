"""Classify answer envelopes without retaining answer text or changing admission."""

from __future__ import annotations

import json
import re


_JSON_FENCE = re.compile(r"\A```(?:json)?[ \t]*\r?\n(?P<body>.*?)\r?\n```\Z", re.DOTALL)


def _reject_constant(value: str) -> None:
    raise ValueError("non-JSON numeric constant")


def _json_value(text: str) -> tuple[bool, object]:
    try:
        return True, json.loads(text, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        return False, None


def response_diagnostics(raw: str) -> dict:
    """Return bounded scalar metadata about a completion, never its contents.

    Direct JSON takes precedence: an object containing an array is other_json,
    not a direct array. Only a whole fenced document counts as fenced_json_array.
    Embedded-array recognition mirrors the legacy first-[ / last-] extraction,
    while requiring the extracted value to be JSON. It does not modify parsing
    or determine whether a finding is admissible.

    Byte length describes the decoded answer re-encoded as UTF-8, not HTTP bytes.
    Unpaired Unicode surrogates use replacement encoding rather than breaking
    telemetry. direct_array_items applies only to an unfenced, whole JSON array.
    """
    result = {
        "response_chars": len(raw),
        "response_utf8_bytes": len(raw.encode("utf-8", errors="replace")),
        "response_envelope": "non_json",
        "direct_array_items": None,
    }
    text = raw.strip()
    valid, value = _json_value(text)
    if valid:
        result["response_envelope"] = "json_array" if isinstance(value, list) else "other_json"
        if isinstance(value, list):
            result["direct_array_items"] = len(value)
        return result

    fenced = _JSON_FENCE.fullmatch(text)
    if fenced is not None:
        valid, value = _json_value(fenced.group("body"))
        if valid and isinstance(value, list):
            result["response_envelope"] = "fenced_json_array"
            return result

    start, end = text.find("["), text.rfind("]")
    if start != -1 and end >= start:
        valid, value = _json_value(text[start:end + 1])
        if valid and isinstance(value, list):
            result["response_envelope"] = "embedded_array"
    return result
