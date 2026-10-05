"""Envelope metadata distinguishes actual empty arrays from parser salvage."""

import pytest

from app.llm.response_diagnostics import response_diagnostics


@pytest.mark.parametrize(("raw", "envelope", "items"), [
    ("[]", "json_array", 0),
    (" \r\n [] \t", "json_array", 0),
    ('[{"premises": []}]', "json_array", 1),
    ("```json\n[]\n```", "fenced_json_array", None),
    (" \n```\r\n[]\r\n```\t", "fenced_json_array", None),
    ('{"premises": []}', "other_json", None),
    ("null", "other_json", None),
    ('"[]"', "other_json", None),
    ("I cannot analyze this. []", "embedded_array", None),
    ("Explanation\n```json\n[]\n```", "embedded_array", None),
    ("```json\n[]\n```\nExplanation", "embedded_array", None),
    ("```python\n[]\n```", "embedded_array", None),
    ('[{"title": }]', "non_json", None),
    ("[] []", "non_json", None),
    ("[NaN]", "non_json", None),
    ("NaN", "non_json", None),
    ("", "non_json", None),
    ("Nothing found", "non_json", None),
])
def test_response_envelope_preserves_format_distinctions(raw, envelope, items):
    diagnostics = response_diagnostics(raw)
    assert diagnostics["response_envelope"] == envelope
    assert diagnostics["direct_array_items"] == items


def test_only_lengths_and_classification_survive_private_unicode_text():
    raw = '[{"title": "Секрет 🔐", "token": "synthetic-private-value"}]'
    assert response_diagnostics(raw) == {
        "response_chars": len(raw),
        "response_utf8_bytes": len(raw.encode("utf-8")),
        "response_envelope": "json_array",
        "direct_array_items": 1,
    }
    assert len(raw.encode("utf-8")) > len(raw)


def test_json_parser_recursion_limit_does_not_break_telemetry(monkeypatch):
    def recursion_limit(*args, **kwargs):
        raise RecursionError("JSON nesting exceeds this runtime's limit")

    monkeypatch.setattr("app.llm.response_diagnostics.json.loads", recursion_limit)
    diagnostics = response_diagnostics("[[[]]]")
    assert diagnostics["response_envelope"] == "non_json"
    assert diagnostics["direct_array_items"] is None


def test_unpaired_surrogate_does_not_break_telemetry():
    diagnostics = response_diagnostics('["\ud800"]')
    assert diagnostics["response_envelope"] == "json_array"
    assert diagnostics["response_chars"] == 5
    assert diagnostics["response_utf8_bytes"] == 5
