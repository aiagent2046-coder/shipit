import copy
import hashlib
import json
import socket

import pytest

from scripts.diagnose_model_trial import diagnose_report, diagnose_row, main


def row(answer, finish="stop", **extra):
    return {"answer": answer, "finish_reason": finish, **extra}


def test_completed_markdown_is_extracted_without_promoting_original_result():
    original = row('Observations\n```json\n[{"title":"Review me"}]\n```',
                   error="incomplete_or_invalid_answer", strict_json_array=False)
    before = copy.deepcopy(original)
    result = diagnose_row(original)
    assert result["extracted_json"] == [{"title": "Review me"}]
    assert result["original_error"] == "incomplete_or_invalid_answer"
    assert result["original_strict_json_array"] is False
    assert result["answer_status"] == "invalid_json"
    assert result["extracted_validation"] == "syntax_and_array_only"
    assert original == before


@pytest.mark.parametrize("answer,finish,issues", [
    ('[{"title":"unfinished', "length", {"output_limit", "invalid_json"}),
    (None, "length", {"output_limit", "empty_answer"}),
    ("[]", "length", {"output_limit"}),
    ("", "stop", {"empty_answer"}),
    ("{}", "stop", {"wrong_top_level"}),
    ([], "stop", {"non_text_answer"}),
    (None, None, {"empty_answer", "missing_finish_reason"}),
    ("[]", "content_filter", {"non_stop_finish"}),
])
def test_completion_and_format_are_independent(answer, finish, issues):
    result = diagnose_row(row(answer, finish))
    assert set(result["issues"]) == issues
    assert result["extracted_json"] is None


@pytest.mark.parametrize("answer", [
    '```json\n[]\n```\n```json\n[]\n```',
    '```json\n[{"title":"cut off',
    '```json\n{}\n```',
    'Text [{"title":"not fenced"}]',
    '```python\n[]\n```',
    '```json\n[]\n````',
    '```json\n[]\n```\n```json\n[',
    '```json\n[NaN]\n```',
    '```json\n[1e999]\n```',
    '```json\n[{"title":"one","title":"two"}]\n```',
])
def test_no_repair_or_ambiguous_extraction(answer):
    assert diagnose_row(row(answer))["extracted_json"] is None


@pytest.mark.parametrize("finish,error", [("length", None), (None, None), ("stop", "ReadTimeout")])
def test_never_extract_incomplete_or_failed_request(finish, error):
    assert diagnose_row(row('```json\n[]\n```', finish, error=error))["extracted_json"] is None


def test_empty_array_is_a_valid_extraction_and_usage_is_not_reinterpreted():
    result = diagnose_row(row('Text\r\n```JSON\r\n[]\r\n```', usage={
        "completion_tokens": 152, "completion_tokens_details": {"reasoning_tokens": 172},
        "balance": "must not be copied",
    }))
    assert result["extracted_json"] == []
    assert result["extraction_status"] == "extracted_for_review"
    assert result["usage_anomalies"] == ["reasoning_exceeds_completion"]
    assert result["completion_tokens"] == 152
    assert result["reasoning_tokens"] == 172
    assert "balance" not in json.dumps(result)


def test_cli_offline_preserves_source_and_refuses_overwrite(tmp_path, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("Network must not be used")
    monkeypatch.setattr(socket, "socket", no_network)
    source = tmp_path / "trial.json"
    output = tmp_path / "diagnostics.json"
    report = {"state": "completed_with_errors_needs_review", "results": [row(None, "length")]}
    source.write_text(json.dumps(report))
    before = source.read_bytes()
    assert main([str(source), "--output", str(output)]) == 0
    result = json.loads(output.read_text())
    assert result["source_sha256"] == hashlib.sha256(before).hexdigest()
    assert result["source_state"] == report["state"]
    assert result["issue_counts"] == {"output_limit": 1, "empty_answer": 1}
    saved = output.read_bytes()
    for target in (source, output):
        with pytest.raises(SystemExit):
            main([str(source), "--output", str(target)])
    assert output.read_bytes() == saved
    assert source.read_bytes() == before


@pytest.mark.parametrize("report", [[], {}, {"results": [None]}])
def test_invalid_report_is_rejected(report):
    with pytest.raises(ValueError):
        diagnose_report(report)
