#!/usr/bin/env python3
"""Diagnose saved model trials offline. Standard library only; no provider calls."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re


def _reject_constant(value):
    raise ValueError("Non-JSON numeric constant")


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("JSON number exceeds finite float range")
    return number


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key")
        result[key] = value
    return result


def parse_answer(raw):
    """Check syntax and top-level array only, not finding truth or schema."""
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return "empty", None, None
    if not isinstance(raw, str):
        return "non_text", None, None
    try:
        parsed = json.loads(raw, parse_constant=_reject_constant, parse_float=_finite_float,
                            object_pairs_hook=_unique_object)
    except json.JSONDecodeError as exc:
        return "invalid_json", None, {"message": exc.msg, "position": exc.pos,
                                      "line": exc.lineno, "column": exc.colno}
    except (ValueError, RecursionError):
        return "invalid_json", None, {"message": "Nonstandard, out-of-range, duplicate-key or deeply nested JSON"}
    return ("json_array" if isinstance(parsed, list) else "wrong_top_level"), parsed, None


def extract_fenced_array(raw):
    """Accept exactly one closed, backtick JSON/plain block; never repair JSON."""
    fences = list(re.finditer(r"(?m)^[ \t]*(?:`{3,}|~{3,})[^\r\n]*\r?$", raw))
    if len(fences) != 2:
        return None
    opening, closing = fences
    marker = re.fullmatch(r"[ \t]*(`{3,})(?:json)?[ \t]*\r?", opening.group(), re.IGNORECASE)
    if not marker or closing.group().strip() != marker.group(1):
        return None
    status, parsed, _ = parse_answer(raw[opening.end():closing.start()])
    return parsed if status == "json_array" else None


def diagnose_row(row):
    raw = row.get("answer")
    finish = row.get("finish_reason")
    error = row.get("error")
    status, _, parse_error = parse_answer(raw)
    usage = row.get("usage") if isinstance(row.get("usage"), dict) else {}
    details = usage.get("completion_tokens_details")
    details = details if isinstance(details, dict) else {}
    completion = usage.get("completion_tokens")
    reasoning = details.get("reasoning_tokens")
    issues = []
    if finish == "length":
        issues.append("output_limit")
    elif finish != "stop":
        issues.append("missing_finish_reason" if finish is None else "non_stop_finish")
    if error and error != "incomplete_or_invalid_answer":
        issues.append("request_error")
    if status != "json_array":
        issues.append({"empty": "empty_answer", "non_text": "non_text_answer",
                       "invalid_json": "invalid_json", "wrong_top_level": "wrong_top_level"}[status])
    extracted = None
    if finish == "stop" and error in (None, "incomplete_or_invalid_answer") and status == "invalid_json":
        extracted = extract_fenced_array(raw)
    if extracted is not None:
        issues.append("markdown_json_available")
    anomalies = []
    if (type(completion) is int and type(reasoning) is int and reasoning > completion):
        anomalies.append("reasoning_exceeds_completion")
    return {
        "case": row.get("case"), "repeat": row.get("repeat"),
        "requested_model": row.get("requested_model"), "served_model": row.get("served_model"),
        "original_error": error, "original_strict_json_array": row.get("strict_json_array"),
        "finish_reason": finish, "answer_status": status,
        "answer_chars": len(raw) if isinstance(raw, str) else None,
        "answer_type": type(raw).__name__, "parse_error": parse_error, "issues": issues,
        "completion_tokens": completion, "reasoning_tokens": reasoning,
        "prompt_tokens": usage.get("prompt_tokens"), "usage_anomalies": anomalies,
        "cost_rub": row.get("cost_rub"), "seconds": row.get("seconds"),
        "extraction_status": "extracted_for_review" if extracted is not None else "not_extracted",
        "extracted_json": extracted,
        "extracted_validation": "syntax_and_array_only" if extracted is not None else None,
    }


def diagnose_report(report):
    if not isinstance(report, dict) or not isinstance(report.get("results"), list):
        raise ValueError("Expected a report object with a results array")
    if any(not isinstance(row, dict) for row in report["results"]):
        raise ValueError("Every result must be an object")
    rows = [diagnose_row(row) for row in report["results"]]
    return {
        "version": 1, "source_state": report.get("state"),
        "requested_max_tokens": report.get("requested_max_tokens"),
        "result_count": len(rows),
        "issue_counts": dict(Counter(issue for row in rows for issue in row["issues"])),
        "note": "Offline diagnostics only. Issue counts overlap. Extracted arrays need schema, source and manual "
                "review; they do not change original trial status. Provider token counters are reported as-is, "
                "not added or subtracted. Raw answers remain in the source file.",
        "results": rows,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Existing saved trial JSON")
    parser.add_argument("--output", type=Path, required=True, help="New diagnostics JSON; never overwritten")
    args = parser.parse_args(argv)
    if args.input.resolve() == args.output.resolve() or args.output.exists():
        parser.error("Use a new output path; source and existing outputs must be preserved")
    try:
        data = args.input.read_bytes()
        result = diagnose_report(json.loads(data))
        result["source_sha256"] = hashlib.sha256(data).hexdigest()
        serialized = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        with args.output.open("x", encoding="utf-8") as output:
            output.write(serialized)
    except (OSError, ValueError, RecursionError):
        parser.error("Cannot read trial or create diagnostics; check input format and output path")
    print(json.dumps({"result_count": result["result_count"], "issue_counts": result["issue_counts"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
