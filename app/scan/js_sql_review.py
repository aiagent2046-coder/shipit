"""Bounded source-only JS SQL workers and saved handoff consistency checks.

No client code, model, database or pending task from a report is executed.
Findings and their severity remain owned by the existing detector.
"""
from collections import deque
from copy import deepcopy
import hashlib
import json
import re
import zipfile

MAX_CANDIDATES = 32
MAX_SOURCE_BYTES = 400_000
MAX_WORK_BYTES = 8_000_000
EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs")
RULE_ID = "sql-injection-string-built-query"
STATES = {"fixed_sql_fragments", "dynamic_sql_unresolved", "unavailable"}
REASONS = {"proven_fixed", "unresolved_expression", "invalid_utf8", "unsupported_file", "file_limit",
           "parse_error", "node_limit", "depth_limit", "sink_not_found", "ambiguous_sink",
           "source_unavailable", "source_limit", "source_changed", "researcher_unavailable"}
FRAGMENTS = {"fixed_literal": "literal", "fixed_helper": "single_return_literal_args",
             "fixed_const": "stable_const", "unknown": "unresolved_expression"}
SHA = re.compile(r"[a-f0-9]{64}\Z")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def sha(value):
    return isinstance(value, str) and SHA.fullmatch(value) is not None


def integer(value, minimum=0, maximum=2**31 - 1):
    return type(value) is int and minimum <= value <= maximum


def normalize_analysis(value):
    """Enforce recorded fact types and fixed/unresolved verdict consistency."""
    keys = {"version", "file", "source_sha256", "sink_line", "sink_column", "sink_method",
            "verdict", "parameter_argument", "fragments", "reason", "runtime_verified"}
    if not isinstance(value, dict) or set(value) != keys:
        return None
    if (type(value["version"]) is not int or value["version"] != 1
            or not isinstance(value["file"], str) or not 1 <= len(value["file"]) <= 4096
            or not sha(value["source_sha256"]) or not integer(value["sink_line"], 1)
            or value["runtime_verified"] is not False
            or not isinstance(value["verdict"], str) or value["verdict"] not in STATES
            or not isinstance(value["reason"], str) or value["reason"] not in REASONS
            or value["parameter_argument"] not in ("present", "absent", "unknown")
            or not isinstance(value["fragments"], list) or len(value["fragments"]) > 32):
        return None
    if (value["sink_column"] is not None and not integer(value["sink_column"], 1)
            or value["sink_method"] is not None and (
                not isinstance(value["sink_method"], str) or not 1 <= len(value["sink_method"]) <= 80)):
        return None
    for item in value["fragments"]:
        if (not isinstance(item, dict) or set(item) != {"line", "kind", "reason"}
                or not integer(item["line"], 1) or not isinstance(item["kind"], str)
                or item["kind"] not in FRAGMENTS or item["reason"] != FRAGMENTS[item["kind"]]):
            return None
    if value["verdict"] == "fixed_sql_fragments":
        if (value["reason"] != "proven_fixed" or not value["fragments"]
                or any(item["kind"] == "unknown" for item in value["fragments"])):
            return None
    elif value["verdict"] == "dynamic_sql_unresolved":
        if value["reason"] != "unresolved_expression":
            return None
    elif value["reason"] in {"proven_fixed", "unresolved_expression"}:
        return None
    if value["verdict"] != "unavailable" and (
            value["sink_column"] is None or value["sink_method"] is None
            or value["parameter_argument"] == "unknown"):
        return None
    return deepcopy(value)


def unavailable(file, line, reason, source_sha256=None):
    return {"version": 1, "file": file, "source_sha256": source_sha256 or hashlib.sha256(b"").hexdigest(),
            "sink_line": line, "sink_column": None, "sink_method": None, "verdict": "unavailable",
            "parameter_argument": "unknown", "fragments": [], "reason": reason, "runtime_verified": False}


def _observation(source, ordinal, analysis, researcher=None):
    """Run a copied, source-bound queue; verifier never adopts a worker verdict blindly."""
    seed = {"source": source, "ordinal": ordinal, "file": analysis["file"], "line": analysis["sink_line"]}
    payload = deepcopy(seed)
    tasks = []
    queue = deque(("detector", "researcher", "verifier"))
    while queue:
        role = queue.popleft()
        before = digest(payload)
        if role == "detector":
            payload = {**payload, "rule_id": RULE_ID, "source_sha256": analysis["source_sha256"]}
        elif role == "researcher":
            if researcher is not None:
                analysis = researcher()
            payload = {**payload, "analysis": deepcopy(analysis)}
        else:
            checked = normalize_analysis(payload["analysis"])
            if checked is None or checked["file"] != seed["file"] or checked["sink_line"] != seed["line"]:
                raise ValueError("Invalid JS SQL worker evidence")
            payload = {**payload, "analysis": checked, "state": checked["verdict"]}
        status = "blocked" if role != "detector" and analysis["verdict"] == "unavailable" else "completed"
        tasks.append({"agent": role, "status": status, "input_sha256": before,
                      "output_sha256": digest(payload),
                      "depends_on": [tasks[-1]["output_sha256"]] if tasks else []})
    return {"id": digest(seed), "file": analysis["file"], "line": analysis["sink_line"],
            "state": analysis["verdict"], "analysis": deepcopy(analysis), "tasks": tasks}


def normalize_review(value, source):
    """Rebuild the bounded record and all receipt links, without executing saved work."""
    try:
        return _normalize_review(value, source)
    except (TypeError, ValueError, KeyError, AttributeError, RecursionError):
        return None


def _normalize_review(value, source):
    keys = {"version", "source", "status", "budget", "observations", "coverage_partial",
            "runtime_verified", "automatic_patch", "model_calls"}
    if (not isinstance(value, dict) or set(value) != keys or not isinstance(source, dict)
            or set(source) != {"archive_sha256", "engine_version"}
            or not sha(source["archive_sha256"]) or not isinstance(source["engine_version"], str)
            or not 1 <= len(source["engine_version"]) <= 128
            or value["source"] != source or type(value["version"]) is not int or value["version"] != 1
            or value["runtime_verified"] is not False or value["automatic_patch"] is not False
            or type(value["model_calls"]) is not int or value["model_calls"] != 0
            or type(value["coverage_partial"]) is not bool
            or not isinstance(value["observations"], list) or len(value["observations"]) > MAX_CANDIDATES):
        return None
    budget = value["budget"]
    if (not isinstance(budget, dict)
            or set(budget) != {"max_candidates", "candidates_found", "processed", "omitted"}
            or any(not integer(v) for v in budget.values())
            or budget["max_candidates"] != MAX_CANDIDATES
            or budget["processed"] != len(value["observations"])
            or budget["processed"] != min(MAX_CANDIDATES, budget["candidates_found"])
            or budget["omitted"] != budget["candidates_found"] - budget["processed"]):
        return None
    rebuilt = []
    for ordinal, row in enumerate(value["observations"]):
        analysis = normalize_analysis(row.get("analysis"))
        if analysis is None:
            return None
        item = _observation(source, ordinal, analysis)
        if digest(item) != digest(row):
            return None
        rebuilt.append(item)
    expected_status = ("partial" if value["coverage_partial"] or budget["omitted"]
                       or any(row["state"] == "unavailable" for row in rebuilt) else "completed")
    if value["status"] != expected_status:
        return None
    return deepcopy(value)



def _research(raw, file, line):
    source_hash = hashlib.sha256(raw).hexdigest()
    try:
        from app.scan.js_sql_source import analyze_source
        analysis = normalize_analysis(analyze_source(raw, file, line))
        if (analysis is None or analysis["source_sha256"] != source_hash
                or analysis["file"] != file or analysis["sink_line"] != line):
            raise ValueError("worker binding mismatch")
        return analysis
    except Exception:
        return unavailable(file, line, "researcher_unavailable", source_hash)


def review_js_sql(static, archive, *, archive_sha256, engine_version):
    """Collect additional facts only for existing JS SQL detector candidates."""
    candidates = [row for row in static.get("findings", []) if isinstance(row, dict)
                  and row.get("source") == "static" and row.get("rule_id") == RULE_ID
                  and isinstance(row.get("file"), str) and row["file"].lower().endswith(EXTENSIONS)
                  and integer(row.get("line"), 1)]
    if not candidates:
        return None
    candidates.sort(key=lambda row: (row["file"], row["line"]))
    source = {"archive_sha256": archive_sha256, "engine_version": engine_version}
    analyses = []
    workers = {}
    bytes_spent = 0
    position = archive.tell() if archive is not None else None
    try:
        if archive is None:
            raise ValueError("source unavailable")
        archive.seek(0)
        if hashlib.file_digest(archive, "sha256").hexdigest() != archive_sha256:
            raise ValueError("source changed")
        archive.seek(0)
        with zipfile.ZipFile(archive) as bundle:
            entries = {}
            for info in bundle.infolist():
                entries.setdefault(info.filename, []).append(info)
            for candidate in candidates[:MAX_CANDIDATES]:
                file, line = candidate["file"], candidate["line"]
                infos = entries.get(file, [])
                if len(infos) != 1 or infos[0].is_dir():
                    analyses.append(unavailable(file, line, "source_unavailable"))
                    continue
                info = infos[0]
                if info.file_size > MAX_SOURCE_BYTES or bytes_spent + info.file_size > MAX_WORK_BYTES:
                    analyses.append(unavailable(file, line, "source_limit"))
                    continue
                with bundle.open(info) as stream:
                    raw = stream.read(MAX_SOURCE_BYTES + 1)
                bytes_spent += len(raw)
                if len(raw) > MAX_SOURCE_BYTES:
                    analyses.append(unavailable(file, line, "source_limit"))
                    continue
                source_hash = hashlib.sha256(raw).hexdigest()
                # Defer the source analysis until the researcher consumes the detector handoff.
                workers[len(analyses)] = lambda raw=raw, file=file, line=line: _research(raw, file, line)
                analyses.append(unavailable(file, line, "researcher_unavailable", source_hash))
    except Exception:
        analyses.extend(unavailable(row["file"], row["line"], "source_unavailable")
                        for row in candidates[len(analyses):MAX_CANDIDATES])
    finally:
        if archive is not None:
            archive.seek(position)
    observations = [_observation(source, i, result, workers.get(i)) for i, result in enumerate(analyses)]
    coverage = static.get("rule_coverage", {}).get("sql_injection_js", {})
    partial = coverage.get("partial") is not False
    result = {"version": 1, "source": source, "status": "completed",
              "budget": {"max_candidates": MAX_CANDIDATES, "candidates_found": len(candidates),
                         "processed": len(observations), "omitted": max(0, len(candidates) - MAX_CANDIDATES)},
              "observations": observations, "coverage_partial": partial,
              "runtime_verified": False, "automatic_patch": False, "model_calls": 0}
    if partial or result["budget"]["omitted"] or any(row["state"] == "unavailable" for row in observations):
        result["status"] = "partial"
    return normalize_review(result, source)
