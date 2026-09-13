"""Project two source-contradicted premises into consistent public wording.

Call only after scanner admission, recommendation preparation and grouping.
Fresh archive hashes are supplied by that caller, never read from model JSON.
This changes wording, not verification, grouping, severity or score eligibility.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import replace
import re

from app.scan.claim_evidence import source_assessments
from app.scan.external_operation_identity import valid_external_identity
from app.scan.scoring import ScoredFinding

_KINDS = {"fact_input_count_unbounded", "retry_callback_scope"}
_MAX = 2**53 - 1


def _location(value):
    if not isinstance(value, dict):
        return False
    start, end, span = value.get("line_start"), value.get("line_end"), value.get("span")
    return (type(start) is int and type(end) is int and 1 <= start <= end <= _MAX
            and isinstance(span, list) and len(span) == 2
            and all(type(v) is int for v in span) and 0 <= span[0] < span[1] <= _MAX)


def _inside(inner, outer):
    return (_location(inner) and _location(outer)
            and outer["span"][0] <= inner["span"][0] < inner["span"][1] <= outer["span"][1]
            and outer["line_start"] <= inner["line_start"] <= inner["line_end"] <= outer["line_end"])


def _bound(value, hashes):
    if not _location(value):
        return False
    path, digest = value.get("file"), value.get("source_sha256")
    return (isinstance(path, str) and 0 < len(path) <= 512 and not path.startswith("/")
            and "\\" not in path and all(p not in {"", ".", ".."} for p in path.split("/"))
            and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
            and hashes.get(path) == digest)


def _fact(check, finding, hashes):
    b = check["source_binding"]
    if (not _bound(b, hashes) or b["file"] != finding.file
            or b["line_start"] != check["line_start"] or b["line_end"] != check["line_end"]
            or any(not _inside(b.get(k), b) for k in
                   ("query_result", "call", "caller_result", "input_argument", "consumer_call"))
            or not _inside(b["call"], b["caller_result"])
            or not _inside(b["input_argument"], b["call"])
            or not b["query_result"]["span"][1] < b["caller_result"]["span"][0]
            or not b["caller_result"]["span"][1] < b["consumer_call"]["span"][0]
            or not any(b[k]["line_start"] <= finding.line <= b[k]["line_end"]
                       for k in ("query_result", "call"))
            or type(b.get("upper")) is not int or not 0 <= b["upper"] <= _MAX
            or b.get("database_read_bound") != "not_checked"
            or b.get("total_prompt_bound") != "not_checked"):
        return None
    callee, consumer = b.get("callee"), b.get("consumer")
    if (not _bound(callee, hashes) or not _bound(consumer, hashes)
            or not _inside(b.get("return"), callee) or not _inside(b.get("slice"), b["return"])
            or not _inside(consumer.get("return"), consumer)
            or not _inside(consumer.get("mapped_input"), consumer["return"])):
        return None
    used = {v["file"]: v["source_sha256"] for v in (b, callee, consumer)}
    for key in ("resolution", "consumer_resolution"):
        resolution = b.get(key)
        if (not isinstance(resolution, dict) or resolution.get("kind") not in
                {"relative_source_candidate", "literal_config_source_candidate"}):
            return None
        config = resolution.get("configuration")
        if config is not None:
            if not _bound(config, hashes):
                return None
            used[config["file"]] = config["source_sha256"]
        elif resolution["kind"] == "literal_config_source_candidate":
            return None
    count = b["upper"]
    observation = (f"The cited query result passes through a collection cap of {count} items "
                   "before the recorded fact-block renderer. The preceding database read "
                   "and the complete prompt have not been shown to be bounded by this check.")
    return ({
        "title": "Fact count is capped before rendering; database read needs separate review",
        "explanation": observation + " An uncapped fact count on this source path is contradicted. "
                       "Database read volume, other prompt inputs, item lengths and actual charges "
                       "remain separate questions; a downstream cap does not settle them.",
        "fix_hint": "Inspect the database query and its expected volume separately. If its read volume "
                    "needs a limit or pagination, preserve the intended ordering and fact selection. "
                    "Retain the existing collection cap; assess other prompt inputs and item lengths "
                    "before claiming a total prompt or cost bound.",
        "observation": observation,
    }, used)


def _retry(check, finding, hashes):
    b = check["source_binding"]
    call, callback, wrapper = b.get("retry_call"), b.get("callback"), b.get("wrapper")
    identity = check.get("operation_identity")
    attempts, extra = b.get("maximum_attempts"), b.get("maximum_additional_attempts")
    checks, parses = b.get("response_status_checks"), b.get("response_json_calls")
    if (not _bound(b, hashes) or b["file"] != finding.file
            or not _bound(wrapper, hashes) or wrapper["file"] != finding.file
            or not _inside(call, b) or not _inside(callback, call)
            or not any(v["line_start"] <= finding.line <= v["line_end"] for v in (call, wrapper))
            or not valid_external_identity(identity, finding.file)
            or identity["source_sha256"] != b["source_sha256"]
            or identity["operation_span"] != call["span"]
            or type(attempts) is not int or not 1 <= attempts <= _MAX
            or type(extra) is not int or extra != attempts - 1
            or b.get("attempt_bound_mode") not in
               {"literal_loop_bound", "parameter_default", "literal_call_override"}
            or not isinstance(checks, list) or not checks
            or not isinstance(parses, list) or not parses
            or any(not _location(v) or v["span"][0] <= call["span"][1] for v in checks + parses)):
        return None
    observation = ("The retry callback returns the recorded request. Checks of that response's HTTP "
                   "status and JSON parsing occur after the awaited retry call, outside its callback.")
    rejection = ("Request rejection can still retry" if extra else
                 "This invocation has no additional attempt for request rejection")
    return ({
        "title": ("Request rejection can retry; later response checks are outside the callback" if extra else
                  "Request has one attempt; later response checks are outside the callback"),
        "explanation": observation + f" The wrapper configures at most {attempts} total attempts "
                       f"({extra} additional {'attempt' if extra == 1 else 'attempts'}). "
                       "Failures in those later response checks "
                       f"do not re-enter this retry invocation. {rejection}; "
                       "runtime outcomes and repeated charges are not established by this source check.",
        "fix_hint": "Review the request rejection and timeout policy separately from HTTP status handling. "
                    "Before repeating an operation after an uncertain response, check its remote outcome "
                    "and applicable idempotency support. Verify actual attempts and charges separately; "
                    "do not attribute retries to response checks outside this callback.",
        "observation": observation,
    }, {v["file"]: v["source_sha256"] for v in (b, wrapper)})


def project_claim_narrative(
    finding: ScoredFinding, *, current_source_hashes: Mapping[str, str] | None = None,
) -> ScoredFinding:
    """Return a copy with bounded wording, or the original when proof is absent.

    ``current_source_hashes`` must come from current raw ZIP bytes. In particular,
    supplying hashes from the finding itself would defeat freshness validation.
    Model JSON cannot supply assessments through normal scanner admission.
    """
    record = finding.claim_evidence
    if (finding.source != "llm" or finding.verification_method != "model_review"
            or not isinstance(record, dict) or not isinstance(current_source_hashes, Mapping)):
        return finding
    quote, producer = record.get("source_check"), record.get("producer")
    if (not isinstance(quote, dict) or quote.get("kind") != "quote_match"
            or type(quote.get("line_start")) is not int or type(quote.get("line_end")) is not int
            or type(finding.line) is not int
            or not 1 <= quote["line_start"] <= finding.line <= quote["line_end"] <= _MAX
            or not isinstance(producer, dict)
            or any(not isinstance(producer.get(k), str) or not producer[k].strip() for k in ("model", "rubric"))
            or type(producer.get("response")) is not int or producer["response"] < 1):
        return finding
    candidates = [c for c in source_assessments(record) if c["kind"] in _KINDS
                  and c["result"] == "contradicted" and c["whole_finding"] is False]
    if len(candidates) != 1:
        return finding
    check = candidates[0]
    b = check["source_binding"]
    if (check["file"] != finding.file or b.get("file") != finding.file
            or check["source_sha256"] != b.get("source_sha256")
            or check["line_start"] != b.get("line_start") or check["line_end"] != b.get("line_end")
            or ("span" in check and check["span"] != b.get("span"))):
        return finding
    projected = (_fact if check["kind"] == "fact_input_count_unbounded" else _retry)(
        check, finding, current_source_hashes)
    if projected is None:
        return finding
    wording, hashes = projected
    # Never overwrite an earliest original, even if saved metadata is malformed.
    previous = record.get("narrative_projection")
    if previous is not None:
        return finding
    original_fix = finding.fix_hint
    recommendation = record.get("recommendation_check")
    if (isinstance(recommendation, dict) and recommendation.get("original_status") == "superseded"
            and isinstance(recommendation.get("original_fix_hint"), str)):
        original_fix = recommendation["original_fix_hint"]
    evidence = deepcopy(record)
    evidence["narrative_projection"] = {
        "version": 1, "method": "source_bound_projection", "kind": check["kind"],
        "applied_checks": [check["kind"]], "active": deepcopy(wording),
        "source_hashes": hashes, "whole_finding": False,
        "original": {"title": finding.title, "explanation": finding.explanation,
                     "fix_hint": original_fix, "observation": deepcopy(record.get("observation")),
                     "producer": deepcopy(producer)},
        "previous_fix_hint": finding.fix_hint,
    }
    evidence["observation"] = wording.pop("observation")
    return replace(finding, **wording, claim_evidence=evidence)


def narrative_projection(finding: dict) -> dict | None:
    """Validate persisted projection consistency for report consumers.

    This checks saved source evidence and the active wording, not a new archive.
    Freshness was required when creating the projection at scanner admission.
    """
    if not isinstance(finding, dict) or not isinstance(finding.get("claim_evidence"), dict):
        return None
    record = finding["claim_evidence"]
    projection = record.get("narrative_projection")
    if not isinstance(projection, dict):
        return None
    original, active = projection.get("original"), projection.get("active")
    if (type(projection.get("version")) is not int or projection["version"] != 1
            or projection.get("method") != "source_bound_projection"
            or not isinstance(projection.get("kind"), str) or projection["kind"] not in _KINDS
            or projection.get("applied_checks") != [projection["kind"]]
            or projection.get("whole_finding") is not False
            or not isinstance(projection.get("previous_fix_hint"), str)
            or not isinstance(original, dict) or not isinstance(active, dict)
            or any(not isinstance(original.get(k), str) for k in ("title", "explanation", "fix_hint"))
            or original.get("producer") != record.get("producer")
            or (original.get("observation") is not None and not isinstance(original["observation"], str))
            or any(not isinstance(active.get(k), str) or active[k] != finding.get(k)
                   for k in ("title", "explanation", "fix_hint"))
            or active.get("observation") != record.get("observation")):
        return None
    evidence = deepcopy(record)
    evidence.pop("narrative_projection")
    candidate = ScoredFinding(
        rule_id=finding.get("rule_id", ""), title=original["title"],
        explanation=original["explanation"], fix_hint=original["fix_hint"],
        severity=finding.get("severity", ""), confidence=finding.get("confidence", 0),
        category=finding.get("category", ""), file=finding.get("file", ""), line=finding.get("line", 0),
        source=finding.get("source", "unknown"), verification_method=finding.get("verification_method", "not_run"),
        claim_evidence=evidence,
    )
    projected = project_claim_narrative(candidate, current_source_hashes=projection.get("source_hashes"))
    rebuilt = (projected.claim_evidence or {}).get("narrative_projection")
    if (not isinstance(rebuilt, dict) or rebuilt["kind"] != projection["kind"]
            or rebuilt["active"] != active or rebuilt["source_hashes"] != projection.get("source_hashes")):
        return None
    return projection
