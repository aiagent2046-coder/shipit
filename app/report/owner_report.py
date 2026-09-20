"""A read-only owner view of saved, exactly bound file-loading evidence.

This projection does not run scans, rank unrelated findings, or change their
verification status. Its source facts come only from replayable scanner receipts.
"""
from __future__ import annotations

import re

from app.scan.evidence_record import normalize_acquisition
from app.scan.security_agent import agent_record, deserialization_observation

_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_TITLE = "File loading needs a trust check"
_IMPACT = "If an untrusted file reaches this loader, it may run commands with the application’s permissions."
_ACTION = "Identify where this file comes from and who can replace or modify it."
_DONE = (
    "Record the file’s producer, everyone who can change it, and the trust check used before loading; "
    "then have a developer review whether that check is sufficient."
)
_UNKNOWN = [
    "Where the file comes from and who can change it.",
    "Whether the application checks the file’s trust before loading it.",
    "Whether the possible command execution can occur in the running application.",
]


def _bound_agent(context: dict) -> dict | None:
    value = context.get("security_agent")
    source = value.get("source") if isinstance(value, dict) else None
    if (not isinstance(source, dict)
            or not isinstance(source.get("archive_sha256"), str)
            or not _SHA256.fullmatch(source["archive_sha256"])
            or not isinstance(source.get("engine_version"), str)
            or not source["engine_version"]
            or any(context.get(key) is not None and context[key] != source.get(key)
                   for key in ("archive_sha256", "engine_version"))):
        return None
    try:
        return agent_record(value)
    except (KeyError, TypeError, ValueError, AttributeError):
        # Corrupt historical receipts must not turn a source observation into
        # an established flow, or prevent the original finding from rendering.
        return None


def _acquisition(agent: dict | None, finding: dict, trace: dict) -> dict | None:
    if agent is None:
        return None
    matches = []
    for observation in agent["observations"]:
        if (not isinstance(observation, dict)
                or observation.get("pattern_id") != "python-unsafe-deserialization"
                or observation.get("rule_id") != finding["rule_id"]
                or observation.get("file") != finding["file"]
                or type(observation.get("line")) is not int
                or observation["line"] != finding["line"]):
            continue
        evidence = observation.get("evidence")
        if not isinstance(evidence, dict) or evidence.get("deserialization_observation") != trace:
            continue
        matches.append(observation)
    if len(matches) != 1:
        return None
    acquisition = normalize_acquisition(matches[0].get("acquisition"), trace)
    return acquisition if acquisition and acquisition["status"] == "completed" else None


def build_owner_report(findings: list[dict], context: dict | None = None) -> dict:
    """Project supported file-loader cards without modifying caller-owned data.

    Adapters pass the saved agent, outer archive/engine identities when present,
    dependency_cve and runtime_verified. Absent evidence stays explicitly unknown.
    """
    context = context if isinstance(context, dict) else {}
    agent = _bound_agent(context)
    cards = []
    locations = set()
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict) or type(finding.get("line")) is not int:
            continue
        trace = deserialization_observation(finding)
        if trace is None or trace["loader"] != "pickle.load":
            continue
        evidence = finding["claim_evidence"]
        syntax = evidence.get("syntax_check")
        if (isinstance(syntax, dict) and syntax.get("result") == "contradicted"
                or any(isinstance(evidence.get(key), list) and evidence[key]
                       for key in ("source_assessments", "premise_checks"))):
            # This narrow view must not override a separately recorded source
            # assessment; the existing finding renderer owns that disposition.
            continue
        acquisition = _acquisition(agent, finding, trace)
        known = ["The code uses a file-loading method that can execute instructions stored in the file."]
        unknown = list(_UNKNOWN)
        source_refs = []
        if acquisition:
            known.append("The code opens the file at the supplied path and passes its contents to this loader.")
            source_refs.append({
                "file": trace["file"], "line": trace["sink_line"], "sha256": trace["source_sha256"],
                "sink_span": list(trace["sink_span"]), "acquisition_version": acquisition["version"],
            })
        else:
            unknown.insert(0, "The file path and handle flow have not been established for this call.")
        cards.append({
            "finding_index": index, "title": _TITLE, "impact": _IMPACT,
            "known": known, "unknown": unknown, "next_action": _ACTION, "done_when": _DONE,
            "source_refs": source_refs,
        })
        locations.add((trace["file"], trace["source_sha256"], tuple(trace["sink_span"])))
    summary = None
    if cards:
        count = len(locations)
        coverage_notes = ["Source review does not establish exploitation or a verified fix."]
        dependency = context.get("dependency_cve")
        if isinstance(dependency, dict) and dependency.get("status") == "partial":
            coverage_notes.append("Dependency checking is incomplete; see the recorded coverage gaps.")
        if context.get("runtime_verified") is False:
            coverage_notes.append("Application behavior has not been verified by this report.")
        summary = {
            "title": "File loading: the next question",
            "text": (f"{count} file-loading {'location needs' if count == 1 else 'locations need'} a trust check. "
                     "This summary covers those locations; other observations remain below."),
            "coverage_notes": coverage_notes,
            "next_action": _ACTION,
        }
    return {"version": 1, "cards": cards, "summary": summary}


def owner_report_context(report: dict) -> dict:
    """Adapt either an online saved result or a local/browser saved report."""
    score = report.get("score")
    manifest = score.get("scan_manifest") if isinstance(score, dict) else None
    source = manifest if isinstance(manifest, dict) else report
    return {key: source[key] for key in (
        "security_agent", "archive_sha256", "engine_version", "dependency_cve", "runtime_verified",
    ) if key in source}
