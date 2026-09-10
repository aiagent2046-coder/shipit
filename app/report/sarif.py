"""Findings as SARIF 2.1.0, so the tools that read SARIF can read this audit.

WHY SARIF AND NOT ANOTHER JSON SHAPE. GitHub's code scanning, VS Code's
problems panel, and most CI security plugins consume SARIF and nothing else.
An audit only reaches those surfaces if it speaks their format, and the format
is specified rather than ours -- the schema is checked in at
tests/fixtures/sarif-schema-2.1.0.json because every consumer validates against
it (see the SOURCE note beside it).

WHAT THIS MODULE IS NOT. It adds no findings, drops none and reorders nothing
that matters: it is a translation of the finding list the report already shows.
The one test that keeps it honest asserts the two agree finding for finding.

TWO DECISIONS WORTH NAMING:

- `level` is set per RESULT, not as a rule default. A rule's severity can vary
  with what it found (generic-assignment is a low-severity habit here and a
  leaked credential there), so a per-rule default would be a claim about the
  rule that this run cannot support.
- A finding with no line gets a location with no `region`. SARIF requires
  `startLine >= 1`, and a structural or dependency finding knows its file but
  not a line; writing 1 would point a reader at the wrong place in the file.
"""
from __future__ import annotations

import hashlib
import json
import urllib.parse

from app.report.plain_language import plain_fields

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "Drydock"

# The consumer-facing severity vocabulary maps onto SARIF's four levels. `error`
# for anything a reader should act on before shipping, `warning` for what is
# worth fixing, `note` for the rest -- the same split the report's own tiers
# make (app/report/plain_language.TIERS), so the two cannot disagree.
LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}

# Fingerprint key. A key of our own rather than SARIF's example
# (`primaryLocationLineHash`), because this one is deliberately NOT derived from
# the line: a finding that moves down a file is the same finding reported again,
# and a consumer that dedupes on it must not see a new one. It changes when the
# evidence changes, which is what makes a genuinely new finding new.
FINGERPRINT_KEY = "drydock/finding/v1"


def _uri(path: str) -> str:
    """An archive-relative path as a URI reference."""
    cleaned = path.lstrip("./").lstrip("/")
    return urllib.parse.quote(cleaned, safe="/")


def _level(severity: str) -> str:
    return LEVELS.get(str(severity).lower(), "warning")


def fingerprint(finding: dict) -> str:
    """A stable identity for this finding, independent of its line number.

    `masked` is the deterministic fingerprint of a secret's value and `title`
    covers every other rule, so two findings of the same rule in the same file
    stay distinct while the same finding keeps one identity across line moves.
    """
    evidence = str(finding.get("masked") or finding.get("title") or "")
    material = "\x00".join((str(finding.get("rule_id") or ""),
                            str(finding.get("file") or ""), evidence))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _message(finding: dict) -> str:
    """Title plus the plain-language explanation, which is what a reader of a
    SARIF viewer actually sees."""
    title = str(finding.get("title") or "").strip()
    explanation = str(finding.get("explanation") or "").strip()
    if title and explanation:
        return f"{title}. {explanation}"
    return title or explanation or "Finding reported by the static analysis engine"


def _rule(findings_for_rule: list[dict], rule_id: str) -> dict:
    """Rule metadata, taken from the same plain-language layer the HTML report
    uses -- so a description cannot be right in one output and stale in the
    other."""
    what, risk, fix = plain_fields(findings_for_rule[0])
    rule = {
        "id": rule_id,
        "name": rule_id.replace("-", " ").title().replace(" ", ""),
        "shortDescription": {"text": what.strip() or rule_id},
        "fullDescription": {"text": risk.strip() or what.strip() or rule_id},
        "help": {"text": (fix.strip() or what.strip() or rule_id)},
    }
    if all(isinstance(f.get("file"), str) and f.get("file") for f in findings_for_rule):
        rule["helpUri"] = f"https://drydock.co/rules/{rule_id}"
    return rule


def build_sarif(findings: list[dict], *, engine_version: str,
                score: dict | None = None, project_name: str | None = None) -> dict:
    """The SARIF document for this finding list.

    `score` is optional and only its recorded facts travel: the engine version,
    the basis (which decides how much was examined) and the limitations (what
    was not). A consumer that shows the log will show those beside the results.
    """
    manifest = ((score or {}).get("scan_manifest") or {})
    by_rule: dict[str, list[dict]] = {}
    for finding in findings:
        rule_id = str(finding.get("rule_id") or "")
        if rule_id:
            by_rule.setdefault(rule_id, []).append(finding)

    rule_ids = sorted(by_rule)
    rules = [_rule(by_rule[rule_id], rule_id) for rule_id in rule_ids]
    rule_index = {rule_id: index for index, rule_id in enumerate(rule_ids)}

    results = []
    for finding in findings:
        rule_id = str(finding.get("rule_id") or "")
        if not rule_id:
            continue
        physical: dict = {"artifactLocation": {"uri": _uri(str(finding.get("file") or ""))}}
        line = finding.get("line")
        if isinstance(line, int) and line > 0:
            physical["region"] = {"startLine": line}
        results.append({
            "ruleId": rule_id,
            "ruleIndex": rule_index[rule_id],
            "level": _level(str(finding.get("severity") or "")),
            "message": {"text": _message(finding)},
            "locations": [{"physicalLocation": physical, "logicalLocations": [
                {"name": rule_id, "kind": "rule"}]}],
            "partialFingerprints": {FINGERPRINT_KEY: fingerprint(finding)},
        })

    run: dict = {
        "tool": {"driver": {"name": TOOL_NAME, "version": engine_version,
                            "informationUri": "https://drydock.co",
                            "rules": rules}},
        "invocations": [{
            "executionSuccessful": True,
            "properties": {
                "engineVersion": engine_version,
                "basis": (score or {}).get("basis"),
                "limitations": list(manifest.get("limitations") or []),
            },
        }],
        "results": results,
    }
    if project_name:
        run["properties"] = {"project": project_name}
    return {"version": SARIF_VERSION, "$schema": SARIF_SCHEMA, "runs": [run]}


def render_sarif(findings: list[dict], **kwargs) -> str:
    """The document as JSON text, for writing to a file or a response body."""
    return json.dumps(build_sarif(findings, **kwargs), indent=2, ensure_ascii=False)
