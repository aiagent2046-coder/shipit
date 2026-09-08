"""Presentation of evidence, including older audits without provenance.

Neither the current static scanners nor the model independently verifies a
finding's consequence. Keep that limit visible regardless of confidence,
severity, tier, or how many model passes repeated the same claim.
"""

import json

from app.scan.secrets import NON_PRODUCTION_CONTEXTS, is_non_production_path
from app.scan.claim_evidence import syntax_contradicted
from app.scan.scoring import CATEGORIES, LLM_ONLY_CATEGORIES


def is_non_production(finding: dict) -> bool:
    context = finding.get("context")
    return (context in NON_PRODUCTION_CONTEXTS if context
            else is_non_production_path(str(finding.get("file", ""))))


def is_informational(finding: dict) -> bool:
    return finding.get("rule_id") == "no-dockerfile" and finding.get("context") == "deployment_inventory"


def finding_counts(findings: list[dict]) -> tuple[int, int]:
    source = examples = 0
    for finding in findings:
        if is_informational(finding) or syntax_contradicted(finding.get("claim_evidence")):
            continue
        # Display-only RLS groups retain one title for each stored observation.
        count = len(finding.get("occurrence_titles") or []) or 1
        if is_non_production(finding):
            examples += count
        else:
            source += count
    return source, examples


def observation_summary(findings: list[dict]) -> str:
    source, examples = finding_counts(findings)
    informational = contradicted = 0
    for finding in findings:
        count = len(finding.get("occurrence_titles") or []) or 1
        if syntax_contradicted(finding.get("claim_evidence")):
            contradicted += count
        elif is_informational(finding):
            informational += count
    return (f"{source + examples + informational + contradicted} observations: "
            f"{source} in source, {examples} in tests/examples, {informational} informational, "
            f"{contradicted} with contradicted syntax premises.")


def review_contribution_rows(score: dict) -> list[tuple[str, str, str]]:
    baseline = score.get("free_baseline") or {}
    if baseline.get("version") != 1:
        return []

    def values(stage: dict) -> list[str]:
        manifest = stage.get("scan_manifest") or {}
        processing = manifest.get("model_findings")
        saved = (sum(r["saved"] for r in processing)
                 if processing and all(isinstance(r.get("saved"), int) for r in processing) else None)
        recorded = [manifest.get("llm_submitted_files"), manifest.get("model_calls"), saved]
        return [str(v) if v is not None else "Not recorded" for v in recorded]

    free = values(baseline.get("score") or {})
    paid = values(score)
    return list(zip(("Files submitted to model", "Model responses", "Retained model hypotheses"), free, paid))


def source_severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = dict.fromkeys(("critical", "high", "medium", "low"), 0)
    for finding in findings:
        if is_informational(finding) or syntax_contradicted(finding.get("claim_evidence")):
            continue
        if is_non_production(finding):
            continue
        for severity in finding.get("occurrence_severities") or [finding.get("severity")]:
            if severity in counts:
                counts[severity] += 1
    return counts


def model_status_notice(score: dict) -> tuple[str, str] | None:
    """Describe recorded execution, never infer a payment tier or a project defect."""
    manifest = score.get("scan_manifest") or {}
    reasons = manifest.get("limitations", [])
    limited = bool(reasons) or score.get("basis") == "static+partial"
    if not limited and score.get("basis") != "static_only":
        return None
    responded = bool(manifest.get("model_calls", 0))
    title = ("Model review incomplete" if responded or score.get("basis") == "static+partial"
             else "Model review unavailable")
    if responded and reasons == ["input_truncated"]:
        title = "Model review may be incomplete"
    detail = ("Model responses are available, but review limits were recorded."
              if responded else "No model response is recorded. Only static observations are available.")
    if "billing" in reasons:
        detail += " The model provider reported a billing or quota limit."
    elif ("provider" in reasons or "provider_failure" in reasons
          or any(r.startswith("rubric_failed:") for r in reasons)):
        detail += " A model request failed."
    if "cost_cap_exceeded" in reasons or "daily_spend_cap" in reasons:
        detail += " A review spending limit was reached."
    if "input_truncated" in reasons:
        detail += " Token accounting suggests possible input truncation; this is not independently verified."
    if not manifest:
        detail = "The review is recorded as limited. The reason and model execution details were not recorded."
    return title, detail + " This is a limit of the audit, not evidence of a defect in your project."


def evidence_label(finding: dict) -> str:
    if syntax_contradicted(finding.get("claim_evidence")):
        return "Model syntax premise contradicted — see bounded check"
    if is_informational(finding):
        return "Deployment inventory — informational"
    source = finding.get("source")
    if source == "llm" or str(finding.get("rule_id", "")).startswith("llm-"):
        return "Model hypothesis — unverified"
    if source == "static":
        return "Static signal — unverified"
    return "Legacy finding — verification not recorded"


def claim_evidence_rows(finding: dict) -> list[tuple[str, str]]:
    """A recorded source check is separate from the model's reading of it."""
    record = finding.get("claim_evidence")
    record = record if isinstance(record, dict) and record.get("version") == 1 else {}
    check = record.get("source_check") or {}
    if check.get("kind") == "quote_match":
        checked = (f"Quoted text matched in source lines {check['line_start']}–{check['line_end']}. "
                   "This does not verify the interpretation.")
    elif check.get("kind") == "static_rule":
        checked = "A static rule emitted this observation. Its consequence was not tested."
    else:
        checked = "Not recorded for this finding; do not assume the cited code was verified."
    rows = [("Source check", checked)]
    context = record.get("source_context") or {}
    if context:
        labels = {"comment": "Comment", "docstring": "Python docstring", "doc_example": "Documentation/example",
                  "test_file": "Test file", "test_fixture": "Test fixture/placeholder",
                  "ci_service": "CI configuration with a local host", "placeholder_uri": "Example URI",
                  "configuration_template": "Configuration text containing change_me",
                  "source_literal": "Source text; runtime use not established"}
        rows.append(("Source context", labels.get(context.get("kind"), "Not recorded")))
        rows.append(("URI protocol", str(context.get("uri_scheme", "Not recorded")) + " — "
                     + str(context.get("uri_kind", "other_or_unknown"))
                     + "; URI use, credential validity and deployment are not verified."))
    syntax = record.get("syntax_check")
    if syntax:
        labels = {"contradicted": "Syntax premise contradicted", "observed": "Syntax pattern observed",
                  "not_checked": "Syntax premise not checked"}
        label = labels.get(syntax.get("result"), "Syntax premise not checked")
        detail = syntax["claim"] + " " + syntax["detail"]
        if syntax.get("line_start"):
            detail += f" Checked source lines {syntax['line_start']}–{syntax['line_end']}."
        rows.append((label, detail))
    context_labels = {
        "guard_context": "Existing guard evidence — compare with the model claim",
        "cost_context": "Cost and ordering evidence — compare with the model claim",
        "rls_recommendation_context": "Policy prerequisites — review before changing clients",
    }
    for context in record.get("context_checks", []):
        label = context_labels.get(context.get("kind"))
        if label:
            summaries = ([context["summary"]] if context.get("summary") else
                         [item.get("summary", "") for item in context.get("checks", [])])
            for summary in summaries:
                if summary:
                    location = str(context.get("file", ""))
                    if context.get("line"):
                        location += ":" + str(context["line"])
                    rows.append((label, (location + " — " if location else "") + summary))
        if context.get("kind") == "react_async_context":
            for item in context.get("checks", []):
                if item.get("summary"):
                    rows.append(("React error-path evidence — compare with the model claim",
                                 str(context.get("scope", "")) + ": " + item["summary"] + " " + item["detail"]))
        rows.append(("Deterministic context check", json.dumps(context, ensure_ascii=False)))
    for i, original in enumerate(record.get("grouped_originals", []), 1):
        rows.append((f"Grouped original {i} — not independent confirmation",
                     json.dumps(original, ensure_ascii=False)))
    if record.get("observation"):
        rows.append(("Model interpretation — unverified", record["observation"]))
    conditions = record.get("required_conditions")
    rows.append(("Required conditions — not checked", "\n".join(conditions) if conditions else
                 "Not recorded; do not assume the conditions for harm are satisfied."))
    rows.append(("Consequence check", "No independent verification recorded."))
    return rows


def coverage_rows(score: dict, findings: list[dict]) -> list[tuple[str, str]]:
    basis = score.get("basis")
    recorded = "unexamined" in score or basis in ("static_only", "static+preview")
    skipped = set(score.get("unexamined", LLM_ONLY_CATEGORIES if recorded else ()))
    names = dict.fromkeys((*CATEGORIES, *score.get("categories", {})))
    rows = []
    for name in names:
        count, examples = finding_counts([f for f in findings if f.get("category") == name])
        if not recorded:
            label = "Coverage not recorded"
        elif name in skipped:
            label = "Not surveyed — see findings" if count else "Not checked"
        else:
            label = "Partly checked"
        if name == "Auth" and name in skipped and "auth_read_consistency" in (
                score.get("scan_manifest", {}).get("static_checks", [])):
            label = "Local Python route check ran — broader auth not checked"
        elsewhere = (score.get("reported_elsewhere") or {}).get(name)
        if elsewhere:
            label += " — findings reported under " + ", ".join(elsewhere)
        if count:
            label += f" · {count} unverified finding{'s' if count != 1 else ''}"
        if examples:
            label += f" · {examples} test/example observations"
        rows.append((name, label))
    return rows


def manifest_rows(score: dict) -> list[tuple[str, str]]:
    manifest = score.get("scan_manifest")
    if not isinstance(manifest, dict):
        return [("Scan record", "Not recorded for this older audit")]
    rows = [
        ("Archive SHA-256", manifest.get("archive_sha256") or "Not recorded"),
        ("Git commit", manifest.get("commit_sha") or "Not recorded for this archive"),
        ("Scan engine", manifest.get("engine_version") or "Not recorded"),
        ("Files in archive", str(manifest.get("archive_files", "Not recorded"))),
        ("Static checks run", ", ".join(manifest.get("static_checks", [])) or "Not recorded"),
        ("Last responding model", manifest.get("model") or "No model response recorded"),
        ("Model responses", str(manifest.get("model_calls", 0))),
        ("Review areas applied", ", ".join(manifest.get("rubrics_completed", [])) or "None"),
    ]
    accounting = manifest.get("model_findings")
    if accounting is None:
        rows.append(("Model finding processing", "Not recorded for this audit"))
    elif not accounting:
        rows.append(("Model finding processing", "No model response processed"))
    else:
        for row in accounting:
            rows.append(("Finding processing: " + str(row.get("model") or "unknown model"),
                         f"Responses: {row['responses']}; unreadable: {row['invalid_responses']}; "
                         f"valid empty: {row['empty_responses']}. "
                         f"Received entries: {row['received']}; rejected: {row['rejected']}; "
                         f"accepted before grouping: {row['accepted']}; merged: {row['merged']}; "
                         f"saved representatives: {row['saved']}. "
                         "Merged originals are retained. These counts do not verify conclusions."))
            rows.append(("Rejection reasons", json.dumps(row["rejection_reasons"], ensure_ascii=False)))
    for key, label in (("llm_candidate_files", "Files eligible for model review"),
                       ("llm_submitted_files", "Unique files submitted to model"),
                       ("llm_files_not_submitted", "Eligible files not submitted")):
        value = manifest.get(key)
        rows.append((label, str(value) if value is not None else "Not recorded"))
    exclusions = manifest.get("llm_selection_exclusions")
    labels = {
        "no_rubric_match": "No keyword match in configured review areas",
        "rubric_not_reached": "Matching review areas were not reached",
        "selection_budget": "Outside file-selection budgets of attempted areas",
        "request_window": "Removed to fit the request window",
    }
    if isinstance(exclusions, dict):
        rows.extend(("Files not submitted: " + label, str(exclusions.get(key, 0)))
                    for key, label in labels.items())
    elif manifest.get("llm_files_not_submitted"):
        rows.append(("File exclusion reasons", "Not recorded for this audit"))
    limitations = manifest.get("limitations", [])
    rows.append(("Model limits / skip reasons", ", ".join(limitations) or "None recorded"))
    for check, status in manifest.get("static_limits", {}).items():
        rows.append((f"Static scope: {check}", str(status)))
    facts = manifest.get("source_facts")
    if isinstance(facts, dict):
        for key, label in (("guards", "Guard evidence"), ("cost_context", "Cost evidence"),
                           ("rls_recommendations", "Policy recommendation evidence")):
            index = facts.get(key)
            if isinstance(index, dict):
                rows.extend([
                    (label + " scope", index.get("scope", "Not recorded")),
                    (label + " limits", ", ".join(index.get("limitations", [])) or "None recorded"),
                    (label + " records", str(len(index.get("records", [])))),
                ])
                rows.extend((f"{label} {i}", json.dumps(item, ensure_ascii=False))
                            for i, item in enumerate(index.get("records", []), 1))
        rows.append(("Source fact scope", facts.get("scope", "Not recorded")))
        rows.append(("Python files parsed for source facts", str(facts.get("parsed_files", 0))))
        rows.append(("Source fact limits", ", ".join(facts.get("limitations", [])) or "None recorded"))
        for i, fact in enumerate(facts.get("facts", []), 1):
            rows.append((f"Source syntax fact {i}",
                         f"{fact['file']}:{fact['line']} — {fact['scope']}: call {fact['call']}; "
                         f"matching {fact['import_module']} import at line {fact['import_line']}"))
        operations = facts.get("operations")
        if isinstance(operations, dict):
            rows.extend([
                ("Operation context scope", operations.get("scope", "Not recorded")),
                ("Files parsed for operation context", str(operations.get("parsed_files", 0))),
                ("Operation context limits", ", ".join(operations.get("limitations", [])) or "None recorded"),
            ])
            for i, fact in enumerate(operations.get("records", []), 1):
                rows.append((f"Operation context {i}",
                             f"{fact['file']}:{fact['line']} — {fact['scope']}: {fact['call']}\n"
                             + fact["detail"]))
        react = facts.get("react_async")
        if isinstance(react, dict):
            rows.extend([
                ("React async scope", react.get("scope", "Not recorded")),
                ("Files parsed for React async context", str(react.get("parsed_files", 0))),
                ("React async limits", ", ".join(react.get("limitations", [])) or "None recorded"),
            ])
            for i, fact in enumerate(react.get("records", []), 1):
                detail = [f"{fact['file']}:{fact['line']}–{fact['line_end']} — {fact['scope']}",
                          "Await lines: " + ", ".join(map(str, fact["await_lines"]))]
                detail.extend(json.dumps(c, ensure_ascii=False) for c in fact["checks"])
                detail.extend("Button syntax: " + json.dumps(c, ensure_ascii=False) for c in fact["controls"])
                rows.append((f"React async context {i}", "\n".join(detail)))
        functions = facts.get("functions")
        if isinstance(functions, dict):
            rows.extend([
                ("Function evidence scope", functions.get("scope", "Not recorded")),
                ("Functions indexed", str(functions.get("indexed_functions", 0))),
                ("Function evidence limits", ", ".join(functions.get("limitations", [])) or "None recorded"),
            ])
            for i, fact in enumerate(functions.get("records", []), 1):
                detail = [f"{fact['file']}:{fact['line']}–{fact['line_end']} — {fact['scope']}"]
                detail.extend(json.dumps(c, ensure_ascii=False) for c in fact["checks"])
                detail.extend("Candidate (binding not resolved): " + json.dumps(c, ensure_ascii=False)
                              for c in fact["candidates"])
                rows.append((f"Function evidence {i}", "\n".join(detail)))
    for kind, paths in manifest.get("inventory", {}).items():
        shown = ", ".join(paths[:5])
        if len(paths) > 5:
            shown += f" (+{len(paths) - 5} more)"
        rows.append((kind, f"{len(paths)} found" + (f": {shown}" if shown else "")))
    return rows
