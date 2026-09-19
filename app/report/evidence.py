"""Presentation of evidence, including older audits without provenance.

Neither the current static scanners nor the model independently verifies a
finding's consequence. Keep that limit visible regardless of confidence,
severity, tier, or how many model passes repeated the same claim.
"""

import json
import re

from app.scan.secrets import NON_PRODUCTION_CONTEXTS, is_non_production_path
from app.sca.stage import freshness
from app.scan.claim_evidence import (
    narrative_review_checks, partial_contradicted, source_assessments, syntax_contradicted, unsupported_transport,
)
from app.scan.scoring import CATEGORIES, LLM_ONLY_CATEGORIES
from app.scan.claim_narrative import narrative_projection
from app.scan.query_read_identity import valid_query_read_identity
from app.scan.rejection_diagnostics import acceptance_summary, diagnostics_manifest
from app.scan.manifest import SCA_LIMITATIONS
from app.report.cve import cve_rows, cve_notices
from app.report.dependency_snapshot import SCOPE_REASONS, snapshot_rows, snapshot_notices, snapshot_finding_rows
from app.scan.rule_coverage import normalize_rule_coverage
from app.scan.check_failures import normalize_check_failures
from app.scan.security_agent import agent_record, sql_driver_rows, sql_observation
from app.scan.evidence_record import acquisition_rows, normalize_acquisition
from app.scan.synthetic_record import normalize_synthetic_contract, synthetic_contract_rows


def is_non_production(finding: dict) -> bool:
    context = finding.get("context")
    return (context in NON_PRODUCTION_CONTEXTS if context
            else is_non_production_path(str(finding.get("file", ""))))


def is_informational(finding: dict) -> bool:
    return finding.get("rule_id") == "no-dockerfile" and finding.get("context") == "deployment_inventory"


def finding_counts(findings: list[dict]) -> tuple[int, int]:
    source = examples = 0
    for finding in findings:
        if (is_informational(finding) or syntax_contradicted(finding.get("claim_evidence"))
                or unsupported_transport(finding.get("claim_evidence"))):
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
    informational = contradicted = unsupported = 0
    for finding in findings:
        count = len(finding.get("occurrence_titles") or []) or 1
        if unsupported_transport(finding.get("claim_evidence")):
            unsupported += count
        elif syntax_contradicted(finding.get("claim_evidence")):
            contradicted += count
        elif is_informational(finding):
            informational += count
    message = (f"{source + examples + informational + contradicted + unsupported} observations: "
            f"{source} in source, {examples} in tests/examples, {informational} informational, "
            f"{contradicted} with contradicted syntax premises.")
    return (message + f" {unsupported} transport-only hypotheses need exposure evidence."
            if unsupported else message)


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
        if (is_informational(finding) or syntax_contradicted(finding.get("claim_evidence"))
                or unsupported_transport(finding.get("claim_evidence"))):
            continue
        if is_non_production(finding):
            continue
        for severity in finding.get("occurrence_severities") or [finding.get("severity")]:
            if severity in counts:
                counts[severity] += 1
    return counts


# Mirror the producer's model flags and known skip/failure reasons, including
# legacy free-tier skips. Unknown reasons retain their own audit notice instead
# of being assigned to a model failure by exclusion.
MODEL_LIMITATIONS = frozenset({
    "billing", "provider", "provider_failure", "cost_cap_exceeded", "daily_spend_cap",
    "input_truncated", "invalid_responses", "no_providers_configured", "free_tier", "paid_job_cost_cap",
})

RULE_COVERAGE_LABELS = {
    "sql_injection": "Python SQL queries",
    "sql_injection_js": "JavaScript/TypeScript SQL queries",
    "outbound_url": "Outbound request URLs",
    "tls_verification": "TLS verification",
    "unsafe_deserialization": "Unsafe deserialization",
    "unsafe_xml_parse": "XML entity resolution",
    "path_traversal": "Filesystem paths",
    "xss": "HTML injection",
    "open_redirect": "Open redirects",
    "insecure_randomness": "Insecure randomness",
    "command_injection": "Shell commands",
    "archive_extraction": "Archive extraction",
}
RULE_EXCLUSION_LABELS = {
    "unsupported_extension": "unsupported file types",
    "non_production_path": "test/example paths",
    "dependency_tree": "dependency directories",
    "generated_build": "generated build directories",
    "symlink": "symbolic links",
    "git_metadata": "Git metadata",
}
RULE_SKIP_LABELS = {
    "file_size_limit": "file size limit",
    "file_limit": "file count limit",
    "finding_limit": "finding limit",
    "read_error": "read errors",
    "decode_error": "decoding errors",
    "parse_error": "syntax errors",
    "ast_limit": "syntax-analysis budget",
    "analysis_limit": "expression analysis limit",
    "unsupported_vue_template": "unsupported Vue template language or external template",
    "unsupported_vue_script": "unsupported Vue script language or external script",
}


def _rule_reasons(reasons: dict, labels: dict) -> str:
    return ", ".join(f"{label}: {reasons[key]}" for key, label in labels.items()
                     if reasons.get(key)) or "None recorded"


def _rule_coverage_rows(manifest: dict) -> list[tuple[str, str]]:
    coverage = normalize_rule_coverage(manifest.get("rule_coverage")) or {}
    checks = manifest.get("static_checks") or []
    rows = []
    for rule, label in RULE_COVERAGE_LABELS.items():
        item = coverage.get(rule)
        if item is None:
            if rule in checks:
                rows.append((f"File coverage: {label}", "Not recorded for this audit"))
            continue
        status = ("Partial check." if item["partial"] else
                  "No file-processing gaps recorded within this rule's scope."
                  if item["eligible_files"] else "No eligible files for this rule.")
        rows.append((f"File coverage: {label}",
                     f"{item['analyzed_files']} of {item['eligible_files']} eligible files analyzed; "
                     f"{item['attempted_files']} attempted; {item['skipped_files']} not fully analyzed; "
                     f"{item['excluded_files']} excluded from {item['files_total']} archive files. {status}"))
        rows.append((f"Files excluded: {label}",
                     _rule_reasons(item["exclusion_reasons"], RULE_EXCLUSION_LABELS)))
        rows.append((f"Files not fully analyzed: {label}",
                     _rule_reasons(item["skip_reasons"], RULE_SKIP_LABELS)))
    return rows


def _classified_limits(score: dict) -> tuple[list[str], list[str], list[str]]:
    model, dependency, other = [], [], []
    for reason in (score.get("scan_manifest") or {}).get("limitations") or []:
        if reason == "static_checks_failed" and normalize_check_failures(
                (score.get("scan_manifest") or {}).get("static_checks_not_run")):
            continue  # Rendered with its named check and type-only reason.
        if reason in MODEL_LIMITATIONS or reason.startswith("rubric_failed:"):
            model.append(reason)
        elif reason in SCA_LIMITATIONS:
            dependency.append(reason)
        else:
            other.append(reason)
    return model, dependency, other


def non_model_status_notices(score: dict) -> list[tuple[str, str]]:
    """Keep dependency gaps and unclassified reasons visible above the findings."""
    _, dependency, other = _classified_limits(score)
    manifest = score.get("scan_manifest") or {}
    has_snapshot = manifest.get("dependency_cve") is not None or manifest.get("dependency_snapshot") is not None
    notices = [*cve_notices(manifest.get("sca_cve")),
               *snapshot_notices(manifest.get("dependency_cve"), manifest.get("dependency_snapshot"))]
    agent = agent_record(manifest.get("security_agent"))
    if agent and agent["status"] in {"unavailable", "partial"}:
        notices.append(("Pattern review incomplete", "The coordinator could not complete its bounded plan. "
                        "Existing findings are retained; missing review does not establish safety."))
    if has_snapshot:
        handled = SCOPE_REASONS | {"dependency_snapshot_unavailable"}
        if manifest.get("sca_skipped_reason") == "no_client":
            handled |= {"dependency_coverage_incomplete"}
        dependency = [reason for reason in dependency if reason not in handled]
    failures = normalize_check_failures((score.get("scan_manifest") or {}).get("static_checks_not_run"))
    if failures:
        notices.append(("Static checks failed",
                        "; ".join(f"{item['check']}: {item['reason']}" for item in failures) +
                        ". These checks did not complete. Their missing findings are not a clean result; "
                        "the overall score and affected category scores cannot be used for comparison."))
    coverage = normalize_rule_coverage((score.get("scan_manifest") or {}).get("rule_coverage")) or {}
    incomplete = []
    for rule, label in RULE_COVERAGE_LABELS.items():
        item = coverage.get(rule)
        if item and item["partial"]:
            incomplete.append(
                f"{label}: {item['analyzed_files']} of {item['eligible_files']} eligible files analyzed "
                f"({_rule_reasons(item['skip_reasons'], RULE_SKIP_LABELS)}).")
    if incomplete:
        notices.append(("Static checks incomplete", " ".join(incomplete) +
                        " These counts cover the named rules only. Files not fully analyzed may contain "
                        "additional findings; an empty result does not establish safety."))
    if dependency:
        details = []
        if "dependency_check_not_run" in dependency:
            details.append("The dependency vulnerability database was not queried in this audit.")
        if "dependency_database_unavailable" in dependency:
            details.append("The dependency vulnerability database did not provide a complete answer.")
        if "dependency_lockfile_unreadable" in dependency:
            details.append("A dependency lockfile could not be read.")
        if "dependency_coverage_incomplete" in dependency:
            details.append("Dependency coverage is incomplete; some dependencies could not be checked.")
        if "dependency_snapshot_scope" in dependency:
            details.append("Only the recorded advisory snapshot was considered.")
        if "dependency_runtime_reachability_not_checked" in dependency:
            details.append("Application reachability was not checked.")
        if "dependency_snapshot_unavailable" in dependency:
            details.append("The bundled advisory catalog could not be checked.")
        title = ("Dependency check not run" if set(dependency) == {"dependency_check_not_run"}
                 else "Dependency snapshot scope" if set(dependency) <= SCOPE_REASONS
                 else "Dependency check incomplete")
        if has_snapshot:
            title = ("Live OSV lookup not run" if set(dependency) == {"dependency_check_not_run"}
                     else "Live dependency lookup incomplete")
        notices.append((title, " ".join(details) +
                        " This does not establish the absence of vulnerable dependencies."))
    if other:
        notices.append(("Additional audit limitations recorded",
                        "Recorded reasons: " + ", ".join(other) +
                        ". The affected check is not classified; these reasons do not establish a model failure."))
    return notices


def _limitation_rows(score: dict) -> list[tuple[str, str]]:
    model, dependency, other = _classified_limits(score)
    rows = [("Model limits / skip reasons", ", ".join(model) or "None recorded")]
    if dependency:
        rows.append(("Dependency limits / skip reasons", ", ".join(dependency)))
    if other:
        rows.append(("Other audit limits / skip reasons", ", ".join(other)))
    return rows


def model_status_notice(score: dict) -> tuple[str, str] | None:
    """Describe recorded execution, never infer a payment tier or a project defect."""
    manifest = score.get("scan_manifest") or {}
    reasons, _, _ = _classified_limits(score)
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
    if ("provider" in reasons or "provider_failure" in reasons
            or any(r.startswith("rubric_failed:") for r in reasons)):
        detail += " A model request failed."
    if "cost_cap_exceeded" in reasons or "daily_spend_cap" in reasons or "paid_job_cost_cap" in reasons:
        detail += " A review spending limit was reached."
    if "input_truncated" in reasons:
        detail += " Token accounting suggests possible input truncation; this is not independently verified."
    if "invalid_responses" in reasons:
        detail += " Some model responses could not be read as valid review results."
    if not manifest:
        detail = "The review is recorded as limited. The reason and model execution details were not recorded."
    return title, detail + " This is a limit of the audit, not evidence of a defect in your project."


def model_acceptance_notice(score: dict) -> tuple[str, str] | None:
    """Surface exclusions independently of provider completion and score fields."""
    summary = acceptance_summary((score.get("scan_manifest") or {}).get("model_findings"))
    if not summary or not summary["rejected"]:
        return None
    title = f"Model observations accepted: {summary['accepted']} of {summary['received']}"
    reasons = [("source_rejected", "could not be matched to the cited source"),
               ("withdrawn", "was withdrawn by the model" if summary["withdrawn"] == 1
                else "were withdrawn by the model"),
               ("other_rejected", "failed response validation")]
    detail = "; ".join(f"{summary[key]} {label}" for key, label in reasons if summary[key])
    detail += (". Excluded observations are not included in the findings. "
              "Acceptance checks source citation and response format; "
              "it does not verify conclusions or establish project safety.")
    return title, detail


def _partial_for_display(finding: dict, historical: bool) -> bool:
    record = finding.get("claim_evidence") or {}
    # Retain recorded assessments in history without applying a new disposition.
    return partial_contradicted({**record, "source_assessments": []} if historical else record)


def evidence_label(finding: dict, historical: bool = False) -> str:
    if not historical and unsupported_transport(finding.get("claim_evidence")):
        return "Credential transport — exposure not established"
    if syntax_contradicted(finding.get("claim_evidence")):
        return "Model syntax premise contradicted — see bounded check"
    if _partial_for_display(finding, historical):
        return "Part of the model claim is contradicted — remaining claims need review"
    if not historical and narrative_review_checks(finding.get("claim_evidence")):
        return "Outcome not established — source conditions need review"
    if is_informational(finding):
        return "Deployment inventory — informational"
    source = finding.get("source")
    if source == "dependency" and finding.get("verification_method") == "package_version_match":
        return "Dependency version match — reachability unverified"
    if source == "llm" or str(finding.get("rule_id", "")).startswith("llm-"):
        return "Model hypothesis — unverified"
    if source == "static":
        return "Static signal — unverified"
    return "Legacy finding — verification not recorded"


def _grouped_claim_rows(record: dict, file: str = "", source: str = "") -> list[tuple[str, str]]:
    grouping = record.get("grouped_claim_scope")
    originals = record.get("grouped_originals")
    if (source == "llm" and isinstance(grouping, dict) and grouping.get("mechanism") == "query_read_volume"
            and isinstance(originals, list) and len(originals) > 1
            and valid_query_read_identity(record.get("source_issue_identity"), file)):
        return [("Grouped hypothesis scope", "Grouped by the same source SELECT operation and pagination-bound "
                 "hypothesis only. Original conditions, retention assumptions and claimed costs remain "
                 "separate and unverified; repetition is not independent confirmation.")]
    if (not isinstance(grouping, dict) or grouping.get("mechanism") != "react_network_rejection_cleanup"
            or not isinstance(originals, list) or len(originals) < 2):
        return []
    rows = [("Grouped hypothesis scope",
             "Grouped by the same source operation and network-rejection cleanup hypothesis. "
             "Original conditions and consequences retain their own verification statuses.")]
    identity = record.get("source_issue_identity")
    handler = identity.get("handler") if isinstance(identity, dict) else None
    disagreements = grouping.get("title_source_disagreements")
    if not isinstance(disagreements, list) or not isinstance(handler, str):
        return rows
    if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]{0,127}", handler):
        return rows
    for item in disagreements:
        if not isinstance(item, dict) or item.get("result") != "different_handler_label":
            continue
        index = item.get("original_index")
        if type(index) is not int or not 0 <= index < len(originals) or item.get("source_handler") != handler:
            continue
        rows.append(("Handler label needs review",
                     f"Original {index + 1} uses a different handler label. Bound source handler: {handler}. "
                     "The original wording is retained; its handler label is not verified."))
    return rows


def claim_evidence_rows(finding: dict, historical: bool = False) -> list[tuple[str, str]]:
    """A recorded source check is separate from the model's reading of it."""
    record = finding.get("claim_evidence")
    projection = narrative_projection(finding)
    record = record if isinstance(record, dict) and record.get("version") == 1 else {}
    check = record.get("source_check") or {}
    if check.get("kind") == "quote_match":
        checked = (f"Quoted text matched in source lines {check['line_start']}–{check['line_end']}. "
                   "This does not verify the interpretation.")
    elif check.get("kind") == "static_rule":
        checked = "A static rule emitted this observation. Its consequence was not tested."
    elif finding.get("source") == "dependency" and finding.get("verification_method") == "package_version_match":
        checked = "A locked package version matched an advisory. Application reachability was not checked."
    else:
        checked = "Not recorded for this finding; do not assume the cited code was verified."
    rows = [("Source check", checked)]
    if trace := sql_observation(finding):
        rows.extend([
            ("SQL source trace", f"{trace['assembly_kind']} at line {trace['assembly_line']} → "
             f"{trace['sink_method']}() at line {trace['sink_line']}. Possible local flow; "
             "input control and runtime behavior were not checked."),
            ("SQL source SHA-256", trace["source_sha256"]),
            *sql_driver_rows(trace),
        ])
    if finding.get("source") == "dependency" and finding.get("verification_method") == "package_version_match":
        rows.extend(snapshot_finding_rows(record))
    if not historical and unsupported_transport(record):
        rows.append(("Needs exposure evidence",
                     "This transport-only hypothesis is excluded from the score. Runtime routing, logging "
                     "and credential exposure remain unverified."))
    if _partial_for_display(finding, historical):
        rows.append(("Assessment needs review",
                     "A bounded source check contradicts part of this finding. The original model severity "
                     "remains in the score because the other claims have not been resolved; it is not "
                     "independent confirmation of their impact. Review the source checks before acting."))
    if not historical:
        for assessment in narrative_review_checks(record):
            rows.append(("Outcome needs review", assessment["narrative_review"]["reason"] +
                         " The original model severity remains in the score pending review; "
                         "this observation does not verify the outcome or establish safety."))
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
    for premise in record.get("premise_checks", []):
        label = ("Atomic premise contradicted — other claims remain unverified"
                 if premise.get("result") == "contradicted" else "Parsed output evidence — compare with the model claim"
                 if premise.get("kind") == "zod_unknown_keys_in_write" and premise.get("result") == "observed"
                 else "Atomic premise not checked")
        location = (f" Target {premise['target']}, source lines "
                    f"{premise['source_line_start']}–{premise['source_line_end']}."
                    if premise.get("source_line_start") else "")
        claim = ("Checked Zod input and the parsed write payload."
                 if premise.get("kind") == "zod_unknown_keys_in_write" and premise.get("result") == "observed"
                 else premise["claim"])
        rows.append((label, claim + " " + premise["detail"] + location))
        if premise.get("kind") == "zod_unknown_keys_in_write" and premise.get("source_binding"):
            for path in premise["source_binding"].get("paths", []):
                for write in path.get("writes", []):
                    rows.append(("Checked parsed-output write",
                                 f"{path['file']}:{path['parse_line']} {path['parse_method']} → "
                                 f"{write['file']}:{write['line_start']} {write['method']}. "
                                 "This does not establish that unknown input must be rejected."))
    for assessment in source_assessments(record):
        rows.append(("Source assessment", assessment["detail"]))
        rows.append(("Source assessment binding", json.dumps(assessment, ensure_ascii=False)))
    context_labels = {
        "guard_context": "Existing guard evidence — compare with the model claim",
        "cost_context": "Cost and ordering evidence — compare with the model claim",
        "rls_recommendation_context": "Policy prerequisites — review before changing clients",
    }
    for context in record.get("context_checks", []):
        if context.get("scope") == "bounded_source_context":
            label = ("Bounded source context — compare with the model claim" if context.get("result") == "observed"
                     else "Source context not checked")
            rows.append((label, context["claim"] + " " + context["detail"]))
            if context.get("result") == "observed" and isinstance(context.get("source_binding"), dict):
                rows.append(("Checked source context binding",
                             json.dumps(context["source_binding"], ensure_ascii=False)))
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
    recommendation = record.get("recommendation_check")
    if isinstance(recommendation, dict) and recommendation:
        detail = recommendation.get("detail")
        rows.append(("Recommendation prerequisites", detail if isinstance(detail, str) else "Not recorded."))
        checks = recommendation.get("checks")
        for i, check in enumerate(checks if isinstance(checks, list) else [], 1):
            if not (isinstance(check, dict) and check.get("version") == 1
                    and check.get("result") == "prerequisites_required"
                    and isinstance(check.get("kind"), str) and isinstance(check.get("detail"), str)):
                continue
            scope = check.get("scope") if isinstance(check.get("scope"), str) else ""
            rows.append((f"Recommendation check {i} — prerequisites not verified",
                         check["kind"] + ": " + check["detail"] + " " + scope))
            prerequisites = check.get("prerequisites")
            conditions = ([p for p in prerequisites if isinstance(p, str) and p]
                          if isinstance(prerequisites, list) else [])
            if conditions:
                rows.append((f"Required recommendation conditions {i}", "\n".join(conditions)))
            if isinstance(check.get("reference"), str) and check["reference"]:
                rows.append((f"Recommendation API reference {i}", check["reference"]))
        if isinstance(recommendation.get("original_fix_hint"), str):
            rows.append(("Superseded original recommendation — do not apply without review",
                         recommendation["original_fix_hint"]))
        if isinstance(recommendation.get("original_provenance"), dict) and recommendation["original_provenance"]:
            rows.append(("Superseded recommendation provenance — not independent verification",
                         json.dumps(recommendation["original_provenance"], ensure_ascii=False)))
        superseded = recommendation.get("superseded_fix_hints")
        for i, hint in enumerate(superseded if isinstance(superseded, list) else [], 1):
            if isinstance(hint, str):
                rows.append((f"Superseded intermediate recommendation {i} — do not apply without review", hint))
    rows.extend(_grouped_claim_rows(record, finding.get("file", ""), finding.get("source", "")))
    for i, original in enumerate(record.get("grouped_originals", []), 1):
        rows.append((f"Grouped original {i} — not independent confirmation",
                     json.dumps(original, ensure_ascii=False)))
    if projection:
        rows.append(("Recorded wording correction", "The active wording follows the recorded source check. "
                     "Only the stated premise is corrected; other claims, conditions and consequences "
                     "remain unverified. Severity and score eligibility are unchanged."))
        rows.append(("Original model provenance — not independent confirmation",
                     json.dumps(projection["original"]["producer"], ensure_ascii=False)))
    if record.get("observation"):
        if projection:
            label = "Source interpretation — outcome unverified"
        elif finding.get("source") == "llm" or str(finding.get("rule_id", "")).startswith("llm-"):
            label = "Model interpretation — unverified"
        elif finding.get("source") == "static":
            label = "Static observation — unverified"
        elif finding.get("source") == "dependency":
            label = "Source observation — unverified"
        else:
            label = "Legacy observation — provenance not recorded"
        rows.append((label, record["observation"]))
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
        # EITHER route check earns this label. Auth has two static producers now
        # -- reads and writes -- and a repository whose Python routes are only
        # writes would otherwise read as "Not checked" while a route check did
        # run. The label stays literal about what it establishes: a local route
        # check ran, and broader authorization did not.
        if name == "Auth" and name in skipped and any(
                key in score.get("scan_manifest", {}).get("static_checks", [])
                for key in ("auth_read_consistency", "auth_write_consistency")):
            label = "Local Python route check ran — broader auth not checked"
        if name in score.get("incomplete_static_categories", []):
            label = "Incomplete — static check failed"
        elsewhere = (score.get("reported_elsewhere") or {}).get(name)
        if elsewhere:
            label += " — findings reported under " + ", ".join(elsewhere)
        if count:
            label += f" · {count} unverified finding{'s' if count != 1 else ''}"
        if examples:
            label += f" · {examples} test/example observations"
        rows.append((name, label))
    return rows


def _dependency_row(manifest: dict) -> tuple[str, str]:
    """What was asked about the dependencies, and when.

    Computed HERE, at read time, and not stored with the score: the same
    stored row is served today and in three weeks, and an answer about
    advisories ages. A date recorded at scan time would keep calling itself
    current forever.
    """
    skipped = manifest.get("sca_skipped_reason")
    if manifest.get("dependency_cve") is not None or manifest.get("dependency_snapshot") is not None:
        if skipped == "no_client":
            return ("Live OSV lookup", "Not run. Bundled snapshot results are recorded separately.")
        # This row describes only the network stage when both kinds are recorded.
        return ("Live OSV lookup", _dependency_row({key: value for key, value in manifest.items()
                                                   if key not in {"dependency_cve", "dependency_snapshot"}})[1])
    resolved = manifest.get("sca_dependencies")
    found = manifest.get("sca_dependencies_found")
    if skipped == "no_client":
        if resolved:
            return ("Dependencies checked",
                    "Not checked in this audit. The resolved versions were read "
                    f"from the lockfile ({resolved} packages), but the "
                    "vulnerability database was not queried.")
        return ("Dependencies checked",
                "Not checked in this audit. This check is part of a paid audit.")
    if skipped == "no_lockfile":
        return ("Dependencies checked",
                "No lockfile was found, so there were no resolved versions to "
                "look up. A range in a manifest is not a version, and guessing "
                "one would report on software the project may not install.")
    if skipped == "no_resolved_dependencies":
        return ("Dependencies checked",
                "Supported lockfiles were read but contained no resolved packages "
                "to query. The vulnerability database was not contacted.")
    if skipped == "no_resolvable_lockfile":
        incomplete = manifest.get("sca_incomplete_lockfiles") or {}
        unusable = ", ".join(incomplete or manifest.get("sca_unusable_lockfiles") or []) or "a lockfile"
        return ("Dependencies checked",
                f"Not checked: {unusable} was found, but this scanner could not "
                "establish its resolved dependency inventory. Malformed, unsupported "
                "or unpinned entries are not a clean result. For Go, go.sum lists "
                "every module version the build ever verified; go.mod alone does "
                "not establish the complete selected dependency graph.")
    if isinstance(skipped, str) and skipped.startswith("lockfile_unreadable"):
        return ("Dependencies checked",
                "Not checked: a lockfile was present and could not be read "
                f"({skipped.removeprefix('lockfile_unreadable: ')}). Nothing "
                "about the dependencies was established.")
    if isinstance(skipped, str) and skipped.startswith("osv_unavailable"):
        return ("Dependencies checked",
                f"Not checked: the vulnerability database could not be reached "
                f"or did not provide a complete answer "
                f"({skipped.removeprefix('osv_unavailable: ')}). A missing "
                "answer here is not a clean result.")
    if not manifest.get("sca_asked_at"):
        return ("Dependencies checked", "Not recorded for this audit")
    asked = str(manifest["sca_asked_at"])[:10]
    state = freshness(str(manifest["sca_asked_at"]))
    counted = (f"{resolved} of {found} resolved packages"
               if isinstance(found, int) and found > (resolved or 0)
               else f"{resolved} resolved packages")
    findings = manifest.get("sca_findings")
    found_text = (f"; {findings} reported" if isinstance(findings, int) and findings
                  else "; no medium-or-higher findings reported")
    filtered = manifest.get("sca_below_severity_floor")
    if isinstance(filtered, int) and filtered:
        found_text += f"; {filtered} package(s) had only below-threshold advisories"
    unclear = manifest.get("sca_unreadable_advisories")
    if isinstance(unclear, int) and unclear:
        found_text += (f"; {unclear} advisory record(s) could not be fetched, "
                       "and those matches are reported without their details")
    truncated = manifest.get("sca_findings_truncated")
    if isinstance(truncated, int) and truncated:
        found_text += f"; {truncated} additional package finding(s) omitted by the report limit"
    incomplete = manifest.get("sca_incomplete_lockfiles") or {}
    if isinstance(incomplete, dict) and incomplete:
        found_text += (f"; dependency inventory incomplete for {len(incomplete)} "
                       "lockfile(s), so this is not a complete repository check")
    elif manifest.get("sca_coverage_incomplete"):
        found_text += "; coverage is incomplete"
    aged = ("" if state == "fresh" else
            " This answer was true of that date; advisories published since are "
            "not in it.")
    return ("Dependencies checked",
            f"Queried {asked} against the OSV database: {counted}{found_text}. "
            f"Lockfile versions only; whether vulnerable code is reachable from "
            f"this application was not checked.{aged}")


def security_agent_rows(value: object) -> list[tuple[str, str]]:
    """Explain the saved bounded review without substituting today's catalog.

    Recipe identities and unmet prerequisites are recorded by the coordinator;
    they do not authorize a patch or establish the candidate weakness at runtime.
    The HTML consumers escape every label and value, including archive paths.
    """
    agent = agent_record(value)
    if agent is None:
        return []

    def text(value: object, fallback: str = "Not recorded") -> str:
        return value if isinstance(value, str) and value.strip() else fallback

    def count(value: object) -> str:
        return str(value) if type(value) is int and value >= 0 else "Not recorded"

    def humanize(value: object) -> str:
        return text(value).replace("_", " ")

    stop = agent.get("stop_reason")
    known_stops = {"agent_unavailable", "checks_unavailable", "candidate_budget_exhausted",
                   "coverage_incomplete", "bounded_review_completed", "evidence_collection_incomplete",
                   "synthetic_verification_incomplete", "synthetic_evidence_invalid",
                   "agent_task_failed", "agent_chain_invalid"}
    # Saved diagnostics are untrusted. Only the producer's type-only error
    # form is displayable; never echo exception messages or arbitrary reasons.
    if not (isinstance(stop, str) and (stop in known_stops
            or re.fullmatch(r"agent_error: [A-Za-z_][A-Za-z0-9_]{0,127}", stop))):
        stop = "Stop reason not recorded"
    catalog = agent.get("catalog")
    catalog = catalog if isinstance(catalog, dict) else {}
    source = agent.get("source")
    source = source if isinstance(source, dict) else {}
    budget = agent["budget"]
    has_synthetic = any(isinstance(item, dict) and "synthetic_contract" in item
                        for item in agent["observations"])
    client_runtime = (agent.get("client_runtime")
                      if agent.get("client_runtime_status") == "accepted" else None)
    observation_label = "Python catalog observations" if agent.get("js_sql_review") else "observations"
    rows = [
        ("Pattern review", f"{agent['status']}; {len(agent['observations'])} {observation_label}; "
         f"{stop}. Completion describes bounded review, not project safety."),
        ("Pattern catalog", f"{text(catalog.get('version'), 'Unavailable')}; "
         f"SHA-256: {text(catalog.get('sha256'), 'Unavailable')}"),
        ("Pattern catalog cards", count(catalog.get("cards"))),
        ("Pattern review source", f"Archive SHA-256: {text(source.get('archive_sha256'))}; "
         f"engine: {text(source.get('engine_version'))}."),
        ("Candidate review budget", f"{count(budget.get('processed'))} processed of "
         f"{count(budget.get('candidates_found'))} candidates; "
         f"{count(budget.get('candidates_omitted'))} omitted; "
         f"limit: {count(budget.get('max_candidates'))}."),
        ("Pattern review limits", (
            "Selected static patterns only. Candidate classes remain unverified. "
            "The scanner did not execute the imported client scenario. "
            "Its reported results cover only project CRUD and cross-tenant isolation; "
            "SQL exploit behavior and repair preconditions remain unverified. No automatic patch applied."
            if client_runtime else
            "Selected static patterns only. Candidate classes are unverified; "
            "attacker control and runtime behavior were not checked. "
            + ("Customer project runtime tests not run. No automatic patch applied." if has_synthetic else
               "No runtime tests or automatic patches were run."))),
    ]
    from app.report.js_sql_review import js_sql_review_rows
    rows.extend(js_sql_review_rows(agent.get("js_sql_review"), source))
    if agent.get("js_sql_review_rejected"):
        rows.append(("JavaScript SQL source review", "Saved source review rejected; findings remain unchanged."))
    if client_runtime:
        rows.extend([
            ("Client runtime evidence", "Operator-supplied scenario results accepted for consistency only. "
             "This is not independent runtime attestation or verification of the entire project."),
            ("Client runtime scope", "Project creation, reading, update and archiving; cross-tenant access "
             "denials and database state checks. "
             f"{len(client_runtime['checks'])} reported checks passed. No SQL repair proof is established."),
            ("Client runtime archive SHA-256", client_runtime["archive_sha256"]),
            ("Client runtime run", client_runtime["run_id"]),
            ("Client runtime scenario", client_runtime["scenario_id"]),
            ("Client runtime scenario SHA-256", client_runtime["scenario_sha256"]),
            ("Client runtime evidence SHA-256", client_runtime["evidence_sha256"]),
        ])
    elif agent.get("client_runtime_status") == "rejected":
        rows.append(("Client runtime evidence unavailable", "The supplied client runtime evidence could not "
                     "be validated. Its reported results are not accepted as evidence."))
    plan_labels = {
        "analyzed": "Analyzed within the recorded scope",
        "not_applicable": "No eligible files for this check",
        "partial": "Partial check; coverage is incomplete",
        "unavailable": "Check unavailable; coverage is not established",
    }
    for item in agent["plan"]:
        if not isinstance(item, dict):
            continue
        check = text(item.get("check"))
        status = item.get("status")
        detail = plan_labels.get(status, "Review status not recorded") if isinstance(status, str) else (
            "Review status not recorded")
        detail += f". Pattern: {text(item.get('pattern_id'))}; check: {check}."
        coverage = (normalize_rule_coverage({check: item.get("coverage")}) or {}).get(check)
        if coverage is None:
            detail += " File coverage not recorded."
        else:
            detail += (f" {coverage['analyzed_files']} of {coverage['eligible_files']} eligible files analyzed; "
                       f"{coverage['attempted_files']} attempted; {coverage['skipped_files']} not fully analyzed; "
                       f"{coverage['excluded_files']} excluded from {coverage['files_total']} archive files. "
                       f"Not fully analyzed: {_rule_reasons(coverage['skip_reasons'], RULE_SKIP_LABELS)}. "
                       f"Excluded: {_rule_reasons(coverage['exclusion_reasons'], RULE_EXCLUSION_LABELS)}.")
        rows.append((f"Pattern check: {text(item.get('title'))}", detail))
    if not agent["observations"]:
        rows.append(("Pattern observations",
                     ("No Python catalog candidates recorded. An empty result does not establish safety."
                      if agent.get("js_sql_review") else
                      "No reviewed candidates recorded. An empty result does not establish safety.")))
    displayed = 0
    for index, observation in enumerate(agent["observations"][:128], 1):
        if (not isinstance(observation, dict) or not isinstance(observation.get("file"), str)
                or type(observation.get("line")) is not int or observation["line"] < 1
                or (observation.get("state"), observation.get("next_action")) not in (
                    ("needs_evidence", "manual_review"),
                    ("source_evidence_collected", "review_runtime_contract"),
                    ("synthetic_recipe_verified", "review_project_runtime_contract"),
                )):
            continue
        recipe = observation.get("recipe")
        if (not isinstance(recipe, dict) or recipe.get("automatic_apply") is not False
                or recipe.get("status") not in ("manual_guidance", "not_available")):
            continue
        evidence = observation.get("evidence")
        trace = sql_observation({"source": "static", "rule_id": observation.get("rule_id"),
                                 "file": observation.get("file"), "line": observation.get("line"),
                                 "claim_evidence": {"version": 1, **evidence}}) if isinstance(evidence, dict) else None
        acquisition = normalize_acquisition(observation.get("acquisition"), trace)
        synthetic = normalize_synthetic_contract(observation.get("synthetic_contract"), observation, source, catalog)
        verified = observation.get("state") == "synthetic_recipe_verified"
        collected = observation.get("state") in ("source_evidence_collected", "synthetic_recipe_verified")
        if verified and (synthetic is None or synthetic["status"] != "passed"):
            continue
        if collected and (acquisition is None or acquisition["status"] != "completed"):
            continue
        displayed += 1
        rows.append((f"Pattern observation {index}",
                     f"{text(observation.get('title'))} — {text(observation.get('file'))}:"
                     f"{count(observation.get('line'))}. Pattern: {text(observation.get('pattern_id'))}, "
                     f"revision {count(observation.get('pattern_revision'))}; "
                     f"rule: {text(observation.get('rule_id'))}."))
        weaknesses = observation.get("weaknesses")
        weaknesses = [item for item in weaknesses if isinstance(item, str) and re.fullmatch(r"CWE-[1-9][0-9]*", item)
                      ] if isinstance(weaknesses, list) else []
        rows.append(("Candidate weakness classes",
                     ", ".join(weaknesses) + " — candidate classes, not verified vulnerabilities."
                     if weaknesses else "Not recorded; do not infer a weakness class."))
        rows.append(("Review state", "Saved synthetic recipe evidence passed; customer project runtime behavior "
                     "and repair preconditions remain unverified." if verified else
                     "Supported source evidence collected; runtime behavior and repair "
                     "preconditions remain unverified." if collected else
                     "Needs evidence; the candidate and repair preconditions remain unverified."))
        rows.extend(acquisition_rows(acquisition, trace))
        if synthetic is not None:
            rows.extend(synthetic_contract_rows(synthetic))
        elif "synthetic_contract" in observation:
            rows.append(("Synthetic evidence unavailable", "The saved synthetic evidence could not be validated. "
                         "Customer project runtime behavior remains unverified."))
        if "acquisition" in observation and acquisition is None:
            rows.append(("Source investigation unavailable", "The saved evidence could not be validated. "
                         "Do not treat missing source facts as established."))
        if trace:
            rows.extend([
                ("SQL source trace", f"{humanize(trace['assembly_kind'])} at line {trace['assembly_line']} → "
                 f"{trace['sink_method']}() at line {trace['sink_line']}. Possible local flow; "
                 "input control and runtime behavior were not checked."),
                ("SQL source SHA-256", trace["source_sha256"]),
                *sql_driver_rows(trace),
            ])
        else:
            rows.append(("Source evidence", "Static rule observation only; no additional SQL source trace recorded."))
        missing = observation.get("missing_evidence")
        missing = [item for item in missing if isinstance(item, str)] if isinstance(missing, list) else []
        rows.append(("Missing evidence", "; ".join(humanize(item) for item in missing) if missing else
                     "Not recorded; do not assume the repair preconditions are satisfied."))
        rows.append(("Next step", "Review the customer project runtime contract: confirm authorization, deployed "
                     "reachability, intended value types and expected query behavior before choosing a repair."
                     if verified else "Review the runtime contract: confirm reachability, input control and expected "
                     "query behavior before choosing a repair." if collected else
                     "Manual review: gather the missing evidence before evaluating a repair."))
        guidance = (f"{text(recipe.get('id'))} — manual guidance only; establish the missing preconditions "
                    "before applying the recorded recipe. No automatic patch was applied."
                    if recipe.get("status") == "manual_guidance" and recipe.get("automatic_apply") is False else
                    "No repair recipe available. Manual review is required; no automatic patch was applied.")
        rows.append(("Repair guidance", guidance))
        steps = observation.get("steps")
        steps = [step for step in steps if isinstance(step, dict)] if isinstance(steps, list) else []
        if steps:
            rows.append(("Review steps", "; ".join(f"{humanize(step.get('action'))}: {humanize(step.get('result'))}"
                                                   for step in steps)))
    if displayed < len(agent["observations"]):
        rows.append(("Observation display incomplete", f"{len(agent['observations']) - displayed} records "
                     "could not be displayed within the supported schema and limit."))
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
        _dependency_row(manifest),
        *snapshot_rows(manifest.get("dependency_cve"), manifest.get("dependency_snapshot")),
        *cve_rows(manifest.get("sca_cve")),
        ("Last responding model", manifest.get("model") or "No model response recorded"),
        ("Model responses", str(manifest.get("model_calls", 0))),
        ("Review areas applied", ", ".join(manifest.get("rubrics_completed", [])) or "None"),
    ]
    rows.extend(security_agent_rows(manifest.get("security_agent")))
    accounting = manifest.get("model_findings")
    rows.extend((f"Static check failed: {item['check']}", item["reason"])
                for item in normalize_check_failures(manifest.get("static_checks_not_run")))
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
    diagnostics = manifest.get("rejection_diagnostics")
    if isinstance(diagnostics, dict) and diagnostics.get("version") == 1:
        safe = diagnostics_manifest({"rejected_items": diagnostics.get("items"),
                                     "rejected_items_omitted": diagnostics.get("omitted", 0)})
        if safe:
            rows.append(("Rejection diagnostic scope",
                         "Bounded metadata only; source path SHA-256 references identify known paths. "
                         "Rejected text, quotes and unknown paths are not retained. "
                         f"Additional records omitted: {safe['omitted']}."))
            for item in safe["items"]:
                rows.append((f"Rejected observation {item['response']}:{item['item']}",
                             json.dumps(item, ensure_ascii=False)))
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
    rows.extend(_limitation_rows(score))
    for check, status in manifest.get("static_limits", {}).items():
        rows.append((f"Static scope: {check}", str(status)))
    rows.extend(_rule_coverage_rows(manifest))
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
