"""Read-only next steps grounded in the current report's recorded scope.

Tasks are questions and review work, not vulnerability confirmations, repairs,
or a project-readiness judgement. Historical observations are not inputs.
"""
from __future__ import annotations

from app.report.owner_report import build_owner_report, dependency_coverage_gap

_ASCII_WHITESPACE = " \t\n\r\v\f"


_REVIEW_TASKS = {
    "dependency-advisory-review": {
        "title": "Review the matched library versions and how they are used",
        "why": ("The report matches recorded library versions to advisory entries. A match does not establish "
                "that affected functionality is used or exploitable in this application."),
        "action": ("Group the linked matches by library, ecosystem, and installed version. Separate application "
                   "dependencies, development dependencies, and unknown use from the recorded evidence. "
                   "Review each advisory and check whether its conditions apply before choosing an update "
                   "or other action."),
        "owner": "Developer responsible for dependencies",
        "needs": ["The linked library versions, advisory references, and manifest locations.",
                  "How each library is installed and used in the application, development, or tests."],
        "done_when": ("For each library/version group, record its use, the applicable advisory conditions, "
                      "any unanswered questions, and the chosen next step. A proposed update still needs compatibility "
                      "testing and a new check; this review does not verify a fix."),
    },
    "html-input-review": {
        "title": "Find out where inserted HTML comes from",
        "why": ("The source observation records a value being inserted as HTML. It does not establish "
                "who controls that value, whether it is sanitized, or what happens in the browser."),
        "action": ("Trace each linked value to its source, identify who can change it, and review any checks "
                   "before insertion. Decide whether markup is needed and whether the existing handling is suitable."),
        "owner": "Frontend developer",
        "needs": ["The linked HTML insertion locations and the code that supplies their values.",
                  "Examples of intended content and any validation or sanitization rules."],
        "done_when": ("Record each value's source, control, and handling. Document the decision and any focused "
                      "browser check still needed; source review alone does not confirm an exploit or a fix."),
    },
    "test-credential-review": {
        "title": "Check whether credential-like values in tests are synthetic",
        "why": ("The scanner found credential-like assignments in test files. The pattern does not establish "
                "that these values are live credentials or accepted by a service."),
        "action": ("Ask the test maintainer to confirm where the values came from and whether they are synthetic. "
                   "If a real exposed credential is confirmed, arrange replacement or revocation with its owner; "
                   "synthetic fixtures do not require account-level rotation."),
        "owner": "Test maintainer and credential owner, if applicable",
        "needs": ["The linked test locations and the purpose of their fixtures.",
                  "Confirmation from the person responsible for the values; "
                  "do not copy secret values into the review."],
        "done_when": ("Record whether each value is synthetic, real, or still unknown and the corresponding next step. "
                      "Record no secret values and do not claim revocation or replacement until separately confirmed."),
    },
    "ui-error-handling-review": {
        "title": "Review how the interface handles rendering errors",
        "why": ("The static check did not identify the expected error-handling boundary. It does not establish "
                "that the running interface fails or that framework-provided handling is absent."),
        "action": ("Review the actual application entry points, routes, and framework error handling. Agree what "
                   "users should see after a rendering error and plan a focused check of that recovery path."),
        "owner": "Frontend developer",
        "needs": ["The linked entry points, route setup, and existing error-handling code.",
                  "The expected fallback screen and recovery action for users."],
        "done_when": ("Document the existing handling, any gap requiring a change, and the planned or observed "
                      "recovery check. Keep untested interface behavior explicitly unverified."),
    },
    "archive-content-review": {
        "title": "Check why dependency-like directories are in the archive",
        "why": ("The archive contains a directory commonly used for installed dependencies or generated files. "
                "Its name does not establish Git tracking or whether the contents should be removed."),
        "action": ("Identify whether the linked directories contain reproducible dependencies, generated files, "
                   "intentional vendored source, or test data. Check the archive's packaging rules and, if relevant, "
                   "Git tracking before deciding what to retain or exclude."),
        "owner": "Developer responsible for packaging",
        "needs": ["The linked archive directories and the instructions used to assemble the archive.",
                  "The purpose of the included files and, if relevant, evidence of Git tracking."],
        "done_when": ("Record what belongs in the archive and why, and how any excluded dependencies or generated "
                      "files can be recreated. Do not record a deletion or Git change as completed without evidence."),
    },
}


def _review_group(finding: dict) -> str | None:
    evidence = finding.get("claim_evidence")
    if evidence is not None:
        if not isinstance(evidence, dict):
            return None
        syntax = evidence.get("syntax_check")
        if (syntax is not None and not isinstance(syntax, dict)
                or isinstance(syntax, dict) and syntax.get("result") == "contradicted"
                or any(evidence.get(key) not in (None, []) for key in ("source_assessments", "premise_checks"))):
            return None
    if finding.get("verification_status") == "contradicted":
        return None
    source, rule, context = finding.get("source"), finding.get("rule_id"), finding.get("context")
    if source == "dependency" and rule == "dependency-cve-match" and context in (None, ""):
        return "dependency-advisory-review"
    if source != "static":
        return None
    if rule == "generic-assignment" and context == "test_file":
        return "test-credential-review"
    if context not in (None, ""):
        return None
    if rule == "xss-unsafe-html-injection":
        return "html-input-review"
    if rule == "missing-error-boundary":
        return "ui-error-handling-review"
    if rule == "dependency-dir-committed":
        return "archive-content-review"
    return None


def _valid_finding(value: object) -> bool:
    return isinstance(value, dict) and any(
        isinstance(value.get(key), str) and bool(value[key].strip(_ASCII_WHITESPACE))
        for key in ("rule_id", "title")
    )


def build_owner_roadmap(findings: list[dict], context: dict | None = None) -> dict:
    """Group follow-up work without changing original findings or evidence."""
    findings = findings if isinstance(findings, list) else []
    context = context if isinstance(context, dict) else {}
    cards = build_owner_report(findings, context)["cards"]
    file_indices = [card["finding_index"] for card in cards]
    deployment_indices = [
        index for index, finding in enumerate(findings)
        if isinstance(finding, dict) and finding.get("rule_id") == "no-dockerfile"
        and finding.get("source") == "static"
    ]
    covered = set(file_indices + deployment_indices)
    groups: dict[str, list[int]] = {name: [] for name in _REVIEW_TASKS}
    remaining_indices = []
    for index, finding in enumerate(findings):
        if not _valid_finding(finding) or index in covered:
            continue
        group = _review_group(finding)
        if group:
            groups[group].append(index)
        else:
            remaining_indices.append(index)
    tasks = []
    if file_indices:
        tasks.append({
            "id": "file-loading-origin", "stage": "first", "kind": "investigate",
            "title": "Find out who supplies and can change loaded files",
            "why": ("The recorded file-loading calls need a trust check; source review alone does not establish "
                    "a runtime problem."),
            "action": ("For every linked location, identify who produces the file, who can change it, "
                       "and what checks happen before it is loaded."),
            "owner": "Project owner and developer",
            "needs": ["The linked file-loading observations.",
                      "The people or services that create, store, and deliver these files."],
            "depends_on": [],
            "done_when": ("Each linked location has a recorded file producer, write access, and trust check, "
                          "or an explicitly named unanswered question."),
            "finding_indices": file_indices, "coverage_refs": [],
        })
    dependency_gap = dependency_coverage_gap(context)
    if dependency_gap:
        unresolved = dependency_gap["unresolved_manifests"]
        tasks.append({
            "id": "dependency-coverage", "stage": "first", "kind": "provide_information",
            "title": "Clarify the gaps in dependency checking",
            "why": ("The report records incomplete or unavailable dependency checking; the gaps do not establish "
                    "whether the dependencies are safe."),
            "action": ("Check the recorded dependency gaps and provide the exact installed versions or matching "
                       "lockfiles for the unresolved manifests."
                       if unresolved else
                       "Read the recorded dependency gaps, identify what information or checking capability "
                       "is missing, and agree how to obtain it."),
            "owner": "Developer",
            "needs": ["The recorded dependency coverage and its limitations."]
                     + ["Unresolved manifest: " + path for path in unresolved],
            "depends_on": [],
            "done_when": ("Record the cause of each gap, the information supplied or next check needed, "
                          "and any limitations that remain. A later scan must record its own coverage."),
            "finding_indices": [], "coverage_refs": ["dependency_cve"],
        })
    for name, template in _REVIEW_TASKS.items():
        if groups[name]:
            tasks.append({**template, "id": name, "stage": "first", "kind": "review",
                          "needs": list(template["needs"]), "depends_on": [],
                          "finding_indices": groups[name], "coverage_refs": []})
    if remaining_indices:
        tasks.append({
            "id": "remaining-observations", "stage": "first", "kind": "review",
            "title": "Review the other recorded observations",
            "why": ("These observations need their own evidence and context reviewed before deciding whether "
                    "any action is warranted."),
            "action": ("Review each linked observation with its original evidence, limits, and test or example "
                       "context. Record what is supported, contradicted, or still unknown and decide the next step."),
            "owner": "Developer",
            "needs": ["The original linked observations and their evidence.",
                      "Someone familiar with the affected part of the project."],
            "depends_on": [],
            "done_when": ("Each linked observation has a documented assessment and a next step or a reason no change "
                          "is needed; unverified claims remain marked as unverified."),
            "finding_indices": remaining_indices, "coverage_refs": [],
        })
    if file_indices:
        tasks.append({
            "id": "file-loading-decision", "stage": "after", "kind": "review",
            "title": "Decide whether file-loading protection needs to change",
            "why": ("The right decision depends on where the files come from, who can change them, "
                    "and the checks already in place."),
            "action": ("Review the file-origin answers with a developer. If protection needs to change, choose an "
                       "approach compatible with existing files and plan a focused check of normal use "
                       "and rejected input."),
            "owner": "Developer",
            "needs": ["The file-origin answers, including unresolved questions.",
                      "Examples of legitimate files and their expected use."],
            "depends_on": ["file-loading-origin"],
            "done_when": ("Document the decision and its evidence for each linked location. If a change is needed, "
                          "record the compatibility requirements and how the change will be tested; "
                          "this task does not certify a fix."),
            "finding_indices": list(file_indices), "coverage_refs": [],
        })
    runtime_unverified = context.get("runtime_verified") is False
    if runtime_unverified or deployment_indices:
        tasks.append({
            "id": "deployment-check", "stage": "when_needed", "kind": "verify",
            "title": "Check the intended way to run the project",
            "why": ("The report records that application behavior has not been verified."
                    if runtime_unverified else
                    "A deployment inventory observation describes files in the archive; it does not establish "
                    "whether the application can run."),
            "action": ("When preparing a deployment, confirm the intended hosting method, configuration, and startup "
                       "steps, then run a basic user journey in an isolated test environment. "
                       "Docker is only one possible hosting option."),
            "owner": "Developer or person responsible for deployment",
            "needs": ["The intended hosting method and required configuration.",
                      "An isolated test environment and an agreed basic user journey."],
            "depends_on": [],
            "done_when": ("Record the tested version, setup, steps, and actual results, including what was not tested. "
                          "This does not verify every application behavior."),
            "finding_indices": deployment_indices,
            "coverage_refs": ["runtime_verified"] if runtime_unverified else [],
        })
    return {"version": 1, "tasks": tasks}
