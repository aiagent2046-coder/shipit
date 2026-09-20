"""Read-only next steps grounded in the current report's recorded scope.

Tasks are questions and review work, not vulnerability confirmations, repairs,
or a project-readiness judgement. Historical observations are not inputs.
"""
from __future__ import annotations

from app.report.owner_report import build_owner_report

_ASCII_WHITESPACE = " \t\n\r\v\f"


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
    remaining_indices = [index for index, finding in enumerate(findings)
                         if _valid_finding(finding) and index not in covered]
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
    dependency = context.get("dependency_cve")
    if isinstance(dependency, dict) and dependency.get("status") in ("partial", "unavailable"):
        manifests = dependency.get("incomplete_manifests")
        unresolved = sorted(path for path, reason in manifests.items()
                            if isinstance(path, str) and path.strip(_ASCII_WHITESPACE) and reason == "unresolved") \
            if isinstance(manifests, dict) else []
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
