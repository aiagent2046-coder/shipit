"""Report and outreach drafts.

Two documents, deliberately different:
  - full technical report: everything we can prove, with the engine's
    limitations carried verbatim. This is the deliverable behind a contract
    or a public disclosure timeline.
  - outreach letter: a short, honest teaser for the rights holder - enough
    to prove the finding is real, no exploit detail, plus the contract offer.
"""
from __future__ import annotations

from datetime import date

from scout.engine import ScanResult, _effective_severity, _exploitation, rank


def _finding_row(finding: dict) -> str:
    claim = finding.get("claim_evidence") or {}
    advisory = claim.get("advisory_id") or (claim.get("advisory_ids") or ["-"])[0]
    package = claim.get("package", "?")
    version = claim.get("installed_version", "?")
    scope = claim.get("dependency_scope", "?")
    ev = _exploitation(finding)
    return (
        f"| {advisory} | {package} {version} | {scope} | "
        f"{_effective_severity(finding)} | {ev} | {finding.get('confidence', '')} |"
    )


def render_report(result: ScanResult) -> str:
    kev = result.kev_listed
    crit = result.critical
    lines = [
        f"# External security assessment: {result.target or 'target'}",
        "",
        f"Date: {date.today().isoformat()}",
        (f"Engine: drydock (shipit) @ {result.engine_commit or 'unknown'}, "
         f"catalog sha256 {result.catalog_digest[:16]}..."),
        f"Artifacts analyzed: {', '.join(result.artifacts) or 'none'}",
        "",
        "## Executive summary",
        "",
        f"- Findings total: {len(result.findings)}",
        f"- CISA KEV-listed (actively exploited in the wild): {len(kev)}",
        f"- Effective critical (incl. KEV escalation): {len(crit)}",
    ]
    if result.stack_hints:
        lines.append(f"Stack hints (passive signals, not proof): "
                     f"{', '.join(result.stack_hints)}")
    lines.append("")
    if kev:
        lines += [
            "## CISA KEV: exploitation confirmed in the wild",
            "",
            "| Advisory | Package | Scope | Severity | Exploitation | Confidence |",
            "|---|---|---|---|---|---|",
        ]
        lines += [_finding_row(f) for f in kev]
        lines += [
            "",
            ("These vulnerabilities appear in the CISA Known Exploited "
             "Vulnerabilities catalog, meaning exploitation is not hypothetical."),
            "",
        ]
    rest = [f for f in result.findings if f not in kev]
    if rest:
        lines += [
            "## Other matched advisories",
            "",
            "| Advisory | Package | Scope | Severity | Exploitation | Confidence |",
            "|---|---|---|---|---|---|",
        ]
        lines += [_finding_row(f) for f in rest]
        lines.append("")
    lines += [
        "## Coverage",
        "",
        f"- Dependencies found: {result.coverage.get('dependencies_found', 0)}",
        f"- Dependencies checked: {result.coverage.get('dependencies_checked', 0)}",
        f"- Manifests: {', '.join(result.coverage.get('manifests') or []) or 'none'}",
        "",
        "## Limitations (carried from the engine, unchanged)",
        "",
    ]
    lines += [f"- {item}" for item in result.limitations]
    lines += [
        "",
        "## Disclosure",
        "",
        ("This assessment used only publicly available artifacts and passive "
         "requests. No exploitation was attempted and no data was accessed. "
         "Per ISO/IEC 29147 we offer 90 days before any publication."),
    ]
    return "\n".join(lines)


def render_outreach(result: ScanResult, contact: str | None) -> str:
    """The letter the rights holder receives first. Proof, not exploitation."""
    kev = result.kev_listed
    top = kev[:3] if kev else result.findings[:3]
    names = ", ".join(
        (f.get("claim_evidence") or {}).get("advisory_id", f.get("title", ""))
        for f in top
    ) or "none"
    to = contact or "(contact not published - see security.txt / repository metadata)"
    return f"""To: {to}
Subject: Security finding in {result.target or 'your project'} - coordinated disclosure

Hello,

we perform independent, passive security research on public projects.
Using only publicly available artifacts of your project we identified
security findings matched against the CISA KEV and CVE advisory data:

  - KEV-listed (actively exploited) findings: {len(kev)}
  - total matched advisories: {len(result.findings)}
  - top items: {names}

We have not attempted exploitation and have accessed no non-public data.
We are ready to share the full technical report with evidence and
remediation guidance. For depth analysis (root cause, reachability,
affected systems, database exposure) we offer a contract for an
authorized assessment with full access.

Coordinated disclosure timeline: 90 days, per ISO/IEC 29147.

Regards,
independent security research
"""


def _llm_basis_line(llm: object) -> str:
    if isinstance(llm, dict):
        if llm.get("failure"):
            return f"LLM stage: partial - {llm['failure']}"
        if llm.get("skipped_reason"):
            return f"LLM stage: skipped ({llm['skipped_reason']})"
        return (f"LLM stage: ran ({llm.get('prompts', 0)} prompts, "
                f"{llm.get('verified', 0)} verified findings)")
    return f"LLM stage: {llm}"


def _collect_limitations(node: object) -> list[str]:
    """Every 'limitations' list in the scan manifest, verbatim, deduped."""
    out: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "limitations" and isinstance(value, list):
                out.extend(str(item) for item in value)
            else:
                out.extend(_collect_limitations(value))
    elif isinstance(node, list):
        for item in node:
            out.extend(_collect_limitations(item))
    seen: set[str] = set()
    unique: list[str] = []
    for line in out:
        if line not in seen:
            seen.add(line)
            unique.append(line)
    return unique


def render_deep_report(audit: dict, db_evidence: list[dict] | None = None) -> str:
    """The contract deliverable: root cause, reachability, DB exposure.

    Everything is a fact from the shipped pipeline, an explicitly labelled
    operator observation, or the engine's own limitation text - verbatim.
    The basis line answers what actually ran, never what was intended.
    """
    result = audit.get("result") or {}
    score = result.get("score") or {}
    findings = rank(list(result.get("findings") or []))
    llm = result.get("llm")
    sca = result.get("sca") or {}
    manifest = score.get("scan_manifest") or {}
    kev = [f for f in findings if _exploitation(f) == "listed"]

    lines = [
        f"# Deep security assessment: {audit.get('target') or 'target'}",
        "",
        f"Date: {date.today().isoformat()}",
        f"Contract: {audit.get('contract_id') or 'unknown'}",
        f"Engine: drydock (shipit) @ {audit.get('engine_commit') or 'unknown'}",
        f"Assessment basis: {score.get('basis') or 'unknown'}",
        "",
        "## Assessment basis",
        "",
        f"- {_llm_basis_line(llm)}",
        (f"- Dependency stage: "
         f"{'asked ' + str(sca.get('asked_at')) if sca.get('asked_at') else 'not asked (inventory never sent)'}, "
         f"{sca.get('advisories', 0)} advisories matched"),
        (f"- Score: {score.get('total')} "
         f"(categories: {score.get('categories') or {}})"),
        f"- CISA KEV-listed (actively exploited in the wild): {len(kev)}",
        "",
        "## Findings (KEV-listed first)",
        "",
        "| Advisory | Package | Scope | Severity | Exploitation | Confidence |",
        "|---|---|---|---|---|---|",
    ]
    for finding in findings:
        lines.append(_finding_row(finding))
    if not findings:
        lines.append("| - | - | - | - | - | - |")

    lines += [
        "",
        "## Root cause and reachability",
        "",
        ("Each finding below carries what the engine proved and no more: "
         "static observations of source and dependency state. Runtime "
         "reachability, attacker control and exploitation are not verified "
         "unless an evidence field says so explicitly."),
        "",
    ]
    for finding in findings[:25]:
        lines.append(f"### {finding.get('title') or 'untitled finding'}")
        claim = finding.get("claim_evidence") or {}
        for key in sorted(claim):
            value = str(claim[key]).replace("\n", " ")
            lines.append(f"- {key}: {value[:300]}")
        if not claim:
            lines.append("- (no structured evidence attached)")
        lines.append("")
    if len(findings) > 25:
        lines += [f"... {len(findings) - 25} more findings in the audit JSON.", ""]

    lines += ["## Database exposure", ""]
    if db_evidence:
        lines.append("Operator-supplied observations from the authorized "
                     "read-only session (audit-logged per query):")
        lines.append("")
        for item in db_evidence:
            lines.append(f"- {item.get('label') or 'observation'}: "
                         f"{item.get('observation') or ''}")
    else:
        lines.append("Not examined in this engagement. Absence of evidence "
                     "is not evidence of safety: a database exposure review "
                     "requires the authorized read-only session "
                     "(`scout db query`) under this contract.")
    lines += [
        "",
        "## Limitations (carried from the engine, unchanged)",
        "",
    ]
    limitations = _collect_limitations(manifest)
    for note in limitations:
        lines.append(f"- {note}")
    if isinstance(llm, dict) and llm.get("failure"):
        lines.append(f"- llm stage incomplete: {llm['failure']}")
    if isinstance(llm, dict) and llm.get("skipped_reason"):
        lines.append(f"- llm stage skipped: {llm['skipped_reason']}")
    if not sca.get("asked_at"):
        lines.append("- dependency advisories were not queried from any "
                     "external database in this run")
    lines.append("- per-check scope statements (what each static rule does "
                 "and does not read) travel verbatim in the audit JSON")
    return "\n".join(lines) + "\n"
