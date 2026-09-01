"""Static scan stage: run all deterministic scanners, normalize, score."""

from __future__ import annotations

from typing import BinaryIO

from app.scan.checks import run_checks
from app.scan.ci_deploy_source import scan_ci_deploy_source
from app.scan.error_boundary import scan_error_boundary
from app.scan.rls import scan_rls
from app.scan.schema_drift import scan_schema_drift
from app.scan.scoring import ScoredFinding, compute_scores
from app.scan.secrets import scan_secrets
from app.scan.service_role import scan_service_role


def run_static_scan(fileobj: BinaryIO) -> dict:
    """Returns {"score": {...}, "findings": [ScoredFinding-as-dict]}.

    The score here describes THIS stage only. app/scan/pipeline.py reads just
    the findings and recomputes the total once it knows whether the LLM stage
    ran, so an audit's real headline never comes from this key -- but callers
    that use it directly (the tests, and anything added later) must not be
    handed a number computed on a premise this function contradicts.
    """
    findings: list[ScoredFinding] = []

    fileobj.seek(0)
    for s in scan_secrets(fileobj):
        findings.append(ScoredFinding(
            rule_id=s.rule_id, title=s.title, severity=s.severity,
            confidence=s.confidence, category="Security",
            file=s.file, line=s.line, masked=s.masked, context=s.context,
        ))

    fileobj.seek(0)
    for r in scan_rls(fileobj):
        findings.append(ScoredFinding(
            rule_id=r.rule_id, title=r.title, severity=r.severity,
            confidence=r.confidence, category=r.category, file=r.file,
            explanation=r.explanation, fix_hint=r.fix_hint,
        ))

    fileobj.seek(0)
    for d in scan_schema_drift(fileobj):
        findings.append(ScoredFinding(
            rule_id=d.rule_id, title=d.title, severity=d.severity,
            confidence=d.confidence, category=d.category, file=d.file,
            explanation=d.explanation, fix_hint=d.fix_hint,
        ))

    fileobj.seek(0)
    for c in run_checks(fileobj):
        findings.append(ScoredFinding(
            rule_id=c.rule_id, title=c.title, severity=c.severity,
            confidence=c.confidence, category=c.category, file=c.file,
            line=c.line, explanation=c.explanation, fix_hint=c.fix_hint,
        ))

    fileobj.seek(0)
    for d in scan_ci_deploy_source(fileobj):
        findings.append(ScoredFinding(
            rule_id=d.rule_id, title=d.title, severity=d.severity,
            confidence=d.confidence, category=d.category, file=d.file,
            line=d.line, explanation=d.explanation, fix_hint=d.fix_hint,
        ))

    fileobj.seek(0)
    for h in scan_service_role(fileobj):
        findings.append(ScoredFinding(
            rule_id=h.rule_id, title=h.title, severity=h.severity,
            confidence=h.confidence, category=h.category, file=h.file,
            line=h.line, explanation=h.explanation, fix_hint=h.fix_hint,
        ))

    # The first static producer for Frontend. Wired on a number measured in
    # this repository (DRYDOCK_LENS_PLAN.md): 11 of 12 mounted apps in the
    # audited corpus ship no error boundary above their routes, the hits on
    # the most reputable repositories read by hand. The three-strata figure
    # is reproducible with `scripts/measure_error_boundary.py --strata`. This
    # is what took Frontend out of LLM_ONLY_CATEGORIES in scoring.py.
    fileobj.seek(0)
    boundary = scan_error_boundary(fileobj)
    for b in boundary.findings:
        findings.append(ScoredFinding(
            rule_id=b.rule_id, title=b.title, severity=b.severity,
            confidence=b.confidence, category=b.category, file=b.file,
            line=b.line, explanation=b.explanation, fix_hint=b.fix_hint,
        ))

    return {
        # llm_ran=False, not the default: no LLM stage runs inside this
        # function, so Auth and Money & Data sit at 10.0 for want of a
        # producer. Taking the default let those two vote on this mean --
        # 42% of the weight pinned at "clean" because nothing had looked --
        # which is the exact defect LLM_ONLY_CATEGORIES exists to prevent,
        # reached by leaving an argument out rather than by passing it wrong.
        "score": compute_scores(findings, llm_ran=False),
        "findings": [vars(f) for f in findings],
        # Carried, not folded into a finding: `budget_exhausted` means the
        # boundary scan stopped before it could say a boundary is absent, so
        # no finding was emitted AND Frontend's clean read is unearned for this
        # repository. A scanner that found nothing and one that gave up must
        # not look identical (#392). Consuming this in the pipeline/report is
        # the follow-up; here it is preserved so it can be.
        "coverage": {"error_boundary": boundary.coverage},
    }
