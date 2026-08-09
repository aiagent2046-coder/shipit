"""Static scan stage: run all deterministic scanners, normalize, score."""

from __future__ import annotations

from typing import BinaryIO

from app.scan.checks import run_checks
from app.scan.scoring import ScoredFinding, compute_scores
from app.scan.secrets import scan_secrets


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
    for c in run_checks(fileobj):
        findings.append(ScoredFinding(
            rule_id=c.rule_id, title=c.title, severity=c.severity,
            confidence=c.confidence, category=c.category, file=c.file,
            explanation=c.explanation, fix_hint=c.fix_hint,
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
    }
