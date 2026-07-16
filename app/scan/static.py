"""Static scan stage: run all deterministic scanners, normalize, score."""

from __future__ import annotations

from typing import BinaryIO

from app.scan.checks import run_checks
from app.scan.scoring import ScoredFinding, compute_scores
from app.scan.secrets import scan_secrets


def run_static_scan(fileobj: BinaryIO) -> dict:
    """Returns {"score": {...}, "findings": [ScoredFinding-as-dict]}."""
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
        ))

    return {
        "score": compute_scores(findings),
        "findings": [vars(f) for f in findings],
    }
