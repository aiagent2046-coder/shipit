"""Production Readiness Score.

score = 10 − Σ(severity_weight × confidence), clamped to [0..10].
Per-category subscores use the same formula over that category's
findings. See shipit-architecture.md, section 2.2 stage C.
"""

from __future__ import annotations

from dataclasses import dataclass

SEVERITY_WEIGHT = {"critical": 2.0, "high": 1.0, "medium": 0.4, "low": 0.1}

CATEGORIES = ("Security", "Auth", "Correctness", "Config", "Testing", "Deploy")


@dataclass(frozen=True)
class ScoredFinding:
    """Normalized finding shape shared by all scanners."""
    rule_id: str
    title: str
    severity: str
    confidence: float
    category: str
    file: str = ""
    line: int = 0
    masked: str = ""


def _score(findings: list[ScoredFinding]) -> float:
    penalty = sum(
        SEVERITY_WEIGHT[f.severity] * f.confidence for f in findings
    )
    return round(max(0.0, min(10.0, 10.0 - penalty)), 1)


def compute_scores(findings: list[ScoredFinding]) -> dict:
    by_cat = {
        cat: _score([f for f in findings if f.category == cat])
        for cat in CATEGORIES
    }
    return {"total": _score(findings), "categories": by_cat}
