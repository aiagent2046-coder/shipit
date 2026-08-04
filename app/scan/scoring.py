"""Production Readiness Score, v2.

Per-category subscore = 10 − Σ(severity_weight × confidence) over that
category's findings, clamped to [0..10]. Total = weighted mean of the
category subscores.

v1 computed total as one global 10 − Σ(...), which saturated at 0.0
for typical vibe-coded repos (6 of 10 real repos in the first batch
run scored exactly 0.0): one noisy category, or one anti-pattern
repeated across many files, zeroed the whole scale, destroying both
differentiation and reproducibility measurement (clamping hides
variance). With per-category floors, a repo drowning in one category
still gets credit for the others. See shipit-architecture.md 2.2 C.
"""

from __future__ import annotations

from dataclasses import dataclass

SEVERITY_WEIGHT = {"critical": 2.0, "high": 1.0, "medium": 0.4, "low": 0.1}

# Only categories a producer can actually assign. "Correctness" and "Config"
# used to be here and were removed: nothing ever emitted a finding in either,
# so both scored a constant 10.0 and together carried 25% of the weight. The
# effect was a scale whose bottom half was unreachable -- a repository with a
# totally failed Security category still totalled 7.5, and audit 0a043539
# (vercel/nextjs-subscription-payments) scored 8.1 while holding a committed
# .env, a subscriptions table with no write RLS policies and two open
# redirects. See issue #181.
#
# Producers, for whoever adds the next category: app/scan/checks.py emits
# Security, Testing and Deploy; the secret rules in app/scan/secrets.py emit
# Security; the two rubrics in app/scan/llm_scan.py map to Auth and Security.
# Adding a name here without adding a producer re-creates the same dead weight.
CATEGORIES = ("Security", "Auth", "Testing", "Deploy")

# Weighted mean for the total. Security and Auth dominate because the product's
# wedge is "safe to put in production".
#
# Declared as the original raw weights and normalised, rather than as
# pre-divided decimals: it keeps the relative importance of the four survivors
# exactly as it was chosen (0.25 : 0.20 : 0.15 : 0.15), makes "sums to 1" true
# by construction instead of by assertion, and means dropping or adding a
# category is a one-line edit that cannot silently stop summing to 1.
_RAW_CATEGORY_WEIGHT = {
    "Security": 0.25, "Auth": 0.20, "Testing": 0.15, "Deploy": 0.15,
}
_RAW_TOTAL = sum(_RAW_CATEGORY_WEIGHT.values())
CATEGORY_WEIGHT = {k: v / _RAW_TOTAL for k, v in _RAW_CATEGORY_WEIGHT.items()}
assert set(CATEGORY_WEIGHT) == set(CATEGORIES)
assert abs(sum(CATEGORY_WEIGHT.values()) - 1.0) < 1e-9


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
    # Plain-language layer: what this means for a non-technical owner
    # and what to do about it. Filled from the rule dictionary for
    # static findings and from the model's own explanation/fix_hint for
    # LLM findings (previously dropped on the floor).
    explanation: str = ""
    fix_hint: str = ""
    # Machine-readable damping/eligibility context, propagated from the
    # scanner (see SecretFinding.context). "test_fixture" when a finding
    # was damped as a test-fixture placeholder, None otherwise. Lets
    # downstream consumers (the future Fix Pack filter) branch reliably
    # instead of string-matching the title suffix.
    context: str | None = None


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
    total = round(sum(by_cat[c] * CATEGORY_WEIGHT[c] for c in CATEGORIES), 1)
    if findings and total == 10.0:
        total = 9.9  # a perfect 10 with a non-empty findings list is a lie
    return {"total": total, "categories": by_cat}
