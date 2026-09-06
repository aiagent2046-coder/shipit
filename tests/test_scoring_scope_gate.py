"""A score may not read as a pass over a report that is not about the code.

MEASURED, and it is why this exists. donjonson-hash/devtools-aggregator was
re-audited on 2026-08-20 with `ci-deploys-a-different-repository` live. The
rule fired, correctly and with the right words — its CI builds the audited
repository and then resets the server to somebody else's. The headline moved

    9.9  ->  9.8

and the ring stayed green.

The arithmetic is not a bug: one high finding at 0.8 confidence charges 0.8 to
Deploy, five other categories sit at 10.0, and the mean barely moves. That is
what every mechanism in scoring.py does — penalise inside a category — and it
is the wrong instrument for this claim. A critical says the code is dangerous.
This says the report may not be about the running code, which is a statement
about the report, and a statement about the report cannot be averaged with
five categories that were computed from the wrong repository in the first
place.

So it joins the gate, which already exists to stop a flattering headline,
already publishes its reason next to the number, and already scales rather
than clamps so ordering survives.
"""

from __future__ import annotations

from app.report.html import render_report
from app.scan.ci_deploy_source import RULE_ID as CI_DEPLOY_RULE_ID
from app.scan.scoring import GATED_MAX, ScoredFinding, compute_scores


def deploy_finding() -> ScoredFinding:
    """The real finding, at the severity and confidence the rule emits."""
    return ScoredFinding(
        rule_id=CI_DEPLOY_RULE_ID,
        title="Your CI builds this repository and deploys a different one",
        severity="high", confidence=0.8, category="Deploy",
        file=".github/workflows/deploy.yml",
    )


def small_finding() -> ScoredFinding:
    return ScoredFinding(rule_id="no-dockerfile", title="No Dockerfile",
                         severity="low", confidence=0.9, category="Deploy")


# --- the number ------------------------------------------------------------

def test_an_otherwise_clean_repository_cannot_present_a_passing_headline() -> None:
    """The measured case. Every category clean except a low in Deploy, which
    is exactly the shape that produced 9.8 with a green ring."""
    ungated = compute_scores([small_finding()])
    assert ungated["total"] > 9.0, "fixture no longer reproduces the 9.8 shape"

    gated = compute_scores([small_finding(), deploy_finding()])
    assert gated["total"] <= GATED_MAX


def test_the_gate_reason_is_published_with_the_number() -> None:
    """A capped headline with no reason beside it is the defect the gate's own
    docstring describes: the number contradicts the bars under it and the
    reader trusts neither."""
    reasons = compute_scores([deploy_finding()])["gated_by"]
    assert [r["kind"] for r in reasons] == ["unaudited_deployment"]
    assert reasons[0]["rule_id"] == CI_DEPLOY_RULE_ID
    assert reasons[0]["title"]


def test_ordering_survives_the_gate() -> None:
    """Scaled, not clamped — the reason _apply_gate gives at length. Two
    repositories that both deploy elsewhere must still rank against each
    other, or the gate trades one loss of information for another."""
    worse = compute_scores([
        deploy_finding(),
        ScoredFinding(rule_id="llm-security", title="x", severity="high",
                      confidence=0.9, category="Security"),
    ])["total"]
    better = compute_scores([deploy_finding()])["total"]
    assert worse < better


def test_a_repository_that_deploys_itself_is_not_gated() -> None:
    """The rule is silent when the deploy target is this repository, so the
    gate must be too. Gating on the rule's ABSENCE would cap every audit."""
    assert compute_scores([small_finding()])["gated_by"] == []


# --- what it must not disturb ----------------------------------------------

def test_the_deploy_category_is_not_charged_twice() -> None:
    """The finding already costs Deploy its 0.8 through the ordinary penalty.
    The critical route additionally ceilings its own category; this one must
    not, or the same fact is paid for twice."""
    with_gate = compute_scores([deploy_finding()])
    penalty_only = compute_scores([
        ScoredFinding(rule_id="other", title="x", severity="high",
                      confidence=0.8, category="Deploy")])
    assert with_gate["categories"]["Deploy"] == penalty_only["categories"]["Deploy"]


# --- what the reader is told -----------------------------------------------

def test_report_preserves_scope_finding_without_a_readiness_cap() -> None:
    html = render_report({
        "score": compute_scores([deploy_finding()]),
        "findings": [vars(deploy_finding())],
        "stack": "nextjs",
    })
    assert deploy_finding().title in html
    assert "verification not recorded" in html
    assert "cannot exceed" not in html


def test_scope_warning_and_model_hypothesis_both_remain_visible() -> None:
    findings = [deploy_finding(), ScoredFinding(
        rule_id="llm-auth", title="Root RCE", severity="critical",
        confidence=0.95, category="Security", source="llm")]
    html = render_report({
        "score": compute_scores(findings), "findings": [vars(f) for f in findings],
    })
    assert "Root RCE" in html and deploy_finding().title in html
    assert "Model hypothesis — unverified" in html
    assert "cannot exceed" not in html
