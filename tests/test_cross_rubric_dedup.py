"""Cross-rubric dedup: the auth and security rubrics can flag the same
issue at the same (file, line); we keep one, note the other, and never
double-count it in the score."""

from dataclasses import replace

from app.scan.cross_rubric_dedup import dedup_cross_rubric
from app.scan.scoring import ScoredFinding, compute_scores


def _llm(rubric, sev, conf=0.9, file="src/api/route.ts", line=42, expl=""):
    return ScoredFinding(
        rule_id=f"llm-{rubric}", title="JWT verified client-side",
        severity=sev, confidence=conf,
        category="Security" if rubric == "security" else "Auth",
        file=file, line=line, explanation=expl,
    )


def test_same_location_two_rubrics_collapses_to_most_severe_with_note():
    # The production scenario: both rubrics flag the same JWT issue at the
    # same file+line, at different severities.
    out = dedup_cross_rubric([
        _llm("auth", "high", expl="A login token is trusted without checking it."),
        _llm("security", "medium"),
    ])
    assert len(out) == 1
    rep = out[0]
    assert rep.severity == "high"          # most severe survives
    assert rep.rule_id == "llm-auth"
    # the other rubric is recorded, not silently dropped
    assert "security review" in rep.explanation
    assert rep.explanation.startswith("A login token is trusted")


def test_different_locations_are_not_merged():
    out = dedup_cross_rubric([
        _llm("auth", "high", line=42),
        _llm("security", "high", line=99),
    ])
    assert len(out) == 2
    assert all("Also independently flagged" not in f.explanation for f in out)


def test_static_finding_at_same_location_is_not_merged_with_llm():
    # Design decision: static and LLM findings that happen to share a
    # (file, line) are NOT the same issue (regex secret hit vs. semantic
    # auth flaw), so the static one passes through untouched.
    static = ScoredFinding(rule_id="generic-assignment", title="secret in code",
                            severity="high", confidence=1.0, category="Security",
                            file="src/api/route.ts", line=42, masked="abcd****")
    out = dedup_cross_rubric([static, _llm("auth", "high")])
    assert len(out) == 2
    assert static in out                    # untouched, same object


def test_same_rubric_repeat_collapses_without_a_provenance_note():
    # Union-of-N mode replays each rubric; identical (file, line) repeats
    # from the SAME rubric collapse, but there's no "other rubric" to note.
    out = dedup_cross_rubric([
        _llm("auth", "high"),
        _llm("auth", "high"),
    ])
    assert len(out) == 1
    assert "Also independently flagged" not in out[0].explanation


def test_dedup_stops_the_score_being_double_counted():
    raw = [_llm("auth", "high", conf=1.0), _llm("security", "high", conf=1.0)]
    deduped = dedup_cross_rubric(raw)

    raw_scores = compute_scores(raw)
    deduped_scores = compute_scores(deduped)

    # Undeduped, the single issue penalizes BOTH the Auth and Security
    # categories; deduped, only the surviving finding's category is hit.
    assert raw_scores["categories"]["Security"] == 9.0
    assert deduped_scores["categories"]["Security"] == 10.0
    assert deduped_scores["categories"]["Auth"] == 9.0
    assert deduped_scores["total"] > raw_scores["total"]
