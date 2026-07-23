"""Cross-rubric dedup: the auth and security rubrics can flag the same
issue at the same (file, line); we keep one, note the other, and never
double-count it in the score."""


from app.scan.cross_rubric_dedup import (
    _NEARBY_LINE_WINDOW,
    _TITLE_SIMILARITY_THRESHOLD,
    _title_ratio,
    dedup_cross_rubric,
)
from app.scan.scoring import ScoredFinding, compute_scores


def _llm(rubric, sev, conf=0.9, file="src/api/route.ts", line=42, expl="",
         title="JWT verified client-side"):
    return ScoredFinding(
        rule_id=f"llm-{rubric}", title=title,
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


# --- Adjacent-line dedup (nearby line + title similarity) ------------------
# Real duplicate from auditing aiagent2046-coder/ai-co-founder-matching: the
# same HMAC-derived-password issue reported by two rubrics on adjacent lines
# (46, 47) of one multi-line crypto.createHmac(...) statement. Exact-line
# dedup missed it; nearby-line + title similarity now catches it.
_TG_TITLE_A = ("Deterministic password derived from service-role key — "
               "key rotation breaks all Telegram accounts")
_TG_TITLE_B = "Telegram user password derived from SUPABASE_SERVICE_ROLE_KEY"


def test_calibration_ratios_bracket_the_threshold():
    # Locks the threshold: the real duplicate must clear it, a same-domain
    # but genuinely distinct pair must not.
    assert _title_ratio(_TG_TITLE_A, _TG_TITLE_B) >= _TITLE_SIMILARITY_THRESHOLD
    assert _title_ratio(
        "Missing server-side session check on account deletion endpoint",
        "No rate limiting on password reset request endpoint",
    ) < _TITLE_SIMILARITY_THRESHOLD


def test_adjacent_line_same_issue_merges_with_nearby_note():
    tg = "app/api/auth/telegram/route.ts"
    out = dedup_cross_rubric([
        _llm("security", "high", file=tg, line=46, title=_TG_TITLE_A),
        _llm("auth", "high", file=tg, line=47, title=_TG_TITLE_B),
    ])
    assert len(out) == 1                       # was 2 under exact-line dedup
    rep = out[0]
    assert rep.rule_id == "llm-security"       # first seen wins the tie
    assert "auth review" in rep.explanation
    assert "at a nearby line" in rep.explanation


def test_distinct_findings_on_nearby_lines_do_not_merge():
    # NEGATIVE case — the important one: two unrelated issues a couple of
    # lines apart must stay separate, or the fix would silently drop real
    # findings. Line distance passes the window; dissimilar titles do not.
    f = "app/api/users/route.ts"
    out = dedup_cross_rubric([
        _llm("auth", "high", file=f, line=10,
             title="Missing server-side session check on account deletion endpoint"),
        _llm("security", "medium", file=f, line=12,
             title="No rate limiting on password reset request endpoint"),
    ])
    assert len(out) == 2
    assert all("Also independently flagged" not in x.explanation for x in out)


def test_line_window_boundary():
    # Titles identical (ratio 1.0) to isolate the line dimension. Window is
    # inclusive: exactly _NEARBY_LINE_WINDOW apart merges, one more does not.
    f = "src/handler.ts"
    at_edge = dedup_cross_rubric([
        _llm("auth", "high", file=f, line=20, title="Same issue"),
        _llm("security", "high", file=f, line=20 + _NEARBY_LINE_WINDOW,
             title="Same issue"),
    ])
    assert len(at_edge) == 1

    past_edge = dedup_cross_rubric([
        _llm("auth", "high", file=f, line=20, title="Same issue"),
        _llm("security", "high", file=f, line=20 + _NEARBY_LINE_WINDOW + 1,
             title="Same issue"),
    ])
    assert len(past_edge) == 2
