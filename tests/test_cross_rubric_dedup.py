"""Cross-rubric dedup: the auth and security rubrics can flag the same
issue at the same (file, line); we keep one, note the other, and never
double-count it in the score."""


from app.scan.cross_rubric_dedup import (
    dedup_cross_rubric,
    _title_ratio,
    _TITLE_SIMILARITY_THRESHOLD,
    _NEARBY_LINE_WINDOW,
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
    assert "not independent confirmation" in rep.explanation
    assert "independently flagged" not in rep.explanation
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


# --- position beats prose ---
#
# Two pairs reached a paying customer's report twice each, because the merge
# required similar titles and these scored 0.317 and 0.352 against a 0.5 gate.
# Measured on the same scale: the pair the threshold exists to KEEP APART
# scores 0.588 -- higher than both that had to join. No threshold separates
# the classes, so the gate moved to position.


def _f(**kw):
    base = dict(rule_id="llm-auth", title="t", severity="high", confidence=0.9,
                category="Auth", file="api.py", line=10, masked="", explanation="",
                fix_hint="", context=None)
    base.update(kw)
    return ScoredFinding(**base)


def test_same_line_authentication_paraphrases_merge():
    out = dedup_cross_rubric([
        _f(rule_id="llm-security", line=128, severity="high",
           title="No authentication on action execution endpoint"),
        _f(rule_id="llm-auth", line=128, severity="critical",
           title="Unauthenticated endpoint executes arbitrary SSH commands"),
    ])

    assert len(out) == 1
    assert out[0].severity == "critical"      # most severe survives


def test_independent_causes_at_same_line_keep_their_own_rows():
    """Merging on position alone can join two different issues that share a
    line. The survivor must carry what the other said, or the second issue
    leaves no trace at all."""
    out = dedup_cross_rubric([
        _f(rule_id="llm-auth", line=128, severity="critical",
           title="Unauthenticated endpoint executes arbitrary SSH commands"),
        _f(rule_id="llm-security", line=128, severity="high",
           title="No rate limit on the action endpoint"),
    ])

    assert len(out) == 2
    assert out[1].title == "No rate limit on the action endpoint"
    assert "security review" not in out[0].explanation


def test_a_nearby_line_still_needs_the_titles_to_agree():
    """The window exists for one statement spanning several lines, where the
    titles genuinely are alike. Widening it to bare adjacency would merge
    neighbours that have nothing to do with each other."""
    out = dedup_cross_rubric([
        _f(rule_id="llm-auth", line=46, title="Session cookie set without Secure"),
        _f(rule_id="llm-security", line=48, title="Shell command built by string concatenation"),
    ])

    assert len(out) == 2


def test_v3_rls_and_fail_open_limiter_do_not_merge():
    out = dedup_cross_rubric([
        _f(title="Agent chat route uses service-role client; reads are not owner-scoped by RLS"),
        _f(rule_id="llm-money", title="Rate limiter is fail-open: Redis outage removes all Claude call protection"),
    ])
    assert len(out) == 2


def test_unknown_similar_and_compound_causes_remain_separate():
    for a, b in [
        ("Missing protection on the same endpoint", "Missing validation on the same endpoint"),
        ("No authentication and no rate limiting", "No authentication on endpoint"),
        ("No authentication and no rate limiting", "No rate limiting on endpoint"),
    ]:
        assert len(dedup_cross_rubric([_f(title=a), _f(title=b)])) == 2


def test_command_injection_paraphrases_keep_all_originals():
    out = dedup_cross_rubric([
        _f(title="Command injection via unsanitised user-controlled parameter"),
        _f(rule_id="llm-security", title="User-controlled input interpolated into SSH shell commands"),
    ])
    assert len(out) == 1
    assert len(out[0].claim_evidence["grouped_originals"]) == 2


def _identity(operation=10, mechanism="query_row_bound"):
    return {"version": 1, "method": "source_ast", "file": "api.py",
            "source_sha256": "a" * 64, "function_span": [0, 100],
            "operation_span": [operation, operation + 10], "mechanism": mechanism}


def _source_evidence(identity=None, *, result="not_checked", target="rows", line=10):
    return {"source_issue_identity": identity,
            "syntax_check": {"kind": "unsupported", "result": "not_checked"},
            "premise_checks": [{"kind": "query_limit_unbounded", "result": result,
                                "target": target, "line_start": line, "line_end": line + 2,
                                "anchor_line_start": line, "anchor_line_end": line + 10}]}


def test_same_source_query_ignores_only_selector_coordinates():
    out = dedup_cross_rubric([
        _f(title="Matches query has no LIMIT", line=10,
           claim_evidence=_source_evidence(_identity(), line=10)),
        _f(title="Matches query has no LIMIT", line=11, rule_id="llm-money",
           claim_evidence=_source_evidence(_identity(), line=11)),
    ])
    assert len(out) == 1
    checks = [item["claim_evidence"]["premise_checks"][0] for item in out[0].claim_evidence["grouped_originals"]]
    assert {item["line_start"] for item in checks} == {10, 11}


def test_different_source_query_beats_identical_title_and_location():
    out = dedup_cross_rubric([
        _f(title="Query has no LIMIT", claim_evidence=_source_evidence(_identity(10))),
        _f(title="Query has no LIMIT", claim_evidence=_source_evidence(_identity(30))),
    ])
    assert len(out) == 2


def test_unresolved_source_identity_does_not_fall_back_to_same_title_or_drop_fresh_observations():
    raw = [_f(title="Identical text", claim_evidence=_source_evidence()),
           _f(title="Identical text", claim_evidence=_source_evidence())]
    out = dedup_cross_rubric(raw)
    assert len(out) == 2
    assert dedup_cross_rubric(out) == out


def test_same_source_mechanism_retains_different_targets_and_dispositions():
    baseline = _f(claim_evidence=_source_evidence(_identity()))
    for changed in [
        _source_evidence(_identity(), result="contradicted"),
        _source_evidence(_identity(), target="otherResponse"),
        {**_source_evidence(_identity()), "premise_checks": []},
        {**_source_evidence(_identity()), "syntax_check": {"kind": "query_limit_unbounded", "result": "contradicted"}},
        {**_source_evidence(_identity()), "recommendation_check": {"result": "prerequisites_required"}},
    ]:
        assert len(dedup_cross_rubric([baseline, _f(claim_evidence=changed)])) == 2


def test_pre_grouped_inputs_are_flat_idempotent_and_keep_origin_statuses():
    identity = _identity()
    a = _f(title="Query has no LIMIT", severity="medium", rule_id="llm-auth", line=10,
           origin_category="Auth", verification_status="unverified",
           claim_evidence=_source_evidence(identity, line=10))
    b = _f(title="Query grows unbounded", severity="high", rule_id="llm-security", line=20,
           origin_category="Security", verification_status="observed",
           claim_evidence=_source_evidence(identity, line=20))
    c = _f(title="Query has no row bound", severity="low", rule_id="llm-money", line=30,
           origin_category="Money & Data", verification_status="unverified",
           claim_evidence=_source_evidence(identity, line=30))
    partial = dedup_cross_rubric([a, b])
    out = dedup_cross_rubric([partial[0], b, c])
    assert len(out) == 1
    originals = out[0].claim_evidence["grouped_originals"]
    assert len(originals) == 3
    assert {item["origin_category"] for item in originals} == {"Auth", "Security", "Money & Data"}
    assert {item["verification_status"] for item in originals} == {"unverified", "observed"}
    assert all("grouped_originals" not in item["claim_evidence"] for item in originals)
    assert dedup_cross_rubric(out) == out
    assert out[0].explanation.count("not independent confirmation") == 1


def test_legacy_representative_change_leaves_no_joinable_representatives():
    from app.scan.cross_rubric_dedup import _same_issue
    # Old first-anchor grouping produced [line 13, line 16], which merged on
    # a second pass. The strongest representative must anchor from the outset.
    out = dedup_cross_rubric([
        _f(title="Same query", line=10, severity="medium"),
        _f(title="Same query", line=13, severity="critical"),
        _f(title="Same query", line=16, severity="high"),
    ])
    assert len(out) == 1
    assert out[0].line == 13
    assert dedup_cross_rubric(out) == out
    assert not any(_same_issue(a, b) for i, a in enumerate(out) for b in out[i + 1:])


def test_historical_group_with_nested_origins_and_new_severity_is_stable():
    a = _f(title="Same query", severity="low", rule_id="llm-auth")
    b = _f(title="Same query", severity="medium", rule_id="llm-security")
    old_group = dedup_cross_rubric([a, b])[0]
    c = _f(title="Same query", severity="critical", rule_id="llm-money")
    out = dedup_cross_rubric([old_group, c])
    assert len(out) == 1 and out[0].severity == "critical"
    assert len(out[0].claim_evidence["grouped_originals"]) == 3
    assert dedup_cross_rubric(out) == out


def test_identical_repeated_observations_preserve_multiplicity_when_regrouped():
    a = _f(title="Same issue")
    out = dedup_cross_rubric([a, a])
    assert len(out) == 1
    assert len(out[0].claim_evidence["grouped_originals"]) == 2
    assert dedup_cross_rubric(out) == out
    assert dedup_cross_rubric([out[0], a]) == out


def test_two_equally_severe_legacy_groups_keep_boundary_member_on_replay():
    raw = [_f(line=line, severity=severity, explanation=str(index), title="Same issue")
           for index, (line, severity) in enumerate([
               (5, "high"), (4, "high"), (3, "medium"), (9, "critical"),
               (5, "critical"), (8, "medium"), (0, "medium"),
           ])]
    out = dedup_cross_rubric(raw)
    assert dedup_cross_rubric(out) == out
    assert sorted(len((item.claim_evidence or {}).get("grouped_originals", [item]))
                  for item in out) == [1, 1, 5]
