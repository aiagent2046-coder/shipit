"""Tests for presence checks and the score formula."""

import io
import zipfile
from pathlib import Path

import pytest

from app.scan.checks import run_checks
from app.scan.scoring import (
    CATEGORIES,
    CATEGORY_WEIGHT,
    CRITICAL_GATE_MIN_CONFIDENCE,
    GATE_THRESHOLD,
    GATED_CATEGORIES,
    GATED_MAX,
    LLM_ONLY_CATEGORIES,
    ScoredFinding,
    compute_scores,
)
from app.scan.static import run_static_scan


def make_zip(entries: dict[str, bytes]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    buf.seek(0)
    return buf


def test_committed_env_detected_even_inside_root_folder():
    buf = make_zip({"my-app/.env": b"KEY=value", "my-app/app.py": b""})
    ids = {f.rule_id for f in run_checks(buf)}
    assert "env-file-committed" in ids


def test_env_example_is_allowed():
    buf = make_zip({".env.example": b"KEY=", ".gitignore": b".env\n",
                    "tests/test_x.py": b"", "Dockerfile": b"",
                    ".github/workflows/ci.yml": b""})
    assert run_checks(buf) == []


def test_gitignore_missing_entirely_is_flagged():
    buf = make_zip({"app.py": b"", ".env.example": b"KEY="})
    ids = {f.rule_id for f in run_checks(buf)}
    assert "gitignore-missing-secrets" in ids


def test_gitignore_without_env_coverage_is_flagged():
    buf = make_zip({".gitignore": b"node_modules/\ndist/\n", "app.py": b""})
    findings = run_checks(buf)
    f = next(f for f in findings if f.rule_id == "gitignore-missing-secrets")
    assert f.severity == "high"
    assert f.category == "Security"


def test_gitignore_covering_env_is_not_flagged():
    buf = make_zip({".gitignore": b"node_modules/\n.env\n*.pem\n", "app.py": b""})
    ids = {f.rule_id for f in run_checks(buf)}
    assert "gitignore-missing-secrets" not in ids


def test_gitignore_env_glob_coverage_is_accepted():
    buf = make_zip({".gitignore": b".env*\n", "app.py": b""})
    ids = {f.rule_id for f in run_checks(buf)}
    assert "gitignore-missing-secrets" not in ids


def test_gitignore_coverage_detected_inside_root_folder():
    buf = make_zip({"my-app/.gitignore": b".env\n", "my-app/app.py": b""})
    ids = {f.rule_id for f in run_checks(buf)}
    assert "gitignore-missing-secrets" not in ids


def test_missing_tests_dockerfile_ci_reported():
    buf = make_zip({"app.py": b""})
    ids = {f.rule_id for f in run_checks(buf)}
    assert {"no-tests", "no-dockerfile", "no-ci"} <= ids


def _f(sev: str, conf: float, cat: str = "Security") -> ScoredFinding:
    return ScoredFinding(
        rule_id="r", title="t", severity=sev, confidence=conf, category=cat
    )


def test_score_v2_total_is_weighted_mean_of_categories():
    # Security: 10 − (1.0×1.0 + 1.0×1.0 + 1.0×0.5) = 7.5; Testing: 10 − 0.4 = 9.6
    #
    # Three highs rather than one critical plus one high, which is what this
    # reached for originally. Both give Security 7.5, but a critical now fails
    # the gate on its own (GATE_ON_CRITICAL), so the old fixture measured the
    # gated path while claiming to measure the ungated mean. The arithmetic
    # under test is the weighted mean; the fixture must not smuggle in a
    # second behaviour to depend on.
    findings = [_f("high", 1.0), _f("high", 1.0), _f("high", 0.5),
                _f("medium", 1.0, "Testing")]
    scores = compute_scores(findings)
    assert scores["categories"]["Security"] == 7.5
    assert scores["categories"]["Testing"] == 9.6
    assert scores["categories"]["Deploy"] == 10.0
    # Weights are the raw values normalised over their own sum:
    # (7.5×.25 + 10×.20 + 9.6×.15 + 10×.15 + 10×.20 + 10×.15) / 1.10 = 9.4
    # Not gated: Security 7.5 clears GATE_THRESHOLD, so the mean stands.
    # Moved from 9.3 when Frontend became the sixth category: the divisor
    # goes .95 -> 1.10 and the only damaged category, Security, is diluted
    # by one more clean one. That is the arithmetic working, not drifting.
    assert scores["total"] == 9.4


def test_saturated_category_does_not_zero_total():
    # v1 regression: 10 criticals in ONE category zeroed the whole
    # score; v2 floors the damage at that category's weight.
    findings = [_f("critical", 1.0)] * 10  # all Security
    scores = compute_scores(findings)
    assert scores["categories"]["Security"] == 0.0
    # Everything except Security intact. The number has moved three times
    # since: to 6.7 when the two producer-less categories were dropped (issue
    # #181), to 5.1 once a failing safety category began compressing the mean
    # into the sub-threshold band, and to 5.3 when Frontend became the sixth
    # category and Security's saturated 0.0 carried proportionally less of the
    # mean. The property under test is unchanged and is the point -- a single
    # saturated category must not zero the total.
    assert scores["total"] == 5.3
    assert scores["total"] > 0.0


def test_findings_across_all_categories_still_reach_zero():
    # Driven off CATEGORIES itself so this cannot quietly stop covering a
    # category the way it did when the tuple was written out by hand.
    findings = [_f("critical", 1.0, cat) for cat in CATEGORIES] * 10
    assert compute_scores(findings)["total"] == 0.0


# --- safety gate: a failing category keeps the headline out of passing range ---

def test_failing_safety_category_keeps_total_below_threshold():
    # The motivating real case, audit 0a043539
    # (vercel/nextjs-subscription-payments): an open redirect, a service-role
    # client that silently no-ops when misconfigured, and a subscriptions
    # table with no write RLS policies put Security at 5.9 -- while Testing
    # 9.7 and Deploy 9.8 carried the weighted mean to a reassuring 8.1.
    # Security: 10 − (2.0×1.0 + 2.0×1.0) = 6.0, while every other category
    # stays at 10.0 -- the weighted mean alone would read 8.9.
    findings = [_f("critical", 1.0), _f("critical", 1.0)]
    scores = compute_scores(findings)

    assert scores["categories"]["Security"] < GATE_THRESHOLD
    assert scores["total"] < GATE_THRESHOLD
    assert scores["total"] <= GATED_MAX


@pytest.mark.parametrize("category", ["Security", "Auth", "Money & Data"])
def test_either_safety_category_alone_triggers_the_gate(category: str) -> None:
    """Both halves gate independently.

    A repo can be clean on Security and still be unsafe to ship on Auth, and
    the headline must say so either way. The category names are written out
    rather than driven off GATED_CATEGORIES: parametrizing off the tuple
    means dropping a category from it silently deletes its own test case
    instead of failing, which is how this stops guarding what it claims to.
    """
    assert category in GATED_CATEGORIES, f"{category} is no longer gated"
    findings = [_f("critical", 1.0, category), _f("critical", 1.0, category)]
    scores = compute_scores(findings)

    assert scores["categories"][category] < GATE_THRESHOLD
    assert scores["total"] < GATE_THRESHOLD
    assert scores["total"] <= GATED_MAX


@pytest.mark.parametrize("category", ["Security", "Auth", "Money & Data"])
def test_one_confident_critical_gates_on_its_own(category: str) -> None:
    """A single critical fails the gate even though the subscore clears it.

    This is the case the subscore route structurally could not reach: one
    critical at 0.9 costs 1.8, leaving the category at 8.2, well clear of
    GATE_THRESHOLD. Seven stored audits sat here, presenting 9.0-9.5 while
    holding a committed .env or a private key.

    Names written out rather than driven off GATED_CATEGORIES, for the reason
    the test above gives: parametrizing off the tuple means dropping a
    category from it deletes its own case instead of failing.
    """
    assert category in GATED_CATEGORIES, f"{category} is no longer gated"
    findings = [_f("critical", 0.9, category)]
    scores = compute_scores(findings)

    # The fixture guard used to read the published subscore and require it
    # above GATE_THRESHOLD. That number is now scaled when this very route
    # fires, so it can no longer speak for the raw one. The routes themselves
    # say the same thing directly: the critical must be what gated, and the
    # subscore route must NOT have fired -- which is exactly "the subscore
    # itself does not fail" without inferring it from a value.
    kinds = {r["kind"] for r in scores["gated_by"] if r.get("category") == category}
    assert "critical" in kinds
    assert "subscore" not in kinds, (
        "fixture no longer exercises the gap: the subscore itself now fails, "
        "so this would pass without GATE_ON_CRITICAL")
    assert scores["total"] <= GATED_MAX
    # And the category no longer outranks its own critical finding.
    assert scores["categories"][category] <= GATED_MAX


def test_a_category_is_capped_once_however_many_criticals_it_holds():
    """The ceiling is a statement about the category, not a per-finding fine.

    `gated_by` carries one entry per critical finding, and scaling straight
    off that list compounded: two criticals multiplied the subscore by 0.69
    twice. Measured on kristina_agent_center, whose Security holds three --
    the published subscore walked 0.9 -> 0.6 -> 0.4 -> 0.3 across three
    passes while its raw subscore had not moved at all.

    Confidence 0.7 rather than 0.9 on purpose: two criticals at 0.9 cost 3.6
    and leave the raw subscore at 6.4, which fails the gate on the subscore
    route as well, and the test would then be measuring the exemption below
    instead of this. At 0.7 the raw subscore is 7.2 -- above GATE_THRESHOLD,
    so only the critical route fires.
    """
    findings = [_f("critical", 0.7, "Auth"), _f("critical", 0.7, "Auth")]
    scores = compute_scores(findings)

    kinds = {r["kind"] for r in scores["gated_by"] if r.get("category") == "Auth"}
    assert kinds == {"critical"}, (
        "fixture no longer isolates the critical route; the subscore route "
        "would exempt the category and this would pass either way")
    assert len([r for r in scores["gated_by"]
                if r.get("kind") == "critical"]) == 2, (
        "fixture no longer produces the repeated reasons this guards against")

    raw = round(10.0 - 2 * 2.0 * 0.7, 1)
    assert scores["categories"]["Auth"] == round(raw * (GATED_MAX / 10.0), 1)


def test_a_category_already_failing_its_subscore_is_not_capped_again():
    """Excluded outright, not scaled: it is already below the ceiling.

    Three criticals at 0.9 put Security at 4.6 on its own arithmetic. The
    ceiling exists to stop a category presenting a HIGH number above a
    confident critical; 4.6 presents nothing of the kind, and scaling it
    charges the same three findings a second time.
    """
    findings = [_f("critical", 0.9, "Security")] * 3
    scores = compute_scores(findings)

    raw = round(10.0 - 3 * 2.0 * 0.9, 1)
    assert raw < GATE_THRESHOLD, "fixture must fail on the subscore route"
    assert {r["kind"] for r in scores["gated_by"]} == {"subscore", "critical"}, (
        "fixture must fire BOTH routes, or it cannot show the exemption")
    assert scores["categories"]["Security"] == raw


def test_an_unsure_critical_does_not_gate_by_itself():
    """Severity claims impact, confidence claims certainty. The gate is
    categorical, so it reads both: a critical the producer is guessing at
    must not fail a repository on its own.

    Nothing in production emits one -- the lowest-confidence critical across
    every stored audit is 0.85, and the static rules cap non-production paths
    at medium before this point. The floor exists for the rubric not yet
    written, so it is tested rather than assumed.
    """
    findings = [_f("critical", CRITICAL_GATE_MIN_CONFIDENCE - 0.1, "Security")]
    scores = compute_scores(findings)

    assert scores["total"] > GATE_THRESHOLD
    # And the same finding one notch more confident does gate, so the test
    # pins the floor rather than merely observing a low score somewhere.
    sure = compute_scores([_f("critical", CRITICAL_GATE_MIN_CONFIDENCE,
                              "Security")])
    assert sure["total"] <= GATED_MAX


def test_critical_in_an_unexamined_category_cannot_gate():
    """On a static-only audit nothing ran that could produce an Auth finding,
    so an Auth critical cannot be present -- but a Security one can, and the
    gate must read only what was examined. Mirrors the subscore rule: an
    unexamined category neither clears the gate nor fails it.
    """
    findings = [_f("critical", 0.95, "Auth")]
    assert compute_scores(findings, llm_ran=False)["total"] > GATE_THRESHOLD
    assert compute_scores(findings, llm_ran=True)["total"] <= GATED_MAX


def test_gate_does_not_fire_on_hygiene_only_findings():
    # Missing tests and no Dockerfile are real findings but say nothing about
    # whether a visitor can break in. A repo whose only problems are hygiene
    # must keep its averaged score -- the gate is a ceiling on the misleading
    # case, not a blanket penalty.
    findings = [_f("medium", 0.8, "Testing"), _f("low", 0.9, "Deploy")]
    scores = compute_scores(findings)

    assert scores["categories"]["Security"] == 10.0
    assert scores["categories"]["Auth"] == 10.0
    assert scores["categories"]["Money & Data"] == 10.0
    assert scores["total"] > GATE_THRESHOLD


def test_gate_preserves_ordering_among_failing_repos():
    """The gate must not flatten the bottom of the scale.

    Replacing the total with the failing subscore was tried first and
    collapsed every repo whose Security penalty saturated to 0.0 down to
    exactly 0.0 -- on the real audit set, 10 of the 72 carrying category
    data. That re-creates for these two categories the v1 flattening the
    module docstring exists to describe. A ceiling leaves the weighted mean
    intact below it, so worse repos still score worse.
    """
    saturated_only = [_f("critical", 1.0)] * 10                      # Security 0.0
    saturated_plus = saturated_only + [_f("critical", 1.0, "Auth")]  # Auth also hit

    worse = compute_scores(saturated_plus)["total"]
    bad = compute_scores(saturated_only)["total"]

    assert compute_scores(saturated_only)["categories"]["Security"] == 0.0
    assert worse < bad, "a repo failing both safety categories must score lower"
    assert worse > 0.0, "the gate must not collapse the scale to zero"


def test_gate_never_raises_a_score():
    # min() by construction, pinned because a future edit that turns the
    # ceiling into an assignment would silently start inflating clean repos.
    clean = compute_scores([])
    assert clean["total"] == 10.0


def test_static_scan_end_to_end():
    buf = make_zip({
        "src/config.ts": b"const k = 'AKIA" + b"A" * 16 + b"'",
        "app.py": b"",
    })
    result = run_static_scan(buf)
    ids = {f["rule_id"] for f in result["findings"]}
    assert "aws-access-key-id" in ids and "no-tests" in ids
    assert result["score"]["total"] < 10.0
    assert result["score"]["categories"]["Security"] < 10.0


def test_static_scan_does_not_let_unexamined_categories_vote():
    """run_static_scan runs no LLM stage, so Auth and Money & Data have no
    producer inside it and their 10.0 means "not examined", not "clean".

    compute_scores defaults to llm_ran=True, so this is one omitted keyword
    away from handing those two 42% of the weight at a constant 10.0 -- the
    inflation LLM_ONLY_CATEGORIES was added to stop, reached by leaving an
    argument out instead of passing it wrong. The pipeline recomputes and so
    never showed it, which is exactly why nothing caught it here.
    """
    buf = make_zip({
        "src/config.ts": b"const k = 'AKIA" + b"A" * 16 + b"'",
        "app.py": b"",
    })
    result = run_static_scan(buf)
    findings = [ScoredFinding(**{k: v for k, v in f.items()})
                for f in result["findings"]]

    assert result["score"]["total"] == compute_scores(
        findings, llm_ran=False)["total"]
    # Not vacuous: the two must actually disagree on this fixture, or the
    # assertion above would hold no matter which one the code picked.
    assert (compute_scores(findings, llm_ran=True)["total"]
            > compute_scores(findings, llm_ran=False)["total"])


def test_static_findings_carry_context_field():
    # The structured context field must survive serialization into the
    # finding dicts stored in findings_json / returned by the API.
    buf = make_zip({
        "src/config.ts": b"const k = 'AKIA" + b"A" * 16 + b"'",
        "app.py": b"",
    })
    result = run_static_scan(buf)
    aws = next(f for f in result["findings"] if f["rule_id"] == "aws-access-key-id")
    assert "context" in aws
    assert aws["context"] is None


def test_perfect_total_impossible_with_findings():
    # weighted mean can round up to 10.0 past one tiny finding
    assert compute_scores([_f("low", 0.1, "Deploy")])["total"] == 9.9
    assert compute_scores([])["total"] == 10.0


def test_score_is_deterministic_regardless_of_finding_order():
    """The core reproducibility invariant: the SAME findings must always
    produce the SAME score, independent of the order they arrive in. The
    score formula has no LLM call and no randomness -- so if the finding
    set is fixed, the number is fixed. (The prod 8.9/9.9/9.9 variance came
    from the LLM producing a *different* finding set each run, not from
    this formula; see app/scan/scoring.py and app/scan/llm_scan.py.)"""
    import random

    findings = [
        _f("critical", 1.0, "Security"), _f("high", 0.5, "Auth"),
        _f("medium", 0.7, "Testing"), _f("low", 0.3, "Deploy"),
        _f("high", 0.9, "Testing"), _f("medium", 0.4, "Deploy"),
        _f("low", 0.2, "Security"), _f("high", 0.6, "Auth"),
    ]
    baseline = compute_scores(findings)
    for _ in range(100):
        shuffled = findings[:]
        random.shuffle(shuffled)
        assert compute_scores(shuffled) == baseline


def test_finding_in_a_category_we_no_longer_score_is_ignored_not_fatal():
    """A finding whose category is not in CATEGORIES must neither raise nor move
    the total.

    Not hypothetical: "Correctness" and "Config" were dropped in #181, stored
    audits still carry findings labelled with them, and a future producer could
    emit a name before the constant learns about it. compute_scores filters by
    CATEGORIES, so such a finding is silently absent from the score while still
    being listed in the report -- which is the tolerable behaviour, but only if
    it is deliberate rather than discovered in production.
    """
    baseline = compute_scores([_f("high", 0.5, "Auth")])
    with_ghost = compute_scores([
        _f("high", 0.5, "Auth"), _f("critical", 1.0, "Correctness"),
    ])
    assert with_ghost == baseline
    assert "Correctness" not in with_ghost["categories"]


def test_gate_scales_rather_than_clamping():
    """Two repos failing the gate by different amounts must not print the same
    number.

    A flat ceiling (total = min(mean, GATED_MAX)) was the first design. It
    stopped the flattering headline but flattened the failing range, because a
    repo's mean sits well above 6.9 even when one category fails: on the 42
    real full audits, 17 of them -- 40% -- would have printed exactly 6.9,
    making one failing category indistinguishable from three.

    Both fixtures here fail only on Security and are strong everywhere else,
    so both means land above GATED_MAX -- which is exactly where a clamp
    erases the difference between them and a scale keeps it.
    """
    mild = [_f("critical", 1.0), _f("high", 1.0), _f("medium", 1.0)]   # Security 6.6
    worse = [_f("critical", 1.0), _f("critical", 1.0), _f("high", 1.0)]  # Security 5.0

    mild_scores = compute_scores(mild)
    worse_scores = compute_scores(worse)

    # Precondition: an unscaled mean above the band top, or a clamp would be
    # indistinguishable from a scale here and the test would prove nothing.
    assert mild_scores["categories"]["Security"] < GATE_THRESHOLD
    assert worse_scores["categories"]["Security"] < GATE_THRESHOLD

    assert worse_scores["total"] < mild_scores["total"], (
        f'gate flattened {worse_scores["total"]} == {mild_scores["total"]}')
    assert mild_scores["total"] < GATE_THRESHOLD


def test_no_gated_repo_can_present_a_passing_score():
    """The one invariant the gate exists for, over the whole input space."""
    import random

    random.seed(20260808)
    for _ in range(3000):
        findings = [
            _f(random.choice(["critical", "high", "medium", "low"]),
               random.random(), cat)
            for cat in CATEGORIES
            for _ in range(random.randint(0, 4))
        ]
        scores = compute_scores(findings)
        failing = [c for c in GATED_CATEGORIES
                   if scores["categories"][c] < GATE_THRESHOLD]
        if failing:
            assert scores["total"] < GATE_THRESHOLD, (failing, scores)


# --- basis-aware weighting ---

def test_static_only_audit_does_not_count_categories_nothing_examined():
    """Auth and Money & Data have no static producer.

    On a static-only audit their 10.0 means "not examined", not "clean", and
    letting it vote is how the free tier came to average 8.99 against 7.79 for
    full audits -- with Auth reading exactly 10.0 in 25 of 25 of them. The
    subscores are still reported; they just no longer carry weight.
    """
    findings = [_f("critical", 0.9), _f("medium", 0.8, "Testing")]

    full = compute_scores(findings, llm_ran=True)
    static_only = compute_scores(findings, llm_ran=False)

    assert static_only["categories"]["Auth"] == 10.0        # still shown
    assert static_only["categories"]["Money & Data"] == 10.0
    assert static_only["total"] < full["total"], (
        "unexamined categories must not prop up a static-only total")


def test_unexamined_category_cannot_trigger_the_gate():
    # The mirror of the above: an Auth of 10.0 that nothing looked at must not
    # clear the gate, and an unexamined category must not fail it either.
    hygiene_only = [_f("medium", 0.8, "Testing"), _f("low", 0.9, "Deploy")]

    scores = compute_scores(hygiene_only, llm_ran=False)

    assert scores["total"] > GATE_THRESHOLD


def test_gate_reasons_are_recorded_whenever_the_gate_fires():
    """The gate's decision and its published explanation come from one list,
    so they cannot disagree: reasons non-empty iff the total was capped.

    Checked over the whole gated/ungated boundary rather than one fixture,
    because the failure this guards against is a route that caps the score
    without recording why -- which reads to a user as an unexplained number.
    """
    cases = [
        [],                                        # clean
        [_f("medium", 0.8, "Testing")],            # hygiene only
        [_f("critical", 0.9, "Security")],         # lone critical
        [_f("critical", 1.0), _f("critical", 1.0)],  # subscore failure
        [_f("critical", 0.5, "Security")],         # unsure critical
    ]
    for findings in cases:
        scores = compute_scores(findings)
        capped = scores["total"] <= GATED_MAX and findings
        assert bool(scores["gated_by"]) == bool(capped), (
            f"{findings}: total {scores['total']} vs "
            f"reasons {scores['gated_by']}")


def test_gate_reason_carries_the_finding_a_reader_must_act_on():
    reasons = compute_scores([_f("critical", 0.9, "Security")])["gated_by"]
    assert reasons == [{"kind": "critical", "category": "Security",
                        "rule_id": "r", "title": "t"}]


def test_ungated_score_reports_an_empty_reason_list_not_a_missing_key():
    """Empty distinguishes "not gated" from "produced before this key
    existed"; a missing key conflates the two, and the report surfaces treat
    the second as unknown rather than as a clean bill."""
    assert compute_scores([_f("low", 0.1, "Deploy")])["gated_by"] == []


def test_a_static_only_score_names_the_categories_nothing_examined():
    """The key both report surfaces read before drawing a category's bar.

    An unexamined category sits at 10.0 for want of a producer, and it is
    already kept out of the mean -- but `categories` still reports it, so
    without this list a renderer has no way to tell that 10.0 from a real
    one. Asserted as the exact list, since an empty one would let every
    surface fall back to drawing full bars.
    """
    findings = [_f("critical", 0.9, "Security")]

    assert compute_scores(findings, llm_ran=False)["unexamined"] == [
        "Auth", "Money & Data", "Frontend"]
    assert compute_scores(findings, llm_ran=True)["unexamined"] == []


# --------------------------------------------------------------------------
# Frontend, the sixth category. Added with the "web" rubric after five
# measured runs; see app/scan/scoring.py and scripts/validate_web_rubric.py.
# --------------------------------------------------------------------------

def test_every_scored_category_has_a_producer():
    """Issue #181 in one assertion.

    "Correctness" and "Config" were categories nothing could ever emit, so
    both sat at a constant 10.0 and together carried 25% of the weight -- a
    scale whose bottom half was unreachable. The lesson was written down as a
    comment; this is the version that fails.

    Producers are the LLM rubrics plus the static rules. Anything in
    CATEGORIES that neither can emit is dead weight by construction.
    """
    import re as _re

    from app.scan.llm_scan import RUBRICS

    produced = {r["category"] for r in RUBRICS.values()}
    # The static rules build ScoredFindings inline rather than from a table,
    # so their categories are read out of the source. Crude on purpose: a
    # structural reader would have to track two modules' shapes, and what this
    # needs to know is only which names can ever be emitted.
    for module in ("checks", "secrets", "static"):
        source = (
            Path(__file__).resolve().parents[1] / "app" / "scan" / f"{module}.py"
        ).read_text()
        produced |= set(_re.findall(r'category=["\']([^"\']+)["\']', source))

    assert set(CATEGORIES) <= produced, (
        f"no producer emits {sorted(set(CATEGORIES) - produced)}; a category "
        f"with no producer scores a constant 10.0 and props up every total"
    )


def test_frontend_is_weighted_with_testing_and_deploy_not_with_the_safety_three():
    """What it finds is real and a user hits it on a normal day, but the
    product's wedge is "safe to put in production" and a blank page is not an
    auth hole. Asserted as a relation, not as 0.136...: the normalised value
    moves whenever any category is added, and the claim being made is about
    the ordering."""
    weight = CATEGORY_WEIGHT["Frontend"]

    assert weight == CATEGORY_WEIGHT["Testing"] == CATEGORY_WEIGHT["Deploy"]
    assert weight < CATEGORY_WEIGHT["Auth"] == CATEGORY_WEIGHT["Money & Data"]
    assert weight < CATEGORY_WEIGHT["Security"]
    assert abs(sum(CATEGORY_WEIGHT.values()) - 1.0) < 1e-9


def test_frontend_is_not_examined_by_a_static_only_audit():
    """The "web" rubric is its only producer. On a static-only audit it would
    otherwise read a perfect 10.0 for a reason that has nothing to do with the
    repository -- which is what LLM_ONLY_CATEGORIES exists to stop, and what
    the free tier was doing to Auth in 25 of 25 audits."""
    assert "Frontend" in LLM_ONLY_CATEGORIES

    scores = compute_scores([_f("critical", 0.9, "Security")], llm_ran=False)

    assert "Frontend" in scores["unexamined"]


def test_a_critical_frontend_finding_does_not_gate_the_headline():
    """Deliberate, and the reason is in app/scan/scoring.py: the gate is about
    a headline that contradicts "safe to put in production", and a white page
    on a render error is a bad app rather than an unsafe one. The money-shaped
    half of what this rubric finds already reaches the reader through Money &
    Data, whose remit the rubric is told not to duplicate.

    If this ever becomes wrong, gating it is a calibration change with its own
    evidence against the stored audits -- not a one-line edit here.
    """
    scores = compute_scores([_f("critical", 0.95, "Frontend")])

    assert scores["categories"]["Frontend"] == 8.1
    assert scores["gated_by"] == []
    assert scores["total"] > GATE_THRESHOLD


# --- a committed dependency tree ---
#
# On a paying customer's repository venv/ was 2,987 of 3,098 tracked files and
# the audit said nothing. Every component that could have noticed was told to
# look away: _SKIP_DIRS excludes these paths from the secret scan and from the
# prompt, correctly, because auditing somebody else's dependencies would spend
# the entire budget. Skipping the CONTENTS is right; saying nothing about the
# FACT is not, and any reviewer names it in the first minute.


def test_a_committed_virtualenv_is_reported_with_its_size():
    from app.scan.checks import _committed_dependency_dirs

    files = [f"venv/lib/python3.12/site-packages/pkg/mod{i}.py" for i in range(40)]
    files += ["app.py", "README.md"]

    assert _committed_dependency_dirs(files) == [("venv", 40)]


def test_only_the_outermost_tree_is_reported():
    """A virtualenv contains site-packages/ and dozens of __pycache__/. Listing
    each would bury the one fact the owner needs under its own consequences."""
    from app.scan.checks import _committed_dependency_dirs

    # Attribution stops at the FIRST marker in _DEPENDENCY_DIRS order, so a
    # path inside venv/ never reaches the site-packages/ or __pycache__/
    # markers at all -- those cannot produce their own entry here.
    files = [f"venv/lib/site-packages/p/m{i}.py" for i in range(30)]
    files += [f"venv/lib/site-packages/p/__pycache__/m{i}.pyc" for i in range(30)]

    assert [d for d, _ in _committed_dependency_dirs(files)] == ["venv"]

    # The case that DOES produce two entries, one inside the other: `venv/`
    # is checked before `vendor/`, so these files are attributed to
    # "vendor/venv" and "vendor" separately. Only the outer one is reported.
    nested = [f"vendor/venv/lib/m{i}.py" for i in range(25)]
    nested += [f"vendor/pkg/m{i}.php" for i in range(25)]

    assert [d for d, _ in _committed_dependency_dirs(nested)] == ["vendor"]


def test_a_stray_file_is_not_a_committed_dependency_tree():
    """One file slipping through is a mistake, not the problem this describes."""
    from app.scan.checks import _committed_dependency_dirs

    assert _committed_dependency_dirs(["node_modules/.package-lock.json"]) == []


def test_the_check_reads_no_file_contents():
    """It counts names. Reading these trees is what _SKIP_DIRS exists to
    prevent, and this check must not become the reason they are read."""
    import inspect

    from app.scan import checks

    source = inspect.getsource(checks._committed_dependency_dirs)
    for forbidden in ("open(", "read(", "decode("):
        assert forbidden not in source


def test_the_dependency_check_fires_through_run_checks():
    """Through the pipeline, not by calling the helper.

    The helper was verified directly and shipped; the version that reached
    main carried only its plain-language translation, because a hand-typed
    list of commits during a branch rebuild missed the one holding the code.
    Nothing caught it: the tests went with it, so the suite stayed green while
    the check no longer existed. A test that drives run_checks would have
    failed on the import.
    """
    import io
    import zipfile

    from app.scan.checks import run_checks

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(40):
            zf.writestr(f"repo-main/venv/lib/site-packages/p/m{i}.py", "x=1\n")
        zf.writestr("repo-main/app.py", "print('hi')\n")
    buf.seek(0)

    ids = [f.rule_id for f in run_checks(buf)]

    assert "dependency-dir-committed" in ids


# --- a category that handed all its findings to a neighbour ------------------
#
# Measured on kristina_agent_center under Sonnet 5. The auth rubric reported an
# endpoint running arbitrary shell commands with no login check; the model filed
# it as Security, because that is what it is. Auth was left holding nothing,
# scored a perfect 10.0, was NOT in `unexamined`, and rendered as a full green
# bar directly above an unauthenticated RCE.
#
# Third route to one defect: #22 was "never examined shows 10.0", #27 was
# "category outranks its own critical", this is "category is empty because its
# findings moved next door".


def _f_from(origin: str, category: str, severity: str = "critical",
            confidence: float = 0.95) -> ScoredFinding:
    return ScoredFinding(rule_id="llm-auth", title="t", severity=severity,
                         confidence=confidence, category=category,
                         origin_category=origin)


def test_a_category_that_exported_all_its_findings_does_not_score_ten():
    scores = compute_scores([_f_from("Auth", "Security")])

    assert scores["reported_elsewhere"] == {"Auth": ["Security"]}
    # It must not be described as unexamined: the rubric ran and it found
    # something. Saying "not checked" sends the reader hunting for an audit
    # that already happened.
    assert "Auth" not in scores["unexamined"]


def test_the_emptied_category_does_not_vote_on_the_total():
    """Its 10.0 is dead weight in the sense of issue #181, by a fourth route.

    Not "no producer exists", not "no producer ran", not "the producer found
    nothing" — but "the producer found things, and they are counted next
    door". A fifth of the weight propping up the mean for a reason that has
    nothing to do with the repository.
    """
    same = dict(rule_id="llm-auth", title="t", severity="critical",
                confidence=0.95, category="Security")
    # Identical findings in every respect but one: whether the scorer knows
    # Auth is empty because it exported, or empty because it was clean. Any
    # difference in the total is attributable to that one field and nothing
    # else -- which is what a control this tight is for.
    control = compute_scores([ScoredFinding(**same)])
    moved = compute_scores([ScoredFinding(**same, origin_category="Auth")])

    assert moved["categories"]["Auth"] == 10.0   # the arithmetic is unchanged
    assert moved["total"] == 6.5                 # ...it simply does not vote
    assert control["total"] == 6.6               # the propped-up reading
    assert moved["total"] < control["total"], (
        "an emptied category must not prop the mean up with a 10.0")


def test_a_category_keeping_even_one_finding_scores_normally():
    """Only the fully-emptied case qualifies.

    A rubric that exports one finding and keeps another is scoring its own
    remainder honestly, and blanking it would hide a real number.
    """
    scores = compute_scores([
        _f_from("Auth", "Security"),
        ScoredFinding(rule_id="llm-auth", title="t", severity="high",
                      confidence=0.9, category="Auth"),
    ])

    assert scores["reported_elsewhere"] == {}
    assert scores["categories"]["Auth"] == 9.1


def test_an_ordinary_clean_category_is_not_marked_as_moved():
    """The guard against the fix firing everywhere: a category with no
    findings and no exports is genuinely clean and keeps its 10.0."""
    scores = compute_scores([ScoredFinding(
        rule_id="llm-security", title="t", severity="high", confidence=0.9,
        category="Security")])

    assert scores["reported_elsewhere"] == {}
    assert scores["categories"]["Auth"] == 10.0
    assert "Auth" not in scores["unexamined"]


def test_origin_category_survives_the_trip_through_the_pipeline():
    """The field is set by the scanner, travels as a dict, and is rebuilt into
    a ScoredFinding by app/scan/pipeline.py — which copies only the names in
    _SCORED_FIELDS. Omitting it there drops it silently: the producer still
    sets it, the report still reads it off the dict, and only the SCORE
    computes as though it were never set. Every test above would still pass.
    """
    from app.scan.pipeline import _SCORED_FIELDS

    assert "origin_category" in _SCORED_FIELDS
    finding = {k: v for k, v in vars(_f_from("Auth", "Security")).items()}
    rebuilt = ScoredFinding(**{k: finding[k] for k in _SCORED_FIELDS
                               if k in finding})
    assert rebuilt.origin_category == "Auth"
    assert compute_scores([rebuilt])["reported_elsewhere"] == {"Auth": ["Security"]}


# --- a preview runs SOME rubrics, not all of them ----------------------------


def test_a_preview_does_not_credit_categories_no_rubric_looked_at():
    """A boolean was enough while the LLM stage was all-or-nothing.

    The free tier runs one rubric. With llm_ran=True and nothing finer, Auth,
    Money & Data and Frontend each scored 10.0 off a stage that never looked
    at them, counted in the mean, and drew a full green bar -- issue #22 again,
    on a preview instead of a static scan.
    """
    findings = [ScoredFinding(rule_id="llm-security", title="t",
                              severity="critical", confidence=0.9,
                              category="Security")]
    preview = compute_scores(findings, llm_ran=True,
                             llm_categories=frozenset({"Security"}))

    assert set(preview["unexamined"]) == set(LLM_ONLY_CATEGORIES)
    # ...and a paid audit, which runs every rubric, still counts them.
    paid = compute_scores(findings, llm_ran=True)
    assert paid["unexamined"] == []
    # The two must differ in the total, or the exclusion is cosmetic.
    assert preview["total"] != paid["total"]


def test_a_widened_preview_credits_the_rubric_it_gained():
    """FREE_TIER_LLM_RUBRICS is env-configurable, so this cannot be hardcoded
    to "Security". Adding the auth rubric must make Auth examined."""
    findings = [ScoredFinding(rule_id="llm-auth", title="t", severity="high",
                              confidence=0.9, category="Auth")]
    wider = compute_scores(findings, llm_ran=True,
                           llm_categories=frozenset({"Security", "Auth"}))

    assert "Auth" not in wider["unexamined"]
    assert set(wider["unexamined"]) == {"Money & Data", "Frontend"}


def test_none_means_every_category_and_is_not_an_empty_set():
    """The distinction every caller written before previews relies on: None is
    "all of them", and an empty set is "the stage ran and covered none".
    Conflating them makes a paid audit look like a preview."""
    findings = [ScoredFinding(rule_id="llm-security", title="t",
                              severity="high", confidence=0.9,
                              category="Security")]

    assert compute_scores(findings, llm_ran=True,
                          llm_categories=None)["unexamined"] == []
    assert set(compute_scores(findings, llm_ran=True,
                              llm_categories=frozenset())["unexamined"]) == set(
        LLM_ONLY_CATEGORIES)


def test_the_preview_category_set_is_derived_from_the_rubrics_that_ran():
    """The pipeline must read RUBRICS rather than repeat the mapping.

    A second copy of "which rubric fills which category" drifts the moment a
    rubric is added or its category changes, and the drift is silent: the
    score simply credits a category nothing examined.
    """
    from app.scan.llm_scan import RUBRICS
    from app.scan.pipeline import FREE_TIER_RUBRICS

    for rubric in FREE_TIER_RUBRICS:
        assert rubric in RUBRICS, (
            f"FREE_TIER_LLM_RUBRICS names {rubric!r}, which no rubric "
            "defines -- the preview would run nothing for it")
    derived = frozenset(RUBRICS[r]["category"] for r in FREE_TIER_RUBRICS)
    assert derived and derived <= set(CATEGORIES)
