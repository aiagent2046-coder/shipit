"""Whether a Fix Pack was wrong, decided from our records rather than belief.

THE THING THIS FILE IS GUARDING AGAINST is not a wrong answer. It is a drift in
what the question means. A "was the customer right to complain" checker becomes
a machine for saying no: every ambiguous case rounds to "we delivered", the
operator has a printout to point at, and the refund conversation is an argument
the customer loses to a program.

So the tests below spend most of their effort on two properties:

  * UNDETERMINED stays a real answer. It must be reachable, it must be
    reachable from the most common shapes, and it must never quietly become
    DELIVERED.
  * A closed pull request never decides anything, in either direction.

The OWED cases are the easy half, and each one is a thing that actually
happened or nearly did.
"""

from __future__ import annotations

from app.fixpack.merit import DELIVERED, OWED, UNDETERMINED, assess


def job(**overrides) -> dict:
    base = {"id": "job-1", "status": "delivered", "verified": True,
            "detail": None}
    return {**base, **overrides}


def outcome(**overrides) -> dict:
    base = {"outcome": "delivered", "rule_ids": ["aws-access-key-id"],
            "is_regression": False, "pr_url": "https://github.com/a/b/pull/1",
            "pr_merged": None}
    return {**base, **overrides}


def codes(verdict) -> set[str]:
    return {r.code for r in verdict.reasons}


# --- we were wrong, and our own tables say so -------------------------------

def test_paid_and_no_job_ever_ran() -> None:
    """The loudest evidence there is. Money was taken and nothing was even
    attempted."""
    verdict = assess(job=None, outcome=None)
    assert verdict.conclusion == OWED
    assert verdict.owed is True
    assert "no_job" in codes(verdict)


def test_a_failed_job_is_not_a_judgement_call() -> None:
    verdict = assess(job=job(status="failed", detail="sandbox timeout"),
                     outcome=None)
    assert verdict.conclusion == OWED
    # The operator sees WHY, because the same screen is where they decide
    # whether it was our infrastructure or the customer's repository.
    assert any("sandbox timeout" in r.detail for r in verdict.reasons)


def test_our_own_verifier_having_rejected_it_is_decisive() -> None:
    """The strongest kind of signal: us disagreeing with us. Whatever the
    customer thinks of the patch, we had already judged it broken and sent it
    anyway."""
    verdict = assess(job=job(verified=False, detail="build failed after patch"),
                     outcome=outcome())
    assert verdict.conclusion == OWED
    assert "verifier_rejected" in codes(verdict)


def test_a_verifier_that_never_ran_is_not_a_rejection() -> None:
    """`verified` is NULL when the verifier did not run, which is a much weaker
    fact than the verifier saying no. Reading NULL as False would refund every
    job that skipped verification."""
    verdict = assess(job=job(verified=None), outcome=outcome())
    assert verdict.conclusion != OWED
    assert "verifier_rejected" not in codes(verdict)


def test_a_regression_flagged_by_our_own_gate() -> None:
    verdict = assess(job=job(), outcome=outcome(is_regression=True))
    assert verdict.conclusion == OWED
    assert "regression" in codes(verdict)


def test_an_empty_pull_request_is_not_the_product() -> None:
    """MEASURED: a customer's Fix Pack changed one line and the pull request
    for the rest was empty. Delivered, technically. Not the product."""
    verdict = assess(job=job(), outcome=outcome(rule_ids=[]))
    assert verdict.conclusion == OWED
    assert "delivered_nothing" in codes(verdict)


def test_nothing_to_fix_is_our_mistake_and_says_so() -> None:
    """Audit 05fa18f5: sold a Fix Pack with zero fixable findings, the job ran,
    found nothing, and the payer was charged for "Nothing to auto-fix". The
    findings were on the audit before the sale. #136 stopped that sale from
    happening again; this recognises it when it does."""
    verdict = assess(job=job(status="no_fix_needed"),
                     outcome=outcome(outcome="no_fix_needed", rule_ids=[]))
    assert verdict.conclusion == OWED
    assert "nothing_to_fix" in codes(verdict)
    # The wording matters: it must not read as though the customer got an
    # unlucky result.
    reason = next(r for r in verdict.reasons if r.code == "nothing_to_fix")
    assert "our" in reason.detail.lower()


def test_a_blocked_job_delivered_nothing() -> None:
    verdict = assess(job=job(status="blocked"),
                     outcome=outcome(outcome="blocked", rule_ids=[],
                                     pr_url=None))
    assert verdict.conclusion == OWED
    assert "blocked" in codes(verdict)


# --- we delivered, which is not the same as "the customer is wrong" ---------

def test_a_delivered_and_merged_fix_pack_reads_as_delivered() -> None:
    verdict = assess(job=job(), outcome=outcome(pr_merged=True))
    assert verdict.conclusion == DELIVERED
    assert "delivered_fixes" in codes(verdict)
    assert "pr_merged" in codes(verdict)


def test_delivered_does_not_claim_the_purchase_was_worth_it() -> None:
    """The boundary that keeps this from becoming a refusal engine. A fix can
    be correct and useless to the person who bought it, and that is still a
    refund a human may decide to make."""
    verdict = assess(job=job(), outcome=outcome(pr_merged=True))
    reason = next(r for r in verdict.reasons if r.code == "delivered_fixes")
    assert "cannot answer" in reason.detail


def test_the_rule_ids_are_named_so_the_operator_can_check_them() -> None:
    verdict = assess(job=job(), outcome=outcome(
        rule_ids=["aws-access-key-id", "supabase-rls-missing"], pr_merged=True))
    reason = next(r for r in verdict.reasons if r.code == "delivered_fixes")
    assert "aws-access-key-id" in reason.detail
    assert "supabase-rls-missing" in reason.detail


def test_a_long_list_of_fixes_is_truncated_rather_than_dumped() -> None:
    """The operator reads this on a refund screen. Twenty rule ids is a wall,
    and a wall is skipped."""
    verdict = assess(job=job(), outcome=outcome(
        rule_ids=[f"rule-{i:02}" for i in range(20)], pr_merged=True))
    reason = next(r for r in verdict.reasons if r.code == "delivered_fixes")
    assert "and 14 more" in reason.detail


# --- undetermined has to stay a real answer ---------------------------------

def test_a_closed_pull_request_decides_nothing() -> None:
    """It has at least four readings -- the fix was wrong, they fixed it
    another way, they preferred their own patch, they never looked -- and only
    one of them is ours to be sorry about. This is the single assertion most
    worth keeping: turning it decisive in EITHER direction is the obvious
    "improvement" somebody will make."""
    verdict = assess(job=job(), outcome=outcome(pr_merged=False))
    assert verdict.conclusion == UNDETERMINED
    assert "pr_closed_unmerged" in codes(verdict)
    reason = next(r for r in verdict.reasons if r.code == "pr_closed_unmerged")
    assert "decides nothing" in reason.detail


def test_a_job_with_no_recorded_outcome_is_undetermined() -> None:
    """Not DELIVERED. A missing row is an absence of evidence, and rounding it
    to "we delivered" is how this becomes a machine for saying no."""
    verdict = assess(job=job(), outcome=None)
    assert verdict.conclusion == UNDETERMINED
    assert "no_outcome_recorded" in codes(verdict)


def test_a_state_with_no_rule_says_so_instead_of_guessing() -> None:
    """A new outcome value can be written without a migration -- that is
    deliberate, and migration 0014 says so. The cost is that this function will
    meet values it has never seen, and the right answer then is to ask a
    person."""
    verdict = assess(job=job(status="something-new"),
                     outcome=outcome(outcome="something-new"))
    assert verdict.conclusion == UNDETERMINED
    assert "unrecognised_state" in codes(verdict)
    reason = next(r for r in verdict.reasons if r.code == "unrecognised_state")
    assert "by hand" in reason.detail


# --- the shape of a verdict -------------------------------------------------

def test_every_verdict_carries_its_reasons() -> None:
    """A conclusion with nothing attached is an authority nobody can check."""
    for verdict in (
        assess(job=None, outcome=None),
        assess(job=job(), outcome=outcome(pr_merged=True)),
        assess(job=job(), outcome=outcome(pr_merged=False)),
        assess(job=job(), outcome=None),
    ):
        assert verdict.reasons, verdict.conclusion
        assert all(r.code and r.detail for r in verdict.reasons)


def test_only_an_owed_verdict_has_a_decisive_reason() -> None:
    """`decisive` marks the reason that settled it. On a verdict that settled
    nothing, marking one would misrepresent what the mechanism knows."""
    undetermined = assess(job=job(), outcome=outcome(pr_merged=False))
    assert not any(r.decisive for r in undetermined.reasons)

    owed = assess(job=job(), outcome=outcome(is_regression=True))
    assert any(r.decisive for r in owed.reasons)


def test_it_serialises_to_something_an_operator_screen_can_render() -> None:
    payload = assess(job=None, outcome=None).as_dict()
    assert payload["conclusion"] == OWED
    assert payload["reasons"][0]["code"] == "no_job"
    assert payload["reasons"][0]["decisive"] is True


def test_it_is_pure() -> None:
    """No database, no network, no clock -- which is what makes a verdict
    reproducible when somebody disputes it six weeks later."""
    import ast
    import pathlib

    import app.fixpack.merit as merit

    source = pathlib.Path(merit.__file__).read_text()
    imported = {
        node.module for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom) and node.module
    } | {
        alias.name for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Import) for alias in node.names
    }
    assert not (imported - {"dataclasses", "typing", "__future__"}), imported
