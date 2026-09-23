"""Context damping in the score: shown in the report, not charged to a category.

The contract these pin (see _NO_PENALTY_CONTEXTS in app/scan/scoring.py):

  * a test-fixture placeholder and a documentation/example value are NOT
    evidence against the running code -- they leave the category score alone;
  * a real source leak IS charged, but a `test_file` hit is NOT -- it is shown
    at medium while the score stays blind to it (operator decision, see
    _NO_PENALTY_CONTEXTS).

ScoredFinding.context is what branches this, so a finding is damped by what it
IS, not by string-matching a title suffix.
"""

from app.scan.scoring import ScoredFinding, _score, compute_scores


def _finding(context: str | None) -> ScoredFinding:
    return ScoredFinding(
        rule_id="generic-assignment",
        title="Hardcoded credential assignment",
        severity="medium",
        confidence=1.0,
        category="Security",
        file="src/config.ts",
        line=1,
        context=context,
    )


def _security(findings) -> float:
    return compute_scores(findings)["categories"]["Security"]


def test_a_test_fixture_placeholder_is_not_charged():
    assert _security([_finding("test_fixture")]) == 10.0


def test_a_doc_example_is_not_charged():
    assert _security([_finding("doc_example")]) == 10.0


def test_a_real_source_leak_is_still_charged():
    assert _security([_finding(None)]) < 10.0


def test_a_test_file_hit_is_shown_but_not_charged():
    """A `test_file` hit is REPORTED (medium, its own section) but must not
    lower the score -- Security is "safe to put in front of users" and test code
    never runs there. The trade-off (a real leak-in-test will not lower the
    headline) is recorded in _NO_PENALTY_CONTEXTS; this pins that decision from
    drifting back silently."""
    assert _security([_finding("test_file")]) == 10.0


def test_a_damped_finding_is_transparent_not_dropped():
    """Damping zeroes the finding's charge; it must not remove the finding, nor
    shield a real one sitting beside it."""
    charged = _finding(None)
    damped = _finding("test_fixture")
    assert _score([charged, damped]) == _score([charged])
