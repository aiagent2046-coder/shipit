"""Run the golden corpus, and gate the corpus itself.

Two test classes of work happen here:

1. every case is run through the real static stage and must produce the
   findings its expected.json declares -- this is the regression net that
   makes "the detector silently stopped working" a failing build instead of
   a customer report;

2. COMPLETENESS: every rule in the report vocabulary or declared by a
   wired scanner must have a positive AND negative case. Existing engine
   tests guard scanner wiring; this suite guards its reviewed examples.
"""

from __future__ import annotations

import inspect

import pytest

from app.report.plain_language import PLAIN
from app.scan import static
from app.scan.static import run_static_scan

from .conftest import build_archive, discover_cases, load_expected

CASES = discover_cases()
CASE_IDS = [f"{rule}/{polarity}/{path.name}" for rule, polarity, path in CASES]


def emitted_rule_ids() -> set[str]:
    """Report vocabulary plus declared IDs of scanners wired into static.

    PLAIN includes contextual secret IDs (demo/local/anon) that RULES does
    not. Other scanners own their own explanation and declare RULE_IDs.
    The existing engine-version tests independently guard scanner wiring.
    """
    ids = set(PLAIN)
    for name, scanner in vars(static).items():
        if name == "run_static_scan" or not name.startswith(("run_", "scan_")):
            continue
        module = inspect.getmodule(scanner)
        if module is None:
            continue
        ids.update(value for key, value in vars(module).items()
                   if key.endswith("RULE_ID") and isinstance(value, str))
    return ids


@pytest.mark.parametrize("rule_id,polarity,case_dir", CASES, ids=CASE_IDS)
def test_corpus_case(rule_id, polarity, case_dir):
    expected = load_expected(case_dir)
    findings = run_static_scan(build_archive(case_dir))["findings"]

    assert_case(rule_id, polarity, expected, findings)


def assert_case(rule_id, polarity, expected, findings):
    wants, forbidden = expected.get("expect", []), expected.get("forbid", [])
    if polarity == "positive":
        assert any(want.get("rule_id") == rule_id for want in wants), (
            "a positive case must expect its directory's rule")
    else:
        assert rule_id in forbidden, "a negative case must forbid its directory's rule"
    for want in wants:
        matches = [f for f in findings if all(
            (f.get("file", "").endswith(value) if key == "file_endswith" else f.get(key) == value)
            for key, value in want.items() if key != "count"
        )]
        assert matches, f"[{rule_id}] no finding satisfies the complete expectation: {want}"
        if "count" in want:
            assert len(matches) == want["count"], f"[{rule_id}] expected {want['count']} matches, got {len(matches)}"
    for rule in forbidden:
        assert rule not in {f["rule_id"] for f in findings}, f"[{rule_id}] forbidden finding {rule!r} fired"


def test_corpus_has_at_least_one_negative_case_per_fixtured_rule():
    """A rule with only positives proves it fires, not that it discriminates."""
    negatives = {rule for rule, polarity, _ in CASES if polarity == "negative"}
    positives = {rule for rule, polarity, _ in CASES if polarity == "positive"}
    missing = positives - negatives
    assert not missing, f"rules with positives but no negative case: {missing}"


def test_corpus_cases_reference_real_rule_ids():
    known = emitted_rule_ids()
    for rule_id, _, case_dir in CASES:
        expected = load_expected(case_dir)
        for want in expected.get("expect", []):
            assert want["rule_id"] in known, f"{case_dir}: {want['rule_id']}"
        for forbidden in expected.get("forbid", []):
            assert forbidden in known, f"{case_dir}: {forbidden}"


def test_every_emitted_rule_has_positive_and_negative_cases():
    emitted = emitted_rule_ids()
    for polarity in ("positive", "negative"):
        covered = {rule for rule, kind, _ in CASES if kind == polarity}
        assert covered == emitted, f"{polarity}: missing={emitted - covered}, unknown={covered - emitted}"


def test_every_case_has_a_description():
    for _, _, case_dir in CASES:
        expected = load_expected(case_dir)
        assert expected.get("description", "").strip(), (
            f"{case_dir}: a case without a description cannot be reviewed"
        )
