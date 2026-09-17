"""An unavailable mutation probe must never be reported as a killed mutant."""
import pytest

from scripts.check_security_mutations import classify


@pytest.mark.parametrize("returncode,body", [
    (1, '<testcase><error message="fixture failed">AssertionError</error></testcase>'),
    (1, '<testcase><failure message="assert False">AssertionError</failure></testcase>'
        '<testcase><skipped message="DATABASE_URL missing" /></testcase>'),
    (1, '<testcase><failure message="RuntimeError: unavailable">RuntimeError</failure></testcase>'),
    (1, '<testcase><failure message="ExceptionGroup: Hypothesis found 2 distinct failures">'
        'AssertionError: mismatch; TypeError: fixture broken</failure></testcase>'),
    (1, '<testcase><failure message="RuntimeError: AssertionError in a dependency">'
        'AssertionError occurred before the runtime error</failure></testcase>'),
    (2, '<testcase><failure message="assert False">AssertionError</failure></testcase>'),
    (0, '<testcase><skipped message="DATABASE_URL missing" /></testcase>'),
    (0, ''),
])
def test_incomplete_execution_is_not_mutation_evidence(tmp_path, returncode, body):
    report = tmp_path / "probe.xml"
    report.write_text(f"<testsuites><testsuite>{body}</testsuite></testsuites>")
    assert classify(returncode, report, mutated=True) == "invalid"
    assert classify(returncode, report, mutated=False) == "invalid"


def test_passing_tests_only_establish_the_baseline_not_mutation_detection(tmp_path):
    report = tmp_path / "probe.xml"
    report.write_text('<testsuite><testcase name="positive-control" /></testsuite>')
    assert classify(0, report, mutated=False) == "passed"
    assert classify(0, report, mutated=True) == "survived"


def test_an_assertion_failure_detects_a_mutation_but_invalidates_the_baseline(tmp_path):
    report = tmp_path / "probe.xml"
    report.write_text('<testsuite><testcase name="ownership">'
                      '<failure message="assert 200 == 404">assert 200 == 404</failure>'
                      '</testcase></testsuite>')
    assert classify(1, report, mutated=True) == "detected"
    assert classify(1, report, mutated=False) == "invalid"


def test_missing_or_truncated_report_is_not_evidence(tmp_path):
    report = tmp_path / "probe.xml"
    assert classify(1, report, mutated=True) == "invalid"
    report.write_text('<testsuite><testcase><failure message="assert False">')
    assert classify(1, report, mutated=True) == "invalid"
