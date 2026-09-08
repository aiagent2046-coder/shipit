"""A corpus must fail when its assertions stop distinguishing correct output."""
import pytest

from .test_golden_corpus import assert_case, emitted_rule_ids


@pytest.mark.parametrize("polarity,expected", [
    ("negative", {"forbid": []}),
    ("negative", {"forbid": ["unrelated-rule"]}),
    ("positive", {"expect": []}),
    ("positive", {"expect": [{"rule_id": "unrelated-rule"}]}),
])
def test_empty_or_unrelated_expectations_cannot_pass(polarity, expected):
    with pytest.raises(AssertionError):
        assert_case("stripe-live-key", polarity, expected, [{"rule_id": "unrelated-rule"}])


def test_file_and_severity_must_belong_to_the_same_finding():
    expected = {"expect": [{"rule_id": "stripe-live-key", "severity": "critical", "file_endswith": "right.ts"}]}
    findings = [{"rule_id": "stripe-live-key", "severity": "critical", "file": "wrong.ts"},
                {"rule_id": "stripe-live-key", "severity": "low", "file": "right.ts"}]
    with pytest.raises(AssertionError):
        assert_case("stripe-live-key", "positive", expected, findings)


def test_expected_multiplicity_catches_duplicate_findings():
    finding = {"rule_id": "stripe-live-key"}
    with pytest.raises(AssertionError):
        assert_case("stripe-live-key", "positive", {"expect": [finding | {"count": 1}]}, [finding, finding])


def test_discovery_includes_contextual_secret_ids_and_auth_scanner():
    assert {"connection-string-dev-password", "connection-string-local-host", "supabase-anon-key",
            "supabase-demo-key", "python-route-read-auth-consistency"} <= emitted_rule_ids()
