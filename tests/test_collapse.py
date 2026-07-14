from app.scan.collapse import collapse_repeats


def _f(rule_id, file, sev="low", conf=0.3, masked=""):
    return {"rule_id": rule_id, "title": "Some finding", "severity": sev,
            "confidence": conf, "category": "Security", "file": file,
            "line": 1, "masked": masked, "explanation": "", "fix_hint": ""}


def test_repeats_of_collapsible_rule_become_one():
    findings = [_f("supabase-anon-key", f"migrations/{i}.sql") for i in range(47)]
    out = collapse_repeats(findings)
    assert len(out) == 1
    assert out[0]["occurrence_count"] == 47
    assert "found in 47 places" in out[0]["title"]
    assert "47 files" in out[0]["explanation"]


def test_single_occurrence_untouched():
    out = collapse_repeats([_f("supabase-anon-key", "a.sql")])
    assert len(out) == 1
    assert "occurrence_count" not in out[0]
    assert "found in" not in out[0]["title"]


def test_non_collapsible_rule_passes_through():
    findings = [_f("stripe-live-key", "a.ts"), _f("stripe-live-key", "b.ts")]
    out = collapse_repeats(findings)
    assert len(out) == 2  # distinct real secrets, not collapsed


def test_representative_is_most_severe():
    findings = [_f("jwt-in-code", "a.sql", "low", 0.3),
                _f("jwt-in-code", "b.sql", "high", 0.9)]
    out = collapse_repeats(findings)
    assert len(out) == 1
    assert out[0]["severity"] == "high"


def test_distinct_secrets_under_one_rule_are_not_collapsed():
    # Two DIFFERENT hardcoded credentials (distinct masked fingerprints)
    # under the same collapsible rule must stay separate -- collapsing
    # them would drop evidence and under-penalize the score.
    findings = [_f("generic-assignment", "a.py", "high", 0.9, masked="AAAA****(20 chars)"),
                _f("generic-assignment", "b.py", "high", 0.9, masked="BBBB****(30 chars)")]
    out = collapse_repeats(findings)
    assert len(out) == 2
    assert all("occurrence_count" not in f for f in out)


def test_same_secret_value_collapses_even_for_non_anon_rule():
    # The SAME value pasted across files (identical masked) still
    # collapses, regardless of which collapsible rule matched it.
    findings = [_f("generic-assignment", f"m{i}.py", "high", 0.9, masked="SAME****(20 chars)")
                for i in range(3)]
    out = collapse_repeats(findings)
    assert len(out) == 1
    assert out[0]["occurrence_count"] == 3
