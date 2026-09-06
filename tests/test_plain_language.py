"""Plain-language reports explain observations and their evidence limits."""
from app.report.html import render_report
from app.report.plain_language import PLAIN, plain_fields, tier
from app.scan.checks import run_checks  # noqa: F401 (import sanity)


def _all_static_rule_ids():
    import re
    ids = set()
    for path in ("app/scan/secrets.py", "app/scan/checks.py"):
        src = open(path).read()
        # SecretRule("id", ... / CheckFinding("id", ...
        ids |= set(re.findall(r'(?:SecretRule|CheckFinding)\(\s*\n?\s*"([a-z0-9-]+)"', src))
        # Fallback for rule ids the constructor regex misses. Requires a
        # leading letter and three characters minimum: without that it also
        # matches any adjacent pair of short string literals, and picked up
        # "--" from the comment-prefix tuple in secrets.py as a rule id.
        ids |= set(re.findall(r'"([a-z][a-z0-9-]{2,})", "', src))
        # Ids that no rule declares: _classify_match re-routes a match to a
        # DIFFERENT id once it knows what the value is (an anon key, a demo
        # key, a tutorial password, a localhost DSN). Four such ids existed
        # and this function saw none of them -- so any of the four could have
        # reached the report with no translation at all, which does not fail
        # loudly: plain_fields falls back to the technical title, and static
        # secret findings carry no explanation or fix_hint of their own, so
        # the reader gets a finding with an EMPTY "what to do".
        ids |= set(re.findall(r'effective_rule_id = "([a-z][a-z0-9-]+)"', src))
    return {i for i in ids if "-" in i}


def test_every_static_rule_has_a_translation():
    missing = _all_static_rule_ids() - set(PLAIN)
    assert not missing, f"rules without plain-language entries: {missing}"


def test_the_re_routed_ids_are_in_what_this_guard_checks():
    """Guards the guard. The check above is only as good as the ids it
    collects, and the ids most likely to be forgotten are exactly the ones no
    rule declares -- they are written at the point a match is reclassified,
    far from any SecretRule constructor."""
    ids = _all_static_rule_ids()

    assert {"supabase-anon-key", "supabase-demo-key",
            "connection-string-dev-password",
            "connection-string-local-host"} <= ids


def test_translations_are_jargon_light_and_complete():
    for rid, (what, risk, fix) in PLAIN.items():
        assert what and risk and fix, rid
        # concrete harm scenario, not a bare term: risk must be a sentence
        assert len(risk) > 40, rid


def test_llm_finding_uses_its_own_explanation():
    f = {"rule_id": "llm-auth", "title": "IDOR on unsubscribe",
         "explanation": "Anyone who finds the link can unsubscribe other "
                        "people's accounts.",
         "fix_hint": "Require a signed token instead of the raw user id."}
    what, risk, fix = plain_fields(f)
    assert what == "IDOR on unsubscribe"
    assert "unsubscribe other" in risk
    assert fix.startswith("Require")


def test_unknown_rule_degrades_to_title_not_empty():
    what, risk, fix = plain_fields({"rule_id": "future-rule", "title": "T"})
    assert what == "T"


def test_report_renders_plain_text_and_tiers():
    """The finding here carries no explanation/fix_hint of its own, which is
    the point: that is the dictionary's remaining job. Since #217 every static
    rule ships its own text and plain_fields prefers it, so PLAIN is reached
    only by findings that have none -- stored audits written before #217, and
    any producer that skips the fields.
    """
    result = {
        "score": {"total": 4.2, "basis": "static+llm",
                  "categories": {c: 5.0 for c in
                                 ("Security", "Auth", "Correctness",
                                  "Config", "Testing", "Deploy")}},
        "findings": [
            {"rule_id": "env-file-committed", "title": "Environment file...",
             "severity": "critical", "confidence": 0.9,
             "category": "Security", "file": ".env", "line": 0, "masked": ""},
        ],
        "llm": {"prompts": 2},
    }
    html = render_report(result, "demo")
    assert "Potential critical impact" in html
    assert "environment configuration file is included in the archive" in html  # plain-language what
    assert "rotate any exposed real credentials" in html        # plain-language fix


def test_tier_mapping_total():
    assert tier("critical")[1] == "Fix before launch"
    assert tier("unknown")[1] == "Good to know"


def test_a_findings_own_text_beats_the_dictionary():
    """The dictionary cannot know which case a graded rule found.

    env-file-committed now says one thing for a .env holding a live key and
    another for one holding a build path. Before this, plain_fields printed
    the dictionary's wording AND appended the finding's own -- so a graded
    rule produced a paragraph asserting both, under a fix telling the reader
    to rotate secrets that may not exist.
    """
    graded = {
        "rule_id": "env-file-committed", "title": "Environment file tracked",
        "severity": "medium", "confidence": 0.6, "category": "Security",
        "explanation": "Nothing in it looks like a password or key today.",
        "fix_hint": "Stop tracking it and add .env to .gitignore.",
    }
    what, risk, fix = plain_fields(graded)

    assert risk == graded["explanation"]
    assert fix == graded["fix_hint"]
    assert "rotate" not in (risk + fix).lower()
    # ...and the dictionary's wording is gone, not merely appended to.
    assert "entire keychain" not in risk


def test_the_occurrence_note_still_reaches_the_report():
    """Keep structured occurrence evidence when replacing categorical prose."""
    collapsed = {
        "rule_id": "generic-assignment", "title": "Hardcoded credential",
        "severity": "high", "confidence": 0.5, "category": "Security",
        "occurrence_count": 4, "occurrence_files": ["a.ts", "b.ts", "c.ts"],
        "explanation": "A secret is written into the code. "
                       "This appears in 4 files: a.ts, b.ts, c.ts.",
        "fix_hint": "Move it to an environment variable.",
    }
    _, risk, _ = plain_fields(collapsed)

    assert "4 occurrences are recorded" in risk
    assert "a.ts, b.ts, c.ts" in risk
