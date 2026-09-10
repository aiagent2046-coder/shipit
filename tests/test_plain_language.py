"""Plain-language reports explain observations and their evidence limits."""
from app.report.html import render_report
from app.report.plain_language import PLAIN, plain_fields, tier
from app.scan.checks import run_checks  # noqa: F401 (import sanity)


def _all_static_rule_ids():
    import ast
    from pathlib import Path

    ids = set()
    for path in ("app/scan/secrets.py", "app/scan/checks.py"):
        for node in ast.walk(ast.parse(Path(path).read_text())):
            value = None
            # Read actual constructors, including ones with comments before
            # their first argument. Adjacent marker strings are not rule IDs.
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id in {"SecretRule", "CheckFinding"}):
                value = node.args[0] if node.args else next(
                    (item.value for item in node.keywords if item.arg in {"id", "rule_id"}), None)
            # Reclassified anon/demo keys and local/development DSNs have no
            # constructor of their own, but still need report translations.
            elif (isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == "effective_rule_id"
                          for target in node.targets)):
                value = node.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                ids.add(value.value)
    return ids


def test_every_static_rule_has_a_translation():
    missing = _all_static_rule_ids() - set(PLAIN)
    assert not missing, f"rules without plain-language entries: {missing}"


def test_the_re_routed_ids_are_in_what_this_guard_checks():
    """Guards the guard. The check above is only as good as the ids it
    collects, and the ids most likely to be forgotten are exactly the ones no
    rule declares -- they are written at the point a match is reclassified,
    far from any SecretRule constructor."""
    ids = _all_static_rule_ids()
    from app.scan.secrets import RULES

    assert {rule.id for rule in RULES} <= ids
    assert not {"not-a-real", "smoke-test"} & ids

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
