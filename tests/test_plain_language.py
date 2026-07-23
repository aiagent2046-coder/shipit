"""The plain-language layer is the conversion surface of the report:
a finding the reader doesn't understand doesn't scare, share, or sell."""
from app.report.html import render_report
from app.report.plain_language import PLAIN, plain_fields, tier
from app.scan.checks import run_checks  # noqa: F401 (import sanity)


def _all_static_rule_ids():
    import re
    ids = set()
    for path in ("app/scan/secrets.py", "app/scan/checks.py"):
        with open(path) as fh:
            src = fh.read()
        # SecretRule("id", ... / CheckFinding("id", ...
        ids |= set(re.findall(r'(?:SecretRule|CheckFinding)\(\s*\n?\s*"([a-z0-9-]+)"', src))
        ids |= set(re.findall(r'"([a-z0-9-]+)", "', src))
    return {i for i in ids if "-" in i}


def test_every_static_rule_has_a_translation():
    missing = _all_static_rule_ids() - set(PLAIN)
    assert not missing, f"rules without plain-language entries: {missing}"


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
    what, _risk, _fix = plain_fields({"rule_id": "future-rule", "title": "T"})
    assert what == "T"


def test_report_renders_plain_text_and_tiers():
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
    assert "Fix before launch" in html          # tier, not raw "critical"
    assert "ALL your secrets" in html           # plain-language what
    assert "rotate every secret" in html        # plain-language fix


def test_tier_mapping_total():
    assert tier("critical")[1] == "Fix before launch"
    assert tier("unknown")[1] == "Good to know"
