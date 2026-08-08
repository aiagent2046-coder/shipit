"""Static findings must arrive with an explanation a non-engineer can act on.

The free tier is static-only, so these five rules are the entire audit most
visitors ever see. They used to arrive as bare titles: "Environment file
committed to repository" and nothing else — which tells someone who shipped
their first app neither what the risk is nor what to do. The LLM findings had
carried `explanation`/`fix_hint` all along; the static ones simply never
populated the fields that `ScoredFinding` already had.

These tests pin two things: every rule carries both fields, and the wiring in
static.py actually forwards them (the fields existing on the dataclass is not
the same as them reaching the output).
"""

from __future__ import annotations

import io
import zipfile

import pytest

from app.scan.checks import run_checks
from app.scan.static import run_static_scan


def make_zip(entries: dict[str, str]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in entries.items():
            zf.writestr(name, body)
    buf.seek(0)
    return buf


# A repo that trips every one of the five checks at once: committed .env, a
# .gitignore that does not cover it, no tests, no Dockerfile, no CI.
BARE_REPO = {
    "proj/.env": 'VITE_SUPABASE_URL="https://example.supabase.co"\n',
    "proj/.gitignore": "node_modules\ndist\n",
    "proj/package.json": '{"dependencies":{"vite":"5","react":"18"}}',
    "proj/src/App.tsx": "export default function App(){return null}",
}

ALL_RULES = {
    "env-file-committed",
    "gitignore-missing-secrets",
    "no-tests",
    "no-dockerfile",
    "no-ci",
}


def test_every_static_rule_fires_on_a_bare_repo() -> None:
    """Guards the fixture itself: if a rule stopped firing, the coverage
    tests below would pass vacuously."""
    fired = {f.rule_id for f in run_checks(make_zip(BARE_REPO))}

    assert fired == ALL_RULES


@pytest.mark.parametrize("rule_id", sorted(ALL_RULES))
def test_every_static_rule_explains_itself(rule_id: str) -> None:
    findings = {f.rule_id: f for f in run_checks(make_zip(BARE_REPO))}
    finding = findings[rule_id]

    assert finding.explanation.strip(), f"{rule_id} has no explanation"
    assert finding.fix_hint.strip(), f"{rule_id} has no fix_hint"


@pytest.mark.parametrize("rule_id", sorted(ALL_RULES))
def test_the_text_says_something(rule_id: str) -> None:
    """A one-word placeholder would satisfy a non-empty check and help nobody.

    Not a style rule — a floor. The point of these fields is a concrete harm
    and a concrete action, neither of which fits in a few words.
    """
    findings = {f.rule_id: f for f in run_checks(make_zip(BARE_REPO))}
    finding = findings[rule_id]

    assert len(finding.explanation) > 80, f"{rule_id} explanation is too thin"
    assert len(finding.fix_hint) > 40, f"{rule_id} fix_hint is too thin"


def test_the_explanations_reach_the_scan_output() -> None:
    """The wiring, not the data.

    checks.py carrying the text and static.py forwarding it are separate
    facts: ScoredFinding had `explanation`/`fix_hint` fields all along, and
    the static-check branch simply never passed them. Populating the dataclass
    without this line would leave the output exactly as empty as before.
    """
    result = run_static_scan(make_zip(BARE_REPO))

    assert len(result["findings"]) == len(ALL_RULES)
    for finding in result["findings"]:
        assert finding["explanation"].strip(), (
            f"{finding['rule_id']} lost its explanation between "
            "run_checks and run_static_scan"
        )
        assert finding["fix_hint"].strip(), (
            f"{finding['rule_id']} lost its fix_hint between "
            "run_checks and run_static_scan"
        )


def test_explanations_avoid_unexplained_jargon() -> None:
    """The audience shipped their first app with an AI assistant.

    Terms of art are allowed where they name a thing the reader must type or
    click (`.gitignore`, `git rm --cached`, GitHub Actions). What is not
    allowed is a term used AS the explanation — telling someone their app is
    "not containerized" restates the title instead of saying what goes wrong.
    """
    banned = ("XSS", "CSRF", "RLS", "CI/CD", "idempotent", "SSRF")
    findings = run_checks(make_zip(BARE_REPO))

    for finding in findings:
        for term in banned:
            assert term not in finding.explanation, (
                f"{finding.rule_id} explanation leans on unexplained "
                f"jargon: {term}"
            )


def test_the_env_fix_says_to_rotate_the_secrets() -> None:
    """The single most consequential instruction in the whole free tier.

    Untracking a committed .env does NOT unpublish it — Git keeps every past
    version, so the values stay readable in the history. Someone who only
    deletes the file believes they are safe while their keys are still live.
    Whatever else the text says, it has to say that.
    """
    findings = {f.rule_id: f for f in run_checks(make_zip(BARE_REPO))}
    text = (
        findings["env-file-committed"].explanation
        + " "
        + findings["env-file-committed"].fix_hint
    ).lower()

    assert "rotate" in text or "new ones" in text, (
        "the .env finding must tell the user to issue new credentials"
    )
    assert "history" in text, (
        "the .env finding must say deleting the file does not erase it from "
        "Git history"
    )
