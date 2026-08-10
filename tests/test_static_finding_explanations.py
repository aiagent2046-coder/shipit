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
# The .env carries a real-looking credential deliberately. env-file-committed
# is now graded on the file's contents, and the "rotate your keys" instruction
# below only belongs on a .env that actually exposes something -- a fixture
# holding nothing but a public URL would exercise the innocuous branch while
# claiming to test the leak one. A Lovable export looks like this: the project
# URL next to the key that opens it.
BARE_REPO = {
    "proj/.env": (
        'VITE_SUPABASE_URL="https://example.supabase.co"\n'
        'DB_PASSWORD="hunter2hunter2"\n'  # scan-allow: fixture, invented credential
    ),
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


def test_a_committed_env_with_no_credentials_is_not_called_a_leak() -> None:
    """The other half of the same instruction.

    env-file-committed used to be critical on the filename alone, and its text
    told every reader that "database passwords, API keys, payment credentials"
    were visible — including readers whose .env holds a build path. React's
    fixtures/fiber-debugger/.env is one line, NODE_PATH=../../build/packages.
    Saying that file leaked their credentials is simply false, and since
    GATE_ON_CRITICAL that false claim also caps the repository's headline.

    So the finding still fires — a tracked .env is how the next real secret
    gets committed — but it must not assert an exposure that is not there.
    """
    repo = dict(BARE_REPO)
    repo["proj/.env"] = "NODE_PATH=../../build/packages\n"
    findings = {f.rule_id: f for f in run_checks(make_zip(repo))}

    env = findings["env-file-committed"]
    assert env.severity == "medium", (
        "a .env with no credential in it must not be critical: one confident "
        "critical caps the score (GATE_ON_CRITICAL)")

    text = (env.explanation + " " + env.fix_hint).lower()
    assert "rotate" not in text and "already leaked" not in text, (
        "nothing was leaked, so the text must not tell the reader to treat "
        "values as compromised")
    # It still has to explain why a tracked .env matters at all, or the
    # downgrade turns the finding into noise the reader learns to skip.
    assert "gitignore" in text
    assert "history" in text


def test_the_env_severity_follows_the_contents_not_the_filename() -> None:
    """Both branches, side by side, off one fixture pair -- so a change that
    collapses them into one answer cannot pass by satisfying either alone."""
    leaky = dict(BARE_REPO)
    # Split the way tests/test_secrets.py does: written whole, the literal
    # trips GitHub push protection and the repo's own added-secrets scanner,
    # neither of which can tell a fixture from a leak.
    leaky["proj/.env"] = "STRIPE_SECRET_KEY=" + "sk_live_" + "a" * 24 + "\n"
    innocuous = dict(BARE_REPO)
    innocuous["proj/.env"] = "PORT=8080\nDEBUG=true\n"

    def sev(repo: dict) -> str:
        return next(f.severity for f in run_checks(make_zip(repo))
                    if f.rule_id == "env-file-committed")

    assert sev(leaky) == "critical"
    assert sev(innocuous) == "medium"
