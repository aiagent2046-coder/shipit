"""`.env.example` is not the only name a template goes by.

find_committed_env_files excluded exactly one filename, `.env.example`, and
called everything else in the `.env.*` family a committed environment file.
Measured on mckaywrigley/chatbot-ui (audit f444873f): `.env.local.example`
was reported as a file that should not be tracked, in a finding whose own
advice tells the reader to keep "a committed .env.example with the secrets
left blank" -- the report telling them to do the thing they had done.

The report is the smaller half. The same function tells the Fix Pack which
files to untrack (app/fixpack/generate.py, `plan.deletions`), so a paid pull
request would have DELETED the customer's `.env.local.example`, `.env.sample`
or `.env.template`: removing the file that documents which variables the app
needs, and charging for it.

Two levels are asserted here on purpose. The predicate is where the rule
lives; the plan is where the money is, and it is the plan that opens the
pull request.

The second half of the file is the OTHER question the same name answers: not
"should this file be tracked" but "how loudly do we report a value found
inside it". A template is example context in the sense `README.md` already
is -- capped at medium, moved to the non-production section, never dropped.
"""

import io
import zipfile

import pytest

from app.fixpack.generate import build_fixpack_plan, render_pr_body
from app.scan.checks import find_committed_env_files, run_checks
from app.scan.secrets import scan_secrets

# Both orderings, because both are common in the wild and neither carries a
# secret: `.env.local.example` (Next.js) and `.env.example.local`.
TEMPLATES = [
    ".env.example",
    ".env.local.example",
    ".env.example.local",
    ".env.sample",
    ".env.template",
    ".env.dist",
    "apps/web/.env.local.example",
]

# The real thing: files that hold values, and that a repository should not be
# tracking. `.env.local` is the one that most often holds the live keys.
REAL_ENV_FILES = [
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    "apps/web/.env",
    "packages/api/.env.local",
]


# A DSN to the developer's own machine, the value that put
# `apps/web/.env.example` into dubinc/dub's main findings table (audit
# a5fcb681). Assembled from parts: written whole, a connection string with a
# password trips GitHub push protection and this repo's own added-secrets
# scanner, neither of which can tell a fixture from a leak.
LOCAL_DSN = "postgres://app:" + "zQ8" + "vT2mKp" + "@localhost:5432/app"
REMOTE_DSN = "postgres://app:" + "zQ8" + "vT2mKp" + "@db.prod.example.com:5432/app"


def make_zip(entries: dict[str, str]) -> bytes:
    """A GitHub-style zipball: one wrapper folder, as the real fetch produces."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, text in entries.items():
            zf.writestr(f"acme-app-deadbeef/{name}", text)
    return buf.getvalue()


def make_scan_zip(entries: dict[str, bytes]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    buf.seek(0)
    return buf


@pytest.mark.parametrize("name", TEMPLATES)
def test_a_template_is_not_a_committed_env_file(name):
    assert find_committed_env_files([name, "src/app.ts"]) == []


@pytest.mark.parametrize("name", REAL_ENV_FILES)
def test_a_real_env_file_still_is_one(name):
    """The other half of the boundary. Widening the exclusion until it
    swallows `.env.local` would be the worse defect of the two: that is the
    file the live keys are actually in."""
    assert find_committed_env_files([name, "src/app.ts"]) == [name]


def test_the_fixpack_does_not_delete_the_template_it_tells_you_to_create():
    """The defect where it costs money.

    `.env` is untracked, which is the fix the customer paid for. The template
    beside it is documentation and must survive the pull request untouched --
    not deleted, not rewritten.
    """
    zip_bytes = make_zip({
        ".env": "STRIPE_SECRET_KEY=sk_live_not_a_real_key\n",
        ".env.local.example": "STRIPE_SECRET_KEY=\nDATABASE_URL=\n",
        "app.py": "print('hi')\n",
    })
    findings = [{"rule_id": "env-file-committed", "file": ".env", "line": 0,
                 "title": "env-file-committed", "context": None}]

    plan = build_fixpack_plan(zip_bytes, findings)

    assert ".env" in plan.deletions
    assert ".env.local.example" not in plan.deletions
    assert ".env.local.example" not in plan.files, (
        "the template is not ours to rewrite either")
    # leaked_env_files is rendered into the pull request the customer reads.
    assert ".env.local.example" not in plan.leaked_env_files
    assert ".env.local.example" not in render_pr_body(plan)


def test_a_repo_whose_only_env_file_is_a_template_is_clean():
    """End to end through the check that produces the finding: a project doing
    it correctly -- template committed, real values outside the repo -- must
    not be told its environment file is committed."""
    buf = make_scan_zip({
        "acme/.env.local.example": b"DATABASE_URL=\nSTRIPE_SECRET_KEY=\n",
        "acme/.gitignore": b".env\n.env.*\n!.env.local.example\n",
        "acme/tests/test_x.py": b"",
        "acme/Dockerfile": b"",
        "acme/.github/workflows/ci.yml": b"",
    })

    ids = {f.rule_id for f in run_checks(buf)}

    assert "env-file-committed" not in ids


def test_a_real_env_file_beside_a_template_is_still_reported():
    """The control for the test above: the exclusion must not turn into a way
    to hide a committed `.env` by putting a template next to it."""
    buf = make_scan_zip({
        "acme/.env.local.example": b"DATABASE_URL=\n",
        "acme/.env": f"DATABASE_URL={REMOTE_DSN}\n".encode(),
    })

    findings = [f for f in run_checks(buf) if f.rule_id == "env-file-committed"]

    assert len(findings) == 1
    assert findings[0].file == ".env"   # the wrapper folder is stripped


# --- the same names, the other question: what a value INSIDE one weighs -----


def _secret_finding(path: str, body: str):
    buf = make_scan_zip({path: body.encode()})
    found = list(scan_secrets(buf))
    assert len(found) == 1, found
    return found[0]


@pytest.mark.parametrize("path", [
    "apps/web/.env.example", ".env.sample",
    "packages/api/.env.local.example", ".env.template",
])
def test_a_template_is_example_context_for_what_is_inside_it(path):
    """`apps/web/.env.example` matched no damping predicate: not a doc suffix,
    and `apps` and `web` are not doc segments. It is the single most
    example-like file a repository has -- its whole purpose is to show which
    variables exist without their values."""
    finding = _secret_finding(path, f'DATABASE_URL={LOCAL_DSN}\n')

    assert finding.context == "doc_example"


@pytest.mark.parametrize("path", [".env.local", "apps/web/.env.production"])
def test_a_real_env_file_is_not_example_context(path):
    """The boundary, and the expensive direction of this mistake: `.env.local`
    is where the live keys actually are."""
    finding = _secret_finding(path, f'DATABASE_URL={REMOTE_DSN}\n')

    assert finding.context is None
    assert finding.severity == "critical"


def test_a_live_key_pasted_into_a_template_is_still_reported():
    """Damped, never dropped -- the contract `README.md` already has. People
    do paste a real key into `.env.example` by mistake, and that finding has
    to survive: capped at medium and shown in the non-production section,
    not deleted."""
    live_stripe = "sk_live_" + "c" * 24

    finding = _secret_finding(".env.example", f"STRIPE_SECRET_KEY={live_stripe}\n")

    assert finding.rule_id == "stripe-live-key"
    assert finding.severity == "medium"          # capped from critical
    assert finding.context == "doc_example"
    assert live_stripe not in finding.masked
