"""The audit describes this repository; the server runs another one.

FOUND ON A REAL AUDIT. `donjonson-hash/devtools-aggregator` scored 9.9 — a
full audit, model included, every category "nothing serious found". Honest
about its 25 files: four source files, no API routes, no auth, no database.
Dishonest about production, because its own deploy workflow does this:

    - uses: actions/checkout@v4          # builds THIS repo
    - name: Deploy via SSH
      script: |
        REPO=https://github.com/aiagent2046-coder/devtools-aggregator.git
        git clone $REPO $APP_DIR
        git reset --hard origin/main

The other repository scored 3.5 with five criticals on anonymous writes. The
owner reading 9.9 has every reason to think they are fine.

WHAT THESE TESTS DEFEND is the boundary either side of that. A workflow that
fetches a tools repo, or reads a URL in a comment, is not deploying it — fire
there and the rule becomes noise on half of CI. And a repository whose own
name we cannot establish gets silence, because "is that a different repo" has
no answer without it.
"""

from __future__ import annotations

import io
import zipfile

from app.scan.ci_deploy_source import (
    RULE_ID,
    deployed_repositories,
    scan_ci_deploy_source,
    self_identity,
)

SELF = "donjonson-hash-devtools-aggregator-bbaa262"


def make_zip(entries: dict[str, str], root: str = SELF) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in entries.items():
            zf.writestr(f"{root}/{name}" if root else name, body)
    buf.seek(0)
    return buf


def scan(entries: dict[str, str], root: str = SELF):
    return scan_ci_deploy_source(make_zip(entries, root))


# The shape found in the wild, reduced to what decides the outcome: the URL is
# assigned to a shell variable on one line and used on the next.
FOREIGN_DEPLOY = {".github/workflows/deploy.yml": """
name: Deploy to 4VPS
on:
  push:
    branches: [main]
jobs:
  deploy:
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npx tsc --noEmit && npm run build
      - name: Deploy via SSH
        uses: appleboy/ssh-action@v1.2.0
        with:
          script: |
            REPO=https://github.com/aiagent2046-coder/devtools-aggregator.git
            git clone $REPO /var/www/devstack
            cd /var/www/devstack
            git fetch origin main
            git reset --hard origin/main
"""}

OWN_DEPLOY = {".github/workflows/deploy.yml": """
jobs:
  deploy:
    steps:
      - uses: actions/checkout@v4
      - name: Deploy via SSH
        with:
          script: |
            git clone https://github.com/donjonson-hash/devtools-aggregator.git /var/www/app
            git reset --hard origin/main
"""}


# --- the finding ------------------------------------------------------------

def test_a_workflow_that_deploys_another_repository_is_reported() -> None:
    found = scan(FOREIGN_DEPLOY)
    assert [f.rule_id for f in found] == [RULE_ID]
    assert found[0].file == ".github/workflows/deploy.yml"
    assert found[0].severity == "high"
    assert found[0].category == "Deploy"
    assert "aiagent2046-coder/devtools-aggregator" in found[0].explanation


def test_deploying_your_own_repository_by_url_is_not_a_finding() -> None:
    """Cloning yourself by URL is legal and looks identical from inside the
    file. Only the archive's own name tells the two apart, which is the whole
    reason this rule needs it."""
    assert scan(OWN_DEPLOY) == []


def test_the_finding_does_not_call_the_other_repository_worse() -> None:
    """A monorepo split and a deliberate mirror have exactly this shape. What
    is always true is that only one of the two was checked — claiming more
    would be inventing a motive for somebody's architecture."""
    text = scan(FOREIGN_DEPLOY)[0].explanation
    assert "may be deliberate" in text
    assert "Nothing here says the other repository is worse" in text


# --- what must NOT fire -----------------------------------------------------

def test_a_url_with_no_git_operation_is_not_a_deployment() -> None:
    """A README link, a comment, an issue URL. Without this the rule fires on
    half the CI in existence."""
    assert scan({".github/workflows/ci.yml": """
      # see https://github.com/actions/checkout for the pinning policy
      jobs:
        test:
          steps:
            - uses: actions/checkout@v4
            - run: npm test
    """}) == []


def test_a_workflow_outside_the_workflows_directory_is_not_read() -> None:
    """`deploy.yml` at the repo root is somebody's config file, not a GitHub
    workflow, and it does not run anything."""
    body = FOREIGN_DEPLOY[".github/workflows/deploy.yml"]
    assert scan({"deploy.yml": body}) == []
    assert scan({"docs/workflows/deploy.yml": body}) == []


def test_an_archive_with_no_verifiable_name_is_silent() -> None:
    """An uploaded zip has no owner. "Is that a different repository" then has
    no answer, and guessing one would put a high finding on a repo that may
    well be cloning itself."""
    assert scan(FOREIGN_DEPLOY, root="repo") == []
    assert scan(FOREIGN_DEPLOY, root="") == []


def test_the_zipball_root_is_parsed_but_nothing_else_is() -> None:
    """GitHub's zipball root is `{owner}-{repo}-{sha}`. Only the trailing SHA
    comes off: an owner or a repo name may contain hyphens, so splitting into
    two fields would mangle exactly the names most likely to be real."""
    assert self_identity("donjonson-hash-devtools-aggregator-bbaa262/") \
        == "donjonson-hash-devtools-aggregator"
    assert self_identity("a-b-c-d-1234567") == "a-b-c-d"
    assert self_identity("repo/") == ""
    assert self_identity("") == ""
    # A directory that merely ends in something hex-ish but too short.
    assert self_identity("myrepo-abc") == ""


# --- the URL reader ---------------------------------------------------------

def test_both_url_forms_are_recognised() -> None:
    for source in (
        "git clone https://github.com/owner/repo.git /srv/app",
        "git clone https://github.com/owner/repo /srv/app",
        "git clone git@github.com:owner/repo.git /srv/app",
    ):
        assert deployed_repositories(source) == [("owner", "repo")], source


def test_a_repository_named_twice_is_listed_once() -> None:
    assert deployed_repositories(
        "git clone https://github.com/o/r.git x\n"
        "git pull https://github.com/o/r.git"
    ) == [("o", "r")]


# --- the seams, because a rule nothing calls is a rule that does nothing -----

def test_the_rule_reaches_a_real_static_scan() -> None:
    """The module can be perfect and still never run. A first mutation pass
    "caught" an unwired scanner only because the runner named a test file that
    does not exist, so pytest errored on every mutant and every one looked
    dead. This asserts the seam itself."""
    from app.scan.static import run_static_scan

    result = run_static_scan(make_zip(FOREIGN_DEPLOY))
    rules = [f["rule_id"] for f in result["findings"]]
    assert RULE_ID in rules, rules


def test_the_fix_pack_declines_it_by_name() -> None:
    """Not "advisory, nothing to rewrite" — there is plenty to rewrite, one
    URL. We decline because which repository is the source of truth is not
    stated in either of them, and guessing redirects somebody's production."""
    from app.fixpack.generate import build_fixpack_plan

    findings = [{"rule_id": RULE_ID, "severity": "high", "category": "Deploy",
                 "title": "Your CI builds this repository and deploys a different one",
                 "file": ".github/workflows/deploy.yml", "line": 0}]
    plan = build_fixpack_plan(make_zip(FOREIGN_DEPLOY).getvalue(), findings)
    reasons = [s.reason for s in plan.skipped if s.rule_id == RULE_ID]
    assert reasons, [s.rule_id for s in plan.skipped]
    assert "advisory" not in reasons[0].lower()
    assert "redirect production" in reasons[0]
    assert plan.files == {}
