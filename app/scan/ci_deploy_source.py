"""CI that builds one repository and deploys another.

FOUND ON A REAL AUDIT, 2026-08-20. `donjonson-hash/devtools-aggregator` scored
9.9 — a full audit, LLM included, with two low-severity findings and every
category reading "nothing serious found". The score was honest about the 25
files it read: four source files, no API routes, no auth, no database, no
committed secrets.

It was not honest about what runs on the server, because the repository's own
deploy workflow ships something else:

    - uses: actions/checkout@v4          # ← builds THIS repo
      ...
    - name: Deploy via SSH
      script: |
        REPO=https://github.com/aiagent2046-coder/devtools-aggregator.git
        git clone $REPO $APP_DIR
        git fetch origin main && git reset --hard origin/main

CI type-checks and builds the audited repository, then logs into the VPS and
resets the deployment to a DIFFERENT repository's main. That other repository
scored 3.5 on its own audit, with five criticals on anonymous writes. The
owner reading the 9.9 has every reason to believe they are fine.

WHAT THIS CLAIMS, and the wording is bounded by it: the workflow's own
checkout and its deploy step name different repositories. It does NOT claim
the other repository is worse, unmaintained, or hostile — a monorepo split or
a deliberate mirror deploy has this exact shape and is somebody's design. What
is always true is that the checks which gate the merge ran on code that never
reaches the server, and that an audit of this repository describes something
other than production.

WHY IT NEEDS THE ARCHIVE'S OWN NAME. "Is this URL a different repository"
cannot be answered from the workflow alone: cloning your own repo by URL is
legal and looks identical. GitHub's zipball wraps everything in
`{owner}-{repo}-{sha}`, which is where the answer comes from — so this rule is
silent on an uploaded zip that has no such root, rather than guessing. Silence
on "cannot tell" is the same contract app/fixpack/generate.py's stamp keeps.

NOT AUTO-FIXABLE. The fix is either "point the deploy at this repository" or
"audit the other one" — a decision about how the owner's projects relate, not
a rewrite. app/fixpack/generate.py declines it by name.
"""

from __future__ import annotations

import re
import zipfile
from typing import BinaryIO

from app.scan.checks import CheckFinding, archive_root

RULE_ID = "ci-deploys-a-different-repository"

# GitHub repository references in either form a script can carry.
_REPO_URL = re.compile(
    r"""(?:https://github\.com/|git@github\.com:)
        ([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(?:\.git)?(?=[\s"'`)/]|$)""",
    re.VERBOSE,
)

# The git operations that decide WHAT CODE IS THERE. A workflow that merely
# curls a file from another repository, or references one in a comment, is not
# deploying it — and reporting that would make the rule fire on half of CI.
_PLACING_CODE = re.compile(
    r"git\s+(?:clone|pull)\b|git\s+reset\s+--hard\b|git\s+checkout\s+\S", re.I)

_WORKFLOW_DIR = ".github/workflows/"
_WORKFLOW_EXTS = (".yml", ".yaml")

# GitHub's zipball root is `{owner}-{repo}-{sha}`. Only the trailing SHA is
# stripped: an owner or repo name may itself contain hyphens, so the remainder
# is compared whole rather than split into two fields.
_ROOT_SHA_SUFFIX = re.compile(r"-[0-9a-f]{7,40}/?$")


def self_identity(root: str) -> str:
    """`owner-repo` for a GitHub zipball root, or "" when it is not one.

    Returns "" for an uploaded zip, a hand-made archive, or anything whose
    root does not end in a commit-shaped suffix. Every caller treats "" as
    "cannot tell" and stays silent.
    """
    trimmed = root.rstrip("/")
    if not trimmed or not _ROOT_SHA_SUFFIX.search(trimmed):
        return ""
    return _ROOT_SHA_SUFFIX.sub("", trimmed).lower()


def deployed_repositories(text: str) -> list[tuple[str, str]]:
    """(owner, repo) for every GitHub repository this workflow PLACES ON DISK.

    Scoped line by line to the git operations above. `REPO=https://…` on one
    line and `git clone $REPO` on the next is the shape that was found in the
    wild, so a URL assigned anywhere in the file counts once the file also
    performs one of those operations — the alternative is resolving shell
    variables, which is a different program.
    """
    if not _PLACING_CODE.search(text):
        return []
    seen: list[tuple[str, str]] = []
    for match in _REPO_URL.finditer(text):
        pair = (match.group(1).lower(), match.group(2).lower())
        if pair not in seen:
            seen.append(pair)
    return seen


def scan_ci_deploy_source(fileobj: BinaryIO) -> list[CheckFinding]:
    """One finding per workflow that deploys a repository other than this one."""
    fileobj.seek(0)
    with zipfile.ZipFile(fileobj) as zf:
        names = zf.namelist()
        root = archive_root(names)
        identity = self_identity(root)
        if not identity:
            # No verifiable name for the repository we are reading, so "is
            # that URL a different repo" has no answer. Say nothing.
            return []

        findings: list[CheckFinding] = []
        for name in sorted(names):
            rel = name[len(root):] if root else name
            if not rel.startswith(_WORKFLOW_DIR) or not rel.endswith(_WORKFLOW_EXTS):
                continue
            try:
                text = zf.read(name).decode("utf-8", errors="replace")
            except Exception:                                  # noqa: BLE001
                continue
            others = [
                f"{owner}/{repo}"
                for owner, repo in deployed_repositories(text)
                if f"{owner}-{repo}" != identity
            ]
            if others:
                findings.append(_finding(rel, others))
    return findings


def _finding(path: str, others: list[str]) -> CheckFinding:
    named = ", ".join(f"`{o}`" for o in others)
    return CheckFinding(
        rule_id=RULE_ID,
        title="Your CI builds this repository and deploys a different one",
        severity="high",
        # The fact is certain; whether it is a mistake is not. A monorepo split
        # or a deliberate mirror deploy has exactly this shape.
        confidence=0.8,
        category="Deploy",
        file=path,
        explanation=(
            f"`{path}` checks out this repository, runs your build and your "
            f"checks over it — and then its deploy step puts {named} on the "
            f"server instead.\n\n"
            f"So the tests, the type check and the build that gate a merge "
            f"here all ran against code that never reaches production. And an "
            f"audit of this repository — including this one — describes "
            f"something other than what your users are running.\n\n"
            f"This may be deliberate: a monorepo split, or a mirror you deploy "
            f"on purpose. Nothing here says the other repository is worse. It "
            f"says the two are not the same, and that only one of them was "
            f"checked."
        ),
        fix_hint=(
            "Decide which repository is the source of truth for this "
            "deployment. If it is this one, point the deploy step at it and "
            "your checks start protecting production. If it is the other one, "
            "run the audit against that repository instead — the report you "
            "are reading now is about code that is not deployed."
        ),
    )
