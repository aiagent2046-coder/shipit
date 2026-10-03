"""Bounded CI source mismatch observations, not deployment verification.

A foreign repository URL is relevant only inside an SSH-action script or a
shell block with a Git placement command naming a conventional application
path. A runner-only clone can fetch data, tools or test fixtures. Neither a
workflow name nor an unrelated deployment step establishes what is deployed.

The archive root supplies the repository identity; archives without that
identity stay silent. Shell variable binding, build provenance, live execution
and the foreign repository contents remain unverified. No automatic fix can
choose the intended deployment source for the owner.
"""

from __future__ import annotations

import re
import shlex
import zipfile

import yaml
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

# Lines that name a repository WITHOUT placing it on the server, and which the
# whole-file URL sweep below would otherwise read as the deploy target:
#
#     # adapted from https://github.com/actions/starter-workflows
#     - run: pip install git+https://github.com/psf/black.git
#
# Both appear beside a legitimate `git clone` of the project's own repository,
# and reporting either accuses a correct workflow of shipping someone else's
# code -- the exact claim this rule exists to make truthfully.
_NOT_A_DEPLOY_TARGET = re.compile(
    r"""^\s*\#                                     # a comment line
      | \b(?:pip|pip3|pipx|npm|pnpm|yarn|bun|cargo|go)\s+(?:install|add|i|get)\b
      | \bgit\+https://                            # pip's VCS syntax
      | \bgithub:[A-Za-z0-9._-]+/                  # npm's shorthand
      | \buses:\s                                  # an action reference
    """,
    re.VERBOSE | re.I,
)

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


def _join_shell_continuations(text: str) -> str:
    """Remove active backslash-newline pairs, retaining comments and literals."""
    output: list[str] = []
    quote = ""
    comment = False
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\n":
            comment = False
            # Each physical YAML line is independent unless the shell
            # explicitly continues it. A quote in a plain YAML name must
            # not change how a later run block is interpreted.
            quote = ""
        elif not comment:
            if char == "\\" and quote != "'" and index + 1 < len(text):
                following = text[index + 1]
                if following == "\n":
                    index += 2
                    continue
                if following == "\r" and text[index + 2:index + 3] == "\n":
                    index += 3
                    continue
                output.extend((char, following))
                index += 2
                continue
            if char == quote:
                quote = ""
            elif not quote and char in "\"'":
                quote = char
            elif not quote and char == "#" and (index == 0 or text[index - 1].isspace()):
                comment = True
        output.append(char)
        index += 1
    return "".join(output)


def _command_segments(line: str) -> list[str]:
    """Separate shell commands without splitting quoted URLs or reading comments.

    A dependency install and a git clone can share a YAML run line. The
    dependency exception belongs to its command, not to that entire line.
    This is lexical segmentation only; shell variables are not resolved.
    """
    command, fields = re.subn(r"^\s*(?:-\s*)?(?:run|script):\s*", "", line)
    if fields and len(command) >= 2 and command[0] in "\"'" and command[-1] == command[0]:
        command = command[1:-1]
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|")
    lexer.whitespace_split = True
    segments: list[str] = []
    words: list[str] = []
    try:
        for word in lexer:
            if word and all(char in ";&|" for char in word):
                if words:
                    segments.append(" ".join(words))
                    words = []
            else:
                words.append(word)
    except ValueError:
        # A partial shell expression does not establish a deploy target.
        return []
    if words:
        segments.append(" ".join(words))
    return segments


def deployed_repositories(text: str) -> list[tuple[str, str]]:
    """(owner, repo) for every GitHub repository this workflow PLACES ON DISK.

    Scoped line by line to the git operations above. `REPO=https://…` on one
    line and `git clone $REPO` on the next is the shape that was found in the
    wild, so a URL assigned anywhere in the file counts once the file also
    performs one of those operations — the alternative is resolving shell
    variables, which is a different program.

    Commands matching _NOT_A_DEPLOY_TARGET are excluded from that sweep. Without
    it a comment crediting the workflow's source, or a `pip install git+…`,
    was read as the deploy target and the rule accused a workflow that deploys
    its own repository correctly.
    """
    commands = [command for line in _join_shell_continuations(text).splitlines()
                for command in _command_segments(line)
                if not _NOT_A_DEPLOY_TARGET.search(command)]
    if not any(_PLACING_CODE.search(command) for command in commands):
        return []
    seen: list[tuple[str, str]] = []
    for command in commands:
        for match in _REPO_URL.finditer(command):
            pair = (match.group(1).lower(), match.group(2).lower())
            if pair not in seen:
                seen.append(pair)
    return seen


def deployment_scripts(text: str) -> list[str]:
    """Select bounded deployment-like steps, never sweep an entire workflow.

    SSH script actions and shell commands placing code under conventional
    application directories are syntax signals only, not proof of execution.
    Names such as 'deploy' alone do not establish a deployment.
    """
    if len(text) > 400_000:
        return []
    try:
        workflow = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError):
        return []
    if not isinstance(workflow, dict) or not isinstance(workflow.get("jobs"), dict):
        return []
    scripts = []
    for job in list(workflow["jobs"].values())[:100]:
        if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
            continue
        for step in job["steps"][:500]:
            if not isinstance(step, dict):
                continue
            options = step.get("with")
            script = options.get("script") if isinstance(options, dict) else None
            action = step.get("uses", "")
            if (isinstance(script, str) and isinstance(action, str)
                    and action.lower().startswith("appleboy/ssh-action@")):
                scripts.append(script)
                continue
            # A bare clone on a CI runner often fetches data or tools. Only a
            # placement command that names an application path is a candidate.
            for candidate in (script, step.get("run")):
                if not isinstance(candidate, str):
                    continue
                commands = [c for line in _join_shell_continuations(candidate).splitlines()
                            for c in _command_segments(line)]
                if any(_PLACING_CODE.search(c) and re.search(r"(?:^|\s)/(?:srv|opt|var/www)/", c)
                       for c in commands):
                    scripts.append(candidate)
    return scripts


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
                for script in deployment_scripts(text)
                for owner, repo in deployed_repositories(script)
                if f"{owner}-{repo}" != identity
            ]
            if others:
                findings.append(_finding(rel, others))
    return findings


def _finding(path: str, others: list[str]) -> CheckFinding:
    named = ", ".join(f"`{o}`" for o in others)
    return CheckFinding(
        rule_id=RULE_ID,
        title="Deployment-like script references a different repository",
        severity="high",
        # A source mismatch is observed; deployment and runtime behavior are unverified.
        confidence=0.8,
        category="Deploy",
        file=path,
        explanation=(
            f"`{path}` contains a deployment-like script referencing {named}, "
            "which differs from the audited archive's repository identity. "
            "The selected script contains a Git placement operation in an SSH action "
            "or a conventional application directory. This does not verify which "
            "repository was built, whether the step runs, or what is live in production. "
            "This may be deliberate: a mirror or a multi-repository deployment. "
            "Nothing here says the other repository is worse. Review the source and "
            "deployment relationship before changing it."
        ),
        fix_hint=(
            "Decide which repository is the source of truth for this "
            "deployment, and verify the referenced step actually deploys it. "
            "If the source differs intentionally, audit that source and its build "
            "checks too. Otherwise correct the target after confirming the intended repository."
        ),
    )
