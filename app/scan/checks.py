"""Deterministic presence checks over the archive file listing.

Cheap signals that need no code analysis: a committed .env, absence of
tests, Dockerfile or CI. Each check yields at most one finding.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass
from typing import BinaryIO

from app.scan.secrets import RULES, value_has_placeholder_marker


@dataclass(frozen=True)
class CheckFinding:
    rule_id: str
    title: str
    severity: str
    confidence: float
    category: str
    file: str = ""
    # Written for someone who shipped their first app and does not know the
    # jargon. The LLM findings already arrive with these filled in, and they
    # read well precisely because the model is told to describe a concrete
    # harm rather than name a category. These are the static equivalent, so
    # the free tier -- which is static-only, and is the only thing most
    # visitors ever see -- stops handing out bare titles like
    # "Environment file committed to repository" with nothing underneath.
    explanation: str = ""
    fix_hint: str = ""


def _strip_root(names: list[str]) -> list[str]:
    """Normalize single-root exports (Lovable/Bolt wrap in one folder)."""
    tops = {n.split("/", 1)[0] for n in names if n.strip("/")}
    if len(tops) == 1 and all("/" in n or n.endswith("/") for n in names):
        root = next(iter(tops)) + "/"
        return [n[len(root):] for n in names if n != root]
    return names


def find_committed_env_files(files: list[str]) -> list[str]:
    """The committed env files a repo should never track: `.env` itself
    and any `.env.<something>` except `.env.example`. Shared by run_checks
    (to fire env-file-committed) and the Fix Pack generator (to know which
    files to untrack), so both agree on exactly what counts."""
    return [
        n for n in files
        if n == ".env" or n.endswith("/.env")
        or (n.rsplit("/", 1)[-1].startswith(".env.")
            and not n.endswith(".env.example"))
    ]


# Keys whose VALUE is a credential if it is anything at all. Matched against
# the key half of a `KEY=value` line, so `NODE_PATH` and `PORT` do not qualify
# while `DB_PASSWORD` and `STRIPE_SECRET_KEY` do.
_SECRET_KEY_RE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|credential|auth|dsn|service[_-]?role)"
)

# A value that is one of these is configuration, not a credential, however
# secret-sounding its key: a path, a port, a boolean, a bare number, an empty
# assignment, or a localhost URL with no password in it.
_INNOCUOUS_VALUE_RE = re.compile(
    r"""(?ix)^(
        | \.{0,2}/[\w./-]*          # ./build, ../../packages, /srv/app
        | [\w.-]*/[\w./-]*          # build/packages (bare relative path)
        | \d+                       # 8080
        | true|false|yes|no|on|off
        | localhost(:\d+)?
        | https?://localhost(:\d+)?[\w/.-]*
    )$"""
)

# scheme://user:password@host -- a DSN carrying its own credentials. Kept
# separate from the key test because DATABASE_URL is a config-sounding name
# that can still hold a live password.
_URL_WITH_PASSWORD_RE = re.compile(r"://[^/\s:@]+:[^/\s:@]+@")

# Template stubs: what a committed .env holds when it is checked in ON PURPOSE
# as a starting point for the next developer. Matched whole, not as a
# substring, so a real key that merely contains "none" or "here" is unaffected.
#
# Kept here rather than added to _PLACEHOLDER_MARKERS in app/scan/secrets.py.
# That list damps test-fixture findings across every scanner, and widening it
# to catch "changeme" would quietly re-grade unrelated secret matches in test
# files. This one has a single caller and a single question to answer.
_ENV_PLACEHOLDER_RE = re.compile(
    r"""(?ix)^(
        change[-_ ]?me | replace[-_ ]?me | fill[-_ ]?me[-_ ]?in
      | your[-_ ]?[\w-]*          # your-api-key, your_token, yourkey
      | <[^>]*> | \{\{[^}]*\}\}   # <your key here>, {{API_KEY}}
      | \*{3,} | x{3,} | \.{3,}
      | todo | tbd | none | null | undefined
      | example ([-_][\w-]*)?
      | [\w-]*[-_]here            # secret_here, key-here
    )$"""
)

# A .env is a handful of lines. Reading more than this buys nothing and would
# let a 500 MB file named ".env.production" be pulled into memory whole.
_MAX_ENV_BYTES = 64 * 1024


def env_file_holds_credentials(body: str) -> bool:
    """Whether a committed .env actually exposes something.

    The check that uses this used to be unconditionally `critical`, on the
    name of the file alone. That was survivable while a single critical only
    dented the score; it stopped being survivable when one confident critical
    began capping the headline (GATE_ON_CRITICAL in app/scan/scoring.py),
    because a .env holding nothing but a build path now drops a repository
    below passing. React's own `fixtures/fiber-debugger/.env` -- one line,
    `NODE_PATH=../../build/packages` -- is the case that surfaced it.

    This cannot be delegated to app/scan/secrets.py. Those rules are written
    for source code and the general one requires quotes around the value, so
    as .env lines both `DB_PASSWORD=hunter2` and a DATABASE_URL holding a
    driver URL with `user:password@host` in it scan completely clean --
    verified against scan_secrets directly. The presence check is the ONLY
    thing standing between a visitor and a committed password file, which is
    exactly why it has to read the file rather than guess from its name.

    (That example is spelled out rather than written literally on purpose:
    a real DSN here trips the repository's own added-secrets CI scanner,
    which cannot tell a docstring from a leak.)
    """
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().removeprefix("export ").strip()
        value = value.strip().strip("'\"").strip()

        if _URL_WITH_PASSWORD_RE.search(value):
            return True
        if (not value or value_has_placeholder_marker(value)
                or _ENV_PLACEHOLDER_RE.match(value)):
            continue
        if _INNOCUOUS_VALUE_RE.match(value):
            continue
        if _SECRET_KEY_RE.search(key):
            return True
        # A value that matches a real secret signature counts whatever its
        # key is called: an AWS id or a live Stripe key is not configuration.
        if any(rule.pattern.search(value) for rule in RULES
               if rule.severity == "critical"):
            return True
    return False


def gitignore_covers_env(gitignore_body: str) -> bool:
    """Whether a .gitignore's text already ignores .env. Same predicate
    run_checks uses to decide gitignore-missing-secrets, exposed so the
    Fix Pack generator can avoid appending a pattern that's already there."""
    return any(
        line.strip() in (".env", ".env*", "*.env", ".env.*")
        for line in gitignore_body.splitlines()
    )


def run_checks(fileobj: BinaryIO) -> list[CheckFinding]:
    with zipfile.ZipFile(fileobj) as zf:
        raw_names = zf.namelist()
        names = _strip_root(raw_names)
        # Read the root .gitignore's bytes while the zip is open. After
        # root-stripping it is exactly ".gitignore"; the original entry is
        # either top-level or prefixed by the single wrapping folder.
        gitignore_body = ""
        gitignore_raw = next(
            (n for n in raw_names
             if n == ".gitignore" or n.endswith("/.gitignore")),
            None,
        )
        if gitignore_raw is not None:
            gitignore_body = zf.read(gitignore_raw).decode("utf-8", errors="ignore")

        # The committed env files' bodies, read while the zip is open, so the
        # finding below can be graded on what is inside rather than on the
        # filename. Capped: a .env is a handful of lines, and anything larger
        # is not the file this check is about.
        env_bodies = [
            zf.read(n)[:_MAX_ENV_BYTES].decode("utf-8", errors="ignore")
            for n in find_committed_env_files(raw_names)
        ]

    findings: list[CheckFinding] = []
    files = [n for n in names if not n.endswith("/")]

    committed_env = find_committed_env_files(files)
    if committed_env:
        exposed = any(env_file_holds_credentials(b) for b in env_bodies)
        if exposed:
            finding = CheckFinding(
                "env-file-committed", "Environment file committed to repository",
                severity="critical", confidence=0.9, category="Security",
                file=committed_env[0],
                explanation=(
                    "Your .env file is stored in the repository, so everything "
                    "in it — database passwords, API keys, payment credentials "
                    "— is visible to anyone who can see this code. If the "
                    "repository is public, that is the whole internet. "
                    "Deleting the file later does not help on its own: Git "
                    "keeps every past version, so the values stay readable in "
                    "the history."
                ),
                fix_hint=(
                    "Treat every value in that file as already leaked and "
                    "issue new ones (rotate the keys in each service's "
                    "dashboard). Then stop tracking the file with `git rm "
                    "--cached .env`, add it to .gitignore, and set the same "
                    "values as environment variables in your hosting provider "
                    "instead."
                ),
            )
        else:
            # Same file, no credential in it. Still worth reporting -- this is
            # the file secrets get added to, and once it is tracked the next
            # one lands in history without anyone noticing -- but calling it
            # critical would be a claim about exposure that the contents
            # contradict, and under GATE_ON_CRITICAL that claim now caps the
            # headline. Medium keeps it visible without asserting a leak.
            finding = CheckFinding(
                "env-file-committed", "Environment file tracked in the repository",
                severity="medium", confidence=0.6, category="Security",
                file=committed_env[0],
                explanation=(
                    "Your .env file is stored in the repository. Nothing in it "
                    "looks like a password or key today, so nothing is exposed "
                    "yet — but .env is the file those values go into, and once "
                    "it is tracked the next secret added to it is committed "
                    "along with everything else. Git keeps every past version, "
                    "so that one would stay readable in the history even after "
                    "a later delete."
                ),
                fix_hint=(
                    "Stop tracking it with `git rm --cached .env` and add "
                    ".env to .gitignore, so the day a real key goes in there "
                    "it does not follow. Values the build genuinely needs can "
                    "live in a committed .env.example with the secrets left "
                    "blank."
                ),
            )
        findings.append(finding)

    # A .gitignore that doesn't cover .env is how the committed-env leak
    # above happens in the first place: without it, the next `git add`
    # sweeps secret-bearing files back in. Fire when there's no
    # .gitignore at all, or one that doesn't ignore .env.
    gitignore = next((n for n in files if n == ".gitignore"), None)
    covers_env = gitignore_covers_env(gitignore_body)
    if not covers_env:
        findings.append(CheckFinding(
            "gitignore-missing-secrets",
            "No .gitignore coverage for secret-bearing files"
            if gitignore is None
            else ".gitignore does not cover .env / secret files",
            severity="high", confidence=0.8, category="Security",
            file=gitignore or "",
            explanation=(
                "Nothing is telling Git to leave your .env file alone, so the "
                "next time you or your AI assistant commits changes, the file "
                "with your passwords and API keys gets swept in along with "
                "everything else. This is how secrets end up published — not "
                "by a deliberate decision, but by a routine commit."
            ),
            fix_hint=(
                "Add a line containing exactly `.env` to your .gitignore file "
                "(create the file in the project root if it does not exist). "
                "This does not remove anything already committed — that needs "
                "the separate fix above — but it stops it happening again."
            ),
        ))

    has_tests = any(
        "test" in n.rsplit("/", 1)[-1].lower() and n.endswith((".py", ".ts", ".tsx", ".js"))
        for n in files
    )
    if not has_tests:
        findings.append(CheckFinding(
            "no-tests", "No test files found",
            severity="medium", confidence=0.8, category="Testing",
            explanation=(
                "There is nothing that checks your app still works after a "
                "change. Right now the only way to find out you broke signup "
                "or checkout is a user hitting it in production. That risk "
                "grows every time you ask an AI assistant to modify code you "
                "are not reading line by line."
            ),
            fix_hint=(
                "Start with one test for the thing that would hurt most if it "
                "silently broke — usually payment or login. One test that runs "
                "on every change is worth far more than a suite you plan to "
                "write later."
            ),
        ))

    if not any(n.rsplit("/", 1)[-1] == "Dockerfile" for n in files):
        findings.append(CheckFinding(
            "no-dockerfile", "No Dockerfile — app is not containerized",
            severity="low", confidence=0.9, category="Deploy",
            explanation=(
                "Your app has no recipe describing how to run it, so it runs "
                "with whatever versions happen to be installed wherever it is "
                "deployed. That is why an app can work on your machine and "
                "fail on the server. It also makes moving to another host a "
                "manual reconstruction rather than a copy."
            ),
            fix_hint=(
                "Not urgent if your host builds the app for you (Vercel, "
                "Netlify and similar do). Worth adding when you move to your "
                "own server, or when 'works locally, breaks in production' "
                "starts costing you time."
            ),
        ))

    if not any(n.startswith(".github/workflows/") for n in files):
        findings.append(CheckFinding(
            "no-ci", "No CI workflow found",
            severity="low", confidence=0.9, category="Deploy",
            explanation=(
                "Nothing runs automatically when you change the code, so a "
                "change that does not even compile can reach production and "
                "the first sign is the site being down. A human remembering "
                "to check every time is not a safety net."
            ),
            fix_hint=(
                "Add a GitHub Actions workflow that at minimum builds the app "
                "on every push. It turns a broken build into a red mark on the "
                "change instead of an outage. Pairs with the tests above: "
                "together they catch most self-inflicted breakage."
            ),
        ))

    return findings
