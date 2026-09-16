"""Deterministic presence checks over the archive file listing.

Cheap signals that need no code analysis: a committed .env, absence of
tests, Dockerfile or CI. Environment findings retain individual file paths.
"""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlsplit
import zipfile
from dataclasses import dataclass
from typing import BinaryIO

from app.scan.gitignore import ArchiveGitIgnore
from app.scan.secrets import (
    RULES,
    damp_for_non_production_path,
    is_env_template_name,
    value_has_placeholder_marker,
)


@dataclass(frozen=True)
class CheckFinding:
    rule_id: str
    title: str
    severity: str
    confidence: float
    category: str
    file: str = ""
    # Most checks here are about a file's EXISTENCE, so they have no line and
    # leave this at 0. app/scan/service_role.py has one -- it points at the
    # statement that reads the key -- and a finding that names a 400-line
    # route file without saying where is a finding the owner has to re-find.
    line: int = 0
    # Written for someone who shipped their first app and does not know the
    # jargon. The LLM findings already arrive with these filled in, and they
    # read well precisely because the model is told to describe a concrete
    # harm rather than name a category. These are the static equivalent, so
    # the free tier -- which is static-only, and is the only thing most
    # visitors ever see -- stops handing out bare titles like
    # "Environment file committed to repository" with nothing underneath.
    explanation: str = ""
    fix_hint: str = ""
    context: str | None = None


def archive_root(names: list[str]) -> str:
    """The single wrapping directory an export uses, or "" when there is none.

    A GitHub archive and a Lovable/Bolt export wrap everything in one folder;
    a zip a customer made by hand often does not. Callers that strip that
    segment UNCONDITIONALLY are wrong on the second kind, and wrong in a way
    that hides: app/scan/service_role.py asks whether a path sits inside an
    `app/` tree, and on a rootless archive the unconditional strip removed the
    very segment it was about to look for, so every route went unreported and
    the scan looked clean.
    """
    tops = {n.split("/", 1)[0] for n in names if n.strip("/")}
    if len(tops) == 1 and all("/" in n or n.endswith("/") for n in names):
        return next(iter(tops)) + "/"
    return ""


def _strip_root(names: list[str]) -> list[str]:
    """Normalize single-root exports (Lovable/Bolt wrap in one folder)."""
    root = archive_root(names)
    if not root:
        return names
    return [n[len(root):] for n in names if n != root]


# Directories a package manager fills, which belong in .gitignore rather than
# in history. Their CONTENTS are skipped everywhere else on purpose -- see
# _SKIP_DIRS in app/scan/secrets.py and app/scan/llm_scan.py -- because
# auditing somebody else's dependencies wastes the whole prompt budget. That
# is correct, and it left nobody able to say the obvious: on one paying
# customer's repository, venv/ was 2,987 of 3,098 tracked files and the audit
# said nothing, because every component that could have noticed was told to
# look away. This check reads no contents; it counts names.
_DEPENDENCY_DIRS = frozenset({
    "venv", ".venv", "node_modules", "vendor", "__pycache__", "site-packages",
})

# One stray committed file is a mistake; a populated tree is the problem this
# describes. Below this it is not worth a finding of its own.
_DEPENDENCY_DIR_MIN_FILES = 20

# What no-dockerfile lists as deployment configuration it DID find. The rule is
# an inventory, not a demand for containers -- severity low, and the whole point
# of the list is that the reader sees their own setup named back to them.
#
# It began as vercel/netlify/fly/Procfile/*.service, which meant a project
# deployed by docker-compose, Kubernetes, Terraform or Render was told "no
# deployment configuration found" while its config sat in the archive. Naming
# nothing is worse here than naming something imprecisely: the reader concludes
# the scanner did not look.
_DEPLOY_CONFIG_NAMES = frozenset({
    # Ordering note: tests/test_plain_language.py collects rule ids from this
    # file by regex, and `"name", "` reads as a declaration to it. Keep
    # hyphenated entries away from that shape -- `captain-definition` was in
    # this set and surfaced as a rule id with no plain-language entry.
    "vercel.json", "netlify.toml", "fly.toml", "Procfile",
    "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
    "Containerfile", "render.yaml", "render.yml", "railway.json", "railway.toml",
    "app.yaml", "app.json", "serverless.yml", "serverless.yaml",
    "Chart.yaml", "skaffold.yaml", "dokku-scale",
})

# Suffixes rather than exact names: a systemd unit, a Terraform file, or a
# Dockerfile variant (Dockerfile.prod, Dockerfile.dev) each vary in the part
# before the marker.
_DEPLOY_CONFIG_SUFFIXES = (".service", ".tf", ".tfvars")


def _committed_dependency_dirs(files: list[str]) -> list[tuple[str, int]]:
    """(directory, tracked file count) for each dependency tree in the repo.

    Reports the TOP-most occurrence only. A virtualenv contains
    site-packages/ and dozens of __pycache__/ directories, and listing each as
    its own finding would bury the one fact the owner needs under its own
    consequences.
    """
    members: dict[str, list[str]] = {}
    for name in files:
        parts = name.split("/")
        # Walk from the archive root, matching complete directory segments.
        # Substrings such as myvenv or custom_vendor are not dependency dirs.
        for index, part in enumerate(parts[:-1]):
            if part not in _DEPENDENCY_DIRS:
                continue
            directory = "/".join(parts[:index + 1])
            members.setdefault(directory, []).append(name)
            break
    return sorted(
        (directory, len(paths)) for directory, paths in members.items()
        if len(paths) >= _DEPENDENCY_DIR_MIN_FILES
        # A stored detector corpus is not an installed dependency tree. Both
        # the test path and every member's inert suffix must establish that;
        # a real venv under tests, or a mixed tree, remains reportable.
        and not (
            any(part in {"tests", "test", "fixtures", "__fixtures__"}
                for part in directory.split("/")[:-1])
            and all(path.endswith(".fixture") for path in paths)
        )
    )


def find_committed_env_files(files: list[str]) -> list[str]:
    """Inventory environment files for content-aware review: `.env` itself
    and any `.env.<something>` that is not a template. Shared by run_checks
    (to fire env-file-committed) and the Fix Pack generator (to know which
    files to untrack), so both agree on exactly what counts.

    The template exclusion used to be `not n.endswith(".env.example")`, an
    exact match, and `.env.local.example` slipped past it. Measured on
    mckaywrigley/chatbot-ui (audit f444873f): that file was reported as an
    environment file that should not be tracked, in a finding whose own advice
    reads "values the build genuinely needs can live in a committed
    .env.example with the secrets left blank" -- the reader told to do the
    thing they had already done.

    THE REPORT IS THE SMALLER HALF. This function also feeds
    app/fixpack/generate.py, where the result goes straight into
    `plan.deletions`. A paid Fix Pack would have opened a pull request
    DELETING the customer's `.env.local.example`, `.env.sample` or
    `.env.template`: removing the file that tells every new contributor what
    to configure, and selling that as a fix.
    """
    return [
        n for n in files
        if n == ".env" or n.endswith("/.env")
        or (n.rsplit("/", 1)[-1].startswith(".env.")
            and not is_env_template_name(n)
            # Stored test inputs are not environment files loaded by default.
            # This affects inventory/Fix Pack only; secrets still scan them.
            and not n.endswith(".fixture"))
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


def env_file_is_public_configuration(body: str) -> bool:
    """Recognize simple frontend-public build settings, never by prefix alone."""
    if env_file_holds_credentials(body):
        return False
    assignments = 0
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.removeprefix("export ").partition("=")
        key = key.strip()
        if (not sep or not re.fullmatch(
                r"(?:VITE_|NEXT_PUBLIC_|REACT_APP_|NUXT_PUBLIC_|PUBLIC_)[A-Z0-9_]+", key)
                or _SECRET_KEY_RE.search(key)):
            return False
        value = value.strip()
        if value.startswith(("'", '\"')):
            if len(value) < 2 or value[-1] != value[0]:
                return False
            value = value[1:-1]
        elif "'" in value or '\"' in value:
            return False
        if value.startswith(("http://", "https://", "ws://", "wss://")):
            try:
                url = urlsplit(value)
                if (not url.hostname or url.username is not None or url.password is not None
                        or url.query or url.fragment or any(c.isspace() for c in value)):
                    return False
            except ValueError:
                return False
        elif not re.fullmatch(r"(?:\d+|true|false|development|production|test)", value):
            return False
        assignments += 1
    return assignments > 0


def gitignore_covers_env(gitignore_body: str) -> bool:
    """Whether root rules ignore an untracked root .env, including overrides."""
    return ArchiveGitIgnore({".gitignore": gitignore_body}).ignores(".env")


_CI_CONFIG_PATHS = frozenset({
    ".gitlab-ci.yml", ".gitlab-ci.yaml", ".circleci/config.yml", ".circleci/config.yaml",
    "Jenkinsfile", "azure-pipelines.yml", "azure-pipelines.yaml",
    "bitbucket-pipelines.yml", ".travis.yml", ".drone.yml", ".drone.yaml",
    ".buildkite/pipeline.yml", ".buildkite/pipeline.yaml",
})


def run_checks(fileobj: BinaryIO) -> list[CheckFinding]:
    with zipfile.ZipFile(fileobj) as zf:
        raw_names = zf.namelist()
        root_prefix = archive_root(raw_names) or ""
        members = {raw[len(root_prefix):]: raw for raw in raw_names
                   if raw != root_prefix and not raw.endswith("/")}
        files = list(members)
        ignore_bodies = {}
        env_bodies = {}
        for path in files:
            if path.rsplit("/", 1)[-1] == ".gitignore":
                with zf.open(members[path]) as source:
                    ignore_bodies[path] = source.read(256 * 1024 + 1).decode("utf-8", errors="replace")
        for path in find_committed_env_files(files):
            with zf.open(members[path]) as source:
                env_bodies[path] = source.read(_MAX_ENV_BYTES + 1).decode("utf-8", errors="replace")

    findings: list[CheckFinding] = []
    for path, body in env_bodies.items():
        exposed = env_file_holds_credentials(body)
        # Reuse the established path vocabulary, but keep presence-check
        # severity unchanged: a test directory cannot make a real key safe.
        _, _, path_context = damp_for_non_production_path(path, "medium", 0.6)
        public = len(body.encode("utf-8")) <= _MAX_ENV_BYTES and env_file_is_public_configuration(body)
        command = "git rm --cached -- " + shlex.quote(path)
        if exposed:
            finding = CheckFinding(
                "env-file-committed", "Credential-like value in an environment file",
                severity="critical", confidence=0.9, category="Security", file=path,
                context=path_context,
                explanation=(f"{path} is included in the archive and contains a credential-like value. "
                             "Static matching does not establish whether the value is live. "
                             "If it is a real credential in published source, anyone with source access "
                             "can read it; deleting the current file does not erase Git history."),
                fix_hint=("Verify the value and rotate any exposed real credential. "
                          f"For a private configuration file, stop tracking it with `{command}`, "
                          f"add `/{path}` to the root .gitignore, and supply its values securely at runtime."),
            )
        elif public:
            finding = CheckFinding(
                "env-file-committed", "Public frontend configuration included in the archive",
                severity="low", confidence=0.6, category="Security", file=path,
                context="public_configuration",
                explanation=(f"{path} contains only recognized frontend-public settings with simple "
                             "URLs or build values. Their names use frontend-public conventions. "
                             "File presence alone is not evidence of credential exposure."),
                fix_hint=("Keep intentional public build settings in version control when the project "
                          "needs them. Put private credentials in separate ignored configuration; "
                          "do not rotate values or delete this file solely because of its name."),
            )
        else:
            finding = CheckFinding(
                "env-file-committed", "Environment configuration included in the archive",
                severity="medium", confidence=0.6, category="Security", file=path,
                context=path_context,
                explanation=(f"{path} is included in the archive. No credential-like value was "
                             "recognized in the inspected content (at most 64 KiB); this does not "
                             "establish that all values are public or that Git history is free of secrets."),
                fix_hint=("Check whether the file is intentional public configuration or private settings. "
                          f"Only for private settings, stop tracking it with `{command}` and add "
                          f"`/{path}` to the root .gitignore. Rotate only exposed real credentials."),
            )
        findings.append(finding)

    ignores = ArchiveGitIgnore(ignore_bodies)
    # Evaluate exact paths in relevant package/configuration directories. Nested
    # rules can protect their own packages, but cannot protect a root .env.
    env_candidates = {".env"}
    for path in files:
        if path.rsplit("/", 1)[-1] in {
            ".gitignore", "package.json", "pyproject.toml", "requirements.txt",
        } or path in env_bodies:
            directory = path.rpartition("/")[0]
            env_candidates.add(f"{directory}/.env" if directory else ".env")
    env_candidates.update(path for path, body in env_bodies.items()
                          if not env_file_is_public_configuration(body))
    uncovered = sorted(path for path in env_candidates if not ignores.ignores(path))
    if not ignores.complete:
        uncovered = sorted(env_candidates)
    if uncovered:
        listed = ", ".join(uncovered[:8]) + (" (and more)" if len(uncovered) > 8 else "")
        findings.append(CheckFinding(
            "gitignore-missing-secrets", "Environment ignore coverage needs review",
            severity="medium" if ignores.complete else "low",
            confidence=0.8 if ignores.complete else 0.5, category="Security",
            file=".gitignore" if ".gitignore" in files else "",
            explanation=(f"Archive-local ignore coverage was not established for candidate paths: {listed}. " +
                         ("Rules were evaluated for each path, including nested files and negations. "
                          if ignores.complete else
                          "Ignore analysis reached a budget or unsupported pattern; protection is unresolved. ") +
                         "Global Git excludes and runtime configuration were not checked. "
                         "This does not establish that credentials were committed."),
            fix_hint=("For paths used for private configuration, add appropriate ignore rules in their "
                      "directory or the repository root. Keep intentional public build configuration "
                      "and templates. Ignore rules do not remove files already tracked by Git."),
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

    for directory, count in _committed_dependency_dirs(files):
        findings.append(CheckFinding(
            "dependency-dir-committed",
            f"{directory} is committed to the repository ({count} files)",
            severity="medium", confidence=0.95, category="Deploy",
            file=directory,
            explanation=(
                f"The archive contains {count} files under {directory}, a "
                "directory name commonly used for installed dependencies or "
                "generated caches. File names alone do not establish how "
                "these files were created, whether they are intentionally "
                "vendored, or which versions run in production."
            ),
            fix_hint=(
                "Check whether this directory contains reproducible installed "
                "dependencies or generated caches. If it does, add it to "
                f".gitignore and stop tracking it with `git rm -r --cached {directory}`, "
                "then document how to recreate it. Keep intentional vendored "
                "source or test data when the project requires it."
            ),
        ))

    if not any(n.rsplit("/", 1)[-1] == "Dockerfile" for n in files):
        alternatives = sorted(n for n in files
                              if n.endswith(_DEPLOY_CONFIG_SUFFIXES)
                              or n.rsplit("/", 1)[-1] in _DEPLOY_CONFIG_NAMES
                              # Dockerfile.prod / Dockerfile.dev: containers
                              # exist, just not under the exact name above.
                              or n.rsplit("/", 1)[-1].startswith("Dockerfile."))
        findings.append(CheckFinding(
            "no-dockerfile", "No Dockerfile found in the archive",
            severity="low", confidence=0.9, category="Deploy",
            context="deployment_inventory" if alternatives else None,
            explanation=(
                "Deployment configuration files found: " + ", ".join(alternatives[:8])
                + (f" (+{len(alternatives) - 8} more)" if len(alternatives) > 8 else "")
                + ". This is file inventory only; configuration validity and live deployment are not checked."
                if alternatives else
                "A Dockerfile is one deployment option. Its absence does not "
                "establish that the app cannot run on a server; systemd and "
                "managed platforms are other options."
            ),
            fix_hint="Review existing deployment instructions; add a Dockerfile only if containers are needed.",
        ))

    has_ci = any(
        (n.startswith(".github/workflows/") and n.count("/") == 2
         and n.endswith((".yml", ".yaml")))
        or n in _CI_CONFIG_PATHS for n in files
    )
    if not has_ci:
        findings.append(CheckFinding(
            "no-ci", "No recognized CI configuration found in the archive",
            severity="low", confidence=0.9, category="Deploy",
            explanation=("No recognized GitHub Actions, GitLab CI, CircleCI, Jenkins, Azure Pipelines, "
                         "Bitbucket Pipelines, Travis, Drone or Buildkite configuration was found. "
                         "External automation and CI settings outside the archive were not checked."),
            fix_hint=("Check whether external CI already builds and tests this project. If it does not, "
                      "add a workflow appropriate to the project's build and test commands. "
                      "Configuration presence alone does not verify successful execution."),
        ))

    return findings
