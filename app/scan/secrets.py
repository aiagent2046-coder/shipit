"""Secrets scanning over a validated ZIP, without extracting to disk.

Design rules:
- Findings NEVER contain the secret value — only file, line, rule and
  a masked preview (first 4 chars + length). See security checklist.
- Rules are high-precision by default; broad heuristics get lower
  confidence so scoring stays honest.
- Interface is rule-based so an external source (e.g. gitleaks rules)
  can be merged in later without changing callers.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import stat
import zipfile
import yaml
from bisect import bisect_right
from dataclasses import dataclass
from typing import BinaryIO, Iterator

from app.scan.credential_context import (MAX_PYTHON_BYTES, MAX_TOTAL_PYTHON_BYTES, python_regions, uri_context)

MAX_SCANNED_FILE_BYTES = 1 * 1024 * 1024  # skip huge files: minified bundles etc.

_SKIP_DIRS = ("node_modules/", ".git/", "dist/", ".next/", "build/", "venv/", ".venv/")
_SKIP_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf",
    ".woff", ".woff2", ".ttf", ".eot", ".zip", ".gz", ".map",
    ".lock",  # lockfiles: huge, hash-heavy, no secrets by convention
)

# Documentation/example context: a credential-shaped string inside a
# blog post, docs page, or test fixture is far more likely a fabricated
# teaching example than a live secret (seen for real: a QA-tutorials
# site scored 0.0 because its articles contain example passwords and a
# sample private key). Findings there are NOT dropped — a real key
# pasted into docs is still a leak — but severity is capped at medium
# and confidence damped, so one tutorial can't zero out the whole score.
_DOC_SEGMENTS = frozenset((
    "blog", "docs", "doc", "content", "posts", "articles",
    "examples", "example", "fixtures", "__fixtures__", "samples",
))
# Storybook files are demonstration code by definition -- a component rendered
# with made-up props so a human can look at it -- so they belong with the
# examples rather than with the tests. Same treatment either way (capped at
# medium, never dropped); listed here because .stories.tsx is common in the
# React exports this product audits and matched neither predicate.
_DOC_SUFFIXES = (
    ".md", ".mdx",
    ".stories.ts", ".stories.tsx", ".stories.js", ".stories.jsx", ".stories.mdx",
)
_DOC_CONFIDENCE_FACTOR = 0.35
_DOC_SEVERITY_CAP = {"critical": "medium", "high": "medium"}

# Database migrations are the opposite of documentation context: a
# secret there is committed, applied state — anon JWTs, cron shared
# secrets and SMTP passwords in supabase/migrations/ showed up as a
# systemic pattern across real Lovable exports. Confidence is raised,
# and migration context always wins over doc-context damping (a path
# like examples/migrations/ is still a migration).
_MIGRATION_SEGMENTS = frozenset(("migrations", "migration"))
_MIGRATION_MIN_CONFIDENCE = 0.9

# Test context, in two strengths.
#
# This used to require BOTH a test path AND a placeholder marker in the value,
# which made the whole rule fire almost never. Measured on this repository:
# 23 of 26 findings were in tests/, 14 of them rendered as "Fix before launch",
# and exactly two were damped -- the two whose values literally contain the
# word "placeholder". A realistic fake key is realistic precisely because it
# does not say "fake" in it, so the marker requirement selected for the one
# jest.setup.ts shape the rule was written from and missed every other fixture.
#
# A wall of red on test files is not a stricter scanner, it is a scanner the
# reader stops believing -- and the credibility it burns is spent on the
# findings that DO matter. So the path alone now damps, exactly like doc
# context: capped at medium, never dropped, because a real leaked key can and
# does live in a test file.
#
# The marker is still worth something: path AND marker is two independent
# signals pointing the same way, so that combination damps further, to low.
# Neither strength drops the finding -- a reader who wants to check their
# fixtures still finds them in the report.
# WRITTEN FROM ONE REPOSITORY, WHICH IS WHY THIS LIST GREW.
#
# The first version of these predicates was calibrated on this codebase and
# pinned by a test whose eleven paths were .py, .js, .rb, .md, .sql and .json.
# Issue #174 asked the right question about that -- "fixtures in a Python test
# suite look nothing like fixtures in a Lovable export" -- and the answer,
# measured on 2026-08-26, was worse than expected:
#
#     src/lib/format.test.ts    -> damped
#     src/lib/format.test.tsx   -> NOT damped
#
# The same test, renamed for a React component, stopped being recognised. This
# repository's own web/ has six such files, and .tsx is the dominant convention
# in exactly the ecosystem this product audits: Lovable, Bolt and Cursor
# exports are React. An LLM finding in one of them came through critical at
# full weight -- 2.0 * confidence against a category budget of 10, so seven
# fixtures zero out Security, which is the failure #167 fixed for .ts and left
# standing for .tsx.
#
# Segments and suffixes below now cover the conventions those ecosystems
# actually use. Nothing here DROPS a finding -- the cap is medium and the
# confidence is scaled -- so the cost of a wrong entry is a real key shown as
# medium rather than critical, and the cost of a missing one is a wall of red
# that makes the reader stop believing the report.
_TEST_PATH_SEGMENTS = frozenset((
    "__tests__", "__mocks__", "__snapshots__", "test", "tests",
    # spec/ is the Ruby and Jasmine convention; e2e/, cypress/ and
    # playwright/ are where browser tests live in a JS project.
    "spec", "e2e", "cypress", "playwright",
    # msw and hand-rolled fakes; __mocks__ was already here, these are the
    # same thing without the jest-specific underscores.
    "mock", "mocks", "fixtures", "__fixtures__", "smoke",
))
_TEST_SETUP_FILENAMES = frozenset(("jest.setup.ts", "jest.setup.js"))
_TEST_FILE_SUFFIXES = (
    ".test.ts", ".test.tsx", ".test.js", ".test.jsx",
    ".spec.ts", ".spec.tsx", ".spec.js", ".spec.jsx",
    # Cypress names its specs <thing>.cy.<ext> rather than .spec.<ext>.
    ".cy.ts", ".cy.tsx", ".cy.js", ".cy.jsx",
)
_PLACEHOLDER_MARKERS = (
    "placeholder",
    "not-real",
    "not_real",
    "fake",
    "dummy",
    "test-only",
    "test_only",
)
_TEST_PATH_CONFIDENCE_FACTOR = 0.35        # path alone: same as doc context
_TEST_PLACEHOLDER_CONFIDENCE_FACTOR = 0.1  # path + self-labelled placeholder
_TEST_PLACEHOLDER_SEVERITY = "low"

# Standalone harnesses do not live under tests/, but their filename alone
# cannot establish that a credential is disposable. Require a self-labelled
# value as well, with marker boundaries so arbitrary secret bytes containing
# "fake" or a variable NAME containing "test" do not qualify.
_TEST_HARNESS_VALUE_MARKER = re.compile(
    r"(?:^|[-_])(?:"
    + "|".join(re.escape(marker) for marker in (
        *_PLACEHOLDER_MARKERS, "not-a-real", "not_a_real", "smoke-test", "smoke_test",
    ))
    + r")(?:$|[-_])",
    re.IGNORECASE,
)

# A match on a comment line is documentation that happens to live in a source
# file: a commented-out example, or a rule declaration describing the shape of
# the thing being searched for. This scanner's own pattern comments were
# reported as leaked Anthropic and SQL credentials -- it found a leak in its
# own description of how it finds leaks.
#
# Damped like doc context rather than dropped, because a commented-out REAL
# key is still committed and still leaked. Deliberately not applied to
# migrations: that escalation was calibrated on real exports and a comment
# marker is too weak a reason to weaken it.
_COMMENT_PREFIXES = ("#", "//", "*", "--", "<!--", "/*")


def _is_migration_context(name: str) -> bool:
    return any(seg.lower() in _MIGRATION_SEGMENTS for seg in name.split("/")[:-1])


def _is_test_fixture_path(name: str) -> bool:
    lower = name.lower()
    base = lower.rsplit("/", 1)[-1]
    if base in _TEST_SETUP_FILENAMES or lower.endswith(_TEST_FILE_SUFFIXES):
        return True
    # Python's own convention, independent of the directory: pytest and
    # unittest both discover test_*.py / *_test.py. A root-level
    # test_mini_app_integration.py escaped damping before -- it was not in
    # tests/ and carried no .test.ts-style suffix, so a quoted credential
    # inside it came back at full severity. Only .py files: test_utils.js
    # is a minifier convention, not a test.
    if base.endswith(".py") and (
            base.startswith("test_") or base.endswith("_test.py")):
        return True
    return any(seg in _TEST_PATH_SEGMENTS for seg in lower.split("/")[:-1])


def value_has_placeholder_marker(value: str) -> bool:
    """Whether a value announces itself as a stand-in (`changeme`, `xxx`, ...).

    Public because app/scan/checks.py grades a committed .env with it. That
    check must reach the same verdict this scanner does about what counts as
    a real value, and a second copy of the marker list is how the two would
    start disagreeing about the same file.
    """
    low = value.lower()
    return any(marker in low for marker in _PLACEHOLDER_MARKERS)


def _is_labelled_test_harness_value(name: str, rule: SecretRule, matched: str) -> bool:
    """Recognize disposable literals without treating scripts/ as test code.

    Only Python e2e/smoke harness assignments qualify. Provider credentials,
    signed tokens and connection strings keep their ordinary classification,
    even when another substring of the value labels it as a test.
    """
    parts = name.lower().split("/")
    if ("scripts" not in parts[:-1] or not parts[-1].endswith(".py")
            or not parts[-1].startswith(("e2e_", "smoke_"))
            or rule.id not in {"generic-assignment", "sql-secret-assignment"}):
        return False
    assignment = rule.pattern.fullmatch(matched)
    if assignment is None:
        return False
    value = assignment.group("value")
    if not _TEST_HARNESS_VALUE_MARKER.search(value):
        return False
    return not any(
        other.pattern.search(value)
        for other in RULES
        if other.id not in {"generic-assignment", "sql-secret-assignment"}
    )


def _is_comment_line(line_text: str) -> bool:
    """True when the match sits on a line that is entirely a comment.

    Prefix check only, and deliberately so: correctly deciding whether an
    offset is inside a comment needs a parser per language, and a wrong answer
    here silently hides a real secret. A line that STARTS as a comment is the
    case this is for -- code with a trailing `// key = "..."` is not damped.
    """
    return line_text.lstrip().startswith(_COMMENT_PREFIXES)


# The words that mark a dotenv file as a TEMPLATE -- a file that exists to be
# committed, because it is how a project documents which variables it needs.
#
# Matched as whole dot-separated parts rather than as a tail, so both
# `.env.local.example` and `.env.example.local` are recognised: the two
# orderings are equally common and neither is a secret-bearing file.
_ENV_TEMPLATE_MARKERS = frozenset(("example", "sample", "template", "dist"))


def is_env_template_name(path: str) -> bool:
    """Whether a path names a dotenv TEMPLATE rather than a real env file.

    By NAME, deliberately, and public because two callers must agree on it:
    app/scan/checks.py decides from it whether a file should be tracked at all
    (and hence whether the Fix Pack offers to delete it), and _is_doc_context
    below decides how loudly to report a value found INSIDE one.

    The two questions stay separate. A template is still read and still
    reported on if it holds something that looks like a credential -- damped
    to the same level as a README, never dropped.
    """
    base = path.rsplit("/", 1)[-1]
    if not base.startswith(".env."):
        return False
    return bool(_ENV_TEMPLATE_MARKERS & set(base.split(".")[2:]))


def _is_doc_context(name: str) -> bool:
    if name.lower().endswith(_DOC_SUFFIXES):
        return True
    # `.env.example` and its family are the canonical "here is the shape, not
    # the value" file -- the one thing in a repository whose entire purpose is
    # to show which variables exist without their contents. It matched neither
    # predicate: not a doc suffix, and `apps/web/` is not a doc segment. So a
    # DSN in `apps/web/.env.example` was reported at full weight beside real
    # code (measured on dubinc/dub, audit a5fcb681).
    #
    # Damped, not dropped, exactly like `README.md`: people do paste a live key
    # into a template by mistake, and that is still reported -- capped at
    # medium and shown in the non-production section rather than silently lost.
    if is_env_template_name(name):
        return True
    return any(seg.lower() in _DOC_SEGMENTS for seg in name.split("/")[:-1])


# `.github/workflows/*.yml` -- and nothing else under `.github/`, which also
# holds issue templates and CODEOWNERS. Used for ONE narrow purpose (see
# _classify_match): a connection string to a service container.
_CI_WORKFLOW_DIR = ".github/workflows/"


def _is_ci_workflow_path(name: str) -> bool:
    return _CI_WORKFLOW_DIR in name.lower()


# Contexts that mean "this file is not what the app runs in production".
# Kept next to the predicates that produce them so the two cannot drift.
# "ci_service" is the odd one out: a CI workflow is production-grade
# infrastructure and a real credential in one is a real finding, so
# is_non_production_path below deliberately does NOT claim workflow paths.
# The context is set only where the value itself is already known to be a
# throwaway (a service container's local connection string), which is a fact
# about the value and not about the path.
NON_PRODUCTION_CONTEXTS = frozenset(("test_fixture", "test_file", "comment",
                                     "doc_example", "ci_service"))


def is_non_production_path(name: str) -> bool:
    """True for test, example and documentation files.

    Public because the report groups findings by it, and findings that did not
    come from this scanner (the LLM pass) carry no `context` field to group on
    — only a path. Migration paths are excluded: a migration is applied state,
    which is as production as it gets.

    Dependency trees are NOT non-production by this predicate on purpose: a
    credential committed inside `node_modules` is still committed bytes, and
    damping it as a test fixture would understate a real leak. Scanners that read
    source for a defect instead use `is_dependency_path`, because vendored code is
    not the repository's own code.
    """
    if _is_migration_context(name):
        return False
    return _is_test_fixture_path(name) or _is_doc_context(name)


# Vendored and dependency trees: code the repository did not write, and the
# scanners that read source for a defect must not report on it. Measured, four
# shipped scanners (tls_verification, unsafe_deserialization, path_traversal,
# outbound_url) reported a defect planted under `node_modules/` and `vendor/`,
# and two of them promise "non-test/vendor" in the coverage sentence they show a
# customer. The route rules in auth_read/auth_write already carried this list
# inline; it lives here now so the fifth copy is not written by hand.
_DEPENDENCY_SEGMENTS = frozenset({"node_modules", "vendor", "venv", ".venv", "site-packages",
                                 "bower_components", ".tox", ".nox"})


def is_dependency_path(name: str) -> bool:
    """True for a file inside a dependency or vendored tree."""
    return any(segment in _DEPENDENCY_SEGMENTS for segment in name.split("/"))


def damp_for_non_production_path(
    name: str, severity: str, confidence: float,
) -> tuple[str, float, str | None]:
    """The path-only half of the damping above, for producers that have
    nothing but a path to go on.

    _classify_match damps a credential found in test, example or
    documentation files: capped at medium, confidence scaled down, never
    dropped. The LLM pass had no equivalent, so the same fixture the static
    rules rated "medium (test file)" came back from the model as critical at
    full weight -- and dedup_cross_rubric deliberately never merges an LLM
    finding with a static one, so both survived into the same report. The
    calibration on one side was being undone by the other.

    Measured on this repository: 14 such criticals cost 2.0 * confidence each
    against a category budget of 10, so Security scored 0.0 at every
    plausible confidence; seven were enough. Every one of them was a fixture
    in tests/ -- including the file literally named FAKE_SECRETS, and this
    scanner's own comment describing the pattern it searches for.

    Path only, deliberately. _classify_match also has the matched value and
    the source line, so it can spot a self-labelled placeholder or a
    commented-out example and damp harder on those two independent signals.
    An LLM finding carries neither, and guessing at them from a title would
    be inventing a signal rather than reading one.

    Migrations are excluded here exactly as they are in
    is_non_production_path: applied state is as production as it gets. The
    two must stay in agreement -- test_damping_agrees_with_path_predicate
    pins that.
    """
    if _is_migration_context(name):
        return severity, confidence, None
    if _is_test_fixture_path(name):
        return (_DOC_SEVERITY_CAP.get(severity, severity),
                round(confidence * _TEST_PATH_CONFIDENCE_FACTOR, 2),
                "test_file")
    if _is_doc_context(name):
        return (_DOC_SEVERITY_CAP.get(severity, severity),
                round(confidence * _DOC_CONFIDENCE_FACTOR, 2),
                "doc_example")
    return severity, confidence, None


@dataclass(frozen=True)
class SecretRule:
    id: str
    title: str
    pattern: re.Pattern
    severity: str      # critical | high | medium | low
    confidence: float  # 0..1


RULES: tuple[SecretRule, ...] = (
    SecretRule(
        "aws-access-key-id", "AWS Access Key ID",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical", 0.95,
    ),
    SecretRule(
        "github-pat", "GitHub personal access token",
        re.compile(r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,255})\b"),
        "critical", 0.95,
    ),
    SecretRule(
        "stripe-live-key", "Stripe live secret key",
        re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), "critical", 0.95,
    ),
    SecretRule(
        "anthropic-api-key", "Anthropic API key",
        re.compile(r"\bsk-ant-api03-[A-Za-z0-9_\-]{20,}\b"), "critical", 0.95,
    ),
    SecretRule(
        "telegram-bot-token", "Telegram bot token",
        re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b"), "critical", 0.9,
    ),
    SecretRule(
        "private-key-block", "Private key material",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
        "critical", 0.95,
    ),
    SecretRule(
        "jwt-in-code", "JWT committed to code",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        "high", 0.6,
    ),
    SecretRule(
        # A connection string carrying its own password:
        # scheme://user:password@host. Nothing else here catches it. The
        # generic-assignment rule requires quotes around the value and keys
        # on a secret-shaped NAME, so a DSN assigned to `DATABASE_URL` -- or
        # passed straight into a client constructor -- scanned completely
        # clean. Verified against scan_secrets on postgres, mysql, mongodb,
        # redis, amqp and https-basic-auth forms: none produced a finding.
        #
        # The password half deliberately excludes $ { } < > %, so an
        # interpolated value (postgres://u:${DB_PASSWORD}@h, ...:%s@...,  scan-allow: rule documentation, no credential
        # ...:{pw}@...) does not match at all -- there is no credential in
        # that file to find. A literal password does match, and is graded
        # by _dsn_severity: a dev default or a localhost host is reported
        # informationally rather than as a leak.
        #
        # Requires >=3 password characters so `u:p@h` shorthand in prose
        # does not fire, and bounds every component so a pathological line
        # cannot drive the engine into backtracking.
        "connection-string-password", "Password embedded in a connection string",
        re.compile(
            r"(?i)(?<![a-z0-9+.-])[a-z][a-z0-9+.-]{0,31}://"      # scheme
            r"[^:/?#@\s\"']{1,64}"                  # user
            r":[^@/?#\s\"'${}<>%]{3,128}"           # password, no interpolation
            r"@[A-Za-z0-9._-]{1,253}"               # host
            # Port and path are part of the match on purpose, so the span IS
            # the whole connection string. The Fix Pack replaces a secret by
            # locating the QUOTED literal around it; a match that stopped at
            # the host left `:5432/app` behind inside the quotes and rewrote
            # DB = "postgres://u:pw@h:5432/app" into  scan-allow: rule documentation, no credential
            # DB = "os.environ['DATABASE_URL']:5432/app" -- scrubbed, and not
            # valid code. _verify_scrubbed would have passed it, because the
            # password really was gone.
            r"(?::\d{1,5})?"                        # port
            r"(?:/[^\s\"'`<>]*)?"                   # database / path / query
        ),
        "critical", 0.9,
    ),
    SecretRule(
        # Systemic Lovable-export pattern, confirmed on real repos:
        # migrations declare PL/pgSQL variables like
        #   v_cron_secret text := 'hunter2...';
        # The generic-assignment rule misses these because a type
        # annotation sits between the name and the assignment.
        # THE TYPE ANNOTATION WAS REQUIRED, and that made the rule read one
        # shape out of six. A hunt run rewrote the fixture into the ways people
        # actually put a secret in a database --
        #
        #   update users set access_token = 'sk-live-...'
        #   alter table config set secret_key = '...'
        #   create table c (token varchar(255) default '...')
        #
        # -- and the scanner was silent on every one. The type is now optional.
        #
        # WHERE IS EXCLUDED. `select * from users where password = '...'` is a
        # comparison, not a stored secret, and matching it would report a login
        # query as a leak. SQL files also get a clause-context check below:
        # whitespace, parentheses and qualified columns do not change a
        # comparison into an assignment. Keep the immediate exclusions for
        # SQL snippets embedded in other source languages.
        "sql-secret-assignment", "Hardcoded secret in SQL/PLpgSQL assignment",
        re.compile(
            r"(?i)(?<!where\s)(?<!and\s)(?<!or\s)"
            r"\b\w*(?:secret|password|api[_-]?key|service[_-]?role)\w*\s*"
            r"(?:(?:text|varchar(?:\(\d+\))?|character varying)\s*)?"
            # DEFAULT('...') and DEFAULT('...') with the parentheses the form
            # actually wears are both read; a hunt run on the stronger model
            # produced the parenthesised spelling and the detector stayed
            # silent. The closing parenthesis is optional so `:= '...'` and
            # `:= ('...')` share one branch.
            r"(?::?=|\s+default\s*)"
            r"\s*(?:\(\s*)?'(?P<value>[^']{8,})'(?:\s*\))?"
        ),
        "high", 0.7,
    ),
    SecretRule(
        # Backticks are quotes too. The rule shipped accepting ' and " only, so
        #   const apiKey = `AKIA...`
        # scanned clean while the same line in single quotes was reported --
        # and a template literal is ordinary JS/TS, not an evasion. Found by
        # scripts/hunt_detector_escapes.py, which rewrote the corpus fixture
        # into a template literal and watched the detector stay silent.
        #
        # The quote character must match on both sides: an unbalanced pair is
        # a string that does not end where the match does, and the Fix Pack
        # replaces a secret by locating the quoted literal around it.
        # `connection-string-password` documents what that costs when a span
        # and its literal disagree.
        #
        # Backtick templates exclude ${...} here. Shell expansion is checked
        # against its source context below; ordinary Python/JS quoted values
        # may contain dollar signs and braces as secret bytes.
        # The NAME vocabulary is the other half of the rule, and it shipped
        # narrower than the things people actually call a credential:
        #   const authToken = "...."      scanned clean
        #   const accessKey = "...."      scanned clean
        # while `service_role` -- rarer in real code than either -- was covered.
        # Also found by scripts/hunt_detector_escapes.py: the model renamed
        # api_key to token and the detector stopped seeing it.
        #
        # WHICH WORDS, AND WHY NOT MORE. Every addition risks false positives,
        # so each candidate was counted against real code before being let in:
        # web/src (59 files), 3000 node_modules files and app/ (142 files).
        # The words below matched NOTHING in that corpus -- they cost no noise.
        # Two were rejected on the evidence:
        #   `key`   -- 14 hits, all ordinary data (jsdom's `key = "modifierAltGraph"`).
        #              Too generic to mean credential.
        #   `token` -- 1 hit, in a *.test.tsx that is_non_production_path already
        #              damps, so it is kept; a bare `token` is common enough in
        #              real code that this one deserves re-measuring if the
        #              corpus ever grows.
        # THE WORD MUST BE A COMPONENT OF THE NAME, not the whole of it.
        # `\b` shipped here, and `_` is a word character, so `\bpassword\b`
        # did not match inside `db_password` -- nor `secret_token`,
        # `my_api_key`, `admin_token` or `dbPassword`. Those are the names
        # people actually use, and the rule saw none of them. Found by
        # scripts/hunt_detector_escapes.py, where the model renamed the
        # fixture's `api_key` to shapes like these and the detector went quiet.
        #
        # A plain substring test was MEASURED AND REJECTED FIRST: it matches
        # `tokenizer` and `secretary`, which are ordinary words. The boundary
        # below keeps the word whole on its right -- a separator, a capital, or
        # the end of the identifier -- so `token` matches in `admin_token` and
        # `adminToken` but not in `tokenizer`. Verified against 8243 files
        # (web/src, app/, scripts/, 8000 from node_modules): 6 matches, of
        # which the scanner damps the test-file one and reports two throwaway
        # container passwords in scripts/ that already carry a `# noqa: S105`
        # from another linter -- so the new reach finds the class of thing it
        # is for. `encryption[_-]?key` is the one added word: nothing else in
        # the vocabulary covers it, and it cost 2 matches in that corpus, both
        # in Next.js internals naming an env var rather than holding a key.
        #
        # The value must follow the WORD, not merely the name containing it, so
        # `hash_password = "..."` matches and `password_hash = "..."` does not.
        # That asymmetry is the boundary doing its job: in the second case the
        # identifier is `password_hash`, and a rule that matched it would also
        # match `tokenizer`. Plurals (`credentials`) are missed for the same
        # reason and are left missed -- the alternative costs the words above.
        "generic-assignment", "Hardcoded credential assignment",
        re.compile(
            r"(?i)"
            # TWO SPELLINGS OF THE NAME, measured on the same corpus:
            #
            # A. A bare identifier, as before: `db_password = "..."`,
            #    `const adminToken = "..."`, `{ db_password: "..." }`.
            # B. A QUOTED KEY in an object literal or JSON document:
            #    `{"db_password": "..."}`, `'client_secret': '...'`.
            #    The quotes must be a CONSENTING PAIR around the name --
            #    `'api-key": "ANTHROPIC_API_KEY"'` (a Python string whose
            #    apostrophe is unrelated to the double quote) does not match.
            #    Prefixed keys (`db_password`) are read because the prefix
            #    ends in `_`, so the word still starts at a boundary.
            #
            # WHY B EXISTS: a JSON config is how real leaks travel
            # (firebase/analytics configs, docker env files). Measured:
            # adding B produced ZERO new matches on 691 files of live
            # repository code and removed none -- it only starts to fire
            # when an actual quoted secret appears.
            r"(?:"
            r"(?:(?<![A-Za-z0-9])|(?<=[a-z0-9])(?=[A-Z]))"
            r"(?:api[_-]?key|secret|password|service[_-]?role"
            r"|token|auth[_-]?token|access[_-]?key|client[_-]?secret"
            r"|credential|private[_-]?key|encryption[_-]?key|passwd)"
            # THE WORD MAY START THE NAME, not only end it. `adminToken` was
            # read because the value follows the word directly; `tokenForAdmin`
            # and `secretOne` were not, though they name the same thing. A hunt
            # run on a stronger model produced exactly those two shapes and the
            # scanner was silent on both.
            #
            # The boundary is "not followed by a LOWERCASE letter", which is
            # what separates a suffix from a longer word: `secretOne` and
            # `token2` qualify, `tokenizer` and `secretary` do not.
            #
            # (?-i:...) IS LOAD-BEARING. Under the pattern's (?i) flag the
            # class [a-z] matches capitals too, so "not lowercase" would have
            # forbidden every letter and this addition would have changed
            # nothing at all -- it read as working while doing nothing.
            r"(?-i:(?![a-z]))[A-Za-z0-9]*"
            # A suffix after a SEPARATOR stays out: `api_key_pepper_env`,
            # `TOKEN_HEADER` and `API_KEY_COOKIE` are the names of environment
            # variables and headers, not the secrets themselves. Measured at
            # 8208 files: allowing it added 4 matches, all of that shape and
            # all wrong. `password_hash` stays out for the same reason it
            # always has.
            r"[_-]*"
            r"|"
            r"(?P<k>['\"])"
            r"(?:[A-Za-z0-9]+_)*"
            r"(?:(?<![A-Za-z0-9])|(?<=[a-z0-9])(?=[A-Z]))"
            r"(?:api[_-]?key|secret|password|service[_-]?role"
            r"|token|auth[_-]?token|access[_-]?key|client[_-]?secret"
            r"|credential|private[_-]?key|encryption[_-]?key|passwd)"
            r"(?-i:(?![a-z]))[A-Za-z0-9]*[_-]*"
            r"(?P=k)"
            r")"
            # Named, not numbered: the backreference has to survive someone
            # adding a group to the name half, which numbering does not.
            r"\s*[:=]\s*(?P<q>['\"]|(?P<template>`))"
            r"(?P<value>(?:(?!(?P=q))(?(template)(?!\$\{))[^\s]){12,})(?P=q)"
        ),
        "high", 0.5,
    ),
)


# Pure parameter references carry no literal credential. In particular an
# empty fallback in `${!token_env_name:-}` is not a hardcoded default. A
# nonempty fallback or literal prefix stays reportable rather than having
# potentially secret bytes discarded merely because a dollar sign occurs.
_SHELL_VARIABLE_VALUE = re.compile(
    r"(?:\$[A-Za-z_][A-Za-z0-9_]*|\$\{!?[A-Za-z_][A-Za-z0-9_]*(?::?[-+?])?\})+"
)
_SHELL_SHEBANG = re.compile(r"^#![^\n]*\b(?:ba|da|k|z)?sh(?:\s|$)")
_SHELL_NAMES = frozenset(("sh", "bash", "dash", "ksh", "zsh"))
_HEREDOC_START = re.compile(r"<<(-?)[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")


def _shell_variable_offsets(script: str, base: int = 0) -> set[int]:
    """Locate active quoted assignments without executing shell code.

    Single-quoted strings, comments and heredoc bodies are not executable
    assignments. This small lexical filter declines ambiguous constructs;
    it only removes candidates whose entire value is parameter expansion.
    """
    generic = next(rule for rule in RULES if rule.id == "generic-assignment")
    candidates = {
        match.start() for match in generic.pattern.finditer(script)
        if match.group("q") == '"'
        and _SHELL_VARIABLE_VALUE.fullmatch(match.group("value"))
    }
    ignored: set[int] = set()
    quote = ""
    comment = False
    heredocs: list[tuple[str, bool]] = []
    in_heredoc = False
    index = 0
    while index < len(script):
        if in_heredoc:
            end = script.find("\n", index)
            end = len(script) if end < 0 else end
            line = script[index:end].rstrip("\r")
            delimiter, strip_tabs = heredocs[0]
            if (line.lstrip("\t") if strip_tabs else line) == delimiter:
                heredocs.pop(0)
                in_heredoc = bool(heredocs)
            index = end + 1
            continue
        char = script[index]
        if index in candidates and not quote and not comment:
            ignored.add(base + index)
        if char == "\n":
            comment = False
            if heredocs and not quote:
                in_heredoc = True
        elif not comment:
            if char == "\\" and quote != "'":
                index += 2
                continue
            if char == quote:
                quote = ""
            elif not quote:
                if char in "'\"`":
                    quote = char
                elif char == "#" and (index == 0 or script[index - 1].isspace()):
                    comment = True
                elif script.startswith("<<", index):
                    marker = _HEREDOC_START.match(script, index)
                    if marker is None:
                        # Here strings and computed delimiters need a fuller
                        # parser; do not suppress later candidates by guessing.
                        break
                    heredocs.append((marker.group(3), bool(marker.group(1))))
                    index = marker.end()
                    continue
        index += 1
    return ignored


def _shell_substitution_offsets(name: str, text: str) -> set[int]:
    """Recognise shell files and the shell run fields of GitHub workflows.

    YAML configuration values and Python/JS run steps are literal data in
    their own languages. Treating the entire workflow as shell would hide
    genuine credentials there, so use YAML node spans to delimit run code.
    """
    lower = name.lower()
    if (lower.endswith((".sh", ".bash", ".zsh", ".ksh"))
            or lower.rsplit("/", 1)[-1] in {".bashrc", ".bash_profile", ".profile", ".zshrc"}
            or _SHELL_SHEBANG.match(text)):
        return _shell_variable_offsets(text)
    if not (_is_ci_workflow_path(name) and lower.endswith((".yml", ".yaml"))):
        return set()
    if len(text) > MAX_PYTHON_BYTES or len(text.encode("utf-8")) > MAX_PYTHON_BYTES:
        return set()  # retain findings when parsing exceeds the source-context budget
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except (yaml.YAMLError, RecursionError):
        return set()
    ignored: set[int] = set()
    pending = [(root, "bash")]
    seen: set[int] = set()
    while pending:
        node, inherited_shell = pending.pop()
        if node is None or id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, yaml.SequenceNode):
            pending.extend((child, inherited_shell) for child in node.value)
            continue
        if not isinstance(node, yaml.MappingNode):
            continue
        fields = {key.value: value for key, value in node.value if isinstance(key, yaml.ScalarNode)}
        shell = inherited_shell
        runner = fields.get("runs-on")
        if runner is not None and "windows" in text[runner.start_mark.index:runner.end_mark.index].lower():
            shell = "pwsh"
        defaults = fields.get("defaults")
        if isinstance(defaults, yaml.MappingNode):
            for key, value in defaults.value:
                if (isinstance(key, yaml.ScalarNode) and key.value == "run"
                        and isinstance(value, yaml.MappingNode)):
                    shell = next((item.value for key, item in value.value
                                  if isinstance(key, yaml.ScalarNode) and key.value == "shell"
                                  and isinstance(item, yaml.ScalarNode)), shell)
        explicit_shell = fields.get("shell")
        if isinstance(explicit_shell, yaml.ScalarNode):
            shell = explicit_shell.value
        run = fields.get("run")
        if isinstance(run, yaml.ScalarNode) and shell.split(" ", 1)[0] in _SHELL_NAMES:
            start, end = run.start_mark.index, run.end_mark.index
            raw = text[start:end]
            if run.style in {"'", '"'}:
                # Escaped YAML content needs its own source map. Retain a
                # candidate when that mapping is uncertain.
                if raw[1:-1] != run.value:
                    raw = ""
                else:
                    raw = raw[1:-1]
                    start += 1
            ignored.update(_shell_variable_offsets(raw, start))
        pending.extend((child, shell) for child in fields.values())
    return ignored


# These tokens locate SQL predicate clauses without reading keywords inside
# quoted values, identifiers or comments. Parentheses retain the outer clause
# so a subquery's WHERE cannot hide a later UPDATE SET assignment.
_SQL_CONTEXT_TOKEN = re.compile(
    r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|--[^\n]*|/\*.*?\*/"
    r"|(?P<word>\b[A-Za-z_][A-Za-z_0-9]*\b)|(?P<punct>[();])",
    re.DOTALL,
)


def _sql_comparison_ranges(text: str) -> list[tuple[int, int]]:
    """Source ranges in recognizable SQL predicates; no query execution."""
    ranges = []
    stack = []
    comparison = False
    start = 0
    for token in _SQL_CONTEXT_TOKEN.finditer(text):
        previous = comparison
        word = (token.group("word") or "").lower()
        punct = token.group("punct")
        if punct == "(":
            stack.append(comparison)
        elif punct == ")":
            comparison = stack.pop() if stack else False
        elif punct == ";":
            comparison = False
            stack.clear()
        elif word in {"where", "having", "on", "select", "check"}:
            comparison = True
        elif word in {"set", "update", "insert", "delete", "create", "alter", "declare", "begin"}:
            comparison = False
        if comparison != previous:
            if comparison:
                start = token.end()
            else:
                ranges.append((start, token.start()))
    if comparison:
        ranges.append((start, len(text)))
    return ranges


@dataclass(frozen=True)
class SecretFinding:
    rule_id: str
    title: str
    severity: str
    confidence: float
    file: str
    line: int
    masked: str  # e.g. "AKIA****(20 chars)" — value itself is never stored
    # Machine-readable damping context, mirroring the title suffix so
    # downstream code (the report's section split, the Fix Pack eligibility
    # filter) can branch on it without string-matching the title. One of
    # "test_fixture", "test_file", "comment", "doc_example", or None when the
    # finding is undamped production code. Escalated migration findings stay
    # None: they are production context, more so than anything else here.
    context: str | None = None
    source_context: dict | None = None


def _mask(value: str) -> str:
    return f"{value[:4]}****({len(value)} chars)"


def _iter_text_files(zf: zipfile.ZipFile, coverage: dict | None = None) -> Iterator[tuple[str, str]]:
    if coverage is None:
        coverage = {}
    coverage.update(files_total=0, files_read=0, files_scanned=0, lossy_decoded_files=0, exclusions={})

    def skip(reason: str) -> None:
        counts = coverage["exclusions"]
        counts[reason] = counts.get(reason, 0) + 1

    for info in zf.infolist():
        name = info.filename
        if info.is_dir():
            continue
        coverage["files_total"] += 1
        if info.file_size > MAX_SCANNED_FILE_BYTES:
            skip("file_size_limit")
            continue
        if stat.S_ISLNK(info.external_attr >> 16):
            skip("symlink")
            continue
        if any(part in name for part in _SKIP_DIRS):
            skip("excluded_directory")
            continue
        if name.lower().endswith(_SKIP_SUFFIXES):
            skip("excluded_extension")
            continue
        data = zf.read(info)
        coverage["files_read"] += 1
        if b"\x00" in data[:4096]:  # binary sniff
            skip("binary_content")
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            coverage["lossy_decoded_files"] += 1
            text = data.decode("utf-8", errors="ignore")
        coverage["files_scanned"] += 1
        yield name, text


# The Supabase CLI's local stack signs its tokens with the SAME secret for
# every developer on earth: `supabase start` prints it, the documentation
# publishes it, and every project scaffolded from the template carries tokens
# signed with it.
#
# That is what makes such a token informational, and the reasoning is not "it
# looks like a demo". It is that the SECRET IS PUBLIC, so anyone can mint an
# identical token -- and a credential everybody can forge opens nothing. Same
# argument as _DSN_DEV_PASSWORDS below: finding `postgres:postgres` tells you
# the author followed a tutorial, not that a credential leaked.
#
# Measured on mckaywrigley/chatbot-ui, audit f444873f:
# supabase/migrations/20240108234540_setup.sql carries a token whose claims
# are iss=supabase-demo, role=service_role, exp=1983812996, and whose
# signature verifies against this secret. (Written without JSON quoting on
# purpose: tests/test_plain_language.py scrapes this file for rule ids with a
# deliberately loose regex, and a quoted `id", "` pair in a COMMENT is enough
# to make it demand a translation for a rule that does not exist.) It was reported as a CRITICAL
# "full RLS bypass", which capped that repository's score at 6.9 and stood
# beside a genuine critical (SSRF via a user-controlled tool URL) claiming
# equal weight. Every Supabase project that commits its scaffolding got the
# same finding.
_SUPABASE_DEMO_JWT_SECRETS = (
    "super-secret-jwt-token-with-at-least-32-characters-long",
)


def _is_demo_jwt(token: str) -> bool:
    """Whether this JWT is signed with a publicly known development secret.

    THE SIGNATURE, AND DELIBERATELY NOT THE `iss` CLAIM. `iss` is unsigned
    data that the holder controls: a self-hosted deployment that kept the
    demo issuer while setting a real secret would carry `iss: supabase-demo`
    on tokens that ARE live credentials, and damping those is the expensive
    direction of this mistake. A signature that verifies against a published
    secret proves the opposite and proves it outright.

    Robust to the token being reissued, too. The CLI has changed the demo
    `exp` before; matching known token strings would go stale on the next
    bump, while the secret is what the whole local stack is built around.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return False
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    for secret in _SUPABASE_DEMO_JWT_SECRETS:
        want = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        if hmac.compare_digest(want, parts[2]):
            return True
    return False


def _jwt_severity(token: str) -> tuple[str, float, str]:
    """Supabase keys are JWTs with a `role` claim: anon is public by
    design (every Lovable app ships it client-side), service_role is a
    full RLS bypass. Decode the payload to tell them apart.

    The demo check comes first because it outranks the role: a service_role
    token signed with a public secret is not a service_role credential, it is
    a fixture that happens to say service_role.
    """
    if _is_demo_jwt(token):
        return ("low", 0.2,
                "Supabase local-development demo key "
                "(public by design, informational)")
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        role = data.get("role", "")
    except Exception:
        return "high", 0.6, "JWT committed to code"
    if role == "service_role":
        return "critical", 0.95, "Supabase service_role key committed — full RLS bypass"
    if role == "anon":
        return "low", 0.3, "Supabase anon key in code (public by design, informational)"
    return "high", 0.6, "JWT committed to code"


# Hosts that mean "this connection never leaves the developer's machine",
# including the service names docker-compose conventionally assigns.
_DSN_LOCAL_HOSTS = frozenset((
    "localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal",
    "db", "database", "postgres", "postgresql", "mysql", "mariadb",
    "redis", "mongo", "mongodb", "rabbitmq", "mq",
))

# Passwords that are conventions rather than secrets: the value every
# docker-compose and quickstart uses. Finding `postgres:postgres` tells you
# the author followed a tutorial, not that a credential leaked.
_DSN_DEV_PASSWORDS = frozenset((
    "postgres", "postgresql", "password", "passwd", "pass", "root", "admin",
    "guest", "test", "testing", "example", "docker", "mysql", "redis",
    "mongo", "secret", "dev", "development", "local", "changeme",
))

_DSN_SPLIT_RE = re.compile(
    r"://(?P<user>[^:/?#@\s]+):(?P<password>[^@/?#\s]+)@(?P<host>[^/?#\s:]+)"
)


def dsn_password_is_conventional(matched: str) -> bool:
    """Whether a connection string's password is a tutorial default.

    Public because the finding gets its own rule_id when this is true, the
    way supabase-anon-key does: same pattern, materially different claim.
    A password of `postgres` against a host of `db` is a docker-compose
    convention rather than a credential, and filing it under the same id as
    a live production one would make the report collapse the two together
    and offer to rewrite the first.
    """
    m = _DSN_SPLIT_RE.search(matched)
    if m is None:
        return False
    pw = m.group("password").lower().replace("_", "").replace("-", "")
    return pw in _DSN_DEV_PASSWORDS


def dsn_host_is_local(matched: str) -> bool:
    """Whether a connection string points at the developer's own machine.

    Public for the same reason dsn_password_is_conventional is: the finding
    gets its own rule_id when this is true, so the advice can say what is
    actually true of a localhost DSN instead of sending the reader to a
    provider that does not exist.

    Deliberately a SECOND, independent question from the password. A DSN can
    be local with a real-looking password (a developer's own postgres, whose
    password may well be reused elsewhere) or remote with `postgres` (a
    tutorial default pointed at something real). The two say different things
    and get different advice.
    """
    m = _DSN_SPLIT_RE.search(matched)
    if m is None:
        return False
    return m.group("host").lower() in _DSN_LOCAL_HOSTS


def _dsn_severity(matched: str) -> tuple[str, float, str]:
    """Grade one connection string by what its password and host actually are.

    A DSN pointing at a production host with a real password is as direct a
    leak as an API key -- it is the database, in one string. The same shape
    pointing at localhost with the password `postgres` is a tutorial default,
    and reporting it as critical would be the committed-.env mistake again:
    a claim of exposure the value itself contradicts. Both are still
    reported; only the claim differs.
    """
    m = _DSN_SPLIT_RE.search(matched)
    if m is None:  # pragma: no cover - the rule pattern guarantees the shape
        return "critical", 0.9, "Password embedded in a connection string"

    # Separators stripped before the lookup: the same convention shows up as
    # changeme, change_me and change-me, and our own Deploy Pack template
    # emits `change_me`. Matching only the unpunctuated spelling graded that
    # template as a real credential.
    host = m.group("host").lower()

    if dsn_password_is_conventional(matched):
        return ("low", 0.3,
                "Connection string with a default development password "
                "(informational)")
    if host in _DSN_LOCAL_HOSTS:
        return ("medium", 0.5,
                "Password in a connection string to a local/development host")
    return ("critical", 0.9,
            "Password embedded in a connection string")


def _classify_match(name: str, lineno: int, rule: SecretRule,
                    matched: str, line_text: str = "", source_role: str | None = None) -> SecretFinding:
    """Turn one rule hit into a SecretFinding, applying the same
    context-damping and effective-rule-id logic scan_secrets has always
    used. Extracted so iter_secret_matches and scan_secrets share one
    definition of "what a finding is" (the Fix Pack relocation path must
    reproduce the exact rule_id/context the audit persisted)."""
    severity, confidence, title = rule.severity, rule.confidence, rule.title
    if rule.id == "jwt-in-code":
        severity, confidence, title = _jwt_severity(matched)
    elif rule.id == "connection-string-password":
        severity, confidence, title = _dsn_severity(matched)
    # Supabase anon key is public by design; migration context must NOT
    # re-escalate it (that produced a wall of 40+ scary-but-false "admin
    # login" rows in a real report). Tag it with its own rule_id so the
    # report can collapse and translate it correctly.
    is_anon = title.startswith("Supabase anon key")
    # The third member of the same family, and it joins for the same reason:
    # a token anyone can mint must not be escalated by migration context, must
    # not collapse together with a live credential, and must not be offered to
    # the Fix Pack as something to rewrite. See _SUPABASE_DEMO_JWT_SECRETS.
    is_demo_jwt = title.startswith("Supabase local-development demo key")
    # A tutorial-default connection password gets its own id for the same
    # reason the anon key does: the report must not collapse it together
    # with a live credential, and the Fix Pack must not offer to rewrite a
    # docker-compose default into an environment variable.
    is_dev_dsn = (rule.id == "connection-string-password"
                  and dsn_password_is_conventional(matched))
    # The third outcome of _dsn_severity, and it had no id of its own. That
    # function grades on TWO signals -- a conventional password, then a local
    # host -- while only the first one routed the rule_id, so a real-looking
    # password against localhost produced a finding titled "to a local/
    # development host" carrying the advice for a live leak: "change that
    # user's password at your database provider". There is no provider.
    # Measured on dubinc/dub, audit a5fcb681, twice in one report.
    is_local_dsn = (rule.id == "connection-string-password"
                    and not is_dev_dsn
                    and dsn_host_is_local(matched))
    if is_anon:
        effective_rule_id = "supabase-anon-key"
    elif is_demo_jwt:
        effective_rule_id = "supabase-demo-key"
    elif is_dev_dsn:
        effective_rule_id = "connection-string-dev-password"
    elif is_local_dsn:
        effective_rule_id = "connection-string-local-host"
    else:
        effective_rule_id = rule.id
    # Order matters. Migration escalation wins outright -- it is the one
    # context calibrated on confirmed real leaks. Everything below it damps,
    # strongest signal first: a self-labelled placeholder on a test path is
    # two signals, a test path is one, a comment or doc path is one.
    context: str | None = None
    if (_is_migration_context(name)
            and not is_anon and not is_dev_dsn and not is_demo_jwt
            and not is_local_dsn):
        confidence = max(confidence, _MIGRATION_MIN_CONFIDENCE)
        title = f"{title} (committed database migration)"
    elif is_anon or is_demo_jwt:
        pass
    elif (is_local_dsn or (is_dev_dsn and dsn_host_is_local(matched))) and _is_ci_workflow_path(name):
        # A connection string to localhost inside a CI workflow is the
        # password of a service container that exists for the length of one
        # job. Measured on dubinc/dub (audit a5fcb681):
        # `.github/workflows/playwright.yaml` was reported at full weight
        # while `apps/web/playwright/assert-local-database.ts` in the same
        # repository was damped -- the same value, and the only difference was
        # whether "playwright" landed in a directory name or a file name.
        #
        # Narrow on purpose, and only for the local-host variant. A workflow
        # can carry a real cloud connection string exactly the way a migration
        # can, and that one must stay critical: see the test.
        severity = _DOC_SEVERITY_CAP.get(severity, severity)
        confidence = round(confidence * _DOC_CONFIDENCE_FACTOR, 2)
        title = f"{title} (CI service container)"
        context = "ci_service"
    elif ((_is_test_fixture_path(name) and value_has_placeholder_marker(matched))
          or _is_labelled_test_harness_value(name, rule, matched)):
        severity = _TEST_PLACEHOLDER_SEVERITY
        confidence = round(confidence * _TEST_PLACEHOLDER_CONFIDENCE_FACTOR, 2)
        title = f"{title} (test fixture/placeholder context)"
        context = "test_fixture"
    elif _is_test_fixture_path(name):
        severity = _DOC_SEVERITY_CAP.get(severity, severity)
        confidence = round(confidence * _TEST_PATH_CONFIDENCE_FACTOR, 2)
        title = f"{title} (test file)"
        context = "test_file"
    elif _is_comment_line(line_text):
        severity = _DOC_SEVERITY_CAP.get(severity, severity)
        confidence = round(confidence * _DOC_CONFIDENCE_FACTOR, 2)
        title = f"{title} (commented-out line)"
        context = "comment"
    elif _is_doc_context(name) or source_role == "docstring":
        severity = _DOC_SEVERITY_CAP.get(severity, severity)
        confidence = round(confidence * _DOC_CONFIDENCE_FACTOR, 2)
        title = f"{title} (documentation/example context)"
        context = "doc_example"
    role = source_role or context or "source_literal"
    if is_dev_dsn and context is None and source_role is None:
        parts = _DSN_SPLIT_RE.search(matched)
        host = parts["host"].lower() if parts else ""
        if host in {"example.com", "example.org", "example.net"} or host.endswith(".example"):
            context, role = "doc_example", "placeholder_uri"
    return SecretFinding(
        rule_id=effective_rule_id,
        title=title,
        severity=severity,
        confidence=confidence,
        file=name,
        line=lineno,
        masked=_mask(matched),
        context=context,
        source_context=uri_context(matched, role) if rule.id == "connection-string-password" else None,
    )


def iter_secret_matches(fileobj: BinaryIO, *, coverage: dict | None = None) -> Iterator[tuple[SecretFinding, str]]:
    """Like scan_secrets, but also yields the RAW matched text alongside
    each finding.

    SECURITY: the second tuple element IS the real secret (or the raw
    assignment span containing it). SecretFinding itself deliberately
    never stores it (only a mask) so findings can be persisted/logged
    safely — this generator is the one place the value is exposed, for
    the Fix Pack generator which must know the literal to scrub it out of
    source. Callers MUST NOT persist, log, or echo the raw value; it may
    only be written OUT of a file, never back into any artifact.
    """
    remaining = MAX_TOTAL_PYTHON_BYTES
    with zipfile.ZipFile(fileobj) as zf:
        for name, text in _iter_text_files(zf, coverage):
            regions = None
            comparison_ranges = None
            shell_substitutions = None
            next_line_offset = 0
            for lineno, raw_line in enumerate(text.splitlines(keepends=True), start=1):
                line_offset = next_line_offset
                next_line_offset += len(raw_line)
                line = raw_line.rstrip("\r\n")
                for rule in RULES:
                    m = rule.pattern.search(line)
                    if not m:
                        continue
                    if regions is None:
                        regions = []
                        size = len(text.encode("utf-8"))
                        if name.endswith(".py") and size <= min(MAX_PYTHON_BYTES, remaining):
                            remaining -= size
                            regions = python_regions(text)
                    for candidate in rule.pattern.finditer(line):
                        if rule.id == "sql-secret-assignment" and name.lower().endswith(".sql"):
                            if comparison_ranges is None:
                                comparison_ranges = _sql_comparison_ranges(text)
                            offset = line_offset + candidate.start()
                            index = bisect_right(comparison_ranges, offset, key=lambda span: span[0]) - 1
                            if index >= 0 and offset < comparison_ranges[index][1]:
                                continue
                        if (rule.id == "generic-assignment" and candidate.group("q") == '"'
                                and _SHELL_VARIABLE_VALUE.fullmatch(candidate.group("value"))):
                            if shell_substitutions is None:
                                shell_substitutions = _shell_substitution_offsets(name, text)
                            if line_offset + candidate.start() in shell_substitutions:
                                continue
                        if rule.id in {"generic-assignment", "sql-secret-assignment"}:
                            value_start = (lineno, len(line[:candidate.start("value")].encode("utf-8")))
                            value_end = (lineno, len(line[:candidate.end("value")].encode("utf-8")))
                            # Only an entire formatted field is nonliteral;
                            # real secret bytes inside its expression or next
                            # to the field must remain visible.
                            if any(role == "formatted_value"
                                   and value_start == (lo, col) and value_end == (hi, end_col)
                                   for lo, col, hi, end_col, role in regions):
                                continue
                        m = candidate
                        break
                    else:
                        continue
                    # AST columns are UTF-8 byte offsets; regex offsets are characters.
                    start = (lineno, len(line[:m.start()].encode("utf-8")))
                    end = (lineno, len(line[:m.end()].encode("utf-8")))
                    source_role = next((role for lo, col, hi, end_col, role in regions
                                        if role != "formatted_value"
                                        and (lo, col) <= start and end <= (hi, end_col)), None)
                    yield (
                        _classify_match(name, lineno, rule, m.group(0), line, source_role),
                        m.group(0),
                    )


def scan_secrets(fileobj: BinaryIO, *, coverage: dict | None = None) -> list[SecretFinding]:
    return [finding for finding, _ in iter_secret_matches(fileobj, coverage=coverage)]
