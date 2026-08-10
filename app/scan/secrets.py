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

import json
import re
import stat
import zipfile
from dataclasses import dataclass
from typing import BinaryIO, Iterator

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
_DOC_SUFFIXES = (".md", ".mdx")
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
_TEST_PATH_SEGMENTS = frozenset(("__tests__", "__mocks__", "test", "tests"))
_TEST_SETUP_FILENAMES = frozenset(("jest.setup.ts", "jest.setup.js"))
_TEST_FILE_SUFFIXES = (".test.ts", ".test.js", ".spec.ts", ".spec.js")
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


def _is_comment_line(line_text: str) -> bool:
    """True when the match sits on a line that is entirely a comment.

    Prefix check only, and deliberately so: correctly deciding whether an
    offset is inside a comment needs a parser per language, and a wrong answer
    here silently hides a real secret. A line that STARTS as a comment is the
    case this is for -- code with a trailing `// key = "..."` is not damped.
    """
    return line_text.lstrip().startswith(_COMMENT_PREFIXES)


def _is_doc_context(name: str) -> bool:
    if name.lower().endswith(_DOC_SUFFIXES):
        return True
    return any(seg.lower() in _DOC_SEGMENTS for seg in name.split("/")[:-1])


# Contexts that mean "this file is not what the app runs in production".
# Kept next to the predicates that produce them so the two cannot drift.
NON_PRODUCTION_CONTEXTS = frozenset(("test_fixture", "test_file", "comment",
                                     "doc_example"))


def is_non_production_path(name: str) -> bool:
    """True for test, example and documentation files.

    Public because the report groups findings by it, and findings that did not
    come from this scanner (the LLM pass) carry no `context` field to group on
    — only a path. Migration paths are excluded: a migration is applied state,
    which is as production as it gets.
    """
    if _is_migration_context(name):
        return False
    return _is_test_fixture_path(name) or _is_doc_context(name)


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
        # interpolated value (postgres://u:${DB_PASSWORD}@h, ...:%s@...,
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
            r"(?i)\b[a-z][a-z0-9+.-]{1,15}://"      # scheme
            r"[^:/?#@\s\"']{1,64}"                  # user
            r":[^@/?#\s\"'${}<>%]{3,128}"           # password, no interpolation
            r"@[A-Za-z0-9._-]{1,253}"               # host
            # Port and path are part of the match on purpose, so the span IS
            # the whole connection string. The Fix Pack replaces a secret by
            # locating the QUOTED literal around it; a match that stopped at
            # the host left `:5432/app` behind inside the quotes and rewrote
            # DB = "postgres://u:pw@h:5432/app" into
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
        "sql-secret-assignment", "Hardcoded secret in SQL/PLpgSQL assignment",
        re.compile(
            r"(?i)\b\w*(?:secret|password|api[_-]?key|service[_-]?role)\w*\s+"
            r"(?:text|varchar(?:\(\d+\))?|character varying)\s*:?=\s*'[^']{8,}'"
        ),
        "high", 0.7,
    ),
    SecretRule(
        "generic-assignment", "Hardcoded credential assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|secret|password|service[_-]?role)\b"
            r"\s*[:=]\s*['\"][^'\"\s]{12,}['\"]"
        ),
        "high", 0.5,
    ),
)


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


def _mask(value: str) -> str:
    return f"{value[:4]}****({len(value)} chars)"


def _iter_text_files(zf: zipfile.ZipFile) -> Iterator[tuple[str, str]]:
    for info in zf.infolist():
        name = info.filename
        if info.is_dir() or info.file_size > MAX_SCANNED_FILE_BYTES:
            continue
        if stat.S_ISLNK(info.external_attr >> 16):
            continue
        if any(part in name for part in _SKIP_DIRS):
            continue
        if name.lower().endswith(_SKIP_SUFFIXES):
            continue
        data = zf.read(info)
        if b"\x00" in data[:4096]:  # binary sniff
            continue
        yield name, data.decode("utf-8", errors="ignore")


def _jwt_severity(token: str) -> tuple[str, float, str]:
    """Supabase keys are JWTs with a `role` claim: anon is public by
    design (every Lovable app ships it client-side), service_role is a
    full RLS bypass. Decode the payload to tell them apart."""
    import base64
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
    `postgres://postgres:postgres@db` is a docker-compose convention, and
    filing it under the same id as a live production credential would make
    the report collapse the two together and offer to rewrite the first.
    """
    m = _DSN_SPLIT_RE.search(matched)
    if m is None:
        return False
    pw = m.group("password").lower().replace("_", "").replace("-", "")
    return pw in _DSN_DEV_PASSWORDS


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
                    matched: str, line_text: str = "") -> SecretFinding:
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
    # A tutorial-default connection password gets its own id for the same
    # reason the anon key does: the report must not collapse it together
    # with a live credential, and the Fix Pack must not offer to rewrite a
    # docker-compose default into an environment variable.
    is_dev_dsn = (rule.id == "connection-string-password"
                  and dsn_password_is_conventional(matched))
    if is_anon:
        effective_rule_id = "supabase-anon-key"
    elif is_dev_dsn:
        effective_rule_id = "connection-string-dev-password"
    else:
        effective_rule_id = rule.id
    # Order matters. Migration escalation wins outright -- it is the one
    # context calibrated on confirmed real leaks. Everything below it damps,
    # strongest signal first: a self-labelled placeholder on a test path is
    # two signals, a test path is one, a comment or doc path is one.
    context: str | None = None
    if _is_migration_context(name) and not is_anon and not is_dev_dsn:
        confidence = max(confidence, _MIGRATION_MIN_CONFIDENCE)
        title = f"{title} (committed database migration)"
    elif is_anon or is_dev_dsn:
        pass
    elif _is_test_fixture_path(name) and value_has_placeholder_marker(matched):
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
    elif _is_doc_context(name):
        severity = _DOC_SEVERITY_CAP.get(severity, severity)
        confidence = round(confidence * _DOC_CONFIDENCE_FACTOR, 2)
        title = f"{title} (documentation/example context)"
        context = "doc_example"
    return SecretFinding(
        rule_id=effective_rule_id,
        title=title,
        severity=severity,
        confidence=confidence,
        file=name,
        line=lineno,
        masked=_mask(matched),
        context=context,
    )


def iter_secret_matches(fileobj: BinaryIO) -> Iterator[tuple[SecretFinding, str]]:
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
    with zipfile.ZipFile(fileobj) as zf:
        for name, text in _iter_text_files(zf):
            for lineno, line in enumerate(text.splitlines(), start=1):
                for rule in RULES:
                    m = rule.pattern.search(line)
                    if not m:
                        continue
                    yield (
                        _classify_match(name, lineno, rule, m.group(0), line),
                        m.group(0),
                    )


def scan_secrets(fileobj: BinaryIO) -> list[SecretFinding]:
    return [finding for finding, _ in iter_secret_matches(fileobj)]
