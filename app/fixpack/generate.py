"""Fix Pack generation: turn an audit's findings into a safe changeset.

Given the fresh bytes of the audited repo and the findings the audit
persisted, produce a `FixpackPlan` — the files to write, the paths to
untrack, and human-readable descriptions of what was fixed — that a
caller hands to app/deploypack/delivery.open_pull_request.

THE ONE RULE THAT MATTERS: a real secret value must NEVER appear in the
plan's output (file contents, PR title, PR body) — only in the ORIGINAL
file it is being edited OUT of. The raw value is read via
app.scan.secrets.iter_secret_matches, used to locate-and-replace, and
then a post-check (`_verify_scrubbed`) refuses to emit any file that
still contains a secret we were supposed to remove. Nothing here ever
stores the value anywhere else.

Eligible finding types (the exact rule_ids are read from the scanners,
not hardcoded strings — see SECRET_RULE_IDS):
  1. Hardcoded secrets — the secrets.py rules, EXCLUDING supabase-anon-key
     (public by design) and any llm-* rule (too unstructured to auto-fix).
  2. env-file-committed (checks.py) — untrack the committed .env.
  3. gitignore-missing-secrets (checks.py) — add secret-file patterns.
Any finding with context == "test_fixture" is excluded regardless of type.
Any finding whose file lives under a test directory (tests/, test/,
__tests__/, spec/ anywhere in the path) is also excluded regardless of
context -- test files intentionally hold literal secret patterns as
detector fixtures, and rewriting that code is unsafe (see _is_test_path).
"""

from __future__ import annotations

import ast
import io
import json
import logging
import re
import zipfile
from dataclasses import dataclass, field

from app.scan.checks import find_committed_env_files, gitignore_covers_env
from app.scan.secrets import (
    NON_PRODUCTION_CONTEXTS,
    RULES,
    iter_secret_matches,
)

logger = logging.getLogger(__name__)

# The secret rule_ids we will auto-fix: every rule secrets.py defines,
# minus the ones that are unsafe/pointless to rewrite. Derived from RULES
# (not a copied list) so a new rule is opted-in by default and this can't
# silently drift from the scanner. supabase-anon-key is a *derived*
# rule_id (never in RULES) for a value that's public by design; excluding
# it here is belt-and-suspenders. llm-* findings never reach RULES either.
_EXCLUDED_SECRET_RULE_IDS = frozenset({"supabase-anon-key"})
SECRET_RULE_IDS = frozenset(r.id for r in RULES) - _EXCLUDED_SECRET_RULE_IDS

_CHECK_RULE_IDS = frozenset({"env-file-committed", "gitignore-missing-secrets"})

# rule_id -> the environment variable name we substitute the literal with.
# Small, explicit, and deliberately not clever: a sensible conventional
# name per provider, not an exhaustive taxonomy.
ENV_VAR_BY_RULE = {
    "aws-access-key-id": "AWS_ACCESS_KEY_ID",
    "github-pat": "GITHUB_TOKEN",
    "stripe-live-key": "STRIPE_SECRET_KEY",
    "anthropic-api-key": "ANTHROPIC_API_KEY",
    "telegram-bot-token": "TELEGRAM_BOT_TOKEN",
    "private-key-block": "PRIVATE_KEY",
    "jwt-in-code": "JWT_SECRET",
    "sql-secret-assignment": "DATABASE_SECRET",
    "generic-assignment": "APP_SECRET",
}

# rule_id -> where the owner must go to rotate the now-compromised secret.
# Removing a secret from code does NOT invalidate it, so every secret fix
# carries one of these into the PR body as an explicit call to action.
ROTATE_GUIDANCE = {
    "aws-access-key-id": "AWS (IAM console — deactivate the key, create a new one)",
    "github-pat": "GitHub (Settings → Developer settings → Personal access tokens → revoke)",
    "stripe-live-key": "Stripe (Dashboard → Developers → API keys → roll the key)",
    "anthropic-api-key": "Anthropic (Console → API keys → revoke and reissue)",
    "telegram-bot-token": "Telegram (@BotFather → /revoke)",
    "private-key-block": "the key's issuer (generate a fresh key pair, replace the old)",
    "jwt-in-code": "your auth/JWT provider (rotate the signing secret)",
    "sql-secret-assignment": "your database/secret provider (change the credential)",
    "generic-assignment": "the relevant provider (rotate the credential)",
}

_JS_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
# Checked BEFORE _JS_SUFFIXES, which also contains them: TypeScript needs a
# narrowed reference where plain JavaScript does not. See _env_reference.
_TS_SUFFIXES = (".ts", ".tsx")

# Full secret-file pattern set for the gitignore-missing-secrets fix,
# mirroring what the scan rule and env-file detection care about (.env and
# .env.<x> except .env.example, plus key material). "!.env.example" keeps
# the safe template committed.
_GITIGNORE_SECRET_PATTERNS = (".env", ".env.*", "!.env.example", "*.pem", "*.key")

_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
# Inner quoted literal of an assignment-style match (generic/sql rules
# match the whole `name = "value"` span; we only want the value).
_QUOTED_LITERAL_RE = re.compile(r"['\"`]([^'\"`\s]+)['\"`]")


@dataclass
class SecretFix:
    rule_id: str
    title: str
    file: str          # repo-relative path
    env_var: str
    rotate_where: str


@dataclass
class ConfigFix:
    rule_id: str
    title: str
    detail: str


@dataclass
class SkippedFinding:
    rule_id: str
    file: str
    line: int
    reason: str


@dataclass
class FixpackPlan:
    files: dict[str, str] = field(default_factory=dict)
    deletions: list[str] = field(default_factory=list)
    secret_fixes: list[SecretFix] = field(default_factory=list)
    config_fixes: list[ConfigFix] = field(default_factory=list)
    skipped: list[SkippedFinding] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.files or self.deletions)


def _repo_relative(name: str) -> str:
    """Drop the single wrapper folder GitHub zipballs (and Lovable/Bolt
    exports) put everything under, so paths match the repo's own layout.
    The audit was fetched the same way, so its stored finding paths carry
    the same style of wrapper — stripping the first segment on both sides
    is what lets a stored finding line up with a fresh re-scan."""
    return name.split("/", 1)[1] if "/" in name else name


_TEST_DIR_SEGMENTS = frozenset(("tests", "test", "__tests__", "spec"))


def _is_test_path(path: str) -> bool:
    """True if any directory segment of `path` is a conventional test dir.

    Applied to the raw finding path (not the repo-relative one, whose first
    segment gets stripped): matches "tests/x.py", "wrapper/tests/x.py" and
    "src/__tests__/foo.ts" alike. Fix Pack never rewrites files here --
    test files deliberately embed literal secret *patterns* as detector
    fixtures, and mechanically editing that code is unsafe for any client,
    not just this repo. Broader than the context="test_fixture" marker,
    which only fires when the value self-labels as a placeholder."""
    segments = path.lower().split("/")[:-1]
    return any(seg in _TEST_DIR_SEGMENTS for seg in segments)


def _env_key_names(body: str) -> set[str]:
    """Variable names declared in a dotenv-style body, values discarded.

    Names only, never values: this feeds `.env.example`, which ships in the
    PR, and the bodies it reads are the customer's real secrets."""
    names: set[str] = set()
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name = line.split("=", 1)[0].strip()
        if name.startswith("export "):
            name = name[len("export "):].strip()
        if name:
            names.add(name)
    return names


def _env_reference(path: str, env_var: str) -> str:
    """The idiomatic way to read an env var in this file's language."""
    lower = path.lower()
    if lower.endswith(_TS_SUFFIXES):
        # `process.env.X` is typed `string | undefined`, which does not
        # satisfy a `string` parameter under `strict` — and `strict` is the
        # create-next-app default, so a bare reference makes the PR we sell
        # fail to compile for most of the market (TS2345). The non-null
        # assertion keeps the "this must be set" contract, is the idiomatic
        # form in this ecosystem, and surfaces a missing variable at first
        # use rather than substituting a plausible-looking empty secret.
        return f"process.env.{env_var}!"
    if lower.endswith(_JS_SUFFIXES):
        return f"process.env.{env_var}"
    if lower.endswith(".py"):
        return f'os.environ["{env_var}"]'
    # Unknown language: a shell/interpolation-style reference removes the
    # secret and clearly signals "an env var goes here" without pretending
    # to know the syntax.
    return f"${{{env_var}}}"


def _sensitive_literals(rule_id: str, raw_match: str) -> list[str]:
    """The actual secret substring(s) to scrub for one match.

    Private keys are multi-line: the rule only matches the BEGIN line, but
    leaving the key body behind would keep the leak, so we return the whole
    block (located by _apply_secret_fix against the file text). For
    assignment-style rules the match is `name = "value"`; we want just the
    quoted value. For token rules the match IS the token.
    """
    if rule_id == "private-key-block":
        return []  # handled specially against the full file text
    m = _QUOTED_LITERAL_RE.search(raw_match)
    if m:
        return [m.group(1)]
    return [raw_match]


def _apply_secret_fix(text: str, rule_id: str, raw_match: str,
                      env_ref: str) -> tuple[str, list[str]]:
    """Replace a secret in `text` with `env_ref`. Returns the new text and
    the list of sensitive strings that must no longer appear (for the
    post-check). Prefers replacing the quoted literal so the result stays
    valid code (`key = "SECRET"` -> `key = process.env.NAME`), falling back
    to a bare replacement."""
    if rule_id == "private-key-block":
        blocks = _PEM_BLOCK_RE.findall(text)
        new_text = _PEM_BLOCK_RE.sub(env_ref, text)
        return new_text, blocks

    sensitive = _sensitive_literals(rule_id, raw_match)
    new_text = text
    for secret in sensitive:
        replaced = False
        for q in ('"', "'", "`"):
            wrapped = f"{q}{secret}{q}"
            if wrapped in new_text:
                new_text = new_text.replace(wrapped, env_ref)
                replaced = True
        if not replaced and secret in new_text:
            new_text = new_text.replace(secret, env_ref)
    return new_text, sensitive


def _verify_scrubbed(text: str, sensitive: list[str]) -> bool:
    """No secret we were meant to remove may survive into the emitted file
    — this is the last line of defence behind the never-leak rule."""
    return all(secret not in text for secret in sensitive)


def _brackets_balanced(text: str) -> bool:
    """True if (), [], {} are properly nested. A cheap, language-agnostic
    heuristic (it ignores quotes/comments, so it is only ever used as a
    *relative* before/after check, never as absolute truth)."""
    pairs = {")": "(", "]": "[", "}": "{"}
    openers = set(pairs.values())
    stack: list[str] = []
    for ch in text:
        if ch in openers:
            stack.append(ch)
        elif ch in pairs:
            if not stack or stack.pop() != pairs[ch]:
                return False
    return not stack


def _validate_syntax(path: str, original: str, new: str) -> bool:
    """Best-effort guard that our edit left the file syntactically valid.

    This is the ROOT-CAUSE safety net, independent of the test-path
    exclusion: a value-span replacement can land *inside* a larger string
    literal (a PEM block, an f-string, a concatenation, a JSON value),
    leaving the surrounding quotes and injecting an env reference that
    itself contains quotes — a SyntaxError. We refuse to ship such a file.

    Authoritative for the languages the standard library can parse:
      * .py            -> ast.parse
      * .json / .jsonc -> json.loads

    For every other language there is NO zero-dependency parser available,
    and we deliberately do not invent one. We fall back to a conservative
    delimiter check: reject only when our edit turned a bracket-balanced
    file into an unbalanced one. Anything we cannot judge, we accept — the
    never-leak post-check (`_verify_scrubbed`) has already run, so the worst
    case for an unparseable-language file is a semantically-odd but
    non-secret-leaking edit, not a broken secret removal.
    """
    lower = path.lower()
    if lower.endswith(".py"):
        try:
            ast.parse(new)
            return True
        except (SyntaxError, ValueError):
            return False
    if lower.endswith((".json", ".jsonc")):
        try:
            json.loads(new)
            return True
        except (json.JSONDecodeError, ValueError):
            return False
    # Unknown language: only fail if we demonstrably broke bracket balance.
    return _brackets_balanced(new) or not _brackets_balanced(original)


def _append_missing(body: str, patterns: tuple[str, ...] | list[str]) -> str:
    """Append any of `patterns` not already present (line-exact) to a
    file body, keeping the existing content untouched."""
    existing = {line.strip() for line in body.splitlines()}
    to_add = [p for p in patterns if p not in existing]
    if not to_add:
        return body
    out = body
    if out and not out.endswith("\n"):
        out += "\n"
    return out + "\n".join(to_add) + "\n"


def _read_zip(zip_bytes: bytes) -> tuple[list[str], dict[str, str]]:
    """Return (raw entry names, {entry name: text}) for text-ish files,
    reading each once. Binary/oversized files are skipped for content but
    still listed."""
    raw_names: list[str] = []
    contents: dict[str, str] = {}
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for info in zf.infolist():
            raw_names.append(info.filename)
            if info.is_dir():
                continue
            data = zf.read(info)
            if b"\x00" in data[:4096]:
                continue
            contents[info.filename] = data.decode("utf-8", errors="ignore")
    return raw_names, contents


def _find_entry(raw_names: list[str], repo_rel: str) -> str | None:
    """The raw zip entry whose repo-relative path is `repo_rel`."""
    for n in raw_names:
        if _repo_relative(n) == repo_rel:
            return n
    return None


def _is_fixable_rule(finding: dict) -> bool:
    """Is this finding's rule one the Fix Pack knows how to rewrite at all?

    Most rules are advice -- "no tests", "no Dockerfile" -- and no amount of
    code generation turns them into a pull request.
    """
    return finding.get("rule_id") in (SECRET_RULE_IDS | _CHECK_RULE_IDS)


def _is_production_code(finding: dict) -> bool:
    """Is it somewhere worth rewriting? See the note in build_fixpack_plan:
    editing a comment, a doc example or a test fixture buys no security."""
    return (
        finding.get("context") not in NON_PRODUCTION_CONTEXTS
        and not _is_test_path(finding.get("file", ""))
    )


def has_auto_fixable_findings(findings: list[dict]) -> bool:
    """Could a Fix Pack for these findings produce anything at all?

    Answers one question reliably -- "there is definitely nothing to fix" --
    and does NOT promise the opposite. A finding eligible here can still fall
    away when the repository is re-fetched, because the code may have moved on
    since the audit ran. So this is a filter against selling a Fix Pack that
    was empty before the customer paid, not a guarantee of a pull request.

    That case is not hypothetical. Audit 05fa18f5 was sold a Fix Pack with
    zero eligible findings: the job ran, found nothing, and the payer got
    "Nothing to auto-fix" for their money. It was computable in advance from
    the stored findings, with no network and no LLM.

    Shares _is_fixable_rule and _is_production_code with build_fixpack_plan on
    purpose. A second copy of "what counts as fixable" is exactly what drifted
    in #132, where the plan builder knew one non-production context and the
    report knew four.
    """
    return any(
        _is_fixable_rule(f) and _is_production_code(f) for f in findings
    )


def build_fixpack_plan(zip_bytes: bytes, findings: list[dict]) -> FixpackPlan:
    """Build the changeset for a Fix Pack from fresh repo bytes and the
    audit's persisted findings. Never opens a PR and never touches the
    network — pure transform, so it's trivially testable and the delivery
    side stays separate."""
    plan = FixpackPlan()

    # NON_PRODUCTION_CONTEXTS, not a single literal. The scanner already
    # classifies a match as test_fixture, test_file, comment or doc_example,
    # and #125 taught the REPORT to damp all four -- but this filter only knew
    # the first, so the Fix Pack kept editing the other three.
    #
    # It shipped a PR that rewrote an illustrative string inside a comment
    # documenting one of our own scanner rules, added a bogus variable to
    # .env.example, and told the customer to rotate a credential that never
    # existed.
    #
    # Editing a secret out of a comment buys no security whatsoever: the value
    # is in git history either way and must be rotated regardless, and a
    # comment executes nothing, so there is no running code to disarm. The
    # entire value of a code fix is absent, and only the damage remains.
    #
    # They stay in the report -- damped, as #125 left them. Noticing something
    # and declining to rewrite it automatically is not the same as hiding it.
    eligible = []
    for f in findings:
        if not _is_fixable_rule(f):
            continue
        context = f.get("context")
        if not _is_production_code(f):
            # Recorded rather than dropped silently, so the PR body can show
            # that the finding was seen and deliberately left alone.
            plan.skipped.append(SkippedFinding(
                rule_id=f.get("rule_id", ""),
                file=_repo_relative(f.get("file", "")),
                line=f.get("line", 0),
                reason=(
                    f"{context or 'test path'} — not executable code, so "
                    "editing it would change nothing an attacker can use; "
                    "reported instead of rewritten"
                ),
            ))
            continue
        eligible.append(f)

    if not eligible:
        return plan

    raw_names, contents = _read_zip(zip_bytes)

    # --- Secret findings: relocate each against a fresh re-scan to get the
    # real value, then scrub it out of the file. ------------------------
    fresh_index: dict[tuple[str, str, int], tuple[str, str]] = {}
    for finding, raw_value in iter_secret_matches(io.BytesIO(zip_bytes)):
        key = (finding.rule_id, _repo_relative(finding.file), finding.line)
        fresh_index.setdefault(key, (finding.file, raw_value))

    # Group the wanted secret fixes by repo-relative file so overlapping
    # findings on one file are applied together in a single edit.
    per_file: dict[str, list[tuple[dict, str, str]]] = {}
    for f in eligible:
        if f.get("rule_id") not in SECRET_RULE_IDS:
            continue
        repo_rel = _repo_relative(f.get("file", ""))
        key = (f["rule_id"], repo_rel, f.get("line", 0))
        match = fresh_index.get(key)
        if match is None:
            plan.skipped.append(SkippedFinding(
                rule_id=f["rule_id"], file=repo_rel, line=f.get("line", 0),
                reason="finding no longer matches on re-fetch (repo changed)",
            ))
            continue
        raw_entry, raw_value = match
        per_file.setdefault(repo_rel, []).append((f, raw_entry, raw_value))

    env_vars_used: set[str] = set()
    for repo_rel, items in per_file.items():
        raw_entry = items[0][1]
        text = contents.get(raw_entry)
        if text is None:
            for f, _, _ in items:
                plan.skipped.append(SkippedFinding(
                    rule_id=f["rule_id"], file=repo_rel, line=f.get("line", 0),
                    reason="file not readable on re-fetch",
                ))
            continue

        new_text = text
        all_sensitive: list[str] = []
        applied: list[tuple[dict, str]] = []
        for f, _, raw_value in items:
            env_var = ENV_VAR_BY_RULE.get(f["rule_id"], "APP_SECRET")
            env_ref = _env_reference(repo_rel, env_var)
            new_text, sensitive = _apply_secret_fix(
                new_text, f["rule_id"], raw_value, env_ref
            )
            all_sensitive.extend(sensitive)
            applied.append((f, env_var))

        # Safety gate: if ANY secret survived, drop the whole file rather
        # than ship a PR that still leaks it. Mark every fix on it skipped.
        if not _verify_scrubbed(new_text, all_sensitive):
            for f, _ in applied:
                plan.skipped.append(SkippedFinding(
                    rule_id=f["rule_id"], file=repo_rel, line=f.get("line", 0),
                    reason="could not safely remove the value; file left unchanged",
                ))
            continue

        # Root-cause safety net: never ship a file our edit made
        # unparseable. A value-span replacement can corrupt the surrounding
        # literal (PEM/f-string/JSON value); drop the file instead of
        # emitting a PR that breaks the client's code.
        if not _validate_syntax(repo_rel, text, new_text):
            for f, _ in applied:
                plan.skipped.append(SkippedFinding(
                    rule_id=f["rule_id"], file=repo_rel, line=f.get("line", 0),
                    reason="edit produced invalid syntax; file excluded from Fix Pack",
                ))
            logger.warning(
                "fixpack: syntax validation failed for %s after applying "
                "%d fix(es); excluding file from Fix Pack",
                repo_rel, len(applied),
            )
            continue

        plan.files[repo_rel] = new_text
        for f, env_var in applied:
            env_vars_used.add(env_var)
            plan.secret_fixes.append(SecretFix(
                rule_id=f["rule_id"],
                title=f.get("title", f["rule_id"]),
                file=repo_rel,
                env_var=env_var,
                rotate_where=ROTATE_GUIDANCE.get(f["rule_id"], "the relevant provider"),
            ))

    # --- Config findings: env-file-committed + gitignore-missing-secrets.
    check_rule_ids = {f["rule_id"] for f in eligible
                      if f.get("rule_id") in _CHECK_RULE_IDS}

    names = [_repo_relative(n) for n in raw_names]
    files_list = [n for n in names if n and not n.endswith("/")]
    gitignore_entry = _find_entry(raw_names, ".gitignore")
    gitignore_body = contents.get(gitignore_entry, "") if gitignore_entry else ""

    required_gitignore: list[str] = []
    # Names declared in the env files we are about to untrack. Recorded so
    # they survive in `.env.example`: untracking removes the file from the
    # customer's working copy on pull, and a key that lived only there would
    # otherwise vanish with no record that the app ever needed it.
    untracked_env_names: set[str] = set()

    if "env-file-committed" in check_rule_ids:
        committed = find_committed_env_files(files_list)
        if committed:
            plan.deletions.extend(committed)
            for env_path in committed:
                entry = _find_entry(raw_names, env_path)
                if entry:
                    untracked_env_names |= _env_key_names(contents.get(entry, ""))
            # A committed .env re-appears on the next `git add` without an
            # ignore rule, so untracking without this is a half-fix.
            for p in (".env",):
                if p not in required_gitignore:
                    required_gitignore.append(p)
            plan.config_fixes.append(ConfigFix(
                rule_id="env-file-committed",
                title="Environment file committed to repository",
                detail="Untracked "
                       + ", ".join(f"`{c}`" for c in committed)
                       + " and added it to `.gitignore`. **Copy the current "
                         "values somewhere safe before you merge** — removing "
                         "the file from version control also removes it from "
                         "your working copy when you pull this merge. The "
                         "values remain in your git history, which is why "
                         "they must be rotated at their providers.",
            ))
        else:
            plan.skipped.append(SkippedFinding(
                rule_id="env-file-committed", file="", line=0,
                reason="no committed env file present on re-fetch",
            ))

    if "gitignore-missing-secrets" in check_rule_ids:
        if not gitignore_covers_env(gitignore_body):
            for p in _GITIGNORE_SECRET_PATTERNS:
                if p not in required_gitignore:
                    required_gitignore.append(p)
            plan.config_fixes.append(ConfigFix(
                rule_id="gitignore-missing-secrets",
                title="No .gitignore coverage for secret-bearing files",
                detail="Added secret-file patterns ("
                       + ", ".join(f"`{p}`" for p in _GITIGNORE_SECRET_PATTERNS)
                       + ") to `.gitignore`.",
            ))
        else:
            plan.skipped.append(SkippedFinding(
                rule_id="gitignore-missing-secrets", file=".gitignore", line=0,
                reason=".gitignore already covers .env on re-fetch",
            ))

    if required_gitignore:
        new_gitignore = _append_missing(gitignore_body, required_gitignore)
        if new_gitignore != gitignore_body:
            plan.files[".gitignore"] = new_gitignore

    # A path we're untracking must never also be emitted as a file. This
    # collides for the exact real case of a committed `.env` that ALSO holds
    # a hardcoded secret: the secret pass scrubs it into plan.files[".env"]
    # while env-file-committed puts ".env" in plan.deletions — a
    # self-contradictory changeset (commit a modified `.env` and untrack it
    # in the same tree). Untracking wins: the file is leaving version
    # control, so a scrubbed copy is pointless and would produce two tree
    # entries for one path in the PR.
    for path in plan.deletions:
        plan.files.pop(path, None)

    # --- .env.example: record every substituted var and every key from an
    # env file we untracked (placeholder values only, never the real ones). --
    wanted_env_names = set(env_vars_used) | untracked_env_names
    if wanted_env_names:
        example_entry = _find_entry(raw_names, ".env.example")
        example_body = contents.get(example_entry, "") if example_entry else ""
        existing_names = _env_key_names(example_body)
        additions = [f"{name}=changeme" for name in sorted(wanted_env_names)
                     if name not in existing_names]
        if additions:
            new_example = _append_missing(example_body, additions)
            plan.files[".env.example"] = new_example

    return plan


def _plural(n: int, singular: str, plural: str | None = None) -> str:
    return singular if n == 1 else (plural or singular + "s")


def render_pr_title(plan: FixpackPlan) -> str:
    n_sec = len(plan.secret_fixes)
    has_cfg = bool(plan.config_fixes)
    if n_sec and has_cfg:
        return (f"Drydock Fix Pack: remove {n_sec} hardcoded "
                f"{_plural(n_sec, 'secret')} and secure repo config")
    if n_sec:
        return f"Drydock Fix Pack: remove {n_sec} hardcoded {_plural(n_sec, 'secret')}"
    return "Drydock Fix Pack: secure repository configuration"


def render_pr_body(plan: FixpackPlan) -> str:
    """PR description. Contains finding titles, files, and rotation
    guidance — NEVER a secret value (the plan never carries one)."""
    parts: list[str] = ["## Drydock Fix Pack\n"]
    parts.append(
        "This PR was generated automatically from your audit. It removes "
        "hardcoded secrets and/or hardens your repository configuration. "
        "Nothing is merged until you press merge.\n"
    )

    if plan.secret_fixes:
        parts.append(
            "> ## ⚠️ ROTATE THESE SECRETS NOW\n"
            "> Removing a secret from the code does **NOT** make it safe. "
            "Every value below has already been committed to your git "
            "history and must be treated as **compromised**. Deleting it "
            "here does not invalidate it — you MUST rotate/revoke each one "
            "at its provider, or an attacker who already has it keeps full "
            "access:\n>"
        )
        # De-dup provider guidance so the same provider isn't listed twice.
        seen: set[str] = set()
        for fix in plan.secret_fixes:
            if fix.rotate_where in seen:
                continue
            seen.add(fix.rotate_where)
            parts.append(f"> - **Rotate at {fix.rotate_where}**")
        parts.append("")

        parts.append("### Secrets removed from code\n")
        for fix in plan.secret_fixes:
            parts.append(
                f"- **{fix.title}** in `{fix.file}` — replaced with a "
                f"reference to the `{fix.env_var}` environment variable."
            )
        parts.append(
            "\nThe substituted variables were added to `.env.example` with a "
            "`changeme` placeholder. Set the **new, rotated** values in your "
            "real environment (never commit them).\n"
        )

    if plan.config_fixes:
        parts.append("### Configuration hardening\n")
        for cfg in plan.config_fixes:
            parts.append(f"- **{cfg.title}** — {cfg.detail}")
        parts.append("")

    if plan.skipped:
        parts.append("### Skipped\n")
        for s in plan.skipped:
            where = f" (`{s.file}`" + (f":{s.line}" if s.line else "") + ")" if s.file else ""
            parts.append(f"- `{s.rule_id}`{where}: {s.reason}")
        parts.append("")

    parts.append(
        "---\nMerge is entirely up to you. Review the diff, rotate any "
        "secrets listed above, then merge when you're ready."
    )
    return "\n".join(parts)
