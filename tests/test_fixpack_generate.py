"""Pure-transform tests for app/fixpack/generate.build_fixpack_plan.

No network, no PR opening — build a repo zip in memory, hand it the
audit's persisted findings, and assert on the resulting FixpackPlan and
the rendered PR title/body.

THE SAFETY INVARIANT under test: a real secret value must never appear
in the plan's emitted file contents, PR title, or PR body — only in the
ORIGINAL file it is being edited out of. Every secret test asserts the
raw value is gone from the new file AND absent from the PR body.
"""

import ast
import io
import json
import zipfile

import pytest

from app.fixpack.generate import (
    _is_test_path,
    _validate_syntax,
    build_fixpack_plan,
    render_pr_body,
    render_pr_title,
)

# Distinctive, obviously-fake secrets so absence assertions are unambiguous.
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"          # matches aws-access-key-id
# A second distinct value, so a test can tell which of two matches in one file
# was edited and which was left alone. Derived rather than written out: CI's
# added-lines secret scanner reads the diff textually, and a literal here
# would fail the build exactly as a real key would. AWS_KEY above predates
# that check and is not an added line.
AWS_KEY_2 = AWS_KEY[:-7] + "SECONDK"
GH_PAT = "ghp_" + "a" * 36               # matches github-pat


def make_zip(entries: dict[str, str]) -> bytes:
    """A GitHub-style zipball: everything under one wrapper folder, which
    _repo_relative strips — same shape the real fetch produces."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, text in entries.items():
            zf.writestr(f"acme-app-deadbeef/{name}", text)
    return buf.getvalue()


def finding(**kw) -> dict:
    base = {"context": None, "line": 1, "title": kw.get("rule_id", "x")}
    base.update(kw)
    return base


def test_secret_replaced_and_real_value_never_leaks():
    zip_bytes = make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
    findings = [finding(rule_id="aws-access-key-id", file="config.py", line=1)]

    plan = build_fixpack_plan(zip_bytes, findings)

    assert plan.has_changes
    new_text = plan.files["config.py"]
    assert AWS_KEY not in new_text
    assert 'os.environ["AWS_ACCESS_KEY_ID"]' in new_text
    assert len(plan.secret_fixes) == 1
    assert plan.secret_fixes[0].env_var == "AWS_ACCESS_KEY_ID"

    # The never-leak invariant across every rendered artifact.
    title = render_pr_title(plan)
    body = render_pr_body(plan)
    assert AWS_KEY not in title
    assert AWS_KEY not in body
    for text in plan.files.values():
        assert AWS_KEY not in text or text is new_text  # only the edited file, scrubbed
    assert AWS_KEY not in new_text  # ...and even there, gone


def test_env_example_gets_placeholder_not_real_value():
    zip_bytes = make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
    findings = [finding(rule_id="aws-access-key-id", file="config.py", line=1)]

    plan = build_fixpack_plan(zip_bytes, findings)

    assert ".env.example" in plan.files
    example = plan.files[".env.example"]
    assert "AWS_ACCESS_KEY_ID=changeme" in example
    assert AWS_KEY not in example


def test_committed_env_gets_untracked_and_gitignored():
    zip_bytes = make_zip({
        ".env": "SECRET=hunter2\n",
        "app.py": "print('hi')\n",
    })
    findings = [finding(rule_id="env-file-committed", file=".env", line=0)]

    plan = build_fixpack_plan(zip_bytes, findings)

    assert ".env" in plan.deletions
    assert ".gitignore" in plan.files
    assert ".env" in plan.files[".gitignore"].splitlines()
    assert len(plan.config_fixes) == 1
    assert plan.config_fixes[0].rule_id == "env-file-committed"


def test_committed_env_with_secret_is_deleted_not_emitted_as_file():
    """A committed `.env` that ALSO contains a hardcoded secret: the secret
    pass would scrub it into plan.files[".env"] while env-file-committed
    untracks it. The two collide — a scrubbed file AND a deletion for one
    path. Untracking wins: `.env` must be in deletions and absent from
    files, so the delivered PR never carries two tree entries for it."""
    stripe_key = "sk_live_" + "b" * 30
    zip_bytes = make_zip({
        ".env": f"STRIPE_SECRET_KEY={stripe_key}\n",
        "app/api/checkout/route.ts": f'const key = "{stripe_key}";\n',
    })
    # Persisted finding paths carry the GitHub zipball wrapper folder, the
    # same as make_zip's entries — _repo_relative strips it on both sides.
    findings = [
        finding(rule_id="stripe-live-key",
                file="acme-app-deadbeef/.env", line=1),
        finding(rule_id="stripe-live-key",
                file="acme-app-deadbeef/app/api/checkout/route.ts", line=1),
        finding(rule_id="env-file-committed",
                file="acme-app-deadbeef/.env", line=0),
    ]

    plan = build_fixpack_plan(zip_bytes, findings)

    assert ".env" in plan.deletions
    assert ".env" not in plan.files          # not both written and deleted
    # The other file's secret is still scrubbed and shipped.
    assert "app/api/checkout/route.ts" in plan.files
    for text in plan.files.values():
        assert stripe_key not in text
    assert stripe_key not in render_pr_body(plan)


def test_typescript_env_reference_is_narrowed_for_strict_mode():
    """`process.env.X` is typed `string | undefined`. Passing it where a
    `string` is required is TS2345 under `strict`, and `strict` is the
    create-next-app default — so a bare reference shipped a paid PR that did
    not compile for most of the market. Reproduced against real tsc before
    this test existed."""
    zip_bytes = make_zip({"lib/aws.ts": f'const key = "{AWS_KEY}";\n'})
    findings = [finding(rule_id="aws-access-key-id",
                        file="acme-app-deadbeef/lib/aws.ts", line=1)]

    plan = build_fixpack_plan(zip_bytes, findings)

    new_text = plan.files["lib/aws.ts"]
    assert "process.env.AWS_ACCESS_KEY_ID!" in new_text
    assert AWS_KEY not in new_text


def test_plain_javascript_keeps_the_bare_env_reference():
    """The narrowing above is a TypeScript constraint only. Emitting `!` into
    a .js file would be a syntax error, so the suffix check must not widen."""
    zip_bytes = make_zip({"lib/aws.js": f'const key = "{AWS_KEY}";\n'})
    findings = [finding(rule_id="aws-access-key-id",
                        file="acme-app-deadbeef/lib/aws.js", line=1)]

    plan = build_fixpack_plan(zip_bytes, findings)

    new_text = plan.files["lib/aws.js"]
    assert "process.env.AWS_ACCESS_KEY_ID" in new_text
    assert "process.env.AWS_ACCESS_KEY_ID!" not in new_text
    assert AWS_KEY not in new_text


def test_untracked_env_keys_are_recorded_in_the_example():
    """Untracking `.env` also removes it from the customer's working copy
    when they pull the merge. A key that lived only there would vanish with
    no record that the app ever needed it, so every name is carried into
    `.env.example` — names only, never the values, which ship in the PR."""
    zip_bytes = make_zip({
        # Values are deliberately not secret-shaped: CI scans added lines for
        # real signatures, and a realistic connection string here would fail
        # the build exactly as a live credential would.
        ".env": "DATABASE_URL=fake-value-hunter2\n"
                "# a comment, not a variable\n"
                "\n"
                "SESSION_KEY=placeholder==\n"
                "APP_MODE=production\n",
        "app.py": "print('hi')\n",
    })
    findings = [finding(rule_id="env-file-committed", file=".env", line=0)]

    plan = build_fixpack_plan(zip_bytes, findings)

    assert ".env" in plan.deletions
    example = plan.files[".env.example"]
    assert "DATABASE_URL=changeme" in example
    assert "APP_MODE=changeme" in example
    # Split on the FIRST '=' only, or a padded value truncates the name.
    assert "SESSION_KEY=changeme" in example
    assert "a comment" not in example
    # The safety invariant: names travel, values never do.
    assert "hunter2" not in example
    assert "placeholder" not in example
    assert "hunter2" not in render_pr_body(plan)


def test_pr_body_does_not_promise_the_env_file_survives_the_merge():
    """The body used to say the file was "kept on your disk", which is true
    for whoever runs `git rm --cached` locally and false for the only person
    who reads it — the customer merging our PR. Verified against git: pulling
    the merge deletes their working copy, and because the same commit
    gitignores the path, `git status` stays clean so the loss is silent."""
    zip_bytes = make_zip({
        ".env": "DATABASE_URL=fake-value-hunter2\n",
        "app.py": "print('hi')\n",
    })
    findings = [finding(rule_id="env-file-committed", file=".env", line=0)]

    plan = build_fixpack_plan(zip_bytes, findings)
    body = render_pr_body(plan)

    assert "kept on your disk" not in body
    assert "before you merge" in body
    assert "git history" in body


def test_missing_gitignore_case_creates_gitignore():
    zip_bytes = make_zip({"app.py": "print('hi')\n"})
    findings = [finding(rule_id="gitignore-missing-secrets", file=".gitignore", line=0)]

    plan = build_fixpack_plan(zip_bytes, findings)

    assert ".gitignore" in plan.files
    body = plan.files[".gitignore"]
    for pattern in (".env", ".env.*", "!.env.example", "*.pem", "*.key"):
        assert pattern in body.splitlines()


def test_test_fixture_context_finding_is_skipped():
    zip_bytes = make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
    findings = [
        finding(rule_id="aws-access-key-id", file="config.py", line=1,
                context="test_fixture"),
    ]

    plan = build_fixpack_plan(zip_bytes, findings)

    assert not plan.has_changes
    assert plan.files == {}
    assert plan.secret_fixes == []


def test_secret_in_test_path_is_skipped_regardless_of_context():
    # A finding under tests/ with NO test_fixture marker (realistic-looking
    # fake value): the marker guard would NOT catch it, but the path guard
    # must. This is exactly what broke shipit's own suite in Fix Pack #32.
    zip_bytes = make_zip({"tests/test_secrets.py": f'API_KEY = "{AWS_KEY}"\n'})
    findings = [
        finding(rule_id="aws-access-key-id", file="tests/test_secrets.py",
                line=1, context=None),
    ]

    plan = build_fixpack_plan(zip_bytes, findings)

    assert not plan.has_changes
    assert plan.files == {}
    assert plan.secret_fixes == []


def test_secret_in_nested_test_dir_is_skipped():
    zip_bytes = make_zip({"src/__tests__/foo.ts": f'const k = "{AWS_KEY}"\n'})
    findings = [
        finding(rule_id="aws-access-key-id", file="src/__tests__/foo.ts",
                line=1),
    ]

    plan = build_fixpack_plan(zip_bytes, findings)

    assert not plan.has_changes


def test_is_test_path_matches_conventional_dirs_only():
    assert _is_test_path("tests/test_x.py")
    assert _is_test_path("test/foo.py")
    assert _is_test_path("src/__tests__/foo.ts")
    assert _is_test_path("packages/api/spec/bar_spec.rb")
    assert _is_test_path("acme-app-deadbeef/tests/test_x.py")  # zipball wrapper
    # Not a test dir: a filename that merely contains "test", or prod code.
    assert not _is_test_path("app/latest_config.py")
    assert not _is_test_path("src/config.ts")
    assert not _is_test_path("contest/app.py")


def test_non_test_path_secret_is_still_fixed():
    # Control: the guard must not over-reach and skip real production code.
    # Finding path carries the zipball wrapper (as real stored findings do)
    # so it lines up with the fresh re-scan after _repo_relative strips it.
    zip_bytes = make_zip({"src/config.py": f'API_KEY = "{AWS_KEY}"\n'})
    findings = [finding(rule_id="aws-access-key-id",
                        file="acme-app-deadbeef/src/config.py", line=1)]

    plan = build_fixpack_plan(zip_bytes, findings)

    assert plan.has_changes
    assert AWS_KEY not in plan.files["src/config.py"]


def test_zero_eligible_findings_produces_empty_plan():
    zip_bytes = make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
    # supabase-anon-key and llm-* are never eligible.
    findings = [
        finding(rule_id="supabase-anon-key", file="config.py", line=1),
        finding(rule_id="llm-something", file="config.py", line=1),
    ]

    plan = build_fixpack_plan(zip_bytes, findings)

    assert not plan.has_changes


def test_pr_body_includes_rotate_warning_for_secret_fixes():
    zip_bytes = make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
    findings = [finding(rule_id="aws-access-key-id", file="config.py", line=1)]

    plan = build_fixpack_plan(zip_bytes, findings)
    body = render_pr_body(plan)

    assert "ROTATE" in body.upper()
    assert "AWS" in body  # provider rotation guidance present


def test_finding_no_longer_present_on_refetch_is_skipped_not_fatal():
    # Stored finding points at a value that isn't in the fresh source.
    zip_bytes = make_zip({"config.py": "API_KEY = os.environ['X']\n"})
    findings = [finding(rule_id="aws-access-key-id", file="config.py", line=1)]

    plan = build_fixpack_plan(zip_bytes, findings)

    assert not plan.has_changes
    assert len(plan.skipped) == 1
    assert plan.skipped[0].rule_id == "aws-access-key-id"


def test_multiple_secrets_on_one_file_applied_together():
    zip_bytes = make_zip(
        {"config.py": f'AWS = "{AWS_KEY}"\nGH = "{GH_PAT}"\n'}
    )
    findings = [
        finding(rule_id="aws-access-key-id", file="config.py", line=1),
        finding(rule_id="github-pat", file="config.py", line=2),
    ]

    plan = build_fixpack_plan(zip_bytes, findings)

    new_text = plan.files["config.py"]
    assert AWS_KEY not in new_text
    assert GH_PAT not in new_text
    assert 'os.environ["AWS_ACCESS_KEY_ID"]' in new_text
    assert 'os.environ["GITHUB_TOKEN"]' in new_text
    assert len(plan.secret_fixes) == 2


# --- Syntax-validation safety net -------------------------------------
# THE ROOT-CAUSE class behind Fix Pack #32: the value-span replacement can
# land *inside* a larger literal (a PEM in a quoted string, a secret inside
# an f-string, a JSON value), leaving surrounding quotes and injecting an
# env reference that itself contains quotes -> a broken file. This must be
# caught by syntax validation and the whole file dropped from the Fix Pack,
# INDEPENDENT of the test-path exclusion (these are all production paths).


def _skipped_reason_for(plan, file):
    return [s.reason for s in plan.skipped if s.file == file]


def test_pem_inside_python_string_literal_is_excluded_not_broken():
    # Exactly the shape that broke tests/test_fixpack_process_endpoint.py:293
    # but on a *production* path: a PEM inside a double-quoted Python string.
    # _PEM_BLOCK_RE matches the block WITHOUT its surrounding quotes, so the
    # env ref `os.environ["PRIVATE_KEY"]` gets injected between the quotes ->
    #   KEY = "os.environ["PRIVATE_KEY"]"   -> SyntaxError.
    pem = "-----BEGIN PRIVATE KEY-----\\nMIICdummy\\n-----END PRIVATE KEY-----"
    source = f'KEY = "{pem}"\n'
    ast.parse(source)  # the ORIGINAL file is valid Python
    zip_bytes = make_zip({"config.py": source})
    findings = [finding(rule_id="private-key-block", file="config.py", line=1)]

    plan = build_fixpack_plan(zip_bytes, findings)

    assert not plan.has_changes
    assert "config.py" not in plan.files
    reasons = _skipped_reason_for(plan, "config.py")
    assert any("invalid syntax" in r for r in reasons)


def test_secret_inside_fstring_is_excluded_not_broken():
    # The AWS token is embedded inside an f-string, not individually quoted,
    # so the wrapped-literal replace misses and the BARE fallback fires,
    # dropping `os.environ["AWS_ACCESS_KEY_ID"]` (with quotes) inside the
    # f-string's own quotes -> SyntaxError. Must be excluded, not shipped.
    source = f'TOKEN = f"env-{{stage}}-{AWS_KEY}"\n'
    ast.parse(source)  # original valid
    zip_bytes = make_zip({"config.py": source})
    findings = [finding(rule_id="aws-access-key-id", file="config.py", line=1)]

    plan = build_fixpack_plan(zip_bytes, findings)

    assert not plan.has_changes
    assert "config.py" not in plan.files
    assert any("invalid syntax" in r for r in _skipped_reason_for(plan, "config.py"))
    # Never-leak still holds on the excluded path.
    assert AWS_KEY not in render_pr_body(plan)


def test_secret_in_json_value_left_unquoted_is_excluded():
    # For an unknown-language value the env ref is `${NAME}` (no quotes).
    # Replacing the quoted JSON value `"AKIA..."` with the bare `${...}`
    # produces `{"api_key": ${AWS_ACCESS_KEY_ID}}` -> invalid JSON.
    source = f'{{"api_key": "{AWS_KEY}"}}\n'
    json.loads(source)  # original valid JSON
    zip_bytes = make_zip({"config.json": source})
    findings = [finding(rule_id="aws-access-key-id", file="config.json", line=1)]

    plan = build_fixpack_plan(zip_bytes, findings)

    assert not plan.has_changes
    assert "config.json" not in plan.files
    assert any("invalid syntax" in r for r in _skipped_reason_for(plan, "config.json"))


def test_valid_python_edit_passes_syntax_gate_and_is_shipped():
    # Control: a clean single-line assignment produces valid Python and must
    # NOT be dropped -- the gate must not over-reach and block good fixes.
    zip_bytes = make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
    findings = [finding(rule_id="aws-access-key-id", file="config.py", line=1)]

    plan = build_fixpack_plan(zip_bytes, findings)

    assert plan.has_changes
    new_text = plan.files["config.py"]
    ast.parse(new_text)  # the shipped file is valid Python
    assert not any("invalid syntax" in r for r in _skipped_reason_for(plan, "config.py"))


def test_validate_syntax_helper_py_json_and_heuristic():
    # .py -> ast.parse authority
    assert _validate_syntax("a.py", "x = 1\n", "x = 2\n")
    assert not _validate_syntax("a.py", "x = 1\n", 'x = "a"b"\n')
    # .json -> json.loads authority
    assert _validate_syntax("a.json", '{"a": 1}', '{"a": 2}')
    assert not _validate_syntax("a.json", '{"a": "x"}', '{"a": ${X}}')
    # unknown language -> conservative bracket-balance: reject only when a
    # balanced original became unbalanced; accept anything already unbalanced.
    assert _validate_syntax("a.go", "f(a)\n", "f(b)\n")
    assert not _validate_syntax("a.go", "f(a)\n", "f(b\n")
    assert _validate_syntax("a.go", "f(a\n", "still f(b\n")  # already broken -> not our fault


# --- non-production contexts are reported, not rewritten ---
#
# From a real Fix Pack, PR #131 on shipit itself. The scanner matched an
# illustrative string inside a comment documenting one of our OWN rules:
#
#     #   v_cron_secret text := 'hunter2...';
#
# The Fix Pack rewrote the comment to Python syntax inside a PL/pgSQL example,
# added DATABASE_SECRET=changeme to .env.example, and told the customer to
# ROTATE THIS SECRET NOW. The value was a joke placeholder that never existed.
#
# Editing a secret out of a comment buys no security at all: the value is in
# git history either way and must be rotated regardless, and a comment
# executes nothing, so there is no running code to disarm. All of the value of
# a code fix is absent and only the damage remains.


@pytest.mark.parametrize("context", ["comment", "doc_example", "test_file"])
def test_non_production_context_is_reported_not_rewritten(context):
    zip_bytes = make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
    findings = [
        finding(rule_id="aws-access-key-id", file="config.py", line=1,
                context=context),
    ]

    plan = build_fixpack_plan(zip_bytes, findings)

    assert not plan.has_changes
    assert plan.files == {}
    assert plan.secret_fixes == []
    # Recorded, not dropped silently: the customer should see that we looked
    # at it and chose not to touch it.
    assert len(plan.skipped) == 1
    assert plan.skipped[0].rule_id == "aws-access-key-id"
    assert context in plan.skipped[0].reason


def test_a_real_secret_beside_a_comment_one_is_still_fixed():
    """The other side of the calibration, and the thing that would make this
    change harmful if it were wrong: two matches in one file, one in a comment
    and one in executable code. Only the executable one may be touched."""
    zip_bytes = make_zip({"config.py": (
        f"# example: v_x text := '{AWS_KEY}';\n"
        f'API_KEY = "{AWS_KEY_2}"\n'
    )})
    findings = [
        finding(rule_id="aws-access-key-id", file="config.py", line=1,
                context="comment"),
        finding(rule_id="aws-access-key-id", file="config.py", line=2,
                context=None),
    ]

    plan = build_fixpack_plan(zip_bytes, findings)

    assert plan.has_changes
    assert len(plan.secret_fixes) == 1
    assert plan.secret_fixes[0].file == "config.py"
    # SecretFix carries no line, so the proof that the RIGHT one was fixed is
    # in the edited text below, not in the fix record.
    assert len(plan.skipped) == 1
    assert plan.skipped[0].line == 1

    edited = plan.files["config.py"]
    # The comment is byte-for-byte untouched, including its example value.
    assert f"# example: v_x text := '{AWS_KEY}';" in edited
    # The executable line no longer holds the secret.
    assert AWS_KEY_2 not in edited
    assert "os.environ[" in edited


def test_a_plan_of_only_comment_findings_opens_no_pull_request():
    """The end-to-end consequence. has_changes drives whether a PR is opened
    at all, so a repo whose every match is a comment now finishes as
    no_fix_needed instead of receiving PR #131."""
    zip_bytes = make_zip({"a.py": f"# key: {AWS_KEY}\n",
                          "b.py": f"# other: {AWS_KEY_2}\n"})
    findings = [
        finding(rule_id="aws-access-key-id", file="a.py", line=1,
                context="comment"),
        finding(rule_id="aws-access-key-id", file="b.py", line=1,
                context="doc_example"),
    ]

    plan = build_fixpack_plan(zip_bytes, findings)

    assert not plan.has_changes
    assert len(plan.skipped) == 2


def test_the_filter_reuses_the_scanner_vocabulary():
    """Not a behaviour test -- a coupling test. The report learned all four
    contexts in #125 while this filter still compared against one string
    literal, and that divergence IS the bug. A second hand-maintained copy of
    the list would diverge again."""
    from app.scan import secrets as scanner

    for context in scanner.NON_PRODUCTION_CONTEXTS:
        zip_bytes = make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
        plan = build_fixpack_plan(zip_bytes, [
            finding(rule_id="aws-access-key-id", file="config.py", line=1,
                    context=context),
        ])
        assert not plan.has_changes, f"{context} still edited"
