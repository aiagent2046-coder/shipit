"""Pure-transform tests for app/fixpack/generate.build_fixpack_plan.

No network, no PR opening — build a repo zip in memory, hand it the
audit's persisted findings, and assert on the resulting FixpackPlan and
the rendered PR title/body.

THE SAFETY INVARIANT under test: a real secret value must never appear
in the plan's emitted file contents, PR title, or PR body — only in the
ORIGINAL file it is being edited out of. Every secret test asserts the
raw value is gone from the new file AND absent from the PR body.
"""

import io
import zipfile

from app.fixpack.generate import (
    build_fixpack_plan,
    render_pr_body,
    render_pr_title,
)

# Distinctive, obviously-fake secrets so absence assertions are unambiguous.
AWS_KEY = os.environ["AWS_ACCESS_KEY_ID"]          # matches aws-access-key-id
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
