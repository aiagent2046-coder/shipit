"""Scan synthetic secrets, then verify the actual Fix Pack output boundary."""

from dataclasses import asdict
import io

import pytest

from app.fixpack import generate
from app.scan.secrets import iter_secret_matches
from tests.test_fixpack_generate import AWS_KEY_2, make_zip


def plan_for(entries):
    archive = make_zip(entries)
    findings = [asdict(f) for f, _ in iter_secret_matches(io.BytesIO(archive))]
    assert findings, "The regression must reach the planner through a real scan"
    return generate.build_fixpack_plan(archive, findings)


@pytest.mark.parametrize("suffix", ["js", "jsx", "mjs", "cjs", "ts", "tsx"])
@pytest.mark.parametrize("source", [
    'const TOKEN = 1;\n',
    'const cfg = {"TOKEN": 1};\n',
])
def test_invalid_secret_replacement_is_not_emitted(suffix, source):
    path = f"src/config.{suffix}"
    plan = plan_for({path: source.replace("TOKEN", AWS_KEY_2)})

    assert not plan.has_changes
    assert not plan.secret_fixes
    assert any(s.file == path and "syntax" in s.reason for s in plan.skipped)
    assert AWS_KEY_2 not in generate.render_pr_body(plan)


@pytest.mark.parametrize("suffix", ["jsx", "tsx"])
def test_jsx_attribute_replacement_is_not_emitted(suffix):
    path = f"src/view.{suffix}"
    plan = plan_for({path: f'const View = () => <div key="{AWS_KEY_2}"/>;\n'})

    assert path not in plan.files
    assert any(s.file == path and "syntax" in s.reason for s in plan.skipped)


@pytest.mark.parametrize("suffix", ["js", "jsx", "mjs", "cjs", "ts", "tsx"])
def test_valid_secret_edit_survives_next_to_rejected_file(suffix):
    good, bad = f"src/good.{suffix}", f"src/bad.{suffix}"
    plan = plan_for({
        good: f'const key = "{AWS_KEY_2}";\n',
        bad: f'const cfg = {{"{AWS_KEY_2}": 1}};\n',
    })

    assert good in plan.files
    assert bad not in plan.files
    assert len(plan.secret_fixes) == 1
    assert "AWS_ACCESS_KEY_ID=changeme" in plan.files[".env.example"]
    assert "process.env.AWS_ACCESS_KEY_ID" in plan.files[good]
    assert all(AWS_KEY_2 not in text for text in plan.files.values())
    assert AWS_KEY_2 not in generate.render_pr_body(plan)


@pytest.mark.parametrize("path,source", [
    ("a.js", "const key: string = process.env.KEY;"),
    ("a.jsx", "const key = process.env.KEY!;"),
    ("a.ts", "const key = ;"),
    ("a.tsx", "const View = () => <div key=process.env.KEY!/>;"),
])
def test_recovered_parse_errors_are_rejected(path, source):
    assert not generate._validate_syntax(path, "const key = 1;", source)


@pytest.mark.parametrize("path,source", [
    ("a.js", "export const x = obj?.value ?? 'fallback';"),
    ("a.jsx", "export const View = () => <div>{process.env.KEY}</div>;"),
    ("a.ts", "const id = <T>(value: T): T => value;"),
    ("a.tsx", "const View = () => <div>{process.env.KEY!}</div>;"),
])
def test_supported_language_syntax_is_accepted(path, source):
    assert generate._validate_syntax(path, source, source)


def test_oversized_edit_is_excluded_with_a_reason(monkeypatch):
    monkeypatch.setattr(generate, "_MAX_JS_SYNTAX_BYTES", 64)
    plan = plan_for({"src/config.ts": f'const key = "{AWS_KEY_2}";\n' + "// padding\n" * 10})

    assert not plan.has_changes
    assert any(s.file == "src/config.ts" and "limit" in s.reason for s in plan.skipped)


def test_syntax_limit_counts_utf8_bytes(monkeypatch):
    source = 'const label = "Привет";'
    monkeypatch.setattr(generate, "_MAX_JS_SYNTAX_BYTES", len(source))
    assert not generate._validate_syntax("a.ts", source, source)
