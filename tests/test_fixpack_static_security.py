"""Tests for CORS / SQLi mechanical Fix Pack rewrites."""

from __future__ import annotations

import io
import zipfile

from app.fixpack.generate import build_fixpack_plan
from app.fixpack.static_security_fixes import apply_cors_fixes, apply_sqli_fixes


def _zip_with(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, text in files.items():
            zf.writestr(f"repo/{name}", text)
    return buf.getvalue()


def test_cors_fastapi_star_is_pinned() -> None:
    src = (
        "app.add_middleware(CORSMiddleware, allow_origins=[\"*\"], "
        "allow_credentials=True)\n"
    )
    updates, fixes = apply_cors_fixes({"main.py": src})
    assert "main.py" in updates
    assert 'allow_origins=["*"]' not in updates["main.py"]
    assert "localhost:3000" in updates["main.py"]
    assert fixes[0].rule_id == "cors-open-credentials"


def test_every_cors_fix_names_the_placeholder_origin_it_substituted() -> None:
    """The fix list must not describe only the safety half of the rewrite.

    Each of these rewrites closes the hole AND pins the app to
    http://localhost:3000 (or an env var defaulting to it), which breaks the
    customer's production frontend if the PR is merged unread. The summary
    used to say only "pinned FastAPI allow_origins away from `*`" — true, and
    silent about the half that a reader needed to act on before merging.

    Anchored per framework rather than once, because each branch writes its
    own detail string and a single sample would let three of them drift.
    """
    cases = {
        "main.py": (
            'app.add_middleware(CORSMiddleware, allow_origins=["*"], '
            "allow_credentials=True)\n"
        ),
        "server.js": (
            "app.use(cors({ origin: true, credentials: true }))\n"
        ),
        "flask_app.py": (
            'CORS(app, origins="*", supports_credentials=True)\n'
        ),
        "headers.conf": (
            'add_header Access-Control-Allow-Origin "*";\n'
            'add_header Access-Control-Allow-Credentials "true";\n'
        ),
    }
    for path, src in cases.items():
        _updates, fixes = apply_cors_fixes({path: src})
        assert fixes, path
        detail = fixes[0].detail
        assert "localhost:3000" in detail, (path, detail)
        # ...and it has to read as an instruction, not as trivia.
        assert ("set your real origin" in detail
                or "set CORS_ORIGIN" in detail), (path, detail)


def test_cors_without_credentials_is_left_alone() -> None:
    src = "app.add_middleware(CORSMiddleware, allow_origins=[\"*\"])\n"
    updates, fixes = apply_cors_fixes({"main.py": src})
    assert updates == {}
    assert fixes == []


def test_sqli_python_execute_fstring_parameterized() -> None:
    src = (
        'db.execute(f"SELECT * FROM users WHERE id = {request.args[\'id\']}")\n'
    )
    updates, fixes = apply_sqli_fixes({"api.py": src})
    assert "api.py" in updates
    assert "%s" in updates["api.py"]
    assert "request.args" in updates["api.py"]
    assert 'f"' not in updates["api.py"]
    assert fixes[0].rule_id == "sqli-dynamic-execute"


def test_sqli_parameterized_already_clean() -> None:
    src = 'db.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
    updates, _ = apply_sqli_fixes({"api.py": src})
    assert updates == {}


def test_build_plan_applies_cors_alongside_secret() -> None:
    stripe = "sk_" + "live_" + ("A" * 24)
    files = {
        "config.py": f'STRIPE = "{stripe}"\n',
        "main.py": (
            "app.add_middleware(CORSMiddleware, allow_origins=[\"*\"], "
            "allow_credentials=True)\n"
        ),
    }
    findings = [
        {
            "rule_id": "stripe-live-key",
            "file": "config.py",
            "line": 1,
            "title": "Stripe live secret key",
            "context": None,
        },
    ]
    plan = build_fixpack_plan(_zip_with(files), findings)
    assert plan.has_changes
    assert "config.py" in plan.files
    assert "main.py" in plan.files
    assert 'allow_origins=["*"]' not in plan.files["main.py"]
    assert any(c.rule_id == "cors-open-credentials" for c in plan.config_fixes)


def test_build_plan_applies_sqli_fix() -> None:
    stripe = "sk_" + "live_" + ("B" * 24)
    files = {
        "api.py": (
            f'STRIPE = "{stripe}"\n'
            'db.execute(f"SELECT * FROM t WHERE id = {request.args[\'id\']}")\n'
        ),
    }
    findings = [
        {
            "rule_id": "stripe-live-key",
            "file": "api.py",
            "line": 1,
            "title": "Stripe live secret key",
            "context": None,
        },
    ]
    plan = build_fixpack_plan(_zip_with(files), findings)
    assert "api.py" in plan.files
    body = plan.files["api.py"]
    assert stripe not in body
    assert "%s" in body
    assert any(c.rule_id == "sqli-dynamic-execute" for c in plan.config_fixes)


def test_cors_documentation_and_python_string_examples_are_untouched() -> None:
    example = 'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)'
    files = {
        "docs/cors.md": f"# Configuration example\n```python\n{example}\n```\n",
        "README.rst": f"For local experiments only::\n\n    {example}\n",
        "probe.py": f"'''Probe usage: {example}'''\nprint('probe')\n",
        "example.py": f"example = {example!r}\n# {example}\n",
        "server.js": 'const example = "cors({ origin: true, credentials: true })";\n',
        "template.ts": "const example = `cors({ origin: '*', credentials: true })`;\n",
    }
    assert apply_cors_fixes(files) == ({}, [])


def test_cors_python_docstring_before_real_call_preserved_exactly() -> None:
    example = 'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)'
    prefix = f"'''Пример настройки: {example}'''\n# {example}\n"
    actual = 'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)\n'
    updates, fixes = apply_cors_fixes({"server.py": prefix + actual})
    assert updates["server.py"] == prefix + actual.replace('["*"]', '["http://localhost:3000"]')
    assert len(fixes) == 1


def test_cors_credentials_from_comments_strings_or_other_calls_are_not_evidence() -> None:
    files = {
        "comments.py": '# allow_credentials=True\napp.add_middleware(CORSMiddleware, allow_origins=["*"])\n',
        "docstring.py": '\'\'\'allow_credentials=True\'\'\'\napp.add_middleware(CORSMiddleware, allow_origins=["*"])\n',
        "string.py": 'example = "allow_credentials=True"\napp.add_middleware(CORSMiddleware, allow_origins=["*"])\n',
        "separate.py": (
            'app.add_middleware(CORSMiddleware, allow_origins=["https://example.org"], allow_credentials=True)\n'
            'other.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False)\n'
        ),
        "flask.py": '# supports_credentials=True\nCORS(app, origins="*")\n',
        "comment.js": "// credentials: true\napp.use(cors({ origin: '*' }));\n",
        "block_comment.ts": "app.use(cors({ origin: '*', /* credentials: true */ credentials: false }));\n",
        "string.js": 'const example = "credentials: true";\napp.use(cors({ origin: true }));\n',
        "separate.js": (
            "app.use(cors({ origin: 'https://example.org', credentials: true }));\n"
            "other.use(cors({ origin: '*', credentials: false }));\n"
        ),
        "headers.conf": (
            '# add_header Access-Control-Allow-Credentials "true";\n'
            'add_header Access-Control-Allow-Origin "*";\n'
        ),
    }
    for path, src in files.items():
        assert apply_cors_fixes({path: src}) == ({}, []), path


def test_cors_js_examples_before_real_object_preserved_exactly() -> None:
    prefix = (
        '// cors({ origin: true, credentials: true })\n'
        '/* cors({ origin: "*", credentials: true }) */\n'
        'const example = `Пример: cors({ origin: true, credentials: true })`;\n'
    )
    actual = 'app.use(cors({ origin: "*", credentials: true }));\n'
    updates, _fixes = apply_cors_fixes({"server.ts": prefix + actual})
    assert updates["server.ts"] == prefix + actual.replace(
        '"*"', "process.env.CORS_ORIGIN || 'http://localhost:3000'",
    )


def test_cors_structured_header_config_is_pinned_without_rewriting_examples() -> None:
    import json

    src = json.dumps({"example": 'Access-Control-Allow-Origin "*"; Access-Control-Allow-Credentials "true";',
                      "headers": {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}})
    updates, _fixes = apply_cors_fixes({"headers.json": src})
    result = json.loads(updates["headers.json"])
    assert result["example"] == json.loads(src)["example"]
    assert result["headers"]["Access-Control-Allow-Origin"] == "http://localhost:3000"


def test_build_plan_preserves_cors_documentation_and_probe_docstring() -> None:
    stripe = "sk_" + "live_" + ("C" * 24)
    example = 'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)'
    files = {
        "config.py": f'STRIPE = "{stripe}"\n',
        "docs/runtime-proof.md": f"```python\n{example}\n```\n",
        "scripts/probe.py": f"'''Runtime probe: {example}'''\nprint('probe')\n",
        "main.py": example + "\n",
    }
    findings = [{"rule_id": "stripe-live-key", "file": "config.py", "line": 1,
                 "title": "Stripe live secret key", "context": None}]
    plan = build_fixpack_plan(_zip_with(files), findings)
    assert "config.py" in plan.files
    assert "main.py" in plan.files
    assert "docs/runtime-proof.md" not in plan.files
    assert "scripts/probe.py" not in plan.files
    assert sum(f.rule_id == "cors-open-credentials" for f in plan.config_fixes) == 1


def test_cors_nginx_multiline_examples_and_separate_blocks_are_untouched() -> None:
    src = (
        'set $example "\nadd_header Access-Control-Allow-Origin \'*\';\n'
        'add_header Access-Control-Allow-Credentials \'true\';\n";\n'
        'server {\nadd_header Access-Control-Allow-Origin "*";\n}\n'
        'server {\nadd_header Access-Control-Allow-Origin "https://example.org";\n'
        'add_header Access-Control-Allow-Credentials "true";\n}\n'
    )
    assert apply_cors_fixes({"nginx.conf": src}) == ({}, [])
