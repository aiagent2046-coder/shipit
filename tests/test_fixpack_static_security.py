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
