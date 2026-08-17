"""Unit tests for static sqli and cors_open proof templates."""

from __future__ import annotations

import io
import zipfile

from app.proof.compare import run_proof_pair
from app.proof.registry import get_template, list_templates


def _zip_with(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, text in files.items():
            zf.writestr(name, text)
    return buf.getvalue()


def test_registry_marks_sqli_and_cors_implemented() -> None:
    meta = {row["id"]: row for row in list_templates()}
    assert meta["sqli"]["implemented"] is True
    assert meta["cors_open"]["implemented"] is True
    assert meta["sqli"]["needs_runtime"] is False
    assert meta["cors_open"]["needs_runtime"] is False


def test_cors_detects_fastapi_star_with_credentials() -> None:
    src = '''
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
)
'''
    attempt = get_template("cors_open")(_zip_with({"main.py": src}))
    assert attempt.status == "success"
    assert attempt.success is True
    assert attempt.evidence["finding_count"] >= 1
    assert any("cors-" in s["rule_id"] for s in attempt.evidence["samples"])


def test_cors_clean_without_credentials() -> None:
    src = '''
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
)
'''
    attempt = get_template("cors_open")(_zip_with({"main.py": src}))
    assert attempt.success is False
    assert attempt.status == "failure"


def test_cors_detects_express_origin_true() -> None:
    src = '''
const cors = require("cors");
app.use(cors({ origin: true, credentials: true }));
'''
    attempt = get_template("cors_open")(_zip_with({"server.js": src}))
    assert attempt.success is True


def test_cors_proof_pair_verified_after_lockdown() -> None:
    original = _zip_with({
        "main.py": (
            "app.add_middleware(CORSMiddleware, allow_origins=[\"*\"], "
            "allow_credentials=True)\n"
        ),
    })
    patched = _zip_with({
        "main.py": (
            "app.add_middleware(CORSMiddleware, "
            "allow_origins=[\"https://app.example.com\"], "
            "allow_credentials=True)\n"
        ),
    })
    report = run_proof_pair("cors_open", original, patched)
    assert report.verified is True
    assert report.before.success is True
    assert report.after.success is False


def test_sqli_detects_python_fstring_select() -> None:
    src = '''
def get_user(request):
    q = f"SELECT * FROM users WHERE id = {request.args['id']}"
    return db.execute(q)
'''
    attempt = get_template("sqli")(_zip_with({"api.py": src}))
    assert attempt.success is True
    assert attempt.evidence["finding_count"] >= 1


def test_sqli_detects_js_template_literal() -> None:
    src = '''
app.get("/users", (req, res) => {
  const q = `SELECT * FROM users WHERE name = '${req.query.name}'`;
  db.query(q);
});
'''
    attempt = get_template("sqli")(_zip_with({"routes.js": src}))
    assert attempt.success is True


def test_sqli_clean_parameterized() -> None:
    src = '''
def get_user(user_id: int):
    return db.execute("SELECT * FROM users WHERE id = %s", (user_id,))
'''
    attempt = get_template("sqli")(_zip_with({"api.py": src}))
    assert attempt.success is False
    assert attempt.status == "failure"


def test_sqli_proof_pair_verified_after_parameterize() -> None:
    original = _zip_with({
        "api.py": (
            'q = f"SELECT * FROM users WHERE id = {request.args[\'id\']}"\n'
            "db.execute(q)\n"
        ),
    })
    patched = _zip_with({
        "api.py": (
            'db.execute("SELECT * FROM users WHERE id = %s", '
            "(request.args['id'],))\n"
        ),
    })
    report = run_proof_pair("sqli", original, patched)
    assert report.verified is True
