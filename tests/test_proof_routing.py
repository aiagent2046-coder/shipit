"""Tests for proof template stage routing."""

from __future__ import annotations

import asyncio
import io
import zipfile
from dataclasses import dataclass, field

from app.proof.routing import select_templates
from app.proof.stage import ProofStageResult, _pick_primary, run_proof_stage
from app.proof.types import ExploitAttempt, ProofReport


def _zip_with(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, text in files.items():
            zf.writestr(name, text)
    return buf.getvalue()


@dataclass
class FakePlan:
    files: dict[str, str] = field(default_factory=dict)
    deletions: list[str] = field(default_factory=list)
    secret_fixes: list = field(default_factory=list)
    leaked_env_files: list[str] = field(default_factory=list)
    leaked_env_vars: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.files or self.deletions)


def test_select_secrets_when_secret_fixes() -> None:
    plan = FakePlan(secret_fixes=[object()], files={"cfg.py": "x"})
    z = _zip_with({"cfg.py": "print(1)\n"})
    assert select_templates(plan, z) == ["secrets_leak"]


def test_select_sqli_when_plan_touches_hit_file() -> None:
    src = 'q = f"SELECT * FROM users WHERE id = {request.args[\'id\']}"\n'
    z = _zip_with({"api.py": src})
    plan = FakePlan(files={"api.py": "db.execute('SELECT 1')\n"})
    assert "sqli" in select_templates(plan, z)


def test_skip_sqli_when_hit_file_not_in_plan() -> None:
    """Residual SQLi in an untouched module must not select the template."""
    src = 'q = f"SELECT * FROM users WHERE id = {request.args[\'id\']}"\n'
    z = _zip_with({
        "api.py": src,
        "config.py": "API_KEY = 'x'\n",
    })
    plan = FakePlan(
        secret_fixes=[object()],
        files={"config.py": "API_KEY = os.environ['API_KEY']\n"},
    )
    selected = select_templates(plan, z)
    assert selected == ["secrets_leak"]
    assert "sqli" not in selected


def test_select_cors_when_plan_touches_middleware() -> None:
    src = (
        "app.add_middleware(CORSMiddleware, allow_origins=[\"*\"], "
        "allow_credentials=True)\n"
    )
    z = _zip_with({"main.py": src})
    plan = FakePlan(
        files={
            "main.py": (
                "app.add_middleware(CORSMiddleware, "
                "allow_origins=[\"https://app.example.com\"], "
                "allow_credentials=True)\n"
            ),
        },
    )
    assert "cors_open" in select_templates(plan, z)


def test_empty_plan_selects_nothing() -> None:
    z = _zip_with({"readme.md": "x\n"})
    plan = FakePlan()
    assert select_templates(plan, z) == []


def test_pick_primary_prefers_verified() -> None:
    def _rep(tid: str, verified: bool, before_ok: bool) -> ProofReport:
        before = ExploitAttempt(
            template_id=tid,  # type: ignore[arg-type]
            status="success" if before_ok else "failure",
            success=before_ok,
            detail="x",
            evidence={},
        )
        after = ExploitAttempt(
            template_id=tid,  # type: ignore[arg-type]
            status="failure" if verified else "success",
            success=not verified,
            detail="y",
            evidence={},
        )
        return ProofReport(
            template_id=tid,  # type: ignore[arg-type]
            before=before,
            after=after,
            verified=verified,
            informational=False,
            detail="d",
        )

    reports = [
        _rep("sqli", False, True),
        _rep("secrets_leak", True, True),
    ]
    primary = _pick_primary(reports)
    assert primary is not None
    assert primary.template_id == "secrets_leak"
    assert primary.verified is True


class _FakeRepo:
    def __init__(self) -> None:
        self.proof_json: dict = {}

    async def set_proof_json(self, job_id, proof) -> None:
        self.proof_json[job_id] = proof


def test_run_proof_stage_runs_selected_sqli() -> None:
    src = 'q = f"SELECT * FROM users WHERE id = {request.args[\'id\']}"\n'
    original = _zip_with({"api.py": src})
    plan = FakePlan(files={"api.py": "db.execute('SELECT 1', ())\n"})
    repo = _FakeRepo()

    async def _run():
        return await run_proof_stage(
            job_id="j1", zip_bytes=original, plan=plan, fixpack_repo=repo,
        )

    result = asyncio.run(_run())
    assert isinstance(result, ProofStageResult)
    assert any(r.template_id == "sqli" for r in result.reports)
    assert "j1" in repo.proof_json
    assert "reports" in repo.proof_json["j1"]
