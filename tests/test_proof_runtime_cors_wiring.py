"""P2 wiring: when the runtime CORS probe runs, and what its report may say.

No docker — the probe is stubbed. What is pinned here is the decision to
spend two container builds, and the rule that a runtime answer is added to
the PR rather than substituted for the static one.
"""

from __future__ import annotations

import io
import zipfile

import pytest

import app.proof.stage as stage_mod
from app.proof.compare import build_proof_report
from app.proof.render import render_proof_markdown
from app.proof.runtime_cors import runtime_cors_applicable, runtime_cors_enabled
from app.proof.types import ExploitAttempt, ProofReport


def _zip(names: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, text in names.items():
            zf.writestr(name, text)
    return buf.getvalue()


def _attempt(template_id: str, status: str, success: bool,
             evidence: dict | None = None) -> ExploitAttempt:
    return ExploitAttempt(
        template_id=template_id, status=status, success=success,
        detail=f"{template_id}/{status}", evidence=evidence or {},
    )


def _static_cors(found: bool) -> ProofReport:
    return build_proof_report(
        _attempt("cors_open", "success" if found else "failure", found),
        _attempt("cors_open", "failure", False),
        informational=False,
    )


_BOOTABLE = {"Dockerfile": "FROM python:3.12-slim\n", "main.py": "x = 1\n"}


# --- applicability ----------------------------------------------------------

def test_disabled_by_default(monkeypatch) -> None:
    """No customer workspace has ever been booted by this path. Off until an
    operator turns it on where the first boot can be watched."""
    monkeypatch.delenv("PROOF_RUNTIME_CORS", raising=False)
    assert runtime_cors_enabled() is False
    ok, reason = runtime_cors_applicable([_static_cors(True)], _zip(_BOOTABLE))
    assert ok is False
    assert "PROOF_RUNTIME_CORS" in reason


@pytest.mark.parametrize("value,expected", [
    ("1", True), ("true", True), ("on", True), ("YES", True),
    ("0", False), ("off", False), ("", False), ("maybe", False),
])
def test_flag_parsing(monkeypatch, value, expected) -> None:
    monkeypatch.setenv("PROOF_RUNTIME_CORS", value)
    assert runtime_cors_enabled() is expected


def test_runs_when_static_hit_and_repo_is_buildable(monkeypatch) -> None:
    monkeypatch.setenv("PROOF_RUNTIME_CORS", "1")
    ok, _reason = runtime_cors_applicable([_static_cors(True)], _zip(_BOOTABLE))
    assert ok is True


def test_not_run_when_the_static_scanner_found_nothing(monkeypatch) -> None:
    """The scanner is the trigger. Booting containers for every Fix Pack would
    spend minutes of CPU to answer a question nobody asked."""
    monkeypatch.setenv("PROOF_RUNTIME_CORS", "1")
    ok, reason = runtime_cors_applicable([_static_cors(False)], _zip(_BOOTABLE))
    assert ok is False
    assert "nothing to reproduce" in reason


def test_not_run_when_cors_was_not_among_the_static_templates(monkeypatch) -> None:
    monkeypatch.setenv("PROOF_RUNTIME_CORS", "1")
    secrets_only = build_proof_report(
        _attempt("secrets_leak", "success", True),
        _attempt("secrets_leak", "failure", False),
        informational=False,
    )
    ok, reason = runtime_cors_applicable([secrets_only], _zip(_BOOTABLE))
    assert ok is False
    assert "did not run" in reason


def test_not_run_without_a_root_dockerfile(monkeypatch) -> None:
    """Booting through a Dockerfile we generated would conflate 'the app's
    CORS is open' with 'our generated Dockerfile is right' — and when the
    stand fails to come up, nobody could tell which."""
    monkeypatch.setenv("PROOF_RUNTIME_CORS", "1")
    ok, reason = runtime_cors_applicable(
        [_static_cors(True)], _zip({"main.py": "x = 1\n"}))
    assert ok is False
    assert "Dockerfile" in reason


def test_a_github_style_wrapper_folder_still_counts_as_buildable(
    monkeypatch,
) -> None:
    monkeypatch.setenv("PROOF_RUNTIME_CORS", "1")
    ok, _r = runtime_cors_applicable(
        [_static_cors(True)],
        _zip({"repo-main/Dockerfile": "FROM x\n", "repo-main/main.py": "1\n"}),
    )
    assert ok is True


def test_a_dockerfile_deep_in_the_tree_does_not_count(monkeypatch) -> None:
    """`services/api/Dockerfile` builds a component, not the repo — and we
    would be guessing which one to boot."""
    monkeypatch.setenv("PROOF_RUNTIME_CORS", "1")
    ok, reason = runtime_cors_applicable(
        [_static_cors(True)],
        _zip({"services/api/Dockerfile": "FROM x\n"}),
    )
    assert ok is False
    assert "Dockerfile" in reason


# --- the stage wiring -------------------------------------------------------

class _Repo:
    def __init__(self) -> None:
        self.proof_json: dict = {}

    async def set_proof_json(self, job_id, proof):
        self.proof_json[job_id] = proof


def _plan():
    return type("_Plan", (), {
        "files": {"main.py": "x = 1\n"},
        "deletions": [],
        "secret_fixes": [],
    })()


async def _run_stage(monkeypatch, probe_results, static_templates=("cors_open",)):
    """Drive run_proof_stage with the static templates and probe stubbed."""
    monkeypatch.setenv("PROOF_RUNTIME_CORS", "1")
    monkeypatch.setattr(stage_mod, "select_templates",
                        lambda *_a, **_k: list(static_templates))
    monkeypatch.setattr(
        stage_mod, "run_proof_pair",
        lambda tid, *_a, **_k: _static_cors(True))

    calls: list = []

    def _probe(zip_bytes, **kwargs):
        calls.append(kwargs)
        return probe_results.pop(0)

    monkeypatch.setattr(stage_mod.sandbox_client, "run_cors_probe", _probe)

    repo = _Repo()
    result = await stage_mod.run_proof_stage(
        job_id="j1", zip_bytes=_zip(_BOOTABLE), plan=_plan(),
        fixpack_repo=repo,
    )
    return result, calls, repo


async def test_a_runtime_report_is_added_next_to_the_static_one(
    monkeypatch,
) -> None:
    """Never substituted. If the scanner found a pattern and the booted app
    did not reproduce it, the reader needs both halves — the disagreement is
    the finding."""
    result, calls, repo = await _run_stage(monkeypatch, [
        _attempt("cors_open_runtime", "success", True),
        _attempt("cors_open_runtime", "failure", False),
    ])

    ids = [r.template_id for r in result.reports]
    assert ids == ["cors_open", "cors_open_runtime"]
    assert len(calls) == 2, "one probe per workspace, before and after"
    assert repo.proof_json["j1"]


async def test_a_runner_outage_leaves_the_static_report_alone(
    monkeypatch,
) -> None:
    """'We could not check' must not remove the static answer, and must not
    invent a runtime one."""
    monkeypatch.setenv("PROOF_RUNTIME_CORS", "1")
    monkeypatch.setattr(stage_mod, "select_templates",
                        lambda *_a, **_k: ["cors_open"])
    monkeypatch.setattr(stage_mod, "run_proof_pair",
                        lambda tid, *_a, **_k: _static_cors(True))

    def _down(*_a, **_k):
        raise RuntimeError("runner unreachable")

    monkeypatch.setattr(stage_mod.sandbox_client, "run_cors_probe", _down)

    result = await stage_mod.run_proof_stage(
        job_id="j2", zip_bytes=_zip(_BOOTABLE), plan=_plan(),
        fixpack_repo=_Repo(),
    )
    assert [r.template_id for r in result.reports] == ["cors_open"]


async def test_the_probe_is_not_called_when_the_flag_is_off(
    monkeypatch,
) -> None:
    monkeypatch.delenv("PROOF_RUNTIME_CORS", raising=False)
    monkeypatch.setattr(stage_mod, "select_templates",
                        lambda *_a, **_k: ["cors_open"])
    monkeypatch.setattr(stage_mod, "run_proof_pair",
                        lambda tid, *_a, **_k: _static_cors(True))

    called: list = []
    monkeypatch.setattr(stage_mod.sandbox_client, "run_cors_probe",
                        lambda *a, **k: called.append(1))

    result = await stage_mod.run_proof_stage(
        job_id="j3", zip_bytes=_zip(_BOOTABLE), plan=_plan(),
        fixpack_repo=_Repo(),
    )
    assert called == []
    assert [r.template_id for r in result.reports] == ["cors_open"]


# --- rendering --------------------------------------------------------------

def test_a_runtime_section_claims_the_request_was_really_made() -> None:
    report = build_proof_report(
        _attempt("cors_open_runtime", "success", True, {
            "allow_origin": "https://drydock-proof.invalid",
            "allow_credentials": "true",
        }),
        _attempt("cors_open_runtime", "failure", False, {
            "allow_origin": None, "allow_credentials": None,
        }),
        informational=False,
    )
    md = render_proof_markdown(report)

    assert "Проверка динамическая" in md
    assert "запрос с постороннего origin получил доступ" in md
    assert "Кросс-доменный запрос" in md
    # The transcript, not our summary of it.
    assert "Access-Control-Allow-Origin: https://drydock-proof.invalid" in md
    assert "(отсутствует)" in md
    # The static disclaimer must not appear over a report that booted the app.
    assert "Проверка статическая" not in md


def test_a_static_section_still_carries_the_static_note() -> None:
    md = render_proof_markdown(_static_cors(True))
    assert "Проверка статическая" in md
    assert "Проверка динамическая" not in md


# --- the build root ---------------------------------------------------------

def test_a_component_dockerfile_is_not_a_build_root(monkeypatch) -> None:
    """`backend/Dockerfile` builds one service of a monorepo, not the repo.

    Measured 2026-08-17: the first version of this check accepted any path of
    two segments or fewer — the same test as "root or GitHub wrapper" only
    while the wrapper is present. On an already-stripped archive it also
    admitted component Dockerfiles, and
    tiangolo/full-stack-fastapi-template (backend/Dockerfile, no root one)
    was sent to the runner, where docker build found nothing at the root it
    was given and failed in 1.2 seconds. `error` was true and useless: the
    stand did not come up because it should never have been asked.
    """
    monkeypatch.setenv("PROOF_RUNTIME_CORS", "1")
    ok, reason = runtime_cors_applicable(
        [_static_cors(True)],
        _zip({"backend/Dockerfile": "FROM python\n",
              "frontend/index.html": "<html>\n",
              "README.md": "# x\n"}),
    )
    assert ok is False
    assert "Dockerfile" in reason


def test_the_github_wrapper_is_still_tolerated(monkeypatch) -> None:
    """The case the loose check existed for has to keep working: one
    top-level folder holding everything, Dockerfile directly inside it."""
    monkeypatch.setenv("PROOF_RUNTIME_CORS", "1")
    ok, _r = runtime_cors_applicable(
        [_static_cors(True)],
        _zip({"repo-main/Dockerfile": "FROM python\n",
              "repo-main/app.py": "x = 1\n"}),
    )
    assert ok is True


def test_a_wrapper_with_only_a_component_dockerfile_does_not_count(
    monkeypatch,
) -> None:
    """Wrapper present AND the Dockerfile one level deeper inside it — the
    two exceptions must not combine into a third."""
    monkeypatch.setenv("PROOF_RUNTIME_CORS", "1")
    ok, reason = runtime_cors_applicable(
        [_static_cors(True)],
        _zip({"repo-main/backend/Dockerfile": "FROM python\n",
              "repo-main/app.py": "x = 1\n"}),
    )
    assert ok is False
    assert "Dockerfile" in reason
