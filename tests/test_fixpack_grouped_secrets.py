"""A display group must not turn a two-file repair into a one-file patch."""

from __future__ import annotations

import ast
from dataclasses import asdict
import io
import json
import zipfile

from app.fixpack.generate import build_fixpack_plan
from app.proof.compare import run_proof_pair
from app.proof.gate import decide_proof_gate
from app.proof.workspace import apply_plan_to_zip
from app.scan.collapse import collapse_repeats
from app.scan.secrets import scan_secrets


_SYNTHETIC = "synTheticTokenValue314159"


def _zip(entries: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for path, body in entries.items():
            archive.writestr(f"repo/{path}", body)
    return buf.getvalue()


def _assignment(value: str = _SYNTHETIC) -> str:
    return f'API_TOKEN = "{value}"\n'


def _findings(data: bytes) -> list[dict]:
    return collapse_repeats([asdict(f) for f in scan_secrets(io.BytesIO(data))])


def _proof(data, plan):
    return run_proof_pair(
        "secrets_leak", data, apply_plan_to_zip(data, plan.files, plan.deletions),
        informational=False,
    )


def test_collapsed_credential_is_removed_from_both_production_files(monkeypatch):
    monkeypatch.setenv("PROOF_GATE_MODE", "hard")
    data = _zip({"src/a.py": _assignment(), "src/b.py": _assignment()})
    findings = _findings(data)
    assert len(findings) == 1
    assert findings[0]["occurrence_count"] == 2

    plan = build_fixpack_plan(data, findings)
    assert {"src/a.py", "src/b.py"} <= plan.files.keys()
    for path in ("src/a.py", "src/b.py"):
        ast.parse(plan.files[path])
        assert _SYNTHETIC not in plan.files[path]
    proof = _proof(data, plan)
    assert proof.before.evidence["finding_count"] == 2
    assert proof.after.evidence["finding_count"] == 0
    assert proof.verified
    assert decide_proof_gate(proof) == "pass"
    assert _SYNTHETIC not in json.dumps(asdict(proof))


def test_mask_collision_does_not_rewrite_an_unrelated_secret(monkeypatch):
    monkeypatch.setenv("PROOF_GATE_MODE", "hard")
    different = "difFerentTokenValue271828"
    assert len(different) == len(_SYNTHETIC)
    data = _zip({"src/a.py": _assignment(), "src/b.py": _assignment(different)})
    findings = _findings(data)
    # The legacy report groups equal masks, which are not value identities.
    assert len(findings) == 1
    assert findings[0]["occurrence_count"] == 2

    plan = build_fixpack_plan(data, findings)
    assert "src/a.py" in plan.files
    assert "src/b.py" not in plan.files
    proof = _proof(data, plan)
    assert proof.after.evidence["finding_count"] == 1
    assert decide_proof_gate(proof) == "hard_fail"


def test_group_expansion_preserves_documentation_and_test_contexts(monkeypatch):
    monkeypatch.setenv("PROOF_GATE_MODE", "hard")
    data = _zip({
        "src/a.py": _assignment(),
        "src/b.py": _assignment(),
        "tests/test_client.py": _assignment(),
        "docs/example.md": _assignment(),
        "src/comment.py": "# " + _assignment(),
    })
    findings = _findings(data)
    assert len(findings) == 1
    assert findings[0]["occurrence_count"] == 5

    plan = build_fixpack_plan(data, findings)
    assert set(plan.files) == {"src/a.py", "src/b.py", ".env.example"}
    proof = _proof(data, plan)
    assert proof.before.evidence["finding_count"] == 2
    assert proof.after.evidence["finding_count"] == 0
    assert decide_proof_gate(proof) == "pass"


def test_group_expansion_stays_within_recorded_files():
    original = _zip({"src/a.py": _assignment(), "src/b.py": _assignment()})
    findings = _findings(original)
    current = _zip({
        "src/a.py": _assignment(), "src/b.py": _assignment(),
        "src/new.py": _assignment(),
    })
    plan = build_fixpack_plan(current, findings)
    assert "src/new.py" not in plan.files
    assert {"src/a.py", "src/b.py"} <= plan.files.keys()


def test_missing_representative_does_not_guess_from_legacy_mask():
    data = _zip({"src/a.py": _assignment(), "src/b.py": _assignment()})
    findings = _findings(data)
    current = _zip({"src/b.py": _assignment()})
    plan = build_fixpack_plan(current, findings)
    assert not plan.has_changes
    assert len(plan.skipped) == 1
    assert "finding no longer matches" in plan.skipped[0].reason


def test_stored_production_context_cannot_override_fresh_docstring_context():
    data = _zip({"src/example.py": '"""\n' + _assignment() + '"""\n'})
    current = _findings(data)
    assert len(current) == 1
    assert current[0]["context"] == "doc_example"
    # Older audits did not classify generic credentials in docstrings.
    stored = [{**current[0], "context": None, "severity": "high"}]
    plan = build_fixpack_plan(data, stored)
    assert not plan.has_changes
    assert not plan.secret_fixes
    assert len(plan.skipped) == 1
    assert "doc_example on fresh scan" in plan.skipped[0].reason
