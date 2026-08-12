"""The single-repo runner must actually run the shipped pipeline.

Two things have now shipped in this repo that were never called: a rubric
(#239) and a self-cancelling filter (#240). Both looked right on the page and
neither was on any path. So a measurement script gets a test that drives it
end to end rather than one that inspects its source.

The LLM half needs a provider, which a test must not have. That is not a gap:
run_scan degrades to static-only without one, and everything this script owns
-- packing a tree, calling the pipeline, printing a location for every finding
-- is on the static path too.
"""

from __future__ import annotations

import importlib.util
import io
import zipfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "audit_one_repo.py"


def _load():
    spec = importlib.util.spec_from_file_location("audit_one_repo", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "api").mkdir(parents=True)
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text("[core]\n")
    (root / "api" / "routes.py").write_text(
        "@router.get('/items/{item_id}')\n"
        "async def get_item(item_id: int, user=Depends(auth)):\n"
        "    return await db.fetch('SELECT * FROM items WHERE id = ?', item_id)\n"
    )
    # The fixture the static scan is meant to find: an .env.example whose
    # placeholder connection string looks like a credential. That is the point
    # of the file -- without it this test asserts "0 findings printed with a
    # location", which passes on a runner that prints nothing at all.
    (root / ".env.example").write_text(
        "DATABASE_URL=postgres://user:password@localhost/db\n")  # scan-allow: literal placeholder, the input this test scans for
    return root


def test_pack_directory_skips_git_and_keeps_relative_paths(tree: Path):
    mod = _load()
    with zipfile.ZipFile(io.BytesIO(mod.pack_directory(tree))) as zf:
        names = set(zf.namelist())
    assert "api/routes.py" in names
    assert not any(n.startswith(".git/") for n in names), names


def test_run_on_local_tree_prints_a_location_for_every_finding(
    tree: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    # No provider configured: the run must still complete and say so, rather
    # than reporting static-only numbers as if the LLM had spoken.
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("AITUNNEL_API_KEY", raising=False)
    mod = _load()
    assert mod.main([str(tree)]) == 0

    out = capsys.readouterr()
    assert "(local clone)" in out.out
    assert "basis=static_only" in out.out
    assert "no LLM providers configured" in out.err

    # Every finding line carries file:line. A finding without coordinates
    # cannot be graded against a clone, which is the only thing this script
    # exists to support.
    body = out.out.split("=== ", 1)[1]
    count = int(body.split(" findings", 1)[0])
    located = [ln for ln in body.splitlines() if ln.startswith("      ")]
    assert len(located) == count
    assert all(":" in ln for ln in located)
