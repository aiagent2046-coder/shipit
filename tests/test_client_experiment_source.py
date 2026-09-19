"""Check source drift independently of Docker and runtime scenario fixtures."""

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from scripts.cumora_experiment import execute
from scripts.cumora_experiment.prepare import digest, encoded, tree_entries


@pytest.fixture
def source(tmp_path):
    work = tmp_path / "work"
    root = work / "source"
    (root / "server/src/api").mkdir(parents=True)
    (root / "server/src/api/router.ts").write_text("export const router = {};\n")
    (root / "server/src/auth.ts").write_text("export const requireCompany = true;\n")
    manifest = encoded(tree_entries(root))
    (work / "source-manifest.json").write_bytes(manifest)
    return work, digest(manifest)


def test_source_drift_prevents_build_and_triggers_cleanup(source, tmp_path, monkeypatch):
    work, source_hash = source
    (work / "source/server/src/auth.ts").write_text("export const requireCompany = false;\n")
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"variants": {"baseline": {
        "run_id": "12345678-1234-4234-8234-123456789012", "tree_sha256": source_hash,
    }}}))
    calls = []

    def command(args, seconds, path, **kwargs):
        calls.append(args)
        Path(path).write_text("")
        return 0

    monkeypatch.setattr(execute, "bounded", command)
    output = tmp_path / "output"
    assert execute.execute(work, output, "baseline", plan) == 2
    assert not any("build" in args or "up" in args for args in calls)
    assert any("down" in args for args in calls)
    receipt = json.loads((output / "execution.json").read_text())
    assert receipt["error"] == "prepared_source_tree_changed"
    assert receipt["status"] == "unavailable"


@pytest.mark.parametrize("mutation", [None, "changed", "missing"])
def test_image_source_verifier_checks_non_router_file(source, mutation):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for the Docker-independent source verifier")
    work, source_hash = source
    if mutation == "changed":
        (work / "source/server/src/auth.ts").write_text("export const requireCompany = false;\n")
    elif mutation == "missing":
        (work / "source/server/src/auth.ts").unlink()
    helper = Path(execute.__file__).with_name("verify-source.mjs")
    result = subprocess.run(
        [node, str(helper), str(work / "source"), str(work / "source-manifest.json"), source_hash],
        capture_output=True, text=True, timeout=10,
    )
    if mutation is None:
        assert result.returncode == 0
        assert result.stdout == source_hash + "\n"
    else:
        assert result.returncode == 1
        assert result.stdout == ""
        assert "Source verification failed" in result.stderr


def test_image_source_verifier_rejects_changed_manifest(source):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for the Docker-independent source verifier")
    work, source_hash = source
    # A changed manifest cannot excuse missing/changed original source files.
    (work / "source-manifest.json").write_text("{}\n")
    helper = Path(execute.__file__).with_name("verify-source.mjs")
    result = subprocess.run(
        [node, str(helper), str(work / "source"), str(work / "source-manifest.json"), source_hash],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 1
    assert result.stdout == ""
    assert "source manifest identity mismatch" in result.stderr
