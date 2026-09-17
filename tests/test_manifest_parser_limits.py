"""Boundary acceptance and isolated failures for bounded manifest parsing.

Small fixtures exercise both sides of a limit; a separate selected sentinel
must survive every refusal. No package manager or project code is executed.
"""
from __future__ import annotations

import io
import json
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

from app.sca import lockfiles, resolved_locks


PNPM = """lockfileVersion: '9.0'
importers: {}
packages:
  widget@1.0.0:
    resolution:
      integrity: synthetic-integrity
snapshots:
  widget@1.0.0: {}
"""
SENTINEL = "sentinel-package==7.8.9\n"
SENTINEL_PATH = "z/requirements.txt"


def _archive(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, content in files.items():
            archive.writestr(path, content)
    return output.getvalue()


def _inventory(path, content):
    return lockfiles.collect_dependency_inventory(_archive({
        path: content, SENTINEL_PATH: SENTINEL,
    }))


def _pins(inventory):
    return {(dep.ecosystem, dep.name, dep.version) for dep in inventory.dependencies}


SENTINEL_PIN = ("PyPI", "sentinel-package", "7.8.9")


@pytest.mark.parametrize("path,content,ecosystem", [
    ("package-lock.json", json.dumps({
        "lockfileVersion": 3, "notes": "é", "packages": {
            "node_modules/widget": {"version": "1.0.0"},
        },
    }, ensure_ascii=False), "npm"),
    ("pnpm-lock.yaml", "# é\n" + PNPM, "npm"),
    ("requirements.txt", "widget==1.0.0\n# é\n", "PyPI"),
    ("poetry.lock", '# é\n[[package]]\nname="widget"\nversion="1.0.0"\n', "PyPI"),
    ("uv.lock", '# é\nversion=1\n[[package]]\nname="widget"\nversion="1.0.0"\n'
                'source={registry="https://pypi.org/simple"}\n', "PyPI"),
])
def test_file_size_boundary_uses_utf8_bytes_and_continues_after_oversized(monkeypatch, path, content, ecosystem):
    # Multibyte content makes an accidental character-count bound observable.
    # A reduced byte limit keeps these fixtures cheap without changing the
    # production boundary comparison or parser dispatch.
    limit = 256
    monkeypatch.setattr(lockfiles, "MAX_LOCKFILE_BYTES", limit)
    encoded = content.encode("utf-8")
    assert len(encoded) < limit
    at_limit = encoded + b" " * (limit - len(encoded))
    assert len(at_limit) == limit and len(at_limit.decode("utf-8")) < limit
    accepted = _inventory(path, at_limit)
    assert accepted.incomplete_manifests == {}
    assert _pins(accepted) == {SENTINEL_PIN, (ecosystem, "widget", "1.0.0")}
    assert path in accepted.manifests

    refused = _inventory(path, at_limit + b" ")
    assert refused.incomplete_manifests == {path: "oversized"}
    assert _pins(refused) == {SENTINEL_PIN}
    assert path not in refused.manifests


def test_yaml_node_budget_accepts_exact_boundary_and_refuses_one_extra_node(monkeypatch):
    # The PNPM fixture has 17 YAML nodes: the root mapping plus its mapping
    # keys, scalar values and nested/empty mappings. Lowering the allowed
    # count by one makes the same valid document exceed the budget by one.
    monkeypatch.setattr(resolved_locks, "MAX_YAML_NODES", 17)
    accepted = _inventory("pnpm-lock.yaml", PNPM)
    assert accepted.incomplete_manifests == {}
    assert _pins(accepted) == {SENTINEL_PIN, ("npm", "widget", "1.0.0")}

    monkeypatch.setattr(resolved_locks, "MAX_YAML_NODES", 16)
    refused = _inventory("pnpm-lock.yaml", PNPM)
    assert refused.incomplete_manifests == {"pnpm-lock.yaml": "parser_limit"}
    assert _pins(refused) == {SENTINEL_PIN}


def test_yaml_depth_boundary_keeps_valid_pins_and_isolates_one_level_over():
    # Root mapping is depth 1; the metadata scalar below N nested sequences
    # is at N + 2. The real documented budget is small enough to exercise.
    nesting = resolved_locks.MAX_YAML_DEPTH - 2
    assert 1 <= nesting <= 100
    accepted = _inventory("pnpm-lock.yaml", PNPM + "metadata: " + "[" * nesting + "0" + "]" * nesting)
    assert accepted.incomplete_manifests == {}
    assert _pins(accepted) == {SENTINEL_PIN, ("npm", "widget", "1.0.0")}

    refused = _inventory("pnpm-lock.yaml", PNPM + "metadata: " + "[" * (nesting + 1) + "0" + "]" * (nesting + 1))
    assert refused.incomplete_manifests == {"pnpm-lock.yaml": "parser_limit"}
    assert _pins(refused) == {SENTINEL_PIN}


@pytest.mark.parametrize("content", [
    # A duplicate below the top level must not silently pick a provenance.
    PNPM.replace("integrity: synthetic-integrity", "integrity: first\n      integrity: second"),
    # Reject YAML merge syntax even without an alias event: the map contains
    # a merge-tagged key whose meaning is not the literal key '<<'.
    PNPM.replace("integrity: synthetic-integrity", "<<: {integrity: synthetic-integrity}"),
    # A finite shared alias is also unsupported, not just cyclic aliases.
    PNPM + "metadata: &shared [1, 2]\ncopy: *shared\n",
])
def test_yaml_nested_duplicates_merges_and_noncyclic_aliases_do_not_hide_gaps(content):
    inventory = _inventory("pnpm-lock.yaml", content)
    assert inventory.incomplete_manifests == {"pnpm-lock.yaml": "malformed"}
    assert _pins(inventory) == {SENTINEL_PIN}


def test_failed_selected_manifest_still_occupies_its_selection_slot(monkeypatch):
    monkeypatch.setattr(lockfiles, "MAX_LOCKFILES", 3)
    # Deliberately opposite archive order: selection is root-first, and a
    # parse failure must not silently substitute an unselected deeper file.
    inventory = lockfiles.collect_dependency_inventory(_archive({
        "c/requirements.txt": "overflow-package==3.0.0\n",
        "b/requirements.txt": "selected-package==2.0.0\n",
        "a/poetry.lock": "[",
        "requirements.txt": SENTINEL,
    }))
    assert inventory.manifests == ["requirements.txt", "a/poetry.lock", "b/requirements.txt"]
    assert inventory.incomplete_manifests == {"a/poetry.lock": "malformed", "c/requirements.txt": "truncated"}
    assert _pins(inventory) == {SENTINEL_PIN, ("PyPI", "selected-package", "2.0.0")}


def test_oversized_file_does_not_displace_a_parseable_selected_manifest(monkeypatch):
    monkeypatch.setattr(lockfiles, "MAX_LOCKFILES", 2)
    monkeypatch.setattr(lockfiles, "MAX_LOCKFILE_BYTES", 128)
    inventory = lockfiles.collect_dependency_inventory(_archive({
        "package-lock.json": b" " * 129,
        "requirements.txt": SENTINEL,
        "app/requirements.txt": "selected-package==2.0.0\n",
    }))
    assert inventory.manifests == ["requirements.txt", "app/requirements.txt"]
    assert inventory.incomplete_manifests == {"package-lock.json": "oversized"}
    assert _pins(inventory) == {SENTINEL_PIN, ("PyPI", "selected-package", "2.0.0")}


@pytest.mark.parametrize("path", ["package-lock.json", "poetry.lock", "uv.lock"])
def test_native_parser_recursion_limit_is_reported_and_does_not_drop_sentinel(path):
    # These fixed payloads are <= 21 KB and exceed the native JSON/TOML
    # parser recursion bounds on the supported CPython runtime. This is not
    # a guessed application depth limit. A subprocess bounds a regression
    # that accidentally turns the parser refusal into a hang or process crash.
    script = r'''
import io
import json
import sys
import zipfile
from app.sca.lockfiles import collect_dependency_inventory

path = sys.argv[1]
if path == "package-lock.json":
    body = ('{"lockfileVersion":3,"packages":{"node_modules/widget":{"version":"1.0.0"}},"metadata":'
            + '[' * 10000 + '0' + ']' * 10000 + '}')
else:
    body = 'metadata=' + '[' * 5000 + '0' + ']' * 5000 + '\n'
    if path == "uv.lock":
        body = 'version=1\n' + body
    body += '[[package]]\nname="widget"\nversion="1.0.0"\n'
    if path == "uv.lock":
        body += 'source={registry="https://pypi.org/simple"}\n'
assert len(body.encode()) < 21000
output = io.BytesIO()
with zipfile.ZipFile(output, "w") as archive:
    archive.writestr(path, body)
    archive.writestr("z/requirements.txt", "sentinel-package==7.8.9\n")
inventory = collect_dependency_inventory(output.getvalue())
print(json.dumps({
    "gaps": inventory.incomplete_manifests,
    "pins": [[dep.ecosystem, dep.name, dep.version] for dep in inventory.dependencies],
}))
'''
    result = subprocess.run(
        [sys.executable, "-c", script, path], cwd=Path(__file__).resolve().parents[1],
        capture_output=True, text=True, timeout=15, check=True,
    )
    assert json.loads(result.stdout) == {
        "gaps": {path: "parser_limit"},
        "pins": [list(SENTINEL_PIN)],
    }
