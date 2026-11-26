"""Contract tests for the architecture size-limit ratchet.

The allow list must behave like the import-linter baseline: known debt is
kept quiet, NEW debt fails, and entries that no longer describe reality
fail too, so the list cannot rot behind refactors.
"""
from __future__ import annotations

import json
from pathlib import Path

import scripts.check_architecture_lints as cal


def _tree(root: Path, layout: dict[str, int]) -> None:
    """Create files from {relative/path.py: line_count} and empty marker
    directories from {relative/dir/with_file: 1}."""
    for rel, lines in layout.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if rel.endswith("/"):
            (path / "placeholder.py").write_text("x = 1\n", encoding="utf-8")
        else:
            path.write_text("x = 1\n" * lines, encoding="utf-8")


def test_a_new_long_file_fails_the_check(tmp_path: Path) -> None:
    _tree(tmp_path, {"app/db.py": cal.MOST_LINES + 1})
    current = cal.measure(tmp_path)
    problems = cal.check(current, {"long_file": {}, "wide_directory": {}})
    assert problems == [
        f"NEW long-file: app/db.py ({cal.MOST_LINES + 1} lines) -- refit under "
        "the limit or record it with --update-allow"]


def test_a_new_wide_directory_fails_the_check(tmp_path: Path) -> None:
    files = {f"app/mod{i}.py": 1 for i in range(cal.MOST_MEMBERS + 1)}
    _tree(tmp_path, files)
    current = cal.measure(tmp_path)
    problems = cal.check(current, {"long_file": {}, "wide_directory": {}})
    assert problems == [
        f"NEW wide-directory: app ({cal.MOST_MEMBERS + 1} members) -- refit "
        "under the limit or record it with --update-allow"]


def test_known_debt_is_kept_and_a_stale_entry_fails(tmp_path: Path) -> None:
    _tree(tmp_path, {"app/db.py": cal.MOST_LINES + 1})
    allowed = {"long_file": {"app/db.py": 4155, "app/gone.py": 2100},
               "wide_directory": {}}
    problems = cal.check(cal.measure(tmp_path), allowed)
    assert problems == [
        "STALE long-file: app/gone.py is in the allow list but no longer over "
        "the limit -- remove it with --update-allow"]


def test_an_allowed_path_may_grow_without_a_new_complaint(tmp_path: Path) -> None:
    _tree(tmp_path, {"app/db.py": cal.MOST_LINES + 500})
    allowed = {"long_file": {"app/db.py": cal.MOST_LINES + 1}, "wide_directory": {}}
    assert cal.check(cal.measure(tmp_path), allowed) == []


def test_update_allow_records_the_current_measurement(tmp_path: Path, monkeypatch) -> None:
    _tree(tmp_path, {"app/db.py": cal.MOST_LINES + 1})
    monkeypatch.setattr(cal, "ALLOW_FILE", ".allow.json")
    import sys
    monkeypatch.setattr(sys, "argv", ["check_architecture_lints.py",
                                      "--root", str(tmp_path), "--update-allow"])
    assert cal.main() == 0
    recorded = json.loads((tmp_path / ".allow.json").read_text(encoding="utf-8"))
    assert recorded == {"long_file": {"app/db.py": cal.MOST_LINES + 1},
                        "wide_directory": {}}
    monkeypatch.setattr(sys, "argv", ["check_architecture_lints.py",
                                      "--root", str(tmp_path)])
    assert cal.main() == 0


def test_detector_corpora_are_not_wide_directories_but_still_count_long_files(
        tmp_path: Path) -> None:
    files = {f"tests/detectors/rule/positive/case{i}.py": 1
             for i in range(cal.MOST_MEMBERS + 5)}
    files["tests/detectors/rule/positive/huge.py"] = cal.MOST_LINES + 1
    _tree(tmp_path, files)
    current = cal.measure(tmp_path)
    assert current["wide_directory"] == {}
    assert current["long_file"] == {
        "tests/detectors/rule/positive/huge.py": cal.MOST_LINES + 1}


def test_pycache_does_not_count_towards_a_directory(tmp_path: Path) -> None:
    files = {f"app/mod{i}.py": 1 for i in range(cal.MOST_MEMBERS)}
    _tree(tmp_path, files)
    cache = tmp_path / "app" / "__pycache__"
    cache.mkdir()
    for i in range(5):
        (cache / f"mod{i}.cpython-312.pyc").write_bytes(b"\x00")
    assert cal.measure(tmp_path)["wide_directory"] == {}
