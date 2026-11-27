"""Contract tests for strict zero-debt architecture size limits.

Every directory in app/, scripts/, and tests/ (outside detector/fixture corpora)
must stay <= MOST_MEMBERS entries, every Python file must stay <= MOST_LINES
lines, and neither --update-allow nor .architecture-lint-allow.json may exist to
suppress violations.
"""
from __future__ import annotations

from pathlib import Path
import pytest

import scripts.check_architecture_lints as cal

REPO_ROOT = Path(__file__).resolve().parents[3]


def _tree(root: Path, layout: dict[str, int]) -> None:
    """Create files from {relative/path.py: line_count} and marker directories
    from {relative/dir/with_file/: 1}."""
    for rel, lines in layout.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if rel.endswith("/"):
            (path / "placeholder.py").write_text("x = 1\n", encoding="utf-8")
        else:
            path.write_text("x = 1\n" * lines, encoding="utf-8")


def test_long_file_fails_unconditionally(tmp_path: Path) -> None:
    _tree(tmp_path, {"app/db.py": cal.MOST_LINES + 1})
    problems = cal.check(cal.measure(tmp_path), root=tmp_path)
    assert problems == [
        f"long-file: app/db.py ({cal.MOST_LINES + 1} lines; limit is "
        f"<= {cal.MOST_LINES}, found lines > {cal.MOST_LINES}) -- "
        "split or narrow without allow-list exemptions"
    ]
    assert cal.main(["--root", str(tmp_path)]) == 1


def test_wide_directory_fails_unconditionally(tmp_path: Path) -> None:
    files = {f"app/mod{i}.py": 1 for i in range(cal.MOST_MEMBERS + 1)}
    _tree(tmp_path, files)
    problems = cal.check(cal.measure(tmp_path), root=tmp_path)
    assert problems == [
        f"wide-directory: app ({cal.MOST_MEMBERS + 1} members; limit is "
        f"<= {cal.MOST_MEMBERS}, found members > {cal.MOST_MEMBERS}) -- "
        "split or narrow without allow-list exemptions"
    ]
    assert cal.main(["--root", str(tmp_path)]) == 1


def test_reintroducing_allow_file_is_forbidden(tmp_path: Path) -> None:
    _tree(tmp_path, {"app/ok.py": 10})
    (tmp_path / cal.FORBIDDEN_ALLOW_FILE).write_text("{}", encoding="utf-8")
    problems = cal.check(cal.measure(tmp_path), root=tmp_path)
    assert problems == [
        f"FORBIDDEN allow-file: {cal.FORBIDDEN_ALLOW_FILE} exists -- "
        "architecture size limits enforce strict zero debt; delete it"
    ]
    assert cal.main(["--root", str(tmp_path)]) == 1


def test_update_allow_flag_is_rejected(tmp_path: Path) -> None:
    _tree(tmp_path, {"app/ok.py": 10})
    with pytest.raises(SystemExit) as exc:
        cal.main(["--root", str(tmp_path), "--update-allow"])
    assert exc.value.code == 2


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
    assert cal.main(["--root", str(tmp_path)]) == 0


def test_live_repository_satisfies_strict_zero_debt() -> None:
    assert not (REPO_ROOT / cal.FORBIDDEN_ALLOW_FILE).exists()
    assert cal.measure(REPO_ROOT) == {"long_file": {}, "wide_directory": {}}
    assert cal.main(["--root", str(REPO_ROOT)]) == 0
