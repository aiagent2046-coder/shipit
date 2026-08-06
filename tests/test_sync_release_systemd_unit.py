from __future__ import annotations

import os
import stat
import subprocess
import textwrap
from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "scripts"
    / "sync-release-systemd-unit.sh"
)

UNIT_TEXT = """\
[Unit]
Description=Test Fix Pack service

[Service]
Type=oneshot
ExecStart=/bin/true
"""


def _write(path: Path, body: str, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body).lstrip())

    if executable:
        path.chmod(0o755)


def _run(
    tmp_path: Path,
    *,
    previous: str | None = "previous unit\n",
    analyze_exit: int = 0,
    reload_failures: int = 0,
) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    release = tmp_path / "release"
    source = release / "deploy" / "systemd" / "shipit-fixpack.service"
    destination = tmp_path / "etc" / "systemd" / "system" / "shipit-fixpack.service"
    calls = tmp_path / "calls.log"
    reload_count = tmp_path / "reload-count"

    _write(source, UNIT_TEXT)

    if previous is not None:
        _write(destination, previous)

    analyze = tmp_path / "bin" / "systemd-analyze"
    systemctl = tmp_path / "bin" / "systemctl"

    _write(
        analyze,
        """\
        #!/usr/bin/env bash
        set -eu
        printf 'systemd-analyze %s\n' "$*" >> "$CALLS_FILE"
        exit "$ANALYZE_EXIT"
        """,
        executable=True,
    )

    _write(
        systemctl,
        """\
        #!/usr/bin/env bash
        set -eu
        printf 'systemctl %s\n' "$*" >> "$CALLS_FILE"

        if [[ "${1:-}" = "daemon-reload" ]]; then
          count=0

          if [[ -f "$RELOAD_COUNT_FILE" ]]; then
            count="$(cat "$RELOAD_COUNT_FILE")"
          fi

          count=$((count + 1))
          printf '%s\n' "$count" > "$RELOAD_COUNT_FILE"

          if ((count <= RELOAD_FAILURES)); then
            exit 1
          fi
        fi

        exit 0
        """,
        executable=True,
    )

    env = dict(os.environ)
    env.update(
        {
            "SHIPIT_SYSTEMCTL": str(systemctl),
            "SHIPIT_SYSTEMD_ANALYZE": str(analyze),
            "SHIPIT_FIXPACK_UNIT_DEST": str(destination),
            "CALLS_FILE": str(calls),
            "RELOAD_COUNT_FILE": str(reload_count),
            "ANALYZE_EXIT": str(analyze_exit),
            "RELOAD_FAILURES": str(reload_failures),
        }
    )

    result = subprocess.run(
        [str(SCRIPT), "--release", str(release)],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )

    return result, destination, calls


def test_installs_release_unit_and_reloads_systemd(tmp_path: Path) -> None:
    result, destination, calls = _run(tmp_path)

    assert result.returncode == 0, result.stderr
    assert destination.read_text() == UNIT_TEXT
    assert stat.S_IMODE(destination.stat().st_mode) == 0o644

    logged = calls.read_text()
    assert "systemd-analyze verify" in logged
    assert logged.count("systemctl daemon-reload") == 1


def test_failed_verification_preserves_installed_unit(tmp_path: Path) -> None:
    result, destination, calls = _run(tmp_path, analyze_exit=1)

    assert result.returncode != 0
    assert destination.read_text() == "previous unit\n"

    logged = calls.read_text()
    assert "systemd-analyze verify" in logged
    assert "systemctl daemon-reload" not in logged


def test_reload_failure_restores_previous_unit(tmp_path: Path) -> None:
    result, destination, calls = _run(tmp_path, reload_failures=1)

    assert result.returncode != 0
    assert destination.read_text() == "previous unit\n"
    assert "restoring the previously installed unit" in result.stderr
    assert calls.read_text().count("systemctl daemon-reload") == 2


def test_reload_failure_removes_new_file_when_no_previous_unit(
    tmp_path: Path,
) -> None:
    result, destination, calls = _run(
        tmp_path,
        previous=None,
        reload_failures=1,
    )

    assert result.returncode != 0
    assert not destination.exists()
    assert calls.read_text().count("systemctl daemon-reload") == 2
