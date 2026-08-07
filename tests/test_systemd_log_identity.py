"""Guards that every shipped unit running a ``configure_logging()`` entrypoint
names itself in its log lines.

Regression cover for a real prod finding: no unit set ``SHIPIT_SERVICE``, so
every JSON log line from the API, the audit worker and the alerter carried
``"service": "unknown"`` and one journald query could not tell them apart. The
worker additionally never loaded ``/opt/shipit/.release-env``, so its lines said
``"release": "unknown"`` while the API's carried the real sha.

Cheap text checks, no systemd required; ``systemd-analyze verify`` in
production-ci.yml covers the syntax side.
"""

from __future__ import annotations

from pathlib import Path

import pytest

SYSTEMD = Path(__file__).resolve().parent.parent / "deploy" / "systemd"

# Unit file -> the SHIPIT_SERVICE value it must declare. Exactly the units whose
# ExecStart runs a Python entrypoint that calls app.logging_config.configure_logging
# (app/main.py, app/worker/main.py, app/alerts.py). shipit.service itself is
# distro-managed and not in this repo, so the API's value lives in its drop-in.
# Timer-driven units shell out to call-internal-endpoint.sh and log nothing.
LOGGING_UNITS = {
    "shipit.service.d/10-production-operations.conf": "shipit-api",
    "shipit-audit-worker.service": "shipit-audit-worker",
    "shipit-alert@.service": "shipit-alert",
}


def _service_lines(path: Path) -> list[str]:
    """Non-comment [Service] lines. Parsed from raw text rather than with
    configparser because units repeat ``Environment=``/``EnvironmentFile=`` and
    configparser would collapse the duplicate keys to just the last one."""
    lines: list[str] = []
    in_service = False
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_service = stripped == "[Service]"
            continue
        if in_service and stripped and not stripped.startswith("#"):
            lines.append(stripped)
    return lines


@pytest.mark.parametrize(("unit", "expected"), sorted(LOGGING_UNITS.items()))
def test_logging_unit_declares_its_service_name(unit: str, expected: str) -> None:
    lines = _service_lines(SYSTEMD / unit)
    assert f"Environment=SHIPIT_SERVICE={expected}" in lines, (
        f"{unit} must set Environment=SHIPIT_SERVICE={expected}; without it every "
        'JSON log line from this process reads "service": "unknown".'
    )
    # systemd applies env directives in file order, so an EnvironmentFile= loaded
    # afterwards would win over the value above.
    assignment = lines.index(f"Environment=SHIPIT_SERVICE={expected}")
    later_files = [line for line in lines[assignment + 1 :] if line.startswith("EnvironmentFile=")]
    assert not later_files, (
        f"{unit} loads {later_files} after Environment=SHIPIT_SERVICE=, which would "
        "let a stray key in that file override the unit's own name."
    )


@pytest.mark.parametrize("unit", sorted(LOGGING_UNITS))
def test_logging_unit_loads_the_release_env(unit: str) -> None:
    """The deploy script rewrites /opt/shipit/.release-env on every release. The
    leading dash keeps a never-deployed host bootable, and must stay."""
    assert "EnvironmentFile=-/opt/shipit/.release-env" in _service_lines(SYSTEMD / unit), (
        f"{unit} must load /opt/shipit/.release-env optionally (leading dash) or "
        'its log lines carry "release": "unknown" while other units report the sha.'
    )
