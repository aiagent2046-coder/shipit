from __future__ import annotations

import shlex
from pathlib import Path

import app.sandbox_client as sandbox_client


UNIT_PATH = Path(
    "deploy/systemd/shipit-fixpack.service"
)

VERIFICATION_REQUESTS_PER_JOB = 2
PROCESSING_OVERHEAD_SECONDS = 120
SYSTEMD_MARGIN_SECONDS = 120


def _directive(
    unit: str,
    name: str,
) -> str:
    prefix = f"{name}="

    matches = [
        line[len(prefix):]
        for line in unit.splitlines()
        if line.startswith(prefix)
    ]

    assert len(matches) == 1

    return matches[0]


def test_fixpack_unit_covers_one_verified_build_job():
    unit = UNIT_PATH.read_text(
        encoding="utf-8"
    )

    command = shlex.split(
        _directive(unit, "ExecStart")
    )

    assert command[:3] == [
        (
            "/opt/shipit/deploy/scripts/"
            "call-internal-endpoint.sh"
        ),
        "/internal/fixpack/process-paid",
        "FIXPACK_PROCESS_TOKEN",
    ]

    assert len(command) == 4

    curl_timeout = int(command[3])

    expected_curl_timeout = int(
        VERIFICATION_REQUESTS_PER_JOB
        * sandbox_client
        .SANDBOX_RUNNER_VERIFICATION_TIMEOUT_S
        + PROCESSING_OVERHEAD_SECONDS
    )

    assert curl_timeout == expected_curl_timeout
    assert curl_timeout == 2040


def test_systemd_deadline_exceeds_curl_deadline():
    unit = UNIT_PATH.read_text(
        encoding="utf-8"
    )

    command = shlex.split(
        _directive(unit, "ExecStart")
    )

    curl_timeout = int(command[3])

    systemd_timeout = int(
        _directive(
            unit,
            "TimeoutStartSec",
        )
    )

    assert systemd_timeout == (
        curl_timeout
        + SYSTEMD_MARGIN_SECONDS
    )

    assert systemd_timeout == 2160
