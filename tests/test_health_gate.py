from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "scripts"
    / "health_gate.py"
)

SPEC = importlib.util.spec_from_file_location(
    "shipit_health_gate",
    MODULE_PATH,
)

assert SPEC is not None
assert SPEC.loader is not None

health_gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = health_gate
SPEC.loader.exec_module(health_gate)


@pytest.mark.parametrize(
    ("url", "payload"),
    [
        (
            "http://local/healthz",
            {"status": "ok"},
        ),
        (
            "http://local/readyz",
            {
                "status": "ready",
                "db": True,
            },
        ),
        (
            "http://local/health",
            {"db": True},
        ),
    ],
)
def test_check_once_accepts_expected_payloads(
    monkeypatch: pytest.MonkeyPatch,
    url: str,
    payload: dict[str, object],
) -> None:
    responses = {
        "http://local/healthz": (
            200,
            {"status": "ok"},
        ),
        "http://local/readyz": (
            200,
            {
                "status": "ready",
                "db": True,
            },
        ),
        "http://local/health": (
            200,
            {"db": True},
        ),
    }

    monkeypatch.setattr(
        health_gate,
        "fetch_json",
        lambda target, timeout: responses[target],
    )

    health_gate.check_once(
        "http://local",
        timeout=1,
    )


def test_check_once_rejects_database_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = {
        "http://local/healthz": (
            200,
            {"status": "ok"},
        ),
        "http://local/readyz": (
            200,
            {
                "status": "ready",
                "db": False,
            },
        ),
    }

    monkeypatch.setattr(
        health_gate,
        "fetch_json",
        lambda target, timeout: responses[target],
    )

    with pytest.raises(
        health_gate.ProbeFailure,
        match="db=True",
    ):
        health_gate.check_once(
            "http://local",
            timeout=1,
        )


def test_wait_requires_consecutive_successes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcomes = iter(
        [
            health_gate.ProbeFailure("booting"),
            None,
            None,
            None,
        ]
    )

    def fake_check_once(
        base_url: str,
        *,
        timeout: float,
    ) -> None:
        outcome = next(outcomes)

        if isinstance(
            outcome,
            health_gate.ProbeFailure,
        ):
            raise outcome

    monkeypatch.setattr(
        health_gate,
        "check_once",
        fake_check_once,
    )
    monkeypatch.setattr(
        health_gate.time,
        "sleep",
        lambda _: None,
    )

    assert health_gate.wait_for_health(
        "http://local",
        attempts=4,
        interval=0,
        timeout=1,
        consecutive=3,
    )
