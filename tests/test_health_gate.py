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


# --- unreachable is not unhealthy ---
#
# An external watchdog on this service sent "DRYDOCK ALERT - health endpoint
# unreachable after 3 attempts: URLError: Temporary failure in name
# resolution" -- a report that production was down, from a host that could not
# resolve DNS, while production was serving fine. The gate had the same
# collapse: every failure printed the same verdict, so a reader could not tell
# a broken release from a broken network path.


def test_a_transport_failure_is_marked_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DNS, refused connections and timeouts all arrive as OSError and say
    nothing about the application."""
    import urllib.error

    def refuse(request, timeout):  # noqa: ANN001, ARG001
        raise urllib.error.URLError("[Errno -3] Temporary failure in name resolution")

    monkeypatch.setattr(health_gate.urllib.request, "urlopen", refuse)

    with pytest.raises(health_gate.ProbeFailure) as caught:
        health_gate.fetch_json("http://local/healthz", timeout=1)

    assert caught.value.reachable is False


def test_an_http_error_is_not_marked_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 503 means the application answered. That IS a claim about its health,
    and it must not be filed under "could not get there" -- HTTPError is a
    subclass of OSError, so the distinction is the order of the excepts and
    would vanish silently if they were merged."""
    import io as _io
    import urllib.error

    def fail(request, timeout):  # noqa: ANN001, ARG001
        raise urllib.error.HTTPError(
            "http://local/healthz", 503, "Service Unavailable", {},
            _io.BytesIO(b"down for maintenance"),
        )

    monkeypatch.setattr(health_gate.urllib.request, "urlopen", fail)

    with pytest.raises(health_gate.ProbeFailure) as caught:
        health_gate.fetch_json("http://local/healthz", timeout=1)

    assert caught.value.reachable is True
    assert "503" in str(caught.value)


def test_a_bad_payload_is_not_marked_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`db: false` is the application telling the truth about itself."""
    monkeypatch.setattr(
        health_gate, "fetch_json",
        lambda target, timeout: (200, {"status": "ready", "db": False}),
    )

    with pytest.raises(health_gate.ProbeFailure) as caught:
        health_gate.check_once("http://local", timeout=1)

    assert caught.value.reachable is True


def test_the_verdict_names_which_of_the_two_failed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The line an operator actually reads. Both verdicts must send them to a
    different place, or the distinction above buys nothing."""
    monkeypatch.setattr(health_gate.time, "sleep", lambda _: None)

    for reachable, expected, forbidden in (
        (False, "could not reach", "answered"),
        (True, "answered and the answer was unhealthy", "could not reach"),
    ):
        def fake(base_url, *, timeout, _r=reachable):  # noqa: ANN001, ARG001
            raise health_gate.ProbeFailure("boom", reachable=_r)

        monkeypatch.setattr(health_gate, "check_once", fake)

        assert health_gate.wait_for_health(
            "http://local", attempts=2, interval=0,
            timeout=1, consecutive=1,
        ) is False

        out = capsys.readouterr().out
        assert expected in out, (reachable, out)
        assert forbidden not in out.split("FAILED", 1)[-1], (reachable, out)
