from __future__ import annotations

import httpx

import app.sandbox_client as sandbox_client
from app.fixpack.verification import (
    VerificationProfile,
    VerificationStep,
)


def _profile() -> VerificationProfile:
    return VerificationProfile(
        ecosystem="node",
        framework="vite",
        image="node:20-slim",
        install_command="npm ci",
        steps=(
            VerificationStep(
                name="build",
                command="npm run build",
                required=True,
            ),
        ),
    )


def _successful_response(
    request: httpx.Request,
) -> httpx.Response:
    return httpx.Response(
        200,
        request=request,
        json={
            "stages": [
                {
                    "name": "install",
                    "status": "passed",
                    "command": "npm ci",
                    "exit_code": 0,
                    "duration_ms": 11,
                    "detail": None,
                },
                {
                    "name": "build",
                    "status": "passed",
                    "command": "npm run build",
                    "exit_code": 0,
                    "duration_ms": 22,
                    "detail": None,
                },
            ]
        },
    )


def _install_mock_client(
    monkeypatch,
    handler,
) -> list[float | None]:
    seen_timeouts: list[float | None] = []

    def factory(
        timeout: float | None = None,
    ) -> httpx.Client:
        seen_timeouts.append(timeout)

        return httpx.Client(
            base_url="http://sandbox-runner",
            transport=httpx.MockTransport(
                handler
            ),
            timeout=(
                timeout
                if timeout is not None
                else 5
            ),
        )

    monkeypatch.setattr(
        sandbox_client,
        "_client",
        factory,
    )

    return seen_timeouts


def test_verification_uses_dedicated_timeout(
    monkeypatch,
):
    monkeypatch.setattr(
        sandbox_client,
        "SANDBOX_RUNNER_TIMEOUT_S",
        123.0,
    )
    monkeypatch.setattr(
        sandbox_client,
        (
            "SANDBOX_RUNNER_"
            "VERIFICATION_TIMEOUT_S"
        ),
        960.0,
    )

    seen = _install_mock_client(
        monkeypatch,
        _successful_response,
    )

    stages = (
        sandbox_client
        .run_verification_profile(
            b"ZIP",
            _profile(),
        )
    )

    assert seen == [960.0]
    assert [
        stage.status
        for stage in stages
    ] == [
        "passed",
        "passed",
    ]


def test_generic_post_preserves_default_timeout(
    monkeypatch,
):
    seen = _install_mock_client(
        monkeypatch,
        lambda request: httpx.Response(
            200,
            request=request,
            json={"ok": True},
        ),
    )

    result = sandbox_client._post(
        "/generic-operation",
        json_body={"value": 1},
    )

    assert result == {"ok": True}

    # None delegates to _client's existing
    # SANDBOX_RUNNER_TIMEOUT_S default.
    assert seen == [None]


def test_verification_read_timeout_fails_closed(
    monkeypatch,
):
    attempts = 0

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        nonlocal attempts
        attempts += 1

        raise httpx.ReadTimeout(
            "verification still running",
            request=request,
        )

    seen = _install_mock_client(
        monkeypatch,
        handler,
    )

    stages = (
        sandbox_client
        .run_verification_profile(
            b"ZIP",
            _profile(),
        )
    )

    assert attempts == 1

    assert seen == [
        sandbox_client
        .SANDBOX_RUNNER_VERIFICATION_TIMEOUT_S
    ]

    assert all(
        stage.status == "unavailable"
        for stage in stages
    )

    assert all(
        "sandbox runner unavailable"
        in (stage.detail or "")
        for stage in stages
    )
