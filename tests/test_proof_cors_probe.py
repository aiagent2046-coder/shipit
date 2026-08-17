"""Status table and safety rules for the runtime CORS probe (P1).

No docker: `verify`, `fetch` and `stop` are injected, which is the whole
reason run_cors_probe takes them. What is pinned here is the mapping from
"what happened on the stand" to "what we are allowed to claim", because that
mapping is where this feature would quietly become the defect the project has
fixed three times (#22, #27, #35).

The rule that matters most: a workspace that did not build, or never answered
200, produces `error` — never `failure`. `failure` renders as "проба не
подтвердила" and reads as safety to anyone skimming; a stand that never came
up has said nothing about the application at all.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.proof.compare import build_proof_report
from app.proof.cors_oracle import PROBE_ORIGIN
from app.proof.cors_probe import TEMPLATE_ID, run_cors_probe


class _Boot:
    """Stand-in for verify_deploy_pack's SandboxResult."""

    def __init__(self, ok: bool, detail: str = "",
                 container: str | None = "c1", image_tag: str | None = "i1"):
        self.ok = ok
        self.detail = detail
        self.container = container
        self.image_tag = image_tag


def _verify(result: _Boot | Exception):
    def _fn(*_a, **_k):
        if isinstance(result, Exception):
            raise result
        return result
    return _fn


def _headers(**kw: str):
    def _fn(*_a, **_k):
        return kw
    return _fn


def _probe(verify, fetch, stopped: list | None = None):
    def _stop(container, image_tag):
        if stopped is not None:
            stopped.append((container, image_tag))
    return run_cors_probe(
        Path("/nonexistent"),
        host_port=21000, container_port=8000,
        verify=verify, fetch=fetch, stop=_stop,
    )


# --- the status table -------------------------------------------------------

def test_reflection_with_credentials_is_a_confirmed_exploit() -> None:
    attempt = _probe(
        _verify(_Boot(True, "HTTP 200 on /")),
        _headers(**{
            "Access-Control-Allow-Origin": PROBE_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        }),
    )
    assert attempt.status == "success"
    assert attempt.success is True
    assert attempt.template_id == TEMPLATE_ID
    assert attempt.evidence["reason"] == "credentialed_reflection"


def test_a_booted_app_that_refuses_the_origin_is_a_failure_not_an_error() -> None:
    """'We checked and the attack did not work' is a real, useful answer —
    the only one of the negative outcomes that is."""
    attempt = _probe(
        _verify(_Boot(True, "HTTP 200 on /")),
        _headers(**{"Content-Type": "application/json"}),
    )
    assert attempt.status == "failure"
    assert attempt.success is False
    assert attempt.evidence["reason"] == "no_cors_headers"


def test_a_build_that_failed_is_an_error_never_a_failure() -> None:
    """The load-bearing case. `failure` would render as 'проба не
    подтвердила' and read as safety; a stand that never came up has said
    nothing about the app."""
    attempt = _probe(
        _verify(_Boot(False, "docker build failed")),
        _headers(),
    )
    assert attempt.status == "error"
    assert attempt.success is False
    assert "стенд не поднялся" in attempt.detail
    assert attempt.evidence["boot_detail"] == "docker build failed"


def test_an_app_that_never_answered_200_is_an_error() -> None:
    attempt = _probe(
        _verify(_Boot(False, "never returned 200 on / within 60s")),
        _headers(),
    )
    assert attempt.status == "error"
    assert attempt.success is False


def test_a_sandbox_that_raised_is_an_error() -> None:
    attempt = _probe(_verify(RuntimeError("docker socket gone")), _headers())
    assert attempt.status == "error"
    assert "RuntimeError" in attempt.detail


def test_a_probe_request_that_failed_is_an_error_not_a_failure() -> None:
    """The app booted but the request did not complete. We learned nothing;
    saying 'did not reproduce' here would be inventing a clean result."""
    def _boom(*_a, **_k):
        raise TimeoutError("read timeout")

    attempt = _probe(_verify(_Boot(True, "HTTP 200 on /")), _boom)
    assert attempt.status == "error"
    assert "TimeoutError" in attempt.detail


@pytest.mark.parametrize("boot_ok", [True, False])
def test_every_outcome_is_one_of_the_four_declared_statuses(boot_ok) -> None:
    attempt = _probe(_verify(_Boot(boot_ok, "d")), _headers())
    assert attempt.status in ("success", "failure", "skipped", "error")


# --- teardown ---------------------------------------------------------------

def test_the_container_is_torn_down_after_a_successful_probe() -> None:
    stopped: list = []
    _probe(
        _verify(_Boot(True, "up", container="c9", image_tag="i9")),
        _headers(**{
            "Access-Control-Allow-Origin": PROBE_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        }),
        stopped,
    )
    assert stopped == [("c9", "i9")]


def test_the_container_is_torn_down_even_when_the_probe_raises() -> None:
    """A leaked container holds a port and a customer's running code. The
    teardown is in `finally` for this case, not the happy one."""
    stopped: list = []

    def _boom(*_a, **_k):
        raise ConnectionError("refused")

    _probe(_verify(_Boot(True, "up", container="c9", image_tag="i9")),
           _boom, stopped)
    assert stopped == [("c9", "i9")]


def test_a_teardown_failure_does_not_swallow_the_verdict() -> None:
    def _bad_stop(_c, _i):
        raise OSError("docker unreachable")

    attempt = run_cors_probe(
        Path("/nonexistent"), host_port=21000, container_port=8000,
        verify=_verify(_Boot(True, "up")),
        fetch=_headers(**{
            "Access-Control-Allow-Origin": PROBE_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        }),
        stop=_bad_stop,
    )
    assert attempt.status == "success"


# --- safety -----------------------------------------------------------------

def test_the_probe_only_ever_addresses_loopback() -> None:
    """A repository that could steer this at an address of its choosing would
    turn the runner into an SSRF relay against its own network. The URL is
    built from the port we published and nothing else — asserted against the
    real _default_fetch, not the injected one."""
    import app.proof.cors_probe as probe_mod

    seen: dict = {}

    class _Resp:
        headers = {"x": "y"}

    def _fake_get(url, **kwargs):
        seen["url"] = url
        seen["headers"] = kwargs.get("headers")
        return _Resp()

    import sys
    import types as pytypes
    fake_httpx = pytypes.ModuleType("httpx")
    fake_httpx.get = _fake_get  # type: ignore[attr-defined]
    original = sys.modules.get("httpx")
    sys.modules["httpx"] = fake_httpx
    try:
        probe_mod._default_fetch(21234, "/", PROBE_ORIGIN)
    finally:
        if original is not None:
            sys.modules["httpx"] = original
        else:
            del sys.modules["httpx"]

    assert seen["url"] == "http://127.0.0.1:21234/"
    assert seen["headers"]["Origin"] == PROBE_ORIGIN


def test_the_probe_sends_a_credential() -> None:
    """Without a cookie the probe under-reports, and a real container proved
    it: Starlette 0.40 (what fastapi 0.115 pulls) reflects the caller's Origin
    only `if self.allow_all_origins and has_cookie`, and answers a bare `*`
    otherwise. The first e2e boot came back "not exploitable" for an app a
    browser session could actually read cross-origin.

    The claim this template makes is about CREDENTIALED reads; a request
    carrying no credential cannot demonstrate one."""
    import sys
    import types as pytypes

    import app.proof.cors_probe as probe_mod

    seen: dict = {}

    class _Resp:
        headers: dict = {}

    fake_httpx = pytypes.ModuleType("httpx")
    fake_httpx.get = lambda url, **kw: (seen.update(kw), _Resp())[1]  # type: ignore[attr-defined]
    original = sys.modules.get("httpx")
    sys.modules["httpx"] = fake_httpx
    try:
        probe_mod._default_fetch(21234, "/", PROBE_ORIGIN)
    finally:
        if original is not None:
            sys.modules["httpx"] = original
        else:
            del sys.modules["httpx"]

    assert seen["headers"]["Cookie"] == probe_mod.PROBE_COOKIE


def test_evidence_never_carries_a_response_body() -> None:
    """proof_json is rendered into a PR; a body from a customer's app can
    contain their users' data."""
    attempt = _probe(
        _verify(_Boot(True, "up")),
        _headers(**{
            "Access-Control-Allow-Origin": PROBE_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        }),
    )
    assert "body" not in attempt.evidence
    assert "content" not in attempt.evidence


# --- pairing with the existing comparison ----------------------------------

def test_a_before_after_pair_composes_with_build_proof_report() -> None:
    """P1 returns one attempt per workspace on purpose; the pair is compared
    by the same function the static path uses."""
    before = _probe(
        _verify(_Boot(True, "up")),
        _headers(**{
            "Access-Control-Allow-Origin": PROBE_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        }),
    )
    after = _probe(
        _verify(_Boot(True, "up")),
        _headers(**{"Content-Type": "application/json"}),
    )
    report = build_proof_report(before, after, informational=False)
    assert report.verified is True
    assert report.template_id == TEMPLATE_ID


def test_an_errored_before_can_never_be_verified() -> None:
    """Two boots that never came up must not compare into a proof."""
    before = _probe(_verify(_Boot(False, "docker build failed")), _headers())
    after = _probe(_verify(_Boot(False, "docker build failed")), _headers())
    report = build_proof_report(before, after, informational=False)
    assert report.verified is False


def test_a_failed_build_reports_its_log_outside_the_evidence() -> None:
    """"docker build failed" is not a diagnosis, and the log that explains it
    must not become evidence.

    app/proof/types.py forbids raw customer content in evidence because
    evidence is stored in proof_json and rendered into a PR, and a build log
    can echo an ARG or a token. So the log travels through an explicit
    diagnostics channel to the caller that asked for it, and no further.
    """
    class _Failed(_Boot):
        def __init__(self):
            super().__init__(False, "docker build failed")
            self.build_log = "npm ERR! 403 Forbidden\nsecret=hunter2\n"

    diagnostics: dict = {}
    attempt = run_cors_probe(
        Path("/nonexistent"), host_port=21000, container_port=8000,
        verify=_verify(_Failed()), fetch=_headers(),
        stop=lambda c, i: None, diagnostics=diagnostics,
    )

    assert attempt.status == "error"
    assert "403 Forbidden" in diagnostics["build_log_tail"]
    # The log must not have leaked into what gets stored and rendered.
    assert "403" not in str(attempt.evidence)
    assert "hunter2" not in str(attempt.evidence)
