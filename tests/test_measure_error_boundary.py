"""The measurement harness's own decisions.

Small surface, and every function here has a defect in its history — which is
why it is tested at all rather than left as "just a script". A measurement tool
that is wrong reports a wrong number confidently, and nothing downstream can
tell.
"""

from __future__ import annotations

import email.message
import urllib.error

from scripts.measure_error_boundary import (
    _api_headers,
    _slug_from_repo_url,
    _why_unresolved,
)


def _http_error(code: int, headers: dict[str, str]) -> urllib.error.HTTPError:
    msg = email.message.Message()
    for k, v in headers.items():
        msg[k] = v
    return urllib.error.HTTPError("https://api.github.com/x", code, "err",
                                  msg, None)


def test_a_spent_rate_limit_does_not_read_as_a_deleted_repository():
    """MEASURED, 2026-09-01: `head unresolved: HTTPError` printed 43 times for
    a spent rate limit, and it read exactly like 43 repositories that had gone
    away. One word for three causes is the collapse that has cost this project
    a diagnosis three times."""
    reason = _why_unresolved(_http_error(
        403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1756800000"}))

    assert "RATE LIMITED" in reason
    assert "1756800000" in reason
    assert "GITHUB_TOKEN" in reason


def test_a_404_says_the_repository_is_gone_not_that_we_were_throttled():
    reason = _why_unresolved(_http_error(404, {}))

    assert "404" in reason
    assert "RATE LIMITED" not in reason


def test_a_403_that_is_not_a_rate_limit_is_not_called_one():
    """A 403 with quota remaining is something else — a blocked repository, a
    token without scope. Naming it a rate limit would send the reader to wait
    an hour for a condition that will not change."""
    reason = _why_unresolved(_http_error(403, {"x-ratelimit-remaining": "58"}))

    assert reason == "HTTP 403"


def test_a_non_http_failure_keeps_its_own_name():
    assert _why_unresolved(TimeoutError()) == "TimeoutError"


def test_the_token_is_only_ever_read_from_the_environment(monkeypatch):
    """Not from /opt/shipit/.env, not from an argument. And app/ingest sends no
    Authorization header BY DESIGN, because it fetches URLs strangers supply —
    this script fetches a list we chose, run by hand, so the two decisions are
    different and neither should drift into the other."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert "Authorization" not in _api_headers()

    monkeypatch.setenv("GITHUB_TOKEN", "ghp_example")
    assert _api_headers()["Authorization"] == "Bearer ghp_example"


def test_an_empty_token_is_not_an_authorization_header(monkeypatch):
    """An unset variable and one set to "" reach the process identically enough
    that a bare truthiness check on os.environ.get would send
    `Authorization: Bearer `, which GitHub answers 401 — a confusing failure in
    place of the working anonymous path."""
    monkeypatch.setenv("GITHUB_TOKEN", "   ")

    assert "Authorization" not in _api_headers()


def test_repo_urls_arrive_in_several_shapes():
    for raw in ("https://github.com/acme/app",
                "https://github.com/acme/app.git",
                "github.com/acme/app",
                "acme/app",
                "  https://github.com/acme/app/  "):
        assert _slug_from_repo_url(raw) == "acme/app", raw


def test_a_url_with_extra_path_segments_keeps_only_the_repository():
    assert _slug_from_repo_url(
        "https://github.com/acme/app/tree/main/src") == "acme/app"


def test_something_that_is_not_a_repository_url_yields_nothing():
    """Returning "" rather than guessing: a malformed line must drop out of the
    corpus, not become a request for a repository nobody named."""
    assert _slug_from_repo_url("not-a-url") == ""
    assert _slug_from_repo_url("") == ""
