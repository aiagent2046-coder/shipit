"""The measurement harness's own decisions.

Small surface, and every function here has a defect in its history — which is
why it is tested at all rather than left as "just a script". A measurement tool
that is wrong reports a wrong number confidently, and nothing downstream can
tell.
"""

from __future__ import annotations

import email.message
import time
import urllib.error

import pytest

from scripts.measure_error_boundary import (
    _api_headers,
    _rate_limit_reset,
    _slug_from_repo_url,
    _targets_from_file,
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
    assert "GITHUB_TOKEN" in reason


def test_the_reset_time_is_readable_without_a_decoder():
    """`resets at unix 1788265311` answered no question anybody was asking. The
    only one being asked is "how long do I wait", so the message says a clock
    time and the minutes until it."""
    reason = _why_unresolved(_http_error(
        403, {"x-ratelimit-remaining": "0",
              "x-ratelimit-reset": str(int(time.time()) + 630)}))

    assert "UTC" in reason
    assert "in 10 min" in reason or "in 11 min" in reason
    assert "unix" not in reason


def test_a_rate_limit_is_reported_to_the_caller_and_not_only_to_the_reader():
    """The caller has to STOP. A spent quota is a fact about the next request
    too, so `_rate_limit_reset` returns the epoch rather than the resolver
    learning it only from prose it cannot act on — which is how 42 further
    requests got sent to be told the same thing."""
    limited = _http_error(403, {"x-ratelimit-remaining": "0",
                                "x-ratelimit-reset": "1756800000"})

    assert _rate_limit_reset(limited) == 1756800000
    assert _rate_limit_reset(_http_error(404, {})) is None
    assert _rate_limit_reset(_http_error(403, {"x-ratelimit-remaining": "7"})) is None
    assert _rate_limit_reset(TimeoutError()) is None


def test_an_unparseable_reset_header_is_still_a_rate_limit():
    """Losing the clock must not lose the diagnosis: without a usable reset we
    still know the quota is spent, which is the part that decides whether to
    keep sending."""
    exc = _http_error(403, {"x-ratelimit-remaining": "0",
                            "x-ratelimit-reset": "soon"})

    assert _rate_limit_reset(exc) == 0
    assert "RATE LIMITED" in _why_unresolved(exc)
    assert "unknown time" in _why_unresolved(exc)


def test_the_resolver_stops_sending_once_the_quota_is_spent(tmp_path,
                                                            monkeypatch):
    """THE POINT OF THE WHOLE DIAGNOSTIC. Knowing the quota is spent is worth
    nothing if the loop keeps going: the 2026-09-01 run sent 42 more requests
    after the first refusal and printed the same sentence 43 times, burying the
    one fact worth reading under 42 copies of itself.
    """
    listing = tmp_path / "repos.txt"
    listing.write_text("\n".join(
        f"https://github.com/acme/app{i}|hash{i}" for i in range(20)))

    calls: list[str] = []

    def _limited(slug: str) -> str:
        calls.append(slug)
        if len(calls) <= 2:
            return "a" * 40
        raise _http_error(403, {"x-ratelimit-remaining": "0",
                                "x-ratelimit-reset": "1756800000"})

    monkeypatch.setattr(
        "scripts.measure_error_boundary._resolve_head", _limited)
    out = _targets_from_file(listing)

    assert len(calls) == 3, (
        "two successes, one refusal, and then it must stop — not walk the "
        "remaining 17")
    assert len(out) == 2, "what did resolve is kept and measured"


def test_a_gone_repository_does_not_stop_the_resolver(tmp_path, monkeypatch):
    """The other half: a 404 is about ONE repository, so the run continues.
    Stopping on it would let a single deleted repo truncate the corpus."""
    listing = tmp_path / "repos.txt"
    listing.write_text("\n".join(
        f"https://github.com/acme/app{i}" for i in range(5)))

    def _one_gone(slug: str) -> str:
        if slug == "acme/app2":
            raise _http_error(404, {})
        return "b" * 40

    monkeypatch.setattr(
        "scripts.measure_error_boundary._resolve_head", _one_gone)

    assert len(_targets_from_file(listing)) == 4


def test_the_same_repository_twice_is_resolved_once(tmp_path, monkeypatch):
    """The audits dump is one row per repo_url, and the same repository can
    appear as both a bare slug and a full URL. Resolving it twice would spend a
    request to learn something already known, against a 60/hour ceiling."""
    listing = tmp_path / "repos.txt"
    listing.write_text(
        "https://github.com/acme/app|h1\nacme/app|h2\ngithub.com/acme/app|h3\n")

    calls: list[str] = []
    monkeypatch.setattr("scripts.measure_error_boundary._resolve_head",
                        lambda slug: calls.append(slug) or ("c" * 40))

    assert _targets_from_file(listing) == [("acme/app", "c" * 40)]
    assert calls == ["acme/app"]


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


def test_the_strata_loader_matches_the_sibling_scripts(tmp_path, monkeypatch):
    """Comment lines skipped, first occurrence wins, PER_STRATUM caps -- the
    exact rules measure_rls_blind_spot.load_candidates applies. If they
    diverge, the error-boundary incidence and the RLS blind-spot rate are
    measured over two different corpora that share a filename."""
    from scripts import measure_error_boundary as m
    data = tmp_path / "data"
    data.mkdir()
    (data / "x_candidates.txt").write_text(
        "# discovery output, not a corpus\n"
        "acme/one\n\nacme/two\nacme/one\n# trailing\nacme/three\n")
    monkeypatch.setattr(m, "DATA", data)

    assert m._load_candidates("x_candidates.txt", None) == [
        "acme/one", "acme/two", "acme/three"]
    assert m._load_candidates("x_candidates.txt", 2) == ["acme/one", "acme/two"]


def test_a_strata_run_over_the_anonymous_ceiling_refuses_up_front(
        tmp_path, monkeypatch):
    """Resolving 61+ heads without a token would resolve the first 60 and
    stop -- a corpus that is 60/211 Lovable and none of the other two strata,
    which reads as a result and is nothing of the kind. Refuse before the
    first request, with the arithmetic."""
    from scripts import measure_error_boundary as m
    data = tmp_path / "data"
    data.mkdir()
    for _, fn in m.STRATA:
        (data / fn).write_text("\n".join(f"acme/r{i}" for i in range(25)))
    monkeypatch.setattr(m, "DATA", data)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    calls: list[str] = []
    monkeypatch.setattr(m, "_resolve_head", lambda s: calls.append(s) or "a" * 40)

    with pytest.raises(SystemExit, match="ceiling is 60"):
        m._strata_targets(None)
    assert calls == [], "refused before spending a single request"

    # Under the ceiling it runs, and each triple carries its stratum.
    out = m._strata_targets(10)
    assert len(out) == 30
    assert {label for label, _, _ in out} == {"Lovable", "bolt", "hand-written"}


# --- the exclusion's own question --------------------------------------------

def _zip(files: dict[str, str]) -> bytes:
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    return buf.getvalue()


_MAIN = ("import {createRoot} from 'react-dom/client';"
         "createRoot(el).render(<App/>)")


def test_a_silenced_repository_is_asked_whether_it_was_an_app_after_all():
    """MEASURED 2026-09-04: 13 repositories left the incidence denominator
    because a boundary token stopped the walk before it reached their mount --
    and an UNPROTECTED repository never stops early, so the exclusion only ever
    removed protected apps and inflated the rate. This is the question that
    decides whether each exclusion was right, so it has to be right itself."""
    from scripts.measure_error_boundary import _render_call_anywhere

    # A GitHub zip wraps everything in <repo>-<sha>/; the mount is still found.
    assert _render_call_anywhere(_zip({
        "repo-abc123/package.json": "{}",
        "repo-abc123/src/App.tsx": "export default function App(){}",
        "repo-abc123/src/main.tsx": _MAIN,
    })) == "src/main.tsx"

    # An archive with no wrapping directory works the same way.
    assert _render_call_anywhere(_zip({
        "package.json": "{}",
        "src/main.tsx": _MAIN,
    })) == "src/main.tsx"

    # A library really has no mount: the exclusion was correct for it.
    assert _render_call_anywhere(_zip({
        "repo-abc123/package.json": "{}",
        "repo-abc123/src/Button.tsx": "export const B = () => null",
    })) == ""


def test_a_render_call_in_node_modules_does_not_make_it_an_app():
    """Every dependency tree contains createRoot. Counting one would move a
    library into the denominator and pull the incidence DOWN with a repository
    that has no screen to blank -- the mirror of the defect this exists to
    measure, and just as wrong."""
    from scripts.measure_error_boundary import _render_call_anywhere

    assert _render_call_anywhere(_zip({
        "repo-abc123/package.json": "{}",
        "repo-abc123/src/Button.tsx": "export const B = () => null",
        "repo-abc123/node_modules/react-dom/client.js": _MAIN,
    })) == ""
