"""Tests for stack detection and the intake endpoint."""

import io
import json
import zipfile

import httpx
import pytest
from fastapi.testclient import TestClient

from app.ingest.github_fetch import RepoFetchError, fetch_repo_zip
from app.ingest.stack_detect import Stack, detect_stack
from app.main import app, get_repo_fetcher

client = TestClient(app)


def make_zip(entries: dict[str, bytes]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    buf.seek(0)
    return buf


NEXT_PKG = json.dumps({"dependencies": {"next": "15.0.0", "react": "19.0.0"}}).encode()


def test_detect_nextjs_by_dependency():
    buf = make_zip({"package.json": NEXT_PKG, "app/page.tsx": b"export default ..."})
    assert detect_stack(buf) is Stack.NEXTJS


def test_detect_nextjs_inside_export_root_folder():
    # Lovable/Bolt exports wrap the project in a single top-level folder.
    buf = make_zip({"my-app/package.json": NEXT_PKG, "my-app/next.config.mjs": b""})
    assert detect_stack(buf) is Stack.NEXTJS


def test_detect_fastapi():
    buf = make_zip({
        "requirements.txt": b"fastapi\nuvicorn\n",
        "app/main.py": b"from fastapi import FastAPI\napp = FastAPI()\n",
    })
    assert detect_stack(buf) is Stack.FASTAPI


def test_python_without_fastapi_import_is_unsupported():
    buf = make_zip({
        "requirements.txt": b"flask\n",
        "app/main.py": b"from flask import Flask\n",
    })
    assert detect_stack(buf) is Stack.UNSUPPORTED


def test_unknown_project_is_unsupported():
    buf = make_zip({"index.html": b"<html></html>"})
    assert detect_stack(buf) is Stack.UNSUPPORTED


# --- API surface ---

def test_healthz():
    assert client.get("/healthz").json() == {"status": "ok"}


def test_audit_intake_accepts_nextjs_zip(audit_queue, audit_spool_dir):
    buf = make_zip({"package.json": NEXT_PKG})
    resp = client.post(
        "/v1/audits", files={"archive": ("app.zip", buf, "application/zip")}
    )
    assert resp.status_code == 202
    body = resp.json()
    # The whole 202 contract: a job to poll, and the token that opens it.
    assert set(body) == {"job_id", "access_token", "state"}
    assert body["state"] == "queued"
    assert body["access_token"]

    # The stack was detected at intake -- an unauditable submission is rejected
    # here rather than queued -- and recorded on the job.
    job = audit_queue.only
    assert job["stack"] == "nextjs"
    assert job["source_kind"] == "zip"
    # And the upload outlived the request: the worker is another process, so
    # bytes that only existed in this request's memory would be unreachable.
    staged = audit_spool_dir / f"{body['job_id']}.zip"
    assert staged.read_bytes() == buf.getvalue()
    assert job["source_ref"] == str(staged)


def test_audit_intake_rejects_traversal_zip_with_reason():
    buf = make_zip({"../../etc/evil": b"x"})
    resp = client.post(
        "/v1/audits", files={"archive": ("app.zip", buf, "application/zip")}
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "unsafe_path"


def test_audit_intake_accepts_a_stack_the_detector_does_not_recognise():
    """A repository outside Next.js / Vite / FastAPI is audited, not refused.

    Everything the audit does is stack-agnostic: app/scan/ never reads the
    detected stack, the presence checks look for .env / .gitignore / tests /
    CI, and the secret rules are regexes over file bytes. A SvelteKit, Django
    or Express repository with a committed .env has exactly the problem this
    product exists to find, and used to be told to go away instead.
    """
    buf = make_zip({
        "svelte.config.js": b"export default {}",
        "src/routes/+page.svelte": b"<h1>hi</h1>",
        ".env": b"DATABASE_URL=postgres://user:hunter2@db/app\n",
    })
    resp = client.post(
        "/v1/audits", files={"archive": ("app.zip", buf, "application/zip")}
    )

    assert resp.status_code == 202, resp.text


def test_unrecognised_stack_still_produces_the_findings_that_matter():
    """The point of accepting it: the findings are real, not an empty report.

    Asserted on the scan directly rather than through the queue, so this
    covers what the visitor actually receives rather than that a job was
    created.
    """
    import io as _io

    from app.scan.static import run_static_scan

    buf = make_zip({
        "svelte.config.js": b"export default {}",
        ".gitignore": b"node_modules\n",
        ".env": b"DATABASE_URL=postgres://user:hunter2@db/app\n",
    })
    result = run_static_scan(_io.BytesIO(buf.getvalue()))
    ids = {f["rule_id"] for f in result["findings"]}

    assert "env-file-committed" in ids
    assert "gitignore-missing-secrets" in ids
    assert result["score"]["total"] < 10.0


def test_detect_vite_react_lovable_export():
    pkg = json.dumps({
        "dependencies": {"react": "18.3.1"},
        "devDependencies": {"vite": "5.4.1", "lovable-tagger": "1.0.0"},
    }).encode()
    buf = make_zip({"proj/package.json": pkg, "proj/vite.config.ts": b""})
    assert detect_stack(buf) is Stack.VITE_REACT


def test_next_takes_priority_over_vite():
    pkg = json.dumps({
        "dependencies": {"next": "15.0.0", "react": "19.0.0", "vite": "5.0.0"}
    }).encode()
    buf = make_zip({"package.json": pkg})
    assert detect_stack(buf) is Stack.NEXTJS


# --- repo_url intake: public GitHub URL as an alternative to file upload ---
#
# The outbound GitHub call is always stubbed (get_repo_fetcher override or a
# MockTransport) — the suite never touches the real network.

def _override_fetcher(fn):
    app.dependency_overrides[get_repo_fetcher] = lambda: fn


def _clear_fetcher():
    app.dependency_overrides.pop(get_repo_fetcher, None)


def test_repo_url_intake_fetches_validates_and_queues(audit_queue,
                                                      audit_spool_dir):
    captured = {}

    def fake_fetch(owner, repo, **kwargs):
        captured["owner"], captured["repo"] = owner, repo
        return make_zip({"package.json": NEXT_PKG}).getvalue()

    _override_fetcher(fake_fetch)
    try:
        resp = client.post(
            "/v1/audits", data={"repo_url": "https://github.com/acme/app"}
        )
    finally:
        _clear_fetcher()

    assert resp.status_code == 202
    # Same 202 shape as the file-upload path.
    assert set(resp.json()) == {"job_id", "access_token", "state"}
    # Only the validated owner/repo reached the fetcher. Intake still fetches
    # even though the worker re-fetches: it is how the archive is validated and
    # the stack detected before anything is queued.
    assert (captured["owner"], captured["repo"]) == ("acme", "app")

    # A repo_url job carries its whole payload in the row, so it is queued
    # directly and nothing is written to the spool.
    job = audit_queue.only
    assert job["stack"] == "nextjs"
    assert job["source_kind"] == "repo_url"
    assert job["source_ref"] == "https://github.com/acme/app"
    assert list(audit_spool_dir.glob("*.zip")) == []


def test_repo_url_accepts_dot_git_suffix():
    captured = {}

    def fake_fetch(owner, repo, **kwargs):
        captured["repo"] = repo
        return make_zip({"package.json": NEXT_PKG}).getvalue()

    _override_fetcher(fake_fetch)
    try:
        resp = client.post(
            "/v1/audits", data={"repo_url": "https://github.com/acme/app.git"}
        )
    finally:
        _clear_fetcher()

    assert resp.status_code == 202
    assert captured["repo"] == "app"  # .git stripped


def test_repo_url_malformed_is_422_before_any_http_call():
    calls = {"n": 0}

    def fake_fetch(owner, repo, **kwargs):
        calls["n"] += 1
        return b""

    _override_fetcher(fake_fetch)
    try:
        bad_urls = [
            "http://github.com/acme/app",             # not https
            "https://gitlab.com/acme/app",            # wrong host
            "https://github.com.evil.com/acme/app",   # suffix-host trick
            "https://github.com@evil.com/acme/app",   # userinfo trick
            "https://evil.com/github.com/acme/app",   # host in path
            "https://github.com:443/acme/app",        # explicit port
            "https://github.com/acme",                # missing repo
            "https://github.com/acme/app/tree/main",  # extra path segments
            "https://github.com/acme/../secrets",     # traversal in segment
            "not-a-url",
        ]
        for bad in bad_urls:
            resp = client.post("/v1/audits", data={"repo_url": bad})
            assert resp.status_code == 422, bad
            assert resp.json()["detail"]["reason"] == "bad_repo_url", bad
    finally:
        _clear_fetcher()

    assert calls["n"] == 0  # never reached the network


def test_both_archive_and_repo_url_is_422():
    buf = make_zip({"package.json": NEXT_PKG})
    resp = client.post(
        "/v1/audits",
        files={"archive": ("app.zip", buf, "application/zip")},
        data={"repo_url": "https://github.com/acme/app"},
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "bad_intake"


def test_neither_archive_nor_repo_url_is_422():
    resp = client.post("/v1/audits")
    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "bad_intake"


def test_repo_url_github_404_is_clean_422_not_500():
    def fake_fetch(owner, repo, **kwargs):
        raise RepoFetchError(
            "repo_not_found", "repo not found or private — only public "
            "GitHub repos are supported")

    _override_fetcher(fake_fetch)
    try:
        resp = client.post(
            "/v1/audits", data={"repo_url": "https://github.com/acme/ghost"}
        )
    finally:
        _clear_fetcher()

    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "repo_not_found"


def test_repo_url_github_unreachable_is_502():
    def fake_fetch(owner, repo, **kwargs):
        raise RepoFetchError("github_unreachable", "connect timeout")

    _override_fetcher(fake_fetch)
    try:
        resp = client.post(
            "/v1/audits", data={"repo_url": "https://github.com/acme/app"}
        )
    finally:
        _clear_fetcher()

    assert resp.status_code == 502
    assert resp.json()["detail"]["reason"] == "github_unreachable"


def test_repo_url_audit_consumes_quota_like_a_file_audit():
    # The rate-limit check sits after validation in the shared handler, so a
    # URL-based audit consumes quota exactly like a file-based one — the
    # third request over a limit of 2 is rejected, no second check needed.
    from app.main import get_rate_limiter
    from app.ratelimit import RateLimiter

    tiny = RateLimiter(limit=2, window_seconds=100, clock=lambda: 0.0)
    app.dependency_overrides[get_rate_limiter] = lambda: tiny
    _override_fetcher(
        lambda owner, repo, **kw: make_zip({"package.json": NEXT_PKG}).getvalue()
    )
    try:
        for _ in range(2):
            resp = client.post(
                "/v1/audits", data={"repo_url": "https://github.com/acme/app"}
            )
            assert resp.status_code == 202
        resp = client.post(
            "/v1/audits", data={"repo_url": "https://github.com/acme/app"}
        )
        assert resp.status_code == 429
        assert resp.json()["detail"]["reason"] == "rate_limited"
    finally:
        _clear_fetcher()
        app.dependency_overrides.pop(get_rate_limiter, None)


# --- fetch_repo_zip unit tests (mocked transport, no real network) ---

def test_fetch_repo_zip_hits_fixed_host_and_returns_bytes():
    payload = make_zip({"package.json": NEXT_PKG}).getvalue()

    def handler(request):
        assert str(request.url) == "https://api.github.com/repos/acme/app/zipball"
        assert "authorization" not in request.headers  # public, no auth
        return httpx.Response(200, content=payload)

    got = fetch_repo_zip("acme", "app", transport=httpx.MockTransport(handler))
    assert got == payload


def test_fetch_repo_zip_404_raises_repo_not_found():
    def handler(request):
        return httpx.Response(404, json={"message": "Not Found"})

    with pytest.raises(RepoFetchError) as ei:
        fetch_repo_zip("acme", "ghost", transport=httpx.MockTransport(handler))
    assert ei.value.reason == "repo_not_found"


def test_fetch_repo_zip_rejects_oversized_content_length(monkeypatch):
    # Declared Content-Length over the limit -> rejected up front, before
    # the (here tiny) body is read at all.
    monkeypatch.setattr("app.ingest.github_fetch.MAX_ARCHIVE_BYTES", 1000)

    def handler(request):
        return httpx.Response(
            200, headers={"content-length": "999999"}, content=b"small"
        )

    with pytest.raises(RepoFetchError) as ei:
        fetch_repo_zip("acme", "app", transport=httpx.MockTransport(handler))
    assert ei.value.reason == "too_large"


def test_fetch_repo_zip_streaming_cutoff_when_length_absent(monkeypatch):
    # codeload can respond chunked with no Content-Length; the streamed
    # byte count is the real guard, not the header.
    monkeypatch.setattr("app.ingest.github_fetch.MAX_ARCHIVE_BYTES", 1000)

    def handler(request):
        def gen():
            for _ in range(5):
                yield b"x" * 1000
        return httpx.Response(200, content=gen())

    with pytest.raises(RepoFetchError) as ei:
        fetch_repo_zip("acme", "app", transport=httpx.MockTransport(handler))
    assert ei.value.reason == "too_large"


def test_fetch_repo_zip_network_error_raises_github_unreachable():
    def handler(request):
        raise httpx.ConnectError("boom")

    with pytest.raises(RepoFetchError) as ei:
        fetch_repo_zip("acme", "app", transport=httpx.MockTransport(handler))
    assert ei.value.reason == "github_unreachable"
