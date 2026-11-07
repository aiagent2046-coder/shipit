"""Recon tests: the passive network boundary.

The network itself is the only faked layer (urllib.request.urlopen); every
assertion runs through the real recon code paths. These tests pin the legal
contour: GET/HEAD only, honest failure mapping, polite pacing.
"""
from __future__ import annotations

import json
import urllib.error

import pytest

from scout import recon
from scout.guard import ActiveModeUnauthorised


class FakeResponse:
    def __init__(self, status=200, headers=None, body=b""):
        self.status = status
        self.headers = headers or {}
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture(autouse=True)
def no_pacing(monkeypatch):
    monkeypatch.setattr(recon, "REQUEST_INTERVAL_S", 0.0)
    recon._last_request.clear()
    yield
    recon._last_request.clear()


@pytest.fixture
def routes(monkeypatch):
    """Route URL -> FakeResponse or exception instance. Records every request."""
    table = {}
    seen = []

    def fake_urlopen(req, timeout=None):
        seen.append(req)
        target = table.get(req.full_url)
        if target is None:
            target = FakeResponse(404)
        if isinstance(target, Exception):
            raise target
        return target

    monkeypatch.setattr(recon.urllib.request, "urlopen", fake_urlopen)
    return table, seen


def test_http_get_sends_only_get(routes):
    table, seen = routes
    table["https://example.test/"] = FakeResponse(200, body=b"hi")
    res = recon.http_get("https://example.test/")
    assert res.status == 200 and res.text == "hi"
    assert [r.get_method() for r in seen] == ["GET"]
    assert "agent-scout" in seen[0].get_header("User-agent")


def test_http_get_maps_http_error_to_status(routes):
    table, _ = routes
    table["https://example.test/missing"] = urllib.error.HTTPError(
        "https://example.test/missing", 404, "Not Found", {}, None)
    res = recon.http_get("https://example.test/missing")
    assert res.status == 404 and res.body == b""


def test_http_get_maps_network_failure_to_recon_error(routes):
    table, _ = routes
    table["https://down.test/"] = urllib.error.URLError("refused")
    with pytest.raises(recon.ReconError):
        recon.http_get("https://down.test/")


def test_http_get_paces_per_host(monkeypatch, routes):
    table, _ = routes
    table["https://example.test/a"] = FakeResponse(200)
    table["https://example.test/b"] = FakeResponse(200)
    monkeypatch.setattr(recon, "REQUEST_INTERVAL_S", 1.0)
    slept = []
    monkeypatch.setattr(recon.time, "sleep", slept.append)
    recon.http_get("https://example.test/a")
    recon.http_get("https://example.test/b")
    recon._last_request.clear()
    # Second same-host call waits the remaining interval; a first call never does.
    assert len(slept) == 1 and 0.9 < slept[0] <= 1.0


def test_fetch_security_txt_prefers_well_known(routes):
    table, _ = routes
    table["https://example.test/.well-known/security.txt"] = FakeResponse(
        200, body=b"Contact: mailto:sec@example.test\nPreferred-Languages: en\n")
    text, contact = recon.fetch_security_txt("https://example.test/")
    assert contact == "mailto:sec@example.test"
    assert "Preferred-Languages" in text


def test_fetch_security_txt_falls_back_to_root(routes):
    table, _ = routes
    table["https://example.test/security.txt"] = FakeResponse(
        200, body=b"Contact: https://example.test/security\n")
    text, contact = recon.fetch_security_txt("https://example.test")
    assert contact == "https://example.test/security"
    assert text is not None


def test_fetch_security_txt_absent(routes):
    assert recon.fetch_security_txt("https://example.test/") == (None, None)


def test_profile_site_keeps_only_signal_headers(routes):
    table, _ = routes
    table["https://example.test/"] = FakeResponse(200, headers={
        "Server": "nginx", "X-Powered-By": "Next.js",
        "Keep-Alive": "timeout=5", "Content-Type": "text/html"})
    site = recon.profile_site("https://example.test/")
    assert site.server_headers == {"Server": "nginx", "X-Powered-By": "Next.js"}
    assert site.contact is None


def test_stack_signals_reads_headers_html_and_scripts():
    hints = recon.stack_signals(
        {"X-Powered-By": "Next.js", "Server": "nginx/1.24", "cf-ray": "abc"},
        '<div id="__NEXT_DATA__">{}</div><p data-reactroot></p>',
        ["https://example.test/_next/static/chunks/main.js"])
    assert hints == ["next.js", "nginx", "cloudflare", "react"]


def test_stack_signals_stays_silent_without_signals():
    assert recon.stack_signals({}, "plain prose about reactive programming",
                               ["https://example.test/static/app.js"]) == []


def test_profile_site_carries_stack_hints(routes):
    table, _ = routes
    table["https://example.test/"] = FakeResponse(
        200, headers={"X-Powered-By": "Next.js"},
        body=b'<div id="__NEXT_DATA__"></div>')
    site = recon.profile_site("https://example.test/")
    assert site.stack_hints == ["next.js"]


def test_github_manifests_fetches_known_lockfiles_and_skips_404(routes):
    table, seen = routes
    table["https://raw.githubusercontent.com/o/r/HEAD/package-lock.json"] = FakeResponse(
        200, body=b'{"lockfileVersion": 3}')
    table["https://raw.githubusercontent.com/o/r/HEAD/web/pnpm-lock.yaml"] = FakeResponse(
        200, body=b"lockfileVersion: '9.0'")
    files = recon.github_manifests("o", "r")
    assert set(files) == {"package-lock.json", "web/pnpm-lock.yaml"}
    assert all(r.get_method() == "GET" for r in seen)


def test_github_manifests_skips_404_even_with_error_body(routes):
    table, _ = routes
    table["https://raw.githubusercontent.com/o/r/HEAD/package-lock.json"] = FakeResponse(
        404, body=b'{"message": "404 File not found"}')
    assert recon.github_manifests("o", "r") == {}


def test_gitlab_manifests_probes_common_layout(routes):
    table, seen = routes
    table["https://gitlab.com/api/v4/projects/o%2Fr/repository/files/package-lock.json/raw?ref=HEAD"] = \
        FakeResponse(200, body=b'{"lockfileVersion": 3}')
    table["https://gitlab.com/api/v4/projects/o%2Fr/repository/files/web%2Fpnpm-lock.yaml/raw?ref=HEAD"] = \
        FakeResponse(200, body=b"lockfileVersion: '9.0'")
    files = recon.gitlab_manifests("o/r")
    assert set(files) == {"package-lock.json", "web/pnpm-lock.yaml"}
    assert all(r.get_method() == "GET" for r in seen)


def test_manifest_probe_covers_src_frontend_layout(routes):
    table, _ = routes
    table["https://raw.githubusercontent.com/o/r/HEAD/src/frontend/package-lock.json"] = \
        FakeResponse(200, body=b'{"lockfileVersion": 3}')
    table[
        "https://gitlab.com/api/v4/projects/o%2Fr/repository/files/src%2Ffrontend%2Fpackage-lock.json/raw?ref=HEAD"
    ] = FakeResponse(200, body=b'{"lockfileVersion": 3}')
    assert "src/frontend/package-lock.json" in recon.github_manifests("o", "r")
    assert "src/frontend/package-lock.json" in recon.gitlab_manifests("o/r")


def test_manifest_archive_drops_binary_and_oversized():
    files = {
        "good/requirements.txt": b"flask==3.0.0\n",
        "bad.bin": b"has\x00null",
        "huge.txt": b"x" * 10_000_001,
    }
    kept = recon.manifest_archive(files)
    assert set(kept) == {"good/requirements.txt"}


def test_passive_enforcement_is_not_bypassable():
    with pytest.raises(ActiveModeUnauthorised):
        recon.enforce_passive_http("POST")


def test_page_scripts_absolute_bounded_and_sane():
    html = ('<script src="/static/app.js"></script>'
            '<script src="https://cdn.example.test/lib.js"></script>'
            '<script src="/static/app.js"></script>'
            '<script src="data:text/javascript,alert(1)"></script>')
    urls = recon.page_scripts(html, "https://example.test/")
    assert urls == ["https://example.test/static/app.js",
                    "https://cdn.example.test/lib.js"]


def test_page_scripts_are_bounded():
    html = "".join(f'<script src="/s{i}.js"></script>' for i in range(30))
    assert len(recon.page_scripts(html, "https://example.test/")) == recon.MAX_BUNDLES


def test_source_map_url_prefers_header_then_tail_comment():
    js_url = "https://example.test/static/app.js"
    assert recon.source_map_url(js_url, b"var x=1;\n//# sourceMappingURL=app.js.map\n", {}) \
        == "https://example.test/static/app.js.map"
    assert recon.source_map_url(js_url, b"var x=1;", {"SourceMap": "/maps/app.map"}) \
        == "https://example.test/maps/app.map"
    assert recon.source_map_url(js_url, b"var x=1;", {}) is None
    assert recon.source_map_url(
        js_url, b"//# sourceMappingURL=data:application/json;base64,AAAA", {}) is None


def test_manifests_from_source_map_extracts_embedded_files():
    body = json.dumps({
        "sources": ["webpack:///src/index.js", "webpack:///package.json",
                    "webpack:///package-lock.json", "webpack:///README.md"],
        "sourcesContent": ["console.log(1)", '{"name": "app"}',
                           '{"lockfileVersion": 3}', "# hi"],
    }).encode()
    assert recon.manifests_from_source_map(body) == {
        "package.json": b'{"name": "app"}',
        "package-lock.json": b'{"lockfileVersion": 3}'}


def test_manifests_from_source_map_refuses_garbage():
    assert recon.manifests_from_source_map(b"not json") == {}
    assert recon.manifests_from_source_map(b"[1,2,3]") == {}
    assert recon.manifests_from_source_map(b'{"sources": "x", "sourcesContent": []}') == {}
    assert recon.manifests_from_source_map(
        b'{"sources": ["package.json"], "sourcesContent": [null]}') == {}


def test_pins_from_source_map_reads_pnpm_install_paths():
    body = json.dumps({"sources": [
        "node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/lodash.js",
        "node_modules/.pnpm/@scope+pkg@1.2.3/node_modules/@scope/pkg/index.js",
        "node_modules/.pnpm/react@18.2.0(react-dom@18.2.0)/node_modules/react/index.js",
        "node_modules/.pnpm/weird@latest/node_modules/weird/index.js",
        "node_modules/webpack/lib/index.js",
        "src/app.js",
    ]}).encode()
    assert recon.pins_from_source_map(body) == {
        "lodash": "4.17.21", "@scope/pkg": "1.2.3", "react": "18.2.0"}


def test_npm_lockfile_from_pins_packages_resolved_versions():
    doc = json.loads(recon.npm_lockfile_from_pins(
        {"lodash": "4.17.21", "@scope/pkg": "1.2.3"}))
    assert doc["lockfileVersion"] == 3
    assert doc["packages"]["node_modules/lodash"]["version"] == "4.17.21"
    assert doc["packages"]["node_modules/@scope/pkg"]["version"] == "1.2.3"
    assert recon.npm_lockfile_from_pins({}) == b""


def test_manifests_from_site_follows_scripts_to_maps(routes):
    table, seen = routes
    table["https://example.test/"] = FakeResponse(
        200, body=b'<script src="/app.js"></script>')
    table["https://example.test/app.js"] = FakeResponse(
        200, body=b"code\n//# sourceMappingURL=app.js.map")
    table["https://example.test/app.js.map"] = FakeResponse(200, body=json.dumps({
        "sources": ["node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/lodash.js",
                    "webpack:///package.json"],
        "sourcesContent": ["x", '{"name": "app"}'],
    }).encode())
    out = recon.manifests_from_site("https://example.test/")
    assert out["sourcemap/package.json"] == b'{"name": "app"}'
    lock = json.loads(out["sourcemap-pins/package-lock.json"])
    assert lock["packages"]["node_modules/lodash"]["version"] == "4.17.21"
    assert all(r.get_method() == "GET" for r in seen)


def test_manifests_from_site_is_quiet_on_failures(routes):
    table, _ = routes
    table["https://example.test/"] = FakeResponse(
        200, body=b'<script src="/app.js"></script>')  # app.js 404s
    assert recon.manifests_from_site("https://example.test/") == {}
    table["https://down.test/"] = urllib.error.URLError("refused")
    assert recon.manifests_from_site("https://down.test/") == {}


def test_manifests_from_site_bounds_maps_read(routes, monkeypatch):
    monkeypatch.setattr(recon, "MAX_MAPS", 1)
    table, _ = routes
    scripts = "".join(f'<script src="/a{i}.js"></script>' for i in range(3))
    table["https://example.test/"] = FakeResponse(200, body=scripts.encode())
    # Distinct manifest name per map so the budget is observable: same-name
    # extracts would collide under setdefault and hide how many maps were read.
    names = ["package.json", "package-lock.json", "requirements.txt"]
    for i, name in enumerate(names):
        table[f"https://example.test/a{i}.js"] = FakeResponse(
            200, body=f"//# sourceMappingURL=a{i}.js.map".encode())
        table[f"https://example.test/a{i}.js.map"] = FakeResponse(200, body=json.dumps({
            "sources": [f"webpack:///{name}"],
            "sourcesContent": [f'{{"name": "app{i}"}}'],
        }).encode())
    out = recon.manifests_from_site("https://example.test/")
    assert set(out) == {"sourcemap/package.json"}  # budget: only the first map read
