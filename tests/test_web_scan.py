"""The web-structure scan kernel: fixed probes, honest answers, masked evidence.

The fetch boundary is faked here exactly as served_bundle's is (`FetchText`),
with a resolver fake for the IP vetting; the LIVE end-to-end shape is proven at
the bottom against a real in-process HTTP server (loopback is a consented local
stand there, as it is in the kernel).

Every refusal path must happen BEFORE any request: a guard that fires after the
read has already happened is decoration (the rls-probe tests' rule, kept).

Fixture values are assembled by concatenation, never spelled out as
key=value literals — a literal that reads like a credential is what the
response body would be masking in production, and it stays masked here too.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from app.proof.web_scan import (
    EXPOSED_FILE_PROBES,
    LISTING_PATHS,
    MIN_DELAY_S,
    render_text,
    run_web_structure_scan,
)

URL = "https://example.com"
PUBLIC_IP = "93.184.216.34"

# A hardened root: every header we ask about present, cookie fully flagged.
HARDENED_HEADERS = [
    ("content-type", "text/html; charset=utf-8"),
    ("strict-transport-security", "max-age=31536000"),
    ("x-content-type-options", "nosniff"),
    ("content-security-policy", "default-src 'self'; frame-ancestors 'self'"),
    ("referrer-policy", "strict-origin-when-cross-origin"),
    ("server", "nginx"),
    ("set-cookie", "sid=abc; Secure; HttpOnly; SameSite=Lax"),
]
HARDENED_BODY = b"<html><head><title>ok</title></head><body>hello</body></html>"
HTML_PAGE = b"<html><head><title>shop</title></head><body>hi</body></html>"


def public_resolver(host: str, port: int) -> list:
    return [(2, 1, 6, "", (PUBLIC_IP, port))]


# A realistic env-file body: two KEY=VALUE lines (the signature), values that
# look like a real DSN and a flag — assembled, never spelled as a literal.
ENV_BODY = b"".join([
    b"DATA", b"BASE_URL=", b"postgres://prod-db/internal\n",
    b"R2D2_", b"MARK=", b"yes\n",
])


class FakeFetch:
    """Routes by path, with dedicated answers for the CORS probe (Origin
    header) and the http:// redirect probe (scheme) — the three probe shapes
    that share paths with the root fetch."""

    def __init__(self, routes: dict, cors=None, http=None, default=(404, [], b"")):
        self.routes = routes
        self.cors = cors
        self.http = http
        self.default = default
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, url: str, host: str, port: int, max_bytes: int,
                 extra_headers: dict | None = None):
        parts = urlsplit(url)
        path = parts.path or "/"
        self.calls.append((f"{parts.scheme}://{host}{path}", dict(extra_headers or {})))
        if parts.scheme == "http" and self.http is not None:
            return self.http[0], list(self.http[1]), self.http[2]
        if extra_headers and "Origin" in extra_headers and self.cors is not None:
            return self.cors[0], list(self.cors[1]), self.cors[2]
        status, headers, body = self.routes.get(path, self.default)
        return status, list(headers), body


def scan(routes: dict, *, url: str = URL, cors=None, http=None, **kwargs):
    fetch = FakeFetch(routes, cors=cors, http=http)
    kwargs.setdefault("resolver", public_resolver)
    result = run_web_structure_scan(url=url, consent=True, fetch=fetch, delay_s=0, **kwargs)
    return result, fetch


def find(result, check_id: str):
    return [f for f in result.findings if f.check_id == check_id]


# --- the wall: refusals come BEFORE any request -----------------------------


def test_no_consent_is_skipped_before_any_request():
    fetch = FakeFetch({"/": (200, HARDENED_HEADERS, HARDENED_BODY)})
    result = run_web_structure_scan(url=URL, consent=False, fetch=fetch,
                                    resolver=public_resolver, delay_s=0)
    assert result.status == "skipped"
    assert "согласия" in result.detail
    assert fetch.calls == []
    assert result.limitations, "a skipped answer still states its limits"


def test_http_scheme_is_refused_without_loopback():
    fetch = FakeFetch({"/": (200, HARDENED_HEADERS, HARDENED_BODY)})
    result = run_web_structure_scan(url="http://example.com", consent=True, fetch=fetch,
                                    resolver=public_resolver, delay_s=0)
    assert result.status == "skipped"
    assert "scheme" in result.detail
    assert fetch.calls == []


def test_credentials_in_url_are_refused():
    result, fetch = scan({}, url="https://user:pass@example.com/")
    assert result.status == "skipped"
    assert "credentials" in result.detail
    assert fetch.calls == []


def test_a_private_resolution_is_refused():
    def private_resolver(host: str, port: int) -> list:
        return [(2, 1, 6, "", ("10.0.0.5", port))]
    fetch = FakeFetch({"/": (200, HARDENED_HEADERS, HARDENED_BODY)})
    result = run_web_structure_scan(url=URL, consent=True, fetch=fetch,
                                    resolver=private_resolver, delay_s=0)
    assert result.status == "skipped"
    assert "non-public" in result.detail
    assert fetch.calls == []


def test_one_private_record_among_public_ones_refuses_the_host():
    """Not "first address wins": a dual-record rebinding setup depends on it."""
    def mixed_resolver(host: str, port: int) -> list:
        return [(2, 1, 6, "", (PUBLIC_IP, port)),
                (2, 1, 6, "", ("169.254.169.254", port))]
    result, fetch = scan({}, resolver=mixed_resolver)
    assert result.status == "skipped"
    assert "169.254.169.254" in result.detail
    assert fetch.calls == []


def test_loopback_is_refused_without_the_local_stand_flag():
    def loopback_resolver(host: str, port: int) -> list:
        return [(2, 1, 6, "", ("127.0.0.1", port))]
    result, fetch = scan({}, url="https://127.0.0.1/", resolver=loopback_resolver)
    assert result.status == "skipped"
    assert fetch.calls == []


# --- a target that does not answer is error, never "clean" -------------------


def test_unreachable_root_is_error_with_the_failure_named():
    def broken_fetch(url, host, port, max_bytes, extra_headers=None):
        raise OSError("no route")
    result = run_web_structure_scan(url=URL, consent=True, fetch=broken_fetch,
                                    resolver=public_resolver, delay_s=0)
    assert result.status == "error"
    assert "недоступен" in result.detail
    assert result.evidence["reason"] == "request_failed"


def test_root_redirect_is_error_and_says_which_url_to_give():
    redirect = (301, [("location", "https://www.example.com/")], b"")
    result, fetch = scan({"/": redirect}, http=redirect)
    assert result.status == "error"
    assert "итог" in result.detail
    assert result.evidence["reason"] == "root_redirect"


def test_root_non_200_is_error():
    result, _ = scan({"/": (503, [], b"")})
    assert result.status == "error"
    assert result.evidence["reason"] == "bad_status"


# --- the vulnerable stand: every finding class fires -----------------------


def vulnerable_routes():
    routes = {
        "/": (200, [
            ("content-type", "text/html"),
            ("server", "nginx/1.24.0"),
            ("x-powered-by", "Express"),
            ("set-cookie", "session=abc123"),
        ], HTML_PAGE),
        "/.env": (200, [("content-type", "text/plain")], ENV_BODY),
        "/.git/config": (200, [("content-type", "text/plain")],
                          b"[core]\n\trepositoryformatversion = 0\n"),
        "/static/": (200, [("content-type", "text/html")],
                      b"<html><head><title>Index of /static/</title></head><body>x</body></html>"),
        "/phpinfo.php": (200, [("content-type", "text/html")],
                         b"<html><body><h1>phpinfo()</h1>PHP Version 8.2.1</body></html>"),
        "/actuator/env": (200, [("content-type", "application/json")],
                          b'{"activeProfiles":["prod"],"propertySources":[]}'),
        "/dump.sql": (200, [("content-type", "text/plain")],
                      b"CREATE TABLE users (id int);\nINSERT INTO users VALUES (1);\n"),
        "/backup.zip": (200, [("content-type", "application/zip")],
                        b"PK\x03\x04" + b"archive-bytes"),
        "/.ssh/id_rsa": (200, [], b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n"),  # scan-allow: synthetic fixture
    }
    return routes


CORS_REFLECT_CREDENTIALS = (200, [
    ("access-control-allow-origin", "https://drydock-cors-probe.example"),
    ("access-control-allow-credentials", "true"),
], b"")

HTTP_PLAIN_200 = (200, [("content-type", "text/html")], HTML_PAGE)


def test_vulnerable_stand_reports_each_class():
    result, _ = scan(vulnerable_routes(), cors=CORS_REFLECT_CREDENTIALS, http=HTTP_PLAIN_200)
    assert result.status == "checked"
    exposed = {f.evidence["path"]: f.severity for f in find(result, "web-exposed-files")}
    assert exposed["/.env"] == "critical"
    assert exposed["/.git/config"] == "critical"
    assert exposed["/.ssh/id_rsa"] == "critical"
    assert exposed["/actuator/env"] == "high"
    assert exposed["/dump.sql"] == "high"
    assert exposed["/backup.zip"] == "high"
    assert exposed["/phpinfo.php"] == "high"
    assert " /.DS_Store".strip() not in exposed      # 404: probed, clean, absent
    assert find(result, "web-security-headers"), "missing HSTS etc must fire"
    assert find(result, "web-cookie-flags"), "cookie without Secure/HttpOnly must fire"
    assert find(result, "web-directory-listing"), "auto-index must fire"
    assert find(result, "web-https-redirect"), "no http→https redirect must fire"
    assert find(result, "web-server-banner"), "versioned Server header must fire"
    assert find(result, "web-cors"), "reflected Origin + credentials must fire"
    assert find(result, "web-security-txt"), "missing security.txt is an info note"


def test_env_evidence_masks_values_and_keeps_key_names():
    routes = {"/": (200, HARDENED_HEADERS, HARDENED_BODY),
              "/.env": (200, [], ENV_BODY)}
    result, _ = scan(routes)
    dumped = json.dumps(result.to_json(), ensure_ascii=False)
    assert "postgres://prod-db/internal" not in dumped, "a value must never be re-stored"
    assert "R2D2_MARK" in dumped or "MARK" in dumped, "key names are the evidence"
    env_findings = [f for f in find(result, "web-exposed-files")
                    if f.evidence.get("path") == "/.env"]
    assert env_findings and env_findings[0].severity == "critical"


def test_hardened_stand_reports_nothing_above_info():
    """A root with everything the checks ask about; 404 probes; clean answers."""
    routes = {"/": (200, HARDENED_HEADERS, HARDENED_BODY)}
    http = (301, [("location", "https://example.com/")], b"")
    cors = (200, [], b"")
    txt = (200, [], b"Contact: https://drydock.example/contact\n")
    result, _ = scan({**routes, "/.well-known/security.txt": txt}, http=http, cors=cors)
    assert result.status == "checked"
    above_info = [f for f in result.findings if f.severity != "info"]
    assert above_info == [], [f.title for f in above_info]
    assert result.coverage["catch_all_detected"] is False
    assert result.coverage["requests_sent"] > 0
    assert not any("лимит запросов" in note for note in result.limitations)


def test_spa_catch_all_answers_no_false_exposed_files():
    shell = b"<html><head><title>app</title></head><body><div id=root></div></body></html>"
    fetch = FakeFetch({"/": (200, HARDENED_HEADERS, shell)},
                      default=(200, HARDENED_HEADERS, shell))
    result = run_web_structure_scan(url=URL, consent=True, fetch=fetch,
                                    resolver=public_resolver, delay_s=0)
    assert result.status == "checked"
    assert result.coverage["catch_all_detected"] is True
    assert find(result, "web-exposed-files") == [], "the page shell is not .git/config"
    assert find(result, "web-directory-listing") == [], "the shell title is not an index"
    assert any("catch-all" in note for note in result.limitations)


def test_mixed_content_in_html_fires():
    page = (200, [("content-type", "text/html")],
            b'<html><body><script src="http://cdn.example.com/lib.js"></script></body></html>')
    result, _ = scan({"/": page})
    mixed = find(result, "web-mixed-content")
    assert mixed and mixed[0].severity == "medium"


def test_cookie_samesite_none_without_secure_fires():
    headers = list(HARDENED_HEADERS)
    headers = [h for h in headers if h[0] != "set-cookie"]
    headers.append(("set-cookie", "sid=1; SameSite=None"))
    result, _ = scan({"/": (200, headers, HARDENED_BODY)})
    titles = [f.title for f in find(result, "web-cookie-flags")]
    assert any("SameSite=None без Secure" in t for t in titles), titles


def test_hsts_shorter_than_owasp_minimum_fires_low():
    headers = [h for h in HARDENED_HEADERS]
    headers = [(k, "max-age=86400") if k == "strict-transport-security" else (k, v)
               for k, v in headers]
    result, _ = scan({"/": (200, headers, HARDENED_BODY)})
    hsts = [f for f in find(result, "web-security-headers")
            if "HSTS короче" in f.title]
    assert hsts and hsts[0].severity == "low"


def test_cors_wildcard_without_credentials_is_not_a_finding():
    cors = (200, [("access-control-allow-origin", "*")], b"")
    result, _ = scan({"/": (200, HARDENED_HEADERS, HARDENED_BODY)}, cors=cors)
    assert find(result, "web-cors") == [], "public content answering * is a decision"


def test_cors_reflection_without_credentials_is_medium():
    cors = (200, [("access-control-allow-origin", "https://drydock-cors-probe.example")], b"")
    result, _ = scan({"/": (200, HARDENED_HEADERS, HARDENED_BODY)}, cors=cors)
    fired = find(result, "web-cors")
    assert fired and fired[0].severity == "medium"


def test_http_redirect_to_https_clears_the_check():
    http = (301, [("location", "https://example.com/")], b"")
    result, _ = scan({"/": (200, HARDENED_HEADERS, HARDENED_BODY)}, http=http)
    assert find(result, "web-https-redirect") == []
    run = [c for c in result.checks if c.check_id == "web-https-redirect"][0]
    assert run.status == "ran" and "редирект на https" in run.detail


def test_http_scheme_stands_skip_the_https_only_checks():
    routes = {"/": (200, [("content-type", "text/html")], HARDENED_BODY)}
    result, _ = scan(routes, url="http://127.0.0.1:8123/", allow_loopback=True)
    assert result.status == "checked"
    skipped = {c.check_id for c in result.checks if c.status == "skipped"}
    assert {"web-security-headers", "web-cookie-flags", "web-https-redirect"} <= skipped


# --- rate and budget: honest stops -------------------------------------------


def test_delay_applies_between_requests():
    import time as _t
    stamps: list[float] = []
    routes = {"/": (200, HARDENED_HEADERS, HARDENED_BODY)}

    class SlowFetch(FakeFetch):
        def __call__(self, url, host, port, max_bytes, extra_headers=None):
            stamps.append(_t.monotonic())
            return super().__call__(url, host, port, max_bytes, extra_headers)

    fetch = SlowFetch(routes)
    run_web_structure_scan(url=URL, consent=True, fetch=fetch,
                           resolver=public_resolver, delay_s=0.05)
    assert len(stamps) > 3
    gaps = [b - a for a, b in zip(stamps, stamps[1:])]
    assert min(gaps) >= 0.04, gaps


def test_budget_cap_stops_probes_and_says_so():
    routes = {"/": (200, HARDENED_HEADERS, HARDENED_BODY)}
    result, fetch = scan(routes, max_requests=2)
    assert result.coverage["probes_truncated"] is True
    assert len(fetch.calls) == 2
    assert any("лимит запросов" in note for note in result.limitations)
    assert result.status == "checked"    # partial, and honest about it


def test_text_rendering_carries_fixes_and_limits():
    routes = {"/": (200, [("server", "nginx/1.24.0"), ("content-type", "text/html")],
                    HARDENED_BODY)}
    result, _ = scan(routes)
    text = render_text(result)
    assert "web-server-banner" in text
    assert "fix:" in text
    assert "Ограничение:" in text


# --- live end-to-end: a real in-process HTTP server (consented local stand) --


class _VulnerableStand(BaseHTTPRequestHandler):
    """The same shapes the fakes answer: exposed .env, phpinfo, missing headers."""

    def log_message(self, format, *args):  # noqa: A002 — stdlib signature
        pass

    def do_GET(self):
        if self.path == "/":
            body = b"<html><head><title>v</title></head><body>vulnerable</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "Apache/2.4.57")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/.env":
            body = b"DB_NAME=" + b"app\n" + b"R2D2_" + b"MARK=" + b"42\n"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/phpinfo.php":
            body = b"<h1>phpinfo()</h1><b>PHP Version 8.2.1</b>"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


def test_live_local_stand_end_to_end():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _VulnerableStand)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = run_web_structure_scan(
            url=f"http://127.0.0.1:{port}/", consent=True, allow_loopback=True, delay_s=0)
        assert result.status == "checked"
        assert result.evidence["host"] == "127.0.0.1"
        exposed = {f.evidence.get("path"): f.severity
                   for f in find(result, "web-exposed-files")}
        assert exposed == {"/.env": "critical", "/phpinfo.php": "high"}, exposed
        assert result.coverage["requests_sent"] > 5
        assert result.coverage["catch_all_detected"] is False
    finally:
        server.shutdown()
        thread.join(timeout=5)


# --- defaults sanity ----------------------------------------------------------


def test_probe_constants_are_the_advertised_shape():
    assert len(EXPOSED_FILE_PROBES) == 16
    assert len(LISTING_PATHS) == 8
    assert MIN_DELAY_S == 0.2
    severities = {p.severity for p in EXPOSED_FILE_PROBES}
    assert severities <= {"low", "medium", "high", "critical"}