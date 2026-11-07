"""Passive reconnaissance: public artifacts only.

Everything here runs in passive mode and is hard-limited to GET/HEAD by
scout.guard. The module deliberately knows only three things:
  1. read a site's public surface (headers, TLS-less GETs, security.txt);
  2. read public repository manifests (raw.githubusercontent.com);
  3. pack what it found into the archive shape the drydock engine consumes.

No crawling of non-public paths, no auth probing, no payloads.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from scout.guard import enforce_passive_http

USER_AGENT = "agent-scout/0.1 (+responsible-disclosure research; passive)"
REQUEST_INTERVAL_S = 1.0  # polite per-host pacing
LOCKFILE_NAMES = ("package-lock.json", "pnpm-lock.yaml", "bun.lock",
                  "poetry.lock", "uv.lock", "requirements.txt")
MANIFEST_DIRS = ("", "web/", "frontend/", "src/frontend/", "client/", "api/",
                 "server/", "backend/", "app/")
GITHUB_RAW = "https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{path}"
GITLAB_RAW = ("https://gitlab.com/api/v4/projects/{project}"
              "/repository/files/{path}/raw?ref=HEAD")
MAX_SOURCE_MAP_BYTES = 5_000_000
MAX_BUNDLES = 10
MAX_MAPS = 5
MAX_MAP_SOURCES = 10_000
SOURCE_MAP_MANIFESTS = frozenset(LOCKFILE_NAMES) | {"package.json"}

_last_request: dict[str, float] = {}

_SCRIPT_SRC = re.compile(r'<script\b[^>]*\bsrc=["\']([^"\']+)["\']', re.IGNORECASE)
_PNPM_INSTALLED = re.compile(
    r"(?:^|/)node_modules/\.pnpm/([^/]+)/node_modules/((?:@[^/]+/)?[^/]+)(?:/|$)")
_VERSION_PREFIX = re.compile(r"[0-9]")
_SOURCE_MAP_COMMENT = "//# sourceMappingURL="


class ReconError(RuntimeError):
    pass


@dataclass
class HttpResult:
    url: str
    status: int
    headers: dict
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


@dataclass
class SiteProfile:
    base_url: str
    server_headers: dict = field(default_factory=dict)
    security_txt: str | None = None
    contact: str | None = None
    stack_hints: list[str] = field(default_factory=list)


def http_get(url: str, timeout: float = 15.0,
             headers: dict | None = None) -> HttpResult:
    """The only network verb in passive mode."""
    enforce_passive_http("GET")
    host = urllib.parse.urlsplit(url).netloc
    since = time.time() - _last_request.get(host, 0.0)
    if since < REQUEST_INTERVAL_S:
        time.sleep(REQUEST_INTERVAL_S - since)
    _last_request[host] = time.time()
    request_headers = {"User-Agent": USER_AGENT}
    request_headers.update(headers or {})
    req = urllib.request.Request(url, headers=request_headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return HttpResult(url, resp.status, dict(resp.headers), resp.read())
    except urllib.error.HTTPError as exc:
        return HttpResult(url, exc.code, dict(exc.headers or {}), b"")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ReconError(f"GET {url} failed: {exc}") from exc


def fetch_security_txt(base_url: str) -> tuple[str | None, str | None]:
    """RFC 9116: the rights holder's own disclosure contact, if they published one."""
    base = base_url.rstrip("/")
    try:
        res = http_get(f"{base}/.well-known/security.txt")
        if res.status != 200:
            res = http_get(f"{base}/security.txt")
    except ReconError:
        return None, None
    if res.status != 200:
        return None, None
    contact = None
    for line in res.text.splitlines():
        if line.lower().startswith("contact:"):
            contact = line.split(":", 1)[1].strip()
            break
    return res.text, contact


_STACK_HTML_MARKERS = (
    ("__NEXT_DATA__", "next.js"),
    ("window.__NUXT__", "nuxt"),
    ("ng-version", "angular"),
    ("data-reactroot", "react"),
)
_STACK_PATH_MARKERS = (("/_next/", "next.js"), ("/_nuxt/", "nuxt"))


def stack_signals(headers: dict, html: str, scripts: list[str]) -> list[str]:
    """Passive stack hints from headers, HTML structure and script paths.

    Signals, not proof: structural markers only (never prose substrings),
    deduplicated in first-seen order. The report repeats this caveat.
    """
    hints: list[str] = []

    def add(value: str) -> None:
        if value and value not in hints:
            hints.append(value)

    fields = {k.lower(): v for k, v in headers.items()}
    if isinstance(fields.get("x-powered-by"), str):
        add(fields["x-powered-by"].split(";")[0].strip().lower())
    if isinstance(fields.get("server"), str):
        add(fields["server"].split("/")[0].strip().lower())
    for header, label in (("cf-ray", "cloudflare"), ("x-vercel-id", "vercel")):
        if header in fields:
            add(label)
    for marker, label in _STACK_HTML_MARKERS:
        if marker in html:
            add(label)
    for script in scripts:
        for marker, label in _STACK_PATH_MARKERS:
            if marker in script:
                add(label)
    return hints


def profile_site(base_url: str) -> SiteProfile:
    res = http_get(base_url)
    interesting = {
        k: v for k, v in res.headers.items()
        if k.lower() in ("server", "x-powered-by", "via", "cf-ray", "x-vercel-id")
    }
    txt, contact = fetch_security_txt(base_url)
    return SiteProfile(base_url=base_url, server_headers=interesting,
                       security_txt=txt, contact=contact,
                       stack_hints=stack_signals(res.headers, res.text,
                                                 page_scripts(res.text, base_url)))


def _probe_manifests(url_for) -> dict[str, bytes]:
    """Probe the common manifest layout; 404s are skipped."""
    files: dict[str, bytes] = {}
    for directory in MANIFEST_DIRS:
        for name in LOCKFILE_NAMES:
            path = f"{directory}{name}"
            try:
                res = http_get(url_for(path))
            except ReconError:
                continue
            if res.status == 200 and res.body:
                files[path] = res.body
    return files


def github_manifests(owner: str, repo: str) -> dict[str, bytes]:
    """Fetch root + common-dir lockfiles from a public repository. 404s are skipped."""
    return _probe_manifests(
        lambda path: GITHUB_RAW.format(owner=owner, repo=repo, path=path))


def gitlab_manifests(project: str) -> dict[str, bytes]:
    """Fetch root + common-dir lockfiles from a public GitLab project. 404s are skipped."""
    quoted = urllib.parse.quote(project, safe="")
    return _probe_manifests(
        lambda path: GITLAB_RAW.format(project=quoted,
                                       path=urllib.parse.quote(path, safe="")))


def manifest_archive(files: dict[str, bytes]) -> dict[str, bytes]:
    """Validate shape before feeding the engine: text-only, bounded, sane names."""
    out: dict[str, bytes] = {}
    for name, data in files.items():
        if len(data) > 10_000_000:
            continue
        if "\0" in data[:1024].decode("utf-8", "replace"):
            continue
        out[name] = data
    return out


def page_scripts(html: str, base_url: str) -> list[str]:
    """Script URLs of a page: absolute, deduplicated, bounded."""
    urls: list[str] = []
    for match in _SCRIPT_SRC.finditer(html):
        url = urllib.parse.urljoin(base_url, match.group(1))
        if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
            continue
        if url not in urls:
            urls.append(url)
        if len(urls) >= MAX_BUNDLES:
            break
    return urls


def source_map_url(js_url: str, body: bytes, headers: dict) -> str | None:
    """Where this bundle's source map lives: SourceMap header, else tail comment."""
    ref = None
    header = {k.lower(): v for k, v in headers.items()}.get("sourcemap")
    if isinstance(header, str) and header.strip():
        ref = header.strip()
    else:
        tail = body[-4096:].decode("utf-8", "replace")
        for line in reversed(tail.splitlines()):
            line = line.strip()
            if line.startswith(_SOURCE_MAP_COMMENT):
                ref = line[len(_SOURCE_MAP_COMMENT):].strip()
                break
    if not ref:
        return None
    url = urllib.parse.urljoin(js_url, ref)
    return url if urllib.parse.urlsplit(url).scheme in ("http", "https") else None


def _map_document(body: bytes) -> dict | None:
    if len(body) > MAX_SOURCE_MAP_BYTES:
        return None
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def manifests_from_source_map(body: bytes) -> dict[str, bytes]:
    """Manifest files embedded in the map's sourcesContent - the real bytes."""
    data = _map_document(body)
    if data is None:
        return {}
    sources = data.get("sources")
    contents = data.get("sourcesContent")
    if not isinstance(sources, list) or not isinstance(contents, list):
        return {}
    out: dict[str, bytes] = {}
    for index, source in enumerate(sources[:MAX_MAP_SOURCES]):
        name = str(source).rstrip("/").rsplit("/", 1)[-1]
        if name not in SOURCE_MAP_MANIFESTS or index >= len(contents):
            continue
        content = contents[index]
        if isinstance(content, str):
            out.setdefault(name, content.encode("utf-8", "replace"))
    return out


def pins_from_source_map(body: bytes) -> dict[str, str]:
    """Resolved name -> version pins read from pnpm-style versioned install paths.

    Deployment evidence, not a lockfile: only paths that state a resolved
    version are pins; unversioned node_modules paths yield nothing.
    """
    data = _map_document(body)
    if data is None:
        return {}
    sources = data.get("sources")
    if not isinstance(sources, list):
        return {}
    pins: dict[str, str] = {}
    for source in sources[:MAX_MAP_SOURCES]:
        match = _PNPM_INSTALLED.search(str(source))
        if match is None:
            continue
        spec, name = match.groups()
        spec = spec.split("(")[0]
        if "@" not in spec:
            continue
        version = spec.rsplit("@", 1)[1]
        if _VERSION_PREFIX.match(version):
            pins.setdefault(name, version)
    return pins


def npm_lockfile_from_pins(pins: dict[str, str]) -> bytes:
    """Pack observed resolved pins as a minimal npm lockfile v3 document.

    The engine reads resolved pins from lockfiles only; this packages
    deployment-observed pins into that shape. Empty pins yield empty bytes:
    nothing observed, nothing fabricated.
    """
    if not pins:
        return b""
    packages = {"": {"name": "sourcemap-pins"}}
    for name, version in sorted(pins.items()):
        packages[f"node_modules/{name}"] = {"version": version}
    return json.dumps({"name": "sourcemap-pins", "lockfileVersion": 3,
                       "packages": packages}).encode()


def manifests_from_site(base_url: str) -> dict[str, bytes]:
    """Discover dependency artifacts from a deployed site via its source maps.

    Chain: HTML -> <script> bundles -> sourceMappingURL -> .map -> two tiers
    of evidence: real embedded manifests (sourcesContent) under sourcemap/,
    and resolved pins from versioned install paths packed under
    sourcemap-pins/. Bounded and best-effort: every failure yields fewer
    artifacts, never an error - absence of evidence is not evidence of safety.
    """
    out: dict[str, bytes] = {}
    try:
        page = http_get(base_url)
    except ReconError:
        return out
    if page.status != 200:
        return out
    pins: dict[str, str] = {}
    maps_read = 0
    for js_url in page_scripts(page.text, base_url):
        if maps_read >= MAX_MAPS:
            break
        try:
            js = http_get(js_url)
        except ReconError:
            continue
        if js.status != 200 or not js.body:
            continue
        map_url = source_map_url(js_url, js.body, js.headers)
        if map_url is None:
            continue
        try:
            mapped = http_get(map_url)
        except ReconError:
            continue
        if mapped.status != 200:
            continue
        maps_read += 1
        for name, data in manifests_from_source_map(mapped.body).items():
            out.setdefault(f"sourcemap/{name}", data)
        for name, version in pins_from_source_map(mapped.body).items():
            pins.setdefault(name, version)
    lock = npm_lockfile_from_pins(pins)
    if lock:
        out["sourcemap-pins/package-lock.json"] = lock
    return out
