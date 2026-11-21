"""Scan a deployment's web STRUCTURE: fixed probes, content-verified, read-only.

The third consented request the product makes against a customer's own
deployment, after the RLS check (a database) and the served-bundle check (the
shipped JavaScript). Both of those answer "is MY credential exposed"; neither
can answer "is the site itself misconfigured" — exposed .env and .git/config,
open directory listings, missing transport-security headers, a CORS policy that
answers any origin. Those live in the structure, not in any one asset, and this
module is the bounded way to look at it.

WHAT IT MAY AND MAY NOT DO, and the wall is the same one served_bundle.py
built:

  * READ-ONLY GET on a FIXED probe list. No payloads, no auth attempts, no
    parameter fuzzing, no exploitation, no crawling beyond the list. The probe
    list is data in this file (`EXPOSED_FILE_PROBES`, `LISTING_PATHS`); a path
    not in it is never requested, and its absence from the report is not
    evidence about anything.
  * EVERY positive is CONTENT-VERIFIED against a signature, never on status
    alone. A SPA answering 200 with the page shell for every unknown path is
    the normal shape of a modern site and the classic false-positive source; a
    body must contain the file's actual magic (a `[core]` line for .git/config,
    KEY=VALUE pairs for .env, the zip magic for a backup) before it is a
    finding. Signatures are non-secret fragments; no response body is copied
    into evidence, so a real secret stays where it was found and is never
    re-stored by us.
  * CONSENT has no default, exactly as rls_probe and fetch_served_bundle. The
    typed phrase lives at the edges (scripts/scan_site.py, the future route);
    the kernel takes `consent: bool` and answers `skipped` without it.
  * SSRF: the target goes through validate_deployment_url + resolve_and_vet
    from app/proof/served_bundle.py — every address the name resolves to must
    be public (loopback only for the local stand), and the default fetch pins
    to the vetted IP so the bytes come from the address that passed the guard.
    Redirects are NOT followed: each hop would be a URL the guard has not
    seen (and a root that redirects is an honest `error`, not a site to walk).
  * RATE: a minimum delay between requests and a hard request cap. This reads
    somebody's production server; the budget bounds their load as much as ours,
    and `probes_truncated` keeps a capped answer from reading as a full one.

WHAT THE ANSWER MAY SAY. `checked`, `skipped` and `error` are three different
answers and none of them is "your site is fine": `skipped` is a refusal or a
missing precondition, `error` is a target that did not answer, and only a run
that actually probed is `checked`. A clean `checked` still states its own
coverage: how many requests, how many paths, whether a catch-all was detected,
and the fixed-list limitation verbatim.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from app.proof.served_bundle import (
    UnsafeDeploymentUrl,
    resolve_and_vet,
    validate_deployment_url,
)

FETCH_TIMEOUT_S = 10
MAX_BODY_BYTES = 256 * 1024          # signatures live in the head of a body
MIN_DELAY_S = 0.2                    # between requests, to somebody's server
MAX_REQUESTS = 48                     # probes + root + http redirect + cors probe
MAX_REDIRECT_STATUS = 60             # 3xx observed without following

# The scanner identifies itself. Reading a site without saying who is reading
# is the one behaviour here that cannot be fixed by patching the target.
USER_AGENT = "DrydockSiteScan/1.0 (structure check; +https://drydock.co)"
CORS_PROBE_ORIGIN = "https://drydock-cors-probe.example"

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")

# ---------------------------------------------------------------------------
# The fixed probe lists. A probe is (path, severity, signature-check, what the
# finding means, how to fix it). Signatures are checked against the BODY of a
# 200-class answer; status alone never makes a finding (SPA catch-alls).


def _is_env_file(body: bytes) -> bool:
    """Two or more KEY=VALUE lines: an env file, not an HTML shell.

    The 200-with-page-shell answer to /.env is the single most common shape a
    naive scanner misreports; requiring two assignment lines excludes a stray
    `key=value` inside markup while keeping any real dotenv.
    """
    text = body[:8192].decode("utf-8", errors="replace")
    return len(re.findall(r"(?m)^[A-Za-z_][A-Za-z0-9_]*=[^\s]", text)) >= 2


def _is_sql_dump(body: bytes) -> bool:
    head = body[:65536].upper()
    return b"CREATE TABLE" in head or b"INSERT INTO" in head


def _env_key_names(body: bytes) -> str:
    """Key NAMES only (never values) — the evidence for an .env finding."""
    text = body[:8192].decode("utf-8", errors="replace")
    names = re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_]*)=", text)
    shown = ", ".join(names[:5]) + (f" (+{len(names) - 5} more)" if len(names) > 5 else "")
    return shown + " — значения не сохранены"


@dataclass(frozen=True)
class FileProbe:
    path: str
    severity: str
    # returns evidence text when the body matches, else None
    verify: Callable[[bytes], str | None]
    title: str
    detail: str
    recommendation: str


def _magic(sig: bytes, label: str) -> Callable[[bytes], str | None]:
    def check(body: bytes) -> str | None:
        return label if body.startswith(sig) or sig in body[:4096] else None
    return check


def _either(a: bytes, b: bytes, label: str) -> Callable[[bytes], str | None]:
    def check(body: bytes) -> str | None:
        head = body[:65536]
        return label if a in head or b in head else None
    return check


def _env_probe(label: str) -> Callable[[bytes], str | None]:
    def check(body: bytes) -> str | None:
        return _env_key_names(body) if _is_env_file(body) else None
    return check


def _sql_probe() -> Callable[[bytes], str | None]:
    def check(body: bytes) -> str | None:
        return "SQL-дамп (CREATE TABLE / INSERT INTO)" if _is_sql_dump(body) else None
    return check


EXPOSED_FILE_PROBES: tuple[FileProbe, ...] = (
    FileProbe("/.git/config", "critical", _magic(b"[core]", "конфиг git-репозитория"),
              "Открыт /.git/config",
              "Конфигурация git-репозитория доступна по прямому URL: из неё восстанавливается "
              "вся история исходного кода.",
              "Запретить отдачу dot-файлов веб-сервером (nginx: location ~ /\\. { deny all; }) "
              "и убрать .git из корня, который раздаёт сервер."),
    FileProbe("/.env", "critical", _env_probe("отдаёт строки KEY=VALUE"),
              "Открыт /.env",
              "Файл окружения с переменными доступен по прямому URL — вероятнее всего вместе с секретами.",
              "Удалить файл из публичного корня и запретить отдачу dot-файлов; проверить, какие ключи "
              "могли утечь, и ротировать их."),
    FileProbe("/.env.local", "critical", _env_probe("отдаёт строки KEY=VALUE"),
              "Открыт /.env.local",
              "Локальный файл окружения доступен по прямому URL — вероятнее всего вместе с секретами.",
              "Удалить файл из публичного корня и ротировать ключи, которые в нём были."),
    FileProbe("/.env.production", "critical", _env_probe("отдаёт строки KEY=VALUE"),
              "Открыт /.env.production",
              "Продакшн-файл окружения доступен по прямому URL.",
              "Удалить файл из публичного корня и ротировать ключи, которые в нём были."),
    FileProbe("/.aws/credentials", "critical", _magic(b"aws_access_key_id", "AWS credentials"),
              "Открыт /.aws/credentials",
              "AWS-ключи доступны по прямому URL.",
              "Немедленно ротировать ключи в IAM и удалить файл из публичного корня."),
    FileProbe("/.ssh/id_rsa", "critical", _magic(b"PRIVATE KEY", "PEM/OPENSSH private key"),
              "Открыт /.ssh/id_rsa",
              "Приватный ключ доступен по прямому URL.",
              "Немедленно удалить ключ с сервера, ротировать его везде, где он использовался."),
    FileProbe("/actuator/heapdump", "critical", _magic(b"JAVA PROFILE", "HPROF heap dump"),
              "Открыт /actuator/heapdump",
              "Дамп памяти приложения доступен по прямому URL: в нём оказываются строки, "
              "включая секреты, попавшие в кучу.",
              "Закрыть actuator от интернета (management.endpoints.web.exposure), ротировать "
              "секреты, которые могли попасть в дамп."),
    FileProbe("/backup.zip", "high", _magic(b"PK\x03\x04", "zip-архив"),
              "Открыт /backup.zip",
              "Архив резервной копии доступен по прямому URL.",
              "Удалить архив из публичного корня; вынести бэкапы за пределы раздачи."),
    FileProbe("/backup.tar.gz", "high", _magic(b"\x1f\x8b", "gzip-архив"),
              "Открыт /backup.tar.gz",
              "Архив резервной копии доступен по прямому URL.",
              "Удалить архив из публичного корня; вынести бэкапы за пределы раздачи."),
    FileProbe("/dump.sql", "high", _sql_probe(),
              "Открыт /dump.sql",
              "SQL-дамп доступен по прямому URL.",
              "Удалить дамп из публичного корня; вынести экспорт БД за пределы раздачи."),
    FileProbe("/db.sql", "high", _sql_probe(),
              "Открыт /db.sql",
              "SQL-дамп доступен по прямому URL.",
              "Удалить дамп из публичного корня; вынести экспорт БД за пределы раздачи."),
    FileProbe("/phpinfo.php", "high", _either(b"phpinfo()", b"PHP Version", "страница phpinfo"),
              "Открыт /phpinfo.php",
              "Страница phpinfo доступна по прямому URL: отдаёт версию PHP, модули и пути.",
              "Удалить отладочный скрипт с сервера."),
    FileProbe("/actuator/env", "high", _either(b"propertySources", b"activeProfiles",
                                               "Spring actuator env"),
              "Открыт /actuator/env",
              "Конфигурация приложения (Spring actuator) доступна по прямому URL — включая "
              "переменные окружения.",
              "Закрыть actuator от интернета; ротировать секреты, видимые в конфигурации."),
    FileProbe("/server-status", "medium", _either(b"Server uptime", b"Apache Server Status",
                                                  "Apache server-status"),
              "Открыт /server-status",
              "Внутренняя страница статуса Apache доступна по прямому URL.",
              "Отключить mod_status или закрыть его для внешних адресов."),
    FileProbe("/.DS_Store", "low", _magic(b"\x00\x00\x00\x01Bud1", "Bud1 (Apple .DS_Store)"),
              "Открыт /.DS_Store",
              "Файл .DS_Store доступен по прямому URL: раскрывает имена файлов в директории.",
              "Удалить файл из публичного корня; исключить .DS_Store из сборки деплоя."),
    FileProbe("/.htaccess", "low", _either(b"RewriteEngine", b"AuthType", "конфиг Apache"),
              "Открыт /.htaccess",
              "Конфиг веб-сервера доступен по прямому URL.",
              "Запретить отдачу dot-файлов веб-сервером."),
)

# Directory auto-indexing, checked on a fixed set of common static dirs. The
# root answer is reused for "/". Titles of the two mainstream auto-indexers;
# free-text "Index of" in markup would match ordinary content pages.
LISTING_PATHS: tuple[str, ...] = (
    "/", "/static/", "/assets/", "/public/", "/uploads/", "/files/", "/dist/", "/media/",
)
_INDEX_TITLE = re.compile(rb"<title>(?:Index of /|Directory listing for )", re.IGNORECASE)

# The honest, always-stated limits of the answer. A reader of a clean report
# must not have to guess what "clean" covered.
LIMITATIONS: tuple[str, ...] = (
    "список проб фиксирован и короток: путь, которого нет в списке, не проверялся, "
    "и отсутствие находок не доказывает отсутствия файлов",
    "аутентификация не выполнялась, JavaScript не исполнялся: состояние, доступное только "
    "после входа или после рендера, не проверялось",
    "протоколы и шифры TLS не проверялись; проверена только валидность сертификата при запросе",
    "никаких попыток эксплуатации не производилось; все находки — наблюдаемые факты конфигурации",
    "запросы шли с честным User-Agent и видны в логах цели",
)


# ---------------------------------------------------------------------------
# Result shapes. `checked`/`skipped`/`error` keep the served-bundle contract:
# a refusal is a result with a reason, never an exception, and none of the
# three means "safe".


@dataclass(frozen=True)
class WebFinding:
    check_id: str
    severity: str
    title: str
    detail: str
    recommendation: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id, "severity": self.severity, "title": self.title,
            "detail": self.detail, "recommendation": self.recommendation,
            "evidence": self.evidence,
        }


@dataclass
class CheckRun:
    check_id: str
    status: str                     # ran | skipped | failed
    detail: str = ""

    def to_json(self) -> dict[str, Any]:
        return {"check_id": self.check_id, "status": self.status, "detail": self.detail}


@dataclass
class WebScanResult:
    status: str                      # "checked" | "skipped" | "error"
    detail: str
    findings: list[WebFinding] = field(default_factory=list)
    checks: list[CheckRun] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0

    @property
    def worst_severity(self) -> str | None:
        return max(
            (f.severity for f in self.findings),
            key=lambda s: SEVERITY_ORDER.index(s), default=None,
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "status": self.status, "detail": self.detail,
            "findings": [f.to_json() for f in self.findings],
            "checks": [c.to_json() for c in self.checks],
            "coverage": self.coverage, "limitations": self.limitations,
            "evidence": self.evidence, "duration_ms": self.duration_ms,
        }


# The fetch boundary: (url, host, port, max_bytes, extra_headers) ->
# (status_code, headers as ordered lowercase list, body capped at max_bytes).
# Injectable for tests exactly as served_bundle's FetchText; the default pins
# to a vetted IP — a caller injecting its own fetch inherits the duty.
FetchDoc = Callable[[str, str, int, int, dict[str, str] | None], tuple[int, list[tuple[str, str]], bytes]]


def default_fetch_doc(*, allow_loopback: bool = False, timeout_s: int = FETCH_TIMEOUT_S) -> FetchDoc:
    """GET pinned to a vetted IP, redirects OFF, size-capped, honest UA.

    Connecting by IP with the original Host (and SNI for TLS) closes the
    resolve-then-connect TOCTOU the same way served_bundle does: the bytes
    come from the address the guard checked.
    """
    import httpx

    def fetch_doc(url: str, host: str, port: int, max_bytes: int,
                  extra_headers: dict[str, str] | None = None
                  ) -> tuple[int, list[tuple[str, str]], bytes]:
        parsed = urlsplit(url)
        # Re-vet here too: this default must be safe even if called directly.
        ips = resolve_and_vet(host, port, allow_loopback=allow_loopback)
        ip = ips[0]
        connect_netloc = f"[{ip}]" if ":" in ip else ip
        connect_url = (f"{parsed.scheme}://{connect_netloc}:{port}"
                       f"{parsed.path or '/'}")
        headers = {"Host": host if parsed.port is None else f"{host}:{parsed.port}",
                   "Accept": "text/html,application/xhtml+xml,*/*",
                   "User-Agent": USER_AGENT}
        if extra_headers:
            headers.update(extra_headers)
        extensions = {"sni_hostname": host} if parsed.scheme == "https" else {}
        with httpx.Client(follow_redirects=False, timeout=timeout_s, verify=True) as client:
            with client.stream("GET", connect_url, headers=headers, extensions=extensions) as response:
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) >= max_bytes:
                        break
                flat = [(k.lower(), v) for k, v in response.headers.multi_items()]
                return response.status_code, flat, bytes(body[:max_bytes])
    return fetch_doc


class _Budget:
    """One place that knows how many requests were sent and why stops happen."""

    def __init__(self, fetch: FetchDoc, delay_s: float, max_requests: int):
        self._fetch = fetch
        self._delay = delay_s
        self.max_requests = max_requests
        self.sent = 0
        self.failures: list[str] = []
        self._first = True

    def remaining(self) -> int:
        return self.max_requests - self.sent

    def get(self, url: str, host: str, port: int, max_bytes: int = MAX_BODY_BYTES,
            extra_headers: dict[str, str] | None = None
            ) -> tuple[int, list[tuple[str, str]], bytes] | None:
        """One bounded request. None means "not sent" (budget) — the caller
        records that as a skip, never as a clean result."""
        if self.remaining() <= 0:
            return None
        if not self._first and self._delay > 0:
            time.sleep(self._delay)
        self._first = False
        self.sent += 1
        try:
            return self._fetch(url, host, port, max_bytes, extra_headers)
        except Exception as exc:  # noqa: BLE001 — infrastructure, not a verdict
            self.failures.append(f"{url}: {type(exc).__name__}")
            return None


def _header(headers: list[tuple[str, str]], name: str) -> str | None:
    for key, value in headers:
        if key == name:
            return value
    return None


def _meta_csp(body: bytes) -> str | None:
    """A Content-Security-Policy declared in a <meta http-equiv> tag, if any.

    Valid for most directives — many static hosts ship exactly this form — so
    a header-only check misreports a real policy as absent. What meta CANNOT
    do (spec): frame-ancestors, report-uri/report-to are ignored there, and
    the policy only engages after parsing begins. The caller keeps those
    consequences visible instead of flattening "meta" into "none".
    """
    for match in re.finditer(rb"<meta\b[^>]*>", body[:262144], re.IGNORECASE):
        tag = match.group(0)
        if not re.search(rb"http-equiv\s*=\s*[\"']?\s*content-security-policy",
                         tag, re.IGNORECASE):
            continue
        # CSP values legitimately contain single quotes ('self', 'none'), so
        # the closing quote must MATCH the opening one; a [^"']* character class
        # truncates every real policy at its first source expression.
        content = re.search(
            rb"content\s*=\s*(?:\"([^\"]*)\"|'([^']*)')", tag, re.IGNORECASE)
        if content:
            raw = content.group(1) if content.group(1) is not None else content.group(2)
            return raw.decode("utf-8", errors="replace")[:400]
    return None


def _all(headers: list[tuple[str, str]], name: str) -> list[str]:
    return [value for key, value in headers if key == name]


# ---------------------------------------------------------------------------
# Checks. Every check appends CheckRun rows and findings; none of them
# silently swallows a failed request — a probe that could not be made is a
# skipped/failed row, so a partial run can never read as a clean one.


def _check_https_redirect(budget: _Budget, host: str, checks: list[CheckRun],
                          findings: list[WebFinding]) -> None:
    run = CheckRun("web-https-redirect", "ran")
    checks.append(run)
    answer = budget.get(f"http://{host}/", host, 80)
    if answer is None:
        run.status = "skipped"
        run.detail = ("не удалось опросить http:// порта 80"
                      if not budget.failures else "запрос на http:// не выполнен")
        return
    status, headers, _body = answer
    if status not in (301, 302, 307, 308):
        if status >= 200 and status < 300:
            findings.append(WebFinding(
                "web-https-redirect", "low", "Сайт отдаёт контент по http без редиректа",
                "Обращение по http:// получает 200 вместо редиректа на https:// "
                "(первые визиты и ссылки-опечатки идут по http).",
                "Настроить 301-редирект http→https на уровне веб-сервера.",
                evidence={"probe": "http://port-80", "status": status}))
            run.detail = "http:// отвечает контентом (200), не редиректом"
        else:
            run.detail = f"http:// ответил {status} (не редирект на https)"
            findings.append(WebFinding(
                "web-https-redirect", "low", "http:// не редиректит на https://",
                f"Обращение по http:// получает {status}, а не редирект на https://.",
                "Настроить 301-редирект http→https на уровне веб-сервера.",
                evidence={"probe": "http://port-80", "status": status}))
        return
    location = _header(headers, "location") or ""
    if location.startswith("https://"):
        run.detail = f"редирект на {location[:100]}"
        return
    findings.append(WebFinding(
        "web-https-redirect", "medium", "Редирект с http:// ведёт не на https://",
        f"http:// редиректит на {location[:100] or 'location отсутствует'} — цепочка может "
        "оставить пользователя на незащищённом соединении.",
        "Редиректить http-запросы сразу на https-версию того же URL.",
        evidence={"probe": "http://port-80", "status": status, "location": location[:200]}))
    run.detail = f"редирект ведёт на {location[:100]}"


def _check_security_headers(headers: list[tuple[str, str]], body: bytes, https: bool,
                            checks: list[CheckRun], findings: list[WebFinding]) -> None:
    run = CheckRun("web-security-headers", "ran")
    checks.append(run)
    if not https:
        run.status = "skipped"
        run.detail = "заголовки безопасности оцениваются только на https-ответе"
        return
    hsts = _header(headers, "strict-transport-security") or ""
    if not hsts:
        findings.append(WebFinding(
            "web-security-headers", "medium", "Нет HSTS (Strict-Transport-Security)",
            "Без HSTS браузер согласится на http-соединение при первом визите и при "
            "MITM-вставке — это хардинг транспорта, не подтверждённая уязвимость.",
            "Отдавать Strict-Transport-Security: max-age=31536000 после того, как https "
            "полностью работает.",
            evidence={"header": "strict-transport-security", "observed": ""}))
    else:
        match = re.search(r"max-age=(\d+)", hsts)
        age = int(match.group(1)) if match else 0
        if age < 10_368_000:
            findings.append(WebFinding(
                "web-security-headers", "low", "HSTS короче рекомендуемых 120 дней",
                f"max-age={age} (рекомендация OWASP: не менее 10368000).",
                "Поднять max-age до 10368000 и выше.",
                evidence={"header": "strict-transport-security", "observed": hsts[:200]}))
    if not _header(headers, "x-content-type-options"):
        findings.append(WebFinding(
            "web-security-headers", "low", "Нет X-Content-Type-Options: nosniff",
            "Браузер может интерпретировать ответ как другой тип содержимого (хардинг).",
            "Отдавать X-Content-Type-Options: nosniff.",
            evidence={"header": "x-content-type-options", "observed": ""}))
    csp = _header(headers, "content-security-policy") or ""
    meta_csp = _meta_csp(body) if not csp else None
    if not csp and meta_csp is not None:
        findings.append(WebFinding(
            "web-security-headers", "low", "CSP задан только через meta-тег",
            "Политика нашлась в <meta http-equiv=...> страницы, а не в HTTP-заголовке. "
            "Для большинства директив meta-форма действует, но frame-ancestors и report-uri/"
            "report-to в meta игнорируются по спецификации, и политика включается позже "
            "начала разбора страницы.",
            "Перенести CSP в HTTP-заголовок ответа (web-сервер или платформа хостинга).",
            evidence={"header": "content-security-policy", "observed": "meta-тег",
                      "meta_directives": meta_csp[:200]}))
    elif not csp:
        findings.append(WebFinding(
            "web-security-headers", "low", "Нет Content-Security-Policy",
            "Без CSP инъекция в разметку не ограничивается политикой (хардинг).",
            "Ввести CSP, начиная с report-only, если продакшн ещё не готов к блокировке.",
            evidence={"header": "content-security-policy", "observed": ""}))
    # frame-ancestors counts ONLY from the header form: in meta it is ignored
    # by every browser, so a meta policy naming it still leaves the site framable.
    frame_ancestors = "frame-ancestors" in csp
    xfo = _header(headers, "x-frame-options")
    if not xfo and not frame_ancestors:
        findings.append(WebFinding(
            "web-security-headers", "low", "Нет защиты от кликджекинга",
            "Ни X-Frame-Options, ни frame-ancestors в CSP (хардинг).",
            "Добавить frame-ancestors в CSP или X-Frame-Options: DENY/SAMEORIGIN.",
            evidence={"header": "x-frame-options", "observed": ""}))
    if not _header(headers, "referrer-policy"):
        findings.append(WebFinding(
            "web-security-headers", "info", "Нет Referrer-Policy",
            "Referer уводит полный URL на сторонние ресурсы (хардинг, не уязвимость).",
            "Отдавать Referrer-Policy: strict-origin-when-cross-origin.",
            evidence={"header": "referrer-policy", "observed": ""}))


def _check_cookie_flags(headers: list[tuple[str, str]], https: bool,
                        checks: list[CheckRun], findings: list[WebFinding]) -> None:
    run = CheckRun("web-cookie-flags", "ran")
    checks.append(run)
    if not https:
        # Flags are unjudgeable on a plain-http answer: judged there, any cookie
        # would fire, and no cookie would read as "checked and clean" about a
        # transport the check never saw. Skipped before looking.
        run.status = "skipped"
        run.detail = "флаги cookie оцениваются только на https-ответе"
        return
    cookies = _all(headers, "set-cookie")
    if not cookies:
        run.detail = "cookie в ответе нет"
        return
    session_like = re.compile(r"(session|token|auth|sid|jwt|remember)", re.IGNORECASE)
    insecure: list[str] = []
    for raw in cookies:
        parts = raw.split(";")
        name = parts[0].split("=", 1)[0].strip()
        attrs = {}
        for part in parts[1:]:
            key, _, value = part.strip().partition("=")
            attrs[key.lower()] = value
        evidence = {"cookie": name, "observed_attrs": sorted(attrs)}
        if "secure" not in attrs:
            findings.append(WebFinding(
                "web-cookie-flags", "medium", f"Cookie «{name}» без флага Secure",
                "Cookie уходит по незащищённому соединению, если оно возникнет.",
                "Добавить атрибут Secure в Set-Cookie.", evidence=evidence))
            insecure.append(name)
        if session_like.search(name) and "httponly" not in attrs:
            findings.append(WebFinding(
                "web-cookie-flags", "medium", f"Сессионная cookie «{name}» без HttpOnly",
                "JavaScript (и внедрившийся скрипт) может прочитать её значение.",
                "Добавить атрибут HttpOnly, если cookie не нужна клиентскому коду.",
                evidence=evidence))
        samesite = attrs.get("samesite", "").lower()
        if not samesite:
            findings.append(WebFinding(
                "web-cookie-flags", "low", f"Cookie «{name}» без SameSite",
                "Cookie посылается в кросс-сайтовых запросах (CSRF-поверхность).",
                "Добавить SameSite=Lax или Strict.", evidence=evidence))
        elif samesite == "none" and "secure" not in attrs:
            findings.append(WebFinding(
                "web-cookie-flags", "medium", f"Cookie «{name}»: SameSite=None без Secure",
                "SameSite=None требует Secure; браузеры отвергнут такую cookie.",
                "Добавить Secure либо убрать SameSite=None.", evidence=evidence))
    run.detail = f"проверено cookie: {len(cookies)}"


def _check_server_banner(headers: list[tuple[str, str]], checks: list[CheckRun],
                         findings: list[WebFinding]) -> None:
    run = CheckRun("web-server-banner", "ran")
    checks.append(run)
    server = _header(headers, "server") or ""
    if re.search(r"\d", server):
        findings.append(WebFinding(
            "web-server-banner", "low", f"Заголовок Server раскрывает версию: {server[:60]}",
            "Точная версия ПО помогает подобрать публичные эксплойты (инвентарь, не уязвимость).",
            "Убрать версию из Server (nginx: server_tokens off; Apache: ServerTokens Prod).",
            evidence={"header": "server", "observed": server[:200]}))
    powered = _header(headers, "x-powered-by") or ""
    if powered:
        findings.append(WebFinding(
            "web-server-banner", "low", f"Заголовок X-Powered-By: {powered[:60]}",
            "Раскрывает технологический стек (инвентарь, не уязвимость).",
            "Убирать X-Powered-By на прокси/приложении.",
            evidence={"header": "x-powered-by", "observed": powered[:200]}))
    run.detail = f"Server: {server[:60] or 'скрыт'}"


def _check_mixed_content(status: int, headers: list[tuple[str, str]], body: bytes,
                         checks: list[CheckRun], findings: list[WebFinding]) -> None:
    run = CheckRun("web-mixed-content", "ran")
    checks.append(run)
    content_type = _header(headers, "content-type") or ""
    if status != 200 or "html" not in content_type.lower():
        run.status = "skipped"
        run.detail = f"корень — не HTML ({content_type[:60] or 'тип неизвестен'})"
        return
    text = body[:262144].decode("utf-8", errors="replace")
    urls = re.findall(r"""<(?:script|img)[^>]*\ssrc\s*=\s*["']http://[^"']+""", text)
    if urls:
        examples = [u[:120] for u in urls[:3]]
        findings.append(WebFinding(
            "web-mixed-content", "medium", "На https-странице есть http-подключения",
            f"Найдено {len(urls)} подключений по http:// к скриптам/картинкам: активный "
            "подмешанный контент даёт MITM-окно на «защищённой» странице.",
            "Перевести все src на https:// (или протокол-относительные не использовать вовсе).",
            evidence={"count": len(urls), "examples": examples}))
    run.detail = f"http-включений в разметке: {len(urls)}"


def _check_cors(budget: _Budget, target, checks: list[CheckRun],
                findings: list[WebFinding]) -> None:
    run = CheckRun("web-cors", "ran")
    checks.append(run)
    answer = budget.get(target.url, target.host, target.port,
                        extra_headers={"Origin": CORS_PROBE_ORIGIN})
    if answer is None:
        run.status = "skipped"
        run.detail = "проба Origin не отправлена (бюджет или сбой)"
        return
    status, headers, _body = answer
    acao = _header(headers, "access-control-allow-origin") or ""
    acac = (_header(headers, "access-control-allow-credentials") or "").lower()
    credentials = acac == "true"
    evidence = {"probe_origin": CORS_PROBE_ORIGIN, "allow_origin": acao[:200],
                "allow_credentials": credentials}
    reflected = acao == CORS_PROBE_ORIGIN
    if reflected and credentials:
        findings.append(WebFinding(
            "web-cors", "high", "CORS отражает произвольный Origin с разрешением credentials",
            "Сервер отвечает Access-Control-Allow-Origin на любой Origin И allows "
            "credentials: любой сайт может читать ответы для залогиненного пользователя.",
            "Задать whitelist допустимых Origin вместо отражения; никогда не сочетать "
            "отражение Origin с Allow-Credentials.",
            evidence=evidence))
    elif acao == "*" and credentials:
        findings.append(WebFinding(
            "web-cors", "medium", "CORS: * вместе с Allow-Credentials",
            "Браузеры такое сочетание отвергают, но оно показывает, что политика собирается "
            "не осознанно.",
            "Убрать Access-Control-Allow-Credentials или задать явный список Origin.",
            evidence=evidence))
    elif reflected:
        findings.append(WebFinding(
            "web-cors", "medium", "CORS отражает произвольный Origin",
            "Любой сайт может читать публичные ответы без credentials. Для публичного "
            "контента это осознанное решение, для API — нет.",
            "Задать whitelist допустимых Origin.",
            evidence=evidence))
    run.detail = f"status={status}, allow-origin={'отражён' if reflected else acao[:60] or 'нет'}"


def _check_security_txt(budget: _Budget, target, checks: list[CheckRun],
                        findings: list[WebFinding]) -> None:
    run = CheckRun("web-security-txt", "ran")
    checks.append(run)
    for path in ("/.well-known/security.txt", "/security.txt"):
        answer = budget.get(target.url.rstrip("/") + path, target.host, target.port)
        if answer is None:
            continue
        status, _headers, body = answer
        if status == 200:
            if b"Contact:" in body[:4096]:
                run.detail = f"найден на {path} с полем Contact"
                return
            findings.append(WebFinding(
                "web-security-txt", "info", "security.txt без поля Contact",
                f"Файл на {path} доступен, но не называет контакт для отчётов об уязвимостях.",
                "Добавить поле Contact (RFC 9116).",
                evidence={"path": path, "status": status}))
            run.detail = f"найден на {path} без поля Contact"
            return
    findings.append(WebFinding(
        "web-security-txt", "info", "security.txt не найден",
        "Нет объявления канала приёма отчётов об уязвимостях (RFC 9116) — исследователю "
        "некуда писать. Это про коммуникацию, не про уязвимость.",
        "Опубликовать /.well-known/security.txt с Contact.",
        evidence={"checked": ["/.well-known/security.txt", "/security.txt"]}))
    run.detail = "не найден"


def _check_directory_listing(budget: _Budget, target, root_status: int,
                             root_headers: list[tuple[str, str]], root_body: bytes,
                             checks: list[CheckRun], findings: list[WebFinding],
                             root_sha: str) -> tuple[int, str | None]:
    """Returns (probes sent, catch-all marker) for coverage."""
    run = CheckRun("web-directory-listing", "ran")
    checks.append(run)
    listed: list[str] = []
    sent = 0
    catch_all_hits = 0
    for path in LISTING_PATHS:
        if path == "/":
            status, headers, body = root_status, root_headers, root_body
        else:
            answer = budget.get(target.url.rstrip("/") + path, target.host, target.port)
            if answer is None:
                continue
            sent += 1
            status, headers, body = answer
            if status == 200 and hashlib.sha256(body).hexdigest() == root_sha:
                catch_all_hits += 1
        if 200 <= status < 300 and _INDEX_TITLE.search(body[:4096]):
            listed.append(path)
            findings.append(WebFinding(
                "web-directory-listing", "medium", f"Листинг директории на {path}",
                "Сервер отдаёт автоиндекс содержимого директории — видны имена всех файлов.",
                "Отключить autoindex (nginx: autoindex off; Apache: Options -Indexes).",
                evidence={"path": path, "status": status}))
    run.detail = f"проверено путей: {len(LISTING_PATHS)}, с листингом: {len(listed)}"
    return sent, ("catch_all" if catch_all_hits >= 3 else None)


def _check_exposed_files(budget: _Budget, target, checks: list[CheckRun],
                         findings: list[WebFinding], root_sha: str) -> tuple[int, int, str | None]:
    """Returns (probes sent, 404s seen, catch-all marker)."""
    run = CheckRun("web-exposed-files", "ran")
    checks.append(run)
    sent = 0
    not_found = 0
    catch_all_hits = 0
    found: list[str] = []
    for probe in EXPOSED_FILE_PROBES:
        answer = budget.get(target.url.rstrip("/") + probe.path, target.host, target.port)
        if answer is None:
            continue
        sent += 1
        status, _headers, body = answer
        if status == 404:
            not_found += 1
            continue
        if not 200 <= status < 300:
            continue
        if hashlib.sha256(body).hexdigest() == root_sha:
            catch_all_hits += 1
            continue          # the page shell answered, not the file
        signature = probe.verify(body)
        if signature is None:
            continue
        found.append(probe.path)
        findings.append(WebFinding(
            "web-exposed-files", probe.severity, probe.title, probe.detail,
            probe.recommendation,
            evidence={"path": probe.path, "status": status, "signature": signature}))
    run.detail = f"проб: {sent}, открыто: {len(found)}"
    return sent, not_found, ("catch_all" if catch_all_hits >= 3 else None)


# ---------------------------------------------------------------------------


def run_web_structure_scan(
    *,
    url: str,
    consent: bool,
    allow_loopback: bool = False,
    resolver: Callable[[str, int], list] | None = None,
    fetch: FetchDoc | None = None,
    delay_s: float = MIN_DELAY_S,
    max_requests: int = MAX_REQUESTS,
    timeout_s: int = FETCH_TIMEOUT_S,
) -> WebScanResult:
    """Scan a site's structure with fixed, content-verified, read-only probes.

    The kernel takes `consent: bool`; the typed phrase (`i-own-this-project`)
    is checked at the edges — scripts/scan_site.py today, the route when one
    exists — exactly as fetch_served_bundle does. A missing consent is
    `skipped`, an unsafe target is `skipped` with the reason, a target that
    will not answer is `error`; only a run that probed is `checked`.
    """
    started = time.monotonic()

    def done(status: str, detail: str, **kw: Any) -> WebScanResult:
        return WebScanResult(
            status=status, detail=detail, duration_ms=int((time.monotonic() - started) * 1000),
            **kw)

    if not consent:
        return done("skipped", "не запускалось: нет подтверждённого согласия владельца сайта",
                    evidence={"reason": "no_consent"},
                    limitations=list(LIMITATIONS))

    try:
        target = validate_deployment_url(url, allow_loopback=allow_loopback)
        resolve_and_vet(target.host, target.port, allow_loopback=allow_loopback,
                        resolver=resolver)
    except UnsafeDeploymentUrl as exc:
        return done("skipped", str(exc), evidence={"reason": "unsafe_url"},
                    limitations=list(LIMITATIONS))

    budget = _Budget(fetch or default_fetch_doc(allow_loopback=allow_loopback,
                                                timeout_s=timeout_s),
                     delay_s=delay_s, max_requests=max_requests)

    root = budget.get(target.url, target.host, target.port)
    status, headers, body = root if root is not None else (None, [], b"")
    if status is None:
        return done("error", "корень сайта недоступен: запрос не выполнился",
                    evidence={"reason": "request_failed",
                              "failures": budget.failures[:5]},
                    limitations=list(LIMITATIONS))
    if status >= 300 and status < 400:
        return done("error",
                    f"сайт ответил {status} на корень; редиректы не преследуются — "
                    "укажите итоговый URL",
                    evidence={"reason": "root_redirect", "status": status},
                    limitations=list(LIMITATIONS))
    if status != 200:
        return done("error", f"сайт ответил {status} на корень",
                    evidence={"reason": "bad_status", "status": status},
                    limitations=list(LIMITATIONS))

    findings: list[WebFinding] = []
    checks: list[CheckRun] = []
    root_sha = hashlib.sha256(body).hexdigest()
    https = target.scheme == "https"

    _check_security_headers(headers, body, https, checks, findings)
    _check_cookie_flags(headers, https, checks, findings)
    _check_server_banner(headers, checks, findings)
    _check_mixed_content(status, headers, body, checks, findings)
    if https:
        _check_https_redirect(budget, target.host, checks, findings)
    else:
        checks.append(CheckRun("web-https-redirect", "skipped",
                                "цель не https; проверка имеет смысл только для https-сайта"))
    _check_cors(budget, target, checks, findings)
    _check_security_txt(budget, target, checks, findings)
    listing_sent, listing_catch_all = _check_directory_listing(
        budget, target, status, headers, body, checks, findings, root_sha)
    exposed_sent, _not_found, exposed_catch_all = _check_exposed_files(
        budget, target, checks, findings, root_sha)

    catch_all = listing_catch_all or exposed_catch_all
    limitations = list(LIMITATIONS)
    if catch_all:
        limitations.append(
            "сайт отвечает 200 оболочкой страницы на неизвестные пути (catch-all): все пробы "
            "сверялись с содержимым, но «404 = файла нет» здесь не работает")
    truncated = budget.remaining() <= 0
    if truncated:
        limitations.append("достигнут лимит запросов: часть списка проб не отправлена")

    worst = max((f.severity for f in findings), key=lambda s: SEVERITY_ORDER.index(s),
                default=None)
    detail = ("открытых элементов структуры не найдено"
              if not findings else
              f"находок: {len(findings)}" + (f", серьёзнейшая — {worst}" if worst else ""))
    coverage = {
        "requests_sent": budget.sent,
        "max_requests": budget.max_requests,
        "probes_truncated": truncated,
        "paths_probed": 1 + listing_sent + exposed_sent,
        "file_probes_total": len(EXPOSED_FILE_PROBES),
        "listing_paths_total": len(LISTING_PATHS),
        "catch_all_detected": bool(catch_all),
        "request_failures": budget.failures[:10],
    }
    return done("checked", detail, findings=findings, checks=checks,
                coverage=coverage, limitations=limitations,
                evidence={"target": target.url, "host": target.host,
                          "scheme": target.scheme, "worst_severity": worst})


def render_text(result: WebScanResult) -> str:
    """Terminal rendering; every finding with its fix, coverage and limits."""
    lines = [f"Скан структуры сайта: {result.status} — {result.detail}"]
    order = {name: i for i, name in enumerate(SEVERITY_ORDER)}
    for finding in sorted(result.findings, key=lambda f: -order[f.severity]):
        lines.append(f"[{finding.severity.upper()}] {finding.title} ({finding.check_id})")
        lines.append(f"    {finding.detail}")
        if finding.evidence:
            shown = ", ".join(f"{k}={v}" for k, v in finding.evidence.items()
                              if isinstance(v, (str, int)))
            lines.append(f"    evidence: {shown[:200]}")
        lines.append(f"    fix: {finding.recommendation}")
    if not result.findings:
        lines.append("Находок нет. «Нет находок» — не доказательство безопасности.")
    checks_ran = [c.check_id for c in result.checks if c.status == "ran"]
    checks_skipped = [f"{c.check_id} ({c.detail})" for c in result.checks if c.status != "ran"]
    lines.append(f"Проверки: {len(checks_ran)} выполнено"
                 + (f", пропущено: {', '.join(checks_skipped)}" if checks_skipped else ""))
    if result.coverage:
        lines.append(f"Покрытие: {result.coverage}")
    for limitation in result.limitations:
        lines.append(f"Ограничение: {limitation}")
    lines.append(f"Время: {result.duration_ms} мс")
    return "\n".join(lines)
