"""Synthetic source fixtures: no uploaded code, no network, no live session.

The load-bearing tests:

  * every corpus negative is MUTATED in the one place that removes the property it
    pins, and the rule must fire on the result -- silence alone proves nothing;
  * every negative on disk has a mutation (the completeness assertion below);
  * the product's own code is scanned with its PREMISE asserted: our tree sets one
    cookie and it carries all three flags, which is the CORRECT form this rule
    reads -- so the silence is not silence over an archive with nothing in it;
  * a dependency directory is not the repository's own code: the same defect under
    `node_modules/` must not be reported.
"""

import io
import re
import zipfile
from pathlib import Path

import pytest

from app.scan.cookie_flags import RULE_ID, _MAX_FINDINGS, scan_cookie_flags
from app.scan.static import run_static_scan

REPO_ROOT = Path(__file__).resolve().parent.parent

PYTHON_POSITIVE = """from fastapi import APIRouter, Response

router = APIRouter()


@router.post("/login")
async def login(response: Response, token: str):
    response.set_cookie("session_id", token)
    return {"ok": True}
"""

TS_POSITIVE = """import { cookies } from "next/headers";

export async function login(token: string) {
  const store = await cookies();
  store.set("session", token, { httpOnly: false });
}
"""


def archive(files: dict[str, str] | str, path: str = "repo/app/login.py") -> io.BytesIO:
    if isinstance(files, str):
        files = {path: files}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    buf.seek(0)
    return buf


def test_a_session_cookie_without_httponly_is_a_finding_on_its_own_line():
    findings = scan_cookie_flags(archive(PYTHON_POSITIVE))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == RULE_ID
    assert finding.severity == "medium"
    assert finding.line == 8
    assert "no HttpOnly" in finding.explanation
    assert "session_id" in finding.explanation
    assert "have NOT been verified" in finding.explanation


def test_the_typescript_half_reads_the_same_claim():
    findings = scan_cookie_flags(archive(TS_POSITIVE, "repo/src/app/actions.ts"))
    assert len(findings) == 1
    assert findings[0].line == 5
    assert "HttpOnly switched off" in findings[0].explanation


def test_a_tsx_file_is_parsed_as_tsx():
    """The customer's language is mostly TSX; a rule that only parsed .ts would be
    silent on the files it exists for."""
    source = """import { cookies } from "next/headers";

export default function Page() {
  const store = cookies();
  store.set("session", "x", { httpOnly: false });
  return null;
}
"""
    findings = scan_cookie_flags(archive(source, "repo/src/app/page.tsx"))
    assert len(findings) == 1


def test_one_cookie_is_one_finding_however_many_attributes_are_missing():
    source = 'def h(response, token):\n    response.set_cookie("session", token, httponly=False, samesite="none")\n'
    findings = scan_cookie_flags(archive(source))
    assert len(findings) == 1, "a single cookie with two problems must not be counted twice"
    assert "HttpOnly switched off" in findings[0].explanation
    assert "SameSite=None" in findings[0].explanation


def test_a_dependency_directory_is_not_the_repository_own_code():
    """Measured: four shipped scanners reported a defect planted under
    node_modules/. Vendored code is not the customer's code, and a report that
    counts it is a false positive on every repository that commits its deps."""
    for path in ("repo/node_modules/pkg/index.js", "repo/vendor/lib/client.ts",
                 "repo/web/node_modules/next/dist/x.js"):
        assert scan_cookie_flags(archive(TS_POSITIVE, path)) == [], path


def test_the_findings_are_capped_and_the_scan_stays_bounded():
    source = "".join(f'def h{i}(response):\n    response.set_cookie("session_{i}", "x")\n\n'
                     for i in range(_MAX_FINDINGS + 20))
    findings = scan_cookie_flags(archive(source))
    assert len(findings) == _MAX_FINDINGS


def test_nothing_is_reported_from_a_file_over_the_size_limit():
    source = PYTHON_POSITIVE + "# padding\n" * 40_000
    assert len(source.encode()) > 400_000
    assert scan_cookie_flags(archive(source)) == []


# case name -> (file, the one change that removes the property the case pins)
CORPUS_NEGATIVES = REPO_ROOT / "tests" / "detectors" / RULE_ID / "negative"
MUTATIONS: dict[str, tuple[str, str, str]] = {
    "python-correct-flags": ("app/login.py", 'httponly=True, secure=True, samesite="lax"',
                             'samesite="lax"'),
    "python-a-theme-cookie-is-not-a-session-cookie": ("app/prefs.py",
                                                      'set_cookie("theme", theme)',
                                                      'set_cookie("session_theme", theme)'),
    "python-double-submit-csrf-cookie": ("app/forms.py", '"csrf_token", token',
                                         '"session_token", token'),
    "python-flag-comes-from-a-variable": ("app/login.py", "httponly=HTTP_ONLY",
                                          "httponly=False"),
    "python-cookie-name-is-not-resolvable": ("app/login.py", "set_cookie(name, token)",
                                             'set_cookie("session_id", token)'),
    "python-django-samesite-python-none": ("app/settings.py", "SESSION_COOKIE_SAMESITE = None",
                                           'SESSION_COOKIE_SAMESITE = "None"'),
    "python-django-http-only-true": ("app/settings.py", "SESSION_COOKIE_HTTPONLY = True",
                                     "SESSION_COOKIE_HTTPONLY = False"),
    "js-correct-express-form": ("src/server.ts", "httpOnly: true", "httpOnly: false"),
    "js-session-config-omission-is-the-safe-default": (
        "src/app.ts", 'cookie: { sameSite: "lax", maxAge: 3600000 }',
        'cookie: { httpOnly: false, sameSite: "lax", maxAge: 3600000 }'),
    "js-options-are-a-variable": ("src/server.ts", "token, cookieOptions)",
                                  "token, { httpOnly: false })"),
    "js-comment-mentions-a-call": ("src/server.ts",
                                   '// res.cookie("session", token) is what we used to do',
                                   'res.cookie("session", token)  // was a comment'),
    "js-set-cookie-header-is-not-read": (
        "src/server.ts", 'res.setHeader("Set-Cookie", "session=" + token + "; Path=/");',
        'res.cookie("session", token);'),
    "js-store-set-is-not-a-cookie-store": (
        "src/cache.ts", 'await store.set("session", payload, { ttl: 60 });',
        'const store = await cookies();\n  await store.set("session", payload, { ttl: 60 });'),
}


def test_every_corpus_negative_has_a_mutation():
    """A negative with no mutation above is pinned by silence alone, and silence
    is the one thing a negative cannot prove."""
    on_disk = {case.name for case in CORPUS_NEGATIVES.iterdir() if case.is_dir()}
    assert on_disk == set(MUTATIONS), f"no mutation for: {on_disk - set(MUTATIONS)}"


@pytest.mark.parametrize("case", sorted(MUTATIONS))
def test_each_corpus_negative_goes_silent_for_its_stated_reason(case):
    relative, old, new = MUTATIONS[case]
    case_dir = CORPUS_NEGATIVES / case
    files = {p.relative_to(case_dir).as_posix().removesuffix(".fixture"): p.read_text()
             for p in case_dir.rglob("*.fixture")}
    assert scan_cookie_flags(archive(files)) == [], "the untouched case must be silent"
    assert old in files[relative], f"mutation anchor is gone from {relative}"
    files[relative] = files[relative].replace(old, new, 1)
    assert scan_cookie_flags(archive(files)), "the mutation must make the rule fire"


def test_the_product_own_code_reports_nothing():
    """A false-positive guard, with its premise asserted: our own tree SETS a
    cookie (app/accounts.py), and it carries all three flags -- the correct form.
    Silence over a tree that never sets one would prove nothing."""
    collected: dict[str, str] = {}
    for root in ("app", "web/src"):
        for path in (REPO_ROOT / root).rglob("*"):
            if path.suffix in {".py", ".ts", ".tsx", ".js", ".jsx"}:
                collected[path.relative_to(REPO_ROOT).as_posix()] = path.read_text(errors="replace")

    calls = [(name, text) for name, text in collected.items() if "set_cookie(" in text]
    assert calls, "the premise is gone: the product no longer sets a cookie at all"
    assert any(re.search(r"set_cookie\([^)]*httponly=True", text, re.S) for _name, text in calls), (
        "the product's own cookie is no longer the correct form")

    findings = scan_cookie_flags(archive(collected))
    assert findings == [], [f"{f.file}:{f.line} {f.title}" for f in findings]


def test_the_wired_stage_emits_the_rule():
    """Wiring check: the corpus harness runs the real stage, so a rule absent from
    it would pass every test above and ship silent."""
    result = run_static_scan(archive(PYTHON_POSITIVE))
    assert RULE_ID in {f["rule_id"] for f in result["findings"]}
    assert "session_cookie" in result["checks_run"]
