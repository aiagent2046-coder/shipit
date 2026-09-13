"""Synthetic source fixtures: no uploaded code is executed.

The load-bearing tests:

  * every corpus negative is MUTATED in the one place that removes the property it
    pins, and the rule must fire on the result;
  * every negative on disk has a mutation;
  * the product's own frontend is scanned with its premise asserted -- shipit's
    layout injects a fixed theme script through dangerouslySetInnerHTML, so the
    silence below is silence over code that uses the sink, not an empty archive.
"""
import io
import re
import zipfile
from pathlib import Path

import pytest

from app.scan.xss import RULE_ID, scan_xss
from app.scan.static import run_static_scan

REPO_ROOT = Path(__file__).resolve().parent.parent

POSITIVE = '''function render(message) {
  document.getElementById("log").innerHTML = message.html;
}
'''


def archive(files: dict[str, str] | str, path: str = "repo/app/x.js") -> io.BytesIO:
    if isinstance(files, str):
        files = {path: files}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    buf.seek(0)
    return buf


def test_html_injected_from_a_non_literal_value_is_a_high_severity_signal():
    findings = [f for f in run_static_scan(archive(POSITIVE))["findings"] if f["rule_id"] == RULE_ID]
    assert len(findings) == 1
    f = findings[0]
    assert "innerHTML" in POSITIVE.splitlines()[f["line"] - 1]
    assert f["severity"] == "high"
    assert f["confidence"] == 0.7
    assert f["category"] == "Security"
    assert f["source"] == "static"
    assert f["verification_status"] == "unverified"
    assert "not a fixed string" in f["explanation"]


@pytest.mark.parametrize("source", [
    # a fixed string is not an injection
    POSITIVE.replace("message.html", '"<b>fixed</b>"'),
    # textContent is text, not markup
    POSITIVE.replace("innerHTML", "textContent"),
    # a template literal with no interpolation is static
    POSITIVE.replace("message.html", "`<b>fixed</b>`"),
    # setAttribute("innerHTML", ...) sets an attribute, not the property
    POSITIVE.replace('document.getElementById("log").innerHTML = message.html;',
                     'document.getElementById("log").setAttribute("innerHTML", message.html);'),
    # a name bound to a fixed string is static
    "const html = \"<b>fixed</b>\";\nel.innerHTML = html;\n",
    "not valid js (",
])
def test_shapes_this_rule_does_not_report(source):
    assert scan_xss(archive(source)) == []


def test_a_string_or_comment_spelling_the_sink_is_not_code():
    """Quote and comment tracking: documentation is not a decision."""
    assert scan_xss(archive('const doc = "el.innerHTML = user.html";\n')) == []
    assert scan_xss(archive("// el.innerHTML = user.html;\n")) == []
    assert scan_xss(archive("/* el.innerHTML = user.html; */\n")) == []


# case name -> (file, the one change that removes the property the case pins)
CORPUS_NEGATIVES = REPO_ROOT / "tests" / "detectors" / RULE_ID / "negative"
MUTATIONS: dict[str, tuple[str, str, str]] = {
    "static-literal": ("app/fixed.js", 'el.innerHTML = "<b>fixed</b>";', "el.innerHTML = user.html;"),
    "text-content": ("app/safe.js", "el.textContent = user.html;", "el.innerHTML = user.html;"),
    "set-attribute": ("app/attr.js", 'el.setAttribute("innerHTML", user.html);', "el.innerHTML = user.html;"),
    "inside-string": ("app/doc.js", 'const doc = "el.innerHTML = user.html";', "el.innerHTML = user.html;"),
    "inside-comment": ("app/history.js", "// el.innerHTML = user.html;", "el.innerHTML = user.html;"),
    "inside-block-comment": ("app/disabled.js", "/* el.innerHTML = user.html; */", "el.innerHTML = user.html;"),
    "static-assignment": ("app/template.js",
                          'const html = "<b>fixed</b>";\nel.innerHTML = html;',
                          "const html = build(x);\nel.innerHTML = html;"),
    "static-template-no-interp": ("app/theme.js",
                                  "el.innerHTML = `<b>fixed</b>`;",
                                  "el.innerHTML = `<b>${x}</b>`;"),
}


def test_every_corpus_negative_has_a_mutation():
    on_disk = {case.name for case in CORPUS_NEGATIVES.iterdir() if case.is_dir()}
    assert on_disk == set(MUTATIONS), f"no mutation for: {on_disk - set(MUTATIONS)}"


@pytest.mark.parametrize("case", sorted(MUTATIONS))
def test_each_corpus_negative_goes_silent_for_its_stated_reason(case):
    relative, old, new = MUTATIONS[case]
    case_dir = CORPUS_NEGATIVES / case
    files = {p.relative_to(case_dir).as_posix().removesuffix(".fixture"): p.read_text()
             for p in case_dir.rglob("*.fixture")}
    assert scan_xss(archive(files)) == [], "the untouched case must be silent"
    assert old in files[relative], f"mutation anchor is gone from {relative}"
    files[relative] = files[relative].replace(old, new, 1)
    assert scan_xss(archive(files)), "the mutation must make the rule fire"


def test_the_product_own_frontend_reports_nothing():
    """A false-positive guard whose premise is asserted.

    shipit's layout injects a fixed theme script through dangerouslySetInnerHTML,
    so a rule that fired on our own frontend would be unusable. If this ever
    fails, read the reported line before touching the rule.
    """
    sources = {p.relative_to(REPO_ROOT).as_posix(): p.read_text()
               for p in sorted((REPO_ROOT / "web" / "src").rglob("*"))
               if p.suffix in (".ts", ".tsx", ".js", ".jsx") and ".next" not in p.parts}
    text = "\n".join(sources.values())
    sinks = len(re.findall(r"dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=", text)) \
        + len(re.findall(r"document\.write(?:ln)?\s*\(|insertAdjacentHTML", text))
    assert sinks > 0, f"expected the product's frontend to use HTML-injection sinks; found {sinks}"
    assert scan_xss(archive(sources)) == []
