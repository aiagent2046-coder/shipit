"""Deterministic grammar-edge fuzzing of every positive corpus case.

WHY THIS EXISTS. The escape hunt rewrites VULNERABLE code and so can only find
misses; the reviewer reads the FIX and finds edge semantics -- and measured on
2026-09-14 a review round produced six blocking defects of exactly that class:
a trailing comment inside an array literal silenced a real draw by taking over
its slot, a spread element paired with slot 0 and produced a false finding,
computed keys collided on an undefined-key map, destructuring defaults were
never read, a walrus in a later argument flipped the sink's verdict, and the
slot map was recomputed per element, quadratic on large arrays (2.13s at
2,000 elements).

Review round 1 hardened the harness's own blind spots: the sql rule owns a
SECOND scanner (JS/TS tree-sitter) the wiring missed -- the
typescript-concatenated positive silently produced no cases; the .vue
positives need their comment inside the script block (a trailing comment
after </template> makes the SFC unparseable and the finding vanish); a
positive the wiring cannot see now fails loudly instead of `continue`-ing;
and a rename transform moves every reference of a binding -- a declaration
renamed without its call site left a broken program that tested nothing.

This file is the third channel: LLM-free, reproducible, and wired into the
gate so it runs before any reviewer does. Every positive fixture is passed
through deterministic transforms, each of which is verdict-proven BY
CONSTRUCTION:

  fire transforms   -- the defect is intact, only its surface changed
                       (comments, spread flattening, slot padding, a walrus
                       in a later argument). The rule must still fire.
  silent transforms -- the defect is removed or made unprovable in a known
                       way (a spread pads the secret slot with a literal, a
                       binding is renamed past the target filter, an import
                       becomes conditional, object keys become computed).
                       The rule must stay silent, and only cases whose
                       ORIGINAL scan yields exactly one finding are eligible,
                       so silence is actually required and not an artifact.

A failing case here is either a detector defect or a transform bug -- both
are findings; the mutated body is printed with the failure.
"""
from __future__ import annotations

import io
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from app.scan.archive_extraction import scan_archive_extraction
from app.scan.command_injection import scan_command_injection
from app.scan.insecure_randomness import scan_insecure_randomness
from app.scan.path_traversal import scan_path_traversal
from app.scan.sql_injection import scan_sql_injection
from app.scan.sql_injection_js import scan_sql_injection_js
from app.scan.unsafe_deserialization import scan_unsafe_deserialization
from app.scan.xxe import scan_unsafe_xml_parse
from app.scan.xss import scan_xss

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_ROOT = REPO_ROOT / "tests" / "detectors"

def _scan_sql_anywhere(buffer):
    """One rule, two scanners: Python ast and JS/TS tree-sitter.

    Review round 1: wiring only the Python half silently skipped the
    typescript-concatenated positive -- a case the full pipeline fires on
    twice. Findings from either scanner count; neither scanner reads the
    other's suffixes, so the union is exactly the pipeline's coverage.
    """
    yield from scan_sql_injection(buffer)
    yield from scan_sql_injection_js(buffer)


SCANNERS = {
    "insecure-randomness": scan_insecure_randomness,
    "sql-injection-string-built-query": _scan_sql_anywhere,
    "archive-extraction-fully-trusted": scan_archive_extraction,
    "xss-unsafe-html-injection": scan_xss,
    "command-injection-shell-built-command": scan_command_injection,
    "path-traversal-file-sink": scan_path_traversal,
    "unsafe-xml-parse": scan_unsafe_xml_parse,
    "unsafe-deserialization": scan_unsafe_deserialization,
}

PY_SUFFIX = ".py"
JS_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts"}
VUE_SUFFIX = ".vue"


@dataclass(frozen=True)
class Transform:
    name: str
    verdict: str  # "fire" | "silent"
    languages: frozenset
    rules: frozenset | None  # None = every rule
    apply: object  # (body: str) -> str | None


# --------------------------------------------------------------------------
# Python transforms
# --------------------------------------------------------------------------

def _conditional_import(body: str) -> str | None:
    """The first import whose module is still referenced moves under an if.

    The code that uses the module stays at its position, so the name is
    unbound where it is used: a NameError path, which the rule must not treat
    as proven provenance.
    """
    import re
    match = None
    for candidate in re.finditer(r"^(import (\w+)|from (\w+) import \w+)$",
                                 body, re.MULTILINE):
        module = candidate.group(2) or candidate.group(3)
        if re.search(rf"\b{re.escape(module)}\.", body):
            match = candidate
            break
    if match is None:
        return None
    line = match.group(0)
    return body.replace(line, f"if _fuzzer:\n    {line}", 1)


def _sql_walrus_later_argument(body: str) -> str | None:
    """A walrus in a LATER argument cannot change the first argument's binding.

    Only mutate a one-argument sink whose query ultimately reads a simple
    local name.  The later argument reassigns that SAME name to a literal:
    this is the regression shape, rather than an unrelated walrus that could
    never detect a post-evaluation re-read.  Restricting the transform to a
    one-argument call also avoids manufacturing calls with three arguments.
    """
    import ast

    tree = ast.parse(body)
    for node in ast.walk(tree):
        if (not isinstance(node, ast.Call)
                or not isinstance(node.func, ast.Attribute)
                or node.func.attr not in {"execute", "executemany", "executescript"}
                or len(node.args) != 1 or node.keywords):
            continue
        argument = node.args[0]
        if isinstance(argument, ast.Name):
            query_name = argument.id
        elif (isinstance(argument, ast.Call) and len(argument.args) == 1
              and isinstance(argument.args[0], ast.Name)):
            query_name = argument.args[0].id
        else:
            continue
        lines = body.splitlines(keepends=True)
        line_start = sum(len(line) for line in lines[:node.end_lineno - 1])
        end = line_start + node.end_col_offset
        call_text = body[sum(len(line) for line in lines[:node.lineno - 1]) + node.col_offset:end]
        close = call_text.rfind(")")
        if close < 0:
            continue
        insertion = end - (len(call_text) - close)
        return body[:insertion] + f', ({query_name} := "SELECT 1")' + body[insertion:]
    return None


def _fresh_identifier(body: str, base: str, used: set[str] | None = None) -> str:
    """Return a deterministic identifier absent from the original and this pass."""
    import re
    occupied = set(re.findall(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b", body))
    if used is not None:
        occupied.update(used)
    candidate = base
    suffix = 1
    while candidate in occupied:
        candidate = f"{base}{suffix}"
        suffix += 1
    return candidate


def _py_rename_secretless(body: str) -> str | None:
    """The binding renamed WITH every reference (review round 1: renaming
    only the declaration left dangling uses behind -- a broken program the
    rule is trivially silent on, not a target-filter counterexample)."""
    import re
    from app.scan.insecure_randomness import _SECRET_WORDS
    words = "|".join(_SECRET_WORDS)
    match = re.search(rf"^(\s*)(\w*(?:{words})\w*)\s*=", body, re.MULTILINE | re.IGNORECASE)
    if match is None:
        return None
    replacement = _fresh_identifier(body, "fz_plain_offset")
    return re.sub(rf"\b{re.escape(match.group(2))}\b", replacement, body)


# --------------------------------------------------------------------------
# JS / TS transforms
# --------------------------------------------------------------------------

def _js_comment(body: str) -> str:
    # rstrip first: a body ending in `}` without a newline would otherwise
    # weld the comment onto the brace and comment it out.
    return body.rstrip() + "\n// fuzzer\n"


def _vue_comment(body: str) -> str | None:
    """A trailing surface comment INSIDE the script block.

    A comment appended after </template> makes the SFC unparseable to the
    scanner's extract_vue and the whole file goes silent (measured on both
    vue positives: the finding vanished), so the surface change goes where
    the JavaScript lives. A .vue body without a script block is left alone.
    """
    if "</script>" not in body:
        return None
    return body.replace("</script>", "// fuzzer\n</script>", 1)


def _js_comment_in_first_value_array(body: str) -> str | None:
    """A comment takes no slot: the element of its position still pairs."""
    anchor = body.find("=")
    if anchor < 0:
        return None
    bracket = body.find("[", anchor)
    if bracket < 0:
        return None
    return body[:bracket + 1] + "/*f*/" + body[bracket + 1:]


def _js_spread_wrap(body: str) -> str | None:
    """Pins the documented boundary: no spread correspondence is resolved.

    A one-element spread flattens to the same first element, so semantically
    the defect survives -- but the reviewer-approved design resolves NO spread
    correspondence, even a provable one, and the corpus negative
    destructure-spread-rhs pins the multi-element silence. This transform pins
    the single-element silence too, so a future change to resolve provable
    spreads has to be a deliberate rule change, not drift.
    """
    import re
    match = re.search(r"= \[([^\[\]]+)\]", body)
    if match is None:
        return None
    return body.replace(match.group(0), f"= [...[{match.group(1)}]]", 1)


def _js_destructure_silent_pad(body: str) -> str | None:
    """A spread pads the secret slot with a literal: the draw is NOT slot 0.

    `const [token] = [X]` becomes `const [token] = [...[1, X]]`: token
    receives 1, the draw lands in slot 1. The rule must stay silent -- a
    finding here is exactly the spread false positive of the review round.
    """
    import re
    match = re.search(r"^(const|let|var) \[(\w+)\] = \[([^\[\]]+)\];", body, re.MULTILINE)
    if match is None:
        return None
    return body.replace(match.group(0),
                        f"{match.group(1)} [{match.group(2)}] = [...[1, {match.group(3)}]];",
                        1)


def _js_destructure_hole(body: str) -> str | None:
    """Holes keep their slots: the secret binding still receives slot 0."""
    import re
    match = re.search(r"^(const|let|var) \[(\w+)\] = \[([^\[\]]+)\];", body, re.MULTILINE)
    if match is None:
        return None
    return body.replace(match.group(0),
                        f"{match.group(1)} [{match.group(2)}, , fz_other] = "
                        f"[{match.group(3)}, 1, 2];", 1)


def _js_rename_secretless(body: str) -> str | None:
    """Every secret-named binding renamed, references included.

    Review round 1 renamed only the first declaration: in the helper shape
    (`const generateToken = () => Math.random(); const resetToken =
    generateToken();`) the call site kept the old spelling and the program
    was BROKEN -- the silence then proved nothing about the target filter.
    Renaming each binding with all of its references keeps the program
    valid and leaves the rule no secret-named target to bind to.
    """
    import re
    from app.scan.insecure_randomness import _SECRET_WORDS
    words = "|".join(_SECRET_WORDS)
    names = re.findall(rf"(?:const|let|var)\s+((?:\w*(?:{words})\w*))\b",
                       body, re.IGNORECASE)
    if not names:
        return None
    result = body
    used: set[str] = set()
    for name in dict.fromkeys(names):
        replacement = _fresh_identifier(body, "fz_plain_offset", used)
        used.add(replacement)
        result = re.sub(rf"\b{re.escape(name)}\b", replacement, result)
    return result


def _js_computed_keys(body: str) -> str | None:
    """Computed keys on both sides correspond to nothing, never to each other."""
    import re
    renamed = re.search(r"^(const|let|var) \{ (\w+): (\w+) \} = \{ \1: ", body)
    if renamed is not None:
        return body.replace(renamed.group(0),
                            f"{renamed.group(1)} {{ [fz_k]: {renamed.group(3)} }} = {{ [fz_o]: ",
                            1)
    shorthand = re.search(r"^(const|let|var) \{ (\w+) \} = \{ \2: ", body)
    if shorthand is not None:
        return body.replace(shorthand.group(0),
                            f"{shorthand.group(1)} {{ [fz_k]: {shorthand.group(2)} }} = "
                            f"{{ [fz_o]: ", 1)
    return None


TRANSFORMS = (
    Transform("py-comment", "fire", frozenset({PY_SUFFIX}), None,
              lambda body: body.rstrip() + "\n# fuzzer\n"),
    Transform("py-conditional-import", "silent", frozenset({PY_SUFFIX}), None,
              _conditional_import),
    Transform("py-walrus-later-argument", "fire", frozenset({PY_SUFFIX}),
              frozenset({"sql-injection-string-built-query"}), _sql_walrus_later_argument),
    Transform("py-rename-secretless", "silent", frozenset({PY_SUFFIX}),
              frozenset({"insecure-randomness"}), _py_rename_secretless),
    Transform("js-comment", "fire", frozenset(JS_SUFFIXES), None, _js_comment),
    Transform("js-comment-in-array", "fire", frozenset(JS_SUFFIXES), None,
              _js_comment_in_first_value_array),
    Transform("vue-comment", "fire", frozenset({VUE_SUFFIX}), None, _vue_comment),
    Transform("js-spread-wrap", "silent", frozenset(JS_SUFFIXES), None, _js_spread_wrap),
    Transform("js-destructure-silent-pad", "silent", frozenset(JS_SUFFIXES), None,
              _js_destructure_silent_pad),
    Transform("js-destructure-hole", "fire", frozenset(JS_SUFFIXES), None,
              _js_destructure_hole),
    Transform("js-rename-secretless", "silent", frozenset(JS_SUFFIXES),
              frozenset({"insecure-randomness"}), _js_rename_secretless),
    Transform("js-computed-keys", "silent", frozenset(JS_SUFFIXES),
              frozenset({"insecure-randomness"}), _js_computed_keys),
)


# --------------------------------------------------------------------------
# Harness
# --------------------------------------------------------------------------

def _scan(rule_id: str, files: dict[str, str]) -> list:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, text in files.items():
            archive.writestr(name, text)
    buffer.seek(0)
    return list(SCANNERS[rule_id](buffer))


def _cases():
    """(rule_id, case, fixture, transform, verdict, files) per application.

    A case may carry several fixture files while the path policy scans only
    some of them (bundled-dependency-and-own-source keeps a vendor copy the
    rule excludes). Transforms therefore target the file the FINDING lives in:
    fire transforms mutate every finding file, silent transforms mutate the
    one finding file of a single-finding case -- silence is only provably
    required there.
    """
    for rule_id, scanner in sorted(SCANNERS.items()):
        rule_dir = CORPUS_ROOT / rule_id / "positive"
        if not rule_dir.is_dir():
            continue
        for case_dir in sorted(rule_dir.iterdir()):
            if not case_dir.is_dir():
                continue
            fixtures = sorted(case_dir.rglob("*.fixture"))
            files = {p.relative_to(case_dir).as_posix().removesuffix(".fixture"): p.read_text()
                     for p in fixtures}
            findings = _scan(rule_id, files)
            # Review round 1: this was a silent `continue`, and the
            # typescript-concatenated positive quietly produced no fuzz cases.
            # A positive the per-rule wiring cannot see must fail loudly --
            # either SCANNERS misses a scanner the full pipeline runs, or the
            # case is not what it claims to be.
            assert findings, (
                f"{rule_id}/{case_dir.name} is a positive corpus case, but the "
                f"fuzzer's SCANNERS wiring found nothing in it. The golden corpus "
                f"holds the case to the pipeline; this gate holds the fuzzer to "
                f"the same coverage.")
            finding_files = sorted({finding.file for finding in findings})
            silent_target = finding_files[0] if len(findings) == 1 else None
            for transform in TRANSFORMS:
                if transform.rules is not None and rule_id not in transform.rules:
                    continue
                targets = finding_files if transform.verdict == "fire" else [silent_target]
                for name in targets:
                    if name is None or Path(name).suffix not in transform.languages:
                        continue
                    mutated = transform.apply(files[name])
                    if mutated is None or mutated == files[name]:
                        continue
                    yield pytest.param(rule_id, case_dir.name, name, transform.name,
                                       transform.verdict, {**files, name: mutated},
                                       id=f"{rule_id}/{case_dir.name}/{transform.name}")


@pytest.mark.parametrize("rule_id,case,fixture,transform,verdict,files", list(_cases()))
def test_transformed_positive_keeps_or_flips_its_verdict(
        rule_id, case, fixture, transform, verdict, files):
    findings = _scan(rule_id, files)
    if verdict == "fire":
        assert findings, (
            f"{transform} must keep the finding on {case}/{fixture} -- the defect "
            f"is intact, only its surface changed.\nMutated body:\n"
            + "\n".join(f"--- {name} ---\n{text}" for name, text in files.items()))
    else:
        assert not findings, (
            f"{transform} must stay silent on {case}/{fixture} -- the defect was "
            f"removed or made unprovable.\nMutated body:\n"
            + "\n".join(f"--- {name} ---\n{text}" for name, text in files.items()))


def test_destructuring_scan_stays_linear_on_large_arrays():
    """The measured review defect: quadratic slot maps (2.13s at 2,000).

    The fixed code measures ~0.009s at 4,000 elements; a 5s bound leaves two
    orders of headroom while still failing on the quadratic curve.
    """
    body = "const [count] = [" + ", ".join("x" for _ in range(4000)) + "];\n"
    start = time.perf_counter()
    findings = _scan("insecure-randomness", {"app/large.js": body})
    elapsed = time.perf_counter() - start
    assert findings == []
    assert elapsed < 5.0, f"scan took {elapsed:.2f}s on 4,000 elements"


def test_every_scanned_rule_still_has_positives():
    for rule_id in SCANNERS:
        assert (CORPUS_ROOT / rule_id / "positive").is_dir(), rule_id


def test_every_positive_case_is_fuzzed_at_least_once():
    """Review round 1 pinned 82 cases and covered 79. A case the fuzzer
    cannot see is a case whose regressions it will never catch."""
    covered = {(item.values[0], item.values[1]) for item in _cases()}
    expected = set()
    for rule_id in SCANNERS:
        rule_dir = CORPUS_ROOT / rule_id / "positive"
        if not rule_dir.is_dir():
            continue
        expected.update((rule_id, case_dir.name) for case_dir in rule_dir.iterdir()
                         if case_dir.is_dir())
    assert covered == expected, (
        f"positive cases with no fuzz coverage: {sorted(expected - covered)}")


def test_a_js_rename_moves_the_call_site_with_the_declaration():
    """Review round 1: the helper shape (`const generateToken = () =>
    Math.random(); const resetToken = generateToken();`) was renamed only at
    its declaration, the call dangled, and the silence test passed on a
    broken program. Every reference must move."""
    body = ("const generateToken = () => Math.random();\n"
            "const resetToken = generateToken();\n")
    mutated = _js_rename_secretless(body)
    assert mutated is not None
    assert "generateToken" not in mutated
    assert "resetToken" not in mutated
    assert "fz_plain_offset()" in mutated   # the call moved with its binding
    assert _scan("insecure-randomness", {"app/token.js": mutated}) == []


def test_a_py_rename_moves_later_uses_with_the_assignment():
    body = ("import random\n"
            "reset_token = ''.join(random.choice(chars) for _ in range(32))\n"
            "print(reset_token)\n")
    mutated = _py_rename_secretless(body)
    assert mutated is not None
    assert "reset_token" not in mutated
    import ast
    ast.parse(mutated)   # a program, not a NameError shell
    assert _scan("insecure-randomness", {"app/token.py": mutated}) == []


def test_the_walrus_transform_reassigns_the_query_binding_not_a_dummy_name():
    body = ('query = "SELECT * FROM users WHERE id = " + user_id\n'
            "cur.execute(query)\n")
    mutated = _sql_walrus_later_argument(body)
    assert mutated is not None
    assert 'cur.execute(query, (query := "SELECT 1"))' in mutated
    assert _scan("sql-injection-string-built-query", {"app/db.py": mutated})


def test_a_later_walrus_cannot_turn_a_safe_first_argument_dangerous():
    body = ('query = "SELECT 1"\n'
            'cur.execute(query, (query := "SELECT " + user_id))\n')
    assert _scan("sql-injection-string-built-query", {"app/db.py": body}) == []


def test_js_secretless_renames_never_collide_with_existing_bindings():
    body = ("const fz_plain_offset = 1;\n"
            "const fz_plain_offset1 = 2;\n"
            "const generateToken = () => Math.random();\n"
            "const resetToken = generateToken();\n")
    mutated = _js_rename_secretless(body)
    assert mutated is not None
    assert "const fz_plain_offset = 1;" in mutated
    assert "const fz_plain_offset1 = 2;" in mutated
    assert "const fz_plain_offset2 = () => Math.random();" in mutated
    assert "const fz_plain_offset3 = fz_plain_offset2();" in mutated
    assert _scan("insecure-randomness", {"app/token.js": mutated}) == []
