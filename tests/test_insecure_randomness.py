"""Synthetic source fixtures: no uploaded code is executed.

The load-bearing tests:

  * every corpus negative is MUTATED in the one place that removes the property it
    pins, and the rule must fire on the result;
  * every negative on disk has a mutation;
  * the product's own code is scanned with its premise asserted -- shipit draws
    random choices for a deploy preview and a probe port, so the silence below is
    silence over code that uses the non-cryptographic sources, not an empty
    archive.
"""
import io
import re
import zipfile
from pathlib import Path

import pytest

from app.scan.insecure_randomness import RULE_ID, scan_insecure_randomness
from app.scan.static import run_static_scan

REPO_ROOT = Path(__file__).resolve().parent.parent

POSITIVE = "import random\nreset_token = ''.join(random.choice(chars) for _ in range(32))\n"


def archive(files: dict[str, str] | str, path: str = "repo/app/x.py") -> io.BytesIO:
    if isinstance(files, str):
        files = {path: files}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    buf.seek(0)
    return buf


def test_a_secret_named_value_from_a_predictable_draw_is_high_severity():
    findings = [f for f in run_static_scan(archive(POSITIVE))["findings"] if f["rule_id"] == RULE_ID]
    assert len(findings) == 1
    f = findings[0]
    assert "reset_token" in POSITIVE.splitlines()[f["line"] - 1]
    assert f["severity"] == "high"
    assert f["confidence"] == 0.7
    assert f["category"] == "Security"
    assert f["source"] == "static"
    assert f["verification_status"] == "unverified"
    assert "predictable" in f["explanation"]


@pytest.mark.parametrize("source", [
    # a draw feeding an animation is not a secret
    "const x = Math.random() * width;\n",
    # a shuffle is not a secret draw
    "import random\nrandom.shuffle(items)\n",
    # picking from a list named tokens is not generating a token
    "import random\nwinner = random.choice(tokens)\n",
    # the secure alternatives are not sinks
    "import secrets\ntoken = secrets.token_hex(16)\n",
    "const token = crypto.getRandomValues(new Uint8Array(16));\n",
    # a comment is history, not code
    "# reset_token = random.choice(chars)\n",
    "not valid python (",
])
def test_shapes_this_rule_does_not_report(source):
    assert scan_insecure_randomness(archive(source)) == []


CORPUS_NEGATIVES = REPO_ROOT / "tests" / "detectors" / RULE_ID / "negative"
MUTATIONS: dict[str, tuple[str, str, str]] = {
    "loop-math-binding": ("app/token.js", "const Math of sources", "const source of sources"),
    "match-random-capture": ("app/token.py", 'case {"random": random}', 'case {"random": source}'),
    "multiline-docstring": ("app/token.py", '\"\"\"\nreset_token = random.randint(1, 9)\n\"\"\"',
                            "reset_token = random.randint(1, 9)"),
    "system-random-rebinding": ("app/token.py", "random = random.SystemRandom()\n", ""),
    "shadowed-math": ("app/token.js", "issue(Math)", "issue()"),
    "animation": ("app/anim.js", "const x = Math.random() * width;", "const token = Math.random();"),
    "shuffle": ("app/shuffle.py", "random.shuffle(items)", "reset_token = random.choice(items)"),
    "pick-from-list": ("app/pick.py", "winner = random.choice(tokens)", "reset_token = random.choice(tokens)"),
    "secure-secrets": ("app/secrets.py", "secrets.token_hex(16)", "random.choice(chars)"),
    "secure-crypto": ("app/crypto.js", "crypto.getRandomValues(new Uint8Array(16))", "Math.random()"),
    "comment": ("app/history.py", "# reset_token = random.choice(chars)", "reset_token = random.choice(chars)"),
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
    assert scan_insecure_randomness(archive(files)) == [], "the untouched case must be silent"
    assert old in files[relative], f"mutation anchor is gone from {relative}"
    files[relative] = files[relative].replace(old, new, 1)
    assert scan_insecure_randomness(archive(files)), "the mutation must make the rule fire"


def test_the_product_own_code_reports_nothing():
    """A false-positive guard whose premise is asserted.

    shipit draws random choices for a deploy preview and a probe port, neither a
    secret, so a rule that fired on our own code would be unusable.
    """
    python = {p.relative_to(REPO_ROOT).as_posix(): p.read_text()
              for p in sorted((REPO_ROOT / "app").rglob("*.py")) if "__pycache__" not in p.parts}
    web = {p.relative_to(REPO_ROOT).as_posix(): p.read_text()
           for p in sorted((REPO_ROOT / "web" / "src").rglob("*"))
           if p.suffix in (".ts", ".tsx", ".js", ".jsx") and ".next" not in p.parts}
    sources = {**python, **web}
    text = "\n".join(sources.values())
    draws = len(re.findall(
        r"Math\.random|random\.(?:random|randint|randrange|choice|getrandbits|uniform|sample)", text))
    assert draws > 0, f"expected the product to draw from the non-cryptographic sources; found {draws}"
    assert scan_insecure_randomness(archive(sources)) == []


@pytest.mark.parametrize("source", [
    'import random\n"""\nreset_token = random.randint(1, 9)\n"""',
    'import random\nrandom = random.SystemRandom()\nreset_token = random.randint(1, 9)',
    'import random\ndef make(random):\n    reset_token = random.randint(1, 9)',
    'import random\nrandom.randint = secure_randint\nreset_token = random.randint(1, 9)',
    'import other_library as random\nreset_token = random.randint(1, 9)',
    'import random\nreset_token = lambda: random.randint(1, 9)',
])
def test_python_text_or_unknown_random_provenance_does_not_claim_a_predictable_draw(source):
    assert scan_insecure_randomness(archive(source)) == []


@pytest.mark.parametrize("source", [
    'import random\nreset_token = f"prefix-{random.getrandbits(128)}"',
    'import random as rnd\nreset_token = rnd.getrandbits(128)',
    'from random import getrandbits\nreset_token = getrandbits(128)',
])
def test_python_draws_use_import_provenance_and_evaluate_fstring_expressions(source):
    findings = scan_insecure_randomness(archive(source))
    assert len(findings) == 1
    assert findings[0].line == 2


@pytest.mark.parametrize("source", [
    'const resetToken = `${Math.random()}`;',
    'const resetToken = `prefix-${Math.random().toString(36)}`;',
    'const resetToken =\n  Math.random();',
])
def test_js_draws_are_calls_in_expressions_including_template_substitution(source):
    assert len(scan_insecure_randomness(archive(source, "repo/app/x.js"))) == 1


@pytest.mark.parametrize("source", [
    'const doc = `\nconst resetToken = Math.random();\n`;',
    'function make(Math) { const resetToken = Math.random(); }',
    'const Math = secureGenerator; const resetToken = Math.random();',
    'const resetToken = Math.random;',
    'const resetToken = () => Math.random();',
    'const resetToken = math.random();',
])
def test_js_literal_text_custom_math_and_function_references_are_not_draws(source):
    assert scan_insecure_randomness(archive(source, "repo/app/x.js")) == []


@pytest.mark.parametrize("pattern", [
    '{"random": random}',
    '[*random]',
    '{**random}',
])
def test_match_capture_shadows_imported_random(pattern):
    source = (f'import random\ndef issue(obj):\n    match obj:\n'
              f'        case {pattern}:\n            secret = random.random()\n')
    assert scan_insecure_randomness(archive(source)) == []


def test_executed_class_body_draw_is_detected_without_leaking_class_bindings_to_methods():
    source = ('import random\nclass Config:\n    secret = random.random()\n'
              '    def issue(self):\n        token = random.random()\n')
    assert [finding.line for finding in scan_insecure_randomness(archive(source))] == [3, 5]
    isolated = ('class Config:\n    import random\n    secret = random.random()\n'
                '    def issue(self):\n        token = random.random()\n')
    assert [finding.line for finding in scan_insecure_randomness(archive(isolated))] == [3]


def test_math_loop_binding_has_unknown_provenance():
    source = 'for (const Math of providers) { const token = Math.random(); }'
    assert scan_insecure_randomness(archive(source, 'repo/app/x.js')) == []
