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

from app.scan import insecure_randomness
from app.scan.insecure_randomness import RULE_ID, scan_insecure_randomness
from app.scan.static import run_static_scan
from tests.test_rule_coverage import assert_accounting

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


def ast_budget_source(suffix, budget, over_limit):
    if budget == "nodes":
        return ("0\n" if suffix == "py" else "0;") * (10_000 if over_limit else 9_999)
    # Module/program and expression statement add two levels; the terminal
    # literal reaches depth 100 or 101 without a parser syntax error.
    return ("+" if suffix == "py" else "!") * (99 if over_limit else 98) + "0\n"


@pytest.mark.parametrize("suffix", ["py", "js", "ts", "jsx", "tsx"])
@pytest.mark.parametrize("budget", ["nodes", "depth"])
@pytest.mark.parametrize("over_limit", [False, True])
def test_real_ast_budgets_preserve_later_findings_and_coverage(suffix, budget, over_limit):
    source = ast_budget_source(suffix, budget, over_limit)
    assert len(source.encode()) < 400_000
    positive = POSITIVE if suffix == "py" else "const resetToken = Math.random();\n"
    path = f"repo/app/token.{suffix}"
    coverage = {}
    findings = scan_insecure_randomness(archive({
        f"repo/app/large.{suffix}": source,
        path: positive,
    }), coverage=coverage)
    assert [(finding.rule_id, finding.file) for finding in findings] == [(RULE_ID, path)]
    assert_accounting(coverage, total=2, eligible=2, attempted=2,
                      analyzed=1 if over_limit else 2,
                      skips={"ast_limit": 1} if over_limit else {})


@pytest.mark.parametrize("suffix", ["py", "ts"])
def test_exact_node_budget_is_analyzed(suffix):
    # 19,999 nodes plus one pass/comment node reaches the 20,000-node cap.
    source = ast_budget_source(suffix, "nodes", False)
    source += "pass\n" if suffix == "py" else "// final node\n"
    coverage = {}
    assert scan_insecure_randomness(archive(source, f"repo/app/large.{suffix}"), coverage=coverage) == []
    assert_accounting(coverage, total=1, eligible=1, attempted=1, analyzed=1)


@pytest.mark.parametrize("suffix", ["py", "ts"])
@pytest.mark.parametrize("budget", ["nodes", "depth"])
def test_static_scan_reports_ast_gap_without_losing_the_randomness_check(suffix, budget):
    report = run_static_scan(archive({
        f"repo/app/large.{suffix}": ast_budget_source(suffix, budget, True),
        "repo/app/token.py": POSITIVE,
    }))
    assert all(failure["check"] != "insecure_randomness" for failure in report["checks_not_run"])
    assert [finding["rule_id"] for finding in report["findings"]].count(RULE_ID) == 1
    assert_accounting(report["rule_coverage"]["insecure_randomness"],
                      total=2, eligible=2, attempted=2, analyzed=1, skips={"ast_limit": 1})


@pytest.mark.parametrize("suffix,helper", [("py", "_python_evidence"), ("ts", "_js_evidence")])
def test_unexpected_value_errors_remain_check_failures(monkeypatch, suffix, helper):
    def broken_analysis(*args):
        raise ValueError("unexpected analysis failure")

    monkeypatch.setattr(insecure_randomness, helper, broken_analysis)
    report = run_static_scan(archive("0\n", f"repo/app/valid.{suffix}"))
    assert {"check": "insecure_randomness", "reason": "check_error: ValueError"} in report["checks_not_run"]
    assert report["rule_coverage"]["insecure_randomness"] == {}


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
    "helper-shadowed-by-parameter": ("app/reset.js", "issue(generateToken)", "issue()"),
    "helper-reassigned": ("app/reset.js", "generateToken = () => crypto.randomUUID();\n", ""),
    "helper-conditional-return": ("app/reset.js",
                                  "if (flag) {\n    return Math.random();\n  }\n  return \"fallback\";",
                                  "return Math.random();"),
    "helper-second-return-secure": ("app/reset.js",
                                    "if (x) {\n    return Math.random();\n  }\n"
                                    "  return crypto.getRandomValues(new Uint8Array(16));",
                                    "return Math.random();"),
    "helper-of-helper": ("app/reset.js", "return drawUnit();", "return Math.random();"),
    "helper-out-of-scope": ("app/reset.js",
                            "if (featureEnabled) {\n  const generateToken = () => Math.random();\n}",
                            "const generateToken = () => Math.random();"),
    "helper-destructured-reassignment": ("app/reset.js",
                                         "({generateToken} = {generateToken: () => crypto.randomUUID()});\n",
                                         ""),
    "helper-destructured-parameter": ("app/reset.js", "issue({generateToken})", "issue()"),
    "helper-generator-shadow": ("app/reset.js",
                                "  function* generateToken() {\n    yield crypto.randomUUID();\n  }\n", ""),
    "helper-ts-import-alias": ("app/reset.ts", "  import generateToken = source.secure;\n", ""),
    "helper-returned-generator": ("app/reset.js",
                                  "return function* () {\n    yield Math.random();\n  };",
                                  "return Math.random();"),
    "helper-returned-object-method": ("app/reset.js",
                                      "return {\n    make() {\n      return Math.random();\n    },\n  };",
                                      "return Math.random();"),
    "helper-inner-function-name": ("app/reset.js",
                                   "function generateToken() {\n  const resetToken",
                                   "function tokenFactory() {\n  const resetToken"),
    "helper-deferred-generator-assignment": ("app/reset.js",
                                             "function* () { yield generateValue(); }",
                                             "generateValue()"),
    "helper-deferred-method-assignment": ("app/reset.js",
                                          "{ make() { return generateValue(); } }",
                                          "generateValue()"),
    "helper-returned-class": ("app/reset.js",
                              "return class { value = Math.random(); };",
                              "return Math.random();"),
    "deferred-method-direct": ("app/reset.js",
                               "make() {\n    return Math.random();\n  }",
                               "make: Math.random()"),
    "destructure-index-mismatch": ("app/reset.js", "const [token, count]", "const [count, token]"),
    "destructure-nested-literal": ("app/reset.js", 'token: "literal"', "token: Math.random()"),
    "destructure-computed-key": ("app/reset.js", "const { [k]: token }", "const { x: token }"),
    "destructure-spread-rhs": ("app/reset.js",
                               "...[1, Math.random()]", "Math.random()"),
    "destructure-computed-both-sides": ("app/reset.js",
                                        "{[k]: token} = {[other]: Math.random()}",
                                        "{ x: token } = { x: Math.random() }"),
    "destructure-math-binding": ("app/reset.js", "const [Math] = sources", "const [other] = sources"),
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
    "function generateToken() {\n  return Math.random();\n}\nconst resetToken = generateToken();\n",
    "const generateToken = () => Math.random();\nconst resetToken = generateToken();\n",
    "const generateToken = () => {\n  return Math.random().toString(36).slice(2);\n};\n"
    "const resetToken = generateToken();\n",
    "const generateToken = function () {\n  return Math.random();\n};\nconst resetToken = generateToken();\n",
    "const resetToken = generateToken();\nfunction generateToken() {\n  return Math.random();\n}\n",
    "export function generateToken() {\n  return Math.random();\n}\nconst resetToken = generateToken();\n",
    "function issue() {\n  const makeToken = () => Math.random();\n  const inner = () => {\n"
    "    const resetToken = makeToken();\n    return resetToken;\n  };\n  return inner;\n}\n",
    # an eagerly evaluated array draws at call time
    "function generateToken() { return [Math.random()]; }\nconst resetToken = generateToken();\n",
    # an eagerly evaluated object property draws at construction of the literal
    "function generateValue() { return Math.random(); }\n"
    "const resetToken = { value: generateValue() };\n",
])
def test_a_single_helper_hop_to_math_random_is_a_draw(source):
    findings = scan_insecure_randomness(archive(source, "repo/app/x.js"))
    assert len(findings) == 1


@pytest.mark.parametrize("source", [
    # a parameter shadows the helper at the call site
    "function generateToken() {\n  return Math.random();\n}\n"
    "function issue(generateToken) {\n  const resetToken = generateToken();\n}\n",
    # reassignment makes the name ambiguous
    "let generateToken = () => Math.random();\n"
    "generateToken = () => crypto.randomUUID();\nconst resetToken = generateToken();\n",
    # a conditional return is not a proven draw
    "function generateToken(flag) {\n  if (flag) {\n    return Math.random();\n  }\n  return 'fallback';\n}\n"
    "const resetToken = generateToken(true);\n",
    # a secure second return leaves the helper unresolved
    "function generateToken(x) {\n  if (x) {\n    return Math.random();\n  }\n"
    "  return crypto.getRandomValues(new Uint8Array(16));\n}\nconst resetToken = generateToken(1);\n",
    # exactly one hop: a helper calling a helper stays unresolved
    "function drawUnit() {\n  return Math.random();\n}\n"
    "function generateToken() {\n  return drawUnit();\n}\nconst resetToken = generateToken();\n",
    # a declaration inside a block does not reach the module scope
    "if (featureEnabled) {\n  const generateToken = () => Math.random();\n}\nconst resetToken = generateToken();\n",
    # a helper scoped to another function stays out of reach
    "function outer() {\n  function generateToken() {\n    return Math.random();\n  }\n}\n"
    "function other() {\n  const resetToken = generateToken();\n}\n",
    # a declarator must precede its call
    "const resetToken = generateToken();\nconst generateToken = () => Math.random();\n",
    # an imported name has cross-file provenance
    "import { generateToken } from './tokens';\nconst resetToken = generateToken();\n",
    # a duplicate declaration makes the binding ambiguous
    "function generateToken() {\n  return Math.random();\n}\n"
    "function issue() {\n  const generateToken = () => Math.random();\n  const resetToken = generateToken();\n}\n",
    # object destructuring reassigns the helper name to a secure source
    "let generateToken = () => Math.random();\n"
    "({generateToken} = {generateToken: () => crypto.randomUUID()});\n"
    "const resetToken = generateToken();\n",
    # a destructured parameter shadows the helper
    "function generateToken() {\n  return Math.random();\n}\n"
    "function issue({generateToken}) {\n  const resetToken = generateToken();\n}\n",
    # the inner name of a function expression shadows the helper inside it
    "function generateToken() {\n  return Math.random();\n}\n"
    "const holder = function generateToken() {\n"
    "  const resetToken = generateToken();\n  return resetToken;\n};\n",
    # a generator declaration shadows the helper and never runs on call
    "function generateToken() {\n  return Math.random();\n}\n"
    "function issue() {\n  function* generateToken() {\n    yield crypto.randomUUID();\n  }\n"
    "  const resetToken = generateToken();\n}\n",
    # a returned generator has not drawn yet
    "function generateToken() {\n  return function* () {\n    yield Math.random();\n  };\n}\n"
    "const resetToken = generateToken();\n",
    # a returned object method has not drawn yet
    "function generateToken() {\n  return {\n    make() {\n      return Math.random();\n    },\n  };\n}\n"
    "const resetToken = generateToken();\n",
    # a generator assigned to the secret name has not run its body
    "function generateValue() { return Math.random(); }\n"
    "const resetToken = function* () { yield generateValue(); };\n",
    # an object method assigned to the secret name has not run its body
    "function generateValue() { return Math.random(); }\n"
    "const resetToken = { make() { return generateValue(); } };\n",
    # a helper returning a class has not drawn: fields initialize at construction
    "function generateValue() {\n  return class { value = Math.random(); };\n}\n"
    "const resetToken = generateValue();\n",
    # a generator assigned to the secret name with a direct draw inside
    "const resetToken = function* () { yield Math.random(); };\n",
])
def test_helper_hops_with_unknown_provenance_stay_silent(source):
    assert scan_insecure_randomness(archive(source, "repo/app/x.js")) == []


def test_a_ts_import_alias_shadows_the_helper_inside_its_namespace():
    source = ("function generateToken() {\n  return Math.random();\n}\n"
              "namespace Inner {\n  import generateToken = source.secure;\n"
              "  export function issue() {\n    const resetToken = generateToken();\n  }\n}\n")
    assert scan_insecure_randomness(archive(source, "repo/app/x.ts")) == []


@pytest.mark.parametrize("source", [
    "const [token] = [Math.random()];\n",
    "const { token } = { token: Math.random() };\n",
    "const { token: resetToken } = { token: Math.random().toString(36).slice(2) };\n",
    "const [token, , other] = [Math.random(), 1];\n",
    "const { 'token': randomToken } = { token: Math.random() };\n",
    # defaults are the binding's value when the slot or key is absent
    "const [token = Math.random()] = [];\n",
    "const { token = Math.random() } = {};\n",
    "const { x: token = 0 } = { x: Math.random() };\n",
    # a comment is not a slot: the real element is still paired
    "const [token] = [Math.random() /* trailing */];\n",
    # a present value that is certainly undefined activates the default
    "const [token = Math.random()] = [void 0];\n",
    "const { token = Math.random() } = { token: void 0 };\n",
    # Math.random in a parameter default mentions Math but does not bind it
    "function helper(value = Math.random()) {}\nconst resetToken = Math.random();\n",
])
def test_destructuring_bindings_receive_the_draw(source):
    assert len(scan_insecure_randomness(archive(source, "repo/app/x.js"))) == 1


@pytest.mark.parametrize("source", [
    # array slots pair exactly: the secret-named slot receives a literal
    'const [token, count] = ["literal", Math.random()];\n',
    # holes keep their slot: token receives slot 0, not the draw in slot 2
    "const [token, , other] = [1, 2, Math.random()];\n",
    # rest patterns have no provable correspondence
    "const [...token] = [Math.random()];\n",
    # computed keys stay unresolved
    "const { [k]: token } = { x: Math.random() };\n",
    # a non-literal container has no element correspondence
    "const [token] = getPair();\n",
    # object keys must match by text
    "const { token } = { count: Math.random() };\n",
    # a spread pairs with no single slot
    "const [token] = [...[1, Math.random()]];\n",
    # computed keys correspond to nothing, not to each other
    "const {[k]: token} = {[other]: Math.random()};\n",
    # a destructuring binding named Math shadows the builtin file-wide
    "const [Math] = sources;\nconst resetToken = Math.random();\n",
    # a default only applies when the slot is absent; a present element wins
    'const { x: token = Math.random() } = { x: "literal" };\n',
    # a spread makes every following array position runtime-dependent
    "const [other, token] = [...[], Math.random()];\n",
    # later object spreads and computed properties can replace a literal key
    'const { token } = { token: Math.random(), ...{ token: "literal" } };\n',
    'const { token } = { token: Math.random(), ["token"]: "literal" };\n',
])
def test_destructuring_without_provable_correspondence_stays_silent(source):
    assert scan_insecure_randomness(archive(source, "repo/app/x.js")) == []


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
