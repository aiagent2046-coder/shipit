"""Offline coverage and coordinate contracts for context compaction."""
import re

from app.scan.prompt_context import PromptExcerpt, numbered_lines, python_excerpt, related_test


KEYWORDS = re.compile(r"auth|password|session|jwt|token", re.I)


def unrelated():
    return "def unrelated():\n    return " + repr("x" * 3000) + "\n"


def test_late_relevant_function_keeps_guard_after_operation_and_original_lines():
    source = (unrelated() + "\ndef authenticate(user):\n    token = user.token\n"
              "    if not user.allowed:\n        return None\n    return token\n")
    excerpt = python_excerpt("app/auth.py", source, KEYWORDS, 500)
    assert isinstance(excerpt, PromptExcerpt)
    assert "if not user.allowed:" in excerpt
    assert "return token" in excerpt
    assert len(excerpt) < 500
    rendered = numbered_lines(excerpt)
    for number, line in enumerate(source.splitlines(), 1):
        if "user.allowed" in line or "return token" in line:
            assert f"{number}\t{line}" in rendered
    assert "omitted original lines 1-2" in rendered
    assert "Never infer" in rendered


def test_keeps_imports_configuration_guard_and_recursive_local_dependency_closure():
    source = ("import hmac\nENABLED = True\nif ENABLED:\n    TIMEOUT = 3\n"
              "def helper(value):\n    return deep(value)\n"
              "def deep(value):\n    return hmac.compare_digest(value, 'known')\n"
              + unrelated() + "def authenticate(value):\n    return helper(value)\n")
    excerpt = python_excerpt("app/auth.py", source, KEYWORDS, 700)
    assert excerpt is not None
    for expected in ("import hmac", "ENABLED = True", "if ENABLED:", "TIMEOUT = 3",
                     "def helper", "def deep", "hmac.compare_digest"):
        assert expected in excerpt
    assert "def unrelated" not in excerpt


def test_decorators_multiline_signatures_and_complete_class_methods_survive():
    source = ("def decorate(fn):\n    return fn\n" + unrelated()
              + "@decorate\nasync def authenticate(\n    value: str,\n):\n    return value\n"
              "class Session:\n    def read(self):\n        return self.value\n"
              "    def guard(self):\n        return self.allowed\n")
    excerpt = python_excerpt("app/auth.py", source, KEYWORDS, 700)
    assert excerpt is not None
    assert "@decorate\nasync def authenticate(\n    value: str," in excerpt
    assert "def decorate" in excerpt
    assert "def guard(self)" in excerpt
    rendered = numbered_lines(excerpt)
    assert all(f"{n}\t{line}" in rendered for n, line in enumerate(source.splitlines(), 1)
               if line == "@decorate" or line == "    def guard(self):")


def test_ambiguous_duplicate_definitions_are_all_included():
    source = ("def helper():\n    return 1\ndef helper():\n    return 2\n"
              + unrelated() + "def authenticate():\n    return helper()\n")
    excerpt = python_excerpt("app/auth.py", source, KEYWORDS, 500)
    assert excerpt is not None
    assert excerpt.count("def helper") == 2


def test_executable_literals_match_but_comments_and_docstrings_do_not():
    source = ("def irrelevant():\n    '''password session token'''\n    # auth jwt\n"
              "    return " + repr("x" * 3000) + "\n"
              "def lookup(db):\n    return db.execute('SELECT password FROM users')\n")
    excerpt = python_excerpt("app/service.py", source, KEYWORDS, 500)
    assert excerpt is not None
    assert "def irrelevant" not in excerpt
    assert "SELECT password" in excerpt


def test_falls_back_instead_of_partial_function_or_missing_configuration():
    source = ("ENABLED = " + repr("x" * 1000) + "\n" + unrelated()
              + "def authenticate():\n    return ENABLED\n")
    assert python_excerpt("app/auth.py", source, KEYWORDS, 500) is None
    huge_function = "def authenticate():\n    return " + repr("x" * 1500) + "\n"
    assert python_excerpt("app/auth.py", unrelated() + huge_function, KEYWORDS, 500) is None


def test_invalid_unsupported_small_or_unmatched_source_uses_existing_fallback():
    assert python_excerpt("app/auth.py", "def invalid(\n" * 100, KEYWORDS, 100) is None
    assert python_excerpt("app/auth.ts", unrelated(), KEYWORDS, 100) is None
    assert python_excerpt("app/auth.py", "token = 1\n", KEYWORDS, 100) is None
    assert python_excerpt("app/auth.py", unrelated(), KEYWORDS, 100) is None


def test_deterministic_and_every_rendered_source_line_matches_original():
    source = "\n# module header\n" + unrelated() + "\ndef authenticate():\n    return None\n\n"
    a = python_excerpt("app/auth.py", source, KEYWORDS, 500)
    b = python_excerpt("app/auth.py", source, KEYWORDS, 500)
    assert a is not None and b is not None
    assert (str(a), a.line_numbers, a.omitted_ranges) == (str(b), b.line_numbers, b.omitted_ranges)
    for row in numbered_lines(a).splitlines():
        if re.match(r"^\d+\t", row):
            number, content = row.split("\t", 1)
            assert content == source.splitlines()[int(number) - 1]
    assert numbered_lines("one\ntwo") == "1\tone\n2\ttwo"


def test_related_test_requires_exact_module_or_import_not_keywords():
    paths = ["repo/app/auth.py", "repo/src/payment.ts", "repo/src/index.ts"]
    assert related_test("repo/tests/test_auth.py", paths)
    assert related_test("repo/src/payment.test.ts", paths)
    assert related_test("repo/tests/test_flow.py", paths, "from app.auth import login")
    assert related_test("repo/tests/test_flow.py", paths, "from app import auth")
    assert related_test("repo/tests/flow.spec.ts", paths, "import { pay } from '../src/payment';")
    assert not related_test("repo/tests/test_auth_other.py", paths, "password jwt token auth")
    assert not related_test("repo/tests/test_flow.py", paths, "from unrelated import auth")
    assert not related_test("repo/tests/test_flow.py", paths, "# import app.auth")
    assert not related_test("repo/tests/index.test.ts", paths)
    assert not related_test("repo/app/auth.py", paths)
    assert not related_test("repo/migrations/test_auth.py", paths)
