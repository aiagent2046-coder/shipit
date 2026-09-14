"""The triage stage must bin noise mechanically, and must not bin signal.

Measured on 2026-09-14: one hunt round produced 75 candidate bodies for 3
real detector gaps; reading and classifying them by hand cost a full review
session. Three noise classes are pure mechanics -- unparseable bodies, bodies
that still name a module they no longer import, and rewrites that removed the
vulnerable construct -- and the fourth (no name the rule's target filter could
match) is a regex. What the tests pin, in the shape that cannot pass by
accident:

  * each noise class lands in its bucket for the RIGHT reason;
  * the real escapes of that measured round -- the array-destructuring and
    renamed-object bodies -- stay in REVIEW;
  * a body without a spec is never binned beyond the parse check;
  * every check errs toward REVIEW: Math.random needs no import, so a pure
    JS body is never "missing import".
"""
import ast
import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def load_triage():
    spec = importlib.util.spec_from_file_location(
        "triage_hunt_escapes", REPO_ROOT / "scripts" / "triage_hunt_escapes.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("triage_hunt_escapes", module)
    spec.loader.exec_module(module)
    return module


TRIAGE = load_triage()
CLASSIFY = TRIAGE.classify


def test_an_unparseable_body_is_a_skip_not_a_miss():
    assert CLASSIFY("insecure-randomness", "token.py",
                   "const [token] = [Math.random()];\nnot valid python (") == "broken (unparseable)"


def test_a_js_body_needs_no_import():
    # Math.random is a JS builtin: `\brandom\.\w+\(` does not match it, so a
    # pure JS body must never be classified as missing an import.
    body = "const resetToken = Math.random().toString(36).slice(2);\n"
    assert CLASSIFY("insecure-randomness", "token.js", body) == "review"


def test_a_python_draw_without_its_import_is_broken():
    body = ("def make_token():\n"
            "    return ''.join(random.choice(chars) for _ in range(32))\n")
    assert CLASSIFY("insecure-randomness", "token.py", body) == "broken (missing import)"


def test_a_rewrite_that_removed_the_vulnerability_is_not_a_candidate():
    body = ("import secrets\n"
            "reset_token = secrets.token_hex(16)\n")
    assert CLASSIFY("insecure-randomness", "token.py", body) == "vuln-removed"


def test_a_body_the_target_filter_could_never_match_is_not_a_candidate():
    body = "const animationOffset = Math.random() * width;\n"
    assert CLASSIFY("insecure-randomness", "anim.js", body) == "no-secret-target"


def test_the_measured_real_escapes_stay_in_review():
    array_destructure = "const [token] = [Math.random().toString(36).slice(2)];\n"
    renamed_object = ("const { token: randomToken } = "
                      "{ token: Math.random().toString(36).slice(2) };\n")
    assert CLASSIFY("insecure-randomness", "token.js", array_destructure) == "review"
    assert CLASSIFY("insecure-randomness", "token.js", renamed_object) == "review"


def test_the_archive_escape_was_broken_not_real():
    body = ("from pathlib import Path\n"
            "def extract_archive(file_path, destination):\n"
            "    with tarfile.open(file_path) as tf:\n"
            "        tf.extractall(path=destination, filter=\"fully_trusted\")\n")
    assert CLASSIFY("archive-extraction-fully-trusted", "unpack.py",
                    body) == "broken (missing import)"


def test_a_proven_archive_positive_is_review():
    body = ("import tarfile\n"
            "with tarfile.open(upload) as tar:\n"
            "    tar.extractall(dest, filter=\"fully_trusted\")\n")
    assert CLASSIFY("archive-extraction-fully-trusted", "unpack.py", body) == "review"


def test_a_sql_rewrite_without_the_vulnerability_is_not_a_candidate():
    body = ("def query(cur, name):\n"
            "    cur.execute(\"SELECT id FROM users WHERE name = %s\", (name,))\n")
    assert CLASSIFY("sql-injection-string-built-query", "db.py", body) == "vuln-removed"


def test_a_sql_wrapper_evasion_stays_in_review():
    # The defect is present behind an unknown sink; only the documented
    # no-cross-file boundary explains the silence, so a human must read it.
    body = ("const dbFunctions = require(\"./queryFunctions\");\n"
            "export async function getUserRecord(userId) {\n"
            "  return dbFunctions.queryDB(\"SELECT id FROM users WHERE id = \" + userId);\n"
            "}\n")
    assert CLASSIFY("sql-injection-string-built-query", "queries.ts", body) == "review"


def test_a_rule_without_a_spec_only_gets_the_parse_check():
    body = "const anything = whatever();\n"
    assert CLASSIFY("some-future-rule", "thing.js", body) == "review (no spec)"
    broken = "def broken(\n"
    assert CLASSIFY("some-future-rule", "thing.py", broken) == "broken (unparseable)"


def test_dump_names_parse_into_rule_and_filename():
    assert TRIAGE._rule_and_file(Path("insecure-randomness__0a547__reset.js")) == \
        ("insecure-randomness", "reset.js")
    assert TRIAGE._rule_and_file(Path("not-a-hunt-file.py")) is None


def test_a_whole_dump_directory_is_binned_with_reasons(tmp_path, capsys):
    dump = tmp_path / "dump"
    dump.mkdir()
    (dump / "insecure-randomness__aa__secure.py").write_text(
        "import secrets\nreset_token = secrets.token_hex(16)\n")
    (dump / "insecure-randomness__bb__real.js").write_text(
        "const [token] = [Math.random().toString(36)];\n")
    (dump / "insecure-randomness__cc__broken.py").write_text("def broken(\n")
    assert TRIAGE.triage([dump]) == 0
    out = capsys.readouterr().out
    assert "vuln-removed: 1" in out
    assert "broken (unparseable): 1" in out
    assert "review: 1" in out
    assert "insecure-randomness__bb__real.js" in out
    assert "TOTAL review queue: 1 bodies" in out


def test_the_specs_cover_the_actively_hunted_rules():
    hunted = {"insecure-randomness", "sql-injection-string-built-query",
              "archive-extraction-fully-trusted", "xss-unsafe-html-injection",
              "command-injection-shell-built-command", "path-traversal-file-sink",
              "unsafe-xml-parse", "unsafe-deserialization"}
    assert hunted <= set(TRIAGE.SPECS)


def test_every_spec_marker_and_import_pattern_is_a_valid_regex():
    for rule_id, spec in TRIAGE.SPECS.items():
        for pattern in spec.markers:
            re_pattern = __import__("re").compile(pattern)
            assert re_pattern.pattern
        for usage, import_line in spec.imports.items():
            __import__("re").compile(usage)
            __import__("re").compile(import_line)


def test_a_parseable_python_body_parses_for_the_check():
    # The parse check itself: a valid body must NOT report broken.
    body = "import tarfile\nwith tarfile.open(p) as t:\n    t.extractall(d)\n"
    parsed = ast.parse(body)  # the same call the triage makes
    assert parsed is not None
    assert TRIAGE._parse_error(body, ".py") is False
