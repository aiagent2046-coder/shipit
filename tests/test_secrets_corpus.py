"""Corpus walker for the `generic-assignment` secret rule.

Mirrors the load-bearing discipline of tests/test_cookie_flags.py:

  * every corpus negative is MUTATED in the one place that removes the property
    it pins, and the rule must fire on the result -- silence alone proves
    nothing;
  * every negative on disk has a mutation (the completeness assertion below).

Two deliberate differences, both the reason this file exists:

1. Fixtures are fed under their REAL repository name -- the inert `.fixture`
   suffix intact -- because that is how a scan of this repository sees them.
   The sibling walkers strip the suffix before scanning (`.ts.fixture` -> `.ts`)
   so the language parser engages, which is right for language-bound rules but
   blind to exactly the class of bug a dogfood audit found: a corpus negative
   `docs/install.md.fixture` came back FIRED, because `_shell_substitution_offsets`
   keyed markdown/shell semantics off the filename and `.fixture` is not `.md`.
   `generic-assignment` is regex-based and reads the same bytes either way, so
   feeding the wrapper name here pins the suffix handling that keeps a wrapper
   from resurrecting a finding a fixture declares absent.

2. A mutation is "replace the whole line carrying this WORD", not a literal
   `str.replace` on the value and not a regex. Fixture values are
   credential-shaped and get masked in tool output, so neither an exact-value
   anchor nor a `NAME=*** pattern is reliably writable from here;
   anchoring on a bare identifier reaches the same one change regardless of
   what the value spells. For the same reason every replacement below that
   needs a `name=value` shape builds it by concatenation, so no source line
   here reads as a secret assignment.
"""

import io
import zipfile
from pathlib import Path

import pytest

from app.scan.secrets import scan_secrets

RULE_ID = "generic-assignment"
REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_NEGATIVES = REPO_ROOT / "tests" / "detectors" / RULE_ID / "negative"

_DQ, _BT = '"', "`"
_FILL = "abcdefghijklmnop"
_FILL2 = "mnopqrstuvwxyz01"

# Replacement lines, each the rule's basic positive form (a credential-shaped
# name carrying a long literal). `name=` shapes are concatenated so the
# assignment is not written out as one secret-looking literal here.
_LEAK = "const api_key = " + _DQ + _FILL + _DQ
_LEAK_PY = "api_key = " + _DQ + _FILL + _DQ
_LEAK_BASH = "docker run -e " + "API_KEY" + "=" + _DQ + _FILL + _DQ + " app"
_LEAK_EXPORT = "export const api_key = " + _DQ + _FILL + _DQ + ";"
_LEAK_TEMPLATE = "const api_key = " + _BT + _FILL + _BT
_LEAK_PASSWORD = "const password = " + _DQ + _FILL2 + _DQ


def archive(files: dict[str, str]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    buf.seek(0)
    return buf


def _case_files(case_dir: Path) -> dict[str, str]:
    """The case's fixtures under their real repository path, `.fixture` on."""
    return {
        p.relative_to(REPO_ROOT).as_posix(): p.read_text()
        for p in case_dir.rglob("*.fixture")
    }


def _rule_hits(files: dict[str, str]) -> list:
    return [f for f in scan_secrets(archive(files)) if f.rule_id == RULE_ID]


def _replace_marked_line(text: str, marker: str, replacement: str) -> str:
    """Replace the single line containing `marker`, preserving its newline."""
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if marker in line:
            body = line.rstrip("\r\n")
            lines[i] = replacement + line[len(body):]
            return "".join(lines)
    return text


# case name -> (fixture path, the WORD marking the line to mutate, the line it
# becomes). Each replacement removes the property the case pins -- a generic
# name, an interpolation, a short literal, a public token, a shell reference all
# become an ordinary leak.
MUTATIONS: dict[str, tuple[str, str, str]] = {
    "generic-names": ("src/config.ts", "modifierAltGraph", _LEAK),
    "interpolated-template": ("src/config.ts", "process.env.API_KEY", _LEAK_TEMPLATE),
    "public-posthog-project-token": ("src/analytics.ts", "PROJECT_TOKEN", _LEAK_EXPORT),
    "shell-reference-in-markdown": ("docs/install.md", "docker run", _LEAK_BASH),
    "short-literal": ("src/config.ts", "const api_key", _LEAK),
    "suffix-after-separator": ("src/config.ts", "API_KEY_COOKIE", _LEAK),
    "unpaired-quotes-and-pwd": ("config.py", "ANTHROPIC_API_KEY", _LEAK_PY),
    "word-inside-word": ("src/config.ts", "passwordless", _LEAK_PASSWORD),
}


def test_every_corpus_negative_has_a_mutation():
    """A negative with no mutation above is pinned by silence alone, and silence
    is the one thing a negative cannot prove."""
    on_disk = {case.name for case in CORPUS_NEGATIVES.iterdir() if case.is_dir()}
    assert on_disk == set(MUTATIONS), f"no mutation for: {on_disk - set(MUTATIONS)}"


@pytest.mark.parametrize("case", sorted(MUTATIONS))
def test_each_corpus_negative_goes_silent_for_its_stated_reason(case):
    relative, marker, replacement = MUTATIONS[case]
    case_dir = CORPUS_NEGATIVES / case
    files = _case_files(case_dir)
    suffix = relative + ".fixture"
    target = next((n for n in files if n.endswith(suffix)), None)
    assert target is not None, f"mutation anchor file {relative} is gone"
    assert _rule_hits(files) == [], "the untouched case must be silent"
    before = files[target]
    files[target] = _replace_marked_line(before, marker, replacement)
    assert files[target] != before, f"mutation anchor word {marker!r} is gone"
    assert _rule_hits(files), "the mutation must make the rule fire"
