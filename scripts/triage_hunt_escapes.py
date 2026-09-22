#!/usr/bin/env python3
"""Mechanically bin hunt escape bodies before a human reads them.

WHY THIS EXISTS. The escape hunt (hunt_detector_escapes.py) produces a REVIEW
QUEUE, and measured on 2026-09-14 that queue was 75 candidate bodies for 3
real detector gaps: a 7B model rewrites vulnerable code into secure code,
drops the import a rewritten body still mentions, or emits syntax no engineer
would write -- and the scanner is RIGHT to stay silent on all of those.
Reading 75 bodies by hand is the expensive part; three of the four noise
classes are detectable without any judgment at all:

  broken (unparseable)   -- the body does not parse; the rule skips it, so
                            its silence is a skip, not a miss.
  broken (missing import) -- the body still uses a module it no longer
                            imports; the code would NameError at runtime.
  vuln-removed           -- the body no longer contains the vulnerable
                            construct the rule exists to detect.
  no-secret-target       -- the body mentions no name the rule's target
                            filter could ever match (rules that have one).

Only the REVIEW bucket needs a human. Every check errs toward REVIEW: a body
that passes the marker but semantically matches a documented rule boundary
(a helper returning a closure, a Python helper, a custom wrapper) lands in
REVIEW too, with its reason attached. The buckets are measurements of noise,
not verdicts about the detector.

USAGE: triage_hunt_escapes.py --dump DIR [--dump DIR ...]
Reads every file the hunt wrote (named {rule_id}__{sha}__{filename}); the
rule id comes from the name, the language from the filename extension.
Rules without a spec still get the parse check; their survivors land in
REVIEW with a note.
"""
from __future__ import annotations

import argparse
import ast
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from app.scan.insecure_randomness import _SECRET_WORDS  # noqa: E402

_PY_SUFFIXES = {".py"}
_JS_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts"}
_TSX_SUFFIXES = {".tsx", ".jsx"}

# Method names, not module spellings: `import random as rnd` still draws
# through rnd.getrandbits, `from random import random` draws bare, and
# Math.random matches the bare `random` arm.  Do not require an immediate
# call: a hunt rewrite can bind the dangerous callable and invoke the alias
# later. A body that only calls secrets/urandom still matches nothing.
_RANDOM_METHODS = r"\b(?:random|randint|randrange|choice|getrandbits|uniform|sample)\b"

_CONCATENATED_LITERAL = re.compile(
    r"""(?P<q>["'])(?P<a>(?:[^\\]|\\.)*?)(?P=q)\s*\+\s*(?P=q)(?P<b>(?:[^\\]|\\.)*?)(?P=q)"""
)


def _fold_literal_concatenations(body: str) -> str:
    """Collapse `"fully_" + "trusted"` into the one literal it spells.

    MEASURED: the metamorphic probe's concat splits binned real corpus
    positives as "vuln-removed" -- the marker looked for one literal where
    the body spelled the same value in two. A statically knowable
    concatenation is still the vulnerable shape (app.scan.literal_values
    folds the same construct for the scanners; this is the triage twin).

    Deliberately a FALLBACK, never the primary text: the regex cannot read
    precedence and will happily fold `" WHERE " + " AND ".join(...)` even
    though the second literal is a join separator. That fold can destroy a
    marker (sql-injection's assembly-operator marker is literally `+`), so
    classify() matches against the raw body first and only retries folded.
    """
    out = body
    for _ in range(4):  # bounded: chains fold left to right
        folded = _CONCATENATED_LITERAL.sub(
            lambda m: f"{m.group('q')}{m.group('a')}{m.group('b')}{m.group('q')}", out
        )
        if folded == out:
            break
        out = folded
    return out


@dataclass(frozen=True)
class Spec:
    """What a body must still contain to be worth a human's reading.

    markers: regexes that must ALL be found, else the body is vuln-removed.
             Deliberately BROAD -- method names, not module spellings: a
             missed marker drops a real escape (review round 1 found seven),
             a loose one costs one human read. The corpus invariant in
             tests/test_triage_hunt_escapes.py fails the moment detector
             coverage outgrows these markers.
    target:  a regex that must be found somewhere (rules with a target
             filter; deliberately liberal, so only clear absences bin out).
    imports: usage regex -> import regex; a usage without its import is a
             body that would NameError -- broken, not a miss.
    """

    markers: tuple[str, ...] = ()
    target: str | None = None
    imports: dict[str, str] = field(default_factory=dict)


SPECS: dict[str, Spec] = {
    "insecure-randomness": Spec(
        markers=(_RANDOM_METHODS,),
        # Any secret word anywhere keeps the body in REVIEW; a body that
        # mentions none cannot match the rule's target filter at all.
        target="|".join(_SECRET_WORDS),
        imports={r"\brandom\.\w+\s*\(": r"^\s*(?:import random\b|from random import\b)"},
    ),
    "sql-injection-string-built-query": Spec(
        markers=(r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b",
                 # `%` is deliberately broad. Distinguishing a placeholder
                 # in a literal from a later `template % value` operation is
                 # semantic work, and dropping the latter would hide exactly
                 # the detector escapes this queue exists to expose.
                 # JS template substitutions are assembly too, including
                 # branches whose later assignments cannot sanitize them.
                 r"\+|\.format\b|\bf['\"]|\{\}|%|\$\{"),
    ),
    "archive-extraction-fully-trusted": Spec(
        markers=(r"fully_trusted",),
        imports={r"\btarfile\.": r"^\s*(?:import tarfile\b|from tarfile import\b)"},
    ),
    "xss-unsafe-html-injection": Spec(
        markers=(r"innerHTML|outerHTML|dangerouslySetInnerHTML|"
                 r"insertAdjacentHTML|document\.write|\.html\(|v-html",),
    ),
    "command-injection-shell-built-command": Spec(
        # Method references stay signal too (`runner = subprocess.run`).
        markers=(r"shell\s*=\s*True|\b(?:system|popen|popen2|popen3|popen4|"
                 r"run|call|check_call|check_output|Popen)\b",),
    ),
    "path-traversal-file-sink": Spec(
        # As above, an assigned sink is not evidence that the vulnerability
        # was removed, so marker calls are not required to be immediate.
        markers=(r"\b(?:open|send_file|read_text|read_bytes|copy|rmtree|Path|join)\b",),
    ),
    "unsafe-xml-parse": Spec(
        markers=(r"resolve_entities",),
        imports={r"\betree\.": r"^\s*(?:import lxml\b|from lxml import\b)"},
    ),
    "unsafe-deserialization": Spec(
        # Method names again: include references and bulk/alias entry points.
        # The word boundaries keep yaml.safe_load out: `_` is a word char, so
        # its trailing `load` is not a standalone marker.
        markers=(r"\b(?:load|loads|load_all|unsafe_load|unsafe_load_all|"
                 r"read_pickle|decode|Unpickler)\b|"
                 r"\b(?:marshal|pickle|dill|jsonpickle)\.",),
        imports={r"\byaml\.": r"^\s*(?:import yaml\b|from yaml import\b)"},
    ),
}

REVIEW = "review"


def is_review(bucket: str) -> bool:
    """Both review spellings belong in the queue: a specced rule returns
    REVIEW, an unknown rule returns "review (no spec)". A bucket left out of
    the queue count is a bucket no human ever reads."""
    return bucket == REVIEW or bucket.startswith(f"{REVIEW} ")


def _parse_error(body: str, suffix: str) -> bool:
    """The body does not parse -- a skip, never a miss."""
    if suffix in _PY_SUFFIXES:
        try:
            ast.parse(body)
        except (SyntaxError, ValueError):
            return True
        return False
    if suffix in _JS_SUFFIXES:
        from app.scan.xss import _parser
        root = _parser(suffix in _TSX_SUFFIXES).parse(body.encode()).root_node
        return root.has_error
    return False


def classify(rule_id: str, filename: str, body: str) -> str:
    """One bucket name for one dumped body."""
    suffix = Path(filename).suffix.lower()
    if _parse_error(body, suffix):
        return "broken (unparseable)"
    spec = SPECS.get(rule_id)
    if spec is None:
        return f"{REVIEW} (no spec)"
    candidates = (body, _fold_literal_concatenations(body))
    for usage, import_line in spec.imports.items():
        if re.search(usage, body, re.MULTILINE) and not any(
            re.search(import_line, candidate, re.MULTILINE) for candidate in candidates
        ):
            return "broken (missing import)"
    if not any(
        all(re.search(marker, candidate) for marker in spec.markers)
        for candidate in candidates
    ):
        return "vuln-removed"
    if spec.target is not None and not any(
        re.search(spec.target, candidate, re.IGNORECASE) for candidate in candidates
    ):
        return "no-secret-target"
    return REVIEW


def _rule_and_file(path: Path) -> tuple[str, str] | None:
    # maxsplit=2: the third field is the ORIGINAL filename, and an original
    # filename may itself contain "__" (auth__reset.py) -- it must survive
    # intact, suffix included, because the parse check reads the suffix.
    parts = path.name.split("__", 2)
    if len(parts) < 3:
        return None
    return parts[0], parts[2]


def triage(dump_dirs: list[Path]) -> int:
    buckets: dict[str, dict[str, list[Path]]] = {}
    unparsed_names = 0
    for dump_dir in dump_dirs:
        for path in sorted(dump_dir.iterdir()):
            rule_and_file = _rule_and_file(path)
            if rule_and_file is None:
                unparsed_names += 1
                continue
            rule_id, filename = rule_and_file
            bucket = classify(rule_id, filename, path.read_text())
            buckets.setdefault(rule_id, {}).setdefault(bucket, []).append(path)
    review_total = 0
    for rule_id in sorted(buckets):
        rule_buckets = buckets[rule_id]
        bodies = sum(len(paths) for paths in rule_buckets.values())
        print(f"=== {rule_id}: {bodies} bodies")
        for bucket in sorted(rule_buckets):
            print(f"    {bucket}: {len(rule_buckets[bucket])}")
        review_paths = [path for bucket in sorted(rule_buckets)
                        if is_review(bucket)
                        for path in rule_buckets[bucket]]
        review_total += len(review_paths)
        for path in review_paths:
            print(f"    REVIEW -> {path}")
    if unparsed_names:
        print(f"(skipped {unparsed_names} files without the {{rule}}__{{sha}}__{{name}} shape)")
    print(f"\nTOTAL review queue: {review_total} bodies")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--dump", type=Path, action="append", required=True,
                        help="a directory the hunt wrote escape bodies to (repeatable)")
    args = parser.parse_args()
    dirs = []
    for dump_dir in args.dump:
        if not dump_dir.is_dir():
            parser.error(f"--dump {dump_dir} is not a directory")
        dirs.append(dump_dir)
    return triage(dirs)


if __name__ == "__main__":
    raise SystemExit(main())
