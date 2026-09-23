"""Pin the escape classes the LLM hunt found -- now as deterministic generators.

Every transform here is a rewrite the escape hunt (scripts/hunt_detector_escapes.py)
surfaced against insecure-session-cookie-attributes and the fix landed for.
The hunt ran those five rounds ONCE; this module keeps them firing FOREVER,
across languages, with no model involved.

The relation: the transformed case must reproduce the same expected.json as
the untouched one -- an edit that cannot change what the code IS must not
change what the audit SAYS.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from app.scan.static import run_static_scan
from tests.detector_samples import expand_samples
from tests.detectors.conftest import load_expected
from tests.detectors.test_golden_corpus import assert_case
from tests.metamorphic_variants import (
    TRANSFORMS,
    Transform,
    language_of,
    variant_entries,
)

CORPUS = Path(__file__).parent.parent / "detectors"

# Hunt class -> the corpus case that embodies it. One case per class is
# enough for the pin: scripts/metamorphic_probe.py sweeps the whole corpus.
PINNED: list[tuple[str, str, str]] = [
    # (rule_id, case name, transform id)
    ("insecure-session-cookie-attributes",
     "js-cookie-name-from-a-local-binding", "local_const"),
    ("insecure-session-cookie-attributes",
     "js-express-httponly-false", "numeric_bool"),
    ("insecure-session-cookie-attributes",
     "js-express-cookie-without-options", "rename_locals"),
    ("insecure-session-cookie-attributes",
     "js-options-held-in-a-local-object", "rename_locals"),
    ("insecure-session-cookie-attributes",
     "js-options-held-in-a-local-object", "local_const"),
    ("insecure-session-cookie-attributes",
     "python-samesite-none-on-the-session-cookie", "local_const"),
    ("insecure-session-cookie-attributes",
     "python-samesite-none-on-the-session-cookie", "concat_split"),
    ("insecure-session-cookie-attributes",
     "python-samesite-none-on-the-session-cookie", "block_nest"),
    ("insecure-session-cookie-attributes",
     "python-samesite-none-on-the-session-cookie", "dead_branch"),
    ("insecure-session-cookie-attributes",
     "python-django-samesite-string-none", "comment_shift"),
    ("insecure-session-cookie-attributes",
     "js-document-cookie-write", "comment_shift"),
]


def _case_dir(rule_id: str, case_name: str) -> Path:
    for polarity in ("positive", "negative"):
        candidate = CORPUS / rule_id / polarity / case_name
        if candidate.is_dir():
            return candidate
    raise AssertionError(f"no corpus case {rule_id}/{case_name}")


def _entries(case_dir: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for path in sorted(case_dir.rglob("*")):
        if path.is_file() and path.name != "expected.json":
            name = path.relative_to(case_dir).as_posix().removesuffix(".fixture")
            out[name] = expand_samples(path.read_text())
    return out


def _scan(entries: dict[str, str]) -> list[dict]:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in entries.items():
            zf.writestr(name, body)
    buf.seek(0)
    return run_static_scan(buf)["findings"]


def _transform_for(transform_id: str, entries: dict[str, str]) -> Transform:
    langs = {language_of(path) for path in entries}
    matches = [
        t for t in TRANSFORMS
        if t.id == transform_id and t.lang in langs
    ]
    assert matches, f"no transform {transform_id} for languages {langs}"
    return matches[0]


@pytest.mark.parametrize(
    "rule_id,case_name,transform_id", PINNED,
    ids=[f"{case}:{t}" for _, case, t in PINNED],
)
def test_hunt_escape_class_stays_closed(rule_id, case_name, transform_id):
    case_dir = _case_dir(rule_id, case_name)
    expected = load_expected(case_dir)
    polarity = case_dir.parent.name
    entries = _entries(case_dir)

    # Control first: the untouched case must satisfy its own contract.
    assert_case(rule_id, polarity, expected, _scan(entries))

    transform = _transform_for(transform_id, entries)
    variant = variant_entries(entries, transform)
    assert variant.status == "applied", (
        f"{transform_id} did not apply to {case_name} ({variant.status})"
    )
    assert_case(rule_id, polarity, expected, _scan(variant.entries))
