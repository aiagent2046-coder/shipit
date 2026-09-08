"""Golden-corpus harness for the deterministic detectors.

Layout:

    tests/detectors/<rule_id>/positive/<case_name>/   -- must FIRE the rule
    tests/detectors/<rule_id>/negative/<case_name>/   -- must NOT

Each case directory is a self-contained mini-repository: every file in it
(except expected.json) becomes one entry of the archive handed to the real
static stage. expected.json:

    {
      "description": "what this case pins, and why it matters",
      "expect": [{"rule_id": "...", "severity": "critical",   // optional
                  "file_endswith": "route.ts"}],              // optional
      "forbid": ["rule_id", ...]                              // optional
    }

Cases are directories of readable source, not base64 fixtures: a reviewer
must be able to READ what the detector is expected to catch, and a hostile
mutation is one reviewable diff away.
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

from tests.detector_samples import expand_samples
CORPUS_ROOT = Path(__file__).parent


def discover_cases() -> list[tuple[str, str, Path]]:
    """(rule_id, polarity, case_dir) for every case in the corpus."""
    cases = []
    for rule_dir in sorted(CORPUS_ROOT.iterdir()):
        if not rule_dir.is_dir() or rule_dir.name.startswith(("_", ".")):
            continue
        for polarity in ("positive", "negative"):
            pol_dir = rule_dir / polarity
            if not pol_dir.is_dir():
                continue
            for case_dir in sorted(pol_dir.iterdir()):
                if case_dir.is_dir():
                    cases.append((rule_dir.name, polarity, case_dir))
    return cases


def build_archive(case_dir: Path) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(case_dir.rglob("*")):
            if path.is_file() and path.name != "expected.json":
                # Keep inert payloads out of pytest/linters and preserve names
                # such as .env/id_rsa despite the repository's ignore rules.
                assert path.name.endswith(".fixture"), path
                name = path.relative_to(case_dir).as_posix().removesuffix(".fixture")
                zf.writestr(name, expand_samples(path.read_text()))
    buf.seek(0)
    return buf


def load_expected(case_dir: Path) -> dict:
    return json.loads((case_dir / "expected.json").read_text())
