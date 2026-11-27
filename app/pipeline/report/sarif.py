"""Findings as SARIF 2.1.0, so the tools that read SARIF can read this audit.

WHY SARIF AND NOT ANOTHER JSON SHAPE. GitHub's code scanning, VS Code's
problems panel, and most CI security plugins consume SARIF and nothing else.
An audit only reaches those surfaces if it speaks their format, and the format
is specified rather than ours -- the schema is checked in at
tests/fixtures/sarif-schema-2.1.0.json because every consumer validates against
it (see the SOURCE note beside it).

WHAT THIS MODULE IS NOT. It adds no findings, drops none and reorders nothing
that matters: it is a translation of the finding list the report already shows.
The one test that keeps it honest asserts the two agree finding for finding.

TWO DECISIONS WORTH NAMING:

- `level` is set per RESULT, not as a rule default. A rule's severity can vary
  with what it found (generic-assignment is a low-severity habit here and a
  leaked credential there), so a per-rule default would be a claim about the
  rule that this run cannot support.
- A finding with no line gets a location with no `region`. SARIF requires
  `startLine >= 1`, and a structural or dependency finding knows its file but
  not a line; writing 1 would point a reader at the wrong place in the file.
"""
from __future__ import annotations

import json

from app.scan.sarif_format import (  # noqa: F401  (re-exported)
    DEPENDENCY_RULE_IDS,
    FINGERPRINT_KEY,
    LEVELS,
    SARIF_SCHEMA,
    SARIF_VERSION,
    TOOL_NAME,
    _level,
    _location,
    _message,
    _relative_path,
    _rule,
    _uri,
    build_sarif,
    fingerprint,
)


# The consumer-facing severity vocabulary maps onto SARIF's four levels. `error`
# for anything a reader should act on before shipping, `warning` for what is
# worth fixing, `note` for the rest -- the same split the report's own tiers
# make (app/report/plain_language.TIERS), so the two cannot disagree.
# A location-based hint for consumers that understand our key. This is not
# GitHub's source-derived `primaryLocationLineHash`, and does not replace its
# fingerprint generation at upload time. Moving a finding changes this hint.
def render_sarif(findings: list[dict], **kwargs) -> str:
    """The document as JSON text, for writing to a file or a response body."""
    return json.dumps(build_sarif(findings, **kwargs), indent=2, ensure_ascii=False)
