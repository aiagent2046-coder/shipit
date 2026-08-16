"""A category emptied by recategorisation, from the scan to the page (#28).

Auth read a perfect 10.0 on a repository whose endpoint runs shell commands
with no login check. Nothing was broken in the scoring: the auth rubric found
the defect, the model correctly called it a Security problem, the finding was
filed there, and Auth was left holding nothing -- and an empty category scores
10.0. The report then drew that as a full green bar next to the word "Auth",
which answers the reader's question with a confident yes nobody gave.

Both halves of the fix have tests. tests/test_checks_scoring.py proves the
scorer reports such a category in `reported_elsewhere` and keeps it out of the
mean; tests/test_report.py proves a score dict carrying that key renders as
"reported under Security". NOTHING JOINED THEM. No test drove a real scan
whose model moved a finding and then looked at the finished page, so the seam
between them -- pipeline assembling the score, the key surviving into
score_json, the renderer finding it there -- was carried by production alone,
where the condition had not arisen since the fix shipped.

This file is that join, and it is deterministic: the model is a stub that
declares the category, so the case arrives on demand instead of waiting for a
repository that happens to produce it.
"""

from __future__ import annotations

import io
import json
import zipfile

from app.llm.client import LLMClient, LLMUsage, Provider
from app.report.html import render_report
from app.scan.pipeline import run_scan

# Matches the auth rubric's keywords, so that rubric runs and its findings are
# the ones the model gets to move.
AUTH_SRC = (
    "// jwt token session login password cookie authorization\n"
    "export function decode(t: string) { return jwt.decode(t) }\n"
    "export function run(cmd: string) { return exec(cmd) }\n"
)


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("src/api/session.ts", AUTH_SRC)
    return buf.getvalue()


def _finding(category: str) -> str:
    return json.dumps([{
        "file": "src/api/session.ts", "line_start": 3, "line_end": 3,
        "evidence": "exec(cmd)", "severity": "critical", "confidence": 0.9,
        "title": "Unauthenticated endpoint executes shell commands",
        "explanation": "...", "fix_hint": "require a session",
        "category": category,
    }])


class DeclaresCategory(LLMClient):
    """A model that files its finding under a category of its choosing."""

    def __init__(self, category: str):
        super().__init__(providers=[Provider("anthropic", "https://x", "k",
                                             "claude-sonnet-4.6")])
        self.category = category

    def complete(self, system, user, max_tokens=4096):
        return _finding(self.category), LLMUsage(
            model="claude-sonnet-4.6", input_tokens=1000, output_tokens=200)


def _scan(category: str) -> dict:
    return run_scan(_zip(), DeclaresCategory(category), llm_rubrics=("auth",))


def test_the_emptied_category_is_named_as_moved_not_scored():
    result = _scan("Security")
    score = result["score"]

    assert score["reported_elsewhere"] == {"Auth": ["Security"]}
    # That the emptied category is also kept OUT OF THE MEAN is asserted in
    # tests/test_checks_scoring.py, against compute_scores directly, and the
    # mutation that drops the exclusion dies there. Stated rather than
    # re-asserted here: an assertion recomputed from this result's own
    # `reported_elsewhere` key would restate the line above and survive that
    # mutation untouched, which is a test that looks stronger than it is.


def test_the_page_says_where_the_findings_went():
    result = _scan("Security")

    html = render_report(result)

    assert "reported under Security" in html


def test_the_emptied_category_does_not_read_ten_out_of_ten():
    """The whole defect in one assertion. An empty category scores 10.0, and
    10.0 on Auth is the single most reassuring thing this report can print."""
    result = _scan("Security")

    html = render_report(result)
    auth_row = next(line for line in html.split('<div class="cat">')
                    if "Auth" in line)

    assert "10.0" not in auth_row
    assert "not checked" not in auth_row, (
        "the rubric ran and found something; 'not checked' sends the reader "
        "hunting for an audit that already happened"
    )


def test_a_rubric_that_keeps_its_finding_is_scored_normally():
    """The control. Without it, a report that said "reported under" for every
    category would pass every assertion above."""
    result = _scan("Auth")

    assert result["score"]["reported_elsewhere"] == {}
    assert result["score"]["categories"]["Auth"] < 10.0
    assert "reported under" not in render_report(result)


def test_the_moved_finding_still_appears_in_the_table():
    """Moved, not lost. The finding is the reason the category is empty, and
    a reader who cannot find it anywhere has been told less, not more."""
    html = render_report(_scan("Security"))

    assert "Unauthenticated endpoint executes shell commands" in html
    # ...and it says where it came from, which is what makes the two halves of
    # the page reconcilable: a bar reading "reported under Security" and a row
    # reading "Security (moved from Auth)" are the same fact, twice.
    assert "Security (moved from Auth)" in html
