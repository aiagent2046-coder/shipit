"""The web app and the HTML report must say the same thing about a category.

They are two renderers of one score, written in two languages, and the web
one is the surface the customer sees FIRST -- the HTML report sits behind a
link on it. When #264 stopped the report publishing category numbers, the web
app kept publishing them for a full release: audit 2230094e drew

    Auth          1.6   width: 16%
    Security      1.9   width: 19%
    Money & Data  3.9   width: 39%

with the cap paragraph underneath restating "Security 1.9, Auth 1.6, Money &
Data 3.9" -- every channel the report had just closed, open on the page more
people read.

TypeScript cannot import GATE_THRESHOLD from app/scan/scoring.py, so
web/src/lib/format.ts holds a second copy of the band rule. These tests are
what makes that copy honest: they read the TypeScript as text and fail when
the two stop agreeing. Text matching is brittle, and it is the only
cross-language check available here -- web/ has no test runner, only
`next build`. Each assertion below names one specific way the surfaces have
drifted or could drift again.
"""

import re
from pathlib import Path

from app.report.html import _band
from app.scan.scoring import GATE_THRESHOLD

_WEB = Path(__file__).resolve().parent.parent / "web" / "src"
_FORMAT_TS = _WEB / "lib" / "format.ts"
_SCORE_RING_TSX = _WEB / "components" / "ScoreRing.tsx"


def _number_after(name: str, text: str) -> float:
    match = re.search(rf"const {name} = ([0-9.]+)", text)
    assert match, f"{name} is not declared as a plain number in format.ts"
    return float(match.group(1))


def test_the_band_boundary_is_the_python_one():
    """The whole point of the boundary is that the scorer already acts on it.
    A hand-copied 7.0 that quietly stays behind a moved GATE_THRESHOLD would
    put the two surfaces in different bands on the same audit."""
    text = _FORMAT_TS.read_text()

    assert _number_after("GATE_THRESHOLD", text) == GATE_THRESHOLD


def test_the_band_floor_is_derived_and_not_typed_out():
    """Written as GATE_THRESHOLD / 2, so moving the threshold moves the floor
    with it. A literal 3.5 here survives a threshold change silently."""
    text = _FORMAT_TS.read_text()

    assert re.search(r"const BAND_FLOOR = GATE_THRESHOLD / 2", text), (
        "BAND_FLOOR must be derived from GATE_THRESHOLD, not typed out")


def _ts_bands() -> list[tuple[str, int, str]]:
    """(label, pct, colour) for each branch of categoryBand, in source order."""
    body = _FORMAT_TS.read_text().split("export function categoryBand")[1]
    found = re.findall(
        r'label: "([^"]+)", pct: (\d+), color: "(#[0-9a-fA-F]+)"', body)
    assert len(found) == 3, f"expected three bands, found {len(found)}"
    return [(label, int(pct), colour) for label, pct, colour in found]


def test_both_surfaces_use_the_same_words_and_widths():
    """A reader who opens the report from the page must not be told two
    different things about one category. The colours are allowed to differ --
    the two surfaces have different palettes -- but the claim may not."""
    python = [_band(v) for v in (GATE_THRESHOLD, GATE_THRESHOLD / 2, 0.0)]

    for (ts_label, ts_pct, _), (py_label, py_pct, _) in zip(_ts_bands(), python):
        assert ts_label == py_label
        assert ts_pct == py_pct


def test_the_web_bands_are_told_apart_by_colour():
    """Three bands, three colours. One flat colour would satisfy every other
    assertion here while making the rows indistinguishable."""
    colours = {colour for _, _, colour in _ts_bands()}

    assert len(colours) == 3, colours


def test_the_page_does_not_print_a_category_number():
    """The defect itself, stated directly. `value` is a category's score; the
    total is a different variable and keeps its toFixed(1) in ScoreRing."""
    bars = _SCORE_RING_TSX.read_text().split("export function CategoryBars")[1]

    assert "value.toFixed" not in bars, (
        "a category's exact number is back on the page")
    assert "(value / 10)" not in bars, (
        "a proportional bar restates the exact number as a width")


def test_the_cap_paragraph_names_categories_without_their_values():
    """The second leak on this surface, and the one that outlived the first
    fix on the Python side too: the paragraph republished what the bars above
    it had just stopped saying."""
    note = _SCORE_RING_TSX.read_text().split("function GateNote")[1]
    note = note.split("export function CategoryBars")[0]

    assert "r.value" not in note, (
        "the cap paragraph prints the failing category's exact value")
    assert "r.category" in note, (
        "the cap paragraph must still name which category failed")


# --- the free tier ----------------------------------------------------------
#
# The report has withheld the score on both free bases for as long as the
# second one has existed. The page excluded only "static_only", so every
# "static+preview" scan took the paid branch. Audit 2b957672 published a 3.8
# ring and "Not production-ready yet" while /pricing sells the free tier as
# "No readiness score out of 10" and lists that score as what the $10 buys.
#
# The root cause was in the types, not the predicate: Score.basis listed two
# of the backend's four values, so `basis !== "static+preview"` was a compile
# error and the correct branch could not be written.

_PAGE_TSX = _WEB / "app" / "audit" / "[id]" / "page.tsx"
_TYPES_TS = _WEB / "lib" / "types.ts"


def test_the_basis_union_lists_every_basis_the_backend_emits():
    """A union narrower than the wire makes the honest branch unwriteable."""
    from app.scan.pipeline import (
        BASIS_FULL, BASIS_PARTIAL, BASIS_PREVIEW, BASIS_STATIC_ONLY,
    )

    text = _TYPES_TS.read_text()
    declared = re.search(r"basis\?:([^;]+);", text)
    assert declared, "Score.basis is not declared as a union"

    for value in (BASIS_FULL, BASIS_PARTIAL, BASIS_PREVIEW, BASIS_STATIC_ONLY):
        assert f'"{value}"' in declared.group(1), value


def test_both_free_bases_withhold_the_score_on_the_page():
    """The page's `scored` predicate must exclude exactly what the report's
    does -- app/report/html.py has excluded both since preview existed."""
    scored = _PAGE_TSX.read_text().split("const scored =")[1].split(";")[0]

    assert '"static_only"' in scored
    assert '"static+preview"' in scored
    # A cut-short full audit is not free and keeps its score.
    assert '"static+partial"' not in scored


def test_a_partly_checked_category_is_not_given_a_band():
    """Deploy and Testing are decided by asking whether a file exists. Drawing
    that as a full green "nothing serious found" is the claim `partial`
    exists to prevent -- and banding made it worse, because a sentence
    asserts where 10.0 merely invited doubt."""
    bars = _SCORE_RING_TSX.read_text().split("export function CategoryBars")[1]

    assert "partly checked" in bars
    assert re.search(r"const partial = !scored && !skipped\.has\(name\)", bars)


def test_the_cap_paragraph_is_withheld_where_there_is_no_score():
    """It explains a headline number. A free page has none, so it opened
    "This score is capped..." under a header saying there is no score."""
    bars = _SCORE_RING_TSX.read_text().split("export function CategoryBars")[1]

    assert re.search(r"\{scored && <GateNote", bars), (
        "the cap paragraph renders regardless of whether a score was published")


def test_the_total_keeps_its_number_on_the_page():
    """Coarsening the headline too would throw away precision the engine does
    have: the same three byte-identical runs moved it 4.1 / 4.0 / 4.1. Without
    this, deleting every toFixed in the file passes the tests above.

    Matched on the RENDERED span, not anywhere in the component. The first
    version of this test asked whether "total.toFixed(1)" appeared at all, and
    a mutation that replaced the visible digits with Math.round(total) survived
    it -- the string was still there in the aria-label above. A number a screen
    reader is told and the page does not show is not the page keeping its
    number.
    """
    ring = _SCORE_RING_TSX.read_text().split("export function ScoreRing")[1]
    ring = ring.split("function GateNote")[0]

    assert re.search(r'tabular-nums">\s*\{total\.toFixed\(1\)\}', ring), (
        "the headline score is not rendered as a one-decimal number")

    # And the screen reader is told the same score the page shows. Found by a
    # mutation that missed: "{total.toFixed(1)}" is a substring of the label's
    # "${total.toFixed(1)}", so a blind replace rewrote the aria-label and left
    # the digits alone -- which nothing here noticed. A page that shows 3.7 and
    # announces "4" is two answers to one question.
    assert "aria-label={`Production readiness score ${total.toFixed(1)}" in ring
