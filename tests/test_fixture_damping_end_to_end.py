"""A model's finding in a colocated fixture, from the scan to the page (#345).

WHAT WAS UNJOINED. `damp_for_non_production_path` is tested directly, over a
parametrised list of paths, in tests/test_llm_scan.py. `compute_scores` is
tested against damped findings there too. NOTHING DROVE A REAL SCAN: no test
took a model finding anchored at a fixture, ran it through run_llm_scan and
run_scan, and then looked at the finished report. The seam between damping and
rendering -- context surviving the verifier, the dedup, the collapse, the
score assembly, and the renderer's decision about which table a finding lands
in -- was carried by production alone.

WHY THAT SEAM WENT UNWATCHED FOR SO LONG. #345 tried to observe it by
auditing external repositories, and five runs failed to produce a single
fixture finding, for three different reasons measured one at a time:

  * the repository had no tests at all (`vercel/nextjs-subscription-payments`);
  * it had tests with nothing credential-shaped in them (`ixartz/Next-js-
    Boilerplate`, `Blazity/next-enterprise`);
  * it had a credential in a test file, but the same VALUE also appeared in
    production code, so collapse_repeats grouped the two and reported them
    under the production anchor (`DayuanJiang/next-ai-draw-io`).

Each attempt cost a paid audit and produced no observation. This file makes
the case arrive on demand instead of waiting for a repository that happens to
produce it -- the same move tests/test_moved_category_end_to_end.py made for
#28, and for the same reason.

THE PATHS ARE COLOCATED, AND THAT IS THE POINT. `apps/web/tests/foo.test.ts`
is damped by the DIRECTORY rule (`tests` in _TEST_PATH_SEGMENTS), which
predates #344 -- which is why `dubinc/dub`'s damped section, the one external
run that produced one, proves nothing about #344. What #344 added was the
`.tsx`/`.jsx`/`.stories` SUFFIXES, and the only way to exercise those is a
fixture sitting next to the component it tests, with no test directory
anywhere in its path. That is the ordinary React layout, and it is what these
files use.

This does NOT close #345. That issue asks for the property to hold on
somebody else's code, and a fixture written here is ours again -- the weakest
possible sample, in #174's words. It closes the regression gap underneath it.
"""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from app.llm.client import LLMClient, LLMUsage, Provider
from app.report.html import render_report
from app.scan.pipeline import run_scan

PRODUCTION = "src/components/CardCheckout.tsx"
FIXTURE = "src/components/CardCheckout.test.tsx"
STORY = "src/components/CardCheckout.stories.tsx"

# Matches the web rubric's keywords so that rubric runs and these files are
# the ones it is shown. The `evidence` each finding quotes must appear in the
# real file or verify_finding discards it, so every source below contains the
# line its finding points at.
_COMPONENT = (
    "import { useState } from 'react'\n"
    "export function CardCheckout() {\n"
    "  const [isSubmitting, setIsSubmitting] = useState(false)\n"
    "  const onSubmit = async () => { await fetch('/api/pay') }\n"
    "  return <button disabled={isSubmitting} onClick={onSubmit} />\n"
    "}\n"
)
_FIXTURE_SRC = (
    "import { render } from '@testing-library/react'\n"
    "const STRIPE_TEST_KEY = 'sk_test_51NotARealKeyForTests00000000'\n"
    "it('renders', () => { render(<CardCheckout onClick={jest.fn()} />) })\n"
)
_STORY_SRC = (
    "export const Default = { args: { onClick: () => {} } }\n"
    "export const Loading = { args: { isSubmitting: true } }\n"
)

_EVIDENCE = {
    PRODUCTION: "await fetch('/api/pay')",
    FIXTURE: "const STRIPE_TEST_KEY = 'sk_test_51NotARealKeyForTests00000000'",
    STORY: "export const Loading = { args: { isSubmitting: true } }",
}


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(PRODUCTION, _COMPONENT)
        zf.writestr(FIXTURE, _FIXTURE_SRC)
        zf.writestr(STORY, _STORY_SRC)
    return buf.getvalue()


class ReportsInEveryFile(LLMClient):
    """A model that files one critical finding against each of the three
    paths, at full confidence. Identical severity on purpose: anything that
    differs between the three afterwards was done by the damping and not by
    the model."""

    def __init__(self):
        super().__init__(providers=[Provider("anthropic", "https://x", "k",
                                             "claude-sonnet-4.6")])

    def complete(self, system, user, max_tokens=4096):
        findings = [{
            "file": path,
            "line_start": 2, "line_end": 2,
            "evidence": _EVIDENCE[path],
            "severity": "critical", "confidence": 0.9,
            "title": f"Hardcoded payment credential in {path.rsplit('/', 1)[-1]}",
            "explanation": "A payment credential is written into the file.",
            "fix_hint": "Move it to an environment variable.",
            "category": "Security",
        } for path in (PRODUCTION, FIXTURE, STORY)]
        return json.dumps(findings), LLMUsage(
            model="claude-sonnet-4.6", input_tokens=1000, output_tokens=200)


@pytest.fixture(scope="module")
def scan() -> dict:
    return run_scan(_zip(), ReportsInEveryFile(), llm_rubrics=("web",))


def _by_file(scan: dict) -> dict[str, dict]:
    found = {}
    for f in scan["findings"]:
        if str(f.get("rule_id", "")).startswith("llm-"):
            found[str(f.get("file"))] = f
    return found


def test_all_three_findings_survive_the_pipeline(scan):
    """The precondition. Without it every assertion below could pass because
    the finding was dropped rather than damped -- which is the failure mode
    this whole file exists to distinguish from the healthy one."""
    found = _by_file(scan)

    assert set(found) == {PRODUCTION, FIXTURE, STORY}, (
        f"expected a finding in each of the three files, got {sorted(found)}")


def test_the_colocated_test_file_is_damped_and_says_why(scan):
    """The case #344 fixed, exercised through the pipeline. No `tests/`
    directory anywhere in this path, so only the `.test.tsx` SUFFIX can save
    it -- the directory rule that damped dub/dub's fixtures cannot."""
    finding = _by_file(scan)[FIXTURE]

    assert finding["severity"] == "medium"
    assert finding["context"] == "test_file"
    assert finding["confidence"] < 0.9


def test_the_colocated_story_is_damped_as_documentation(scan):
    """`.stories.tsx` is documentation context, not test context, and the two
    carry different confidence factors. Asserting the context STRING rather
    than merely 'something was set' is what keeps them distinguishable."""
    finding = _by_file(scan)[STORY]

    assert finding["severity"] == "medium"
    assert finding["context"] == "doc_example"


def test_the_component_beside_them_keeps_full_severity(scan):
    """THE CONTROL, and the half a damping change breaks quietly.

    All three findings arrived from the model as critical, in the same
    directory, in the same call. If this one is damped too, the damper is
    matching the directory rather than the file, and every real defect in
    src/components/ would be reported as a test fixture.
    """
    finding = _by_file(scan)[PRODUCTION]

    assert finding["severity"] == "critical"
    assert finding.get("context") is None
    assert finding["confidence"] == pytest.approx(0.9)


def test_the_fixtures_do_not_sink_the_security_score(scan):
    """Why the damping exists at all. Undamped, three criticals at 0.9 against
    a category budget of 10 take Security most of the way to zero; measured on
    this repository, seven were enough to reach exactly 0.0."""
    assert scan["score"]["categories"]["Security"] > 0.0


def test_the_page_puts_the_fixtures_under_their_own_heading(scan):
    """The seam no unit test covers: `context` surviving into score_json and
    the renderer reading it. A finding damped in the scan but rendered in the
    main table is damped where nobody looks and loud where everybody does."""
    html = render_report(scan)

    assert "In tests, examples and documentation" in html

    head, _, damped_section = html.partition(
        "In tests, examples and documentation")

    assert "CardCheckout.test.tsx" in damped_section
    assert "CardCheckout.stories.tsx" in damped_section
    # And the production one is above the fold, not filed away with them.
    assert "CardCheckout.tsx" in head
