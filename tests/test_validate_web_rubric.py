"""The web rubric shipped; the script must read it, never copy it.

The mirror image of tests/test_validate_money_rubric.py, one step further
along the same lifecycle. Both scripts carried their own copy of the prompt
while nothing shipped -- correct then, because running a measurement must not
change what a customer receives -- and validate_money_rubric.py's copy became
a trap the moment #219 wired that rubric in: the two drifted by 185 characters
and anyone measuring was measuring a draft.

So this file guarded both ends of one rule, and the second end has now fired:

  * while the rubric was NOT in RUBRICS, the script held its own text and
    could not reach production by accident;
  * now that it IS in RUBRICS, the local copy is gone and the script reads
    the shipped dict.

What remains here asserts the shipped prompt still carries every rule five
measured runs put into it, and that select_with_primitives -- which is NOT in
select_files -- stays a wrapper around the shipped selector rather than a
second implementation of it.
"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

from app.scan.llm_scan import PRESENTATION, RUBRICS

MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "validate_web_rubric.py"
)
SPEC = importlib.util.spec_from_file_location(
    "shipit_validate_web_rubric", MODULE_PATH
)
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)


def test_the_script_holds_no_copy_of_the_prompt_now_that_it_ships():
    """The assertion that fired at the commit that shipped the rubric, which
    is exactly when someone needed reminding.

    It used to read the other way: while `"web": {` was absent from llm_scan
    the script had to hold its own dict. Now that the rubric ships, the dict
    must be gone, or the script measures a draft the customer never receives
    -- see tests/test_validate_money_rubric.py for how that went last time.
    """
    shipped = (
        Path(__file__).resolve().parents[1] / "app" / "scan" / "llm_scan.py"
    ).read_text()
    script = MODULE_PATH.read_text()

    assert '"web": {' in shipped, "the web rubric is no longer in RUBRICS"

    assert "CANDIDATE = {" not in script, (
        "scripts/validate_web_rubric.py has grown a local copy of the prompt "
        "again; it must read RUBRICS['web'] so that what is measured is what "
        "production sends"
    )
    assert '"instructions": (' not in script


def test_the_rubric_looks_for_the_frontend():
    """The reason path weighting became per-rubric. Under BEHAVIOUR this
    rubric would be shown ui/ and components/ divided by four -- everything
    except its own subject."""
    assert RUBRICS["web"]["lives_in"] == PRESENTATION


def test_the_rubric_excludes_what_other_rubrics_already_cover():
    """A duplicate finding spends a slot twice. The server half of a double
    submit belongs to money; only the browser half belongs here."""
    instructions = RUBRICS["web"]["instructions"]

    assert "Do NOT report server-side issues" in instructions
    assert "idempotency key" in instructions


def test_the_rubric_refuses_a_double_submit_claim_without_the_mapping():
    """The one thing two measured runs agree is broken.

    Ten of dub's twelve findings in the second run were the same claim -- this
    button is not disabled while its request is in flight -- and all ten were
    refuted by packages/ui/src/button.tsx:114, `disabled={props.disabled ||
    loading}`, which was IN the prompt that run. Selection was fixed first, on
    the theory that the model could not see the file; it could, and the
    numbers did not move. So the rule has to be stated.

    Asserted on the two halves that carry the whole argument: that the mapping
    must be quoted, and that `loading` is named as a thing which may already
    imply `disabled`. A version that only says "check the button component" is
    what the evidence rule already said, and it did not work.
    """
    instructions = RUBRICS["web"]["instructions"]

    assert "QUOTE the line" in instructions
    assert "disabled={props.disabled || loading}" in instructions
    assert "confidence 0.5 or lower" in instructions


def test_the_rubric_treats_a_quoted_guard_as_the_end_of_the_matter():
    """The companion to the timing ban, and the half that makes it usable.

    A ban on one argument is only as good as the model's ability to tell when
    it has already won. Runs 3 and 4 both quoted the guard that refuted them
    and kept going, so the rule has to close the question explicitly: a flag
    or ref set anywhere before the first await guards the control, and once
    a guard is quoted there is nothing left to report.

    This assertion moved once already, when the paragraph it guards was
    rewritten from refuting the timing argument to forbidding it. It is
    pointed at the requirement -- a named guard, and an explicit end to the
    inquiry -- rather than at the sentence that carried it in run 3.
    """
    instructions = RUBRICS["web"]["instructions"]

    assert "before its first await" in instructions
    assert "the control is guarded and there is nothing to report" in instructions
    assert "Once you have quoted a guard, you are finished" in instructions


def test_the_rubric_forbids_reporting_a_check_that_came_back_clean():
    """What the third run cost, having fixed what the second run measured.

    Told to quote the props-to-disabled mapping, the model started quoting it
    and reaching the right answer every time -- and then reporting the right
    answer as a finding. Five of dub's six read like "[HIGH conf=0.9] Retry
    payment: double-submit correctly guarded via ref ... No action needed."

    Nothing in the rubric had ever said not to. Until that run it had never
    been correct often enough for the omission to show.
    """
    instructions = RUBRICS["web"]["instructions"]

    assert "report NOTHING" in instructions
    assert "no action needed" in instructions
    assert "Silence is the correct output" in instructions


def test_the_rubric_forbids_timing_as_a_ground_for_a_double_submit_finding():
    """The one conclusion four measured runs agree on.

    Split the double-submit findings by what they rest on. SYNTAX -- a
    `loading` prop the component never maps to `disabled`, a `handleRequest`
    called without `await` -- was right in every run it appeared in, and is
    where Pricing.tsx, CustomerPortalForm, NameForm, EmailForm and the three
    auth forms came from. TIMING -- a flag set 'too late', an update that
    'has not propagated', a click 'before the re-render' -- was wrong in every
    run, all four, including run 4, whose instructions refuted that argument
    in advance and whose dub findings quote button.tsx line 114, agree it
    disables the button, and argue past it anyway.

    Three rounds tried to correct the reasoning. This one removes it from the
    set of admissible grounds instead, which is the difference between
    debating a model and constraining it.
    """
    instructions = RUBRICS["web"]["instructions"]

    assert "TIMING IS NOT A GROUND" in instructions
    assert "There is exactly ONE ground for this finding" in instructions

    for banned in ("too late", "before the re-render", "has not propagated"):
        assert banned in instructions, banned

    # A disabled textarea takes no key events; that path is closed too.
    assert "disabled input or textarea" in instructions


def test_the_rubric_asks_six_closed_questions_and_says_so():
    """The narrowing, after four runs.

    Each question earned its place by producing a finding that survived
    hand-verification: the missing error boundary (4 of 4 runs), the flag
    cleared after an await with no finally, the dirty form with no
    beforeunload (3 of 4), the timer with no cleanup (4 of 4), the
    conditionally called hook (GroupChat:22 is a real crash), and the
    in-flight prop the component never maps to `disabled` (4 of 4, on the
    money path).

    The closed list is the point. What was cut -- racing fetches, optimistic
    updates that might diverge, a swallowed error behind a toast -- had four
    runs to prove itself and produced confident prose about correct code. A
    question the model cannot answer reliably does not come back empty; it
    comes back wrong, and the verifier cannot catch that because the quoted
    line really is there.
    """
    instructions = RUBRICS["web"]["instructions"]

    assert "Six questions, and only these six" in instructions
    assert "If it is not one of the six, it is not a finding" in instructions

    for number in ("1. ", "2. ", "3. ", "4. ", "5. ", "6. "):
        assert number in instructions, number


def test_the_rubric_requires_a_conditional_hook_to_actually_be_reachable():
    """Navlinks.tsx:16 and EmailSignIn.tsx:22, reported at 0.95 as crashes
    that would blank the page for every user. Both really do call useRouter()
    inside a ternary -- a genuine Rules-of-Hooks violation -- but the
    condition reads a build-time constant, so the hook order never changes
    between renders and nothing crashes. A lint violation, not a finding.

    GroupChat.tsx:22 is the one that counts: hooks after an early return on
    `personas`, which goes from empty to non-empty as the parent loads.
    """
    instructions = RUBRICS["web"]["instructions"]

    assert "the condition can differ between two renders" in instructions
    assert "build-time constant" in instructions


def test_the_digest_line_ignores_wording_and_confidence():
    """Two runs of the same rubric on the same input reword the same defect
    and wobble its confidence, which is what makes reading two transcripts
    side by side unreliable -- and reading them side by side is how three
    rounds of prompt work each found a signal in the spread.

    So the digest carries file, line and severity, and nothing that moves for
    reasons other than a different claim.
    """
    finding = {
        "file": "src/App.tsx",
        "line_start": 17,
        "severity": "high",
        "confidence": 0.9,
        "title": "No error boundary wrapping the route tree",
        "explanation": "reworded every single run",
    }
    line = validator.digest_line(finding)

    assert line.startswith("DIGEST ")
    assert "src/App.tsx:17" in line
    assert "HIGH" in line

    for volatile in ("0.9", "reworded", "wrapping"):
        assert volatile not in line, volatile

    # A confidence wobble on the same defect must not read as a difference.
    assert validator.digest_line({**finding, "confidence": 0.85}) == line
    assert validator.digest_line({**finding, "title": "Blank page"}) == line
    # A different claim must.
    assert validator.digest_line({**finding, "line_start": 18}) != line
    assert validator.digest_line({**finding, "severity": "critical"}) != line


def test_the_rubric_carries_the_evidence_rule():
    """Learned on the money rubric: without it, findings state inferences in
    the voice of things read, and one in three was simply wrong."""
    instructions = RUBRICS["web"]["instructions"]

    assert "PROVES the claim" in instructions
    assert "confidence 0.5 or lower" in instructions


def test_the_script_never_mutates_the_rubric_dict():
    """An earlier version injected its draft into RUBRICS -- first at import,
    which broke three unrelated tests the moment the suite ran in one process,
    then from main(). Now that the rubric ships there is nothing to inject,
    and a measurement harness that reweights the rubrics it is not measuring
    would invalidate its own numbers.
    """
    script = MODULE_PATH.read_text()

    # An assignment, not a mention: the docstring names RUBRICS["web"] on
    # purpose, and a test that forbade the word would forbid explaining
    # itself.
    assert not re.search(r"^\s*RUBRICS\s*\[", script, re.M), (
        "the script assigns into RUBRICS again"
    )
    assert "install_candidate" not in script

    for name in ("auth", "security", "money"):
        assert RUBRICS[name].get("lives_in", "behaviour") == "behaviour", name


def test_both_validation_scripts_put_the_repo_root_on_sys_path():
    """Python puts the SCRIPT's directory on sys.path, never the working
    directory, so `python scripts/validate_web_rubric.py` from the repo root
    cannot import app/ on its own.

    Asserted against the source, which is unusual and is the only thing that
    works here. The obvious test -- run the script in a subprocess with a
    clean environment and check it starts -- passes whether or not the line is
    present, because this repository is installed into the development venv as
    an editable package, so `app` resolves from site-packages no matter what
    sys.path[0] is. Removing the line and watching the suite stay green is how
    that was established.

    Two separate things therefore hid this: every invocation happened to carry
    `PYTHONPATH=.`, and every test run happened to have the editable install.
    It surfaced on the server, whose venv is a built release with neither, as
    a ModuleNotFoundError at line 92 of a script that had worked all week.

    Eleven sibling scripts under scripts/ carry the same line for the same
    reason; these two were the exceptions.
    """
    line = "sys.path.insert(0, str(Path(__file__).resolve().parent.parent))"
    root = Path(__file__).resolve().parents[1]

    for name in ("validate_web_rubric.py", "validate_money_rubric.py"):
        source = (root / "scripts" / name).read_text()
        first_app_import = source.index("\nfrom app.")

        assert line in source, (
            f"{name} relies on the caller passing PYTHONPATH=. -- it will "
            f"fail on any venv without an editable install of this package"
        )
        assert source.index(line) < first_app_import, (
            f"{name} inserts the repo root after it imports from app/"
        )


def test_both_validation_scripts_start_without_PYTHONPATH():
    """The weaker companion to the assertion above: it cannot prove the
    sys.path line is there, but it does prove nothing else at import time is
    broken. Run with no arguments both scripts refuse to do anything and print
    their own usage.

    The exit code is deliberately not asserted -- the two disagree (2 here, 1
    there via SystemExit(__doc__)) and that is not what this is about.
    """
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    root = Path(__file__).resolve().parents[1]

    for name in ("validate_web_rubric.py", "validate_money_rubric.py"):
        result = subprocess.run(
            [sys.executable, str(root / "scripts" / name)],
            cwd=root, env=environment, capture_output=True, text=True,
        )
        output = result.stdout + result.stderr

        assert "Traceback" not in output, f"{name}:\n{output[-800:]}"
        assert "earns a place in the audit" in output, (
            f"{name} never reached its own usage text:\n{output[-800:]}"
        )


def test_the_primitive_buffer_ignores_the_rubric_keywords():
    """The reason the buffer exists rather than a relevance boost.

    On digital-rolecraft, tooltip.tsx, popover.tsx and form.tsx match not one
    of the rubric's keywords, so no amount of reweighting reaches them -- they
    are not in the ranking to be reweighted. All three decide whether a
    control is disabled, which is the question the rubric asks.
    """
    files = [("src/components/ui/tooltip.tsx", "export const Tooltip = 1\n")]

    assert not RUBRICS["auth"]["keywords"].search(files[0][1])

    assert not RUBRICS["web"]["keywords"].search(files[0][1])
    assert files[0][0] not in {
        n for n, _ in validator.select_files(files, validator.RUBRIC_KEY)
    }
    chosen = validator.select_with_primitives(files, validator.RUBRIC_KEY)

    assert [n for n, _ in chosen] == [files[0][0]]


def test_the_buffer_takes_primitives_not_the_components_named_after_them():
    """`(^|/)` anchors the word at the start of the basename. Without it
    retry-payment-modal.tsx and add-folder-form.tsx are 'primitives' too, and
    on dub the buffer would be spent on the twenty consumers rather than on
    the one file that answers the question about them."""
    primitive = validator._PRIMITIVE_NAME

    for name in (
        "packages/ui/src/button.tsx",
        "components/ui/Button/Button.tsx",
        "src/components/ui/textarea.tsx",
    ):
        assert primitive.search(name), name

    for name in (
        "apps/web/ui/modals/retry-payment-modal.tsx",
        "apps/web/ui/folders/add-folder-form.tsx",
        "apps/web/ui/modals/import-bitly-modal.tsx",
    ):
        assert not primitive.search(name), name

    # An icon that happens to be called checkbox.tsx is an SVG, not a control.
    assert validator._PRIMITIVE_NOISE.search(
        "packages/ui/src/icons/nucleo/checkbox.tsx"
    )


def test_the_buffer_cannot_eat_the_whole_prompt():
    """A repository that names three hundred files button.tsx must not turn
    the buffer into the answer. Measured spend on the largest of the three
    repositories is 105 KB; the cap is what keeps that a measurement rather
    than an assumption."""
    huge = "x" * 50_000
    files = [(f"ui/{i}/button.tsx", huge) for i in range(100)]

    chosen = validator.select_with_primitives(files, validator.RUBRIC_KEY)

    spent = sum(len(t) for _, t in chosen)
    assert spent <= validator.PRIMITIVE_BUDGET, spent


def test_the_buffer_leaves_the_shipped_selector_alone():
    """It wraps select_files; it must not reach inside it. If this ever fails,
    the change belongs in llm_scan with an AUDIT_ENGINE_VERSION bump, not
    here."""
    source = MODULE_PATH.read_text()

    assert "select_files(files, rubric)" in source
    assert "llm_scan.select_files =" not in source
    assert "monkeypatch" not in source


def test_main_reaches_the_llm_client_without_a_typo(monkeypatch, capsys):
    """The entry point was never exercised: the dry run called select_files
    directly, so `LLMClient.from_env()` -- a method that does not exist --
    survived review, the commit and the push, and failed on the operator's
    machine after a worktree and a fetch.

    This runs main() with no providers configured, which is the one path that
    reaches the constructor and returns before spending anything.
    """
    monkeypatch.setattr(sys, "argv", ["validate_web_rubric.py", "https://x/y/z"])
    monkeypatch.delenv("AITUNNEL_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    assert validator.main() == 1

    assert "no LLM provider configured" in capsys.readouterr().err
