"""The web-rubric candidate must stay a candidate until it ships.

The mirror image of tests/test_validate_money_rubric.py, at the earlier point
in the same lifecycle. That script carried its own copy of the prompt while
nothing shipped -- correct, because running it could not change what a
customer received -- and the copy became a trap the moment #219 wired the
rubric in: the two drifted by 185 characters and anyone measuring was
measuring a draft.

So this file guards both ends of the same rule:

  * while the rubric is NOT in RUBRICS, the script must hold its own text,
    and must not be able to reach production by accident;
  * the moment it IS in RUBRICS, the local copy must be gone.

The second assertion is the one that will fire one day, at exactly the commit
that ships the rubric, which is when someone needs reminding.
"""

from __future__ import annotations

import importlib.util
import os
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


def test_the_candidate_is_not_wired_into_the_shipped_audit():
    """Importing the script injects the candidate into the RUBRICS dict so
    select_files can find it by key. That is fine for a measurement process
    and would not be fine for the API: this asserts the rubric is not in the
    source of truth, only in this process's copy of it.
    """
    shipped = Path(
        Path(__file__).resolve().parents[1] / "app" / "scan" / "llm_scan.py"
    ).read_text()

    assert '"web": {' not in shipped, (
        "the web rubric now ships; delete CANDIDATE from "
        "scripts/validate_web_rubric.py and read RUBRICS['web'] instead, or "
        "the script will measure a draft the customer never receives -- see "
        "tests/test_validate_money_rubric.py for how that went last time"
    )


def test_the_candidate_looks_for_the_frontend():
    """The reason path weighting became per-rubric. Under BEHAVIOUR this
    rubric would be shown ui/ and components/ divided by four -- everything
    except its own subject."""
    assert validator.CANDIDATE["lives_in"] == PRESENTATION


def test_the_candidate_excludes_what_other_rubrics_already_cover():
    """A duplicate finding spends a slot twice. The server half of a double
    submit belongs to money; only the browser half belongs here."""
    instructions = validator.CANDIDATE["instructions"]

    assert "Do NOT report server-side issues" in instructions
    assert "idempotency key" in instructions


def test_the_candidate_refuses_a_double_submit_claim_without_the_mapping():
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
    instructions = validator.CANDIDATE["instructions"]

    assert "QUOTE the line" in instructions
    assert "disabled={props.disabled || loading}" in instructions
    assert "confidence 0.5 or lower" in instructions


def test_the_candidate_names_the_guards_that_close_the_race():
    """Four false findings quoted the guard that refuted them and argued past
    it anyway -- a synchronous ref set before the first await, an early
    `if (isSubmitting) return` -- on the theory that a second click arrives
    before the re-render. It does not: updates from a discrete event are
    flushed before the next event is delivered.

    Naming the guards is what makes the rule checkable by the model. Without
    it, "quote the mapping" is satisfied by quoting the mapping and then
    reasoning around it, which is exactly what happened.
    """
    instructions = validator.CANDIDATE["instructions"]

    assert "before the first await" in instructions
    assert "if (isSubmitting) return" in instructions
    assert "argue past it" in instructions


def test_the_candidate_carries_the_evidence_rule():
    """Learned on the money rubric: without it, findings state inferences in
    the voice of things read, and one in three was simply wrong."""
    instructions = validator.CANDIDATE["instructions"]

    assert "PROVES the claim" in instructions
    assert "confidence 0.5 or lower" in instructions


def test_importing_the_script_adds_no_rubric_at_all():
    """The first version injected at import, and three unrelated tests failed
    once the whole suite ran in one process: the cost cap counted a fourth
    rubric, the prompt fingerprint moved, and the guard that every shipped
    rubric keeps the BEHAVIOUR weighting saw a PRESENTATION one.

    A measurement harness that quietly reweights the rubrics it is NOT
    measuring invalidates its own numbers. The mutation belongs in the process
    that is about to make LLM calls, and nowhere else.
    """
    assert validator.CANDIDATE_KEY not in RUBRICS

    for name in ("auth", "security", "money"):
        assert RUBRICS[name].get("lives_in", "behaviour") == "behaviour", name


def test_the_candidate_is_installed_when_the_script_actually_runs():
    """The other half: deferring the injection must not mean forgetting it."""
    try:
        validator.install_candidate()
        assert RUBRICS[validator.CANDIDATE_KEY] is validator.CANDIDATE
    finally:
        RUBRICS.pop(validator.CANDIDATE_KEY, None)


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

    try:
        validator.install_candidate()
        assert not validator.CANDIDATE["keywords"].search(files[0][1])
        assert files[0][0] not in {
            n for n, _ in validator.select_files(files, validator.CANDIDATE_KEY)
        }
        chosen = validator.select_with_primitives(
            files, validator.CANDIDATE_KEY
        )
    finally:
        RUBRICS.pop(validator.CANDIDATE_KEY, None)

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

    try:
        validator.install_candidate()
        chosen = validator.select_with_primitives(
            files, validator.CANDIDATE_KEY
        )
    finally:
        RUBRICS.pop(validator.CANDIDATE_KEY, None)

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

    try:
        assert validator.main() == 1
    finally:
        RUBRICS.pop(validator.CANDIDATE_KEY, None)

    assert "no LLM provider configured" in capsys.readouterr().err
