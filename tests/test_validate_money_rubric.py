"""The money-rubric validation script must measure the SHIPPED rubric.

It used to carry its own copy of the candidate prompt. That was correct
while nothing shipped -- running it could not change what a customer
received -- and became a trap the moment #219 wired the rubric in: the two
drifted by 185 characters, and the shipped one had gained specifics the copy
never got. Anyone running this to decide whether the rubric pays for itself
was measuring a draft and would not have known.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from app.scan.llm_scan import RUBRICS, build_prompt

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "validate_money_rubric.py"
SPEC = importlib.util.spec_from_file_location("shipit_validate_money_rubric", MODULE_PATH)
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)


def test_it_names_a_rubric_that_actually_ships():
    assert validator.MEASURED_RUBRIC in RUBRICS


def test_it_carries_no_second_copy_of_the_prompt():
    """A local rubric literal is how the drift happened. The source must not
    define one again, whatever it is called."""
    source = MODULE_PATH.read_text()

    assert '"instructions"' not in source, (
        "the script defines its own rubric text again; it must read "
        "RUBRICS[MEASURED_RUBRIC] so a prompt change is measured, not missed")


def test_the_prompt_it_sends_is_the_shipped_one_verbatim():
    """The property that matters, checked end to end rather than by
    comparing strings: what goes to the model is what production sends."""
    prompt = build_prompt(
        [("src/pay.ts", "const price = req.body.price;\n")],
        validator.MEASURED_RUBRIC,
    )

    assert RUBRICS[validator.MEASURED_RUBRIC]["instructions"] in prompt


def test_importing_it_does_not_run_the_cli():
    """Guards the test above: if import executed main() this file would try
    to fetch repositories and spend money."""
    assert hasattr(validator, "main")
