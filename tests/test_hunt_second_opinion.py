"""The second opinion is a ranking aid -- its offline half must be exact.

The tier-1 triage bins mechanical noise; tier-3 asks a local model one question
per surviving body: is the rule's defect still there, as the rule itself defines
it? Measured on the 2026-09-14 round, 27 review bodies held 3 real gaps, and the
point of this stage is the ORDER they get read in. What the tests pin, without
any model:

  * the prompt carries the rule's own capability title (the judge must not
    invent its own definition of the defect) and a fixed verdict vocabulary;
  * the parser tolerates the formatting habits models actually have --
    lowercase, fences, an essay before the verdict -- and refuses to guess:
    no VERDICT line means unsure, never likely-noise;
  * the review bucket is derived by the same triage classification, so a
    noise body never reaches the judge at all;
  * a judge that says nothing readable lands its body in unsure, where a
    human reads it next.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))


def load_module(name: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


TRIAGE = load_module("triage_hunt_escapes")
OPINION = load_module("hunt_second_opinion")


def test_the_prompt_carries_the_rules_own_definition():
    prompt = OPINION.build_prompt("insecure-randomness", "const token = Math.random();\n")
    # The rule's own capability title is the judge's definition of the defect.
    from app.capabilities import CAPABILITIES
    titles = {rule_id: cap.title for cap in CAPABILITIES for rule_id in cap.rule_ids}
    assert titles["insecure-randomness"] in prompt
    assert "insecure-randomness" in prompt
    assert "const token = Math.random();" in prompt
    assert "VERDICT" in prompt
    assert "BROKEN" in prompt and "UNSURE" in prompt


def test_an_unknown_rule_still_gets_a_prompt():
    prompt = OPINION.build_prompt("a-future-rule", "x = 1\n")
    assert "an unspecified security defect" in prompt


@pytest.mark.parametrize("response, expected", [
    ("VERDICT: VULNERABLE\nThe draw reaches a secret-named value.", "likely-real"),
    ("VERDICT: NOT-VULNERABLE\nThe target was renamed.", "likely-noise"),
    ("verdict: not-vulnerable\nlowercase happens", "likely-noise"),
    ("VERDICT: NOT VULNERABLE\nspace variant", "likely-noise"),
    ("```\nVERDICT: VULNERABLE\n```\nfenced", "likely-real"),
    ("I looked carefully.\nVERDICT: BROKEN\nmissing import", "unsure"),
    ("VERDICT: UNSURE\nambiguous", "unsure"),
    ("No verdict line at all, just an essay about the code.", "unsure"),
    ("", "unsure"),
])
def test_parse_verdict_tolerates_formatting_and_refuses_to_guess(response, expected):
    assert OPINION.parse_verdict(response) == expected


def test_the_first_sentence_after_the_verdict_is_the_reason():
    response = "VERDICT: VULNERABLE\nThe spread flattens to the same draw."
    assert OPINION._first_sentence(response) == "The spread flattens to the same draw."


def test_noise_never_reaches_the_judge(tmp_path):
    dump = tmp_path / "dump"
    dump.mkdir()
    (dump / "insecure-randomness__aa__secure.py").write_text(
        "import secrets\nreset_token = secrets.token_hex(16)\n")
    (dump / "insecure-randomness__bb__real.js").write_text(
        "const [token] = [Math.random().toString(36)];\n")
    bodies = OPINION.review_bodies([dump])
    assert [path.name for _, path, _, _ in bodies] == ["insecure-randomness__bb__real.js"]


def test_second_opinion_ranks_by_judged_verdict(tmp_path):
    dump = tmp_path / "dump"
    dump.mkdir()
    (dump / "insecure-randomness__aa__real.js").write_text(
        "const [token] = [Math.random().toString(36)];\n")
    (dump / "insecure-randomness__bb__closure.js").write_text(
        "const makeSecureToken = function () {\n"
        "  return () => Math.random();\n};\nconst resetToken = makeSecureToken();\n")
    seen = []

    def fake_judge(prompt, model):
        seen.append(prompt)
        if "makeSecureToken" in prompt:
            return "VERDICT: NOT-VULNERABLE\nThe assigned value is a closure, not a draw."
        return "VERDICT: VULNERABLE\nThe destructure binds the draw into a secret name."

    buckets = OPINION.second_opinion([dump], "fake-model", judge_fn=fake_judge)
    assert len(seen) == 2
    assert len(buckets["likely-real"]) == 1
    assert len(buckets["likely-noise"]) == 1
    assert buckets["likely-noise"][0][2] == "The assigned value is a closure, not a draw."


def test_an_unreadable_judge_answer_lands_in_unsure(tmp_path):
    dump = tmp_path / "dump"
    dump.mkdir()
    (dump / "insecure-randomness__aa__real.js").write_text(
        "const [token] = [Math.random().toString(36)];\n")

    def broken_judge(prompt, model):
        return "I refuse to answer in your format."

    buckets = OPINION.second_opinion([dump], "fake-model", judge_fn=broken_judge)
    assert len(buckets["unsure"]) == 1
    assert buckets["likely-real"] == []