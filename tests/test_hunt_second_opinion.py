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
    human reads it next -- and a judge CALL that fails does the same
    without ending the run;
  * the preamble is never the verdict: only VERDICT lines that start their
    own line count, and conflicting ones are unsure (review round 1).
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
MODEL_CLIENT = load_module("model_client")


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
    # Review round 1: a preamble that RECITES the vocabulary must not be read
    # as a verdict, and two VERDICT lines that disagree are unsure.
    ("I will not use VERDICT: VULNERABLE in my answer.\nVERDICT: UNSURE\n", "unsure"),
    ("Preamble mentions VERDICT: VULNERABLE mid-line.\nVERDICT: UNSURE\n", "unsure"),
    ("VERDICT: VULNERABLE\nVERDICT: VULNERABLE\nrepeated is fine", "likely-real"),
    ("VERDICT: VULNERABLE\nVERDICT: NOT-VULNERABLE\ntorn", "unsure"),
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


def test_a_rule_without_a_triage_spec_reaches_the_judge_too(tmp_path):
    # Review round 1 (inherited from tier 1): "review (no spec)" is a review
    # bucket -- tier 1 prints it in the queue, so the judge must see it too.
    dump = tmp_path / "dump"
    dump.mkdir()
    (dump / "future-rule__aa__thing.js").write_text("const anything = whatever();\n")
    bodies = OPINION.review_bodies([dump])
    assert [path.name for _, path, _, _ in bodies] == ["future-rule__aa__thing.js"]


def test_a_failed_judge_call_bins_its_body_and_the_run_continues(tmp_path):
    # Review round 1: one failed call ended the whole run with no partial
    # result. 27 sequential local calls must tolerate a single failure.
    dump = tmp_path / "dump"
    dump.mkdir()
    (dump / "insecure-randomness__aa__real.js").write_text(
        "const [token] = [Math.random().toString(36)];\n")
    (dump / "insecure-randomness__bb__also.js").write_text(
        "const resetToken = Math.random().toString(36).slice(2);\n")

    def flaky_judge(prompt, model):
        if "resetToken" in prompt:
            raise RuntimeError("connection reset by peer")
        return "VERDICT: VULNERABLE\nThe destructure binds the draw."

    buckets = OPINION.second_opinion([dump], "fake-model", judge_fn=flaky_judge)
    assert len(buckets["likely-real"]) == 1
    assert len(buckets["unsure"]) == 1
    assert "judge call failed" in buckets["unsure"][0][2]


def test_the_cli_preflights_and_reports_the_model_it_was_told_to_use(
        monkeypatch, tmp_path, capsys):
    # Review round 1: the CLI defaults to qwen3:8b while preflight checked
    # HUNT_MODEL/qwen2.5-coder -- wrong attribution, and no existence check
    # for the --model value.
    dump = tmp_path / "dump"
    dump.mkdir()
    (dump / "insecure-randomness__aa__real.js").write_text(
        "const [token] = [Math.random().toString(36)];\n")
    seen = {}

    def fake_preflight(model=None):
        seen["preflight_model"] = model
        return True, "ok"

    def fake_second_opinion(dirs, model, limit=None, judge_fn=OPINION.judge):
        seen["judge_model"] = model
        return {"likely-real": [], "unsure": [], "likely-noise": []}

    monkeypatch.setattr(OPINION.model_client, "preflight", fake_preflight)
    monkeypatch.setattr(OPINION, "second_opinion", fake_second_opinion)
    monkeypatch.setattr(sys, "argv", ["hunt_second_opinion.py",
                                      "--dump", str(dump), "--model", "qwen3:8b"])
    assert OPINION.main() == 0
    assert seen == {"preflight_model": "qwen3:8b", "judge_model": "qwen3:8b"}
    out = capsys.readouterr().out
    assert "(judge: qwen3:8b)" in out


def test_model_availability_matches_exact_tags_and_family_prefixes():
    installed = {"qwen2.5-coder:7b", "qwen3:8b", "llama3.2:latest"}
    assert MODEL_CLIENT._model_available(installed, "qwen3:8b")
    assert MODEL_CLIENT._model_available(installed, "qwen3")       # family pull
    assert MODEL_CLIENT._model_available(installed, "llama3.2:latest")
    assert not MODEL_CLIENT._model_available(installed, "qwen9:99b")