"""README for the hunt triage pipeline: hunt -> triage -> second opinion.

Three stages, one queue. Each stage removes what the previous one cannot,
and the last body a human reads is the one only a human can judge.

    scripts/hunt_detector_escapes.py --dump DIR   (tier 0: generate)
    scripts/triage_hunt_escapes.py --dump DIR      (tier 1: deterministic)
    scripts/hunt_second_opinion.py --dump DIR      (tier 3: LLM ranking)

Measured on 2026-09-14 (75 candidates, 3 real gaps, full ground truth):

  stage        | in  | out | removed        | how
  -------------|-----|-----|----------------|---------------------------------
  hunt         |  82 |  75 |  7 (scanner    | generation + silence counting
  (tier 0)     |     |     |   fired)       |
  triage       |  75 |  27 | 48 (mechanical:| parse check, missing import,
  (tier 1)     |     |     |   marker,      | marker regex, target regex
               |     |     |   target)      |
  second       |  27 |  18 |  8 (scope      | qwen3:8b judge with the rule's
  opinion      |     |     |   violations   | scope text as the definition
  (tier 3)     |     |     |   + closures)  |
  human        |  18 |   3 | 15 (by-design  | reading the body + reason
               |     |     |   silences)   | sentence

TIER 3 DETAILS (the honest numbers)

qwen3:8b (thinking enabled, max_tokens 2048) judged 27 review bodies:
- 8 correctly binned as likely-noise: 4 TypeScript evasions of a Python-only
  rule (scope says Python), 2 closure factories (scope says deferred bodies
  are unresolved), 2 non-invocation/non-secret patterns
- 18 ranked likely-real; the 2-3 true gaps are among them, but so are ~15
  by-design silences the model cannot distinguish at 8B size
- 1 unsure (thinking consumed all tokens, answer empty)

A repeat run of the same 27 bodies and model moved three by-design
silences across the real/noise boundary (18/8/1 -> 17/9/1); every real
gap stayed in likely-real and the unsure body was the same both times.
The buckets are a reading order, not a set membership.

The model-size finding: 7-8B local models cannot reliably read a rule's
scope text and check multiple conditions (secret-named target AND Math.random
AND no shadowing AND no helper wrapping AND not a deferred body). They see
"Math.random" in both the scope and the code and vote VULNERABLE. qwen3:8b
with thinking + 2048 tokens makes the EASY scope calls (wrong language,
obvious closure, no invocation) but not the nuanced ones. A 14B+ model
would improve the split; the tool architecture is ready for it.

TIER 2 is not in this pipeline table because it is wired into the pytest
gate (tests/test_fuzz_corpus_positives.py), not run on hunt dumps.
"""