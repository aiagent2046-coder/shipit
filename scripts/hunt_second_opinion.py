#!/usr/bin/env python3
"""A local second opinion on the triage REVIEW bucket -- a ranking, not an oracle.

WHY THIS EXISTS. Tier 1 (triage_hunt_escapes.py) mechanically bins three noise
classes; what survives still mixes real detector gaps with silences the rules
document on purpose (a closure factory hands the secret a function, a Python
helper draws one hop away, a custom wrapper hides the sink). Measured on
2026-09-14: 27 review bodies held 3 real gaps. Reading them in the order the
dump produced costs more attention than ranking them does.

This stage asks a LOCAL model -- default qwen3:8b, one size up from the hunt's generator
generator -- a single question per body: does this code still contain the
defect, as the rule itself defines it (the capability title is the definition,
so the judge is not inventing its own)? The verdict vocabulary is fixed, and
the parser reads only VERDICT lines that start their own line and agree with
each other. The output is three ranked buckets:

  likely-real    the judge says the defect is still there
  unsure         the judge answered nothing parseable
  likely-noise   the judge says the defect is gone

A human still reads all of it -- likely-real first. A judge verdict is never
recorded as a detector verdict, and nothing here runs in CI: the gate stays
LLM-free. The judge temperature is 0.2; the hunt's 0.9 is for diversity this
stage does not want.

USAGE: hunt_second_opinion.py --dump DIR [--dump DIR ...] [--model qwen3:8b]
                                [--max N]
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import model_client  # noqa: E402
from triage_hunt_escapes import _rule_and_file, classify, is_review  # noqa: E402

PROMPT_TEMPLATE = """A static security scanner was tested with a code sample that contained a defect.
The sample was then rewritten many times, and the scanner stayed silent on the
code below. Your job: decide whether that silence is a REAL DETECTOR GAP (the
code is within the rule's stated scope but the rule missed it) or whether the
code is OUTSIDE what the rule claims to detect.

The rule "{rule_id}" claims to detect: {title}
Its documented scope and limitations: {scope}

Judge strictly by what the scope above says the rule covers. If the code shape
is listed as unresolved/uncovered in the scope, it is NOT-VULNERABLE even if a
human would consider the code risky. If the code is within the scope but the
scanner still stayed silent, it is VULNERABLE. If the code would not run (an
import is missing, or it does not parse), answer BROKEN. If you cannot tell,
answer UNSURE.

Your answer must start with exactly one line of this form, nothing before it:
VERDICT: VULNERABLE
or VERDICT: NOT-VULNERABLE, BROKEN, UNSURE -- then one short sentence.

CODE:
{body}
"""

# Line-anchored on purpose: a model that first RECITES the vocabulary
# ("I will not use VERDICT: VULNERABLE...") must not have its preamble read
# as a verdict. Only a line that starts with the verdict counts, and every
# such line must agree (parse_verdict).
_VERDICT_RE = re.compile(
    r"^\s*VERDICT\s*:\s*(VULNERABLE|NOT[- ]VULNERABLE|NOTVULNERABLE|BROKEN|UNSURE)\s*$",
    re.IGNORECASE | re.MULTILINE)


def build_prompt(rule_id: str, body: str) -> str:
    from app.capabilities import CAPABILITIES
    title = "an unspecified security defect"
    scope = "no scope documented"
    for _capability in CAPABILITIES:
        if rule_id in _capability.rule_ids:
            title = _capability.title
            scope = _capability.scope
            break
    return PROMPT_TEMPLATE.format(rule_id=rule_id, title=title, scope=scope, body=body)


def parse_verdict(response: str) -> str:
    """Every line-anchored VERDICT line must agree; anything else is unsure.

    NOT-VULNERABLE is normalized before the bare VULNERABLE it contains is
    compared. Conflicting lines -- a preamble reciting one vocabulary word
    and a real answer carrying another -- are unsure: a body mis-bucketed is
    worse than a body a human reads twice.
    """
    verdicts = {match.group(1).upper().replace(" ", "").replace("-", "")
                for match in _VERDICT_RE.finditer(response)}
    if verdicts == {"NOTVULNERABLE"}:
        return "likely-noise"
    if verdicts == {"VULNERABLE"}:
        return "likely-real"
    return "unsure"


def review_bodies(dump_dirs: list[Path]) -> list[tuple[str, Path, str, str]]:
    """The triage REVIEW bucket: (rule_id, path, filename, body).

    Both review spellings count: a rule without a triage spec still reaches
    the judge -- tier 1 prints it in the queue, and dropping it here would
    drop it for the human too.
    """
    out = []
    for dump_dir in dump_dirs:
        for path in sorted(dump_dir.iterdir()):
            rule_and_file = _rule_and_file(path)
            if rule_and_file is None:
                continue
            rule_id, filename = rule_and_file
            body = path.read_text()
            if is_review(classify(rule_id, filename, body)):
                out.append((rule_id, path, filename, body))
    return out


def judge(prompt: str, model: str) -> str:
    """One model call; a low temperature because diversity is not wanted here."""
    # qwen3 spends thinking tokens before its answer; 512 truncates the answer.
    # 2048 leaves room for both on every local model tested.
    return model_client.generate(prompt, model=model, temperature=0.2, max_tokens=2048)


def second_opinion(dump_dirs: list[Path], model: str, limit: int | None = None,
                   judge_fn=judge) -> dict[str, list[tuple[str, Path, str]]]:
    """Run the judge over the REVIEW bucket and return ranked buckets.

    Returns {bucket: [(rule_id, path, one-line reason)]} where bucket is one of
    likely-real, unsure, likely-noise. Unparseable answers land in unsure --
    a judge that said nothing readable is a body a human reads next.
    """
    buckets: dict[str, list[tuple[str, Path, str]]] = {
        "likely-real": [], "unsure": [], "likely-noise": [],
    }
    bodies = review_bodies(dump_dirs)
    if limit is not None:
        bodies = bodies[:limit]
    for rule_id, path, _, body in bodies:
        # One failed call must not end the run: the body lands in unsure,
        # where a human reads it next, and the rest keep their verdicts.
        try:
            response = judge_fn(build_prompt(rule_id, body), model)
        except Exception as exc:
            buckets["unsure"].append((rule_id, path, f"(judge call failed: {exc})"))
            continue
        bucket = parse_verdict(response)
        reason = _first_sentence(response)
        buckets[bucket].append((rule_id, path, reason))
    return buckets


def _first_sentence(text: str) -> str:
    """The first non-verdict line after (or after stripping) the verdict.

    The verdict itself is formatting, not reasoning; the judge's sentence
    explaining it is what a reviewer wants beside the body.
    """
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    seen_verdict = False
    for line in lines:
        without = _VERDICT_RE.sub("", line).strip(" ,:-`*")
        if _VERDICT_RE.search(line):
            seen_verdict = True
            if without:
                return without[:160]
            continue
        if seen_verdict:
            return line[:160]
    return " ".join(lines)[:160] if lines else "(no answer)"


def _report(buckets: dict[str, list[tuple[str, Path, str]]], model: str) -> None:
    total = sum(len(entries) for entries in buckets.values())
    print(f"review bodies judged: {total} (judge: {model})")
    for bucket in ("likely-real", "unsure", "likely-noise"):
        entries = buckets[bucket]
        print(f"\n=== {bucket}: {len(entries)}")
        for rule_id, path, reason in entries:
            print(f"  {rule_id}: {path.name}")
            print(f"      {reason}")
    print(f"\n{model_client.usage_line()}")


def main() -> int:
    parser = argparse.ArgumentParser(description=( __doc__ or "").splitlines()[0])
    parser.add_argument("--dump", type=Path, action="append", required=True,
                        help="a directory the hunt wrote escape bodies to (repeatable)")
    parser.add_argument("--model", default="qwen3:8b",
                        help="judge model (default: qwen3:8b)")
    parser.add_argument("--max", type=int, default=None,
                        help="judge at most N review bodies (cost control)")
    args = parser.parse_args()
    dirs = []
    for dump_dir in args.dump:
        if not dump_dir.is_dir():
            parser.error(f"--dump {dump_dir} is not a directory")
        dirs.append(dump_dir)
    bodies = review_bodies(dirs)
    if not bodies:
        print("no review bodies: triage already binned everything, or the dump is empty")
        return 0
    ok, message = model_client.preflight(args.model)
    if not ok:
        print(message, file=sys.stderr)
        return 2
    _report(second_opinion(dirs, args.model, args.max), args.model)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())