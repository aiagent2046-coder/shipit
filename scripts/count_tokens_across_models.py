#!/usr/bin/env python3
"""Measure what a model change does to this scanner's token bill.

    scripts/count_tokens_across_models.py <repo-dir-or-slug> [model ...]

Why this exists rather than a published multiplier: Sonnet 5 uses the Opus
4.7/4.8 tokenizer, documented at roughly +30% tokens on the same text, and a
30% swing on the paid tier's cost is a pricing decision. "Roughly" is a
statement about English prose in general; this repository's prompts are
source code carrying line-number prefixes, XML file wrappers and a repo map,
and that mix is nothing like the corpus the figure was measured on. So the
number that should drive the decision is this one, taken on the real prompts.

It counts the ACTUAL prompts the scanner sends -- SYSTEM_PROMPT plus
build_prompt() per rubric, over the same select_files() budget -- so the
result is the audit's bill, not a sample's. Counting is free: the
count_tokens endpoint bills nothing and runs no inference.

Needs ANTHROPIC_API_KEY (the direct API; the OpenAI-compatible reseller has
no count_tokens endpoint). Prints per-rubric and total counts, the ratio
between models, and the resulting cost per audit at each model's table price.
"""

from __future__ import annotations

import io
import os
import sys
import zipfile
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.llm.pricing import cost_usd  # noqa: E402
from app.scan.llm_scan import (  # noqa: E402
    RUBRICS,
    SYSTEM_PROMPT,
    _iter_code_files,
    build_prompt,
    select_files,
)

COUNT_URL = "https://api.anthropic.com/v1/messages/count_tokens"
DEFAULT_MODELS = ["claude-sonnet-4-6", "claude-sonnet-5"]

# What one rubric answer costs us in output tokens, averaged over the measured
# runs (4 prompts, 4_314 output tokens). count_tokens prices the INPUT only --
# it cannot know what the model will write back -- so the output side has to
# come from a real run or the cost column would read low.
MEASURED_OUTPUT_TOKENS_PER_PROMPT = 1079


def pack(root: Path) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        for path in sorted(root.rglob("*")):
            if path.is_file() and ".git" not in path.parts:
                dst.write(path, path.relative_to(root).as_posix())
    return out.getvalue()


def count(model: str, system: str, user: str, key: str) -> int:
    resp = httpx.post(
        COUNT_URL,
        headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                 "content-type": "application/json"},
        json={"model": model, "system": system,
              "messages": [{"role": "user", "content": user}]},
        timeout=60.0,
    )
    resp.raise_for_status()
    return int(resp.json()["input_tokens"])


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        print("ANTHROPIC_API_KEY is not set — count_tokens is only on the "
              "direct Anthropic API.", file=sys.stderr)
        return 2

    root = Path(argv[0]).expanduser()
    if not root.is_dir():
        print(f"{root} is not a directory. Clone the repo first and pass its "
              "path — this script measures a tree on disk.", file=sys.stderr)
        return 2
    models = argv[1:] or DEFAULT_MODELS

    with zipfile.ZipFile(io.BytesIO(pack(root))) as zf:
        files = _iter_code_files(zf)

    prompts: list[tuple[str, str]] = []
    for rubric in RUBRICS:
        selected = select_files(files, rubric)
        if selected:
            prompts.append((rubric, build_prompt(selected, rubric)))
    if not prompts:
        print("no rubric matched any file — nothing to measure", file=sys.stderr)
        return 1

    print(f"{root}  {len(prompts)} prompts\n")
    header = f"{'rubric':16s}" + "".join(f"{m:>22s}" for m in models)
    print(header)
    print("-" * len(header))

    totals = dict.fromkeys(models, 0)
    for rubric, user in prompts:
        row = f"{rubric:16s}"
        for m in models:
            n = count(m, SYSTEM_PROMPT, user, key)
            totals[m] += n
            row += f"{n:>22,}"
        print(row)

    print("-" * len(header))
    print(f"{'input total':16s}" + "".join(f"{totals[m]:>22,}" for m in models))

    base = totals[models[0]]
    if base:
        print(f"{'vs first':16s}" + "".join(
            f"{totals[m] / base - 1:>+21.1%}" for m in models))

    out_tokens = MEASURED_OUTPUT_TOKENS_PER_PROMPT * len(prompts)
    print(f"\nper audit at table prices (output estimated at {out_tokens:,} "
          "tokens from measured runs):")
    for m in models:
        print(f"    {m:22s} ${cost_usd(m, totals[m], out_tokens):.2f}")
    print("\nA model absent from app/llm/pricing.py is priced at DEFAULT_PRICE "
          "(the dearest known row), so an unknown model reads high, not low.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
