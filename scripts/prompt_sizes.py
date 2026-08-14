#!/usr/bin/env python3
"""How many bytes each rubric actually sends, and how many the provider read.

    scripts/prompt_sizes.py --repo tscircuit/tscircuit.com
    scripts/prompt_sizes.py --repo owner/name --compare /tmp/model_comparison.json

Costs nothing: it builds the prompts and measures them. No LLM is called.

WHY THIS EXISTS.

A two-model comparison on tscircuit.com reported 1,256K input tokens for
Sonnet and 330K for Haiku -- 3.8x apart on prompts that are IDENTICAL. They
have to be identical: select_files and build_prompt take a rubric and a file
list and know nothing about the model, and both runs read the same archive
bytes on purpose.

So one of three things is true, and the difference matters:

  * the provider truncated the input for one model and billed what it kept,
    in which case that model reviewed a quarter of the repository and its
    score is a statement about a quarter of the repository;
  * the provider counts input tokens differently per model, in which case
    the cost comparison is wrong and the finding comparison is fine;
  * we are wrong about the prompts being identical.

Nothing in the pipeline can currently tell these apart, because the size of
what we SEND is never recorded -- only what the provider says it received.
This script records the missing half.

READING THE OUTPUT.

The number to look at is chars/token. English runs ~4 chars per token and
code runs lower, roughly 2.5-3.5, so a healthy row lands near 3. A row at 12
means the provider read about a quarter of what was sent. The ratio is
derived from our own byte count, so it does not depend on trusting the
provider's accounting -- which is the thing in question.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scan.llm_scan import (  # noqa: E402
    ALL_RUBRICS, SYSTEM_PROMPT, _iter_code_files, build_prompt, select_files,
)


def fetch(slug: str, branch: str) -> bytes:
    url = f"https://codeload.github.com/{slug}/zip/refs/heads/{branch}"
    with urllib.request.urlopen(url, timeout=300) as resp:
        return resp.read()


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", required=True, help="owner/name[@branch]")
    ap.add_argument("--compare", default=None,
                    help="a compare_models.py --json file to line this up with")
    args = ap.parse_args(argv)

    slug, _, branch = args.repo.partition("@")
    raw = fetch(slug, branch or "main")
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        files = _iter_code_files(zf)
    print(f"{slug}  {len(raw)/1e6:.1f} MB zip  {len(files)} code files\n")

    print(f"{'rubric':10s}{'files':>7}{'chars':>12}{'~tokens at 3.0':>17}")
    sizes: dict[str, int] = {}
    for rubric in ALL_RUBRICS:
        selected = select_files(files, rubric)
        if not selected:
            # A rubric with no matching files sends no prompt at all. That is
            # a real difference between repositories and the reason a preview
            # can cost nothing on a repo its one rubric does not match.
            print(f"{rubric:10s}{0:>7}{'-- no prompt sent --':>29}")
            continue
        sizes[rubric] = len(SYSTEM_PROMPT) + len(build_prompt(selected, rubric))
        print(f"{rubric:10s}{len(selected):>7}{sizes[rubric]:>12,}"
              f"{sizes[rubric]/3000:>16.0f}K")
    total = sum(sizes.values())
    print(f"{'TOTAL':10s}{len(sizes):>7} prompts{total:>12,}"
          f"{total/3000:>16.0f}K")

    if not args.compare:
        return 0

    data = json.loads(Path(args.compare).read_text())
    per = data.get(slug)
    if not per:
        print(f"\n{slug} is not in {args.compare} "
              f"(it has: {', '.join(sorted(data)) or 'nothing'})", file=sys.stderr)
        return 1

    print(f"\n{'model':22s}{'prompts':>9}{'in tokens':>12}{'chars/token':>14}"
          f"{'read':>8}")
    for model, row in sorted(per.items()):
        got = row.get("input_tokens") or 0
        made = row.get("prompts") or 0
        # Our byte count covers one prompt per rubric that selected files. A
        # run that made fewer -- a cost cap cutting it short -- sent less than
        # that, and charging it the full total would blame the provider for a
        # call we never made. Scaling by prompt COUNT assumes the missing
        # prompts were average size, which they need not be, so the row is
        # marked rather than quietly adjusted.
        approx = made and made != len(sizes)
        sent = total * made / len(sizes) if approx else total
        ratio = sent / got if got else 0.0
        flag = "  <-- ?" if ratio > 5 else ""
        print(f"{model:22s}{made:>9}{got/1000:>11.0f}K{ratio:>14.1f}"
              f"{flag}{'  (approx: fewer prompts)' if approx else ''}")
    print("\nchars/token near 3 = the provider read what we sent. Much higher "
          "= it did not, and that model's findings and score describe only the "
          "part it read.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
