#!/usr/bin/env python3
"""Breakdown of one rubric prompt: what it is made of, in chars/tokens.

No LLM is called. Fetches laya, runs the static stage only to get
source_facts (the same facts_prompt the pipeline sends), then decomposes
each rubric's prompt into SYSTEM / instructions / repo_map / code /
gutter overhead / facts and prints capacity math for local windows.
"""
from __future__ import annotations

import io
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scan.llm_scan import (  # noqa: E402
    ALL_RUBRICS, RUBRICS, SYSTEM_PROMPT, _iter_code_files, build_prompt,
    select_files,
)
from app.scan.source_facts import facts_prompt  # noqa: E402

URL = "https://codeload.github.com/NandhaKishorM/laya/zip/refs/heads/main"


def main() -> int:
    raw = urllib.request.urlopen(URL, timeout=300).read()
    zf = zipfile.ZipFile(io.BytesIO(raw))
    files = list(_iter_code_files(zf))
    print(f"code files: {len(files)}")

    sys_len = len(SYSTEM_PROMPT)
    print(f"SYSTEM_PROMPT: {sys_len:,} chars (~{sys_len / 3000:.1f}K tok)")

    facts = ""
    t0 = time.time()
    try:
        from app.scan.pipeline import run_static_scan
        static = run_static_scan(io.BytesIO(raw))
        facts = facts_prompt(static.get("source_facts"), 16_000)
        print(f"static scan {time.time() - t0:.0f}s; facts_prompt "
              f"{len(facts):,} chars (~{len(facts) / 3000:.1f}K tok)")
    except Exception as exc:  # facts are optional context, not the subject
        print(f"facts unavailable: {type(exc).__name__}: {exc}")

    print()
    print(f"{'rubric':10s} {'files':>5} {'TOTAL':>10} {'~tok':>6} | "
          f"{'system':>7} {'instr':>6} {'map':>6} {'code':>8} {'gutter':>7} {'facts':>6}")
    rows = []
    for rubric in ALL_RUBRICS:
        selected = select_files(files, rubric)
        if not selected:
            print(f"{rubric:10s} no prompt")
            continue
        instr = f"Rubric: {RUBRICS[rubric]['instructions']}"
        tree = "\n".join(n for n, _ in selected)
        repomap = f"<repo_map>\n{tree}\n</repo_map>"
        code_raw = sum(len(t) for _, t in selected)
        fparts = []
        for n, t in selected:
            numbered = "\n".join(f"{i}\t{line}"
                                 for i, line in enumerate(t.splitlines(), start=1))
            fparts.append(f'<file path="{n}">\n{numbered}\n</file>')
        gutter = sum(len(p) for p in fparts) - code_raw
        total = len(SYSTEM_PROMPT) + len(build_prompt(selected, rubric, facts))
        rows.append(dict(rubric=rubric, n=len(selected), total=total,
                         sys=sys_len, instr=len(instr), map=len(repomap),
                         code=code_raw, gutter=gutter, facts=len(facts),
                         selected=selected))
        print(f"{rubric:10s} {len(selected):>5} {total:>10,} {total / 3000:>6.0f}K | "
              f"{sys_len:>7,} {len(instr):>6,} {len(repomap):>6,} "
              f"{code_raw:>8,} {gutter:>7,} {len(facts):>6,}")

    print()
    print("CAPACITY: what a local window holds (3.0 char/tok, 8192-tok response reserve)")
    for win in (8_000, 16_000, 32_000, 82_000):
        budget_chars = (win - 8192) * 3
        for r in rows:
            fixed = r["sys"] + r["instr"] + r["map"] + r["facts"]
            ratio = r["gutter"] / r["code"] if r["code"] else 0.0
            room = budget_chars - fixed
            fit_code = max(0.0, room / (1 + ratio))
            # files kept in selection order
            cum, kept = 0.0, 0
            for _, t in r["selected"]:
                if cum + len(t) > fit_code:
                    break
                cum += len(t)
                kept += 1
            print(f"  {win // 1000:>3}K tok ({budget_chars:>7,} chars) "
                  f"{r['rubric']:8s}: code room {fit_code:>8,.0f} of {r['code']:,} "
                  f"-> {kept}/{r['n']} files ({100 * kept / r['n']:.0f}%)")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
