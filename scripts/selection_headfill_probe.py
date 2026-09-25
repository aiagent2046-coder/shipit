#!/usr/bin/env python3
"""Hypothesis probe (RESULT: REJECTED): does head-filling rescue core files?

select_files' relevance pass `continue`s past a file that does not fit the
remaining reserve, so at a 32K window's ~34K reserve the first at-cap core
file overflows and every later core file is skipped; the breadth pass then
fills with the repo's smallest files (metadata.json, dependabot.yml).
Measured on laya: 0 core-package files per rubric at content_budget=57,260
vs 11-16 at 900,000.

This probe re-ran ONLY the selection logic (no prompt build, no LLM) with
one mutation: an overflowing relevance-pass file contributes a head slice of
the room remaining INSTEAD of being skipped whole.

RESULT: rejected in this naive form -- the first file by relevance ate the
whole reserve (rank 1 on laya is a 48K benchmark JSON), so core files still
lost. The shipped fix is the other side of the same coin: cap EVERY file at
reserve/RELEVANCE_RESERVE_FILES up front (select_files' file_cap), which
bounds any single file to a fair share instead of letting rank 1 take all.
Kept because it is the falsification record for why cap-per-file exists.

Run: .venv/bin/python scripts/selection_headfill_probe.py
"""
from __future__ import annotations

import io
import sys
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scan.llm_scan import (  # noqa: E402
    ALL_RUBRICS, BEHAVIOUR, MAX_FILE_CHARS, RELEVANCE_BUDGET_SHARE,
    _iter_code_files, content_budget, relevance, truncate_at_line, RUBRICS,
)

URL = "https://codeload.github.com/NandhaKishorM/laya/zip/refs/heads/main"
WINDOW_CHARS = (32_768 - 8_192) * 3


class FakeClient:
    def input_char_budget(self) -> int:
        return WINDOW_CHARS


def select_original(matched, budget, kw, lives_in):
    reserve = int(budget * RELEVANCE_BUDGET_SHARE)
    by_rel = sorted(matched, key=lambda x: (-relevance(x[0], x[1], kw, lives_in),
                                            len(x[1]), x[0]))
    selected, taken, total = [], set(), 0
    for n, t in by_rel:
        if total + len(t) > reserve:
            continue
        selected.append((n, t))
        taken.add(n)
        total += len(t)
    for n, t in sorted(matched, key=lambda x: (len(x[1]), x[0])):
        if n in taken or total + len(t) > budget:
            continue
        selected.append((n, t))
        taken.add(n)
        total += len(t)
    return selected


def select_headfill(matched, budget, kw, lives_in):
    """One change: an overflowing relevance file donates a head slice."""
    reserve = int(budget * RELEVANCE_BUDGET_SHARE)
    by_rel = sorted(matched, key=lambda x: (-relevance(x[0], x[1], kw, lives_in),
                                            len(x[1]), x[0]))
    selected, taken, total = [], set(), 0
    for n, t in by_rel:
        room = reserve - total
        if room <= 0:
            break
        if len(t) <= room:
            selected.append((n, t))
            taken.add(n)
            total += len(t)
        else:
            # head slice, line-aligned, with the same cut marker the product
            # already uses, so the model can tell it was cut
            sliced = truncate_at_line(t, room)
            selected.append((n, sliced))
            taken.add(n)
            total += len(sliced)
    for n, t in sorted(matched, key=lambda x: (len(x[1]), x[0])):
        if n in taken or total + len(t) > budget:
            continue
        selected.append((n, t))
        taken.add(n)
        total += len(t)
    return selected


def compose(sel):
    core = [n for n, _ in sel if "/laya/" in n and "/laya-ts/" not in n]
    tests = [n for n, _ in sel if "/tests/" in n or "/test_" in n]
    conf = [n for n, _ in sel if n.endswith((".yml", ".yaml", ".json", ".toml"))]
    return len(sel), len(core), len(tests), len(conf)


def main() -> int:
    raw = urllib.request.urlopen(URL, timeout=300).read()
    files = list(_iter_code_files(zipfile.ZipFile(io.BytesIO(raw))))
    budget = content_budget(FakeClient())
    print(f"content_budget (local 32K): {budget:,}; reserve: "
          f"{int(budget * RELEVANCE_BUDGET_SHARE):,}; files: {len(files)}")
    print(f"\n{'rubric':10s} {'variant':10s} {'files':>5} {'core':>4} "
          f"{'tests':>5} {'config':>6}")
    for rubric in ALL_RUBRICS:
        kw = RUBRICS[rubric]["keywords"]
        lives_in = RUBRICS[rubric].get("lives_in", BEHAVIOUR)
        matched = [(n, truncate_at_line(t, MAX_FILE_CHARS)) for n, t in files
                   if kw.search(n) or kw.search(t)]
        for label, fn in (("original", select_original), ("headfill", select_headfill)):
            f, c, t, cf = compose(fn(matched, budget, kw, lives_in))
            print(f"{rubric:10s} {label:10s} {f:5d} {c:4d} {t:5d} {cf:6d}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
