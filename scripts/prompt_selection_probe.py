#!/usr/bin/env python3
"""What does a rubric prompt ACTUALLY contain at a 32K local window?

No LLM. Replicates the selection path (select_files + content_budget +
fit_to_window) with input_char_budget pinned to the 32K declaration, and
prints per rubric: which files were selected, how many chars of CODE made it,
and whether the package's core source is among them.

Answer to: why did the 32K falsifier return empty_responses=4 while holding
20.5K tokens of prompt -- what were those tokens?
"""
from __future__ import annotations

import io
import sys
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scan.llm_scan import (  # noqa: E402
    ALL_RUBRICS, SYSTEM_PROMPT, _iter_code_files, content_budget, fit_to_window, select_files,
)

URL = "https://codeload.github.com/NandhaKishorM/laya/zip/refs/heads/main"
WINDOW_CHARS = (32_768 - 8_192) * 3  # 73,728 -- what falsify_32k declared


class FakeClient:
    """Declares the 32K window so content_budget sees what the local run saw."""
    def input_char_budget(self) -> int:
        return WINDOW_CHARS


def main() -> int:
    raw = urllib.request.urlopen(URL, timeout=300).read()
    files = list(_iter_code_files(zipfile.ZipFile(io.BytesIO(raw))))
    budget = content_budget(FakeClient())
    print(f"window chars: {WINDOW_CHARS:,}  content_budget: {budget:,}  "
          f"system: {len(SYSTEM_PROMPT):,}")
    print(f"code files: {len(files)}")

    # The package dir, not a bare prefix: zip members are rooted at
    # "laya-main/", so startswith("laya/") never matched anything and an
    # earlier version of this probe reported 0 core files even when
    # agent.py was in the selection.
    for rubric in ALL_RUBRICS:
        selected = select_files(files, rubric, budget)
        total_chars = sum(len(t) for _, t in selected)
        fitted, prompt = fit_to_window(selected, rubric, WINDOW_CHARS - len(SYSTEM_PROMPT))
        fitted_core = [n for n, _ in fitted
                       if "/laya/" in n and "/laya-ts/" not in n]
        fitted_tests = [n for n, _ in fitted
                        if "/tests/" in n or "/test_" in n]
        fitted_config = [n for n, _ in fitted
                         if n.endswith((".yml", ".yaml", ".json", ".toml"))]
        code_chars = sum(len(t) for _, t in fitted)
        print(f"\n=== {rubric} ===")
        print(f"  selected: {len(selected)} files, {total_chars:,} chars "
              f"-> fitted: {len(fitted)} files, {code_chars:,} chars "
              f"(prompt {len(prompt):,})")
        print(f"  core(laya/): {len(fitted_core)}  tests: {len(fitted_tests)}  "
              f"config(yml/json/toml): {len(fitted_config)}")
        for n, _ in fitted:
            print(f"    {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
