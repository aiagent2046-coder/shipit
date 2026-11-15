#!/usr/bin/env python3
"""Run the escape hunt on a fixed, deterministic sample with two models.

Compares gpt-oss:20b against the current local default (qwen2.5-coder:7b-16k)
on the SAME corpus cases, so the numbers answer one question: does the 20B MoE
produce better-scoring variations than the 7B, and at what wall-clock cost.

Sample = every ceil(229/30)-th positive case, same order as discover_cases(),
so both models see identical bytes and a rerun reproduces the same sample.
"""
from __future__ import annotations

import json
import math
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import model_client  # noqa: E402
from tests.detectors.conftest import discover_cases  # noqa: E402

# Sibling harness, imported by module name because scripts/ is on sys.path.
# Loading it via importlib.util without registering in sys.modules breaks its
# @dataclass decorators (dataclasses looks the module up in sys.modules).
import hunt_detector_escapes as _hunt  # noqa: E402

MODELS = ["gpt-oss:20b", "qwen2.5-coder:7b-16k"]
VARIATIONS = 4
OUT = Path("/tmp/hunt_compare.json")

cases = [(rule, path) for rule, polarity, path in discover_cases()
         if polarity == "positive"]
stride = max(1, math.ceil(len(cases) / 30))
sample = cases[::stride]
print(f"corpus {len(cases)} positive cases, stride {stride} -> sample {len(sample)}",
      flush=True)

results = {m: [] for m in MODELS}
for model in MODELS:
    ok, msg = model_client.preflight(model)
    print(f"[{model}] preflight: {msg}", flush=True)
    if not ok:
        print(f"[{model}] PREFLIGHT FAILED, skipping", flush=True)
        continue
    for i, (rule, path) in enumerate(sample, 1):
        t0 = time.time()
        r = _hunt.hunt(rule, path, model, VARIATIONS)
        line = {"rule": rule, "case": path.name, "caught": r.caught,
                "candidates": len(r.escapes), "uncompilable": r.uncompilable,
                "placeholder_violations": r.invented_placeholders,
                "skipped": r.skipped, "seconds": round(time.time() - t0, 1)}
        results[model].append(line)
        print(f"[{model}] {i}/{len(sample)} {rule}/{path.name}: {line}", flush=True)
        OUT.write_text(json.dumps(results, indent=2))
    print(f"[{model}] usage: {model_client.usage_line()}", flush=True)

summary = {}
for m, rows in results.items():
    scored = [r for r in rows if not r["skipped"]]
    total = sum(r["caught"] + r["candidates"] for r in scored)
    summary[m] = {
        "cases_scored": len(scored),
        "variations_scored": total,
        "caught": sum(r["caught"] for r in scored),
        "candidates": sum(r["candidates"] for r in scored),
        "escape_rate": round(sum(r["candidates"] for r in scored) / total, 4) if total else None,
        "uncompilable": sum(r["uncompilable"] for r in scored),
        "placeholder_violations": sum(r["placeholder_violations"] for r in scored),
        "wall_seconds": round(sum(r["seconds"] for r in scored), 1),
    }
OUT.write_text(json.dumps({"summary": summary, "detail": results}, indent=2))
print("\nSUMMARY\n" + json.dumps(summary, indent=2), flush=True)
