#!/usr/bin/env python3
"""What LLM provider and model this environment will ACTUALLY use, checked.

Run this before a deploy and after changing any AITUNNEL_*/LLM_MODEL/FREE_TIER_*
setting. It answers the three questions an operator gets wrong:

  1. which providers the environment builds, in what order (the fallback chain);
  2. which model each stage will request -- the paid rubric stage and the free
     preview resolve through different variables;
  3. whether those model names exist at that provider.

The third question is the one that costs a production incident. Model names are
exact and the punctuation differs per provider: AITunnel lists `claude-haiku-4.5`
and `claude-sonnet-4.6` (dots) while this repository's code defaults spell them
with dashes. A deployment that leaves the preview model at its default answers
400 on every preview, and nothing else in the project says so at startup.

Read-only: it never stores, prints or logs a key, and `--probe` sends only an
eight-token request per model.

Usage:
    python3 scripts/verify_llm_provider.py                  # env from ./.env
    python3 scripts/verify_llm_provider.py --env /opt/shipit/.env --probe

Exit codes: 0 everything the environment names exists at its provider;
            1 a named model is missing, or no provider is configured at all;
            2 the provider could not be reached (network, auth, HTTP error).
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PROBE_MAX_TOKENS = 8
PROBE_TIMEOUT = 60


def load_env(path: pathlib.Path) -> list[str]:
    """Set names from an env file without overriding what the process already has.

    Returns the names it added, so a caller can print what came from where
    without ever touching a value.
    """
    added: list[str] = []
    if not path.exists():
        return added
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name, value = name.strip(), value.strip()
        if name and name not in os.environ:
            os.environ[name] = value
            added.append(name)
    return added


def providers() -> list:
    from app.llm.client import providers_from_env
    return providers_from_env()


def stage_models(chain: list) -> list[tuple[str, str, str]]:
    """(stage, provider kind, model) for every model this deployment will request."""
    from app.scan.pipeline import FREE_TIER_MODEL, FREE_TIER_MODEL_BY_KIND
    rows = [(f"paid ({provider.kind})", provider.kind, provider.model) for provider in chain]
    kinds = [provider.kind for provider in chain] or ["openai_compat"]
    for kind in kinds:
        rows.append((f"free preview ({kind})", kind,
                     FREE_TIER_MODEL_BY_KIND.get(kind, FREE_TIER_MODEL)))
    return rows


def fetch_model_ids(base_url: str, api_key: str) -> set[str]:
    request = urllib.request.Request(base_url.rstrip("/") + "/models",
                                     headers={"Authorization": "Bearer " + api_key})
    with urllib.request.urlopen(request, timeout=PROBE_TIMEOUT) as response:
        body = json.loads(response.read())
    return {entry.get("id") for entry in body.get("data", []) if entry.get("id")}


def probe_model(base_url: str, api_key: str, model: str) -> str:
    payload = {"model": model, "max_tokens": PROBE_MAX_TOKENS,
               "messages": [{"role": "user", "content": "ок"}]}
    request = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions", data=json.dumps(payload).encode(),
        headers={"Authorization": "Bearer " + api_key, "Content-Type": "application/json"})
    started = time.monotonic()
    with urllib.request.urlopen(request, timeout=PROBE_TIMEOUT) as response:
        body = json.loads(response.read())
    elapsed = time.monotonic() - started
    usage = body.get("usage", {}) or {}
    served = body.get("model")
    return (f"{elapsed:.1f}s, completion={usage.get('completion_tokens')}, "
            f"cost_rub={usage.get('cost_rub')}, balance={usage.get('balance')}, "
            f"served_as={served}")


def check(env_path: pathlib.Path, probe: bool = False) -> tuple[int, list[str]]:
    """Returns (exit code, report lines). No key material in the lines."""
    lines: list[str] = []
    added = load_env(env_path)
    lines.append(f"env file: {env_path} ({'найден' if env_path.exists() else 'НЕТ'}; "
                 f"из него взято {len(added)} переменных)")

    chain = providers()
    if not chain:
        lines.append("ПРОВАЛ: ни одного LLM-провайдера не настроено — аудиты будут "
                     "static-only. Нужны AITUNNEL_API_KEY + AITUNNEL_BASE_URL "
                     "(или ANTHROPIC_API_KEY).")
        return 1, lines

    lines.append(f"провайдеров в цепочке: {len(chain)} "
                 f"({'фолбэка нет — все запросы идут через первый' if len(chain) == 1 else 'есть фолбэк'})")
    for provider in chain:
        lines.append(f"  {provider.kind:<14} {provider.base_url:<32} model={provider.model} "
                     f"key={len(provider.api_key)} симв.")

    rows = stage_models(chain)
    lines.append("стадии:")
    for stage, _kind, model in rows:
        lines.append(f"  {stage:<22} -> {model}")

    failures: list[str] = []
    unreachable = False

    # one listing per provider, then one verdict per distinct model
    by_kind: dict[str, list[str]] = {}
    for _stage, kind, model in rows:
        by_kind.setdefault(kind, [])
        if model not in by_kind[kind]:
            by_kind[kind].append(model)

    for provider in chain:
        models = by_kind.get(provider.kind, [])
        try:
            available = fetch_model_ids(provider.base_url, provider.api_key)
        except Exception as exc:                                  # noqa: BLE001
            unreachable = True
            lines.append(f"  {provider.kind}: список моделей недоступен — "
                         f"{type(exc).__name__}: {str(exc)[:120]}")
            continue
        lines.append(f"  {provider.kind}: провайдер отдаёт {len(available)} моделей")
        for model in models:
            if model in available:
                lines.append(f"    ЕСТЬ   {model}")
            else:
                failures.append(f"{provider.kind}: модели {model!r} нет в списке "
                                f"провайдера — каждый запрос к ней будет 400")
                lines.append(f"    НЕТ    {model}  <- в списке провайдера отсутствует")
        if probe:
            for model in models:
                if model not in available:
                    lines.append(f"    probe {model}: пропущен (модели нет в списке)")
                    continue
                try:
                    lines.append(f"    probe {model}: {probe_model(provider.base_url, provider.api_key, model)}")
                except Exception as exc:                          # noqa: BLE001
                    failures.append(f"{provider.kind}: probe {model!r} не прошёл — "
                                    f"{type(exc).__name__}: {str(exc)[:120]}")
                    lines.append(f"    probe {model}: ОШИБКА {type(exc).__name__}")

    for failure in failures:
        lines.append("ПРОВАЛ: " + failure)
    if failures:
        return 1, lines
    if unreachable:
        lines.append("НЕ ПРОВЕРЕНО: провайдер недоступен, имена моделей не подтверждены")
        return 2, lines
    lines.append("ОК: каждое имя модели, которое запросит это окружение, есть у провайдера")
    return 0, lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    parser.add_argument("--env", default=str(ROOT / ".env"), help="env file (default: <repo>/.env)")
    parser.add_argument("--probe", action="store_true",
                        help="send one eight-token request per distinct model")
    args = parser.parse_args(argv)
    code, lines = check(pathlib.Path(args.env), probe=args.probe)
    for line in lines:
        print(line)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
