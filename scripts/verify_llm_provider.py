#!/usr/bin/env python3
"""Check the configured LLM chain and paid/preview model identifiers.

By default read <repo>/.env ONLY, using the deployment validator's parser.
Use --env for another file, or --process-env for exported settings. No files
are modified. Catalog checks do not generate completions. Optional --probe
can incur charges: max_tokens=8 is a request, not a billing guarantee.

Exit codes: 0 all catalog checks (and requested probes) passed;
            1 invalid configuration, unlisted model, or invalid completion;
            2 verification incomplete (network/auth/HTTP/invalid catalog).
When both failure types occur, 2 takes precedence: not everything was checked.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import replace
import os
import pathlib
import sys
import time
from urllib.parse import quote, urlsplit

import httpx

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.llm.client import LLMClient, Provider, providers_from_env  # noqa: E402
from scripts.env_file import read_values  # noqa: E402

PROBE_MAX_TOKENS = 8
CATALOG_TIMEOUT = 60
MAX_CATALOG_PAGES = 100
CONFIG_NAMES = (
    "AITUNNEL_API_KEY", "AITUNNEL_BASE_URL", "AITUNNEL_LLM_MODEL",
    "ANTHROPIC_API_KEY", "ANTHROPIC_LLM_MODEL", "LLM_MODEL",
    "FREE_TIER_LLM_MODEL", "FREE_TIER_LLM_MODEL_AITUNNEL", "FREE_TIER_LLM_MODEL_ANTHROPIC",
)


@contextmanager
def configured_environment(values: dict[str, str]):
    """Scope provider resolution to this configuration; restore the caller's env."""
    previous = {name: os.environ.get(name) for name in CONFIG_NAMES}
    try:
        for name in CONFIG_NAMES:
            if name in values:
                os.environ[name] = values[name]
            else:
                os.environ.pop(name, None)
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def stage_models(chain: list[Provider], values: dict[str, str]) -> list[tuple[str, str, str]]:
    """Resolve as a fresh service would, without importing/reloading pipeline globals."""
    # Match pipeline.FREE_TIER_MODEL and free_tier_models_by_kind(): a blank
    # per-provider override falls back, but a present blank shared value does not.
    shared = values.get("FREE_TIER_LLM_MODEL", "claude-haiku-4-5")
    overrides = {"openai_compat": "FREE_TIER_LLM_MODEL_AITUNNEL",
                 "anthropic": "FREE_TIER_LLM_MODEL_ANTHROPIC"}
    rows = [(f"paid ({p.kind})", p.kind, p.model) for p in chain]
    rows.extend((f"free preview ({p.kind})", p.kind,
                 values.get(overrides[p.kind], "").strip() or shared) for p in chain)
    return rows


def fetch_model_ids(provider: Provider, transport: httpx.BaseTransport | None = None) -> set[str]:
    """Fetch the complete catalog using each provider's own authentication/API."""
    anthropic = provider.kind == "anthropic"
    url = provider.base_url + ("/v1/models" if anthropic else "/models")
    headers = ({"x-api-key": provider.api_key, "anthropic-version": "2023-06-01"}
               if anthropic else {"Authorization": "Bearer " + provider.api_key})
    params: dict[str, str | int] = {"limit": 1000} if anthropic else {}
    ids: set[str] = set()
    cursors: set[str] = set()
    # Never follow a redirect carrying credentials to another endpoint.
    with httpx.Client(timeout=CATALOG_TIMEOUT, transport=transport, follow_redirects=False) as client:
        for _ in range(MAX_CATALOG_PAGES):
            response = client.get(url, headers=headers, params=params)
            response.raise_for_status()
            body = response.json()
            if not isinstance(body, dict) or not isinstance(body.get("data"), list):
                raise ValueError("invalid catalog shape")
            for entry in body["data"]:
                if not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or not entry["id"]:
                    raise ValueError("invalid model identifier")
                ids.add(entry["id"])
            more = body.get("has_more", False)
            if not isinstance(more, bool):
                raise ValueError("invalid pagination flag")
            if not more:
                return ids
            cursor = body.get("last_id")
            if not anthropic or not isinstance(cursor, str) or not cursor or cursor in cursors:
                raise ValueError("incomplete catalog pagination")
            cursors.add(cursor)
            params["after_id"] = cursor
    raise ValueError("catalog page limit exceeded")


def resolve_anthropic_alias(provider: Provider, model: str,
                            transport: httpx.BaseTransport | None = None) -> str | None:
    """Anthropic's get-model API resolves valid aliases absent from the list."""
    with httpx.Client(timeout=CATALOG_TIMEOUT, transport=transport, follow_redirects=False) as client:
        response = client.get(provider.base_url + "/v1/models/" + quote(model, safe=""),
                              headers={"x-api-key": provider.api_key, "anthropic-version": "2023-06-01"})
        if response.status_code == 404:
            return None
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, dict) or not isinstance(body.get("id"), str) or not body["id"]:
            raise ValueError("invalid model metadata")
        return body["id"]


def probe_model(provider: Provider, model: str, transport: httpx.BaseTransport | None = None) -> str:
    """One attempt with the product's payload, transport and nonempty-answer parser."""
    selected = replace(provider, model=model)
    client = LLMClient(providers=[selected], transport=transport)
    started = time.monotonic()
    # _call is the product's single wire attempt. complete() would retry paid
    # requests and allow fallback to conceal which configured provider failed.
    _answer, usage = client._call(selected, "Reply briefly.", "Reply OK.", PROBE_MAX_TOKENS)
    return (f"{time.monotonic() - started:.1f}s, requested_max_tokens={PROBE_MAX_TOKENS}, "
            f"input={usage.input_tokens}, completion={usage.output_tokens}, served_as={usage.model}")


def error_summary(exc: Exception) -> str:
    """Exception messages, URLs and response bodies may echo a key; omit them."""
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP {exc.response.status_code}"
    return type(exc).__name__


def redact(lines: list[str], secrets: list[str]) -> list[str]:
    tokens = {token for secret in secrets if secret for token in (secret, quote(secret, safe=""))}
    clean = []
    for line in lines:
        for token in sorted(tokens, key=len, reverse=True):
            line = line.replace(token, "[REDACTED]")
        clean.append("".join(c if c.isprintable() else " " for c in line))
    return clean


def _check(values: dict[str, str], probe: bool,
           transport: httpx.BaseTransport | None) -> tuple[int, list[str]]:
    lines: list[str] = []
    if bool(values.get("AITUNNEL_API_KEY")) != bool(values.get("AITUNNEL_BASE_URL")):
        return 1, ["ПРОВАЛ: AITUNNEL_API_KEY и AITUNNEL_BASE_URL должны быть заданы вместе"]
    with configured_environment(values):
        chain = providers_from_env()
    if not chain:
        return 1, ["ПРОВАЛ: ни одного LLM-провайдера не настроено — аудиты будут static-only"]
    # Reject URL credentials/query/fragment instead of printing or sending them.
    for provider in chain:
        url = urlsplit(provider.base_url)
        if (url.scheme not in {"http", "https"} or not url.hostname or url.username is not None
                or url.password is not None or url.query or url.fragment):
            return 1, [f"ПРОВАЛ: некорректный base URL для {provider.kind}"]
    rows = stage_models(chain, values)
    if any(not model.strip() for _stage, _kind, model in rows):
        return 1, ["ПРОВАЛ: имя модели не должно быть пустым"]
    lines.append(f"провайдеров в цепочке: {len(chain)} "
                 f"({'фолбэка нет' if len(chain) == 1 else 'есть фолбэк'})")
    for provider in chain:
        lines.append(f"  {provider.kind}: {provider.base_url}")
    lines.append("стадии:")
    lines.extend(f"  {stage} -> {model}" for stage, _kind, model in rows)
    if probe:
        lines.append("ПЛАТНЫЙ PROBE: одна попытка на каждую пару провайдер/модель; "
                     "max_tokens=8 не гарантирует восемь оплачиваемых токенов")
    failed = incomplete = False
    for provider in chain:
        models = list(dict.fromkeys(model for _stage, kind, model in rows if kind == provider.kind))
        try:
            available = fetch_model_ids(provider, transport)
        except Exception as exc:  # noqa: BLE001
            incomplete = True
            lines.append(f"НЕ ПРОВЕРЕНО: {provider.kind}: каталог недоступен — {error_summary(exc)}")
            continue
        lines.append(f"  {provider.kind}: провайдер отдаёт {len(available)} моделей")
        for model in models:
            confirmed = model in available
            if not confirmed and provider.kind == "anthropic":
                try:
                    resolved = resolve_anthropic_alias(provider, model, transport)
                except Exception as exc:  # noqa: BLE001
                    incomplete = True
                    lines.append(f"НЕ ПРОВЕРЕНО: alias {model}: {error_summary(exc)}")
                    continue
                if resolved:
                    confirmed = True
                    lines.append(f"    ALIAS {model} -> {resolved}")
            if not confirmed:
                failed = True
                lines.append(f"ПРОВАЛ: {provider.kind}: НЕТ {model} в каталоге; "
                             "имя не подтверждено (это не предсказание HTTP-статуса генерации)")
                continue
            lines.append(f"    ЕСТЬ {model}")
            if probe:
                try:
                    lines.append(f"    probe {model}: {probe_model(provider, model, transport)}")
                except (httpx.HTTPError, OSError) as exc:
                    incomplete = True
                    lines.append(f"НЕ ПРОВЕРЕНО: probe {model}: {error_summary(exc)}")
                except Exception as exc:  # noqa: BLE001
                    failed = True
                    lines.append(f"ПРОВАЛ: probe {model}: некорректный ответ — {error_summary(exc)}")
    if incomplete:
        return 2, lines
    if failed:
        return 1, lines
    lines.append("ОК: имена подтверждены каталогами" +
                 ("; пробные ответы прошли проверку LLMClient" if probe else
                  "; генерация и баланс не проверялись"))
    return 0, lines


def check(env_path: pathlib.Path | None, probe: bool = False, *,
          transport: httpx.BaseTransport | None = None) -> tuple[int, list[str]]:
    """Check one configuration source, without retaining its values in os.environ."""
    ambient_keys = [os.environ.get(name, "") for name in CONFIG_NAMES if name.endswith("API_KEY")]
    if env_path is None:
        values = {name: os.environ[name] for name in CONFIG_NAMES if name in os.environ}
        source = "источник: окружение процесса"
    else:
        # read_values uses the deployment validator's quote handling and never
        # exposes a failed parse. An empty/unreadable file is not ambient config.
        values = read_values(env_path)
        if not values:
            return 1, ["ПРОВАЛ: env-файл отсутствует, пуст или не читается; окружение оболочки не используется"]
        source = "источник: только указанный env-файл (переменные оболочки не подмешиваются)"
    secrets = ambient_keys + [value for name, value in values.items() if name.endswith("API_KEY")]
    try:
        code, lines = _check(values, probe, transport)
    except Exception as exc:  # noqa: BLE001
        code, lines = 1, [f"ПРОВАЛ: не удалось проверить конфигурацию — {error_summary(exc)}"]
    return code, redact([source, *lines], secrets)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--env", type=pathlib.Path, help="read ONLY this env file (default: <repo>/.env)")
    source.add_argument("--process-env", action="store_true", help="read ONLY exported process settings")
    parser.add_argument("--probe", action="store_true",
                        help="paid: one product-client attempt per provider/model; max_tokens is not a billing cap")
    args = parser.parse_args(argv)
    path = None if args.process_env else (args.env if args.env is not None else ROOT / ".env")
    code, lines = check(path, probe=args.probe)
    for line in lines:
        print(line)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
