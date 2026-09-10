"""One text-generation call, from Ollama or an OpenAI-compatible API.

WHY THIS EXISTS. Two harnesses ask a model to write code -- the escape hunt
rewrites corpus fixtures, the injection probe dresses planted defects in
plausible surroundings -- and both had their own copy of an Ollama call. The
copies had already drifted (different timeouts, different fence handling), and
adding a second provider to each was the moment to stop.

WHAT THE MODEL IS FOR, IN BOTH CALLERS. Volume, never truth. It writes code
whose correctness is decided by the shipped scanner or by a planted defect at a
known path. That division is why a hosted model is safe to use here at all: a
worse model produces worse variations, not wrong verdicts.

PROVIDERS.

    ollama   local, free, no network. Default, and the fallback when nothing
             is configured -- the harnesses must keep working on a laptop with
             no API key.

    openai   any OpenAI-compatible /chat/completions endpoint: DeepSeek,
             OpenRouter, AITunnel, a local vLLM. Configured entirely by
             environment, because a key belongs in the environment and not in
             a file that gets committed.

CONFIGURED BY ENVIRONMENT, not by flags:

    HUNT_PROVIDER   ollama | openai        (default: ollama)
    HUNT_MODEL      model name             (provider-specific default)
    HUNT_API_KEY    secret                 (openai only; required)
    HUNT_API_BASE   endpoint root          (default: https://api.deepseek.com)
    HUNT_THINKING   on to allow reasoning  (default: off; see _openai)
    OLLAMA_URL      local server           (default: http://127.0.0.1:11434)

The key is read from the environment on every call and never logged, never
written to a report, and never passed on a command line where it would land in
shell history.

TOKENS ARE COUNTED HERE, not in the callers. A run that costs money should say
what it cost, and the number has to come from the provider's own `usage` block
rather than an estimate -- DeepSeek prices cache hits differently from misses,
so a token count that ignores `prompt_cache_hit_tokens` is not the bill.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")

_DEFAULT_MODELS = {
    "ollama": "qwen2.5-coder:7b",
    "openai": "deepseek-chat",
}

# Accumulated across every call in a process. A module-level total, because
# the alternative is threading a counter through two harnesses that do not
# otherwise share state, and the harnesses are single-purpose scripts.
_usage_lock = threading.Lock()
_usage = {
    "calls": 0,
    "failed_calls": 0,
    "prompt_tokens": 0,
    "completion_tokens": 0,
    "reasoning_tokens": 0,
    "cache_hit_tokens": 0,
    "cache_miss_tokens": 0,
}


def _record(body: dict) -> None:
    """Add one response's usage to the running total. Never raises."""
    usage = (body or {}).get("usage") or {}
    detail = usage.get("completion_tokens_details") or {}
    with _usage_lock:
        _usage["calls"] += 1
        for key, source in (
            ("prompt_tokens", usage.get("prompt_tokens")),
            ("completion_tokens", usage.get("completion_tokens")),
            ("reasoning_tokens", detail.get("reasoning_tokens")),
            ("cache_hit_tokens", usage.get("prompt_cache_hit_tokens")),
            ("cache_miss_tokens", usage.get("prompt_cache_miss_tokens")),
        ):
            if isinstance(source, int):
                _usage[key] += source


def usage_report() -> dict:
    """Totals so far. Safe to call when nothing has run: all zeros."""
    with _usage_lock:
        snapshot: dict[str, object] = dict(_usage)
    snapshot["provider"] = describe()
    return snapshot


def usage_line() -> str:
    """One human line for the end of a run."""
    u = usage_report()
    if not u["calls"]:
        return "tokens: no model calls"
    parts = [f"{u['calls']} calls",
             f"{u['prompt_tokens']} prompt",
             f"{u['completion_tokens']} completion"]
    if u["reasoning_tokens"]:
        parts.append(f"{u['reasoning_tokens']} of it reasoning")
    if u["cache_hit_tokens"] or u["cache_miss_tokens"]:
        parts.append(f"cache {u['cache_hit_tokens']} hit / "
                     f"{u['cache_miss_tokens']} miss")
    if u["failed_calls"]:
        parts.append(f"{u['failed_calls']} failed")
    return "tokens: " + ", ".join(parts)


class GenerationError(RuntimeError):
    """A call that produced no usable text. Carries no key material."""


def provider() -> str:
    return os.environ.get("HUNT_PROVIDER", "ollama").strip().lower()


def model_name() -> str:
    configured = os.environ.get("HUNT_MODEL", "").strip()
    return configured or _DEFAULT_MODELS.get(provider(), _DEFAULT_MODELS["ollama"])


def describe() -> str:
    """One line for the report header. Never includes the key."""
    if provider() == "openai":
        base = os.environ.get("HUNT_API_BASE", "https://api.deepseek.com")
        return f"openai-compatible {model_name()} at {base}"
    return f"ollama {model_name()} at {OLLAMA_URL}"


def _ollama(model: str, prompt: str, temperature: float,
            max_tokens: int, timeout: int) -> str:
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "keep_alive": "20m",   # a cold load costs ~15s; we make many calls
        "options": {"temperature": temperature, "num_predict": max_tokens},
    }).encode()
    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/generate", data=payload,
        headers={"Content-Type": "application/json"},
    )
    # A localhost service must never be reached through the user's HTTP proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as resp:
        body = json.loads(resp.read())
    # Ollama names its counters differently and reports no cost. Mapped onto
    # the same totals so a run's line reads the same whichever provider served
    # it -- the point of the number is comparability between runs.
    _record({"usage": {
        "prompt_tokens": body.get("prompt_eval_count"),
        "completion_tokens": body.get("eval_count"),
    }})
    return body["response"]


def _openai(model: str, prompt: str, temperature: float,
            max_tokens: int, timeout: int) -> str:
    key = os.environ.get("HUNT_API_KEY", "").strip()
    if not key:
        raise GenerationError(
            "HUNT_PROVIDER=openai but HUNT_API_KEY is empty. Export the key "
            "in the shell that runs the harness; it is never read from a file "
            "in the repository.")
    base = os.environ.get("HUNT_API_BASE", "https://api.deepseek.com").rstrip("/")
    body_payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": False,
    }
    # REASONING OFF BY DEFAULT, and this is not a preference.
    #
    # deepseek-v4-flash is a reasoning model: it spends completion tokens on
    # `reasoning_content` before writing anything the caller sees. On the hunt
    # prompt it spent the ENTIRE budget thinking -- 8192 of 8192 tokens at the
    # default, 16384 of 16384 when raised -- and returned `finish_reason:
    # length` with an empty `content`. Every rule scored 0 variations, which
    # the harness would otherwise have reported as a clean run.
    #
    # Measured on this endpoint: {"thinking": {"type": "disabled"}} drops
    # reasoning_tokens to 0 and returns the answer. `reasoning_effort: none`
    # does the same; the two are kept as one switch because a provider that
    # rejects the parameter should fail loudly rather than silently think.
    #
    # HUNT_THINKING=on restores it for a model that needs it. The harness
    # wants bulk code, not deliberation, so off is the right default here --
    # this is not a claim about the model's quality on other work.
    if os.environ.get("HUNT_THINKING", "off").strip().lower() != "on":
        body_payload["thinking"] = {"type": "disabled"}
    payload = json.dumps(body_payload).encode()
    req = urllib.request.Request(
        f"{base}/v1/chat/completions", data=payload,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {key}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        # The body can echo the request, so only the status is surfaced.
        with _usage_lock:
            _usage["failed_calls"] += 1
        raise GenerationError(
            f"{base} returned HTTP {exc.code}. Check HUNT_MODEL and the key's "
            f"balance; the response body is withheld because it can quote the "
            f"request headers.") from None
    # Recorded before the content check below: an answer that cost tokens and
    # returned nothing still cost tokens, and a run that hides that spend
    # under-reports its own bill.
    _record(body)
    try:
        choice = body["choices"][0]
        text = choice["message"]["content"] or ""
    except (KeyError, IndexError, TypeError):
        raise GenerationError(
            f"unexpected response shape from {base}: keys {sorted(body)[:6]}"
        ) from None
    # AN EMPTY ANSWER MUST NOT LOOK LIKE A QUIET RUN. A reasoning model that
    # spends its whole budget thinking returns 200 with content == "", and the
    # harness would score that as zero variations -- indistinguishable from a
    # rule the model could not break. Say what happened instead.
    if not text.strip():
        detail = (body.get("usage") or {}).get("completion_tokens_details") or {}
        reasoning = detail.get("reasoning_tokens")
        raise GenerationError(
            f"{model} returned an empty answer "
            f"(finish_reason={choice.get('finish_reason')!r}, "
            f"reasoning_tokens={reasoning}). If reasoning consumed the budget, "
            f"leave HUNT_THINKING unset so thinking stays disabled, or raise "
            f"max_tokens.")
    return text


def generate(prompt: str, *, model: str | None = None,
             temperature: float = 0.9, max_tokens: int = 8192,
             timeout: int = 900) -> str:
    """Text for `prompt`. Diversity is the point, hence a high temperature.

    Raises GenerationError with an actionable message and no key material.
    """
    chosen = model or model_name()
    which = provider()
    if which == "openai":
        return _openai(chosen, prompt, temperature, max_tokens, timeout)
    if which == "ollama":
        return _ollama(chosen, prompt, temperature, max_tokens, timeout)
    raise GenerationError(
        f"HUNT_PROVIDER={which!r} is not a provider. Use 'ollama' or 'openai'.")


def preflight() -> tuple[bool, str]:
    """Cheap reachability check before a run that costs money or an hour.

    Returns (ok, message). Callers print the message either way -- a run that
    starts against an unreachable provider wastes the whole loop, and one that
    starts against the WRONG provider silently produces results attributed to
    a model that never ran.
    """
    which = provider()
    try:
        if which == "ollama":
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(f"{OLLAMA_URL}/api/version", timeout=10) as resp:
                version = json.loads(resp.read()).get("version", "?")
            return True, f"ollama {version} at {OLLAMA_URL}, model {model_name()}"
        text = generate("Reply with the single word: ready",
                        temperature=0.0, max_tokens=16, timeout=60)
        return True, f"{describe()} responded: {text.strip()[:40]!r}"
    except GenerationError as exc:
        return False, str(exc)
    except Exception as exc:                                   # noqa: BLE001
        return False, f"{describe()} unreachable: {type(exc).__name__}: {exc}"
