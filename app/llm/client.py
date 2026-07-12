"""LLM client: provider chain with fallback, no vendor SDK.

Order: AITunnel (OpenAI-compatible /chat/completions) if configured,
then direct Anthropic /v1/messages. Direct `httpx` calls — same
pattern proven in production elsewhere. `.env` is the single source
of truth; nothing is hardcoded except API shapes.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

import httpx

DEFAULT_MODEL = "claude-sonnet-4-6"
TIMEOUT = httpx.Timeout(120.0, connect=10.0)
TRANSIENT_RETRIES = 2      # extra attempts per provider on 5xx/transport errors
RETRY_BACKOFF_S = 2.0      # linear: 2s, then 4s


class LLMError(Exception):
    """All providers failed."""


@dataclass(frozen=True)
class Provider:
    kind: str      # "openai_compat" | "anthropic"
    base_url: str
    api_key: str
    model: str


def providers_from_env() -> list[Provider]:
    chain: list[Provider] = []
    model = os.environ.get("LLM_MODEL", DEFAULT_MODEL)

    aitunnel_key = os.environ.get("AITUNNEL_API_KEY")
    aitunnel_url = os.environ.get("AITUNNEL_BASE_URL")  # e.g. https://.../v1
    if aitunnel_key and aitunnel_url:
        chain.append(Provider("openai_compat", aitunnel_url.rstrip("/"),
                              aitunnel_key, model))

    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    if anthropic_key:
        chain.append(Provider("anthropic", "https://api.anthropic.com",
                              anthropic_key, model))
    return chain


class LLMClient:
    def __init__(self, providers: list[Provider] | None = None,
                 transport: httpx.BaseTransport | None = None):
        self.providers = providers if providers is not None else providers_from_env()
        self._transport = transport  # injectable for tests

    def complete(self, system: str, user: str, max_tokens: int = 4096) -> str:
        if not self.providers:
            raise LLMError("no providers configured (check .env)")
        errors: list[str] = []
        for p in self.providers:
            for attempt in range(1 + TRANSIENT_RETRIES):
                try:
                    return self._call(p, system, user, max_tokens)
                except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
                    # 5xx and transport/timeout errors are transient:
                    # retry the SAME provider with backoff (a single
                    # provider-side 500 killed a whole audit stage in a
                    # real run; the chain is often length 1, so "next
                    # provider" is no safety net). 4xx means OUR request
                    # is wrong — retrying it is spam.
                    transient = isinstance(exc, httpx.TransportError) or (
                        isinstance(exc, httpx.HTTPStatusError)
                        and exc.response.status_code >= 500
                    )
                    if transient and attempt < TRANSIENT_RETRIES:
                        time.sleep(RETRY_BACKOFF_S * (attempt + 1))
                        continue
                    errors.append(f"{p.kind}@{p.base_url}: {exc}")
                    break
        raise LLMError("; ".join(errors))

    def _call(self, p: Provider, system: str, user: str, max_tokens: int) -> str:
        with httpx.Client(timeout=TIMEOUT, transport=self._transport) as client:
            if p.kind == "anthropic":
                resp = client.post(
                    f"{p.base_url}/v1/messages",
                    headers={
                        "x-api-key": p.api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": p.model,
                        "max_tokens": max_tokens,
                        # Audit pipeline: reproducibility over creativity.
                        # Unset temperature = provider default (usually
                        # 1.0) = finding sets that differ run to run.
                        "temperature": 0,
                        "system": system,
                        "messages": [{"role": "user", "content": user}],
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                return "".join(
                    b["text"] for b in data["content"] if b.get("type") == "text"
                )

            # openai_compat
            resp = client.post(
                f"{p.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {p.api_key}",
                         "content-type": "application/json"},
                json={
                    "model": p.model,
                    "max_tokens": max_tokens,
                    "temperature": 0,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                },
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
