"""Exploit template registry.

Templates are pure callables: workspace zip bytes in, ExploitAttempt out.
No docker, no network in the MVP secrets path — runtime templates will
later go through sandbox-runner, but the registry interface stays the same.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from app.proof.templates import cors_open, secrets_leak, sqli
from app.proof.types import ExploitAttempt, TemplateId

TemplateFn = Callable[..., ExploitAttempt]

TEMPLATE_IDS: tuple[TemplateId, ...] = (
    "secrets_leak",
    "sqli",
    "cors_open",
)

_REGISTRY: dict[TemplateId, TemplateFn] = {
    "secrets_leak": secrets_leak.run,
    "sqli": sqli.run,
    "cors_open": cors_open.run,
}


def get_template(template_id: str) -> TemplateFn:
    """Return the callable for ``template_id``.

    Raises KeyError for unknown ids so callers fail loudly rather than
    silently skipping a typo.
    """
    try:
        return _REGISTRY[template_id]  # type: ignore[index]
    except KeyError as exc:
        raise KeyError(f"unknown proof template: {template_id!r}") from exc


def list_templates() -> tuple[dict[str, Any], ...]:
    """Stable metadata for docs/tests — does not execute anything."""
    return (
        {
            "id": "secrets_leak",
            "implemented": True,
            "needs_runtime": False,
            "summary": "Re-scan workspace for high-confidence leaked secrets",
        },
        {
            "id": "sqli",
            "implemented": False,
            "needs_runtime": True,
            "summary": "HTTP SQLi probe against a sandboxed app (stub)",
        },
        {
            "id": "cors_open",
            "implemented": False,
            "needs_runtime": True,
            "summary": "CORS Origin probe against a sandboxed app (stub)",
        },
    )
