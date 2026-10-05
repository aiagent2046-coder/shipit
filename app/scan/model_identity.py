"""Separate opt-in Luna audit cache rows from the default model's results."""

import hashlib
import json

from app.llm.client import LUNA_MODELS, providers_from_env


def configured_model_engine_version(base_version: str) -> str:
    """Return the server identity for the configured primary provider chain.

    Pipeline calls this once at import: changing provider/model configuration
    requires restarting both API and worker processes. Credentials and URLs
    are deliberately absent from the identity. Preview-only configuration and
    chains without Luna retain the existing manual engine-version policy.
    """
    providers = providers_from_env()
    if not any(provider.model in LUNA_MODELS for provider in providers):
        return base_version
    identity = {
        "policy": "luna-medium-v1",
        "providers": [
            [provider.kind, "gpt-6-luna" if provider.model in LUNA_MODELS else provider.model]
            for provider in providers
        ],
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()[:12]
    return f"{base_version}-luna-{digest}"
