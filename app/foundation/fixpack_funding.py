"""Stable identity of the confirmed payment that first funds a Fix Pack."""

import hashlib
import json


def funding_key(provider: str, external_ref: str) -> str:
    return hashlib.sha256(json.dumps(
        [provider, external_ref], ensure_ascii=True, separators=(",", ":"),
    ).encode()).hexdigest()
