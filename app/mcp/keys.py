"""Minting and reading an MCP key.

BORROWED, NOT REWRITTEN. The pepper, the HMAC and the prefix rule all live in
app/accounts.py and are imported from there. A second copy of key hashing is
how two credentials in one system start disagreeing about what a valid key is,
and the failure mode of getting that wrong -- a pepper read from a different
place, a prefix of a different length -- is silent until every key stops
verifying at once.

What differs from an account key is the visible prefix, and only that. An
operator reading a log, or a holder reading their own list, should be able to
tell at a glance which of the two credentials they are looking at; `sk_live_`
on both would make a Pro key and an MCP key indistinguishable in exactly the
places people go when something is wrong.
"""

from __future__ import annotations

import secrets

from app.accounts import KEY_PREFIX_LEN, hash_api_key

# Deliberately not `sk_live_`. See the module docstring: the two credentials
# must be distinguishable on sight. The length matches the account key's body
# so KEY_PREFIX_LEN reveals the same amount of nothing.
MCP_KEY_PREFIX = "dk_mcp_"


def generate_mcp_key() -> str:
    """A new key. The plaintext exists here, in memory, and nowhere else --
    the caller has one chance to hand it to its owner before it is gone."""
    return f"{MCP_KEY_PREFIX}{secrets.token_urlsafe(32)}"


def mcp_key_prefix(key: str) -> str:
    """The safe-to-display head of a key.

    Same length as an account key's prefix, so the two are stored and shown
    with one rule. `dk_mcp_` is seven characters, leaving five of the random
    body -- enough to pick one key out of a list, far short of enough to
    guess the rest.
    """
    return key[:KEY_PREFIX_LEN]


def hash_mcp_key(key: str) -> str:
    """HMAC-SHA256(pepper, key) as hex, exactly as accounts does it.

    Raises loudly when the pepper is unset rather than hashing with an empty
    one: a wrong pepper produces hashes that look fine and match nothing, so
    every key silently stops working at once. See accounts.require_pepper.
    """
    return hash_api_key(key)


def looks_like_mcp_key(value: str) -> bool:
    """Whether a bearer token is shaped like one of ours.

    Cheap enough to run before touching the database, and its only job is to
    keep an account key -- or a pasted GitHub token, or a URL -- from becoming
    a lookup. It authorises nothing: a value that passes here is still
    verified by hash against a stored row, and a value that fails is refused
    with exactly the same answer as a wrong one, so this cannot be used to
    learn which keys exist.
    """
    return value.startswith(MCP_KEY_PREFIX) and len(value) > len(MCP_KEY_PREFIX)
