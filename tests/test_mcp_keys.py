"""The MCP credential: what it is, and what it may read.

docs/MCP.md makes two decisions this file exists to hold:

  * a key is not an account -- free, self-service, no tier;
  * a key reads ONLY the audits it asked for.

The second is the one worth writing first. `audits.access_token` is a per-row
capability precisely so that knowing an audit_id is not enough, and a key that
could fetch any audit by id would step around it. What that would expose is a
map of somebody else's vulnerabilities -- a broken object-level authorisation
in the tool that reports broken object-level authorisation.

Everything here is pure or against fakes. The same properties are exercised
against real Postgres in tests/test_db_postgres_smoke.py, because a
membership test is SQL and an in-memory fake agrees with itself no matter what
the query says.
"""

from __future__ import annotations

import pytest

from app.accounts import KEY_PREFIX_LEN
from app.mcp.keys import (
    MCP_KEY_PREFIX,
    generate_mcp_key,
    hash_mcp_key,
    looks_like_mcp_key,
    mcp_key_prefix,
)

PEPPER = "mcp-test-pepper-not-a-real-secret"


@pytest.fixture(autouse=True)
def _pepper(monkeypatch):
    monkeypatch.setenv("API_KEY_PEPPER", PEPPER)


# --- the key itself --------------------------------------------------------

def test_a_key_announces_which_credential_it_is():
    """An account key and an MCP key must be distinguishable on sight.

    They are read side by side in exactly the places people go when something
    is wrong -- a log line, a holder's own list -- and `sk_live_` on both
    would make "which of these two is failing?" unanswerable by looking.
    """
    key = generate_mcp_key()
    assert key.startswith(MCP_KEY_PREFIX)
    assert not key.startswith("sk_live_")


def test_two_keys_are_not_the_same_key():
    assert generate_mcp_key() != generate_mcp_key()


def test_the_prefix_reveals_a_key_and_not_its_body():
    key = generate_mcp_key()
    prefix = mcp_key_prefix(key)

    assert len(prefix) == KEY_PREFIX_LEN
    assert key.startswith(prefix)
    # The whole point: what is stored and displayed must not be enough to
    # reconstruct the credential.
    assert len(prefix) < len(key) / 2


def test_hashing_is_the_accounts_hashing(monkeypatch):
    """Borrowed, not rewritten. A second copy of key hashing is how two
    credentials in one system start disagreeing about what a valid key is."""
    from app.accounts import hash_api_key

    key = generate_mcp_key()
    assert hash_mcp_key(key) == hash_api_key(key)


def test_a_different_pepper_is_a_different_hash(monkeypatch):
    """The pepper is env-only and never in the database, so a database leak
    alone cannot replay a key. That is only true if it actually participates."""
    key = generate_mcp_key()
    first = hash_mcp_key(key)

    monkeypatch.setenv("API_KEY_PEPPER", "a-different-pepper")
    assert hash_mcp_key(key) != first


def test_hashing_refuses_without_a_pepper(monkeypatch):
    """Loudly, rather than hashing with an empty one. A wrong pepper produces
    hashes that look fine and match nothing, so every key stops working at
    once and the cause is invisible."""
    monkeypatch.delenv("API_KEY_PEPPER", raising=False)
    with pytest.raises(RuntimeError, match="API_KEY_PEPPER"):
        hash_mcp_key(generate_mcp_key())


@pytest.mark.parametrize("value,expected", [
    ("dk_mcp_abcdefghijklmnop", True),
    ("sk_live_abcdefghijklmnop", False),   # an account key, not ours
    ("ghp_abcdefghijklmnopqrst", False),   # a pasted GitHub token
    ("https://drydock.co", False),
    ("dk_mcp_", False),                    # the marker with no body
    ("", False),
])
def test_the_shape_check_is_a_filter_and_not_an_authorisation(value, expected):
    """looks_like_mcp_key keeps a pasted GitHub token from becoming a database
    lookup. It authorises nothing -- a value that passes is still verified by
    hash, and one that fails is refused exactly as a wrong one is, so it
    cannot be used to learn which keys exist."""
    assert looks_like_mcp_key(value) is expected


# --- what a key may read ---------------------------------------------------

class FakeMcpKeyRepo:
    """The membership half of McpKeyRepository, in memory.

    Mirrors the SQL predicate rather than the intent: `may_read_audit` is a
    lookup in the set of (key, audit) pairs and nothing else. A fake that
    answered "well, the key has audits, so yes" would let the handler tests
    pass over a repository that grants too much.
    """

    def __init__(self):
        self.links: set[tuple[str, str]] = set()
        self.revoked: set[str] = set()
        self.keys: dict[str, dict] = {}

    async def create(self, *, key_hash, key_prefix, label=None):
        row = {"id": f"key-{len(self.keys) + 1}", "key_prefix": key_prefix,
               "label": label, "revoked_at": None}
        self.keys[key_hash] = row
        return row

    async def get_by_key_hash(self, key_hash):
        row = self.keys.get(key_hash)
        if row is None or row["id"] in self.revoked:
            return None
        return row

    async def revoke(self, key_id):
        if key_id in self.revoked:
            return False
        self.revoked.add(key_id)
        return True

    async def link_audit(self, key_id, audit_id):
        self.links.add((key_id, audit_id))

    async def may_read_audit(self, key_id, audit_id):
        return (key_id, audit_id) in self.links


async def test_a_second_key_cannot_read_the_first_keys_audit():
    """THE TEST THIS MODULE WAS WRITTEN AROUND.

    Holding a valid key and a real audit_id must not be enough. If it were,
    every audit_id that ever appeared in a log, a chat message or a shared
    screenshot would be readable by anybody with a free key -- and what it
    returns is a list of somebody's unfixed vulnerabilities.
    """
    repo = FakeMcpKeyRepo()
    await repo.link_audit("key-1", "audit-a")

    assert await repo.may_read_audit("key-1", "audit-a") is True
    assert await repo.may_read_audit("key-2", "audit-a") is False


async def test_two_keys_can_hold_the_same_audit_without_taking_it():
    """The content-hash cache returns a PREVIOUSLY CREATED audit row when
    byte-identical content was audited before, by anyone. So two keys land on
    one audit legitimately, and a single-owner column would either deny the
    second the audit it just asked for or take it from the first."""
    repo = FakeMcpKeyRepo()
    await repo.link_audit("key-1", "audit-a")
    await repo.link_audit("key-2", "audit-a")

    assert await repo.may_read_audit("key-1", "audit-a") is True
    assert await repo.may_read_audit("key-2", "audit-a") is True


async def test_linking_twice_is_harmless():
    """A cache hit can land the same key on the same audit again, mid-answer.
    That must be a no-op, not a 500."""
    repo = FakeMcpKeyRepo()
    await repo.link_audit("key-1", "audit-a")
    await repo.link_audit("key-1", "audit-a")

    assert await repo.may_read_audit("key-1", "audit-a") is True


async def test_a_key_with_audits_still_cannot_read_a_stranger_one():
    """The failure a lazier predicate makes: answering from "this key has
    audits" instead of "this key has THIS audit"."""
    repo = FakeMcpKeyRepo()
    for n in range(5):
        await repo.link_audit("key-1", f"audit-{n}")

    assert await repo.may_read_audit("key-1", "audit-99") is False


async def test_a_revoked_key_resolves_to_nothing():
    """Revocation is decided in the lookup, not left as a field each caller
    must remember to check -- one forgetful call site is a revoked credential
    that still works."""
    repo = FakeMcpKeyRepo()
    key = generate_mcp_key()
    row = await repo.create(key_hash=hash_mcp_key(key),
                            key_prefix=mcp_key_prefix(key))

    assert await repo.get_by_key_hash(hash_mcp_key(key)) is not None
    assert await repo.revoke(row["id"]) is True
    assert await repo.get_by_key_hash(hash_mcp_key(key)) is None
    # A second revoke is visibly a no-op rather than a silent success.
    assert await repo.revoke(row["id"]) is False


async def test_revoking_one_key_leaves_the_other_working():
    repo = FakeMcpKeyRepo()
    first, second = generate_mcp_key(), generate_mcp_key()
    row_one = await repo.create(key_hash=hash_mcp_key(first),
                                key_prefix=mcp_key_prefix(first))
    await repo.create(key_hash=hash_mcp_key(second),
                      key_prefix=mcp_key_prefix(second))

    await repo.revoke(row_one["id"])

    assert await repo.get_by_key_hash(hash_mcp_key(first)) is None
    assert await repo.get_by_key_hash(hash_mcp_key(second)) is not None
