"""Mint one MCP key, on the box, and print it exactly once.

WHY A SCRIPT. docs/MCP.md leaves key issuance open -- self-service implies a
page, and there is no dashboard. Until there is one, an operator mints keys by
hand, and without this the Phase 1 endpoint is an endpoint nobody can
authenticate to.

    python3 scripts/mint_mcp_key.py "vitaly's cursor"

WHAT IT PRINTS, AND WHY ONLY ONCE. The plaintext key exists in this process's
memory and nowhere else: what is stored is HMAC-SHA256(pepper, key), the same
posture accounts has had since migration 0019. A lost key is rotated, not
recovered, and no path in the code could recover one. So the line this prints
is the only copy that will ever exist -- hand it over, and keep it out of
tickets, chat, and any scrollback somebody else reads.

THE PEPPER AND THE DATABASE come from /opt/shipit/.env, read literally by
scripts/env_file.py rather than sourced into a shell. Sourcing that file is
what truncated an SMTP password at a `#` on this host, and the habit does not
get a second chance here: the value it would mangle is the pepper every key in
the system is hashed against, and a wrong pepper produces hashes that look
fine and match nothing.

THE ENVIRONMENT WINS over the file, matching scripts/env_file.py. An engineer
who has deliberately exported DATABASE_URL is not silently pointed at
production's.

REVOKING needs no script, and is one statement:

    update mcp_api_keys set revoked_at = now() where key_prefix = 'dk_mcp_ab';

The row stays, deliberately -- the audits a revoked key reached still trace
back to it, which is why revocation is a timestamp rather than a delete.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SCRIPT_DIR))

import env_file  # noqa: E402

from app.db import McpKeyRepository  # noqa: E402
from app.logging_config import configure_logging  # noqa: E402
from app.mcp.keys import (  # noqa: E402
    generate_mcp_key,
    hash_mcp_key,
    mcp_key_prefix,
)

NEEDED = ("DATABASE_URL", "API_KEY_PEPPER")

# THE API HOST, NOT THE SITE. `drydock.co` is the Next.js frontend on Vercel;
# the backend answers on `api.drydock.co`, which is the first name in
# deploy/caddy/Caddyfile's reverse-proxy block.
#
# This line was wrong once, and it printed a working-looking URL that 404s from
# the frontend's own router -- the failure looks identical to "MCP is switched
# off", so the holder would have gone looking at the flag. Every key handed out
# carries this line, so it is worth the test that pins it
# (tests/test_mint_mcp_key.py reads the Caddyfile).
MCP_URL = "https://api.drydock.co/mcp"


def load_environment() -> None:
    """Fill in whichever of NEEDED the process does not already have."""
    missing = [name for name in NEEDED if not os.environ.get(name)]
    if not missing:
        return
    path = env_file.env_file_path()
    values = env_file.read_values(path)
    for name in missing:
        value = values.get(name)
        if not value:
            raise SystemExit(
                f"{name} is not set in the environment and not readable from "
                f"{path}. Set it, or point SHIPIT_ENV_FILE at the file that "
                f"has it."
            )
        os.environ[name] = value


async def mint(key: str, label: str | None) -> dict:
    row = await McpKeyRepository().create(
        key_hash=hash_mcp_key(key), key_prefix=mcp_key_prefix(key), label=label)
    if row is None:
        # The repository's not-configured contract: no exception, no row.
        # Nothing was minted, so there is nothing to clean up -- say so, since
        # the alternative reading ("a key exists that I cannot see") would send
        # an operator looking through the table.
        raise SystemExit(
            "The key was not stored -- DATABASE_URL is unset or unreachable "
            "from here. Nothing was minted; nothing to clean up.")
    return row


def main() -> int:
    configure_logging()
    parser = argparse.ArgumentParser(
        description="Mint one MCP key and print it once.")
    parser.add_argument("label", nargs="?", default=None,
                        help="what the holder will call it, for their own list")
    args = parser.parse_args()

    load_environment()
    key = generate_mcp_key()
    row = asyncio.run(mint(key, args.label))

    print()
    print("  Key (shown once, and never recoverable):")
    print(f"      {key}")
    print()
    print(f"  id      {row['id']}")
    print(f"  prefix  {row['key_prefix']}")
    print(f"  label   {row.get('label') or '(none)'}")
    print()
    print("  The holder configures their editor with:")
    print(f"      url     {MCP_URL}")
    print("      header  Authorization: Bearer <the key above>")
    print()
    print("  The endpoint answers 404 unless MCP_ENABLED is set on the box.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
