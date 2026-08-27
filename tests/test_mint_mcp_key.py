"""The URL handed to every MCP key holder must be the API host.

WHAT HAPPENED. The first version of scripts/mint_mcp_key.py printed
`https://drydock.co/mcp`. That is the Next.js frontend on Vercel; the backend
answers on `api.drydock.co`. The address was printed to the operator, in the
same block as the key, and every holder configured from it would have got a
404 -- from the frontend's own router, for a path it does not have.

WHY IT WAS HARD TO SEE. A disabled MCP endpoint also answers 404, by design.
So the wrong host produces exactly the symptom of the right host with the flag
off, and the holder goes looking at MCP_ENABLED. The same confusion cost a
production check its meaning on the day this was written: a `curl` against
drydock.co returned the expected 404 and proved nothing.

WHY THIS TEST READS THE CADDYFILE. Asserting the literal string would only
restate the constant. What can actually drift is the relationship: the host
this script names must be a host the reverse proxy serves. If the API is ever
renamed, this fails and names the file to change, instead of the rename being
discovered by somebody whose editor stopped working.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CADDYFILE = REPO_ROOT / "deploy" / "caddy" / "Caddyfile"


def _proxied_hostnames() -> set[str]:
    """The hostnames Caddy reverse-proxies to the backend.

    A site block is `host[, host...] {` on one line, and only the block whose
    body proxies to the app is of interest -- a static or redirect block would
    not serve /mcp.
    """
    text = CADDYFILE.read_text()
    hosts: set[str] = set()
    for block, body in re.findall(r"^([^\s#{][^\n{]*)\{([^}]*)\}", text,
                                  re.MULTILINE):
        if "reverse_proxy" not in body:
            continue
        for name in block.split(","):
            name = name.strip()
            if name:
                hosts.add(name)
    return hosts


def test_the_caddyfile_still_parses_into_hostnames():
    """Guards the guard. A regex over a config file that silently matches
    nothing would make every assertion below vacuously true."""
    hosts = _proxied_hostnames()

    assert hosts, f"no reverse-proxied hostnames found in {CADDYFILE}"


def test_the_minted_key_points_at_a_host_the_proxy_actually_serves():
    from scripts.mint_mcp_key import MCP_URL

    assert MCP_URL.startswith("https://")
    assert MCP_URL.endswith("/mcp")

    host = MCP_URL[len("https://"):-len("/mcp")]
    assert host in _proxied_hostnames(), (
        f"{host} is not reverse-proxied to the backend in {CADDYFILE}; the "
        f"URL printed with every minted key would 404")


def test_the_url_is_not_the_frontend():
    """Named separately from the check above because it is the specific
    mistake that was made, and because `drydock.co` would still be a real,
    reachable host -- it simply serves a different application."""
    from scripts.mint_mcp_key import MCP_URL

    assert "//drydock.co/" not in MCP_URL, (
        "drydock.co is the Next.js frontend; the backend is api.drydock.co")
