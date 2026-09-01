#!/usr/bin/env python3
"""Build the three variants of the rotation stand as plain static directories.

WHAT THIS STAND IS FOR, and it is not what smoke/service_role_bundle's e2e is
for. Part B already proved the harder thing — that a service_role key survives a
real Vite production build and is not tree-shaken away. That question is
settled, so this stand does not rebuild it, and drops the whole node toolchain
with it.

What is NOT settled, and what these three directories exist to settle, is the
pair of claims that have only ever been true in fixtures:

  1. the four live rotation verdicts (`no_baseline` -> `unchanged` ->
     `replaced_still_shipped` -> `gone_from_bundle`), which need a deployment
     that actually serves a credential and then stops;
  2. the TRANSITIVE crawl reaching a finding. The 2026-09-01 run on drydock.co
     read 8 chunks and found nothing, because there is nothing there. Whether
     the walk finds a key that is TWO hops from the HTML has never been shown
     against a live deployment.

So each variant is deliberately two levels deep: index.html names one chunk, and
that chunk names a second by quoted filename — the shape a bundler's manifest
has — and the credential lives only in the second. A stand that put the key in
the first script would prove the crawl works exactly where it was never in
doubt.

    dist_key_a/   SERVICE_ROLE_A in the second chunk
    dist_key_b/   SERVICE_ROLE_B — a different key of the same class
    dist_clean/   the anon key only, which is publishable by design

THE KEYS COME FROM keys.rotation.env AND ARE NEVER COMMITTED. mint_rotation_keys
writes that file 0600 and .gitignore excludes it, because this repository's own
`added secrets` preflight gate would refuse the commit — correctly. Nothing here
weakens that: the tokens are synthetic and inert (see mint_rotation_keys), and
they still do not enter git.

    python smoke/service_role_bundle/build_rotation_stand.py
"""

from __future__ import annotations

import hashlib
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
KEYS = HERE / "keys.rotation.env"

# THE PAGE SAYS WHAT IT IS, IN PUBLIC. Whoever finds this host — a scanner, a
# curious reader, us in six months — sees a JWT with a `service_role` claim in
# the bundle and draws the only reasonable conclusion available to them, which
# is that somebody leaked one. The note costs two lines and removes a reading
# that would otherwise be entirely rational.
INDEX = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Drydock rotation stand — synthetic fixture</title>
  </head>
  <body>
    <h1>Drydock rotation stand</h1>
    <p><strong>This is a test fixture, not a deployed application.</strong>
      The Supabase-shaped credential in this page's JavaScript is synthetic: a
      random project ref, signed with a random secret that was discarded when it
      was minted. It was never issued by Supabase and grants access to nothing.
      It exists so an automated check can be shown to notice a credential in a
      served bundle, and to notice when one changes.</p>
    <div id="app">loading…</div>
    <script type="module" src="/assets/entry-{entry}.js"></script>
  </body>
</html>
"""

# The first chunk names the second the way a bundler manifest does: a quoted
# path, resolved at runtime. This is what app/proof/served_bundle._asset_refs_in_js
# follows, and following it is the half of the crawl no live run has exercised
# while there was anything to find.
ENTRY_JS = """// entry chunk — routes to the client chunk by name, as a bundler manifest does
const CHUNKS = {{ client: "/assets/client-{client}.js" }};
import(CHUNKS.client).then((m) => m.start());
export {{ CHUNKS }};
"""

CLIENT_JS = """// client chunk — the only place the credential appears
import {{ createClient }} from "https://esm.sh/@supabase/supabase-js@2";
const URL = "https://{ref}.supabase.co";
const KEY = "{key}";
export function start() {{
  const supabase = createClient(URL, KEY);
  supabase.from("founders").select("*").limit(3).then(({{ data, error }}) => {{
    const el = document.getElementById("app");
    if (el) el.textContent = error ? String(error.message) : JSON.stringify(data);
  }});
}}
"""


def _read_keys() -> dict[str, str]:
    if not KEYS.is_file():
        raise SystemExit(
            f"{KEYS} not found — run mint_rotation_keys.py first "
            "(it is 0600 and gitignored on purpose)")
    out: dict[str, str] = {}
    for line in KEYS.read_text().splitlines():
        name, _, value = line.partition("=")
        if name and value:
            out[name.strip()] = value.strip()
    missing = {"SERVICE_ROLE_A", "SERVICE_ROLE_B", "ANON"} - set(out)
    if missing:
        raise SystemExit(f"{KEYS} is missing {sorted(missing)}")
    return out


def _ref_of(token: str) -> str:
    """The project ref the minted token carries, so the URL and the key agree.

    Cosmetic for the check — nothing resolves this host — but a stand whose URL
    and key referred to different projects would be the first thing a reader
    noticed and the last thing they trusted.
    """
    import base64
    import json
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload)).get("ref", "unknown")


def _build(out: Path, key: str) -> None:
    if out.exists():
        shutil.rmtree(out)
    (out / "assets").mkdir(parents=True)

    client_body = CLIENT_JS.format(ref=_ref_of(key), key=key)
    client_hash = hashlib.sha256(client_body.encode()).hexdigest()[:8]
    (out / "assets" / f"client-{client_hash}.js").write_text(client_body)

    entry_body = ENTRY_JS.format(client=client_hash)
    entry_hash = hashlib.sha256(entry_body.encode()).hexdigest()[:8]
    (out / "assets" / f"entry-{entry_hash}.js").write_text(entry_body)

    (out / "index.html").write_text(INDEX.format(entry=entry_hash))


def _verify(out: Path, key: str, expect_present: bool) -> None:
    """Read the built directory back and check what it actually serves.

    The instrument, checked before it is used. A stand that silently failed to
    bake the key would produce a clean bundle-check and read as
    `gone_from_bundle` — the stand proving the opposite of what it was built
    for, and nothing in the run would say so.
    """
    blob = "".join(p.read_text() for p in sorted(out.rglob("*"))
                   if p.is_file())
    present = key in blob
    if present != expect_present:
        raise SystemExit(
            f"{out.name}: credential {'missing from' if expect_present else 'present in'} "
            "the built output — the stand would prove the opposite of what it "
            "is for")
    if expect_present and key in (out / "index.html").read_text():
        raise SystemExit(
            f"{out.name}: the key is in index.html, so a one-hop crawl would "
            "find it and the transitive walk would go untested")


def main() -> int:
    keys = _read_keys()
    plan = [("dist_key_a", keys["SERVICE_ROLE_A"], True),
            ("dist_key_b", keys["SERVICE_ROLE_B"], True),
            ("dist_clean", keys["ANON"], False)]

    for name, key, is_secret in plan:
        out = HERE / name
        _build(out, key)
        _verify(out, key, expect_present=True)
        files = sorted(p.relative_to(out).as_posix()
                       for p in out.rglob("*") if p.is_file())
        print(f"{name:12s} {'service_role' if is_secret else 'anon only':13s} "
              f"{files}")

    print("\nEach variant is two hops deep: index.html -> entry chunk -> client "
          "chunk.\nThe credential is only in the second chunk, so a run that "
          "finds it has\nexercised the transitive walk against a real finding "
          "for the first time.")
    print(f"\nkeys were read from {KEYS.name}; none of them is in git.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
