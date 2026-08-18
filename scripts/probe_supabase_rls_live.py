"""Part C: the RLS probe against a LIVE Supabase project.

This is the only script here that touches a real database with real people's
data in it. Everything about it is shaped by that.

CONSENT IS NOT A FLAG. `RLS_PROBE_CONSENT` must be set to the exact string
`i-own-this-project`. A boolean would get set once and stay set; a sentence
someone has to type is a sentence they have to mean. The probe itself refuses
without `consent=True` — this is the second lock, on the operator rather than
the caller.

THE KEY NEVER TOUCHES DISK OR STDOUT. It arrives in the environment, goes into
one request, and is never printed, logged or written to the report. It is a
public key by design, but "public by design" is not a reason to scatter copies
of it through a repository and a terminal history.

AT MOST THREE ROWS, NO VALUES. app.proof.rls_oracle.summarise_rows keeps
columns, a count and value LENGTHS. Nothing a person wrote or that identifies
them leaves the process.

    export SUPABASE_ANON_KEY=...            # not echoed anywhere
    export RLS_PROBE_CONSENT=i-own-this-project
    python scripts/probe_supabase_rls_live.py <project-ref> table [table ...]
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.proof.rls_probe import run_rls_probe  # noqa: E402

CONSENT_PHRASE = "i-own-this-project"


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    ref, tables = argv[0], argv[1:]

    if (os.environ.get("RLS_PROBE_CONSENT") or "").strip() != CONSENT_PHRASE:
        print(f"refusing: set RLS_PROBE_CONSENT={CONSENT_PHRASE} to confirm "
              f"this project is yours to probe", file=sys.stderr)
        return 2

    key = (os.environ.get("SUPABASE_ANON_KEY") or "").strip()
    if not key:
        print("refusing: SUPABASE_ANON_KEY is not set", file=sys.stderr)
        return 2
    if not key.isascii():
        # MEASURED 2026-08-18: the key arrived with its characters replaced
        # one-for-one by bullets — a masked rendering that had been copied
        # instead of the value. Length matched exactly, so nothing looked
        # wrong until httpx raised UnicodeEncodeError building the header, and
        # the probe reported that as "the request did not complete" for every
        # table.
        #
        # That is a true statement and a useless one. A key that cannot be put
        # in a header is a configuration mistake the operator can fix in ten
        # seconds, not an infrastructure failure, and the two must not read
        # the same. Caught here, before any request, and named.
        bad = sorted({c for c in key if not c.isascii()})[:5]
        print(f"refusing: SUPABASE_ANON_KEY contains non-ASCII characters "
              f"({''.join(bad)!r}). This is almost always a MASKED value that "
              f"was copied instead of the key itself — the mask preserves the "
              f"length, so it looks right.", file=sys.stderr)
        return 2

    url = f"https://{ref}.supabase.co"
    print(f"project: {url}")
    print(f"key    : anon, {len(key)} chars (not shown)\n")

    exposed = 0
    for table in tables:
        attempt = run_rls_probe(
            project_url=url, anon_key=key, table=table,
            consent=True, limit=3,
        )
        mark = {"success": "EXPOSED ", "failure": "closed  ",
                "skipped": "skipped ", "error": "ERROR   "}.get(
                    attempt.status, "?       ")
        print(f"{mark}{table}")
        print(f"         {attempt.detail}")
        # The evidence is what would be stored and rendered; printing it here
        # is also the check that it carries no value from anyone's row.
        print(f"         {attempt.evidence}\n")
        if attempt.status == "success":
            exposed += 1

    print(f"{exposed} of {len(tables)} tables readable by the anon key.")
    # Non-zero when something is exposed: this is a finding, and a wrapper
    # should be able to notice without parsing the text.
    return 1 if exposed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
