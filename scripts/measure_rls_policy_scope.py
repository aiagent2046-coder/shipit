"""Does the cross-tenant gap matter? Prevalence of non-per-user RLS policies.

The anon-only rls_probe is blind to cross-tenant reads: a table with RLS ON but
a policy that scopes to "any authenticated user" rather than to the caller
returns 200 [] to anon (probe says not-exposed) while every logged-in user reads
everyone's rows. Closing that needs an AUTHENTICATED probe -- a signup (a write)
on the customer's project, a second identity, and ownership reasoning about the
rows. A real escalation, so it is measured before it is built, the same test
that sent BOLA-in-a-route to the model.

The policy predicate is usually in a committed migration (`create policy ...
using (...)`), so this is a cheap static read of the corpus. Each read-applicable
policy is classified by its USING clause:

  per_user      references auth.uid()/jwt sub compared to an owner column, or an
                owner column at all -> scopes rows to the caller. The anon probe
                plus this is enough; cross-tenant is closed by the policy.
  cross_tenant  constant-true (`using (true)`) OR authenticated-only (checks a
                role/logged-in state but no per-row owner) -> any signed-in user
                reads every row. THIS is the shape the anon probe cannot see.
  other         a predicate we cannot classify cheaply -> reported, not guessed.

The denominator is read-applicable policies on RLS-on tables. A high
cross_tenant share means the gap is real and common -> the authenticated probe
earns its complexity. A low share means the per-user policy is the norm and the
anon probe already covers the exposure that exists.

Reuses read_committed_sql + parse_schema, so the count agrees with what the RLS
detector already sees.

    PER_STRATUM=40 python scripts/measure_rls_policy_scope.py
"""

from __future__ import annotations

import io
import os
import re
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scan.rls import read_committed_sql  # noqa: E402
from app.scan.sql_schema import _is_constant_true, parse_schema  # noqa: E402

DATA = Path(__file__).resolve().parent / "data"
STRATA = (("Lovable", "lovable_candidates.txt"),
          ("bolt", "bolt_candidates.txt"),
          ("hand-written", "handwritten_candidates.txt"))

# Per-row ownership: the predicate ties a row to the caller. auth.uid()/jwt sub,
# or an owner column compared to something. The auth rubric's vocabulary.
_PER_USER = re.compile(
    r"auth\.uid\s*\(\)|auth\.jwt\s*\(\)|current_setting\s*\(\s*'request\.jwt"
    r"|\b(user_id|owner_id|team_id|workspace_id|org_id|account_id|tenant_id|"
    r"created_by|author_id|profile_id|member_id)\b",
    re.I)

# Authenticated-only, no per-row scoping: any logged-in user passes. The
# cross-tenant shape when NO owner column is also present.
_AUTH_ONLY = re.compile(
    r"auth\.role\s*\(\)\s*=\s*'authenticated'"
    r"|\(\s*select\s+auth\.role.*authenticated"
    r"|auth\.uid\s*\(\)\s+is\s+not\s+null"
    r"|current_user\s*=\s*'authenticated'",
    re.I)


@dataclass
class Counts:
    read_policies: int = 0
    per_user: int = 0
    cross_tenant: int = 0
    # cross_tenant split by whether the ANON probe already sees it:
    public_true: int = 0    # constant-true AND reaches anon -> current probe fires
    auth_only: int = 0      # logged-in-only, or true-but-authenticated-role ->
                            # needs an authenticated (signup) probe
    other: int = 0
    hits: list = field(default_factory=list)   # (table, kind, using)


def _classify(using: str, reaches_anon: bool) -> str:
    """Return per_user | public_true | auth_only | other.

    The cross-tenant shape splits on WHO the policy opens to, which is what
    decides whether the existing anon probe already covers it:

      public_true  constant-true AND the policy reaches anon (no TO clause, or
                   TO public/anon) -> anon reads the table directly, so the
                   current rls_probe ALREADY fires on it. No new probe needed.
      auth_only    logged-in-only (auth.role()='authenticated', uid IS NOT
                   NULL), OR constant-true but scoped TO authenticated -> anon
                   gets [], every signed-in user reads all rows. This is the
                   part the anon probe cannot see; an authenticated probe would.
    """
    u = (using or "").strip()
    const_true = (not u) or _is_constant_true(u)

    if const_true and reaches_anon:
        return "public_true"
    if const_true:            # true, but only for a non-anon role (TO authenticated)
        return "auth_only"

    owner_col = re.search(
        r"\b(user_id|owner_id|team_id|workspace_id|org_id|account_id|"
        r"tenant_id|created_by|author_id|profile_id|member_id)\b", u, re.I)
    auth_only = _AUTH_ONLY.search(u) is not None
    per_user = _PER_USER.search(u) is not None

    if per_user and not (auth_only and not owner_col):
        return "per_user"
    if auth_only:
        return "auth_only"
    return "other"


def _repo(slug: str) -> Counts | None:
    try:
        raw = urllib.request.urlopen(
            f"https://codeload.github.com/{slug}/zip/HEAD", timeout=90).read()
    except Exception:  # noqa: BLE001
        return None
    c = Counts()
    try:
        sql, _paths = read_committed_sql(io.BytesIO(raw))
    except Exception:  # noqa: BLE001
        return c
    if not sql.strip():
        return c
    try:
        schema = parse_schema(sql)
    except Exception:  # noqa: BLE001
        return c
    for table in schema.values():
        if not getattr(table, "rls_enabled", True):
            continue
        for pol in getattr(table, "policies", []):
            if not pol.applies_to_read:
                continue
            c.read_policies += 1
            kind = _classify(pol.using, pol.reaches_anon)
            setattr(c, kind, getattr(c, kind) + 1)
            if kind in ("public_true", "auth_only"):
                c.cross_tenant += 1
                c.hits.append((table.name, kind, (pol.using or "(no using)")[:50]))
    return c


def _load(f: str, per: int) -> list[str]:
    out = []
    for line in (DATA / f).read_text().splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(s)
        if len(out) >= per:
            break
    return out


def _pct(num: int, den: int) -> str:
    if den == 0:
        return "n/a (0)"
    import math
    z, p = 1.96, num / den
    d = 1 + z * z / den
    centre = (p + z * z / (2 * den)) / d
    half = z * math.sqrt(p * (1 - p) / den + z * z / (4 * den * den)) / d
    return (f"{num}/{den} = {100 * p:.0f}% "
            f"[95% CI {100 * max(0, centre - half):.0f}"
            f"-{100 * min(1, centre + half):.0f}%]")


def main() -> int:
    per = int(os.environ.get("PER_STRATUM", "40"))
    workers = int(os.environ.get("WORKERS", "12"))
    jobs = [(slug, lab) for lab, f in STRATA for slug in _load(f, per)]
    print(f"scanning {len(jobs)} repositories for committed RLS policy scope\n",
          flush=True)
    with ThreadPoolExecutor(workers) as pool:
        res = list(pool.map(lambda j: (j[1], _repo(j[0]), j[0]), jobs))
    ok = [(lab, c, slug) for lab, c, slug in res if c is not None]
    print(f"fetched: {len(ok)}/{len(jobs)}\n")

    tot = Counts()
    apps_with_policies = 0
    apps_with_auth_only = 0
    for lab, _f in STRATA:
        rows = [c for lbl, c, _ in ok if lbl == lab]
        rp = sum(c.read_policies for c in rows)
        pu = sum(c.per_user for c in rows)
        pt = sum(c.public_true for c in rows)
        ao = sum(c.auth_only for c in rows)
        ot = sum(c.other for c in rows)
        tot.read_policies += rp
        tot.per_user += pu
        tot.public_true += pt
        tot.auth_only += ao
        tot.other += ot
        apps_with_policies += sum(1 for c in rows if c.read_policies)
        apps_with_auth_only += sum(1 for c in rows if c.auth_only)
        print(f"{lab}")
        print(f"  read policies (denominator) ..... {rp}")
        print(f"  per-user (scopes to caller) ..... {_pct(pu, rp)}")
        print(f"  public true (anon ALREADY sees) . {_pct(pt, rp)}"
              f"   <- current probe fires")
        print(f"  auth-only (needs signup probe) .. {_pct(ao, rp)}"
              f"   <- the real gap")
        print(f"  other/unclassified .............. {ot}")
        print()

    print("=" * 62)
    print(f"POOLED public-true (anon already sees): "
          f"{_pct(tot.public_true, tot.read_policies)}")
    print(f"POOLED auth-only (uncovered gap):       "
          f"{_pct(tot.auth_only, tot.read_policies)}")
    print(f"POOLED per-user:                        "
          f"{_pct(tot.per_user, tot.read_policies)}")
    print(f"apps with an auth-only read policy: {apps_with_auth_only}/{len(ok)}")
    print("=" * 62)

    print("\nAUTH-ONLY hits (the uncovered part -- read by hand):")
    shown = 0
    for _lab, c, slug in ok:
        for table, kind, using in c.hits:
            if kind == "auth_only" and shown < 16:
                print(f"  {slug}  `{table}`  using: {using}")
                shown += 1

    print("\nREADING: the anon probe ALREADY covers public-true. The auth-only "
          "slice is\nthe part it cannot see. A large auth-only share justifies "
          "the signup probe;\na small one means the current probe already "
          "catches most of the exposure.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
