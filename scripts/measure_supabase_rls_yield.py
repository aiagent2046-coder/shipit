"""How often is a Supabase table actually exposed through the anon key?

The go/no-go number for SUPABASE_RLS_YIELD_PLAN.md Part A, and the same rule
that governed the CORS experiment applies: nothing gets built until this comes
back. That one cost a day and returned 0 of 26; the point of running this first
is to find out cheaply whether this class is different.

    repos
      └─ uses Supabase?                ← else the question does not apply
           └─ commits its own schema?  ← else "cannot be determined", NOT "safe"
                └─ has a PII-shaped table?  ← else public-by-design, no finding
                     └─ anon can read it?   ← RLS off OR a permissive policy
                          => exposed

READS NO ONE'S DATABASE. Every stage above is answered from SQL the repository
itself commits. A committed anon key would let this query a stranger's live
PostgREST endpoint, and it deliberately does not: the project belongs to
someone who never consented, which is the same line "live secret validation"
was ruled out over (PROOF_RUNTIME_CORS_PLAN.md, Not in scope). The live probe
exists in Part C and runs only against a project we own or a consenting
customer. Costs no LLM money and makes no request beyond fetching the pinned
archives.

THE CORPUS IS NOT PRE-FILTERED FOR SUPABASE, on purpose. It is the same
vibe-coded set the CORS measurement used, chosen in July for an unrelated
reason — so it cannot have been selected on its RLS state, the bias that would
make any number here meaningless. "Uses Supabase" is a funnel stage, not an
entry requirement, and its count is part of the result.

Usage (from /opt/shipit — needs outbound access to codeload.github.com):
    .venv/bin/python scripts/measure_supabase_rls_yield.py
    LIMIT=3 .venv/bin/python scripts/measure_supabase_rls_yield.py
    VERBOSE=1 .venv/bin/python scripts/measure_supabase_rls_yield.py

    SCREEN=1 .venv/bin/python scripts/measure_supabase_rls_yield.py
        Resolve CANDIDATES to their current SHAs, report which qualify, and
        print paste-ready pinned tuples for CORPUS. Corpus assembly has to be
        repeatable too — the CORS corpus was assembled by hand and needed
        hand-inspection later to find out what it actually contained.

Writes batch_reports/supabase_rls_yield.json alongside the printed table.
"""

from __future__ import annotations

import io
import json
import os
import re
import sys
import urllib.request
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Pinned, resolved 2026-08-17 for the CORS measurement and reused unchanged.
# Same SHAs, so the two measurements describe the same repositories at the same
# revision and can be read side by side.
CORPUS: tuple[tuple[str, str], ...] = (
    ("PramodDutta/qaskills", "287bbfb352a6384e95db04996d4d92cbe40669f0"),
    ("Avisafety-1/blank-slate", "5e82a79a2b5381bd544d7bbc21722ee7a5d1a4d6"),
    ("dalebooth9-ui/servexaapp", "fc66eccb7f48252cdc5301b168b9d323e16a8775"),
    ("aliganey2016000-del/Minhaaj.com",
     "40a795583193f374318776ee0070da21764bf841"),
    ("5streams/peri-track-insights-quiz",
     "66e6bdcfa8ac844648eefa007d9e54a3f31f5d77"),
    ("dzianisv/VibeBrowserProductPage",
     "d767bc1246c38d32045ffe51407278b6658155ed"),
    ("SahonSrabon/zombiecodersmarteditor",
     "a787a111ede8c17ad23cd38a46eaa0f39b543aa0"),
    ("tscircuit/tscircuit.com", "0b90e089be74e88e3464377a14ae6b20f22d0720"),
    ("aiagent2046-coder/ai-co-founder-matching",
     "c15be34f488521123a0ff77a30a7f885c3f1fdc6"),
)

# SCREEN=1 candidates: unpinned slugs to evaluate for admission to CORPUS.
# Empty until someone has a reason to widen the corpus — a list of repositories
# nobody has looked at is not a corpus, and adding names here without running
# the screen is how a measurement acquires a population it cannot describe.
CANDIDATES: tuple[str, ...] = ()

OUT = Path(__file__).resolve().parent.parent / "batch_reports"

# --- the oracle -------------------------------------------------------------
#
# Two traps, and they are the entire reason this file is longer than a grep.
#
# 1. RLS enabled is NOT the same as protected. `USING (true)` is the same hole
#    wearing a seatbelt, and a measurement that greps for ENABLE ROW LEVEL
#    SECURITY calls it secure and undercounts.
# 2. A table anyone may read is not automatically a finding. `products`,
#    `blog_posts`, a public leaderboard — those are APIs. Counting them is the
#    same error as scoring `Access-Control-Allow-Origin: *` without credentials
#    as an exploit, which this project already made once and removed.

PRIVATE_TABLE_NAMES = frozenset({
    "users", "user", "profiles", "profile", "accounts", "account",
    "customers", "clients", "members", "subscribers", "leads", "contacts",
    "orders", "payments", "invoices", "transactions", "subscriptions",
    "messages", "chats", "conversations", "notifications", "sessions",
    "bookings", "appointments", "applications", "submissions", "responses",
    "waitlist", "signups", "feedback", "tickets", "documents", "files",
    "api_keys", "tokens", "credentials", "secrets", "settings",
})

# A public-by-design table stays out of the numerator even when it carries a
# name fragment below. Checked first, deliberately.
PUBLIC_BY_DESIGN = frozenset({
    "posts", "post", "blog", "blogs", "articles", "products", "product",
    "categories", "tags", "pages", "faqs", "features", "plans", "pricing",
    "testimonials", "reviews", "events", "locations", "stores",
})

PRIVATE_COLUMN_HINTS: tuple[str, ...] = (
    "email", "phone", "mobile", "address", "postcode", "zip_code",
    "password", "passwd", "hash", "salt",
    "token", "api_key", "secret", "credential",
    "stripe_", "customer_id", "payment", "card_last", "iban",
    "ssn", "tax_id", "passport", "birth", "dob",
    "user_id", "owner_id", "auth_id",
    "ip_address", "user_agent",
    "notes", "message", "content",
)

_CREATE_TABLE = re.compile(
    r"create\s+table\s+(?:if\s+not\s+exists\s+)?"
    r'(?:"?(?P<schema>[a-z0-9_]+)"?\s*\.\s*)?"?(?P<name>[a-z0-9_]+)"?\s*\('
    r"(?P<body>.*?)\)\s*;",
    re.IGNORECASE | re.DOTALL,
)
_ENABLE_RLS = re.compile(
    r"alter\s+table\s+(?:only\s+)?"
    r'(?:"?(?:[a-z0-9_]+)"?\s*\.\s*)?"?(?P<name>[a-z0-9_]+)"?\s+'
    r"enable\s+row\s+level\s+security",
    re.IGNORECASE,
)
_CREATE_POLICY = re.compile(
    r"create\s+policy\s+(?P<pname>\"[^\"]+\"|'[^']+'|[a-z0-9_]+)\s+on\s+"
    r'(?:"?(?:[a-z0-9_]+)"?\s*\.\s*)?"?(?P<table>[a-z0-9_]+)"?'
    r"(?P<rest>.*?);",
    re.IGNORECASE | re.DOTALL,
)
_FOR_CLAUSE = re.compile(r"\bfor\s+(select|insert|update|delete|all)\b",
                         re.IGNORECASE)
_TO_CLAUSE = re.compile(r"\bto\s+([a-z0-9_,\s\"]+?)(?=\busing\b|\bwith\b|$)",
                        re.IGNORECASE)
_USING_CLAUSE = re.compile(r"\busing\s*\((?P<expr>.*?)\)\s*(?:with\s+check|$)",
                           re.IGNORECASE | re.DOTALL)


@dataclass
class Table:
    name: str
    schema: str
    columns: list[str] = field(default_factory=list)
    rls_enabled: bool = False
    open_policy: str = ""      # the policy text that leaves anon a read
    policies_for_read: int = 0

    @property
    def private_shaped(self) -> tuple[bool, str]:
        """Does this table look like it holds data the app treats as private?

        Returns (verdict, why) — the reason is printed so a human can overrule
        a heuristic that is, unavoidably, a heuristic.
        """
        low = self.name.lower()
        singular = low[:-1] if low.endswith("s") else low
        if low in PUBLIC_BY_DESIGN or singular in PUBLIC_BY_DESIGN:
            return False, f"`{self.name}` reads as public-by-design"
        if low in PRIVATE_TABLE_NAMES or singular in PRIVATE_TABLE_NAMES:
            return True, f"table name `{self.name}`"
        hit = next((c for c in self.columns
                    if any(h in c.lower() for h in PRIVATE_COLUMN_HINTS)), "")
        if hit:
            return True, f"column `{hit}`"
        return False, "no private-looking table name or column"

    @property
    def anon_readable(self) -> tuple[bool, str]:
        """Can the anon role read this table?

        RLS off  -> yes, everything is readable.
        RLS on   -> only if some SELECT-applicable policy is effectively public.
                    RLS on with NO read policy is default-deny, i.e. secure.
        """
        if self.schema not in ("public", ""):
            return False, f"schema `{self.schema}` is not exposed by PostgREST"
        if not self.rls_enabled:
            return True, "RLS never enabled"
        if self.open_policy:
            return True, f"permissive policy: {self.open_policy}"
        if self.policies_for_read == 0:
            return False, "RLS on, no read policy (default deny)"
        return False, "RLS on with a predicated read policy"


def _columns(body: str) -> list[str]:
    """Column names from a CREATE TABLE body. Table-level constraints skipped:
    they start with a keyword, not an identifier."""
    cols: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            cols.append("".join(current))
            current = []
        else:
            current.append(ch)
    cols.append("".join(current))

    out: list[str] = []
    skip = {"primary", "foreign", "unique", "check", "constraint", "exclude",
            "like", "partition"}
    for raw in cols:
        token = raw.strip().split()
        if not token:
            continue
        name = token[0].strip('"').strip("`")
        if name.lower() in skip or not re.fullmatch(r"[a-z0-9_]+", name, re.I):
            continue
        out.append(name)
    return out


def _policy_leaves_read_open(rest: str) -> tuple[bool, bool, str]:
    """(applies_to_read, leaves_anon_a_read, description).

    A policy is a read grant when its FOR clause is SELECT or ALL, or absent
    (which means ALL). It leaves anon a read when it targets anon/public and
    its USING predicate is a constant truth — or is missing entirely.
    """
    for_match = _FOR_CLAUSE.search(rest)
    command = (for_match.group(1).lower() if for_match else "all")
    if command not in ("select", "all"):
        return False, False, ""

    to_match = _TO_CLAUSE.search(rest)
    roles = (to_match.group(1) if to_match else "public").lower()
    roles = {r.strip().strip('"') for r in roles.split(",") if r.strip()}
    # No TO clause means PUBLIC. `authenticated` alone does not expose anon.
    if roles and not (roles & {"public", "anon"}):
        return True, False, ""

    using = _USING_CLAUSE.search(rest)
    if not using:
        # A SELECT policy with no USING is not valid PostgreSQL, but a FOR ALL
        # policy carrying only WITH CHECK is: it constrains writes and leaves
        # reads unqualified.
        return True, True, "read policy with no USING predicate"

    expr = " ".join(using.group("expr").split()).lower()
    if re.fullmatch(r"true|1\s*=\s*1|\(\s*true\s*\)", expr):
        return True, True, f"USING ({expr})"
    return True, False, ""


def parse_schema(sql: str) -> dict[str, Table]:
    """Read the RLS-relevant facts out of committed SQL.

    NOT a SQL parser. It reads Supabase migrations — a narrow, largely
    generated dialect — and answers three questions: which tables exist, which
    have RLS enabled, and which policies leave anon a read.
    """
    tables: dict[str, Table] = {}
    for m in _CREATE_TABLE.finditer(sql):
        name = m.group("name")
        tables[name.lower()] = Table(
            name=name,
            schema=(m.group("schema") or "public").lower(),
            columns=_columns(m.group("body")),
        )

    for m in _ENABLE_RLS.finditer(sql):
        t = tables.get(m.group("name").lower())
        if t:
            t.rls_enabled = True

    for m in _CREATE_POLICY.finditer(sql):
        t = tables.get(m.group("table").lower())
        if not t:
            continue
        is_read, open_read, why = _policy_leaves_read_open(m.group("rest"))
        if is_read:
            t.policies_for_read += 1
        if open_read and not t.open_policy:
            t.open_policy = why
    return tables


# --- repository inspection --------------------------------------------------

_SUPABASE_MARKERS = ("@supabase/supabase-js", "supabase.co",
                     "SUPABASE_URL", "SUPABASE_ANON_KEY", "createClient(")
_SCHEMA_PATHS = ("supabase/migrations/", "supabase/schema", "migrations/",
                 "schema.sql", "db/", "database/", "sql/")


@dataclass
class RepoResult:
    slug: str
    sha: str
    uses_supabase: bool = False
    schema_files: list[str] = field(default_factory=list)
    tables: int = 0
    private_tables: int = 0
    exposed_tables: list[str] = field(default_factory=list)
    exposure_reasons: list[str] = field(default_factory=list)
    stage: str = "not_attempted"
    error: str = ""

    @property
    def measurable(self) -> bool:
        return self.uses_supabase and bool(self.schema_files)


def fetch(slug: str, sha: str) -> zipfile.ZipFile:
    url = f"https://codeload.github.com/{slug}/zip/{sha}"
    return zipfile.ZipFile(io.BytesIO(
        urllib.request.urlopen(url, timeout=180).read()))


def _texts(zf: zipfile.ZipFile, suffixes: tuple[str, ...],
           limit_bytes: int = 400_000) -> dict[str, str]:
    out: dict[str, str] = {}
    for zi in zf.infolist():
        if zi.is_dir() or zi.file_size > limit_bytes:
            continue
        rel = zi.filename.split("/", 1)[-1]
        if rel.lower().endswith(suffixes):
            try:
                out[rel] = zf.read(zi).decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001 — an unreadable file is not data
                continue
    return out


def measure_one(slug: str, sha: str) -> RepoResult:
    result = RepoResult(slug=slug, sha=sha)
    try:
        zf = fetch(slug, sha)
    except Exception as exc:  # noqa: BLE001
        result.stage = "fetch_failed"
        result.error = f"{type(exc).__name__}: {exc}"[:160]
        return result

    code = _texts(zf, (".ts", ".tsx", ".js", ".jsx", ".json", ".env",
                       ".example", ".toml", ".md"))
    result.uses_supabase = any(
        marker in text for text in code.values() for marker in _SUPABASE_MARKERS
    )
    if not result.uses_supabase:
        result.stage = "no_supabase"
        return result

    sql_files = _texts(zf, (".sql",))
    result.schema_files = sorted(
        n for n in sql_files
        if any(p in n.lower() for p in _SCHEMA_PATHS) or n.lower().endswith(".sql")
    )[:40]
    if not result.schema_files:
        # NOT "secure". The repository simply does not carry the evidence, and
        # saying otherwise is the disjoint-population error the CORS detector
        # ran into: a method reporting on a population it cannot see.
        result.stage = "no_committed_schema"
        return result

    tables = parse_schema("\n".join(sql_files.values()))
    result.tables = len(tables)
    for t in tables.values():
        private, why_private = t.private_shaped
        if not private:
            continue
        result.private_tables += 1
        readable, why_readable = t.anon_readable
        if readable:
            result.exposed_tables.append(t.name)
            result.exposure_reasons.append(
                f"{t.name}: {why_private}; {why_readable}")

    result.stage = "exposed" if result.exposed_tables else "not_exposed"
    return result


# --- corpus screening -------------------------------------------------------

def screen(candidates: tuple[str, ...]) -> int:
    """Resolve each candidate to its current default-branch SHA and report
    whether it qualifies, printing paste-ready CORPUS lines."""
    if not candidates:
        print("CANDIDATES is empty — nothing to screen.\n"
              "Add slugs to CANDIDATES first; the point of this mode is that\n"
              "corpus assembly leaves a record instead of being done by hand.")
        return 1

    print(f"screening {len(candidates)} candidates\n")
    qualified: list[tuple[str, str]] = []
    for slug in candidates:
        try:
            with urllib.request.urlopen(
                f"https://api.github.com/repos/{slug}/commits?per_page=1",
                timeout=60,
            ) as response:
                sha = json.loads(response.read())[0]["sha"]
        except Exception as exc:  # noqa: BLE001
            print(f"  {slug:45.45s} resolve failed: {type(exc).__name__}")
            continue
        r = measure_one(slug, sha)
        mark = "OK  " if r.measurable else "skip"
        print(f"  {mark} {slug:45.45s} supabase={r.uses_supabase} "
              f"schema_files={len(r.schema_files)} {r.error}")
        if r.measurable:
            qualified.append((slug, sha))

    print(f"\n{len(qualified)} of {len(candidates)} qualify. Paste into CORPUS:\n")
    for slug, sha in qualified:
        print(f'    ("{slug}",\n     "{sha}"),')
    return 0


def main() -> int:
    if (os.environ.get("SCREEN") or "").strip().lower() in ("1", "true", "yes"):
        return screen(CANDIDATES)

    verbose = (os.environ.get("VERBOSE") or "").strip().lower() in (
        "1", "true", "yes")
    limit = int(os.environ.get("LIMIT", "0")) or len(CORPUS)
    corpus = CORPUS[:limit]
    OUT.mkdir(exist_ok=True)

    print("Reads no one's database: every verdict below comes from SQL the\n"
          "repository itself commits. See SUPABASE_RLS_YIELD_PLAN.md for why\n"
          "the live probe is gated on owning or being invited to the project.\n")

    results: list[RepoResult] = []
    for i, (slug, sha) in enumerate(corpus):
        print(f"[{i + 1}/{len(corpus)}] {slug}", flush=True)
        r = measure_one(slug, sha)
        results.append(r)
        print(f"    supabase={r.uses_supabase} schema_files={len(r.schema_files)} "
              f"tables={r.tables} private={r.private_tables} "
              f"stage={r.stage}", flush=True)
        if r.error:
            print(f"    error: {r.error}", flush=True)
        # Every exposed verdict prints its reason. A regex over SQL is exactly
        # the kind of thing that looks right and counts wrong, so each row has
        # to be checkable by a human without opening the JSON.
        for reason in r.exposure_reasons:
            print(f"    EXPOSED {reason}", flush=True)
        if verbose and r.schema_files:
            print(f"    schema: {', '.join(r.schema_files[:6])}", flush=True)

    # A repository we could not download was not examined, and must not sit in
    # a denominator as though it had been. Left in, the summary above reads
    # "uses Supabase: 0" for a corpus nobody ever opened — the error/failure
    # conflation this project keeps removing, arriving this time through
    # arithmetic instead of a status string. Found by running it: the first
    # smoke run 403'd on every fetch and printed a clean-looking zero.
    unreachable = [r for r in results if r.stage == "fetch_failed"]
    examined = [r for r in results if r.stage != "fetch_failed"]

    total = len(examined)
    supa = [r for r in examined if r.uses_supabase]
    measurable = [r for r in supa if r.schema_files]
    blind = [r for r in supa if not r.schema_files]
    with_private = [r for r in measurable if r.private_tables]
    exposed = [r for r in measurable if r.exposed_tables]

    print("\n=== SUPABASE RLS EXPOSURE ===")
    print(f"{'repo':45s} {'supa':6s} {'schema':7s} {'tables':7s} stage")
    for r in results:
        print(f"{r.slug:45.45s} {str(r.uses_supabase):6s} "
              f"{str(bool(r.schema_files)):7s} {r.tables:<7d} {r.stage}")

    if unreachable:
        print()
        print(f"!! {len(unreachable)} of {len(results)} repositories could not "
              f"be downloaded and were NOT examined.")
        for r in unreachable:
            print(f"     {r.slug}: {r.error}")
        print("   They are excluded from every count below. A partially "
              "fetched corpus\n   produces a number nobody should quote — "
              "fix the fetch and re-run.")

    print()
    print(f"repos examined                    : {total}")
    print(f"  uses Supabase                   : {len(supa)}"
          f"  {_pct(len(supa), total)}")
    print(f"    commits its own schema        : {len(measurable)}"
          f"  {_pct(len(measurable), len(supa))} of Supabase repos")
    print(f"      has a private-shaped table  : {len(with_private)}"
          f"  {_pct(len(with_private), len(measurable))} of measurable")
    print(f"        anon can read it          : {len(exposed)}"
          f"  {_pct(len(exposed), len(with_private))} of those")
    print()
    print(f"EXPOSURE RATE: {len(exposed)}/{len(measurable)} "
          f"{_pct(len(exposed), len(measurable))} of repos whose schema we can "
          f"actually read.")
    print(f"BLIND SPOT   : {len(blind)}/{len(supa)} "
          f"{_pct(len(blind), len(supa))} of Supabase repos commit no schema. "
          f"Those are NOT secure — they are undetermined, and they are the "
          f"population a live probe exists to cover.")
    print()
    print("Quote both lines or neither. Collapsing them into one '% vulnerable'\n"
          "is the mistake the CORS detector made: implying a method saw a\n"
          "population it structurally cannot.")

    payload = {
        "measured_at": __import__("time").strftime(
            "%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
        "corpus_size": len(results),
        "examined": total,
        "unreachable": len(unreachable),
        "uses_supabase": len(supa),
        "measurable": len(measurable),
        "blind_spot": len(blind),
        "with_private_table": len(with_private),
        "exposed": len(exposed),
        "results": [asdict(r) for r in results],
    }
    path = OUT / "supabase_rls_yield.json"
    path.write_text(json.dumps(payload, indent=1))
    print(f"\nwrote {path}")
    # Non-zero on an incomplete corpus so a wrapper, or a tired operator, does
    # not read "it finished" as "it measured".
    return 1 if unreachable else 0


def _pct(part: int, whole: int) -> str:
    return f"({part / whole:.0%})" if whole else "(n/a)"


if __name__ == "__main__":
    raise SystemExit(main())
