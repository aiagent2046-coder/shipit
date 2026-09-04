"""How often does a routed React/Next app ship with no error boundary?

The DRYDOCK_LENS_PLAN experiment, made concrete for question 1 of the frontend
rubric — the cheapest of the six, the one the rubric says is "settled by reading
lines". No LLM spend, no browser.

    python scripts/measure_error_boundary.py                    # pinned SERIES
    python scripts/measure_error_boundary.py owner/repo@<sha> ...
    python scripts/measure_error_boundary.py --from-file /root/audited-repos.txt
    PER_STRATUM=40 python scripts/measure_error_boundary.py --strata

THREE VERDICTS, NOT TWO. A repository is `MISSING`, `ok`, or `undetermined`, and
the third is the reason app/scan/error_boundary.py returns a BoundaryScan rather
than a list. A repository whose read budget ran out has not been measured, and
folding it into either of the other two would put a number in this report that
nothing established. The incidence is reported over DECIDED repositories, with
the undecided ones counted beside it — a denominator that quietly absorbed them
is how a measurement flatters itself.

THE REASON COMES FROM THE SCAN, NOT FROM A SECOND COPY OF ITS LOGIC. An earlier
version of this script re-derived why a repository was silent, which meant the
report could explain a verdict using logic that did not produce it. The whole
deliverable here is an accountable per-repo call, so the analyzer says why and
this prints what it said.

TWO DENOMINATORS, AND ONLY ONE ANSWERS THE QUESTION. Incidence over every
submitted repository is diluted by servers, CLIs and component libraries — none
of which have a screen to blank, so none of them are evidence either way. The
plan asks what a free frontend tier would have to say to the people it is for,
and that is the incidence among MOUNTED react/next apps. Both are printed, the
useful one first, with the mount classes beside them.

THE CORPUS IS SMALL AND THAT IS THE POINT OF SAYING SO. batch_audit.SERIES pins
three repositories by full commit SHA; three is an anecdote, not an incidence.
`--from-file` reads the audited repositories out of a `repo_url|content_hash`
dump and measures them.

    THE STORED content_hash IS READ AND IGNORED, deliberately. It answers "is
    this the same code the LLM saw", which is the ground-truth question for
    comparing against stored findings. Incidence of a DETERMINISTIC rule does
    not need it — any real repository counts — and requiring a hash match would
    have discarded most of the corpus for a property this measurement never
    uses. The two experiments were conflated in the plan; they are separate.

A head resolved today is not reproducible tomorrow, which is why SERIES pins
SHAs at all. So `--from-file` resolves each default branch to its commit SHA,
measures THAT commit, and prints the `slug@sha` list to replay the run exactly.
"""

from __future__ import annotations

import datetime
import io
import json
import os
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scan.checks import archive_root  # noqa: E402
from app.scan.error_boundary import (  # noqa: E402
    _MAX_FILE_BYTES,
    _RENDER_CALLS,
    _is_source,
    _norm,
    COVERAGE_EXHAUSTED,
    MOUNT_UNKNOWN,
    MOUNT_YES,
    scan_error_boundary,
)


def _render_call_anywhere(data: bytes) -> str:
    """The mount the analyzer stopped before reaching, or "".

    NOT a product code path, and it must not become one. The scanner stops at a
    boundary token on purpose -- a boundary means silence whatever else is true,
    and reading on would buy nothing for the FINDING. It buys something for the
    MEASUREMENT: a repository silenced that early never had its mount decided,
    so it left the incidence denominator, and only "is there a render call
    further in?" says whether that exclusion was right. Skips the same
    directories the scanner does, so a createRoot inside node_modules or a
    committed dist/ cannot answer yes.
    """
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        raw_names = zf.namelist()
        root = archive_root(raw_names)
        for name in _norm(raw_names):
            if not _is_source(name):
                continue
            try:
                body = zf.read(root + name if root else name)
            except KeyError:
                continue
            text = body[:_MAX_FILE_BYTES].decode("utf-8", errors="ignore")
            if any(call in text for call in _RENDER_CALLS):
                return name
    return ""

try:
    from scripts.batch_audit import SERIES, fetch_repack  # noqa: E402
except Exception:  # noqa: BLE001 — the corpus is optional, the fixtures are not
    SERIES = []
    fetch_repack = None


# --------------------------------------------------------------------------- #
# fixtures — a standalone proof of the decisions before any network is used
# --------------------------------------------------------------------------- #
# tests/test_error_boundary.py is the authoritative set; these are the handful
# that would make the corpus numbers meaningless if they were wrong, kept here
# so running this file alone still proves the analyzer first.

def _zip(files: dict[str, str]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    buf.seek(0)
    return buf


_ROUTED_NEXT = {
    "package.json": '{"dependencies":{"next":"14","react":"18","react-dom":"18"}}',
    "app/layout.tsx": "export default function L({children}){return children}",
    "app/page.tsx": "export default function P(){return <div>hi</div>}",
}
_ROUTED_SPA = {
    "package.json": '{"dependencies":{"react":"18","react-dom":"18"}}',
    "src/main.tsx": ("import {createRoot} from 'react-dom/client';"
                     "createRoot(el).render(<App/>)"),
    "src/App.tsx": "export default function App(){return <div/>}",
}
_LIB_PKG = '{"name":"ui-kit","dependencies":{"react":"18","react-dom":"18"}}'


def _fixtures() -> bool:
    cases = [
        ("routed Next, no boundary", _ROUTED_NEXT, True),
        ("mounted SPA, no boundary", _ROUTED_SPA, True),
        ("Next with app/error.tsx",
         {**_ROUTED_NEXT,
          "app/error.tsx": "'use client'; export default function E(){return null}"},
         False),
        ("class componentDidCatch present",
         {**_ROUTED_SPA, "src/Boundary.tsx": "class B{componentDidCatch(){}}"},
         False),
        ("react-error-boundary in deps",
         {**_ROUTED_SPA,
          "package.json": ('{"dependencies":{"react":"18","react-dom":"18",'
                           '"react-error-boundary":"4"}}')},
         False),
        # The four shapes the UI gate exists for. Version one fired on all four.
        ("component library with index barrels",
         {"package.json": _LIB_PKG,
          "src/components/Button/index.tsx": "export const B=()=> <button/>"},
         False),
        ("design system barrel",
         {"package.json": _LIB_PKG, "src/index.tsx": "export * from './c'"},
         False),
        ("react-email templates",
         {"package.json": '{"dependencies":{"react":"18"}}',
          "emails/index.tsx": "export default () => <Html/>"},
         False),
        ("docs site with a nested app/ folder",
         {"package.json": '{"dependencies":{"react":"18"}}',
          "website/examples/app/demo/page.tsx": "export default ()=> <div/>"},
         False),
        ("boundary only inside node_modules -> still fires",
         {**_ROUTED_SPA, "node_modules/dep/index.js": "componentDidCatch(){}"},
         True),
        ("non-react repo",
         {"package.json": '{"dependencies":{"express":"4"}}',
          "server.js": "require('express')()"},
         False),
    ]
    ok = True
    print("FIXTURES — the analyzer's decisions")
    for label, files, expect_fire in cases:
        scan = scan_error_boundary(_zip(files))
        fired = bool(scan.findings)
        if fired != expect_fire:
            ok = False
        print(f"  {'OK ' if fired == expect_fire else 'FAIL'}  "
              f"{'FIRES ' if fired else 'silent'}  {label}")
    print(f"  => {'all decisions correct' if ok else 'DECISION FAILURE'}\n")
    return ok


# --------------------------------------------------------------------------- #
# corpus
# --------------------------------------------------------------------------- #

def _slug_sha(arg: str) -> tuple[str, str]:
    slug, _, sha = arg.partition("@")
    if not sha:
        raise SystemExit(f"expected owner/repo@sha, got {arg!r}")
    return slug, sha


def _slug_from_repo_url(raw: str) -> str:
    """`owner/repo` out of whatever the audits table stored."""
    s = raw.strip().removesuffix(".git")
    for prefix in ("https://github.com/", "http://github.com/", "github.com/"):
        if s.startswith(prefix):
            s = s[len(prefix):]
            break
    parts = [p for p in s.split("/") if p]
    return "/".join(parts[:2]) if len(parts) >= 2 else ""


def _api_headers() -> dict[str, str]:
    """Authorization from GITHUB_TOKEN when the environment offers one.

    NOT the same decision as app/ingest/github_fetch.py, which sends no
    Authorization header BY DESIGN because it fetches a URL a stranger supplied
    — a token there would let a caller aim our credentials at repositories they
    cannot see. This script fetches a list WE chose, offline, run by hand. The
    token is read from the environment only: never from /opt/shipit/.env, never
    an argument, and never printed.
    """
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "drydock-measure-error-boundary"}
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _resolve_head(slug: str) -> str:
    """The default branch's current commit SHA, in ONE request.

    RESOLVED AND PRINTED, never used implicitly. A corpus fetched at "whatever
    the branch points at today" is not a measurement anyone can repeat — the
    same rule that made batch_audit.SERIES pin full SHAs ("a branch head would
    silently fork the series"). So a run over a URL list resolves each head
    once, measures that exact commit, and emits the `slug@sha` line needed to
    replay the run byte for byte.

    ONE REQUEST, NOT TWO, and that is what makes the run possible without a
    token. The first version asked /repos/{slug} for the default branch and
    then /commits/{branch} for its head: 86 requests for 43 repositories,
    against an unauthenticated ceiling of 60 an hour. It did not "sometimes
    fall short" — it could not complete, and the second run resolved zero.
    /commits?per_page=1 already answers on the default branch.
    """
    req = urllib.request.Request(  # noqa: S310
        f"https://api.github.com/repos/{slug}/commits?per_page=1",
        headers=_api_headers())
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
        return json.load(resp)[0]["sha"]


def _rate_limit_reset(exc: Exception) -> int | None:
    """The epoch this exception's rate limit clears, or None if it is not one.

    Separated from the message because the CALLER has to act on it: a spent
    quota is a fact about the next request too, not only about this one.
    """
    if not isinstance(exc, urllib.error.HTTPError):
        return None
    if exc.code not in (403, 429):
        return None
    if exc.headers.get("x-ratelimit-remaining") != "0":
        return None
    try:
        return int(exc.headers.get("x-ratelimit-reset", ""))
    except ValueError:
        return 0


def _when(epoch: int) -> str:
    """A time a person can act on. `unix 1788265311` needed a decoder ring to
    answer the only question being asked of it — how long do I wait."""
    if not epoch:
        return "an unknown time"
    when = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    minutes = max(0, round((epoch - time.time()) / 60))
    return f"{when:%Y-%m-%d %H:%M:%S UTC} (in {minutes} min)"


def _why_unresolved(exc: Exception) -> str:
    """Rate limit, gone, or something else — never one word for all three.

    `head unresolved: HTTPError` was printed 43 times for what turned out to be
    a spent rate limit, and it read exactly like 43 deleted repositories. The
    same collapse has cost this project a diagnosis three times.
    """
    reset = _rate_limit_reset(exc)
    if reset is not None:
        return (f"RATE LIMITED — quota resets at {_when(reset)}; set "
                "GITHUB_TOKEN to raise the ceiling from 60/hour to 5000")
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code == 404:
            return "404 — private, renamed or deleted since the audit"
        return f"HTTP {exc.code}"
    return type(exc).__name__


DATA = Path(__file__).resolve().parent / "data"
STRATA = (("Lovable", "lovable_candidates.txt"),
          ("bolt", "bolt_candidates.txt"),
          ("hand-written", "handwritten_candidates.txt"))


def _load_candidates(filename: str, per_stratum: int | None) -> list[str]:
    """The sibling scripts' loader, verbatim in semantics: strip, skip `#`,
    first occurrence wins. The same rules or the counts stop agreeing with
    measure_rls_blind_spot and the others that read these files."""
    slugs: list[str] = []
    seen: set[str] = set()
    for line in (DATA / filename).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line in seen:
            continue
        seen.add(line)
        slugs.append(line)
    return slugs[:per_stratum] if per_stratum else slugs


def _strata_targets(per_stratum: int | None) -> list[tuple[str, str, str]]:
    """`(stratum, slug, sha)` for the three-strata corpus in scripts/data/.

    Resolving a head costs one API request per repository and the anonymous
    ceiling is 60 an hour; the full corpus is 540. So a run over more than 60
    REFUSES without GITHUB_TOKEN rather than resolving the first 60 and
    reporting a stratum that is 60/211 Lovable and 0 of the rest -- a shape
    that would read as a result and be nothing of the kind.
    """
    wanted = [(label, slug) for label, fn in STRATA
              for slug in _load_candidates(fn, per_stratum)]
    if len(wanted) > 60 and not os.environ.get("GITHUB_TOKEN", "").strip():
        raise SystemExit(
            f"{len(wanted)} repositories need {len(wanted)} head resolutions "
            "and the anonymous ceiling is 60 an hour. Set GITHUB_TOKEN, or "
            "PER_STRATUM=20 for a first look that fits.")
    out: list[tuple[str, str, str]] = []
    for label, raw in wanted:
        slug = _slug_from_repo_url(raw)
        if not slug:
            continue
        try:
            out.append((label, slug, _resolve_head(slug)))
        except Exception as exc:  # noqa: BLE001 — gone, or limited
            reset = _rate_limit_reset(exc)
            if reset is not None:
                print(f"  ‼   RATE LIMITED after {len(out)} of {len(wanted)} "
                      f"resolved. Quota resets at {_when(reset)}.")
                break
            print(f"  ??  {slug:45s} head unresolved: {_why_unresolved(exc)}")
    return out


def _targets_from_file(path: Path) -> list[tuple[str, str]]:
    """`repo_url|content_hash` lines (the audits query) or bare repo URLs.

    The content_hash column is READ AND IGNORED here, deliberately. It answers
    "is this the same code the LLM saw", which is the ground-truth question for
    comparing against stored findings. Incidence of a deterministic rule does
    not need it: any real repository counts, and requiring a hash match would
    have thrown away most of the corpus for a property this measurement never
    uses.
    """
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in path.read_text().splitlines():
        raw = line.split("|", 1)[0].strip()
        if not raw:
            continue
        slug = _slug_from_repo_url(raw)
        if not slug or slug in seen:
            continue
        seen.add(slug)
        try:
            out.append((slug, _resolve_head(slug)))
        except Exception as exc:  # noqa: BLE001 — gone private, renamed, limited
            reset = _rate_limit_reset(exc)
            if reset is not None:
                # STOP, do not send the rest. The quota is spent for every
                # request, not just this one -- continuing printed the same
                # sentence 43 times and buried the one fact worth reading
                # under 42 copies of itself, having spent 42 more requests to
                # learn nothing.
                print(f"  ‼   RATE LIMITED after {len(out)} of {len(seen)} "
                      f"resolved. Quota resets at {_when(reset)}.")
                print("      Stopped instead of sending the rest, which would "
                      "all fail. Re-run then,\n      or set GITHUB_TOKEN for "
                      "5000/hour.")
                break
            print(f"  ??  {slug:45s} head unresolved: {_why_unresolved(exc)}")
    return out


def _fetch(slug: str, sha: str) -> bytes:
    if fetch_repack is not None:
        return fetch_repack(slug, sha)
    url = f"https://codeload.github.com/{slug}/zip/{sha}"
    raw = urllib.request.urlopen(url, timeout=120).read()  # noqa: S310
    src = zipfile.ZipFile(io.BytesIO(raw))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        for zi in src.infolist():
            parts = zi.filename.split("/", 1)
            if len(parts) < 2 or not parts[1] or zi.is_dir():
                continue
            dst.writestr(parts[1], src.read(zi))
    return out.getvalue()


def main() -> int:
    if not _fixtures():
        print("fixtures failed — not running the corpus", file=sys.stderr)
        return 1

    args = sys.argv[1:]
    strata_of: dict[str, str] = {}
    if args and args[0] == "--strata":
        per = os.environ.get("PER_STRATUM", "").strip()
        per_stratum = int(per) if per else None
        print(f"RESOLVING heads for the three-strata corpus in {DATA}"
              + (f" (PER_STRATUM={per_stratum})" if per_stratum else ""))
        triples = _strata_targets(per_stratum)
        targets = [(slug, sha) for _, slug, sha in triples]
        strata_of = {slug: label for label, slug, _ in triples}
        print(f"  {len(targets)} repositories resolved\n")
    elif args and args[0] == "--from-file":
        if len(args) < 2:
            raise SystemExit("--from-file needs a path")
        print(f"RESOLVING heads from {args[1]}")
        if not os.environ.get("GITHUB_TOKEN", "").strip():
            print("  no GITHUB_TOKEN — GitHub allows 60 requests an hour "
                  "unauthenticated, and this\n  costs one per repository. A "
                  "list longer than that will not resolve in full.")
        targets = _targets_from_file(Path(args[1]))
        print(f"  {len(targets)} repositories resolved\n")
    elif args:
        targets = [(*_slug_sha(a),) for a in args]
    else:
        targets = [(s.slug, s.sha) for s in SERIES]

    if not targets:
        print("no corpus available (batch_audit SERIES not importable and no "
              "slug@sha args given) — fixtures passed, that is the deliverable "
              "here", file=sys.stderr)
        return 0

    print(f"CORPUS — {len(targets)} repositories\n")
    fired = undetermined = failed = 0
    mounted_decided = other_decided = 0
    by_mount: dict[str, int] = {}
    replay: list[str] = []
    # Repositories that finished a COMPLETE scan and still have no mount: the
    # population the incidence silently drops. Collected by name because the
    # question "is that actually an app?" is answered by reading it, not by a
    # count.
    excluded_unknown: list[tuple[str, str, str]] = []
    # (fired, mounted-decided) per stratum, so a difference between Lovable
    # and hand-written is a number and not an impression.
    per_stratum_tally: dict[str, list[int]] = {}

    for slug, sha in targets:
        replay.append(f"{slug}@{sha}")
        try:
            data = _fetch(slug, sha)
        except Exception as exc:  # noqa: BLE001 — one bad fetch must not end the run
            failed += 1
            print(f"  ??  {slug:45s} fetch failed: {type(exc).__name__}")
            continue

        scan = scan_error_boundary(io.BytesIO(data))
        by_mount[scan.mount] = by_mount.get(scan.mount, 0) + 1
        # MOUNT ON EVERY LINE, because the aggregate hid a defect. A repository
        # silenced by a boundary token BEFORE the walk reached its render call
        # is classified `undetermined` and leaves the denominator -- and an
        # UNPROTECTED repository never stops early, so it always stays in it.
        # The exclusion is therefore one-directional and inflates the rate. Only
        # the per-repository mount says who this happened to.
        if scan.mount == MOUNT_UNKNOWN and scan.coverage != COVERAGE_EXHAUSTED:
            # Answer the exclusion's own question in the same pass, on bytes
            # already in hand: was this an app after all? Only for the handful
            # that landed here, so the cost is a second read of a few
            # repositories, not of the corpus.
            excluded_unknown.append((slug, scan.reason,
                                     _render_call_anywhere(data)))
        # `files_read` can be far below `files_total` on a COMPLETE scan: a
        # boundary token ends the walk. Printed together so nobody reads the
        # small number as a truncated pass.
        span = f"[{scan.coverage}, mount={scan.mount}, read {scan.files_read}]"

        if scan.coverage == COVERAGE_EXHAUSTED:
            undetermined += 1
            print(f"  —   {slug:45s} UNDETERMINED {span} — {scan.reason}")
            continue
        if scan.mount == MOUNT_YES:
            mounted_decided += 1
            tally = per_stratum_tally.setdefault(strata_of.get(slug, "-"), [0, 0])
            tally[1] += 1
            if scan.findings:
                tally[0] += 1
        else:
            other_decided += 1
        if scan.findings:
            fired += 1
            print(f"  ✗   {slug:45s} MISSING {span} — {scan.reason}")
        else:
            print(f"  ✓   {slug:45s} ok {span} — {scan.reason}")

    # TWO DENOMINATORS, AND ONLY ONE OF THEM ANSWERS THE QUESTION. Incidence
    # over every submitted repository is diluted by servers, CLIs and component
    # libraries, none of which have a screen to blank. The plan asks what a
    # free frontend tier would have to say to the people it is for, and those
    # are the MOUNTED apps.
    print()
    total_decided = mounted_decided + other_decided
    if mounted_decided:
        print(f"incidence among MOUNTED react/next apps: "
              f"{fired}/{mounted_decided} = "
              f"{100 * fired / mounted_decided:.0f}%   <- the plan's question")
    else:
        print("incidence among MOUNTED react/next apps: none in this corpus")
    if total_decided:
        print(f"incidence over all decided repositories: {fired}/{total_decided}"
              f" = {100 * fired / total_decided:.0f}%   (diluted by non-apps)")
    classes = ", ".join(f"{k}={v}" for k, v in sorted(by_mount.items()))
    print(f"  mount classes: {classes or 'none — nothing was read'}")
    if strata_of:
        print("  by stratum (fired / mounted):")
        for label, _fn in STRATA:
            f_, m_ = per_stratum_tally.get(label, [0, 0])
            pct = f"{100 * f_ / m_:.0f}%" if m_ else "—"
            print(f"    {label:13s} {f_}/{m_} = {pct}")
    if undetermined or failed:
        print(f"  not counted: {undetermined} undetermined (read budget), "
              f"{failed} unfetchable")

    # THE DENOMINATOR'S OWN BLIND SPOT, printed because a rate quoted without it
    # is quoted too high. Each of these finished a complete scan, found a
    # boundary, and never established a mount -- so it left the denominator
    # while every unprotected repository stayed in. If they are apps, the true
    # incidence is the LOW end below; if none of them are, it is the high end.
    # Which they are is settled by reading them, so they are named.
    if excluded_unknown and mounted_decided:
        really_apps = [e for e in excluded_unknown if e[2]]
        print(f"\n  {len(excluded_unknown)} silenced repositories left the "
              f"denominator with no mount established;")
        print(f"  {len(really_apps)} of them DO mount an app the walk never "
              f"reached, so the exclusion was wrong for those:")
        for slug, _reason, mount in excluded_unknown:
            where = f"mounts at {mount}" if mount else "no render call anywhere"
            print(f"    {slug:45s} {where}")
        # Not a bound any more: each repository was asked directly. The ones
        # that mount belong in the denominator, the ones that do not were
        # excluded correctly.
        true_denom = mounted_decided + len(really_apps)
        print(f"\n  incidence, denominator corrected: {fired}/{true_denom} = "
              f"{100 * fired / true_denom:.0f}%   "
              f"(reported as {fired}/{mounted_decided} = "
              f"{100 * fired / mounted_decided:.0f}% before this was measured)")

    print("\nreplay this exact run:\n  python scripts/measure_error_boundary.py "
          + " \\\n    ".join(replay))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
