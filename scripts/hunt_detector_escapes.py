"""Do the deterministic detectors catch the same vulnerability written differently?

WHY THIS EXISTS. tests/detectors/ pins one positive example per rule. A green
corpus proves each detector fires on the example somebody wrote for it; it does
not prove the detector recognises the same defect in code it has not seen. The
gap between those two statements is where a paying customer's real repository
lives, and it is not visible from a passing test run.

WHAT IT DOES. For a positive corpus case it asks a local model for semantic
variations -- the same vulnerability, different syntax, naming, formatting or
idiom -- and runs every variation through the REAL static stage. A variation
the detector does not flag is a CANDIDATE ESCAPE.

IT RUNS THE SHIPPED DETECTOR. Not a copy of the matcher, not a
reimplementation: it calls `run_static_scan` with archive bytes, exactly as
uploads, jobs and the golden corpus do. The failure mode this avoids is the one
SUPABASE_RLS_YIELD_PLAN.md already recorded once -- a script that carried its
own copy of the rule and drifted from production within the hour.

WHAT A CANDIDATE IS NOT. It is NOT a proven detector gap. A 7B model asked to
rewrite vulnerable code will sometimes remove the vulnerability, break the
syntax, or emit something no engineer would write. In those cases silence is
the CORRECT answer and the candidate is noise. Nothing here can tell the two
apart, because the only oracle for "is this still vulnerable" is a human
reading the code. The output is therefore a REVIEW QUEUE, ranked and
deduplicated, not a defect list -- and the numbers it prints are counts of
things to look at, not of bugs found.

WHY A LOCAL MODEL. Variations are cheap, disposable and individually
unimportant; what matters is volume and diversity. That is the shape of work
worth handing to a laptop GPU rather than a metered API. The model proposes.
The shipped scanner, and then a reviewer, dispose.

NO GENERATED CREDENTIALS. The model is shown the corpus fixture WITH its
`@DRYDOCK_SAMPLE:NAME@` placeholders intact and told to preserve them.
Expansion happens after generation, in memory, on the way into the archive --
so the model neither reads nor invents anything shaped like a real key. Escape
bodies are written to disk only under --dump, and secret-like runs of
characters are masked in every report.

Usage:
    python scripts/hunt_detector_escapes.py --rule stripe-live-key
    python scripts/hunt_detector_escapes.py --all --variations 10
    python scripts/hunt_detector_escapes.py --all --model qwen2.5-coder:7b --out report.json

Requires a running Ollama (http://127.0.0.1:11434). No network, no database,
no API keys, no LLM spend.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field, asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
# scripts/ is on the path when this file is run directly, but not when it is
# imported as scripts.hunt_detector_escapes -- and tests do the latter.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import model_client                                              # noqa: E402
from app.scan.static import run_static_scan                      # noqa: E402
from tests.detector_samples import expand_samples                # noqa: E402
from tests.detectors.conftest import discover_cases                 # noqa: E402

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
DEFAULT_MODEL = model_client.model_name()

# A variation is a rewrite of ONE file. Above this size the model starts
# truncating rather than rewriting, and a truncated file is a syntax error
# wearing a costume -- it escapes detection for reasons that teach us nothing.
MAX_TARGET_BYTES = 6000

SEPARATOR = "=== VARIATION ==="

# The model reproduces the separator with its own whitespace -- "===\nVARIATION
# ===" appeared in a real run -- and an exact split then misses it, welding two
# rewrites into one body. The welded body is not valid source, the scanner is
# right to stay silent on it, and the silence is counted as an escape. So the
# split is tolerant of the whitespace while still requiring the word.
SEPARATOR_RE = re.compile(r"=+\s*VARIATION\s*=+", re.IGNORECASE)

# ```lang\n ... \n``` -- the fence we asked the model not to emit, and which it
# emits anyway, sometimes with an essay after it.
FENCE_BLOCK = re.compile(r"```[a-zA-Z]*\n(.*?)```", re.DOTALL)

# The prompt shows the source between `--- FILE: x ---` / `--- END FILE ---`
# markers, and the model echoes them back into its answer often enough to
# matter. They are not source: a body carrying one fails to parse, and a
# detector that skips an unparseable file then looks like it missed a defect.
# Stripping them is not cosmetic -- it is the difference between a real
# candidate and a fabricated one.
FILE_MARKER = re.compile(r"^\s*-{2,}\s*(?:FILE|END FILE)\b.*$", re.MULTILINE)

PROMPT = """You are helping test a static security scanner. Below is a file from a test \
fixture that deliberately contains a security defect: {rule_id}.

Rewrite this file {n} different ways. Every rewrite MUST still contain the SAME \
security defect -- your goal is to express it differently, NOT to fix it.

Vary things like: variable and function names, string quoting and concatenation, \
formatting and line breaks, equivalent language idioms, surrounding code, comments, \
import style.

Hard rules:
- The defect must survive in every rewrite. Do not fix, redact or comment it out.
- Keep any @DRYDOCK_SAMPLE:...@ placeholder EXACTLY as written. Never replace one \
with an invented key or literal.
- Keep every literal value AT LEAST AS LONG as it is in the original. Detectors \
have length thresholds; a shortened value is a different test, not a variation.
- Keep credential-shaped NAMES intact (api_key stays api_key, not api_key_string). \
Rename other identifiers freely.
- The rewrite must COMPILE. Keep every import the code needs: if you use useState, \
import it by name from react. Do not output a fragment or a truncated file.
- Output the full file contents each time, not a diff and not an explanation.
- Separate the rewrites with a line containing exactly: {sep}
- No markdown code fences. No commentary before, between or after.

--- FILE: {filename} ---
{content}
--- END FILE ---
"""

@dataclass
class Escape:
    """One variation the detector did not flag. A question, not a verdict."""
    rule_id: str
    case: str
    variation_index: int
    target_file: str
    body_sha: str
    body_chars: int
    fired_rules: list[str]
    body: str = field(default="", repr=False)  # kept in memory; dumped only on request


@dataclass
class RuleResult:
    rule_id: str
    case: str
    target_file: str
    baseline_ok: bool
    skipped: str | None = None
    variations_requested: int = 0
    variations_parsed: int = 0
    identical_to_source: int = 0
    # Variations thrown out before scoring because they do not compile. Counted
    # rather than silently dropped: a rule whose "escapes" were all uncompilable
    # tells you about the model, not the detector, and the number is how you see
    # that from the report.
    uncompilable: int = 0
    caught: int = 0
    escapes: list[Escape] = field(default_factory=list)
    seconds: float = 0.0

    @property
    def escape_rate(self) -> float:
        scored = self.caught + len(self.escapes)
        return len(self.escapes) / scored if scored else 0.0


def ollama_generate(model: str, prompt: str, timeout: int = 900) -> str:
    """One non-streaming completion, from whichever provider is configured.

    Kept under its original name because the call sites read fine as-is and
    renaming would have made this commit a rename commit. See
    scripts/model_client.py for the provider selection: default is still local
    Ollama, so a machine with no API key behaves exactly as before.
    """
    return model_client.generate(prompt, model=model, timeout=timeout)


def read_case(case_dir: Path) -> dict[str, str]:
    """Fixture-relative path -> RAW contents, placeholders unexpanded."""
    files = {}
    for path in sorted(case_dir.rglob("*")):
        if path.is_file() and path.name != "expected.json":
            files[path.relative_to(case_dir).as_posix()] = path.read_text()
    return files


def build_archive(files: dict[str, str]) -> io.BytesIO:
    """Same contract as the corpus harness: strip .fixture, expand placeholders."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name.removesuffix(".fixture"), expand_samples(content))
    buf.seek(0)
    return buf


def scan(files: dict[str, str]) -> list[dict]:
    return run_static_scan(build_archive(files))["findings"]


def parse_variations(raw: str, expected: int) -> list[str]:
    """Split on the separator and recover the code from a chatty model.

    A 7B model ignores "no fences, no commentary" often enough that the naive
    split leaves prose in the body -- and prose is not valid source, so the
    scanner's silence on it means nothing. A variation polluted that way looks
    exactly like a detector gap in the report, which is the one thing this
    tool must never fake. When a fenced block is present it IS the variation;
    anything outside the fence is the model talking to itself.
    """
    out = []
    for part in _split_variations(raw):
        body = part.strip()
        if not body:
            continue
        fenced = FENCE_BLOCK.search(body)
        if fenced:
            body = fenced.group(1)
        elif body.startswith("```"):        # opened a fence and never closed it
            body = body.split("\n", 1)[-1].removesuffix("```")
        # A stray CLOSING fence, with no opening one, is the model ending a block
        # it never started. Left in, it makes the body unparseable, and an
        # unparseable body is silence for a reason that has nothing to do with the
        # rule -- measured: two of the eighteen cookie-rule candidates in one
        # round, which would have read as escapes.
        body = re.sub(r"\n\s*```[a-zA-Z]*\s*$", "", body)
        body = FILE_MARKER.sub("", body).strip("\n")
        if body.strip():
            out.append(body)
    return out[:expected]


def _split_variations(raw: str) -> list[str]:
    """Split the model's answer into candidate bodies.

    Two separators, because the model uses both: the one it was asked for
    (`=== VARIATION N ===`), and a bare rule line between snippets -- measured,
    a whole answer of six variations joined by `===`, which arrived as a single
    unparseable body and would have counted as one escape.
    """
    parts: list[str] = []
    for chunk in SEPARATOR_RE.split(raw):
        parts.extend(re.split(r"(?m)^\s*=+\s*$", chunk))
    return parts


def variation_is_broken(body: str, filename: str) -> str | None:
    """Why this variation cannot be scored, or None if it can.

    A variation that does not compile is not evidence about the detector. The
    scanner is right to stay silent on code that could never run, and counting
    that silence as an escape manufactures a gap out of the model's mistake --
    the one failure mode this tool must not have.

    MEASURED, not assumed: all 14 react-unchecked-http-success candidates in one
    full run were the same non-compiling shape --

        import React from 'react';          // default import only
        const [x, setX] = useState(false);  // ...but useState used bare

    which tsc rejects with "Cannot find name 'useState'". tree-sitter parses it
    happily, so a syntax check alone would not have caught it; the test has to
    be whether the names used are actually in scope.

    Deliberately narrow. This checks the hook-import mistake and Python syntax,
    not general type-correctness -- a full type-check per variation would cost
    more than the hunt itself, and every extra rejection risks discarding a real
    escape. Anything not recognised here is still scored.
    """
    if filename.endswith(".py"):
        try:
            ast.parse(body)
        except (SyntaxError, ValueError, RecursionError) as exc:
            return f"unparseable Python: {type(exc).__name__}"
        return None

    if filename.endswith((".ts", ".tsx", ".js", ".jsx")):
        for hook in ("useState", "useEffect", "useRouter", "useCallback", "useMemo"):
            used_bare = re.search(rf"(?<![.\w]){hook}\s*[(<]", body)
            if not used_bare:
                continue
            imported = re.search(
                rf"import\s+(?:[\w${{}}]+\s*,\s*)?{{[^}}]*\b{hook}\b[^}}]*}}\s*from",
                body,
            )
            declared = re.search(rf"(?:const|let|var|function)\s+{hook}\b", body)
            if not imported and not declared:
                return f"{hook} used without importing it -- does not compile"
    return None


def pick_target(findings: list[dict], rule_id: str, files: dict[str, str]) -> str | None:
    """The fixture file the baseline finding points at.

    Structural rules (no-ci, no-tests, no-dockerfile) are findings ABOUT AN
    ABSENCE. There is no file to rewrite, so rewriting cannot probe them, and
    they are reported as skipped rather than silently counted as clean.
    """
    for finding in findings:
        if finding.get("rule_id") != rule_id:
            continue
        name = finding.get("file") or ""
        if not name:
            continue
        for candidate in files:
            if candidate.removesuffix(".fixture") == name or candidate == name:
                return candidate
    return None


def hunt(rule_id: str, case_dir: Path, model: str, n: int) -> RuleResult:
    started = time.time()
    files = read_case(case_dir)
    result = RuleResult(rule_id=rule_id, case=case_dir.name, target_file="", baseline_ok=False)

    # 1. Baseline. If the shipped detector does not fire on the corpus case
    #    itself, every later silence is meaningless and we say so instead of
    #    reporting a hundred spectacular escapes.
    baseline = scan(files)
    result.baseline_ok = any(f.get("rule_id") == rule_id for f in baseline)
    if not result.baseline_ok:
        result.skipped = "baseline did not fire: corpus case or harness is broken"
        result.seconds = time.time() - started
        return result

    target = pick_target(baseline, rule_id, files)
    if target is None:
        result.skipped = "structural rule: the finding names no rewritable file"
        result.seconds = time.time() - started
        return result
    result.target_file = target

    source = files[target]
    if len(source) > MAX_TARGET_BYTES:
        result.skipped = f"target file is {len(source)} bytes, over the {MAX_TARGET_BYTES} limit"
        result.seconds = time.time() - started
        return result

    # 2. Generate. The fixture is our own corpus, not third-party input, so
    #    feeding it to the model carries no prompt-injection exposure beyond
    #    what we wrote ourselves.
    prompt = PROMPT.format(rule_id=rule_id, n=n, sep=SEPARATOR,
                           filename=target.removesuffix(".fixture"), content=source)
    try:
        raw = ollama_generate(model, prompt)
    except (model_client.GenerationError, urllib.error.URLError,
            TimeoutError, OSError) as exc:
        result.skipped = f"model call failed: {type(exc).__name__}: {exc}"
        result.seconds = time.time() - started
        return result

    variations = parse_variations(raw, n)
    result.variations_requested = n
    result.variations_parsed = len(variations)

    # 3. Score each variation through the real scanner.
    seen: set[str] = set()
    for index, body in enumerate(variations):
        if body.strip() == source.strip():
            result.identical_to_source += 1
            continue
        digest = hashlib.sha256(body.encode()).hexdigest()
        if digest in seen:            # the model repeats itself under high temperature
            result.identical_to_source += 1
            continue
        seen.add(digest)

        broken = variation_is_broken(body, target.removesuffix(".fixture"))
        if broken:
            result.uncompilable += 1
            print(f"    variation {index}: discarded -- {broken}", file=sys.stderr)
            continue

        mutated = dict(files)
        mutated[target] = body
        try:
            findings = scan(mutated)
        except Exception as exc:      # noqa: BLE001 - a malformed archive is a skip, not a crash
            result.identical_to_source += 1
            print(f"    variation {index}: unscannable ({type(exc).__name__})", file=sys.stderr)
            continue

        fired = sorted({f.get("rule_id", "") for f in findings})
        if rule_id in fired:
            result.caught += 1
        else:
            result.escapes.append(Escape(
                rule_id=rule_id, case=case_dir.name, variation_index=index,
                target_file=target.removesuffix(".fixture"),
                body_sha=digest[:12], body_chars=len(body),
                fired_rules=[r for r in fired if r], body=body,
            ))

    result.seconds = time.time() - started
    return result


def dump_escapes(results: list[RuleResult], out_dir: Path) -> None:
    """Write escape bodies for review, VERBATIM.

    The bodies are written as the model produced them, not through a masker. The
    earlier version masked every run of 24+ word characters, and the reviews it
    was meant to serve could not read it: `Depends(provide_storage_interface)`
    reached the file as `Depends(prov...[25 chars])`, which does not parse, so a
    reviewer counting escapes was counting bodies nobody could judge. Measured
    cost over two rules: 6 of 19 and 3 of 12 dumped bodies were unreadable.

    Nothing valuable is exposed by writing them raw. A body carries the corpus
    fixture's `@DRYDOCK_SAMPLE:NAME@` placeholders INTACT -- expansion happens in
    memory on the way into the archive (see build_archive), never on disk -- so
    the only credential-shaped text that can appear here is a value the model
    invented contrary to its instructions, and an invented value is not a secret.
    The report prints counts, ids and body hashes; it never prints a body, so the
    masking that remains meaningful stays where it belongs, on the terminal.

    A test pins this (`tests/test_hunt_detector_escapes.py`): a dump whose text
    differs from the escape body is a dump that cannot be reviewed.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    for result in results:
        for escape in result.escapes:
            name = f"{result.rule_id}__{escape.body_sha}__{Path(escape.target_file).name}"
            (out_dir / name).write_text(escape.body)


def report(results: list[RuleResult], model: str) -> dict:
    scored = [r for r in results if not r.skipped]
    total_escapes = sum(len(r.escapes) for r in scored)
    total_scored = sum(r.caught + len(r.escapes) for r in scored)

    print(f"\n{'=' * 78}")
    print(f"CANDIDATE ESCAPES  (model: {model})")
    print("=" * 78)
    print(f"{'rule':<40} {'caught':>7} {'escaped':>8} {'rate':>7} {'thrown':>7}")
    print("-" * 78)
    for r in sorted(scored, key=lambda r: -r.escape_rate):
        print(f"{r.rule_id:<40} {r.caught:>7} {len(r.escapes):>8} {r.escape_rate:>6.0%} "
              f"{r.uncompilable:>7}")

    skipped = [r for r in results if r.skipped]
    if skipped:
        print(f"\n{'-' * 78}\nSKIPPED\n{'-' * 78}")
        for r in skipped:
            print(f"{r.rule_id:<40} {r.skipped}")

    print(f"\n{'=' * 78}")
    print(f"{total_escapes} candidates from {total_scored} scored variations "
          f"across {len(scored)} rules.")
    print("A candidate is a variation the scanner did not flag. It is NOT a proven")
    print("gap: the model may have removed the defect or broken the syntax. Each")
    print("one needs a human to read it before it means anything.")
    print("=" * 78)

    return {
        "model": model,
        # Which provider produced these bodies. Two runs of the same rule can
        # differ entirely because the model differed, and a report that only
        # names the model leaves that ambiguous once more than one endpoint
        # can serve the same name.
        "provider": model_client.describe(),
        # What the run cost, from the provider's own counters rather than an
        # estimate. Cache hits are priced differently from misses, so the
        # split matters when comparing a rerun against the first run.
        "usage": model_client.usage_report(),
        "rules_scored": len(scored),
        "rules_skipped": len(skipped),
        "variations_scored": total_scored,
        "candidates": total_escapes,
        "results": [
            {**{k: v for k, v in asdict(r).items() if k != "escapes"},
             "escape_rate": round(r.escape_rate, 4),
             "escapes": [{k: v for k, v in asdict(e).items() if k != "body"} for e in r.escapes]}
            for r in results
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--rule", help="a single rule_id from tests/detectors/")
    group.add_argument("--all", action="store_true", help="every positive corpus case")
    parser.add_argument("--variations", type=int, default=8, help="variations per case (default 8)")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"ollama model (default {DEFAULT_MODEL})")
    parser.add_argument("--out", type=Path, help="write the JSON report here")
    parser.add_argument("--dump", type=Path, help="write escape bodies here for review")
    args = parser.parse_args()

    cases = [(rule, path) for rule, polarity, path in discover_cases()
             if polarity == "positive" and (args.all or rule == args.rule)]
    if not cases:
        print(f"no positive corpus case for rule {args.rule!r}", file=sys.stderr)
        return 2

    # Preflight the CONFIGURED provider, not Ollama specifically. A run that
    # starts against an unreachable endpoint wastes the whole loop, and one
    # that starts against the wrong provider silently attributes its results
    # to a model that never ran.
    ok, message = model_client.preflight()
    print(f"provider: {message}", file=sys.stderr)
    if not ok:
        return 3

    results = []
    for index, (rule, path) in enumerate(cases, 1):
        print(f"[{index}/{len(cases)}] {rule}/{path.name} ...", flush=True)
        result = hunt(rule, path, args.model, args.variations)
        note = result.skipped or (f"{result.caught} caught, {len(result.escapes)} candidates")
        print(f"    {note}  ({result.seconds:.1f}s)", flush=True)
        results.append(result)

    payload = report(results, args.model)
    print(model_client.usage_line())
    if args.out:
        args.out.write_text(json.dumps(payload, indent=2))
        print(f"\nreport: {args.out}")
    if args.dump:
        dump_escapes(results, args.dump)
        print(f"escape bodies: {args.dump}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
