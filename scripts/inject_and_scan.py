"""Inject known defects into real repositories and check the scanner finds them.

WHY THIS IS NOT THE ESCAPE HUNT. hunt_detector_escapes.py rewrites a corpus
fixture and asks whether the scanner still fires; the defect is assumed to
survive the rewrite, which is why its output is a review queue rather than a
verdict. Here the defect is PLANTED, at a known file and line, in a real
repository -- so a miss is a miss and a hit is a hit, with no reading required.

WHAT OLLAMA IS FOR. Not the oracle. The local model writes the SURROUNDING
CODE: a plausible function, a realistic variable name, an idiomatic wrapper, so
the planted defect sits in something that looks like the repository rather than
in a synthetic one-liner. The defect itself and the expected rule id come from
this file, where they can be read and argued with.

That division is the same one the escape hunt settled on and the same one that
failed when the model was asked to write a detector: the model produces volume
where being wrong is cheap, and the oracle stays in code.

NEVER A REAL SECRET. Planted credentials are drawn from documented example
values -- AWS's own AKIAIOSFODNN7EXAMPLE, Stripe's test-key shape -- so a  # scan-allow: AWS documented example
leaked fixture leaks nothing. The mutated tree lives in /tmp and is never
committed.

Usage:
    python scripts/inject_and_scan.py --repos /tmp/fleet
    python scripts/inject_and_scan.py --repos /tmp/fleet --with-model
    python scripts/inject_and_scan.py --repos /tmp/fleet --rule generic-assignment
"""

from __future__ import annotations

import argparse
import io
import json
import pathlib
import random
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import model_client                              # noqa: E402
from app.scan.static import run_static_scan  # noqa: E402

MODEL = model_client.model_name()

SKIP_DIRS = {".git", "node_modules", ".next", "venv", ".venv", "__pycache__",
             "dist", "build", ".mypy_cache", ".pytest_cache", "site-packages"}
MAX_FILE = 2_000_000
MAX_FILES = 4000


@dataclass
class Defect:
    """One planted defect: the code, where it may go, and what must fire."""
    name: str
    rule_id: str
    language: str                    # "py" | "ts"
    body: str
    why: str
    # Prompt for the model when --with-model is on. The defect line must
    # survive verbatim; everything around it is the model's to invent.
    dress_hint: str = ""


# Values below are DOCUMENTED EXAMPLES from the vendors themselves, chosen so
# that nothing here is a live credential even by accident.
AWS_EXAMPLE = "AKIA" + "IOSFODNN7EXAMPLE"
GENERIC_16 = "abcdefghijklmnop"

DEFECTS: list[Defect] = [
    Defect(
        "hardcoded-credential-backtick", "generic-assignment", "ts",
        f"const api_key = `{GENERIC_16}`;\n",
        "a template literal is a quote like any other",
        "a small config module that exports a client setup",
    ),
    Defect(
        "hardcoded-credential-compound", "generic-assignment", "ts",
        f'const db_password = "{GENERIC_16}";\n',
        "the credential word is a component of the name",
        "a database connection helper",
    ),
    Defect(
        "hardcoded-credential-python", "generic-assignment", "py",
        f'admin_token = "{GENERIC_16}"\n',
        "same rule, Python side",
        "a settings module",
    ),
    Defect(
        "aws-key", "aws-access-key-id", "py",
        f'AWS_ACCESS_KEY_ID = "{AWS_EXAMPLE}"\n',
        "AWS's own documented example key shape",
        "a module that configures an S3 client",
    ),
    Defect(
        "sql-injection-py", "sql-injection-string-built-query", "py",
        'def find_user(conn, user_id):\n'
        '    return conn.execute("SELECT * FROM users WHERE id = " + user_id)\n',
        "concatenated query with a parameter",
        "a data-access function in a repository class",
    ),
    Defect(
        "sql-injection-py-variable", "sql-injection-string-built-query", "py",
        'def find_user(conn, user_id):\n'
        '    query = "SELECT * FROM users WHERE id = " + user_id\n'
        '    return conn.execute(query)\n',
        "assembled one line before use",
        "a data-access function",
    ),
    Defect(
        "sql-injection-ts", "sql-injection-string-built-query", "ts",
        'export async function findUser(db: any, userId: string) {\n'
        '  return db.query("SELECT id FROM users WHERE id = " + userId);\n'
        '}\n',
        "the TypeScript half of the same rule",
        "an API route helper",
    ),
    Defect(
        "sql-secret-update", "sql-secret-assignment", "sql",
        f"update app_config set api_secret = '{GENERIC_16}';\n",
        "assignment without a type annotation",
        "",
    ),
]

# Where each language may be planted, relative to the repository root.
PLANT_PATHS = {
    "py": "drydock_probe/planted_{n}.py",
    "ts": "drydock_probe/planted_{n}.ts",
    "sql": "supabase/migrations/9999_planted_{n}.sql",
}


def ask_model(defect: Defect, timeout: int = 90) -> str | None:
    """Ask the local model to dress the defect in plausible surrounding code."""
    prompt = (
        "Write a short, realistic source file for a production project.\n\n"
        "HARD REQUIREMENT: include the following lines EXACTLY as given, "
        "unchanged, character for character:\n\n"
        f"{defect.body}\n"
        f"Context: {defect.dress_hint or 'a small module'}.\n"
        "Add imports, one or two other functions, and comments so it reads like "
        "real code. Do NOT fix, redact, comment out or parameterise the lines "
        "above. Do NOT add markdown fences. Output only the file contents."
    )
    try:
        text = model_client.generate(prompt, temperature=0.7,
                                     max_tokens=2000, timeout=timeout)
    except (model_client.GenerationError, urllib.error.URLError,
            TimeoutError, KeyError, OSError):
        return None
    # The model emits fences despite the instruction, and the language tag
    # rides along with them: stripping ``` alone leaves a bare `python` or
    # `typescript` as the file's first line. That parses (it is just a name
    # expression) but it is not the file we meant to plant, and it was the
    # difference between a defect the scanner reads and one it does not.
    if "```" in text:
        parts = text.split("```")
        text = max(parts, key=len)
    first, _, rest = text.partition("\n")
    if first.strip().lower() in {"python", "typescript", "ts", "js", "javascript",
                                 "sql", "tsx", "jsx", "py"}:
        text = rest
    # EVERY line of the defect must survive, not just the first. Checking one
    # line accepted files where the model had rewritten the injection itself
    # and kept the signature -- a planted defect that is not there.
    return text if all(line in text
                       for line in defect.body.strip().splitlines()) else None


def build_archive(src: pathlib.Path, root: str, extra: dict[str, str]):
    buf = io.BytesIO()
    n = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(src.rglob("*")):
            if n >= MAX_FILES:
                break
            if not p.is_file() or any(part in SKIP_DIRS for part in p.parts):
                continue
            try:
                if p.stat().st_size > MAX_FILE:
                    continue
                zf.writestr(root + str(p.relative_to(src)), p.read_bytes())
                n += 1
            except OSError:
                continue
        for rel, body in extra.items():
            zf.writestr(root + rel, body)
    buf.seek(0)
    return buf, n


def archive_root(repo: pathlib.Path) -> str:
    owner, _, name = repo.name.partition("_")
    sha = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                         capture_output=True, text=True).stdout.strip()[:7]
    return f"{owner}-{name}-{sha}/"


@dataclass
class Outcome:
    repo: str
    defect: str
    rule_id: str
    dressed: bool
    found: bool
    path: str
    baseline_count: int = 0
    after_count: int = 0


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    parser.add_argument("--repos", default="/tmp/fleet")
    parser.add_argument("--rule", help="only defects for this rule id")
    parser.add_argument("--with-model", action="store_true",
                        help="have Ollama write the surrounding code")
    parser.add_argument("--out", default="/tmp/fleet/injection_report.json")
    args = parser.parse_args()

    base = pathlib.Path(args.repos)
    repos = sorted(d for d in base.iterdir() if (d / ".git").is_dir())
    defects = [d for d in DEFECTS if not args.rule or d.rule_id == args.rule]
    if not repos or not defects:
        print("nothing to do", file=sys.stderr)
        return 2

    baseline_path = base / "baseline.json"
    baseline = json.loads(baseline_path.read_text()) if baseline_path.exists() else {}

    # Only when the model is actually going to be called: without --with-model
    # the defects are planted verbatim and no provider is needed at all.
    if args.with_model:
        ok, message = model_client.preflight()
        print(f"provider: {message}")
        if not ok:
            return 3

    outcomes: list[Outcome] = []
    random.seed(20260909)

    for repo in repos:
        root = archive_root(repo)
        base_counts = baseline.get(repo.name, {}).get("by_rule", {})
        print(f"\n=== {repo.name}")
        for index, defect in enumerate(defects):
            body, dressed = defect.body, False
            if args.with_model:
                written = ask_model(defect)
                if written:
                    body, dressed = written, True
            rel = PLANT_PATHS[defect.language].format(n=index)
            archive, _ = build_archive(repo, root, {rel: body})
            findings = run_static_scan(archive)["findings"]
            # THE PLANTED PATH, not a count. Counting was the first version and
            # it produced one false miss: the model's dressing added a second
            # injectable line, so an earlier defect's run already raised the
            # total and `after > before` read as unchanged. The file the defect
            # went into is known exactly, so ask about it directly.
            found = any(f["rule_id"] == defect.rule_id and rel in (f["file"] or "")
                        for f in findings)
            after = sum(1 for f in findings if f["rule_id"] == defect.rule_id)
            before = base_counts.get(defect.rule_id, 0)
            outcomes.append(Outcome(repo.name, defect.name, defect.rule_id,
                                    dressed, found, rel, before, after))
            mark = "НАЙДЕН " if found else "ПРОПУСК"
            tag = "модель" if dressed else "как есть"
            print(f"  [{mark}] {defect.name:<32} {tag:<9} {before}->{after}")

    total = len(outcomes)
    missed = [o for o in outcomes if not o.found]
    print(f"\n{'='*74}")
    print(f"подсажено {total} дефектов, найдено {total - len(missed)}, "
          f"пропущено {len(missed)}")
    if missed:
        print("\nПРОПУСКИ (каждый — либо дыра, либо неверное ожидание):")
        for o in missed:
            print(f"  {o.repo:<44} {o.defect}  ({o.rule_id})")
    print("=" * 74)

    json.dump([o.__dict__ for o in outcomes], open(args.out, "w"), indent=1)
    print(f"отчёт: {args.out}")
    if args.with_model:
        print(model_client.usage_line())
    return 0 if not missed else 1


if __name__ == "__main__":
    raise SystemExit(main())
