"""Do the structural rules survive a repository laid out differently?

WHY A SECOND HARNESS. scripts/hunt_detector_escapes.py rewrites the file a
finding points at. Nine rules have no such file: no-ci, no-tests,
no-dockerfile, dependency-dir-committed, gitignore-missing-secrets, the two
rls-table rules, schema-drift-undeclared-table and
ci-deploys-a-different-repository are findings ABOUT AN ABSENCE or about the
shape of the tree. The escape hunt skips them by design and says so, which
means they are the only detectors whose blind spots nothing has probed.

WHAT THIS PROBES INSTEAD. The rules read PATHS, so the thing to vary is the
layout: a monorepo where the app lives under apps/web/, a project whose tests
sit in __tests__/ rather than in files named *test*, a .gitignore that ignores
.env by a pattern the predicate does not recognise. Each case is a small
repository built in memory and handed to the real static stage.

EVERY CASE STATES ITS OWN TRUTH. A layout is declared with what the correct
answer is -- should_fire True or False -- and the harness only reports where
the scanner disagrees. That is the difference from the escape hunt, which
cannot know whether a mutated file still contains the defect and therefore
produces a review queue rather than a verdict. Here the cases are written by
hand, so a disagreement IS a defect, in the rule or in the case.

The cost of that certainty is coverage: these are the layouts somebody thought
of. It finds what the corpus's single example per rule does not pin, not
everything a real repository can look like.

Usage:
    python scripts/probe_structural_rules.py
    python scripts/probe_structural_rules.py --rule no-tests
    python scripts/probe_structural_rules.py --verbose

No model, no network, no database: the layouts are literal and the oracle is
the declaration beside each one.
"""

from __future__ import annotations

import argparse
import io
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scan.static import run_static_scan  # noqa: E402

# A minimal tree that keeps the OTHER rules quiet, so a case says one thing.
# Every layout starts from this and overrides what it is about.
BASELINE = {
    "package.json": '{"name":"app","dependencies":{"next":"15"}}',
    "src/app/page.tsx": "export default function Page(){return null}\n",
    ".gitignore": "node_modules\n.env\n",
    "Dockerfile": "FROM node:22\n",
    ".github/workflows/ci.yml": "name: ci\non: [push]\njobs:\n  t:\n    runs-on: ubuntu-latest\n",
    "src/app/page.test.tsx": "test('renders', () => {})\n",
}


@dataclass
class Layout:
    """One repository shape, and what the rule is supposed to say about it."""
    rule_id: str
    name: str
    should_fire: bool
    why: str
    files: dict[str, str] = field(default_factory=dict)
    drop: tuple[str, ...] = ()
    # ci-deploys-a-different-repository can only answer "is that a different
    # repository" when the archive carries GitHub's zipball root, {owner}-{repo}-{sha}.
    # Without one it stays silent by design, so its layouts have to supply it or
    # they would all pass vacuously.
    root: str = ""


def build(layout: Layout) -> io.BytesIO:
    entries = {k: v for k, v in BASELINE.items() if k not in layout.drop}
    entries.update(layout.files)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in entries.items():
            zf.writestr(layout.root + name, body)
    buf.seek(0)
    return buf


LAYOUTS: list[Layout] = [
    # ---------------------------------------------------------------- no-ci
    Layout("no-ci", "no workflows directory", True,
           "nothing runs on push", drop=(".github/workflows/ci.yml",)),
    Layout("no-ci", "workflow present", False,
           "the baseline has one"),
    Layout("no-ci", "GitLab CI instead of GitHub", True,
           "the rule reads .github/workflows only; a project on GitLab has CI "
           "and would be told it has none",
           drop=(".github/workflows/ci.yml",),
           files={".gitlab-ci.yml": "stages: [test]\ntest:\n  script: npm test\n"}),
    Layout("no-ci", "CircleCI instead of GitHub", True,
           "same question for .circleci/config.yml",
           drop=(".github/workflows/ci.yml",),
           files={".circleci/config.yml": "version: 2.1\njobs:\n  test:\n    steps: [checkout]\n"}),
    Layout("no-ci", "workflow nested in a monorepo package", True,
           "GitHub only reads .github/workflows at the ROOT, so a workflow "
           "under apps/web/.github/ genuinely does not run -- firing is correct",
           drop=(".github/workflows/ci.yml",),
           files={"apps/web/.github/workflows/ci.yml": "name: ci\non: [push]\n"}),

    # -------------------------------------------------------------- no-tests
    Layout("no-tests", "no test files", True,
           "nothing checks the app", drop=("src/app/page.test.tsx",)),
    Layout("no-tests", "*.test.tsx present", False,
           "the baseline has one"),
    Layout("no-tests", "__tests__ directory, files not named *test*", True,
           "__tests__/page.tsx is the React convention and contains tests; the "
           "rule matches on the FILENAME, so a project using it is told it has none",
           drop=("src/app/page.test.tsx",),
           files={"src/__tests__/page.tsx": "it('works', () => {})\n"}),
    Layout("no-tests", "*.spec.ts naming", True,
           "spec is as common as test in JS projects",
           drop=("src/app/page.test.tsx",),
           files={"src/app/page.spec.ts": "it('works', () => {})\n"}),
    Layout("no-tests", "Python tests in tests/ directory", False,
           "tests/test_api.py has test in the filename, so this one is covered",
           drop=("src/app/page.test.tsx",),
           files={"tests/test_api.py": "def test_ok():\n    assert True\n"}),
    Layout("no-tests", "Go test file", True,
           "api_test.go is Go's mandatory convention; the extension list is "
           "py/ts/tsx/js only, so a Go service is told it has no tests",
           drop=("src/app/page.test.tsx",),
           files={"api_test.go": "package main\nfunc TestOK(t *testing.T) {}\n"}),

    # ---------------------------------------------------------- no-dockerfile
    Layout("no-dockerfile", "no Dockerfile", True,
           "none present", drop=("Dockerfile",)),
    Layout("no-dockerfile", "Dockerfile present", False,
           "the baseline has one"),
    Layout("no-dockerfile", "Dockerfile.prod only", True,
           "the rule matches the exact basename Dockerfile; a project with "
           "Dockerfile.prod and Dockerfile.dev has containers and is told it has none",
           drop=("Dockerfile",),
           files={"Dockerfile.prod": "FROM node:22\n", "Dockerfile.dev": "FROM node:22\n"}),
    Layout("no-dockerfile", "containerfile (Podman spelling)", True,
           "Containerfile is the OCI name for the same file",
           drop=("Dockerfile",),
           files={"Containerfile": "FROM node:22\n"}),

    # -------------------------------- ci-deploys-a-different-repository
    # This rule needs the GitHub zipball root to know its own name, so these
    # layouts carry it. BASELINE has no root, which is why the rule is absent
    # from every other case here rather than silently passing them.
    Layout("ci-deploys-a-different-repository", "deploys another repository", True,
           "the workflow checks out this repo and clones a different one",
           files={".github/workflows/deploy.yml":
                  "name: deploy\non: [push]\njobs:\n  d:\n    steps:\n"
                  "      - uses: actions/checkout@v4\n"
                  "      - run: |\n"
                  "          REPO=https://github.com/other/thing.git\n"
                  "          git clone $REPO /srv/app\n"},
           root="acme-webapp-a1b2c3d4e5f6/"),
    Layout("ci-deploys-a-different-repository", "deploys its own repository", False,
           "cloning yourself by URL is legal and common",
           files={".github/workflows/deploy.yml":
                  "name: deploy\non: [push]\njobs:\n  d:\n    steps:\n"
                  "      - uses: actions/checkout@v4\n"
                  "      - run: git clone https://github.com/acme/webapp.git /srv/app\n"},
           root="acme-webapp-a1b2c3d4e5f6/"),
    Layout("ci-deploys-a-different-repository", "credit comment beside a self-deploy", False,
           "a comment naming where the workflow was copied from is not a deploy "
           "target; reporting it accuses a correct workflow",
           files={".github/workflows/deploy.yml":
                  "name: deploy\non: [push]\njobs:\n  d:\n    steps:\n"
                  "      # adapted from https://github.com/actions/starter-workflows\n"
                  "      - uses: actions/checkout@v4\n"
                  "      - run: git clone https://github.com/acme/webapp.git /srv/app\n"},
           root="acme-webapp-a1b2c3d4e5f6/"),
    Layout("ci-deploys-a-different-repository", "pip install from git beside a self-deploy", False,
           "installing a tool from GitHub is not deploying it",
           files={".github/workflows/deploy.yml":
                  "name: deploy\non: [push]\njobs:\n  d:\n    steps:\n"
                  "      - uses: actions/checkout@v4\n"
                  "      - run: pip install git+https://github.com/psf/black.git\n"
                  "      - run: git clone https://github.com/acme/webapp.git /srv/app\n"},
           root="acme-webapp-a1b2c3d4e5f6/"),
    Layout("ci-deploys-a-different-repository", "rsync instead of git", False,
           "the rule reads git operations only; rsync of a build directory "
           "names no repository, so there is nothing to compare -- a documented "
           "limit rather than a miss",
           files={".github/workflows/deploy.yml":
                  "name: deploy\non: [push]\njobs:\n  d:\n    steps:\n"
                  "      - run: rsync -a ./dist deploy@host:/srv/app\n"},
           root="acme-webapp-a1b2c3d4e5f6/"),

    # ------------------------------------------- gitignore-missing-secrets
    Layout("gitignore-missing-secrets", "no .gitignore at all", True,
           "nothing is ignored", drop=(".gitignore",)),
    Layout("gitignore-missing-secrets", ".gitignore covers .env", False,
           "the baseline covers it"),
    Layout("gitignore-missing-secrets", "pattern .env** ", True,
           "the predicate accepts .env, .env*, *.env and .env.* exactly; a "
           "double-star spelling ignores the same files and is not recognised",
           files={".gitignore": "node_modules\n.env**\n"}),
    Layout("gitignore-missing-secrets", "pattern **/.env", True,
           "the recursive spelling git itself documents",
           files={".gitignore": "node_modules\n**/.env\n"}),
    Layout("gitignore-missing-secrets", "trailing comment on the line", True,
           "`.env  # secrets` ignores .env; the predicate compares the whole "
           "stripped line, so a comment defeats it",
           files={".gitignore": "node_modules\n.env  # local secrets\n"}),
    Layout("gitignore-missing-secrets", ".gitignore in a subdirectory only", True,
           "a nested .gitignore does cover its own directory, but the root "
           "one is what protects the repository -- firing is correct here",
           drop=(".gitignore",),
           files={"src/.gitignore": ".env\n"}),

    # ------------------------------------------- dependency-dir-committed
    # _DEPENDENCY_DIR_MIN_FILES is 20: one stray file is a mistake, a populated
    # tree is the defect. Cases therefore have to BE populated -- the first
    # draft of this probe used two files and read the threshold as three bugs.
    Layout("dependency-dir-committed", "node_modules committed", True,
           "the dependency tree is in the repository",
           files={f"node_modules/react/f{i}.js": "module.exports={}\n" for i in range(25)}),
    Layout("dependency-dir-committed", "no dependency directory", False,
           "the baseline has none"),
    Layout("dependency-dir-committed", "one stray file under node_modules", False,
           "below the threshold on purpose: a single committed file is not the "
           "populated tree this finding describes",
           files={"node_modules/react/index.js": "module.exports={}\n"}),
    Layout("dependency-dir-committed", "vendor/ (Go and PHP convention)", True,
           "vendor/ is what Go modules and Composer commit",
           files={f"vendor/pkg/f{i}.go": "package pkg\n" for i in range(25)}),
    Layout("dependency-dir-committed", ".venv committed", True,
           "a Python virtualenv in the repository is the same defect",
           files={f".venv/lib/python3.12/site-packages/m{i}.py": "x = 1\n" for i in range(25)}),

    # --------------------------------------------------------- rls + schema
    # These need SQL, so the baseline gets migrations rather than being dropped.
    Layout("rls-table-anon-readable", "table without RLS enabled", True,
           "anon can read it",
           files={"supabase/migrations/0001_init.sql":
                  "create table public.profiles (id uuid primary key, email text);\n"}),
    Layout("rls-table-anon-readable", "RLS enabled", False,
           "the migration enables row level security",
           files={"supabase/migrations/0001_init.sql":
                  "create table public.profiles (id uuid primary key);\n"
                  "alter table public.profiles enable row level security;\n"}),
    Layout("rls-table-anon-readable", "RLS enabled in a LATER migration", False,
           "migrations are cumulative; enabling it in 0002 protects the table "
           "created in 0001, and reporting it would be a false claim",
           files={"supabase/migrations/0001_init.sql":
                  "create table public.profiles (id uuid primary key);\n",
                  "supabase/migrations/0002_rls.sql":
                  "alter table public.profiles enable row level security;\n"}),
    Layout("rls-table-anon-readable", "migrations in db/migrate/ (Rails layout)", False,
           "the rule reads supabase/migrations and db/; an unrecognised "
           "location means no SQL was read, and silence is then correct rather "
           "than a claim that RLS is fine",
           files={"db/migrate/001_init.sql":
                  "create table public.profiles (id uuid primary key);\n"}),

    # ------------------------------------------- rls-table-anon-writable
    # The only rule neither harness had touched: structural, so the escape hunt
    # skips it, and the layout probe had no cases for it either.
    Layout("rls-table-anon-writable", "policy lets anon UPDATE", True,
           "anyone can change other people's rows",
           files={"supabase/migrations/0001_init.sql":
                  "create table public.profiles (id uuid primary key, email text);\n"
                  "alter table public.profiles enable row level security;\n"
                  "create policy p on public.profiles for update to anon using (true);\n"}),
    Layout("rls-table-anon-writable", "policy lets anon SELECT only", False,
           "reading is the other rule's claim; this one is about writes",
           files={"supabase/migrations/0001_init.sql":
                  "create table public.profiles (id uuid primary key, email text);\n"
                  "alter table public.profiles enable row level security;\n"
                  "create policy p on public.profiles for select to anon using (true);\n"}),
    Layout("rls-table-anon-writable", "write policy scoped to the owner", False,
           "auth.uid() = id is the correct shape and must not be reported",
           files={"supabase/migrations/0001_init.sql":
                  "create table public.profiles (id uuid primary key, email text);\n"
                  "alter table public.profiles enable row level security;\n"
                  "create policy p on public.profiles for update to anon "
                  "using (auth.uid() = id);\n"}),
    Layout("rls-table-anon-writable", "GRANT with RLS enabled", False,
           "a GRANT alone opens nothing once RLS is on -- Postgres still needs a "
           "policy, so reporting it would describe access that does not exist",
           files={"supabase/migrations/0001_init.sql":
                  "create table public.profiles (id uuid primary key, email text);\n"
                  "alter table public.profiles enable row level security;\n"
                  "grant update on public.profiles to anon;\n"}),
    Layout("rls-table-anon-writable", "GRANT with RLS never enabled", True,
           "without RLS the grant is the whole story and the write really is open",
           files={"supabase/migrations/0001_init.sql":
                  "create table public.profiles (id uuid primary key, email text);\n"
                  "grant update on public.profiles to anon;\n"}),

    Layout("schema-drift-undeclared-table", "code names a table no migration declares", True,
           "the repository reads a table it never creates",
           files={"supabase/migrations/0001_init.sql":
                  "create table public.profiles (id uuid primary key);\n"
                  "alter table public.profiles enable row level security;\n",
                  "src/app/data.ts":
                  "import { supabase } from './client';\n"
                  "export const rows = () => supabase.from('invoices').select('*');\n"}),
    Layout("schema-drift-undeclared-table", "every named table is declared", False,
           "no drift",
           files={"supabase/migrations/0001_init.sql":
                  "create table public.profiles (id uuid primary key);\n"
                  "alter table public.profiles enable row level security;\n",
                  "src/app/data.ts":
                  "import { supabase } from './client';\n"
                  "export const rows = () => supabase.from('profiles').select('*');\n"}),
    Layout("schema-drift-undeclared-table", "storage bucket, not a table", False,
           "supabase.storage.from('avatars') names a BUCKET; reporting it as a "
           "missing table would be a false claim about the customer's data",
           files={"supabase/migrations/0001_init.sql":
                  "create table public.profiles (id uuid primary key);\n"
                  "alter table public.profiles enable row level security;\n",
                  "src/app/data.ts":
                  "import { supabase } from './client';\n"
                  "export const f = () => supabase.storage.from('avatars').list();\n"}),
]


def run(layouts: list[Layout], verbose: bool) -> int:
    disagreements = 0
    current_rule = None
    for layout in layouts:
        if layout.rule_id != current_rule:
            current_rule = layout.rule_id
            print(f"\n=== {current_rule}")
        fired = layout.rule_id in {
            f.get("rule_id") for f in run_static_scan(build(layout))["findings"]
        }
        agrees = fired == layout.should_fire
        if not agrees:
            disagreements += 1
        mark = "ok      " if agrees else "MISMATCH"
        want = "fire" if layout.should_fire else "stay silent"
        print(f"  [{mark}] {layout.name:<46} expected to {want}")
        if not agrees or verbose:
            print(f"             {layout.why}")

    print(f"\n{'=' * 78}")
    print(f"{len(layouts)} layouts, {disagreements} disagreements.")
    print("A disagreement is a defect in the rule OR in the case's stated truth;")
    print("both are worth reading, and neither is noise the way an escape can be.")
    print("=" * 78)
    return 0 if disagreements == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    parser.add_argument("--rule", help="probe one rule id only")
    parser.add_argument("--verbose", action="store_true", help="print the reasoning for every case")
    args = parser.parse_args()

    layouts = [x for x in LAYOUTS if not args.rule or x.rule_id == args.rule]
    if not layouts:
        print(f"no layouts for {args.rule!r}", file=sys.stderr)
        return 2
    return run(layouts, args.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
