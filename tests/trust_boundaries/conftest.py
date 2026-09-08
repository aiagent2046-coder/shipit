"""Builders for static detector, scoring and report-retention regressions.

Synthetic ZIP contents are scanned as data, never executed. These examples
exercise particular rules; they do not establish runtime authorization,
payment correctness or exhaustive project security.
"""

from __future__ import annotations

import io
import zipfile


def make_zip(entries: dict[str, str | bytes]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in entries.items():
            zf.writestr(name, body)
    buf.seek(0)
    return buf


NEXTJS_PACKAGE = '{"dependencies": {"next": "14.0.0", "react": "18.0.0"}}'

NEXTJS_APP_FILES: dict[str, str] = {
    "package.json": NEXTJS_PACKAGE,
    "app/layout.tsx": "export default function L({children}) { return <html>{children}</html> }",
    "app/page.tsx": "export default function P() { return <div/> }",
    "app/error.tsx": "'use client'\nexport default function E(){return <div/>}",
    "src/x.test.ts": "test('a', () => {})",
    "Dockerfile": "FROM node:20",
    ".github/workflows/ci.yml": "name: ci\non: push\njobs: {}\n",
    ".gitignore": ".env\nnode_modules\n",
}


def clean_nextjs_repo(**overrides: str) -> dict[str, str]:
    """A small Next.js repository that the static stage reports NOTHING on.

    If a change to the scanners makes this repo produce a finding, either the
    scanner gained a rule this fixture should grow (update it) or the rule
    false-positives on a mundane app (fix the rule). Kept in one place so the
    hostile-mutation tests share one definition of 'clean'.
    """
    repo = dict(NEXTJS_APP_FILES)
    repo.update(overrides)
    return repo


def findings_keys(findings: list[dict]) -> list[tuple[str, str, str]]:
    """The identity a finding keeps across benign edits: rule, file, severity.

    `line` is deliberately excluded -- app/monitor/diff.py excludes it for the
    same reason: unrelated edits above a finding shift it, and identity must
    survive that.
    """
    return sorted((f["rule_id"], f["file"], f["severity"]) for f in findings)
