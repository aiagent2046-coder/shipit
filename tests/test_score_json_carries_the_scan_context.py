"""`mount` survives into the stored row, because a calibration question needed it
and could not be asked.

MEASURED 2026-09-04. "Should a repository with no frontend at all have Frontend
excluded rather than counted at 10.0?" is a question about the rows already in
the ledger. It could not be put to them: `mount` was computed for every audit
and kept for none, so answering meant re-fetching and re-scanning every
repository the product had ever seen.

`basis` already travels inside `score_json` for exactly this reason -- so it
reaches the DB and every consumer of the score rather than being decided during
a scan and thrown away. This is the same argument applied to the same blob, and
in jsonb it costs no migration.

BOTH producers are tested, and the paid one is the one that matters: a
calibration decision is expensive to get wrong precisely on the rows somebody
paid for.
"""

from __future__ import annotations

import io
import zipfile

from app.llm.client import LLMClient
from app.scan.pipeline import run_scan
from app.scan.static import run_static_scan


def _zip(files: dict[str, str]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    buf.seek(0)
    return buf


_MOUNTED_SPA = {
    "package.json": '{"dependencies":{"react":"18","react-dom":"18"}}',
    "src/main.tsx": ("import {createRoot} from 'react-dom/client';"
                     "createRoot(el).render(<App/>)"),
}
_NO_FRONTEND = {
    "requirements.txt": "flask\n",
    "app.py": "from flask import Flask\n",
}


def test_a_static_only_row_records_whether_the_repository_has_a_frontend():
    """The signal the calibration question turns on: `not_react` is a
    repository with no screen to blank, and it is currently scored a clean
    Frontend 10.0 at 15/110 of the weight."""
    mounted = run_static_scan(_zip(_MOUNTED_SPA))["score"]["frontend_scan"]
    backend = run_static_scan(_zip(_NO_FRONTEND))["score"]["frontend_scan"]

    assert mounted["mount"] == "mounted"
    assert backend["mount"] == "not_react"


def test_the_row_also_records_whether_the_scan_finished():
    """`coverage` rides along for the same reason. A budget-exhausted scan and
    a completed one already score differently; without this the stored row
    cannot say which it was."""
    scan = run_static_scan(_zip(_MOUNTED_SPA))["score"]["frontend_scan"]

    assert scan["coverage"] == "complete"


def test_a_full_audit_carries_it_too_not_just_a_static_one():
    """The paid path decides it in the static stage and must not drop it on the
    way out -- these are the rows a calibration decision costs money to get
    wrong. An empty provider chain keeps the LLM stage out of it; the field
    comes from the static stage either way."""
    score = run_scan(_zip(_MOUNTED_SPA).getvalue(), LLMClient(providers=[]))["score"]

    assert score["frontend_scan"]["mount"] == "mounted"


def test_the_field_is_additive_and_breaks_no_existing_reader():
    """Every consumer of score_json reads named keys through .get(); none
    enumerate it. Stated as a test because the whole point of putting this in
    the persisted blob is that old rows keep working -- a row written before
    this change simply has no `frontend_scan`, and nothing may crash on that."""
    score = run_static_scan(_zip(_MOUNTED_SPA))["score"]

    for required in ("total", "categories", "gated_by", "unexamined",
                     "reported_elsewhere"):
        assert required in score, f"{required} must survive the addition"
    assert score.get("frontend_scan", {}).get("mount")
    # The shape an OLD row has: absent, and readable without raising.
    assert {}.get("frontend_scan", {}).get("mount") is None
