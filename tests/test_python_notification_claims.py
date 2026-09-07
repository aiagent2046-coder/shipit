"""Bounded control-flow counterexamples; submitted Python is never executed."""
import io
from pathlib import Path
import zipfile

import pytest

from app.scan.syntax_claims import SyntaxVerifier

TITLE = "Completed invoice still calls notify_operator"
SOURCE = '''async def report_paid(repo, ref):
    row = await get_invoice(repo, ref)
    if row is None:
        return None
    if row["status"] == "completed":
        return {"reference": ref, "notified": False}
    notified = await notify_operator(row)
    return {"notified": notified}
'''


def check(source=SOURCE, *, title=TITLE, start=1, end=None):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("billing.py", source)
    return SyntaxVerifier(archive).check({"title": title, "file": "billing.py",
                                        "line_start": start,
                                        "line_end": end or len(source.splitlines())})


def test_completed_branch_returns_before_direct_notification():
    result = check()
    assert result["result"] == "contradicted"
    assert (result["line_start"], result["line_end"]) == (5, 6)
    assert "concurrency and delivery were not tested" in result["detail"]


def test_real_bank_transfer_completed_guard():
    import ast

    source = Path("app/billing/bank_transfer.py").read_text()
    fn = next(n for n in ast.parse(source).body
              if isinstance(n, ast.AsyncFunctionDef) and n.name == "mark_awaiting_confirmation")
    assert check(source, start=fn.lineno, end=fn.end_lineno)["result"] == "contradicted"


@pytest.mark.parametrize("source", [
    SOURCE.replace('return {"reference": ref, "notified": False}', 'pass'),
    SOURCE.replace('return {"reference": ref, "notified": False}', 'return notify_operator(row)'),
    SOURCE.replace('    if row["status"]', '    await notify_operator(row)\n    if row["status"]'),
    SOURCE.replace('    if row["status"]', '    alias = notify_operator\n    if row["status"]')
    .replace('await notify_operator(row)', 'await alias(row)'),
    SOURCE.replace('== "completed"', '!= "completed"'),
    SOURCE.replace('== "completed"', '== "pending"'),
    '@wrapper\n' + SOURCE,
    SOURCE + '\nasync def other():\n    return 0\n',
    'async def report_paid(row):\n    try:\n        return None\n    finally:\n        await notify_operator(row)\n',
    'async def report_paid(row):\n    text = "if completed: return"\n    await notify_operator(row)\n',
    'async def broken(',
])
def test_unsupported_shapes_are_not_dismissed(source):
    assert check(source)["result"] == "not_checked"


@pytest.mark.parametrize("title", [
    "Completed invoice still calls notify_operator and writes no state",
    "Completed invoice never calls notify_operator",
    "mark_awaiting_confirmation writes no state, so a payer still triggers the notify path",
    "Completed invoice still sends an email",
    "other_function: Completed invoice still calls notify_operator",
])
def test_compound_or_broader_claims_remain_unknown(title):
    assert check(title=title)["result"] == "not_checked"
