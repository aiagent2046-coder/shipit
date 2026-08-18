"""Judge one PostgREST answer: did the anon key read rows it should not have?

Part B of SUPABASE_RLS_YIELD_PLAN.md. Separated from the probe for the reason
app/proof/cors_oracle.py was: the judgement is the part that can be wrong in a
way nobody notices, so it is a pure function over a response with tests on the
statuses, and the network lives elsewhere.

WHAT POSTGREST ACTUALLY RETURNS, because the intuition is wrong:

    RLS on, no matching policy  -> 200 []          (rows FILTERED, not denied)
    GRANT missing               -> 401/403, 42501  (denied)
    table not in exposed schema -> 404, PGRST205
    bad or missing key          -> 401

The healthy, correctly-secured application answers **200 with an empty array**.
It does not answer 403. Anyone expecting a denial will read the normal secure
case as an error and the exposed case as normal.

THE TRAP THIS FILE EXISTS FOR. `200 []` is what a protected table returns AND
what an empty table returns, and one request cannot tell them apart. Reporting
it alone as "we checked, your data is protected" would be the same defect this
project removed from the CORS oracle, where `*` without credentials was scored
as an exploit: a verdict stated more strongly than the evidence supports.

So `empty_result` never proves protection on its own. It means something only
as the AFTER half of a pair whose BEFORE half read real rows out of that same
table — at which point the table is known to be non-empty and the same request
returning nothing is a genuine before/after. `app/proof/compare.py` already
enforces exactly that shape, which is why this returns a verdict rather than a
conclusion.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# PostgREST's code for a row-level/permission refusal, surfaced in the JSON
# body rather than only in the status line.
PG_INSUFFICIENT_PRIVILEGE = "42501"
PGRST_UNDEFINED_TABLE = "PGRST205"


@dataclass(frozen=True)
class RlsVerdict:
    exposed: bool
    reason: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)
    # False when the probe learned nothing about the application — a bad key,
    # a 5xx, an unreadable body. The caller MUST report those as `error`, not
    # as "the attack did not work"; a stand that never answered has said
    # nothing, which is the distinction #22 was about.
    conclusive: bool = True


def summarise_rows(rows: list[dict[str, Any]], limit: int = 3) -> dict[str, Any]:
    """Describe rows without carrying a single value out of them.

    This record is stored in proof_json and rendered into a PR. The rows are a
    customer's users' data — the one thing that must not travel, even redacted
    into something clever. Column names, count, and value LENGTHS are enough to
    prove a read happened and to show the customer which fields were reachable.

    Length is included because "email: str(24)" is evidence a real address sat
    there, while "email" alone could be an empty column.
    """
    sample = rows[:limit]
    columns: list[str] = []
    for row in sample:
        for key in row:
            if key not in columns:
                columns.append(key)
    shapes = {
        key: _shape(next((r[key] for r in sample if r.get(key) is not None), None))
        for key in columns
    }
    return {
        "rows_read": len(rows),
        "columns": columns,
        "shapes": shapes,
    }


def _shape(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return type(value).__name__
    if isinstance(value, str):
        return f"str({len(value)})"
    if isinstance(value, list):
        return f"list({len(value)})"
    if isinstance(value, dict):
        return f"object({len(value)} keys)"
    return type(value).__name__


def evaluate_rls_response(
    status_code: int,
    body: Any,
    *,
    table: str = "",
) -> RlsVerdict:
    """Decide what one anon `select` says about a table's protection."""
    if status_code == 200 and isinstance(body, list):
        if body:
            summary = summarise_rows(body)
            return RlsVerdict(
                exposed=True,
                reason="rows_readable",
                detail=(f"анонимный ключ прочитал {summary['rows_read']} "
                        f"строк(и) из `{table or 'таблицы'}`"),
                evidence={**summary, "table": table, "status": status_code},
            )
        return RlsVerdict(
            exposed=False,
            reason="empty_result",
            detail=("анонимный запрос вернул пустой результат — это ответ и "
                    "защищённой таблицы, и пустой"),
            evidence={
                "table": table,
                "status": status_code,
                "rows_read": 0,
                # Carried explicitly so nothing downstream can quote this as
                # proof of protection without the pair that earns it.
                "alone_proves_nothing": True,
            },
        )

    code = ""
    message = ""
    if isinstance(body, dict):
        code = str(body.get("code") or "")
        message = str(body.get("message") or "")

    if status_code in (401, 403) or code == PG_INSUFFICIENT_PRIVILEGE:
        # A real denial, and unlike an empty result it stands on its own: the
        # database refused rather than returning nothing.
        return RlsVerdict(
            exposed=False,
            reason="permission_denied",
            detail="база отказала анонимному ключу в доступе к таблице",
            evidence={"table": table, "status": status_code, "code": code},
            # A 401 with no PostgREST code is more likely OUR key being wrong
            # than their table being safe, and guessing between the two is how
            # a broken probe reports every customer as secure.
            conclusive=bool(code),
        )

    if status_code == 404 or code == PGRST_UNDEFINED_TABLE:
        return RlsVerdict(
            exposed=False,
            reason="table_not_exposed",
            detail="таблица не опубликована через PostgREST",
            evidence={"table": table, "status": status_code, "code": code},
        )

    return RlsVerdict(
        exposed=False,
        reason="unexpected_response",
        detail=f"неожиданный ответ: HTTP {status_code} {code or message}"[:200],
        evidence={"table": table, "status": status_code, "code": code},
        conclusive=False,
    )
