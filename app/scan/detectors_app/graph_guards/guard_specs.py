"""Intra-procedural guard polarity and privileged state-mutation sink specs."""

from __future__ import annotations

import ast
import re

GUARD_CALL_PREFIXES = (
    "verify_",
    "check_auth",
    "check_perm",
    "check_role",
    "check_admin",
    "check_owner",
    "check_access",
    "check_sig",
    "require_auth",
    "require_perm",
    "require_role",
    "require_admin",
    "require_owner",
    "ensure_auth",
    "ensure_admin",
    "ensure_owner",
    "authorize",
    "authenticate",
    "validate_token",
    "validate_signature",
    "validate_webhook",
)

GUARD_EXACT_CALLS = frozenset({
    "compare_digest",
    "verify_hmac",
    "verify_jwt",
    "verify_csrf",
    "is_authenticated",
    "is_authorized",
    "has_permission",
    "has_role",
})

OWNERSHIP_ATTRS = frozenset({
    "owner_id",
    "account_id",
    "tenant_id",
    "org_id",
    "organization_id",
    "is_admin",
    "is_superuser",
    "is_staff",
})

MUTATING_SQL_RE = re.compile(
    r"^\s*\(*\s*(insert|update|delete|replace|upsert|merge|truncate)\b",
    re.IGNORECASE,
)
SQL_RUNNER_METHODS = frozenset({"execute", "executemany", "execute_sql", "raw", "run"})

PRIVILEGED_SINK_METHODS = frozenset({
    "delete_account",
    "delete_user",
    "delete_record",
    "delete_project",
    "delete_item",
    "drop_table",
    "grant_role",
    "grant_admin",
    "grant_access",
    "grant_pro",
    "issue_refund",
    "process_refund",
    "refund_payment",
    "transfer_funds",
    "payout",
    "mark_paid",
    "mark_delivered",
    "mark_fixpack_delivered",
    "update_permissions",
    "update_role",
    "set_password",
    "reset_password",
    "rotate_secret",
})

SAFE_SCHEDULER_CALLS = frozenset({"add_task", "create_task"})


def _call_tail_name(call: ast.Call) -> str | None:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _is_positive_guard_Atomic(expr: ast.expr) -> str | None:
    """Return guard class ('signature' | 'authz') if expr is a positive security check."""
    if isinstance(expr, ast.Call):
        name = _call_tail_name(expr)
        if not name:
            return None
        low = name.lower()
        if low == "compare_digest" or "signature" in low or "hmac" in low or "webhook" in low or "csrf" in low:
            if low in GUARD_EXACT_CALLS or low.startswith(GUARD_CALL_PREFIXES):
                return "signature"
        if low in GUARD_EXACT_CALLS or low.startswith(GUARD_CALL_PREFIXES):
            return "authz"
        return None

    auth_flags = {"is_admin", "is_superuser", "is_staff", "is_authenticated"}
    if isinstance(expr, ast.Attribute) and expr.attr.lower() in auth_flags:
        return "authz"

    if isinstance(expr, ast.Compare) and len(expr.ops) == 1 and isinstance(expr.ops[0], (ast.Eq, ast.In)):
        names = {
            n.attr.lower()
            for side in (expr.left, *expr.comparators)
            for n in ast.walk(side)
            if isinstance(n, ast.Attribute)
        } | {
            n.id.lower()
            for side in (expr.left, *expr.comparators)
            for n in ast.walk(side)
            if isinstance(n, ast.Name)
        }
        if names & OWNERSHIP_ATTRS:
            return "authz"
    return None


def _is_negative_ownership_compare(expr: ast.expr) -> str | None:
    if isinstance(expr, ast.Compare) and len(expr.ops) == 1 and isinstance(expr.ops[0], (ast.NotEq, ast.NotIn)):
        names = {
            n.attr.lower()
            for side in (expr.left, *expr.comparators)
            for n in ast.walk(side)
            if isinstance(n, ast.Attribute)
        } | {
            n.id.lower()
            for side in (expr.left, *expr.comparators)
            for n in ast.walk(side)
            if isinstance(n, ast.Name)
        }
        if names & OWNERSHIP_ATTRS:
            return "authz"
    return None


def classify_branch_guard(condition: ast.expr | None) -> tuple[str, str] | None:
    """Return (guard_class, protected_edge_kind) for a branch condition, or None.

    - Positive condition `if verify_token(req):` -> ("authz", "branch_true")
    - Inverted guard `if not verify_token(req):` -> ("authz", "branch_false")
    - Negative ownership check `if row.owner_id != user.id:` -> ("authz", "branch_false")
    """
    if condition is None:
        return None
    if isinstance(condition, ast.UnaryOp) and isinstance(condition.op, ast.Not):
        inner = _is_positive_guard_Atomic(condition.operand)
        if inner is not None:
            return (inner, "branch_false")
        return None

    neg = _is_negative_ownership_compare(condition)
    if neg is not None:
        return (neg, "branch_false")

    pos = _is_positive_guard_Atomic(condition)
    if pos is not None:
        return (pos, "branch_true")

    if isinstance(condition, ast.BoolOp) and isinstance(condition.op, ast.And):
        for val in condition.values:
            g = _is_positive_guard_Atomic(val)
            if g is not None:
                return (g, "branch_true")
    return None


def classify_standalone_guard_call(stmt: ast.stmt) -> str | None:
    """Detect non-branch guard calls like `require_admin(user)` or `verify_signature(raw)`."""
    if not isinstance(stmt, ast.Expr) or not isinstance(stmt.value, ast.Call):
        return None
    name = _call_tail_name(stmt.value)
    if not name:
        return None
    low = name.lower()
    if low.startswith(("require_", "ensure_", "authorize", "verify_")):
        if "signature" in low or "hmac" in low or "webhook" in low or "csrf" in low:
            return "signature"
        return "authz"
    return None


def find_privileged_sink(stmt: ast.stmt) -> tuple[str, int] | None:
    """Return (sink_label, line) if stmt executes a privileged state mutation."""
    compound = (
        ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.If, ast.For,
        ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith, ast.Match,
    )
    if isinstance(stmt, compound):
        return None
    for node in ast.walk(stmt):
        if not isinstance(node, ast.Call):
            continue
        name = _call_tail_name(node)
        if not name or name in SAFE_SCHEDULER_CALLS:
            continue
        low = name.lower()
        if low in PRIVILEGED_SINK_METHODS:
            return (name, getattr(node, "lineno", getattr(stmt, "lineno", 1)))
        if low in SQL_RUNNER_METHODS and node.args:
            first = node.args[0]
            sql_text: str | None = None
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                sql_text = first.value
            elif isinstance(first, ast.JoinedStr):
                parts = [
                    p.value for p in first.values
                    if isinstance(p, ast.Constant) and isinstance(p.value, str)
                ]
                sql_text = "".join(parts)
            if sql_text and MUTATING_SQL_RE.search(sql_text):
                return (f"{name}(SQL mutation)", getattr(node, "lineno", getattr(stmt, "lineno", 1)))
    return None
