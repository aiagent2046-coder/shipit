"""TypeScript / Next.js / Express guard polarity and privileged sink specifications."""

from __future__ import annotations

import re

from app.scan.detectors_app.graph_guards.ts_cfg_builder import TSStmt, TSToken

THROWING_SIGNATURE_CALLS = frozenset({
    "constructEvent",
    "constructEventAsync",
    "assertWebhookSignature",
    "requireValidSignature",
})

THROWING_AUTHZ_PREFIXES = (
    "requireAuth",
    "requireAdmin",
    "requireUser",
    "requireSession",
    "requireRole",
    "requirePerm",
    "requireOwner",
    "requireMember",
    "requireOrg",
    "ensureAuth",
    "ensureAdmin",
    "ensureOwner",
    "assertAuth",
    "assertAdmin",
    "assertOwner",
    "authorize",
)

LOOKUP_AUTHZ_CALLS = frozenset({
    "auth",
    "getServerSession",
    "currentUser",
    "getAuth",
    "getUser",
    "getSession",
    "verifyToken",
    "verifyJwt",
    "verifyIdToken",
    "validateRequest",
    "validateSession",
    "checkAuth",
    "checkAdmin",
    "checkPermission",
    "checkRole",
    "hasPermission",
    "hasRole",
    "isAdmin",
    "isAuthenticated",
    "isAuthorized",
})

LOOKUP_SIGNATURE_CALLS = frozenset({
    "timingSafeEqual",
    "verifySignature",
    "verifyWebhook",
    "verifyWebhookSignature",
    "verifyHmac",
    "validateWebhook",
    "validateSignature",
})

OWNERSHIP_IDENTIFIERS = frozenset({
    "ownerId",
    "owner_id",
    "userId",
    "user_id",
    "accountId",
    "account_id",
    "orgId",
    "org_id",
    "organizationId",
    "organization_id",
    "tenantId",
    "tenant_id",
    "authorId",
    "author_id",
    "isAdmin",
    "is_admin",
    "role",
})

NON_DB_DELETE_RECEIVERS = frozenset({
    "headers",
    "reqHeaders",
    "resHeaders",
    "searchParams",
    "urlSearchParams",
    "params",
    "cookies",
    "cookieStore",
    "cache",
    "map",
    "set",
    "seen",
    "formData",
    "localStorage",
    "sessionStorage",
    "classList",
})

ORM_ROOT_NAMES = frozenset({"prisma", "tx", "db", "trx", "knex", "drizzle"})
ORM_MUTATION_METHODS = frozenset({
    "delete",
    "deleteMany",
    "deleteOne",
    "findByIdAndDelete",
    "findOneAndDelete",
    "update",
    "updateMany",
    "updateOne",
    "findByIdAndUpdate",
    "upsert",
    "$executeRaw",
    "$executeRawUnsafe",
})

DIRECT_PRIVILEGED_CALLS = frozenset({
    "deleteUser",
    "deleteAccount",
    "deleteOrganization",
    "deleteProject",
    "deleteWorkspace",
    "issueRefund",
    "processRefund",
    "refundPayment",
    "transferFunds",
    "grantRole",
    "grantAdmin",
    "updatePermissions",
    "updateRole",
    "resetPassword",
    "rotateSecret",
})

MUTATING_SQL_RE = re.compile(
    r"^\s*\(*\s*(insert|update|delete|replace|upsert|merge|truncate|drop|alter)\b",
    re.IGNORECASE,
)
SQL_CALL_TAILS = frozenset({
    "query",
    "execute",
    "raw",
    "unsafe",
    "$executeRaw",
    "$executeRawUnsafe",
})

_IGNORED_BINDINGS = frozenset({"error", "err", "data", "const", "let", "var", "await", "async"})


def _called_names_in_tokens(toks: tuple[TSToken, ...]) -> list[tuple[str | None, str, int]]:
    calls: list[tuple[str | None, str, int]] = []
    n = len(toks)
    for i, t in enumerate(toks):
        if t.kind == "IDENT" and i + 1 < n:
            nxt = toks[i + 1]
            open_idx = i + 1
            if nxt.value == "<":
                depth = 0
                for k in range(i + 1, n):
                    if toks[k].value == "<":
                        depth += 1
                    elif toks[k].value == ">":
                        depth -= 1
                        if depth == 0:
                            open_idx = k + 1
                            break
            if open_idx < n and toks[open_idx].value == "(":
                prev_id: str | None = None
                if i >= 2 and toks[i - 1].value in {".", "?."} and toks[i - 2].kind == "IDENT":
                    prev_id = toks[i - 2].value
                calls.append((prev_id, t.value, t.line))
    return calls


def collect_guard_var_bindings(stmt: TSStmt, guard_vars: dict[str, str]) -> None:
    """Record local variables populated by auth/session or webhook-signature lookups."""
    toks = stmt.tokens
    if not toks or toks[0].value not in {"const", "let", "var"}:
        return
    eq_idx = -1
    depth = 0
    for i, t in enumerate(toks):
        if t.value in {"{", "[", "("}:
            depth += 1
        elif t.value in {"}", "]", ")"} and depth > 0:
            depth -= 1
        elif t.value == "=" and depth == 0:
            eq_idx = i
            break
    if eq_idx == -1:
        return

    lhs = toks[1:eq_idx]
    rhs = toks[eq_idx + 1 :]
    rhs_cls: str | None = None
    for prev_id, fn_name, _ in _called_names_in_tokens(rhs):
        if fn_name in LOOKUP_SIGNATURE_CALLS or (prev_id in {"svix", "wh"} and fn_name == "verify"):
            rhs_cls = "signature"
            break
        if fn_name in LOOKUP_AUTHZ_CALLS or fn_name.startswith(("getAuth", "verifyAuth", "checkAuth")):
            rhs_cls = "authz"
            break

    if rhs_cls is None:
        return

    for idx, tok in enumerate(lhs):
        if tok.kind != "IDENT" or tok.value in _IGNORED_BINDINGS:
            continue
        if idx + 1 < len(lhs) and lhs[idx + 1].value == ":":
            continue
        guard_vars[tok.value] = rhs_cls


def classify_ts_standalone_guard(
    stmt: TSStmt,
    custom_must_guards: dict[str, str] | None = None,
) -> str | None:
    """Detect calls that throw on guard failure (not wrapped in an `if` test)."""
    toks = stmt.tokens
    if not toks or toks[0].value in {"return", "throw"}:
        return None
    for prev_id, fn_name, _ in _called_names_in_tokens(toks):
        if fn_name in THROWING_SIGNATURE_CALLS or (
            prev_id in {"wh", "svix", "webhooks"} and fn_name == "verify"
        ):
            return "signature"
        if fn_name.startswith(THROWING_AUTHZ_PREFIXES):
            return "authz"
        if custom_must_guards and fn_name in custom_must_guards:
            return custom_must_guards[fn_name]
    return None


def classify_ts_branch_guard(
    cond: tuple[TSToken, ...] | None,
    guard_vars: dict[str, str],
) -> tuple[str, str] | None:
    """Return `(guard_class, protected_edge_kind)` for an `if (cond)` condition."""
    if not cond:
        return None

    ops = [t.value for t in cond if t.kind == "OP"]
    idents = {t.value for t in cond if t.kind == "IDENT"}
    if idents & OWNERSHIP_IDENTIFIERS:
        if "!==" in ops or "!=" in ops:
            return ("authz", "branch_false")
        if "===" in ops or "==" in ops:
            return ("authz", "branch_true")

    has_bang = any(t.value == "!" for t in cond)
    for _, fn_name, _ in _called_names_in_tokens(cond):
        if fn_name in LOOKUP_SIGNATURE_CALLS or fn_name in THROWING_SIGNATURE_CALLS:
            return ("signature", "branch_false" if has_bang else "branch_true")
        if fn_name in LOOKUP_AUTHZ_CALLS or fn_name.startswith(THROWING_AUTHZ_PREFIXES):
            return ("authz", "branch_false" if has_bang else "branch_true")

    for idx, t in enumerate(cond):
        g_cls = guard_vars.get(t.value)
        if g_cls is None and t.value in {"session", "currentUser"}:
            g_cls = "authz"
        if (
            g_cls is None
            and t.value == "user"
            and idx >= 2
            and cond[idx - 1].value in {".", "?."}
            and cond[idx - 2].value in {"req", "ctx", "session", "locals"}
        ):
            g_cls = "authz"
        if g_cls is not None:
            negated = any(p.value == "!" for p in cond[max(0, idx - 3) : idx])
            null_eq = any(
                cond[k].value in {"===", "=="}
                and k + 1 < len(cond)
                and cond[k + 1].value in {"null", "undefined", "false"}
                for k in range(idx + 1, min(len(cond), idx + 5))
            )
            if negated or null_eq:
                return (g_cls, "branch_false")
            return (g_cls, "branch_true")

    return None


def find_ts_privileged_sink(stmt: TSStmt) -> tuple[str, int] | None:
    """Return `(sink_label, line)` if `stmt` executes a privileged DB/ORM/payment mutation."""
    toks = stmt.tokens
    if not toks:
        return None

    n = len(toks)
    for i, t in enumerate(toks):
        if t.kind != "IDENT":
            continue

        if t.value in DIRECT_PRIVILEGED_CALLS and i + 1 < n and toks[i + 1].value == "(":
            return (t.value, t.line)

        if (
            t.value == "create"
            and i >= 4
            and i + 1 < n
            and toks[i + 1].value == "("
            and toks[i - 1].value == "."
            and toks[i - 2].value in {"refunds", "transfers", "payouts"}
        ):
            return (f"stripe.{toks[i - 2].value}.create", t.line)

        if t.value in ORM_MUTATION_METHODS and i >= 2 and i + 1 < n and toks[i + 1].value == "(":
            if toks[i - 1].value in {".", "?."}:
                recv = toks[i - 2].value
                if recv in NON_DB_DELETE_RECEIVERS:
                    continue
                if recv in ORM_ROOT_NAMES or t.value not in {"delete", "update"}:
                    return (f"{recv}.{t.value}", t.line)
                if (
                    i >= 4
                    and toks[i - 3].value in {".", "?."}
                    and toks[i - 4].value in ORM_ROOT_NAMES
                ):
                    return (f"{toks[i - 4].value}.{recv}.{t.value}", t.line)
                prefix_idents = {pt.value for pt in toks[:i] if pt.kind == "IDENT"}
                if prefix_idents & {"supabase", "from", "table", "prisma", "db", "tx", "knex"}:
                    return (f"{t.value}({recv})", t.line)

        if t.value in SQL_CALL_TAILS and i + 2 < n and toks[i + 1].value == "(":
            first_arg = toks[i + 2]
            if first_arg.kind == "STRING" and MUTATING_SQL_RE.search(first_arg.value):
                return (f"{t.value}(SQL mutation)", t.line)

    return None
