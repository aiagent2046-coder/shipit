"""TypeScript / Next.js / Express guard polarity and privileged sink specifications."""

from __future__ import annotations

import re

from app.scan.detectors_app.graph_guards.ts_cfg_builder import TSStmt, TSToken, _match_delim

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

_ERROR_KEYS = frozenset({"error", "err", "errors"})
_IGNORED_BINDINGS = frozenset({
    "error",
    "err",
    "errors",
    "const",
    "let",
    "var",
    "await",
    "async",
    "supabase",
    "client",
    "admin",
    "db",
    "prisma",
})
_SECRET_ENV_MARKERS = ("TOKEN", "SECRET", "KEY", "PASS", "AUTH")
_GUARD_RESULT_PROPS = frozenset({"user", "session", "ok", "valid", "authenticated", "authorized", "id"})


def _called_names_in_tokens(toks: tuple[TSToken, ...]) -> list[tuple[str | None, str, int]]:
    calls: list[tuple[str | None, str, int]] = []
    n = len(toks)
    for i, t in enumerate(toks):
        if t.kind == "IDENT" and i + 1 < n:
            nxt = toks[i + 1]
            open_idx = i + 1
            if nxt.value == "<":
                end_g = _match_delim(toks, i + 1, "<", ">")
                if end_g != -1:
                    open_idx = end_g + 1
            if open_idx < n and toks[open_idx].value == "(":
                prev_id: str | None = None
                if i >= 2 and toks[i - 1].value in {".", "?."} and toks[i - 2].kind == "IDENT":
                    prev_id = toks[i - 2].value
                calls.append((prev_id, t.value, t.line))
    return calls


def collect_guard_var_bindings(
    stmt: TSStmt,
    guard_vars: dict[str, str],
    callee_returns_guard: dict[str, str] | None = None,
) -> None:
    """Record local variables populated by auth/session, signature, or helper lookups."""
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
        if callee_returns_guard:
            qual_key = f"{prev_id}.{fn_name}" if prev_id else fn_name
            if qual_key in callee_returns_guard:
                rhs_cls = callee_returns_guard[qual_key]
                break
            if fn_name in callee_returns_guard:
                rhs_cls = callee_returns_guard[fn_name]
                break

    if rhs_cls is None:
        return

    brace_depth = 0
    skip_indices: set[int] = set()
    for idx, tok in enumerate(lhs):
        if idx in skip_indices:
            continue
        if tok.value == "{":
            brace_depth += 1
            continue
        if tok.value == "}":
            brace_depth = max(0, brace_depth - 1)
            continue
        if brace_depth == 0 and tok.value == ":":
            break
        if tok.kind != "IDENT" or tok.value in _IGNORED_BINDINGS:
            continue
        if brace_depth > 0 and idx + 1 < len(lhs) and lhs[idx + 1].value == ":":
            if tok.value in _ERROR_KEYS and idx + 2 < len(lhs) and lhs[idx + 2].kind == "IDENT":
                skip_indices.add(idx + 2)
            continue
        low = tok.value.lower()
        if low.endswith(("err", "error")):
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


def _split_top_level_boolean(
    cond: tuple[TSToken, ...],
) -> tuple[list[tuple[TSToken, ...]], list[str]]:
    clauses: list[tuple[TSToken, ...]] = []
    ops: list[str] = []
    cur: list[TSToken] = []
    p_d = b_d = s_d = 0
    for tok in cond:
        v = tok.value
        if v == "(":
            p_d += 1
        elif v == ")" and p_d > 0:
            p_d -= 1
        elif v == "{":
            b_d += 1
        elif v == "}" and b_d > 0:
            b_d -= 1
        elif v == "[":
            s_d += 1
        elif v == "]" and s_d > 0:
            s_d -= 1
        elif v in {"||", "&&"} and p_d == 0 and b_d == 0 and s_d == 0:
            if cur:
                clauses.append(tuple(cur))
                cur = []
            ops.append(v)
            continue
        cur.append(tok)
    if cur:
        clauses.append(tuple(cur))
    return (clauses, ops)


def _has_secret_env_ref(clause: tuple[TSToken, ...]) -> bool:
    n = len(clause)
    for i in range(n - 4):
        if (
            clause[i].value == "process"
            and clause[i + 1].value == "."
            and clause[i + 2].value == "env"
            and clause[i + 3].value == "."
            and clause[i + 4].kind == "IDENT"
        ):
            env_name = clause[i + 4].value.upper()
            if any(m in env_name for m in _SECRET_ENV_MARKERS):
                return True
    return False


def _classify_atomic_clause(
    clause: tuple[TSToken, ...],
    guard_vars: dict[str, str],
) -> tuple[str, str] | None:
    if not clause:
        return None

    ops = [t.value for t in clause if t.kind == "OP"]
    idents = {t.value for t in clause if t.kind == "IDENT"}

    if _has_secret_env_ref(clause):
        non_env_idents = idents - {"process", "env"}
        if any(not k.isupper() for k in non_env_idents):
            if "!==" in ops or "!=" in ops:
                return ("authz", "branch_false")
            if "===" in ops or "==" in ops:
                return ("authz", "branch_true")

    if idents & OWNERSHIP_IDENTIFIERS:
        if "!==" in ops or "!=" in ops:
            return ("authz", "branch_false")
        if "===" in ops or "==" in ops:
            return ("authz", "branch_true")

    has_bang = any(t.value == "!" for t in clause)
    for _, fn_name, _ in _called_names_in_tokens(clause):
        if fn_name in LOOKUP_SIGNATURE_CALLS or fn_name in THROWING_SIGNATURE_CALLS:
            return ("signature", "branch_false" if has_bang else "branch_true")
        if fn_name in LOOKUP_AUTHZ_CALLS or fn_name.startswith(THROWING_AUTHZ_PREFIXES):
            return ("authz", "branch_false" if has_bang else "branch_true")

    for idx, t in enumerate(clause):
        if t.kind != "IDENT":
            continue
        is_prop_tail = idx >= 1 and clause[idx - 1].value in {".", "?."}
        g_cls: str | None = None
        root_idx = idx

        if not is_prop_tail:
            g_cls = guard_vars.get(t.value)
            if g_cls is None and t.value in {"session", "currentUser"}:
                g_cls = "authz"
        elif idx >= 2 and clause[idx - 2].kind == "IDENT":
            parent = clause[idx - 2].value
            if parent in guard_vars and t.value in _GUARD_RESULT_PROPS:
                g_cls = guard_vars[parent]
                root_idx = idx - 2
            elif t.value == "user" and parent in {"req", "ctx", "session", "locals"}:
                g_cls = "authz"
                root_idx = idx - 2

        if g_cls is not None:
            if (
                not is_prop_tail
                and idx + 2 < len(clause)
                and clause[idx + 1].value in {".", "?."}
                and clause[idx + 2].value in _ERROR_KEYS
            ):
                continue
            negated = any(p.value == "!" for p in clause[max(0, root_idx - 3) : root_idx])
            null_eq = any(
                clause[k].value in {"===", "=="}
                and k + 1 < len(clause)
                and clause[k + 1].value in {"null", "undefined", "false"}
                for k in range(idx + 1, min(len(clause), idx + 5))
            )
            if negated or null_eq:
                return (g_cls, "branch_false")
            return (g_cls, "branch_true")

    return None


def classify_ts_branch_guard(
    cond: tuple[TSToken, ...] | None,
    guard_vars: dict[str, str],
) -> tuple[str, str] | None:
    """Return `(guard_class, protected_edge_kind)` for an `if (cond)` condition using De Morgan laws."""
    if not cond:
        return None

    if cond[0].value == "(" and _match_delim(cond, 0, "(", ")") == len(cond) - 1:
        return classify_ts_branch_guard(cond[1:-1], guard_vars)
    if (
        len(cond) >= 3
        and cond[0].value == "!"
        and cond[1].value == "("
        and _match_delim(cond, 1, "(", ")") == len(cond) - 1
    ):
        inner = classify_ts_branch_guard(cond[2:-1], guard_vars)
        if inner is None:
            return None
        g_cls, edge_k = inner
        return (g_cls, "branch_false" if edge_k == "branch_true" else "branch_true")

    clauses, top_ops = _split_top_level_boolean(cond)
    if len(clauses) == 1:
        return _classify_atomic_clause(clauses[0], guard_vars)

    subs = [classify_ts_branch_guard(c, guard_vars) for c in clauses]
    op_set = set(top_ops)

    if op_set == {"||"}:
        for pref in ("signature", "authz"):
            if any(s == (pref, "branch_false") for s in subs):
                return (pref, "branch_false")
        if all(s is not None and s[1] == "branch_true" for s in subs):
            first_cls = subs[0][0]  # type: ignore[index]
            return (first_cls, "branch_true")
        return None

    if op_set == {"&&"}:
        for pref in ("signature", "authz"):
            if any(s == (pref, "branch_true") for s in subs):
                return (pref, "branch_true")
        if all(s is not None and s[1] == "branch_false" for s in subs):
            first_cls = subs[0][0]  # type: ignore[index]
            return (first_cls, "branch_false")
        return None

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
