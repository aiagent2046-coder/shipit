"""Deterministic TypeScript/Next.js/Express inter-procedural guard & taint summaries over Tarjan SCCs.

Pure-Python, zero native dependencies, bounded memory/CPU for 100% parity across
server scans, `drydock-local`, and Pyodide WASM.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import posixpath

from app.scan.detectors_app.graph_guards.call_summaries import (
    MAX_CALLEE_CHAIN,
    MAX_SUMMARY_FUNCTIONS,
    DelegatedSink,
    ParamSinkFlow,
    tarjan_scc,
)
from app.scan.detectors_app.graph_guards.cfg_builder import CFGBuildLimitError
from app.scan.detectors_app.graph_guards.ts_cfg_builder import (
    TSFunctionSpan,
    TSToken,
    _match_delim,
    build_ts_function_cfg,
)
from app.scan.detectors_app.graph_guards.ts_guard_specs import (
    LOOKUP_AUTHZ_CALLS,
    LOOKUP_SIGNATURE_CALLS,
    SQL_CALL_TAILS,
    classify_ts_branch_guard,
    classify_ts_standalone_guard,
    collect_guard_var_bindings,
    find_ts_privileged_sink,
)

TS_SANITIZER_CALLS = frozenset({
    "Number",
    "parseInt",
    "parseFloat",
    "BigInt",
    "Boolean",
    "encodeURIComponent",
    "escapeHtml",
})

TS_UNSAFE_SQL_CALLS = frozenset({
    "$queryRawUnsafe",
    "$executeRawUnsafe",
    "unsafe",
})

TS_SHELL_CALLS = frozenset({"exec", "execSync"})
TS_SPAWN_CALLS = frozenset({"spawn", "spawnSync"})
TS_EVAL_CALLS = frozenset({"eval", "Function", "runInNewContext", "runInThisContext"})

NEXT_HTTP_EXPORTS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
PROBE_SUFFIXES = (
    "",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mts",
    ".mjs",
    "/index.ts",
    "/index.tsx",
    "/index.js",
    "/index.mjs",
)


@dataclass(frozen=True)
class TSFunctionSummary:
    qual_id: str
    rel_file: str
    func_name: str
    lineno: int
    param_names: tuple[str, ...]
    must_guards: frozenset[str]
    unguarded_sinks: tuple[DelegatedSink, ...]
    param_to_return: frozenset[int]
    returns_untrusted_source: bool
    param_to_sinks: tuple[ParamSinkFlow, ...]
    returns_guard: frozenset[str] = frozenset()


@dataclass
class TSParsedFunctionUnit:
    qual_id: str
    mod_path: str
    rel_file: str
    span: TSFunctionSpan
    has_use_server: bool
    has_use_client: bool
    imports_child_process: bool
    # local_ident -> (target_mod_path, exported_symbol_or_default_or_star)
    imports_map: dict[str, tuple[str, str]]


@dataclass
class TSRepositoryCallIndex:
    units: dict[str, TSParsedFunctionUnit]
    by_mod_and_name: dict[tuple[str, str], str]
    default_by_mod: dict[str, str]
    by_unique_tail: dict[str, str | None]
    summaries: dict[str, TSFunctionSummary]


def normalize_ts_mod_path(rel_file: str) -> str:
    clean = rel_file.replace("\\", "/").strip("/")
    parts = clean.split("/")
    if len(parts) > 1 and "-" in parts[0] and "." not in parts[0]:
        if parts[1] in {"app", "src", "pages", "lib", "server", "api", "routes", "services"}:
            parts = parts[1:]
    return "/".join(parts)


def resolve_ts_import_path(
    spec: str,
    importer_mod_path: str,
    known_mod_paths: set[str],
) -> str | None:
    candidates: list[str] = []
    if spec.startswith("."):
        base_dir = posixpath.dirname(importer_mod_path)
        joined = posixpath.normpath(posixpath.join(base_dir, spec)).lstrip("/")
        candidates.append(joined)
    elif spec.startswith(("@/", "~/", "#/")):
        tail = spec[2:].lstrip("/")
        candidates.extend([tail, f"src/{tail}", f"app/{tail}"])
    else:
        return None

    for cand in candidates:
        for suf in PROBE_SUFFIXES:
            probe = f"{cand}{suf}"
            if probe in known_mod_paths:
                return probe
    return None


def parse_ts_imports(
    tokens: list[TSToken],
    importer_mod_path: str,
    known_mod_paths: set[str],
) -> tuple[dict[str, tuple[str, str]], bool]:
    """Return `(imports_map, imports_child_process)` for a tokenized TS/JS module."""
    imports_map: dict[str, tuple[str, str]] = {}
    has_child_proc = False
    n = len(tokens)
    i = 0

    while i < n:
        tok = tokens[i]
        # ES `import ... from "spec"`
        if tok.kind == "IDENT" and tok.value == "import":
            j = i + 1
            if j < n and tokens[j].value == "type":
                i = j + 1
                continue
            from_idx = -1
            for k in range(j, min(n, i + 60)):
                if tokens[k].kind == "IDENT" and tokens[k].value == "from":
                    from_idx = k
                    break
                if tokens[k].value == ";":
                    break
            if from_idx != -1 and from_idx + 1 < n and tokens[from_idx + 1].kind == "STRING":
                spec = tokens[from_idx + 1].value
                if spec in {"child_process", "node:child_process"}:
                    has_child_proc = True
                resolved = resolve_ts_import_path(spec, importer_mod_path, known_mod_paths)
                if resolved is not None:
                    clause = tokens[j:from_idx]
                    c_idx = 0
                    while c_idx < len(clause):
                        ct = clause[c_idx]
                        if ct.value == "*" and c_idx + 2 < len(clause) and clause[c_idx + 1].value == "as":
                            ns = clause[c_idx + 2]
                            if ns.kind == "IDENT":
                                imports_map[ns.value] = (resolved, "*")
                            c_idx += 3
                            continue
                        if ct.value == "{":
                            close_b = _match_delim(clause, c_idx, "{", "}")
                            inner = clause[c_idx + 1 : close_b] if close_b != -1 else clause[c_idx + 1 :]
                            m = 0
                            while m < len(inner):
                                if inner[m].value in {",", "type"}:
                                    m += 1
                                    continue
                                if inner[m].kind == "IDENT":
                                    orig = inner[m].value
                                    if (
                                        m + 2 < len(inner)
                                        and inner[m + 1].value == "as"
                                        and inner[m + 2].kind == "IDENT"
                                    ):
                                        imports_map[inner[m + 2].value] = (resolved, orig)
                                        m += 3
                                        continue
                                    imports_map[orig] = (resolved, orig)
                                m += 1
                            c_idx = (close_b + 1) if close_b != -1 else len(clause)
                            continue
                        if ct.kind == "IDENT" and ct.value != "type":
                            imports_map[ct.value] = (resolved, "default")
                        c_idx += 1
                i = from_idx + 2
                continue

        # CommonJS `require("child_process")` or `require("./helper")`
        if (
            tok.kind == "IDENT"
            and tok.value == "require"
            and i + 3 < n
            and tokens[i + 1].value == "("
            and tokens[i + 2].kind == "STRING"
        ):
            spec = tokens[i + 2].value
            if spec in {"child_process", "node:child_process"}:
                has_child_proc = True
        i += 1

    return (imports_map, has_child_proc)


def split_call_arguments(
    toks: tuple[TSToken, ...],
    open_paren_idx: int,
) -> tuple[list[tuple[TSToken, ...]], int]:
    """Given `toks[open_paren_idx].value == '('`, return `(arg_token_tuples, close_idx)`."""
    close_idx = _match_delim(toks, open_paren_idx, "(", ")")
    if close_idx == -1:
        return ([], len(toks) - 1)
    inner = toks[open_paren_idx + 1 : close_idx]
    if not inner:
        return ([], close_idx)

    args: list[tuple[TSToken, ...]] = []
    cur: list[TSToken] = []
    p_d = b_d = s_d = 0
    for t in inner:
        v = t.value
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
        elif v == "," and p_d == 0 and b_d == 0 and s_d == 0:
            if cur:
                args.append(tuple(cur))
                cur = []
            continue
        cur.append(t)
    if cur:
        args.append(tuple(cur))
    return (args, close_idx)


def iter_ts_calls(
    toks: tuple[TSToken, ...],
) -> list[tuple[str | None, str, int, list[tuple[TSToken, ...]]]]:
    """Return `(receiver_or_None, fn_name, line, arg_tuples)` for every call in `toks`."""
    out: list[tuple[str | None, str, int, list[tuple[TSToken, ...]]]] = []
    n = len(toks)
    for i, t in enumerate(toks):
        if t.kind != "IDENT":
            continue
        open_idx = i + 1
        if open_idx < n and toks[open_idx].value == "<":
            end_g = _match_delim(toks, open_idx, "<", ">")
            if end_g != -1:
                open_idx = end_g + 1
        if open_idx < n and toks[open_idx].value == "(":
            recv: str | None = None
            if i >= 2 and toks[i - 1].value in {".", "?."} and toks[i - 2].kind == "IDENT":
                recv = toks[i - 2].value
            args, _ = split_call_arguments(toks, open_idx)
            out.append((recv, t.value, t.line, args))
    return out


def resolve_ts_callee_id(
    recv: str | None,
    fn_name: str,
    caller: TSParsedFunctionUnit,
    index_by_mod_name: dict[tuple[str, str], str],
    default_by_mod: dict[str, str],
    by_unique_tail: dict[str, str | None],
) -> str | None:
    if recv is None:
        if fn_name in caller.imports_map:
            t_mod, sym = caller.imports_map[fn_name]
            if sym == "default":
                return default_by_mod.get(t_mod)
            return index_by_mod_name.get((t_mod, sym))
        same_mod = index_by_mod_name.get((caller.mod_path, fn_name))
        if same_mod is not None:
            return same_mod
    elif recv in caller.imports_map:
        t_mod, sym = caller.imports_map[recv]
        if sym == "*":
            cand = index_by_mod_name.get((t_mod, fn_name))
            if cand is not None:
                return cand

    uniq = by_unique_tail.get(fn_name)
    if uniq is not None and uniq != caller.qual_id:
        return uniq
    return None


def is_ts_client_ui_unit(unit: TSParsedFunctionUnit) -> bool:
    """Return True for browser `"use client"` modules and client React `.tsx`/`.jsx` UI components."""
    if unit.has_use_client:
        return True
    if (
        unit.rel_file.endswith((".tsx", ".jsx"))
        and not unit.has_use_server
        and "/api/" not in f"/{unit.mod_path}"
        and not unit.mod_path.startswith("api/")
        and unit.span.name[:1].isupper()
        and unit.span.name not in NEXT_HTTP_EXPORTS
    ):
        return True
    return False


def build_callee_returns_guard_map(
    unit: TSParsedFunctionUnit,
    summaries: dict[str, TSFunctionSummary],
    by_mod_and_name: dict[tuple[str, str], str],
    default_by_mod: dict[str, str],
    by_unique_tail: dict[str, str | None],
) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for recv, fn_name, _, _ in iter_ts_calls(unit.span.body_tokens):
        cid = resolve_ts_callee_id(
            recv, fn_name, unit, by_mod_and_name, default_by_mod, by_unique_tail
        )
        if cid and cid in summaries and summaries[cid].returns_guard:
            g_cls = "signature" if "signature" in summaries[cid].returns_guard else "authz"
            key = f"{recv}.{fn_name}" if recv else fn_name
            mapping[key] = g_cls
            mapping.setdefault(fn_name, g_cls)
    return mapping


def _is_falsy_return_expr(ret_toks: tuple[TSToken, ...]) -> bool:
    if len(ret_toks) == 1 and ret_toks[0].value in {"null", "undefined", "false"}:
        return True
    vals = [t.value for t in ret_toks[:8]]
    for idx in range(len(vals) - 2):
        if vals[idx] in {"ok", "valid"} and vals[idx + 1] == ":" and vals[idx + 2] == "false":
            return True
    return False


def is_ts_entrypoint(unit: TSParsedFunctionUnit) -> bool:
    sp = unit.span
    if sp.is_route_callback:
        return True
    if sp.is_exported and sp.name in NEXT_HTTP_EXPORTS:
        return True
    if sp.is_default_export and ("/api/" in f"/{unit.mod_path}" or unit.mod_path.startswith("api/")):
        return True
    if unit.has_use_server and sp.is_exported:
        return True
    return False


def tokens_read_ts_request_source(
    toks: tuple[TSToken, ...],
    req_names: set[str],
) -> bool:
    """Detect untrusted HTTP request reads in Next.js, Express, Fastify, and Hono."""
    n = len(toks)
    for i, t in enumerate(toks):
        if t.kind != "IDENT":
            continue
        # `req.json()`, `req.text()`, `req.formData()`, `req.query`, `req.body`, `req.params`
        if t.value in req_names and i + 2 < n and toks[i + 1].value in {".", "?."}:
            prop = toks[i + 2].value
            if prop in {"json", "text", "formData", "query", "body", "params", "nextUrl"}:
                return True
            # Hono `c.req.query(...)` / `c.req.param(...)`
            if prop == "req" and i + 4 < n and toks[i + 3].value == ".":
                if toks[i + 4].value in {"query", "param", "json", "text", "parseBody"}:
                    return True
        # `searchParams.get(...)` / `cookies().get(...)` / `headers().get(...)`
        if (
            t.value == "searchParams"
            and i + 3 < n
            and toks[i + 1].value in {".", "?."}
            and toks[i + 2].value in {"get", "getAll", "toString"}
            and toks[i + 3].value == "("
        ):
            return True
        if (
            t.value in {"cookies", "headers"}
            and i + 4 < n
            and toks[i + 1].value == "("
            and toks[i + 2].value == ")"
            and toks[i + 3].value in {".", "?."}
            and toks[i + 4].value == "get"
        ):
            return True
    return False


def _tokens_have_string_concat(toks: tuple[TSToken, ...]) -> bool:
    return any(t.kind == "OP" and t.value in {"+", "+="} for t in toks)


def _tokens_are_sanitized(toks: tuple[TSToken, ...]) -> bool:
    for recv, fn_name, _, _ in iter_ts_calls(toks):
        if fn_name in TS_SANITIZER_CALLS:
            return True
        if recv in {"Number", "z"} and fn_name in {"parseInt", "parseFloat", "number", "boolean", "enum"}:
            return True
    return False


def detect_ts_taint_sink_in_call(
    recv: str | None,
    fn_name: str,
    args: list[tuple[TSToken, ...]],
    eval_arg_fn,
    imports_child_process: bool,
) -> tuple[set[str], str, str] | None:
    """Return `(origins, sink_kind, sink_label)` if call is an injection/eval sink."""
    if not args:
        return None

    # 1. Explicit unsafe raw SQL (`$queryRawUnsafe`, `$executeRawUnsafe`, `sql.unsafe`)
    if fn_name in TS_UNSAFE_SQL_CALLS:
        origins, _ = eval_arg_fn(args[0])
        if origins:
            lbl = f"{recv}.{fn_name}" if recv else fn_name
            return (origins, "sql_exec", lbl)

    # 2. String-built SQL query (`db.query("SELECT ..." + x)` or template literal `${x}`)
    if fn_name in SQL_CALL_TAILS and recv not in {"searchParams", "router", "document"}:
        origins, is_built = eval_arg_fn(args[0])
        if origins and (is_built or _tokens_have_string_concat(args[0])):
            lbl = f"{recv}.{fn_name}" if recv else fn_name
            return (origins, "sql_exec", f"{lbl}(dynamic SQL)")

    # 3. Shell execution (`child_process.exec`, `execSync`, `spawn(..., { shell: true })`)
    if fn_name in TS_SHELL_CALLS:
        if (recv is None and imports_child_process) or recv in {"cp", "childProcess", "child_process"}:
            origins, _ = eval_arg_fn(args[0])
            if origins:
                lbl = f"{recv}.{fn_name}" if recv else fn_name
                return (origins, "shell_exec", lbl)

    if fn_name in TS_SPAWN_CALLS and len(args) >= 2:
        # Check `{ shell: true }` in options argument
        has_shell_true = False
        for opt_arg in args[1:]:
            vals = [t.value for t in opt_arg]
            for idx, v in enumerate(vals):
                if v == "shell" and idx + 2 < len(vals) and vals[idx + 1] == ":" and vals[idx + 2] == "true":
                    has_shell_true = True
                    break
        if has_shell_true:
            o0, _ = eval_arg_fn(args[0])
            o1, _ = eval_arg_fn(args[1])
            comb = o0 | o1
            if comb:
                lbl = f"{recv}.{fn_name}" if recv else fn_name
                return (comb, "shell_exec", f"{lbl}(shell=true)")

    # 4. Dynamic code evaluation (`eval`, `new Function`, `vm.runInNewContext`)
    if fn_name in TS_EVAL_CALLS:
        if (fn_name in {"eval", "Function"} and recv is None) or recv == "vm":
            target_arg = args[-1] if fn_name == "Function" else args[0]
            origins, _ = eval_arg_fn(target_arg)
            if origins:
                lbl = f"{recv}.{fn_name}" if recv else fn_name
                return (origins, "code_eval", lbl)

    return None


def _extract_allowlist_var(
    cond: tuple[TSToken, ...] | None,
) -> tuple[str, bool] | None:
    """Detect `ALLOWED.includes(x)` or `ALLOWED.has(x)` -> `(var_name, is_negated)`."""
    if not cond:
        return None
    negated = any(t.value == "!" for t in cond)
    for _, fn_name, _, args in iter_ts_calls(cond):
        if fn_name in {"includes", "has"} and len(args) == 1 and len(args[0]) == 1:
            arg_tok = args[0][0]
            if arg_tok.kind == "IDENT":
                return (arg_tok.value, negated)
    return None


def _reachable(start: int, target: int, adj: dict[int, list[int]]) -> bool:
    q: deque[int] = deque([start])
    seen: set[int] = {start}
    while q:
        u = q.popleft()
        if u == target:
            return True
        for nxt in adj.get(u, ()):
            if nxt not in seen:
                seen.add(nxt)
                q.append(nxt)
    return False


def _compute_single_ts_summary(
    unit: TSParsedFunctionUnit,
    summaries: dict[str, TSFunctionSummary],
    units: dict[str, TSParsedFunctionUnit],
    by_mod_and_name: dict[tuple[str, str], str],
    default_by_mod: dict[str, str],
    by_unique_tail: dict[str, str | None],
) -> TSFunctionSummary:
    span = unit.span
    must_guards: set[str] = set()
    unguarded_sinks: list[DelegatedSink] = []

    try:
        cfg = build_ts_function_cfg(span)
    except CFGBuildLimitError:
        cfg = None

    if cfg is not None:
        guard_vars: dict[str, str] = {}
        callee_ret_guards = build_callee_returns_guard_map(
            unit, summaries, by_mod_and_name, default_by_mod, by_unique_tail
        )
        is_client_ui = is_ts_client_ui_unit(unit)
        standalone_guards: dict[str, set[tuple[int, int]]] = {"authz": set(), "signature": set()}
        branch_guards: dict[str, set[tuple[int, int, str]]] = {"authz": set(), "signature": set()}
        block_sinks: dict[int, DelegatedSink] = {}

        for bid in sorted(cfg.blocks):
            block = cfg.blocks[bid]
            if block.is_synthetic:
                continue
            active_guard: str | None = None
            for stmt in block.statements:
                collect_guard_var_bindings(stmt, guard_vars, callee_ret_guards)
                s_cls = classify_ts_standalone_guard(stmt)
                if s_cls is None and stmt.tokens and stmt.tokens[0].value not in {"return", "throw"}:
                    for recv, fn_name, _, _ in iter_ts_calls(stmt.tokens):
                        cid = resolve_ts_callee_id(
                            recv, fn_name, unit, by_mod_and_name, default_by_mod, by_unique_tail
                        )
                        if cid and cid in summaries:
                            for g_c in ("signature", "authz"):
                                if g_c in summaries[cid].must_guards:
                                    s_cls = g_c
                                    break
                        if s_cls is not None:
                            break
                if s_cls is not None:
                    active_guard = s_cls

                if not is_client_ui and bid not in block_sinks and active_guard is None:
                    direct_priv = find_ts_privileged_sink(stmt)
                    if direct_priv is not None:
                        lbl, ln = direct_priv
                        block_sinks[bid] = DelegatedSink(
                            sink_label=lbl,
                            origin_file=unit.rel_file,
                            origin_line=ln,
                            callee_chain=(span.name,),
                        )
                    else:
                        for recv, fn_name, _, _ in iter_ts_calls(stmt.tokens):
                            cid = resolve_ts_callee_id(
                                recv, fn_name, unit, by_mod_and_name, default_by_mod, by_unique_tail
                            )
                            if cid and cid in summaries and summaries[cid].unguarded_sinks:
                                first_del = summaries[cid].unguarded_sinks[0]
                                if (
                                    len(first_del.callee_chain) < MAX_CALLEE_CHAIN
                                    and span.name not in first_del.callee_chain
                                ):
                                    block_sinks[bid] = DelegatedSink(
                                        sink_label=first_del.sink_label,
                                        origin_file=first_del.origin_file,
                                        origin_line=first_del.origin_line,
                                        callee_chain=(span.name, *first_del.callee_chain),
                                    )
                                    break

            if active_guard is not None:
                for edge in cfg.succ.get(bid, ()):
                    if edge.kind != "exception":
                        standalone_guards[active_guard].add((edge.src, edge.dst))

            b_guard = classify_ts_branch_guard(block.condition, guard_vars)
            if b_guard is not None:
                g_cls, protected_kind = b_guard
                for edge in cfg.succ.get(bid, ()):
                    if edge.kind == protected_kind:
                        branch_guards[g_cls].add((edge.src, edge.dst, edge.kind))

        full_adj = {
            bid: [e.dst for e in edges if e.dst != cfg.abort_exit_id]
            for bid, edges in cfg.succ.items()
        }
        normal_ok = _reachable(cfg.entry_id, cfg.normal_exit_id, full_adj)
        has_abort = bool(cfg.pred.get(cfg.abort_exit_id))

        for g_cls in ("signature", "authz"):
            pos_b = branch_guards[g_cls]
            pos_s = standalone_guards[g_cls]
            if not pos_b and not pos_s:
                continue
            ug_adj: dict[int, list[int]] = {bid: [] for bid in cfg.blocks}
            for edge in cfg.edges:
                if edge.dst == cfg.abort_exit_id:
                    continue
                if (edge.src, edge.dst, edge.kind) in pos_b:
                    continue
                if (edge.src, edge.dst) in pos_s and edge.kind != "exception":
                    continue
                ug_adj[edge.src].append(edge.dst)
            if normal_ok and has_abort and not _reachable(cfg.entry_id, cfg.normal_exit_id, ug_adj):
                must_guards.add(g_cls)

        all_pos_b = branch_guards["signature"] | branch_guards["authz"]
        all_pos_s = standalone_guards["signature"] | standalone_guards["authz"]
        ug_any: dict[int, list[int]] = {bid: [] for bid in cfg.blocks}
        for edge in cfg.edges:
            if edge.dst == cfg.abort_exit_id:
                continue
            if (edge.src, edge.dst, edge.kind) in all_pos_b:
                continue
            if (edge.src, edge.dst) in all_pos_s and edge.kind != "exception":
                continue
            ug_any[edge.src].append(edge.dst)

        for s_bid, d_sink in sorted(block_sinks.items()):
            if _reachable(cfg.entry_id, s_bid, ug_any):
                unguarded_sinks.append(d_sink)

        # --- Part B: Taint Summary (param_to_return, returns_untrusted_source, param_to_sinks) ---
        env_taint: dict[str, set[str]] = {}
        env_built: dict[str, bool] = {}
        req_names = {"req", "request", "c", "ctx"}
        for idx, pname in enumerate(span.param_names):
            if pname in {"req", "request", "c", "ctx"}:
                req_names.add(pname)
            env_taint[pname] = {f"p:{idx}"}
        for p_idx, d_ident in span.destructured_params:
            env_taint[d_ident] = {f"p:{p_idx}"}

        # Detect Dominating Allowlist Guards (`if (!ALLOWED.includes(col)) return/throw`)
        allowlisted_vars: set[str] = set()
        for bid, blk in cfg.blocks.items():
            al = _extract_allowlist_var(blk.condition)
            if al is not None:
                v_name, is_neg = al
                if is_neg:
                    # If branch_true leads straight to abort_exit or normal_exit (early return),
                    # then `v_name` is allowlist-validated on the false continuation!
                    true_targets = [e.dst for e in cfg.succ.get(bid, ()) if e.kind == "branch_true"]
                    if true_targets and all(
                        all(
                            out_e.dst in {cfg.abort_exit_id, cfg.normal_exit_id}
                            for out_e in cfg.succ.get(tt, ())
                        )
                        for tt in true_targets
                    ):
                        allowlisted_vars.add(v_name)

        param_to_ret: set[int] = set()
        returns_untrusted = False
        param_sinks: dict[tuple[int, str], ParamSinkFlow] = {}

        def eval_tokens(toks: tuple[TSToken, ...]) -> tuple[set[str], bool]:
            if not toks or _tokens_are_sanitized(toks):
                return (set(), False)
            origins: set[str] = set()
            is_built = _tokens_have_string_concat(toks)
            if tokens_read_ts_request_source(toks, req_names):
                origins.add("SRC")

            for recv, fn_name, _, args in iter_ts_calls(toks):
                if fn_name in TS_SANITIZER_CALLS:
                    continue
                cid = resolve_ts_callee_id(
                    recv, fn_name, unit, by_mod_and_name, default_by_mod, by_unique_tail
                )
                if cid and cid in summaries:
                    cal = summaries[cid]
                    if cal.returns_untrusted_source:
                        origins.add("SRC")
                    for pos_i, arg_toks in enumerate(args):
                        if pos_i in cal.param_to_return:
                            ao, ab = eval_tokens(arg_toks)
                            origins |= ao
                            is_built = is_built or ab

            # Variable references (excluding property access tails like `obj.prop` where `prop` is field)
            for idx_t, tok in enumerate(toks):
                if tok.kind == "IDENT" and tok.value not in allowlisted_vars:
                    if idx_t >= 1 and toks[idx_t - 1].value in {".", "?."}:
                        continue
                    if idx_t + 1 < len(toks) and toks[idx_t + 1].value == ":":
                        continue
                    if tok.value in env_taint:
                        origins |= env_taint[tok.value]
                        if env_built.get(tok.value):
                            is_built = True
            return (origins, is_built)

        for bid in sorted(cfg.blocks):
            blk = cfg.blocks[bid]
            if blk.is_synthetic:
                continue
            al_branch = _extract_allowlist_var(blk.condition)
            # Propagate statements
            for stmt in blk.statements:
                st = stmt.tokens
                if not st:
                    continue
                # Assignments (`const x = ...` or `x = ...`)
                eq_pos = -1
                d = 0
                for idx_s, tok in enumerate(st):
                    if tok.value in {"(", "{", "["}:
                        d += 1
                    elif tok.value in {")", "}", "]"} and d > 0:
                        d -= 1
                    elif tok.value == "=" and d == 0:
                        eq_pos = idx_s
                        break
                if eq_pos != -1:
                    lhs = st[:eq_pos]
                    rhs = st[eq_pos + 1 :]
                    ro, rb = eval_tokens(rhs)
                    for idx_l, lt in enumerate(lhs):
                        if lt.kind != "IDENT" or lt.value in {"const", "let", "var"}:
                            continue
                        if idx_l + 1 < len(lhs) and lhs[idx_l + 1].value == ":":
                            continue
                        if ro and lt.value not in allowlisted_vars:
                            env_taint[lt.value] = set(ro)
                            env_built[lt.value] = rb
                        else:
                            env_taint.pop(lt.value, None)
                            env_built.pop(lt.value, None)

                # Check calls in statement for direct or delegated taint sinks
                for recv, fn_name, call_ln, args in iter_ts_calls(st):
                    direct = detect_ts_taint_sink_in_call(
                        recv, fn_name, args, eval_tokens, unit.imports_child_process
                    )
                    if direct is not None:
                        s_orig, s_kind, s_lbl = direct
                        for tag in s_orig:
                            if tag.startswith("p:"):
                                p_idx = int(tag.split(":", 1)[1])
                                p_name = (
                                    span.param_names[p_idx]
                                    if p_idx < len(span.param_names)
                                    else f"param_{p_idx}"
                                )
                                if p_name not in allowlisted_vars:
                                    param_sinks.setdefault(
                                        (p_idx, s_kind),
                                        ParamSinkFlow(
                                            param_index=p_idx,
                                            param_name=p_name,
                                            sink_kind=s_kind,
                                            sink_label=s_lbl,
                                            origin_file=unit.rel_file,
                                            origin_line=call_ln,
                                            callee_chain=(span.name,),
                                        ),
                                    )
                    else:
                        cid = resolve_ts_callee_id(
                            recv, fn_name, unit, by_mod_and_name, default_by_mod, by_unique_tail
                        )
                        if cid and cid in summaries and summaries[cid].param_to_sinks:
                            cal_s = summaries[cid]
                            for p_flow in cal_s.param_to_sinks:
                                if (
                                    p_flow.param_index < len(args)
                                    and len(p_flow.callee_chain) < MAX_CALLEE_CHAIN
                                    and span.name not in p_flow.callee_chain
                                ):
                                    passed_o, _ = eval_tokens(args[p_flow.param_index])
                                    for tag in passed_o:
                                        if tag.startswith("p:"):
                                            cp_idx = int(tag.split(":", 1)[1])
                                            cp_name = (
                                                span.param_names[cp_idx]
                                                if cp_idx < len(span.param_names)
                                                else f"param_{cp_idx}"
                                            )
                                            if cp_name not in allowlisted_vars:
                                                param_sinks.setdefault(
                                                    (cp_idx, p_flow.sink_kind),
                                                    ParamSinkFlow(
                                                        param_index=cp_idx,
                                                        param_name=cp_name,
                                                        sink_kind=p_flow.sink_kind,
                                                        sink_label=p_flow.sink_label,
                                                        origin_file=p_flow.origin_file,
                                                        origin_line=p_flow.origin_line,
                                                        callee_chain=(span.name, *p_flow.callee_chain),
                                                    ),
                                                )

                if st[0].value == "return" and len(st) > 1 and not blk.has_deny_status:
                    ret_o, _ = eval_tokens(st[1:])
                    for tag in ret_o:
                        if tag == "SRC":
                            returns_untrusted = True
                        elif tag.startswith("p:"):
                            p_idx = int(tag.split(":", 1)[1])
                            p_name = (
                                span.param_names[p_idx]
                                if p_idx < len(span.param_names)
                                else ""
                            )
                            if p_name not in allowlisted_vars:
                                param_to_ret.add(p_idx)
            # Suppress unused local check when positive `if (ALLOWED.includes(x))` wraps block
            if al_branch is not None and not al_branch[1]:
                allowlisted_vars.add(al_branch[0])

        returns_guard: set[str] = set()
        body_calls = (
            [] if is_client_ui else [fn_n for _, fn_n, _, _ in iter_ts_calls(span.body_tokens)]
        )
        has_hmac_calc = any(fn_n in {"createHmac", "timingSafeEqual"} for fn_n in body_calls)
        has_falsy_ret = False
        has_truthy_ret = False

        for bid_r in (() if is_client_ui else sorted(cfg.blocks)):
            blk_r = cfg.blocks[bid_r]
            if blk_r.is_synthetic or blk_r.has_deny_status:
                continue
            for st_r in blk_r.statements:
                rt = st_r.tokens
                if not rt or rt[0].value != "return" or len(rt) <= 1:
                    continue
                ret_expr = rt[1:]
                if _is_falsy_return_expr(ret_expr):
                    has_falsy_ret = True
                    continue
                has_truthy_ret = True
                for recv_r, fn_r, _, _ in iter_ts_calls(ret_expr):
                    if fn_r in LOOKUP_SIGNATURE_CALLS:
                        returns_guard.add("signature")
                    elif fn_r in LOOKUP_AUTHZ_CALLS:
                        returns_guard.add("authz")
                    elif fn_r in callee_ret_guards:
                        returns_guard.add(callee_ret_guards[fn_r])
                    elif recv_r and f"{recv_r}.{fn_r}" in callee_ret_guards:
                        returns_guard.add(callee_ret_guards[f"{recv_r}.{fn_r}"])
                for tok_r in ret_expr:
                    if tok_r.kind == "IDENT" and tok_r.value in guard_vars:
                        returns_guard.add(guard_vars[tok_r.value])

        if (
            has_hmac_calc
            and has_falsy_ret
            and has_truthy_ret
            and span.name.startswith(("verify", "validate", "check"))
        ):
            returns_guard.add("signature")

        return TSFunctionSummary(
            qual_id=unit.qual_id,
            rel_file=unit.rel_file,
            func_name=span.name,
            lineno=span.lineno,
            param_names=span.param_names,
            must_guards=frozenset(must_guards),
            unguarded_sinks=tuple(unguarded_sinks),
            param_to_return=frozenset(param_to_ret),
            returns_untrusted_source=returns_untrusted,
            param_to_sinks=tuple(param_sinks.values()),
            returns_guard=frozenset(returns_guard),
        )

    return TSFunctionSummary(
        qual_id=unit.qual_id,
        rel_file=unit.rel_file,
        func_name=span.name,
        lineno=span.lineno,
        param_names=span.param_names,
        must_guards=frozenset(),
        unguarded_sinks=(),
        param_to_return=frozenset(),
        returns_untrusted_source=False,
        param_to_sinks=(),
    )


def build_ts_repository_summaries(
    parsed_files: list[tuple[str, list[TSToken], list[TSFunctionSpan]]],
) -> TSRepositoryCallIndex:
    """Index TS/JS modules, resolve imports/aliases, and run Tarjan SCC fixpoint summaries."""
    mod_entries: list[tuple[str, str, list[TSToken], list[TSFunctionSpan]]] = []
    known_mod_paths: set[str] = set()
    for rel_file, tokens, spans in parsed_files:
        mp = normalize_ts_mod_path(rel_file)
        known_mod_paths.add(mp)
        mod_entries.append((rel_file, mp, tokens, spans))

    units: dict[str, TSParsedFunctionUnit] = {}
    by_mod_and_name: dict[tuple[str, str], str] = {}
    default_by_mod: dict[str, str] = {}
    tail_counts: dict[str, list[str]] = {}

    for rel_file, mp, tokens, spans in mod_entries:
        if len(units) >= MAX_SUMMARY_FUNCTIONS:
            break
        has_use_server = any(
            t.kind == "STRING" and t.value.strip() == "use server" for t in tokens[:8]
        )
        has_use_client = any(
            t.kind == "STRING" and t.value.strip() == "use client" for t in tokens[:8]
        )
        imports_map, has_cp = parse_ts_imports(tokens, mp, known_mod_paths)
        for idx_s, sp in enumerate(spans):
            if len(units) >= MAX_SUMMARY_FUNCTIONS:
                break
            qid = f"{mp}:{sp.name}@{sp.lineno}" if (mp, sp.name) in by_mod_and_name else f"{mp}:{sp.name}"
            units[qid] = TSParsedFunctionUnit(
                qual_id=qid,
                mod_path=mp,
                rel_file=rel_file,
                span=sp,
                has_use_server=has_use_server,
                has_use_client=has_use_client,
                imports_child_process=has_cp,
                imports_map=imports_map,
            )
            by_mod_and_name.setdefault((mp, sp.name), qid)
            if sp.is_default_export or (idx_s == 0 and sp.name == "default_handler"):
                default_by_mod[mp] = qid
            tail_counts.setdefault(sp.name, []).append(qid)

    by_unique_tail: dict[str, str | None] = {
        name: qids[0] if len(qids) == 1 else None
        for name, qids in tail_counts.items()
        if name not in {"GET", "POST", "PUT", "PATCH", "DELETE", "default_handler"}
    }

    call_adj: dict[str, set[str]] = {qid: set() for qid in units}
    for qid, unit in units.items():
        for recv, fn_name, _, _ in iter_ts_calls(unit.span.body_tokens):
            cid = resolve_ts_callee_id(
                recv, fn_name, unit, by_mod_and_name, default_by_mod, by_unique_tail
            )
            if cid is not None and cid in units:
                call_adj[qid].add(cid)

    sccs = tarjan_scc(units.keys(), call_adj)
    summaries: dict[str, TSFunctionSummary] = {}

    for comp in sccs:
        max_iters = (
            1
            if len(comp) == 1 and comp[0] not in call_adj.get(comp[0], ())
            else min(6, len(comp) + 2)
        )
        for _ in range(max_iters):
            changed = False
            for qid in comp:
                new_sum = _compute_single_ts_summary(
                    units[qid],
                    summaries,
                    units,
                    by_mod_and_name,
                    default_by_mod,
                    by_unique_tail,
                )
                if summaries.get(qid) != new_sum:
                    summaries[qid] = new_sum
                    changed = True
            if not changed:
                break

    return TSRepositoryCallIndex(
        units=units,
        by_mod_and_name=by_mod_and_name,
        default_by_mod=default_by_mod,
        by_unique_tail=by_unique_tail,
        summaries=summaries,
    )
