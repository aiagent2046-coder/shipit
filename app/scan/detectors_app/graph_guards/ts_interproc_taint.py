"""Inter-procedural summary-based taint flow detector for TypeScript/Next.js/Express.

Detects untrusted HTTP request or Server Action input flowing across at least one
helper or service call boundary (`hop_count >= 1`) into a dynamic SQL query,
`child_process` shell command, or code-evaluation sink without scalar coercion
or allowlist checks. Zero native dependencies for 100% Pyodide WASM parity.
"""

from __future__ import annotations

from typing import BinaryIO

from app.scan.core.checks import CheckFinding
from app.scan.detectors_app.graph_guards.cfg_builder import CFGBuildLimitError
from app.scan.detectors_app.graph_guards.ts_bypass_detector import _collect_parsed_ts_files
from app.scan.detectors_app.graph_guards.ts_call_summaries import (
    TS_SANITIZER_CALLS,
    TSParsedFunctionUnit,
    TSRepositoryCallIndex,
    _extract_allowlist_var,
    _tokens_are_sanitized,
    _tokens_have_string_concat,
    build_ts_repository_summaries,
    detect_ts_taint_sink_in_call,
    is_ts_entrypoint,
    iter_ts_calls,
    resolve_ts_callee_id,
    tokens_read_ts_request_source,
)
from app.scan.detectors_app.graph_guards.ts_cfg_builder import TSToken, build_ts_function_cfg

TS_TAINT_RULE_ID = "ts-interprocedural-taint-flow"
MAX_FINDINGS = 50

_SINK_HUMAN_NOUN = {
    "sql_exec": "dynamic SQL execution",
    "shell_exec": "shell command execution",
    "code_eval": "dynamic code evaluation",
}

_SINK_FIX_ADVICE = {
    "sql_exec": (
        "Use parameterized queries (such as tagged `prisma.$queryRaw`...`` or `$1` placeholders) "
        "and validate dynamic SQL identifiers (such as `ORDER BY` columns) against a strict allowlist."
    ),
    "shell_exec": (
        "Replace `exec` / `execSync` or `shell: true` with `execFile` / `spawn(cmd, args, { shell: false })` "
        "and validate untrusted arguments against a strict allowlist."
    ),
    "code_eval": (
        "Avoid `eval`, `new Function`, and `vm.runInNewContext` on request-derived input; "
        "use `JSON.parse` or a declarative dispatch map instead."
    ),
}

_SAFE_HANDLER_PARAMS = frozenset({"res", "reply", "next"})


def _analyze_ts_entrypoint_taint(
    unit: TSParsedFunctionUnit,
    call_index: TSRepositoryCallIndex,
) -> list[CheckFinding]:
    try:
        cfg = build_ts_function_cfg(unit.span)
    except CFGBuildLimitError:
        return []

    is_entry = is_ts_entrypoint(unit)
    req_names = {"req", "request", "c", "ctx"}
    # var_name -> (source_label, helper_chain_tuple, is_string_built)
    taint_env: dict[str, tuple[str, tuple[str, ...], bool]] = {}

    for idx, pname in enumerate(unit.span.param_names):
        if pname in {"req", "request", "c", "ctx"}:
            req_names.add(pname)
        elif is_entry and pname not in _SAFE_HANDLER_PARAMS and not pname.startswith("__"):
            if unit.has_use_server or pname in {"params", "searchParams"}:
                taint_env[pname] = (f"handler parameter `{pname}`", (), False)

    if is_entry:
        for _, d_ident in unit.span.destructured_params:
            if d_ident not in _SAFE_HANDLER_PARAMS:
                taint_env[d_ident] = (f"handler parameter `{d_ident}`", (), False)

    # Identify dominating allowlist checks (`if (!ALLOWED.includes(x)) return/throw`)
    allowlisted: set[str] = set()
    for bid, blk in cfg.blocks.items():
        al = _extract_allowlist_var(blk.condition)
        if al is not None and al[1]:
            true_targets = [e.dst for e in cfg.succ.get(bid, ()) if e.kind == "branch_true"]
            if true_targets and all(
                all(
                    oe.dst in {cfg.abort_exit_id, cfg.normal_exit_id}
                    for oe in cfg.succ.get(tt, ())
                )
                for tt in true_targets
            ):
                allowlisted.add(al[0])

    findings: list[CheckFinding] = []
    seen_sites: set[tuple[str, int, str]] = set()

    def eval_taint(toks: tuple[TSToken, ...]) -> tuple[str, tuple[str, ...], bool] | None:
        if not toks or _tokens_are_sanitized(toks):
            return None
        built = _tokens_have_string_concat(toks)

        for recv, fn_name, _, args in iter_ts_calls(toks):
            if fn_name in TS_SANITIZER_CALLS:
                return None
            cid = resolve_ts_callee_id(
                recv,
                fn_name,
                unit,
                call_index.by_mod_and_name,
                call_index.default_by_mod,
                call_index.by_unique_tail,
            )
            if cid and cid in call_index.summaries:
                cal = call_index.summaries[cid]
                if cal.returns_untrusted_source:
                    return ("HTTP request input", (cal.func_name,), built)
                for pos_i, arg_toks in enumerate(args):
                    if pos_i in cal.param_to_return:
                        sub_ev = eval_taint(arg_toks)
                        if sub_ev is not None:
                            src_lbl, chain, sub_b = sub_ev
                            nxt_chain = (
                                (*chain, cal.func_name)
                                if cal.func_name not in chain
                                else chain
                            )
                            return (src_lbl, nxt_chain, built or sub_b)

        if tokens_read_ts_request_source(toks, req_names):
            return ("HTTP request input", (), built)

        for idx_t, tok in enumerate(toks):
            if tok.kind == "IDENT" and tok.value not in allowlisted:
                if idx_t >= 1 and toks[idx_t - 1].value in {".", "?."}:
                    continue
                if idx_t + 1 < len(toks) and toks[idx_t + 1].value == ":":
                    continue
                if tok.value in taint_env:
                    s_lbl, ch, v_b = taint_env[tok.value]
                    return (s_lbl, ch, built or v_b)
        return None

    for bid in sorted(cfg.blocks):
        blk = cfg.blocks[bid]
        if blk.is_synthetic:
            continue
        for stmt in blk.statements:
            if len(findings) >= MAX_FINDINGS:
                return findings
            st = stmt.tokens
            if not st:
                continue

            # Track assignments & destructured bindings (`const { sort } = await req.json()`)
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
                ev = eval_taint(rhs)
                for idx_l, lt in enumerate(lhs):
                    if lt.kind != "IDENT" or lt.value in {"const", "let", "var"}:
                        continue
                    if idx_l + 1 < len(lhs) and lhs[idx_l + 1].value == ":":
                        continue
                    if ev is not None and lt.value not in allowlisted:
                        taint_env[lt.value] = ev
                    else:
                        taint_env.pop(lt.value, None)

            for recv, fn_name, call_ln, args in iter_ts_calls(st):
                def _adapter(a_toks: tuple[TSToken, ...]) -> tuple[set[str], bool]:
                    res = eval_taint(a_toks)
                    if res is None:
                        return (set(), False)
                    return ({"HIT"}, res[2])

                direct = detect_ts_taint_sink_in_call(
                    recv, fn_name, args, _adapter, unit.imports_child_process
                )
                if direct is not None and args:
                    _, s_kind, s_label = direct
                    target_arg = args[-1] if fn_name == "Function" else args[0]
                    ev0 = eval_taint(target_arg)
                    if ev0 is None and len(args) > 1:
                        ev0 = eval_taint(args[1])
                    if ev0 is not None and len(ev0[1]) >= 1:
                        src_lbl, helper_chain, _ = ev0
                        site_key = (unit.rel_file, call_ln, s_kind)
                        if site_key not in seen_sites:
                            seen_sites.add(site_key)
                            full_chain = [unit.span.name, *helper_chain]
                            findings.append(
                                _build_ts_taint_finding(
                                    rel_file=unit.rel_file,
                                    line=call_ln,
                                    entry_func=unit.span.name,
                                    source_label=src_lbl,
                                    sink_kind=s_kind,
                                    sink_label=s_label,
                                    sink_file=unit.rel_file,
                                    sink_line=call_ln,
                                    call_chain=full_chain,
                                )
                            )
                    continue

                cid = resolve_ts_callee_id(
                    recv,
                    fn_name,
                    unit,
                    call_index.by_mod_and_name,
                    call_index.default_by_mod,
                    call_index.by_unique_tail,
                )
                if cid and cid in call_index.summaries and call_index.summaries[cid].param_to_sinks:
                    cal = call_index.summaries[cid]
                    for p_flow in cal.param_to_sinks:
                        if p_flow.param_index < len(args):
                            ev_arg = eval_taint(args[p_flow.param_index])
                            if ev_arg is not None:
                                src_lbl, pre_chain, _ = ev_arg
                                site_key = (p_flow.origin_file, p_flow.origin_line, p_flow.sink_kind)
                                if site_key not in seen_sites:
                                    seen_sites.add(site_key)
                                    raw_chain = [unit.span.name, *pre_chain, *p_flow.callee_chain]
                                    dedup_chain: list[str] = []
                                    for fn_n in raw_chain:
                                        if not dedup_chain or dedup_chain[-1] != fn_n:
                                            dedup_chain.append(fn_n)
                                    findings.append(
                                        _build_ts_taint_finding(
                                            rel_file=p_flow.origin_file,
                                            line=p_flow.origin_line,
                                            entry_func=unit.span.name,
                                            source_label=src_lbl,
                                            sink_kind=p_flow.sink_kind,
                                            sink_label=p_flow.sink_label,
                                            sink_file=p_flow.origin_file,
                                            sink_line=p_flow.origin_line,
                                            call_chain=dedup_chain,
                                            entry_file=unit.rel_file,
                                            entry_line=call_ln,
                                        )
                                    )

        al_pos = _extract_allowlist_var(blk.condition)
        if al_pos is not None and not al_pos[1]:
            allowlisted.add(al_pos[0])

    return findings


def _build_ts_taint_finding(
    *,
    rel_file: str,
    line: int,
    entry_func: str,
    source_label: str,
    sink_kind: str,
    sink_label: str,
    sink_file: str,
    sink_line: int,
    call_chain: list[str],
    entry_file: str | None = None,
    entry_line: int | None = None,
) -> CheckFinding:
    sink_noun = _SINK_HUMAN_NOUN[sink_kind]
    chain_str = " -> ".join(call_chain)
    cross_note = (
        f" initiated at `{entry_file}:{entry_line}`"
        if entry_file and entry_file != sink_file and entry_line
        else ""
    )
    explanation = (
        f"Untrusted {source_label} enters `{entry_func}`{cross_note} and flows unvalidated "
        f"across call chain `{chain_str}` into {sink_noun} (`{sink_label}`) at "
        f"`{sink_file}:{sink_line}`. External framework middleware and runtime reachability "
        f"outside the analyzed modules were not verified."
    )
    return CheckFinding(
        rule_id=TS_TAINT_RULE_ID,
        title=f"Inter-procedural TypeScript input reaches {sink_noun} via `{chain_str}`",
        severity="high",
        confidence=0.86,
        category="Security",
        file=rel_file,
        line=line,
        explanation=explanation,
        fix_hint=_SINK_FIX_ADVICE[sink_kind],
        claim_evidence={
            "source_type": "static_interproc_taint_summary",
            "language": "typescript",
            "sink_kind": sink_kind,
            "sink_label": sink_label,
            "entry_function": entry_func,
            "call_chain": call_chain,
            "hop_count": max(1, len(call_chain) - 1),
        },
    )


def scan_ts_interproc_taint(fileobj: BinaryIO) -> list[CheckFinding]:
    """Scan TypeScript/JavaScript modules for inter-procedural taint flows."""
    parsed = _collect_parsed_ts_files(fileobj)
    if not parsed:
        return []
    call_index = build_ts_repository_summaries(parsed)

    findings: list[CheckFinding] = []
    seen_keys: set[tuple[str, int, str]] = set()
    for qid in sorted(call_index.units):
        unit = call_index.units[qid]
        for hit in _analyze_ts_entrypoint_taint(unit, call_index):
            dedup_k = (hit.file, hit.line, hit.title)
            if dedup_k in seen_keys:
                continue
            seen_keys.add(dedup_k)
            findings.append(hit)
            if len(findings) >= MAX_FINDINGS:
                return findings
    return findings
