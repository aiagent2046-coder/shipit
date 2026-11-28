"""Pure-Python TypeScript/JavaScript lexer and bounded CFG builder for WASM parity."""

from __future__ import annotations

from dataclasses import dataclass, field

from app.scan.detectors_app.graph_guards.cfg_builder import CFGBuildLimitError, CFGEdge

MAX_TS_TOKENS = 16_000
MAX_TS_CFG_BLOCKS = 512

_REGEX_PREV_PUNCT = frozenset({"(", ",", "=", ":", "!", "&", "|", "?", "{", ";", "["})
_REGEX_PREV_KW = frozenset({"return", "case", "throw", "typeof", "void", "delete"})
_DENY_STATUS_CODES = frozenset({"400", "401", "403", "404", "422", "429"})
_ABORT_CALL_NAMES = frozenset({
    "redirect",
    "permanentRedirect",
    "unauthorized",
    "forbidden",
    "notFound",
})
_ROUTE_METHODS = frozenset({"get", "post", "put", "patch", "delete", "all"})
_LINE_CONT_BEFORE = frozenset({
    ".", ",", "+", "-", "*", "/", "=", "&&", "||", "??",
    "?", ":", "=>", "async", "await", "return", "throw",
})
_LINE_CONT_AFTER = frozenset({".", "?.", "(", "[", "else", "catch", "finally"})


@dataclass(frozen=True)
class TSToken:
    kind: str  # "IDENT" | "NUMBER" | "STRING" | "PUNCT" | "OP"
    value: str
    line: int


@dataclass(frozen=True)
class TSStmt:
    tokens: tuple[TSToken, ...]
    start_line: int
    end_line: int


@dataclass
class TSBasicBlock:
    block_id: int
    statements: list[TSStmt] = field(default_factory=list)
    condition: tuple[TSToken, ...] | None = None
    start_line: int | None = None
    end_line: int | None = None
    in_loop: bool = False
    in_except: bool = False
    is_synthetic: bool = False
    has_deny_status: bool = False

    def record_stmt(self, stmt: TSStmt) -> None:
        self.statements.append(stmt)
        if self.start_line is None or stmt.start_line < self.start_line:
            self.start_line = stmt.start_line
        if self.end_line is None or stmt.end_line > self.end_line:
            self.end_line = stmt.end_line


@dataclass
class TSControlFlowGraph:
    func_name: str
    entry_id: int
    normal_exit_id: int
    abort_exit_id: int
    blocks: dict[int, TSBasicBlock]
    edges: tuple[CFGEdge, ...]
    succ: dict[int, tuple[CFGEdge, ...]]
    pred: dict[int, tuple[CFGEdge, ...]]


@dataclass(frozen=True)
class TSFunctionSpan:
    name: str
    lineno: int
    body_tokens: tuple[TSToken, ...]
    param_names: tuple[str, ...] = ()
    destructured_params: tuple[tuple[int, str], ...] = ()
    is_exported: bool = False
    is_default_export: bool = False
    is_route_callback: bool = False


def _parse_ts_params(
    param_tokens: list[TSToken] | tuple[TSToken, ...],
) -> tuple[tuple[str, ...], tuple[tuple[int, str], ...]]:
    """Extract positional parameter names and `{ a, b }` destructured bindings."""
    if not param_tokens:
        return ((), ())
    segments: list[list[TSToken]] = []
    cur: list[TSToken] = []
    p_d = b_d = s_d = a_d = 0
    for tok in param_tokens:
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
        elif v == "<":
            a_d += 1
        elif v == ">" and a_d > 0:
            a_d -= 1
        elif v == "," and p_d == 0 and b_d == 0 and s_d == 0 and a_d == 0:
            if cur:
                segments.append(cur)
                cur = []
            continue
        cur.append(tok)
    if cur:
        segments.append(cur)

    names: list[str] = []
    destructured: list[tuple[int, str]] = []
    for idx, seg in enumerate(segments):
        k = 0
        if k < len(seg) and seg[k].value == "...":
            k += 1
        if k < len(seg) and seg[k].kind == "IDENT":
            names.append(seg[k].value)
        elif k < len(seg) and seg[k].value == "{":
            names.append(f"__destructured_{idx}")
            close_b = _match_delim(seg, k, "{", "}")
            inner = seg[k + 1 : close_b] if close_b != -1 else seg[k + 1 :]
            # Extract bound identifiers before optional `: Type` annotation
            m = 0
            nested = 0
            while m < len(inner):
                tv = inner[m].value
                if tv in {"{", "[", "("}:
                    nested += 1
                elif tv in {"}", "]", ")"} and nested > 0:
                    nested -= 1
                elif inner[m].kind == "IDENT" and nested == 0:
                    # `{ raw: renamed }` binds `renamed`, whereas `{ id }` binds `id`
                    if m + 2 < len(inner) and inner[m + 1].value == ":" and inner[m + 2].kind == "IDENT":
                        destructured.append((idx, inner[m + 2].value))
                        m += 3
                        continue
                    destructured.append((idx, inner[m].value))
                m += 1
        else:
            names.append(f"__param_{idx}")
    return (tuple(names), tuple(destructured))


def _can_precede_regex(prev: TSToken | None) -> bool:
    if prev is None:
        return True
    if prev.kind in {"PUNCT", "OP"} and prev.value in _REGEX_PREV_PUNCT:
        return True
    if prev.kind == "IDENT" and prev.value in _REGEX_PREV_KW:
        return True
    return False


def tokenize_ts(source: str) -> list[TSToken]:
    """Tokenize TS/JS/TSX source without native dependencies, preserving line numbers."""
    tokens: list[TSToken] = []
    n = len(source)
    i = 0
    line = 1

    while i < n:
        if len(tokens) >= MAX_TS_TOKENS:
            raise CFGBuildLimitError("ts_token_limit")
        ch = source[i]
        if ch == "\n":
            line += 1
            i += 1
            continue
        if ch in " \t\r\f\v":
            i += 1
            continue

        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            i += 2
            while i < n and source[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            i += 2
            while i + 1 < n and not (source[i] == "*" and source[i + 1] == "/"):
                if source[i] == "\n":
                    line += 1
                i += 1
            i += 2
            continue

        if ch in {"'", '"'}:
            quote = ch
            start_line = line
            i += 1
            buf: list[str] = []
            while i < n and source[i] != quote:
                if source[i] == "\\":
                    if i + 1 < n and source[i + 1] == "\n":
                        line += 1
                    i += 2
                    continue
                if source[i] == "\n":
                    line += 1
                buf.append(source[i])
                i += 1
            i += 1
            tokens.append(TSToken("STRING", "".join(buf), start_line))
            continue

        if ch == "`":
            start_line = line
            i += 1
            seg: list[str] = []
            while i < n and source[i] != "`":
                if source[i] == "\\":
                    if i + 1 < n and source[i + 1] == "\n":
                        line += 1
                    i += 2
                    continue
                if source[i] == "$" and i + 1 < n and source[i + 1] == "{":
                    tokens.append(TSToken("STRING", "".join(seg), start_line))
                    seg = []
                    tokens.append(TSToken("OP", "+", line))
                    tokens.append(TSToken("PUNCT", "(", line))
                    i += 2
                    depth = 1
                    inner_start = i
                    while i < n and depth > 0:
                        c2 = source[i]
                        if c2 == "\n":
                            line += 1
                        elif c2 in {"'", '"', "`"}:
                            q2 = c2
                            i += 1
                            while i < n and source[i] != q2:
                                if source[i] == "\\":
                                    i += 2
                                    continue
                                if source[i] == "\n":
                                    line += 1
                                i += 1
                        elif c2 == "{":
                            depth += 1
                        elif c2 == "}":
                            depth -= 1
                            if depth == 0:
                                break
                        i += 1
                    tokens.extend(tokenize_ts(source[inner_start:i]))
                    tokens.append(TSToken("PUNCT", ")", line))
                    tokens.append(TSToken("OP", "+", line))
                    if i < n and source[i] == "}":
                        i += 1
                    start_line = line
                    continue
                if source[i] == "\n":
                    line += 1
                seg.append(source[i])
                i += 1
            if i < n and source[i] == "`":
                i += 1
            tokens.append(TSToken("STRING", "".join(seg), start_line))
            continue

        if ch == "/" and _can_precede_regex(tokens[-1] if tokens else None):
            j = i + 1
            in_class = False
            valid_regex = False
            while j < n and source[j] != "\n":
                rc = source[j]
                if rc == "\\":
                    j += 2
                    continue
                if rc == "[":
                    in_class = True
                elif rc == "]":
                    in_class = False
                elif rc == "/" and not in_class:
                    valid_regex = True
                    j += 1
                    while j < n and source[j].isalpha():
                        j += 1
                    break
                j += 1
            if valid_regex:
                tokens.append(TSToken("STRING", source[i:j], line))
                i = j
                continue

        if ch.isalpha() or ch in {"_", "$"}:
            j = i + 1
            while j < n and (source[j].isalnum() or source[j] in {"_", "$"}):
                j += 1
            tokens.append(TSToken("IDENT", source[i:j], line))
            i = j
            continue

        if ch.isdigit():
            j = i + 1
            while j < n and (source[j].isalnum() or source[j] in {".", "_"}):
                j += 1
            tokens.append(TSToken("NUMBER", source[i:j], line))
            i = j
            continue

        three = source[i : i + 3]
        two = source[i : i + 2]
        if three in {"===", "!==", "...", ">>>", "??=", "||=", "&&="}:
            tokens.append(TSToken("OP", three, line))
            i += 3
            continue
        if two in {"==", "!=", "<=", ">=", "=>", "&&", "||", "??", "?.", "++", "--", "+=", "-="}:
            tokens.append(TSToken("OP", two, line))
            i += 2
            continue
        if ch in "{}()[];,.:":
            tokens.append(TSToken("PUNCT", ch, line))
        else:
            tokens.append(TSToken("OP", ch, line))
        i += 1

    return tokens


def _match_delim(
    tokens: list[TSToken] | tuple[TSToken, ...],
    idx: int,
    open_ch: str,
    close_ch: str,
) -> int:
    depth = 0
    for k in range(idx, len(tokens)):
        val = tokens[k].value
        if val == open_ch:
            depth += 1
        elif val == close_ch:
            depth -= 1
            if depth == 0:
                return k
    return -1


def _find_function_body_open(tokens: list[TSToken], after_params: int) -> int:
    k = after_params
    n = len(tokens)
    if k < n and tokens[k].value == ":":
        k += 1
        angle = 0
        while k < n:
            v = tokens[k].value
            if v == "<":
                angle += 1
            elif v == ">" and angle > 0:
                angle -= 1
            elif v == "{" and angle == 0:
                close_b = _match_delim(tokens, k, "{", "}")
                if close_b != -1 and close_b + 1 < n and tokens[close_b + 1].value == "{":
                    return close_b + 1
                return k
            elif v == ";" and angle == 0:
                return -1
            k += 1
        return -1
    if k < n and tokens[k].value == "{":
        return k
    return -1


def extract_ts_functions(tokens: list[TSToken]) -> list[TSFunctionSpan]:
    """Extract top-level, exported, and Express/Fastify/Hono route callback functions."""
    spans: list[TSFunctionSpan] = []
    seen_ranges: set[tuple[int, int]] = set()
    n = len(tokens)
    i = 0

    while i < n:
        tok = tokens[i]

        if tok.kind == "IDENT" and tok.value == "function":
            prev_vals = {t.value for t in tokens[max(0, i - 3) : i]}
            is_exp = "export" in prev_vals
            is_def = "default" in prev_vals
            j = i + 1
            fn_name = "default_handler"
            if j < n and tokens[j].kind == "IDENT":
                fn_name = tokens[j].value
                j += 1
            if j < n and tokens[j].value == "<":
                end_gen = _match_delim(tokens, j, "<", ">")
                if end_gen != -1:
                    j = end_gen + 1
            if j < n and tokens[j].value == "(":
                close_p = _match_delim(tokens, j, "(", ")")
                if close_p != -1:
                    p_names, d_params = _parse_ts_params(tokens[j + 1 : close_p])
                    body_open = _find_function_body_open(tokens, close_p + 1)
                    if body_open != -1:
                        body_close = _match_delim(tokens, body_open, "{", "}")
                        if body_close != -1 and (body_open, body_close) not in seen_ranges:
                            seen_ranges.add((body_open, body_close))
                            spans.append(
                                TSFunctionSpan(
                                    name=fn_name,
                                    lineno=tok.line,
                                    body_tokens=tuple(tokens[body_open + 1 : body_close]),
                                    param_names=p_names,
                                    destructured_params=d_params,
                                    is_exported=is_exp,
                                    is_default_export=is_def,
                                )
                            )
                            i = body_close + 1
                            continue

        if tok.kind == "IDENT" and tok.value in {"const", "let", "var"} and i + 1 < n:
            is_exp = i >= 1 and tokens[i - 1].value == "export"
            if tokens[i + 1].kind == "IDENT":
                var_name = tokens[i + 1].value
                eq_idx = i + 2
                while eq_idx < n and tokens[eq_idx].value not in {"=", ";", "{"}:
                    eq_idx += 1
                if eq_idx < n and tokens[eq_idx].value == "=":
                    k = eq_idx + 1
                    if k < n and tokens[k].value == "async":
                        k += 1
                    if k < n and tokens[k].value == "<":
                        end_gen = _match_delim(tokens, k, "<", ">")
                        if end_gen != -1:
                            k = end_gen + 1
                    if k < n and tokens[k].value == "(":
                        close_p = _match_delim(tokens, k, "(", ")")
                        if close_p != -1:
                            p_names, d_params = _parse_ts_params(tokens[k + 1 : close_p])
                            arrow = close_p + 1
                            while arrow < n and tokens[arrow].value not in {"=>", ";"}:
                                arrow += 1
                            if (
                                arrow + 1 < n
                                and tokens[arrow].value == "=>"
                                and tokens[arrow + 1].value == "{"
                            ):
                                b_open = arrow + 1
                                b_close = _match_delim(tokens, b_open, "{", "}")
                                if b_close != -1 and (b_open, b_close) not in seen_ranges:
                                    seen_ranges.add((b_open, b_close))
                                    spans.append(
                                        TSFunctionSpan(
                                            name=var_name,
                                            lineno=tok.line,
                                            body_tokens=tuple(tokens[b_open + 1 : b_close]),
                                            param_names=p_names,
                                            destructured_params=d_params,
                                            is_exported=is_exp,
                                        )
                                    )
                                    i = b_close + 1
                                    continue

        if (
            tok.kind == "PUNCT"
            and tok.value == "."
            and i + 2 < n
            and tokens[i + 1].kind == "IDENT"
            and tokens[i + 1].value in _ROUTE_METHODS
            and tokens[i + 2].value == "("
        ):
            method = tokens[i + 1].value.upper()
            call_close = _match_delim(tokens, i + 2, "(", ")")
            if call_close != -1:
                route_path = ""
                if i + 3 < call_close and tokens[i + 3].kind == "STRING":
                    route_path = tokens[i + 3].value
                k = i + 3
                while k < call_close:
                    if tokens[k].value == "=>" and k + 1 < call_close and tokens[k + 1].value == "{":
                        # Locate preceding `(...)` parameter list for arrow callback
                        cb_params: tuple[str, ...] = ()
                        cb_destr: tuple[tuple[int, str], ...] = ()
                        p_end = k - 1
                        if p_end >= i + 3 and tokens[p_end].value == ")":
                            p_start = p_end
                            depth = 0
                            while p_start >= i + 3:
                                if tokens[p_start].value == ")":
                                    depth += 1
                                elif tokens[p_start].value == "(":
                                    depth -= 1
                                    if depth == 0:
                                        cb_params, cb_destr = _parse_ts_params(
                                            tokens[p_start + 1 : p_end]
                                        )
                                        break
                                p_start -= 1
                        elif p_end >= i + 3 and tokens[p_end].kind == "IDENT":
                            cb_params = (tokens[p_end].value,)

                        b_open = k + 1
                        b_close = _match_delim(tokens, b_open, "{", "}")
                        if b_close != -1 and b_close < call_close and (b_open, b_close) not in seen_ranges:
                            seen_ranges.add((b_open, b_close))
                            label = f"{method} {route_path}".strip() if route_path else f"{method}_handler"
                            spans.append(
                                TSFunctionSpan(
                                    name=label,
                                    lineno=tokens[k].line,
                                    body_tokens=tuple(tokens[b_open + 1 : b_close]),
                                    param_names=cb_params,
                                    destructured_params=cb_destr,
                                    is_route_callback=True,
                                )
                            )
                            k = b_close + 1
                            continue
                    k += 1
        i += 1

    return spans


def _tokens_denote_deny_response(toks: tuple[TSToken, ...]) -> bool:
    vals = [t.value for t in toks]
    for idx, t in enumerate(toks):
        if t.kind == "IDENT" and t.value in _ABORT_CALL_NAMES:
            if idx + 1 < len(toks) and toks[idx + 1].value == "(":
                return True
        if t.kind == "IDENT" and t.value in {"status", "code", "sendStatus"}:
            for nxt in toks[idx + 1 : idx + 5]:
                if nxt.kind == "NUMBER" and nxt.value in _DENY_STATUS_CODES:
                    return True
        if t.kind == "NUMBER" and t.value in _DENY_STATUS_CODES:
            if any(w in vals for w in ("NextResponse", "Response", "json", "status", "code", "text", "send")):
                return True
        if t.kind == "STRING":
            low = t.value.lower()
            if any(p in low for p in ("unauthorized", "forbidden", "unauthenticated", "invalid signature")):
                if any(w in vals for w in ("NextResponse", "Response", "res", "reply")):
                    return True
    return False


class _TSCFGBuilder:
    def __init__(self, func_name: str, func_lineno: int) -> None:
        self.func_name = func_name
        self.blocks: dict[int, TSBasicBlock] = {}
        self.edges: list[CFGEdge] = []
        self._seen: set[tuple[int, int, str]] = set()
        self._loop_stack: list[tuple[int, int]] = []
        self._except_stack: list[int] = []
        self.entry_id = self._new_block(start_line=func_lineno)
        self.normal_exit_id = self._new_block(synthetic=True)
        self.abort_exit_id = self._new_block(synthetic=True)

    def _new_block(self, *, start_line: int | None = None, synthetic: bool = False) -> int:
        if len(self.blocks) >= MAX_TS_CFG_BLOCKS:
            raise CFGBuildLimitError("ts_cfg_block_limit")
        bid = len(self.blocks)
        self.blocks[bid] = TSBasicBlock(
            block_id=bid,
            start_line=start_line,
            end_line=start_line,
            in_loop=bool(self._loop_stack),
            in_except=bool(self._except_stack),
            is_synthetic=synthetic,
        )
        return bid

    def _add_edge(self, src: int, dst: int, kind: str = "fallthrough") -> None:
        key = (src, dst, kind)
        if key not in self._seen:
            self._seen.add(key)
            self.edges.append(CFGEdge(src=src, dst=dst, kind=kind))

    def _read_simple_stmt(self, toks: tuple[TSToken, ...], start: int) -> tuple[TSStmt, int]:
        n = len(toks)
        k = start
        p_depth = b_depth = s_depth = 0
        while k < n:
            v = toks[k].value
            if v == "(":
                p_depth += 1
            elif v == ")" and p_depth > 0:
                p_depth -= 1
            elif v == "{":
                b_depth += 1
            elif v == "}" and b_depth > 0:
                b_depth -= 1
            elif v == "[":
                s_depth += 1
            elif v == "]" and s_depth > 0:
                s_depth -= 1
            elif v == ";" and p_depth == 0 and b_depth == 0 and s_depth == 0:
                sl = toks[start : k + 1]
                return (TSStmt(sl, sl[0].line, sl[-1].line), k + 1)
            elif (
                p_depth == 0
                and b_depth == 0
                and s_depth == 0
                and k + 1 < n
                and toks[k + 1].line > toks[k].line
                and v not in _LINE_CONT_BEFORE
                and toks[k + 1].value not in _LINE_CONT_AFTER
            ):
                sl = toks[start : k + 1]
                return (TSStmt(sl, sl[0].line, sl[-1].line), k + 1)
            k += 1
        sl = toks[start:n]
        return (TSStmt(sl, sl[0].line, sl[-1].line), n)

    def _read_unit_tokens(
        self,
        toks: tuple[TSToken, ...],
        start: int,
    ) -> tuple[tuple[TSToken, ...], int]:
        if start < len(toks) and toks[start].value == "{":
            close_b = _match_delim(toks, start, "{", "}")
            if close_b != -1:
                return (toks[start + 1 : close_b], close_b + 1)
        if start < len(toks) and toks[start].kind == "IDENT" and toks[start].value == "if":
            if start + 1 < len(toks) and toks[start + 1].value == "(":
                cp = _match_delim(toks, start + 1, "(", ")")
                if cp != -1:
                    _, after_then = self._read_unit_tokens(toks, cp + 1)
                    end_pos = after_then
                    if end_pos < len(toks) and toks[end_pos].value == "else":
                        _, end_pos = self._read_unit_tokens(toks, end_pos + 1)
                    return (toks[start:end_pos], end_pos)
        stmt, nxt = self._read_simple_stmt(toks, start)
        return (stmt.tokens, nxt)

    def build_seq(self, toks: tuple[TSToken, ...], current: int | None) -> int | None:
        i = 0
        n = len(toks)
        while i < n and current is not None:
            tok = toks[i]
            if tok.value == ";":
                i += 1
                continue

            if tok.value == "{":
                close_b = _match_delim(toks, i, "{", "}")
                if close_b == -1:
                    break
                current = self.build_seq(toks[i + 1 : close_b], current)
                i = close_b + 1
                continue

            if tok.kind == "IDENT" and tok.value == "if" and i + 1 < n and toks[i + 1].value == "(":
                cp = _match_delim(toks, i + 1, "(", ")")
                if cp != -1:
                    cond_toks = toks[i + 2 : cp]
                    if self.blocks[current].condition is not None:
                        cond_blk = self._new_block(start_line=tok.line)
                        self._add_edge(current, cond_blk, "fallthrough")
                        current = cond_blk
                    elif self.blocks[current].start_line is None:
                        self.blocks[current].start_line = tok.line
                    self.blocks[current].condition = cond_toks

                    then_toks, after_then = self._read_unit_tokens(toks, cp + 1)
                    then_ln = then_toks[0].line if then_toks else tok.line
                    then_entry = self._new_block(start_line=then_ln)
                    self._add_edge(current, then_entry, "branch_true")
                    then_out = self.build_seq(then_toks, then_entry)

                    end_idx = after_then
                    if end_idx < n and toks[end_idx].kind == "IDENT" and toks[end_idx].value == "else":
                        else_toks, end_idx = self._read_unit_tokens(toks, end_idx + 1)
                        else_ln = else_toks[0].line if else_toks else tok.line
                        else_entry = self._new_block(start_line=else_ln)
                        self._add_edge(current, else_entry, "branch_false")
                        else_out = self.build_seq(else_toks, else_entry)
                    else:
                        else_out = self._new_block(start_line=tok.line)
                        self._add_edge(current, else_out, "branch_false")

                    if then_out is None and else_out is None:
                        current = None
                    elif then_out is None:
                        current = else_out
                    elif else_out is None:
                        current = then_out
                    else:
                        join_ln = toks[end_idx].line if end_idx < n else tok.line
                        join_blk = self._new_block(start_line=join_ln)
                        self._add_edge(then_out, join_blk, "fallthrough")
                        self._add_edge(else_out, join_blk, "fallthrough")
                        current = join_blk
                    i = end_idx
                    continue

            if tok.kind == "IDENT" and tok.value == "try" and i + 1 < n and toks[i + 1].value == "{":
                try_close = _match_delim(toks, i + 1, "{", "}")
                if try_close != -1:
                    try_toks = toks[i + 2 : try_close]
                    pos = try_close + 1
                    catch_toks: tuple[TSToken, ...] | None = None
                    catch_line = tok.line
                    if pos < n and toks[pos].value == "catch":
                        catch_line = toks[pos].line
                        pos += 1
                        if pos < n and toks[pos].value == "(":
                            cp = _match_delim(toks, pos, "(", ")")
                            if cp != -1:
                                pos = cp + 1
                        if pos < n and toks[pos].value == "{":
                            cc = _match_delim(toks, pos, "{", "}")
                            if cc != -1:
                                catch_toks = toks[pos + 1 : cc]
                                pos = cc + 1
                    finally_toks: tuple[TSToken, ...] | None = None
                    if (
                        pos < n
                        and toks[pos].value == "finally"
                        and pos + 1 < n
                        and toks[pos + 1].value == "{"
                    ):
                        fc = _match_delim(toks, pos + 1, "{", "}")
                        if fc != -1:
                            finally_toks = toks[pos + 2 : fc]
                            pos = fc + 1

                    catch_entry: int | None = None
                    if catch_toks is not None:
                        self._except_stack.append(1)
                        catch_entry = self._new_block(start_line=catch_line)
                        self._except_stack.pop()

                    try_entry = self._new_block(start_line=tok.line)
                    self._add_edge(current, try_entry, "fallthrough")
                    if catch_entry is not None:
                        self._add_edge(try_entry, catch_entry, "exception")
                    try_out = self.build_seq(try_toks, try_entry)

                    catch_out: int | None = None
                    if catch_entry is not None and catch_toks is not None:
                        self._except_stack.append(1)
                        catch_out = self.build_seq(catch_toks, catch_entry)
                        self._except_stack.pop()

                    if try_out is None and catch_out is None:
                        current = None
                    else:
                        after_ln = toks[pos].line if pos < n else tok.line
                        after_try = self._new_block(start_line=after_ln)
                        if try_out is not None:
                            self._add_edge(try_out, after_try, "fallthrough")
                        if catch_out is not None:
                            self._add_edge(catch_out, after_try, "fallthrough")
                        current = after_try

                    if finally_toks is not None and current is not None:
                        current = self.build_seq(finally_toks, current)
                    i = pos
                    continue

            if (
                tok.kind == "IDENT"
                and tok.value in {"while", "for"}
                and i + 1 < n
                and toks[i + 1].value == "("
            ):
                cp = _match_delim(toks, i + 1, "(", ")")
                if cp != -1:
                    body_toks, after_loop = self._read_unit_tokens(toks, cp + 1)
                    head_blk = self._new_block(start_line=tok.line)
                    self._add_edge(current, head_blk, "fallthrough")
                    exit_ln = toks[after_loop].line if after_loop < n else tok.line
                    exit_blk = self._new_block(start_line=exit_ln)
                    self._add_edge(head_blk, exit_blk, "branch_false")

                    self._loop_stack.append((head_blk, exit_blk))
                    body_ln = body_toks[0].line if body_toks else tok.line
                    body_entry = self._new_block(start_line=body_ln)
                    self._add_edge(head_blk, body_entry, "branch_true")
                    body_out = self.build_seq(body_toks, body_entry)
                    self._loop_stack.pop()
                    if body_out is not None:
                        self._add_edge(body_out, head_blk, "loop_back")
                    current = exit_blk
                    i = after_loop
                    continue

            if tok.kind == "IDENT" and tok.value == "switch" and i + 1 < n and toks[i + 1].value == "(":
                cp = _match_delim(toks, i + 1, "(", ")")
                if cp != -1 and cp + 1 < n and toks[cp + 1].value == "{":
                    sc = _match_delim(toks, cp + 1, "{", "}")
                    if sc != -1:
                        sw_toks = toks[cp + 2 : sc]
                        after_sw = self._new_block(start_line=toks[sc].line)
                        self._loop_stack.append((current, after_sw))
                        case_starts: list[tuple[int, bool, int]] = []
                        k = 0
                        d = 0
                        while k < len(sw_toks):
                            sv = sw_toks[k].value
                            if sv == "{":
                                d += 1
                            elif sv == "}":
                                d -= 1
                            elif d == 0 and sv in {"case", "default"}:
                                col = k + 1
                                while col < len(sw_toks) and sw_toks[col].value != ":":
                                    col += 1
                                if col < len(sw_toks):
                                    case_starts.append((col + 1, sv == "default", sw_toks[k].line))
                            k += 1
                        has_default = any(is_def for _, is_def, _ in case_starts)
                        prev_fall: int | None = None
                        for idx_c, (c_body_start, _, c_line) in enumerate(case_starts):
                            c_end = len(sw_toks)
                            if idx_c + 1 < len(case_starts):
                                nxt_col = case_starts[idx_c + 1][0] - 1
                                while (
                                    nxt_col > c_body_start
                                    and sw_toks[nxt_col].value not in {"case", "default"}
                                ):
                                    nxt_col -= 1
                                c_end = nxt_col
                            c_blk = self._new_block(start_line=c_line)
                            self._add_edge(current, c_blk, "branch_true")
                            if prev_fall is not None:
                                self._add_edge(prev_fall, c_blk, "fallthrough")
                            prev_fall = self.build_seq(sw_toks[c_body_start:c_end], c_blk)
                        if prev_fall is not None:
                            self._add_edge(prev_fall, after_sw, "fallthrough")
                        if not has_default:
                            self._add_edge(current, after_sw, "branch_false")
                        self._loop_stack.pop()
                        current = after_sw
                        i = sc + 1
                        continue

            if tok.kind == "IDENT" and tok.value in {"function", "class"}:
                _, nxt_i = self._read_simple_stmt(toks, i)
                i = nxt_i
                continue

            stmt, nxt_i = self._read_simple_stmt(toks, i)
            i = nxt_i
            if not stmt.tokens:
                continue

            first_val = stmt.tokens[0].value
            self.blocks[current].record_stmt(stmt)
            if _tokens_denote_deny_response(stmt.tokens):
                self.blocks[current].has_deny_status = True

            if first_val == "throw":
                self._add_edge(current, self.abort_exit_id, "exception")
                current = None
            elif first_val == "return":
                if self.blocks[current].has_deny_status or _tokens_denote_deny_response(stmt.tokens):
                    self._add_edge(current, self.abort_exit_id, "fallthrough")
                else:
                    self._add_edge(current, self.normal_exit_id, "fallthrough")
                current = None
            elif first_val == "break" and self._loop_stack:
                self._add_edge(current, self._loop_stack[-1][1], "fallthrough")
                current = None
            elif first_val == "continue" and self._loop_stack:
                self._add_edge(current, self._loop_stack[-1][0], "loop_back")
                current = None

        return current


def build_ts_function_cfg(span: TSFunctionSpan) -> TSControlFlowGraph:
    builder = _TSCFGBuilder(span.name, span.lineno)
    out = builder.build_seq(span.body_tokens, builder.entry_id)
    if out is not None:
        builder._add_edge(out, builder.normal_exit_id, "fallthrough")

    succ: dict[int, list[CFGEdge]] = {bid: [] for bid in builder.blocks}
    pred: dict[int, list[CFGEdge]] = {bid: [] for bid in builder.blocks}
    for edge in builder.edges:
        succ[edge.src].append(edge)
        pred[edge.dst].append(edge)

    return TSControlFlowGraph(
        func_name=span.name,
        entry_id=builder.entry_id,
        normal_exit_id=builder.normal_exit_id,
        abort_exit_id=builder.abort_exit_id,
        blocks=builder.blocks,
        edges=tuple(builder.edges),
        succ={k: tuple(v) for k, v in succ.items()},
        pred={k: tuple(v) for k, v in pred.items()},
    )
