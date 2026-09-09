"""Bounded source identities for grouping hypotheses, never proof of their risk.

Titles only select a supported mechanism. The submitted archive supplies the
operation identity; model-provided keys, excerpts and target spellings are not
trusted. Ambiguous operations and exhausted budgets return None. No source
literal (including URLs, tokens or SQL policy text) is returned in the identity.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import PurePosixPath
import re
import stat
import zipfile

from tree_sitter import Language, Parser
import tree_sitter_typescript

from app.scan import guard_context as g

MAX_FILE_BYTES = 256_000
MAX_TOTAL_BYTES = 2_000_000
MAX_FILES = 64
MAX_NODES = 24_000
MAX_CHECKS = 256
MAX_DEPTH = 128
MAX_WORK_NODES = 400_000


def _mechanism(title):
    title = str(title)[:2000]
    patterns = {
        "derived_password": r"password.*(?:deriv|HMAC|service[ _-]?role)|HMAC.*password",
        "service_role_access": r"service[ _-]?role.*(?:client|database|reads?|writes?|RLS|operations)|"
                               r"(?:read/written|reads?|writes?|RLS).*service[ _-]?role",
        "forwarded_host_ssrf": r"SSRF.*(?:forwarded.host|header)|forwarded.host.*SSRF",
        "token_comparison": r"(?:timing.unsafe|constant.time|timing.attack).*(?:token|comparison)|"
                            r"(?:token|comparison).*(?:timing.unsafe|constant.time|timing.attack)",
        "prediction_url": r"prediction ID.*(?:URL|path)",
        "query_row_bound": r"query.*(?:no LIMIT|without (?:a )?LIMIT|unbounded)|"
                           r"(?:unbounded|unlimited).*query",
        "auto_reply_race": r"(?:auto.reply|first.message|mutual.match).*(?:race|not atomic|non.atomic|deduplication)|"
                           r"(?:race|not atomic|non.atomic).*auto.reply",
        "model_metadata_request": r"model version.*(?:fetch|lookup)|version lookup.*(?:call|request)",
        "prediction_polling": r"(?:polling|poll) loop.*(?:iterations|retries|sleep)",
    }
    selected = [name for name, pattern in patterns.items() if re.search(pattern, title, re.I)]
    # A recognized cause cannot swallow a separate concern simply because the
    # latter has no source resolver here. HTTP and transport rejection differ.
    blockers = [r"rate[ -]limit", r"(?:token|secret).*(?:URL|query string)",
                r"(?:network|transport).*(?:error|failure|reject)",
                r"HTTP.*(?:status|error)", r"(?:no|missing|without) authentication"]
    if len(selected) != 1 or any(re.search(pattern, title, re.I) for pattern in blockers):
        return None
    # A client choice and an authorization gap on one of its queries are
    # different claims, even when the same createClient call underlies both.
    if (";" in title or (selected[0] == "service_role_access" and re.search(
            r"(?:without|missing|no) (?:an? )?(?:ownership|owner(?:ship)?[ -]scop|user[ _-]?id)",
            title, re.I))):
        return None
    return selected[0]


def _span(node):
    return [node.start_byte, node.end_byte]


def _lines(node):
    return node.start_point[0] + 1, node.end_point[0] + 1


def _enclosing(node, types):
    while node is not None and node.type not in types:
        node = node.parent
    return node


def _call_name(node):
    if node.type != "call_expression":
        return ""
    fn = node.child_by_field_name("function")
    return g._name(fn) or (g._text(fn.child_by_field_name("property"))
                           if fn and fn.type == "member_expression" else "")


def _args(node):
    return g._children(node.child_by_field_name("arguments"))


def _chain(node):
    """The full fluent call, stopping before unrelated parent expressions."""
    while (node.parent and node.parent.type == "member_expression"
           and node.parent.child_by_field_name("object") == node
           and node.parent.parent and node.parent.parent.type == "call_expression"):
        node = node.parent.parent
    return node


def _header_call(node):
    return (_call_name(node) == "get" and len(_args(node)) == 1
            and g._literal(_args(node)[0]) == "x-forwarded-host")


def _fetch(node):
    return _call_name(node) in {"fetch", "fetchWithTimeout"}


def _url_text(node):
    args = _args(node)
    return g._text(args[0]) if args and args[0].type in {"string", "template_string"} else ""


def _query(node):
    return (_call_name(node) == "from" and len(_args(node)) == 1
            and g._literal(_args(node)[0]) is not None
            and any(_call_name(child) == "select" for child in g._walk(_chain(node))))


def _owning_scope(root, nodes, start):
    functions = [n for n in nodes if n.type in g._FUNCTIONS and _lines(n)[0] <= start <= _lines(n)[1]]
    return min(functions, key=lambda n: n.end_byte - n.start_byte) if functions else root


def _select(candidates, start, end):
    # First locate an actual operation touched by the citation. Only if the
    # cited scope contains one candidate can a nearby introduction/comment
    # stand for it; a broad range across two operations remains ambiguous.
    intersecting = [n for n in candidates if _lines(n)[0] <= end and start <= _lines(n)[1]]
    if len(intersecting) == 1:
        return intersecting[0]
    if not intersecting and len(candidates) == 1:
        return candidates[0]
    return None


class SourceIssueResolver:
    """One audit's cached parsing budget. Does not execute/import target code."""

    def __init__(self, archive, source_facts=None):
        self.archive = archive
        self.source_facts = source_facts
        self.remaining = MAX_TOTAL_BYTES
        self.checks = 0
        self.remaining_nodes = MAX_WORK_NODES
        self._cache = {}

    def _document(self, path):
        if path in self._cache:
            return self._cache[path]
        if len(self._cache) >= MAX_FILES:
            return None
        self._cache[path] = None
        with zipfile.ZipFile(self.archive) as archive:
            matches = [info for info in archive.infolist() if info.filename == path]
            if (len(matches) != 1 or matches[0].is_dir()
                    or stat.S_ISLNK(matches[0].external_attr >> 16)):
                return None
            info = matches[0]
            if info.file_size > min(MAX_FILE_BYTES, self.remaining):
                return None
            self.remaining -= info.file_size
            data = archive.read(info)
        data.decode("utf-8", errors="strict")
        language = (tree_sitter_typescript.language_tsx() if path.endswith((".tsx", ".jsx"))
                    else tree_sitter_typescript.language_typescript())
        root = Parser(Language(language)).parse(data).root_node
        if root.has_error:
            return None
        nodes = []
        pending = [(root, 0)]
        while pending:
            node, depth = pending.pop()
            nodes.append(node)
            if len(nodes) > MAX_NODES or depth > MAX_DEPTH:
                return None
            pending.extend((child, depth + 1) for child in node.named_children)
        self._cache[path] = (root, nodes, sha256(data).hexdigest())
        return self._cache[path]

    def identity(self, finding):
        if self.checks >= MAX_CHECKS:
            return None
        from app.scan.react_network_identity import network_cleanup_identity
        network = network_cleanup_identity(finding, self.source_facts)
        if network is not None:
            self.checks += 1
            # Facts belong to this audit's archive. A stale/reused inventory
            # cannot supply an identity for different source bytes.
            try:
                document = self._document(network["file"])
                return network if document and document[2] == network["source_sha256"] else None
            except (UnicodeError, ValueError, TypeError, RecursionError, RuntimeError,
                    OSError, zipfile.BadZipFile):
                return None
        kind = _mechanism(finding.get("title", ""))
        path = finding.get("file")
        start = finding.get("line_start", finding.get("line"))
        end = finding.get("line_end", start)
        if (not kind or not isinstance(path, str) or len(path) > 512
                or PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts
                or not path.endswith((".js", ".jsx", ".ts", ".tsx"))
                or type(start) is not int or type(end) is not int or not 1 <= start <= end
                or self.checks >= MAX_CHECKS):
            return None
        self.checks += 1
        try:
            document = self._document(path)
            if document is None:
                return None
            root, nodes, digest = document
            if end > _lines(root)[1]:
                return None
            scope = _owning_scope(root, nodes, start)
            if scope == root or end > _lines(scope)[1]:
                return None
            # A citation may span a whole enclosing function, but cannot select
            # a sibling function's operation. Nested callbacks stay separate,
            # except a polling-loop title may cite its enclosing retry call.
            own = list(g._walk(scope, skip=g._FUNCTIONS))
            # Charge the full function, including nested callbacks used by
            # polling/count identities, for every selector invocation.
            work = sum(1 for _ in g._walk(scope))
            if work > self.remaining_nodes:
                return None
            self.remaining_nodes -= work
            candidates = self._candidates(kind, scope, own)
            if kind == "query_row_bound":
                # A title can select an actual table, just as coordinates can
                # select a statement. It cannot invent the source identity.
                title = str(finding.get("title", ""))[:2000]
                named = [node for node in candidates if any(
                    _call_name(call) == "from" and len(_args(call)) == 1
                    and (table := g._literal(_args(call)[0]))
                    and re.search(r"(?<![\w])" + re.escape(table) + r"(?![\w])", title, re.I)
                    for call in g._walk(node))]
                if named:
                    candidates = named
            operation = _select(candidates, start, end)
            if operation is None:
                return None
            operation_scope = _enclosing(operation.parent, g._FUNCTIONS) or scope
            return {"version": 1, "method": "source_ast", "file": path,
                    "source_sha256": digest, "mechanism": kind,
                    "function_span": _span(operation_scope), "operation_span": _span(operation),
                    "operation_line_start": _lines(operation)[0], "operation_line_end": _lines(operation)[1]}
        except (UnicodeError, ValueError, TypeError, RecursionError, RuntimeError,
                OSError, zipfile.BadZipFile):
            return None

    def _candidates(self, kind, scope, own):
        if kind == "derived_password":
            return [n for n in own if _call_name(n) == "createHmac"]
        if kind == "service_role_access":
            return [n for n in own if _call_name(n) == "createClient" and any(
                c.type == "member_expression"
                and g._text(c.child_by_field_name("property")) == "SUPABASE_SERVICE_ROLE_KEY"
                for c in g._walk(n))]
        if kind == "token_comparison":
            return [n for n in own if n.type == "binary_expression"
                    and g._text(n.child_by_field_name("operator")) in {"!=", "!==", "==", "==="}
                    and any(c.type == "member_expression"
                            and re.search(r"(?:TOKEN|SECRET|KEY)$", g._text(c.child_by_field_name("property")))
                            for c in g._walk(n))]
        if kind == "forwarded_host_ssrf":
            # Bind an immutable local header to the exact outbound URL use.
            headers = [n for n in own if _header_call(n)]
            declarations = [_enclosing(node, {"variable_declarator"}) for node in headers]
            if (not declarations or any(node != declarations[0] for node in declarations)
                    or len({g._text(node.child_by_field_name("function")) for node in headers}) != 1):
                return []
            declaration = declarations[0]
            if (declaration is None or declaration.parent.type != "lexical_declaration"
                    or not g._text(declaration.parent).lstrip().startswith("const ")):
                return []
            name = g._name(declaration.child_by_field_name("name"))
            bindings = g._bindings(own)
            if not name or bindings[name] != 1:
                return []
            # Resolve a single const URL-building intermediary. Dynamic calls
            # or arbitrary aliases are deliberately outside this check.
            names = {name}
            for dec in [n for n in own if n.type == "variable_declarator"]:
                value = dec.child_by_field_name("value")
                if value is not None and value.type == "template_string" and any(
                        c.type == "identifier" and g._name(c) in names for c in g._walk(value)):
                    alias = g._name(dec.child_by_field_name("name"))
                    if (alias and bindings[alias] == 1 and dec.parent.type == "lexical_declaration"
                            and g._text(dec.parent).lstrip().startswith("const ")):
                        names.add(alias)
            return [n for n in own if _fetch(n) and _args(n) and any(
                c.type == "identifier" and g._name(c) in names for c in g._walk(_args(n)[0]))]
        if kind == "prediction_url":
            return [n for n in own if _fetch(n) and _args(n) and sum(
                c.type == "member_expression" and g._text(c.child_by_field_name("property")) == "id"
                for c in g._walk(_args(n)[0])) == 1]
        if kind == "query_row_bound":
            return [_chain(n) for n in own if _query(n)]
        if kind == "auto_reply_race":
            # A count/read-then-act candidate is a concrete query; no reasoning
            # about concurrent visibility or the outcome is implied.
            count_queries = [_chain(n) for n in g._walk(scope) if _query(n) and any(
                c.type == "pair" and g._text(c.child_by_field_name("key")) == "count"
                for c in g._walk(_chain(n)))]
            return count_queries
        if kind == "model_metadata_request":
            return [n for n in own if _fetch(n) and "/models/" in _url_text(n)]
        if kind == "prediction_polling":
            # Enclosing retry arrow and its loop must resolve to the same
            # operation, even when one title cites the outer function line.
            loops = [n for n in g._walk(scope) if n.type in {"while_statement", "for_statement"}
                     and any(_fetch(c) and "/predictions/" in _url_text(c) for c in g._walk(n))]
            return loops
        return []
