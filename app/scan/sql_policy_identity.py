"""Bounded PostgreSQL policy/cascade identities, never evidence of live risk.

A constrained claim selects an AST policy or two-hop foreign-key path in the
cited file. No migration ordering, SQL execution, grants or exploitation is
inferred. Unsupported claims and ambiguous source targets remain separate.
"""
from __future__ import annotations

from bisect import bisect_right
from hashlib import sha256
import json
import re
import stat
import zipfile

POLICY = "sql_insert_membership"
CASCADE = "sql_delete_cascade_chain"
MECHANISMS = {POLICY, CASCADE}
MAX_BYTES = 256_000
MAX_TOTAL_BYTES = 2_000_000
MAX_FILES = 64
MAX_CHECKS = 256
MAX_NODES = 24_000
MAX_DEPTH = 128
MAX_WORK_NODES = 400_000
MAX_OPERATIONS = 256

# Full title grammars select a single hypothesis. Nouns resolve to source
# identifiers below; they cannot introduce an arbitrary grouping key.
_POLICY = re.compile(
    r"(?P<table>[a-z_]+) insert policy does not (?:check (?P<target>[a-z_]+) membership|"
    r"scope the (?P<scope>[a-z_]+) to its participants)", re.I)
_CASCADE = re.compile(
    r"Deleting (?:a|an) (?P<root>[a-z_]+) can (?:delete|remove) "
    r"(?:shared )?(?P<middle>[a-z_]+) (?P<leaf>[a-z_]+)", re.I)
_OTHER = re.compile(r"\b(?:SQL injection|XSS|SSRF|CSRF|deadlock|race condition|"
                    r"encryption|password|timing attack|rate.limit|unbounded|pagination)\b", re.I)


def _noun(word):
    word = word.lower()
    if word in {"conversation", "conversations"}:
        return "message"
    return word[:-2] if word.endswith("ches") else word[:-1] if word.endswith("s") else word


# Full observation grammars deliberately abstain on additional clauses. The
# title alone cannot hide a second ownership or deletion hypothesis. These
# shapes project only the stated source relation; conditions and consequences
# remain separately preserved and unchecked.
_POLICY_OBSERVATION = re.compile(
    r"The INSERT policy checks that (?:the authenticated user owns the "
    r"(?P<table>[a-z_]+)'s sender profile|sender_id belongs to the authenticated user's profile), "
    r"but (?:this condition does not check whether that profile participates in the "
    r"(?P<message>[a-z_]+)'s (?P<target>[a-z_]+)|does not check that the user participates "
    r"in the (?P<relation>[a-z_]+) identified by (?P<column>[a-z_]+))\.?", re.I)
_CASCADE_OBSERVATIONS = [re.compile(pattern, re.I) for pattern in (
    r"The schema cascades (?P<root>[a-z_]+(?: [a-z_]+)?) deletion to (?P<middle>[a-z_]+) "
    r"and (?P<again>[a-z_]+) deletion to (?P<leaf>[a-z_]+)\.?",
    r"(?P<root>[a-z_]+(?: [a-z_]+)?) references in the (?P<middle>[a-z_]+) table use "
    r"ON DELETE CASCADE, and (?P<leaf>[a-z_]+) reference (?P<again>[a-z_]+) with ON DELETE CASCADE\.?",
)]


def _observation_scope(observation, kind, nouns):
    if not isinstance(observation, str) or len(observation) > 16000:
        return False
    text = " ".join(observation.replace("’", "'").split())
    if kind == POLICY:
        match = _POLICY_OBSERVATION.fullmatch(text)
        if match is None:
            return False
        for key in ("table", "message"):
            if match[key] is not None and _noun(match[key]) != nouns[0]:
                return False
        target = match["target"] or match["relation"]
        column = match["column"]
        return (_noun(target) == nouns[1] and (column is None or
                (column.lower().endswith("_id") and _noun(column[:-3]) == nouns[1])))
    for pattern in _CASCADE_OBSERVATIONS:
        match = pattern.fullmatch(text)
        if match is not None:
            return (tuple(_noun(match[key].split()[-1]) for key in ("root", "middle", "leaf")) == nouns
                    and _noun(match["again"]) == nouns[1])
    return False


def sql_policy_claim(finding):
    title = finding.get("title")
    if (not isinstance(title, str) or len(title) > 2000 or finding.get("premises")
            or finding.get("operation_claim") is not None):
        return None
    conditions = finding.get("required_conditions") or []
    if not isinstance(conditions, list) or len(conditions) > 16:
        return None
    texts = [title] + [finding.get(key, "") for key in ("observation", "explanation", "fix_hint")] + conditions
    if any(not isinstance(text, str) or len(text) > 16000 or _OTHER.search(text) for text in texts):
        return None
    match = _POLICY.fullmatch(title.strip())
    if match:
        nouns = (_noun(match["table"]), _noun(match["target"] or match["scope"]))
        return (POLICY, nouns) if _observation_scope(finding.get("observation"), POLICY, nouns) else None
    match = _CASCADE.fullmatch(title.strip())
    if match:
        nouns = tuple(_noun(match[key]) for key in ("root", "middle", "leaf"))
        return (CASCADE, nouns) if _observation_scope(finding.get("observation"), CASCADE, nouns) else None
    return None


def _path(path):
    return (isinstance(path, str) and 0 < len(path) <= 512 and path.endswith(".sql")
            and "\\" not in path and "\x00" not in path
            and all(part not in {"", ".", ".."} for part in path.split("/")))


def _table(node):
    # Explicit schemas only: search_path resolution is outside this collector.
    if node is None or not node.schemaname or node.catalogname:
        return None
    return (node.schemaname, node.relname)


def _matches(table, noun):
    return table is not None and _noun(table[1].split("_")[-1]) == noun


def _hash(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class SQLPolicyResolver:
    def __init__(self, archive):
        self.archive = archive
        self.remaining = MAX_TOTAL_BYTES
        self.work = MAX_WORK_NODES
        self.checks = 0
        self.cache = {}

    def _document(self, path):
        if path in self.cache:
            return self.cache[path]
        if len(self.cache) >= MAX_FILES:
            return None
        self.cache[path] = None
        with zipfile.ZipFile(self.archive) as archive:
            entries = [item for item in archive.infolist() if item.filename == path]
            if (len(entries) != 1 or entries[0].is_dir() or stat.S_ISLNK(entries[0].external_attr >> 16)
                    or entries[0].file_size > min(MAX_BYTES, self.remaining)):
                return None
            self.remaining -= entries[0].file_size
            data = archive.read(entries[0])
        from pglast import ast, parse_sql, scan
        from pglast.parser import ParseError
        source = data.decode("utf-8", errors="strict")
        try:
            statements = parse_sql(source)
            tokens = [t for t in scan(source) if t.name not in {"SQL_COMMENT", "C_COMMENT"}]
        except ParseError:
            return None
        pending, count = [(statements, 0)], 0
        while pending:
            node, depth = pending.pop()
            count += 1
            if count > MAX_NODES or depth > MAX_DEPTH:
                return None
            if isinstance(node, ast.Node):
                pending.extend((getattr(node, field), depth + 1) for field in node)
            elif isinstance(node, (tuple, list)):
                pending.extend((child, depth + 1) for child in node)
        starts = [0] + [i + 1 for i, char in enumerate(source) if char == "\n"]
        def location(lo, hi):
            return {"span": [len(source[:lo].encode()), len(source[:hi].encode())],
                    "lines": [bisect_right(starts, lo), bisect_right(starts, max(lo, hi - 1))]}
        policies, edges, tables = [], [], []
        ti = 0
        for index, raw in enumerate(statements):
            boundary = statements[index + 1].stmt_location if index + 1 < len(statements) else len(source)
            part = []
            while ti < len(tokens) and tokens[ti].start < boundary:
                if tokens[ti].start >= raw.stmt_location:
                    part.append(tokens[ti])
                ti += 1
            if not part:
                continue
            node = raw.stmt
            lo, hi = part[0].start, part[-1].end + 1
            if isinstance(node, ast.CreatePolicyStmt) and _table(node.table):
                policies.append({"table": _table(node.table), "command": node.cmd_name,
                                 "check": node.with_check is not None, **location(lo, hi)})
            if not isinstance(node, ast.CreateStmt) or not _table(node.relation):
                continue
            table = _table(node.relation)
            tables.append(table)
            elements = node.tableElts or ()
            for pos, element in enumerate(elements):
                constraints = element.constraints or () if isinstance(element, ast.ColumnDef) else (element,)
                for constraint in constraints:
                    if (not isinstance(constraint, ast.Constraint) or constraint.contype.name != "CONSTR_FOREIGN"
                            or not _table(constraint.pktable)):
                        continue
                    cols = ((element.colname,) if isinstance(element, ast.ColumnDef)
                            else tuple(col.sval for col in constraint.fk_attrs or ()))
                    stop = elements[pos + 1].location if pos + 1 < len(elements) else hi
                    if pos + 1 == len(elements):
                        # ColumnDef has no end offset. Do not let the last
                        # column's citation include the enclosing table close.
                        depth = 0
                        for token in part:
                            if token.start < element.location:
                                continue
                            if token.name == "ASCII_40":
                                depth += 1
                            elif token.name == "ASCII_41":
                                if depth == 0:
                                    stop = token.start
                                    break
                                depth -= 1
                    stop = len(source[:stop].rstrip())
                    if element.location < 0 or stop <= element.location:
                        continue
                    edges.append({"child": table, "parent": _table(constraint.pktable), "columns": cols,
                                  "cascade": constraint.fk_del_action == "c", **location(element.location, stop)})
        if len(policies) + len(edges) > MAX_OPERATIONS:
            return None
        # Chain selection can inspect every edge for each terminal candidate.
        count += len(edges) ** 2
        self.cache[path] = (policies, edges, tables, sha256(data).hexdigest(), len(starts), count)
        return self.cache[path]

    def identity(self, finding):
        path = finding.get("file")
        start = finding.get("line_start", finding.get("line"))
        end = finding.get("line_end", start)
        claim = sql_policy_claim(finding)
        if (not _path(path) or claim is None or self.checks >= MAX_CHECKS
                or type(start) is not int or type(end) is not int or not 1 <= start <= end):
            return None
        self.checks += 1
        try:
            document = self._document(path)
            if document is None:
                return None
            policies, edges, tables, digest, line_count, count = document
            if end > line_count or count > self.work:
                return None
            self.work -= count
            kind, nouns = claim
            def overlaps(item):
                return item["lines"][0] <= end and start <= item["lines"][1]
            binding = None
            if kind == POLICY:
                candidates = [p for p in policies if p["command"] == "insert" and p["check"]
                              and _matches(p["table"], nouns[0]) and overlaps(p)]
                if len(candidates) != 1:
                    return None
                operation = candidates[0]
                targets = {edge["parent"] for edge in edges if edge["child"] == operation["table"]
                           and _matches(edge["parent"], nouns[1])}
                if len(targets) != 1 or tables.count(operation["table"]) != 1:
                    return None
                binding = {"target": sorted(targets), "table": operation["table"]}
            else:
                # A distinct terminal FK is a distinct chain, even when both
                # constraints reference the same parent table.
                candidates = []
                for terminal in edges:
                    if (not terminal["cascade"] or not _matches(terminal["child"], nouns[2])
                            or not _matches(terminal["parent"], nouns[1]) or not overlaps(terminal)):
                        continue
                    parents = [e for e in edges if e["cascade"] and e["child"] == terminal["parent"]
                               and _matches(e["parent"], nouns[0])]
                    roots = {e["parent"] for e in parents}
                    if len(roots) == 1:
                        candidates.append((terminal, parents))
                if len(candidates) != 1:
                    return None
                operation, parents = candidates[0]
                chain_tables = {operation["child"], operation["parent"], parents[0]["parent"]}
                if len(chain_tables) != 3 or any(tables.count(table) != 1 for table in chain_tables):
                    return None
                binding = {"terminal": operation, "parents": parents}
            return {"version": 1, "method": "source_ast", "mechanism": kind,
                    "claim_scope": "insert_relation_membership" if kind == POLICY else "two_hop_delete_cascade",
                    "file": path, "source_sha256": digest, "binding_sha256": _hash(binding),
                    "operation_span": operation["span"],
                    "operation_line_start": operation["lines"][0], "operation_line_end": operation["lines"][1]}
        except (UnicodeError, ValueError, TypeError, ImportError, RecursionError, RuntimeError,
                OSError, zipfile.BadZipFile):
            return None


def valid_sql_policy_identity(identity, path):
    if not isinstance(identity, dict) or set(identity) != {
            "version", "method", "mechanism", "claim_scope", "file", "source_sha256", "binding_sha256",
            "operation_span", "operation_line_start", "operation_line_end"}:
        return False
    if (not _path(path) or identity["file"] != path or type(identity["version"]) is not int
            or identity["version"] != 1 or identity["method"] != "source_ast"
            or not isinstance(identity["mechanism"], str) or identity["mechanism"] not in MECHANISMS
            or identity["claim_scope"] != ("insert_relation_membership" if identity["mechanism"] == POLICY
                                          else "two_hop_delete_cascade")):
        return False
    if any(not isinstance(identity[key], str) or not re.fullmatch(r"[0-9a-f]{64}", identity[key])
           for key in ("source_sha256", "binding_sha256")):
        return False
    span = identity["operation_span"]
    start, end = identity["operation_line_start"], identity["operation_line_end"]
    return (isinstance(span, list) and len(span) == 2 and all(type(n) is int for n in span)
            and 0 <= span[0] < span[1] <= MAX_BYTES
            and type(start) is int and type(end) is int and 1 <= start <= end <= MAX_BYTES)


def compatible_sql_policy_claims(left, right, identity):
    if not valid_sql_policy_identity(identity, left.file):
        return False
    for key in ("source", "verification_method", "verification_status", "category", "origin_category", "context"):
        if getattr(left, key) != getattr(right, key):
            return False
    if left.source != "llm" or left.verification_method != "model_review":
        return False
    claims = []
    for finding in (left, right):
        record = finding.claim_evidence or {}
        if not isinstance(record, dict):
            return False
        check, producer = record.get("source_check"), record.get("producer")
        if not isinstance(check, dict) or not isinstance(producer, dict) or record.get("premise_checks"):
            return False
        start, end = check.get("line_start"), check.get("line_end")
        if (check.get("kind") != "quote_match" or check.get("result") not in (None, "observed")
                or type(start) is not int or type(end) is not int or type(finding.line) is not int
                or not 1 <= start <= finding.line <= end
                or not start <= identity["operation_line_end"] or not identity["operation_line_start"] <= end
                or check.get("file", finding.file) != identity["file"]
                or check.get("source_sha256", identity["source_sha256"]) != identity["source_sha256"]
                or any(not isinstance(producer.get(key), str) or not producer[key].strip()
                       for key in ("model", "rubric"))
                or type(producer.get("response")) is not int or producer["response"] < 1):
            return False
        claim = sql_policy_claim({"title": finding.title, "explanation": finding.explanation,
                                  "fix_hint": finding.fix_hint, "observation": record.get("observation", ""),
                                  "required_conditions": record.get("required_conditions"),
                                  "operation_claim": record.get("operation_claim")})
        if claim is None or claim[0] != identity["mechanism"]:
            return False
        claims.append(claim)
        if any(record.get(key) != "not_checked" for key in ("conditions_status", "consequence_status")):
            return False
    return claims[0] == claims[1]
