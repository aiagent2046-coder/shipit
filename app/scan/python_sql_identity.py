"""Bounded identities for table-name interpolation hypotheses, not SQL safety.

Only one simple f-string table slot at one cited call can identify a group.
No target code is executed. Unsupported or compound claims remain separate.
"""
from __future__ import annotations

import ast
from hashlib import sha256
import re
import stat
import zipfile

MECHANISM = "python_sql_table_interpolation"
CLAIM_SCOPE = "table_identifier_interpolation"
MAX_BYTES = 256_000
MAX_TOTAL_BYTES = 2_000_000
MAX_FILES = 64
MAX_CHECKS = 256
MAX_NODES = 24_000
MAX_DEPTH = 128
MAX_WORK_NODES = 400_000

# New responses select a source operation explicitly. Legacy prose is admitted
# by a bounded vocabulary, not a list of full model-generated sentences.
# Unknown or compound titles abstain; this is routing, never proof of safety.
SELECTOR_KIND = "sql_table_interpolation"
_LEGACY_WORDS = frozenset("""
a an the into in from of to through via directly direct dynamic dynamically
python sql postgresql sqlite query queries string strings statement statements
table tables name names identifier identifiers list migration script method
unsanitised unsanitized unvalidated unparameterized unparameterised
interpolation interpolated interpolating substitution substituted embedded
embedding inserted inserting concatenation concatenated concatenating
f-string f-strings without validation sanitisation sanitization parameterisation
parameterization allowlist whitelist check checks using uses used is are
""".split())


def sql_operation_selector(finding):
    """Return only a well-formed untrusted selector, not an evidence result."""
    selector = finding.get("operation_claim")
    if (not isinstance(selector, dict)
            or set(selector) != {"kind", "target", "line_start", "line_end"}
            or selector.get("kind") != SELECTOR_KIND
            or not isinstance(selector.get("target"), str)
            or not re.fullmatch(r"[a-zA-Z_]\w{0,127}", selector["target"])):
        return None
    start, end = selector.get("line_start"), selector.get("line_end")
    if type(start) is not int or type(end) is not int or not 1 <= start <= end <= MAX_BYTES:
        return None
    return dict(selector)


def _legacy_table_title(title):
    # Backtick/local function labels carry no claim meaning. Permit only a
    # single trailing scope label; don't swallow a clause containing a risk.
    title = re.sub(r"\s+in\s+`?[a-zA-Z_]\w*_[a-zA-Z_\d]*`?$", "", title.strip(), flags=re.I)
    if not re.fullmatch(r"[a-zA-Z\s().`-]+", title):
        return False
    title = title.lower().replace("table-name", "table name")
    words = re.findall(r"[a-zA-Z]+(?:-[a-zA-Z]+)*", title.lower())
    return (bool(words) and set(words) <= _LEGACY_WORDS
            and bool(set(words) & {"sql", "postgresql", "sqlite"})
            and bool(set(words) & {"table", "tables"})
            and bool(set(words) & {"name", "names", "identifier", "identifiers"})
            and bool(set(words) & {"interpolation", "interpolated", "interpolating", "substitution",
                                  "substituted", "embedded", "embedding", "inserted", "inserting",
                                  "concatenation", "concatenated", "concatenating", "f-string", "f-strings"}))


_OTHER = re.compile(
    r"\b(?:SSRF|XSS|CSRF|authentication|authorization|unauthenticated|passwords?|"
    r"credentials?|race|deadlock|concurren\w*|timeout|unbounded|pagination|"
    r"encrypt\w*|ownership|tenant|isolation|missing WHERE|without WHERE|"
    r"command injection|shell injection|denial.of.service)\b|rate[ -]limit", re.I)
_METHODS = {"execute", "executemany", "executescript", "raw", "execute_sql", "fetch", "fetchrow", "fetchval"}


def sql_table_claim(finding):
    title = finding.get("title")
    if not isinstance(title, str) or not title.strip() or len(title) > 2000:
        return False
    # An explicit invalid selector must not silently fall back to prose.
    if finding.get("operation_claim") is not None:
        if sql_operation_selector(finding) is None:
            return False
    elif not _legacy_table_title(title):
        return False
    conditions = finding.get("required_conditions") or []
    if not isinstance(conditions, list) or len(conditions) > 16 or finding.get("premises"):
        return False
    texts = [title] + [finding.get(key, "") for key in ("observation", "explanation", "fix_hint")] + conditions
    return all(isinstance(text, str) and len(text) <= 16000 and not _OTHER.search(text) for text in texts)


def _path(path):
    return (isinstance(path, str) and 0 < len(path) <= 512 and path.endswith(".py")
            and "\\" not in path and "\x00" not in path
            and all(part not in {"", ".", ".."} for part in path.split("/")))


def _table_slot(node):
    if (not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute)
            or node.func.attr not in _METHODS or not node.args or not isinstance(node.args[0], ast.JoinedStr)):
        return None
    parts = node.args[0].values
    # Complete SELECT read only; no value slots, suffix clauses, conversions,
    # format specifications or second statement can share this identity.
    if len(parts) != 2 or not isinstance(parts[0], ast.Constant) or not isinstance(parts[0].value, str):
        return None
    if not re.fullmatch(r"\s*SELECT\s+(?:\*|COUNT\s*\(\s*\*\s*\))\s+FROM\s+", parts[0].value, re.I):
        return None
    slot = parts[1]
    return (slot.value if isinstance(slot, ast.FormattedValue) and isinstance(slot.value, ast.Name)
            and slot.conversion == -1 and slot.format_spec is None else None)


class PythonSQLResolver:
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
            matches = [info for info in archive.infolist() if info.filename == path]
            if (len(matches) != 1 or matches[0].is_dir() or stat.S_ISLNK(matches[0].external_attr >> 16)
                    or matches[0].file_size > min(MAX_BYTES, self.remaining)):
                return None
            self.remaining -= matches[0].file_size
            data = archive.read(matches[0])
        root = ast.parse(data.decode("utf-8", errors="strict"))
        pending, nodes = [(root, 0)], []
        while pending:
            node, depth = pending.pop()
            nodes.append(node)
            if len(nodes) > MAX_NODES or depth > MAX_DEPTH:
                return None
            pending.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
        offsets = [0]
        for line in data.splitlines(keepends=True):
            offsets.append(offsets[-1] + len(line))
        self.cache[path] = (nodes, offsets, sha256(data).hexdigest())
        return self.cache[path]

    def identity(self, finding):
        path = finding.get("file")
        start, end = finding.get("line_start"), finding.get("line_end")
        if (not _path(path) or not sql_table_claim(finding) or self.checks >= MAX_CHECKS
                or type(start) is not int or type(end) is not int or not 1 <= start <= end):
            return None
        self.checks += 1
        try:
            document = self._document(path)
            if document is None:
                return None
            nodes, offsets, digest = document
            if end >= len(offsets) or len(nodes) > self.work:
                return None
            self.work -= len(nodes)
            # Two possible database calls are ambiguous even if only one has
            # a supported argument. Result readers such as fetchall() are not
            # SQL execution candidates. Never select a nearby uncited call.
            calls = [node for node in nodes if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Attribute) and node.func.attr in _METHODS
                     and node.lineno <= end and start <= node.end_lineno]
            if len(calls) != 1 or (slot := _table_slot(calls[0])) is None:
                return None
            call = calls[0]
            selector = sql_operation_selector(finding)
            if selector is not None and (
                    selector["target"] != slot.id
                    or not start <= selector["line_start"] <= selector["line_end"] <= end
                    or not call.lineno <= selector["line_start"] <= selector["line_end"] <= call.end_lineno):
                return None
            def span(node):
                return [offsets[node.lineno - 1] + node.col_offset,
                        offsets[node.end_lineno - 1] + node.end_col_offset]
            return {"version": 1, "method": "source_ast", "mechanism": MECHANISM,
                    "claim_scope": CLAIM_SCOPE, "file": path, "source_sha256": digest,
                    "operation_span": span(call), "slot_span": span(slot),
                    "operation_line_start": call.lineno, "operation_line_end": call.end_lineno}
        except (UnicodeError, ValueError, TypeError, SyntaxError, RecursionError, RuntimeError,
                OSError, zipfile.BadZipFile):
            return None


def valid_sql_identity(identity, path):
    if not isinstance(identity, dict) or set(identity) != {
            "version", "method", "mechanism", "claim_scope", "file", "source_sha256",
            "operation_span", "slot_span", "operation_line_start", "operation_line_end"}:
        return False
    if (not _path(path) or identity["file"] != path or type(identity["version"]) is not int
            or identity["version"] != 1 or identity["method"] != "source_ast"
            or identity["mechanism"] != MECHANISM or identity["claim_scope"] != CLAIM_SCOPE
            or not isinstance(identity["source_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", identity["source_sha256"])):
        return False
    for key in ("operation_span", "slot_span"):
        span = identity[key]
        if (not isinstance(span, list) or len(span) != 2 or any(type(n) is not int for n in span)
                or not 0 <= span[0] < span[1] <= MAX_BYTES):
            return False
    operation, slot = identity["operation_span"], identity["slot_span"]
    start, end = identity["operation_line_start"], identity["operation_line_end"]
    return (operation[0] <= slot[0] < slot[1] <= operation[1]
            and type(start) is int and type(end) is int and 1 <= start <= end <= MAX_BYTES)


def compatible_sql_claims(left, right, identity):
    if not valid_sql_identity(identity, left.file):
        return False
    for key in ("source", "verification_method", "verification_status", "category", "origin_category", "context"):
        if getattr(left, key) != getattr(right, key):
            return False
    if left.source != "llm" or left.verification_method != "model_review":
        return False
    for finding in (left, right):
        record = finding.claim_evidence or {}
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
        if not sql_table_claim({"title": finding.title, "explanation": finding.explanation,
                                "fix_hint": finding.fix_hint, "observation": record.get("observation", ""),
                                "required_conditions": record.get("required_conditions"),
                                "operation_claim": record.get("operation_claim")}):
            return False
        if any(record.get(key) != "not_checked" for key in ("conditions_status", "consequence_status")):
            return False
    return True
