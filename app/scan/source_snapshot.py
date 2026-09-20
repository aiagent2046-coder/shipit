"""Bounded, read-only source access for evidence collection from a scan ZIP.

This never extracts an archive or imports project code. Parsed files are cached
only for this immutable archive snapshot, and facts must match the source digest
recorded by the SQL detector before any additional analysis can run.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import io
from itertools import islice
import zipfile

from app.ingest.validators import MAX_ARCHIVE_BYTES

MAX_SOURCE_BYTES = 400_000
MAX_SNAPSHOT_BYTES = 2_000_000
MAX_SOURCE_NODES = 80_000


class SourceUnavailable(Exception):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class SourceDocument:
    file: str
    source_sha256: str
    tree: ast.Module
    calls: dict


def source_span(node):
    return [node.lineno, node.col_offset, node.end_lineno, node.end_col_offset]


class SourceSnapshot:
    def __init__(self, data: bytes, archive_sha256: str):
        if len(data) > MAX_ARCHIVE_BYTES:
            raise SourceUnavailable("source_limit")
        if hashlib.sha256(data).hexdigest() != archive_sha256:
            raise SourceUnavailable("source_changed")
        self.archive_sha256 = archive_sha256
        self._archive = zipfile.ZipFile(io.BytesIO(data))
        self._entries = {}
        for info in self._archive.infolist():
            if info.filename in self._entries:
                self._archive.close()
                raise SourceUnavailable("source_unavailable")
            self._entries[info.filename] = info
        self.framework_shadowed = any(
            part.casefold().split(".", 1)[0] in {"fastapi", "starlette"}
            for path in self._entries for part in path.replace("\\", "/").split("/"))
        self.deserialization_import_shadowed = any(
            part.casefold().split(".", 1)[0] in {
                "pickle", "fastapi", "starlette", "typing", "typing_extensions", "builtins"}
            for path in self._entries for part in path.replace("\\", "/").split("/"))
        self.file_deserialization_import_shadowed = any(
            part.casefold().split(".", 1)[0] in {"pickle", "builtins"}
            for path in self._entries for part in path.replace("\\", "/").split("/"))
        self._documents = {}
        self._source_bytes = 0
        self.acquisitions = {}

    @classmethod
    def from_archive(cls, fileobj, *, archive_sha256):
        position = fileobj.tell()
        try:
            fileobj.seek(0)
            data = fileobj.read(MAX_ARCHIVE_BYTES + 1)
        finally:
            fileobj.seek(position)
        return cls(data, archive_sha256)

    def close(self):
        self._archive.close()

    def locate(self, trace, *, spend):
        """Require one exact AST call; line-level findings cannot merge calls."""
        path = trace["file"]
        spend()
        document = self._documents.get(path)
        if isinstance(document, str):
            raise SourceUnavailable(document)
        if document is None:
            try:
                document = self._read(path, spend)
            except SourceUnavailable as exc:
                self._documents[path] = exc.reason
                raise
            self._documents[path] = document
        if document.source_sha256 != trace["source_sha256"]:
            raise SourceUnavailable("source_changed")
        key = (tuple(trace["sink_span"]) if trace.get("method") == "python_ast_import_resolved"
               else (trace["sink_line"], trace["sink_method"]))
        candidates = document.calls.get(key, ())
        if not candidates:
            raise SourceUnavailable("sink_not_found")
        if len(candidates) != 1:
            raise SourceUnavailable("ambiguous_sink")
        return document, candidates[0]

    def _read(self, path, spend):
        info = self._entries.get(path)
        if info is None or info.is_dir() or not path.lower().endswith(".py"):
            raise SourceUnavailable("source_unavailable")
        if info.file_size > MAX_SOURCE_BYTES or self._source_bytes + info.file_size > MAX_SNAPSHOT_BYTES:
            raise SourceUnavailable("source_limit")
        spend(info.file_size // 64 + 1)
        with self._archive.open(info) as entry:
            data = entry.read(MAX_SOURCE_BYTES + 1)
        if len(data) > MAX_SOURCE_BYTES:
            raise SourceUnavailable("source_limit")
        self._source_bytes += len(data)
        try:
            tree = ast.parse(data.decode("utf-8"))
        except (UnicodeError, SyntaxError, ValueError):
            raise SourceUnavailable("source_parse_error") from None
        except RecursionError:
            raise SourceUnavailable("source_limit") from None
        calls = {}
        count = 0
        for node in islice(ast.walk(tree), MAX_SOURCE_NODES + 1):
            count += 1
            spend()
            if isinstance(node, ast.Call):
                calls.setdefault(tuple(source_span(node)), []).append(node)
                if isinstance(node.func, ast.Attribute):
                    calls.setdefault((node.lineno, node.func.attr), []).append(node)
        if count > MAX_SOURCE_NODES:
            raise SourceUnavailable("source_limit")
        return SourceDocument(path, hashlib.sha256(data).hexdigest(), tree, calls)
