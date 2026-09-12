"""File accounting for bounded source rules; no source text or paths are exported."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
import zipfile

from app.scan.file_scope import is_dependency_path, is_generated_path
from app.scan.secrets import is_non_production_path


RULE_COVERAGE_KEYS = ("outbound_url", "tls_verification", "unsafe_deserialization", "path_traversal")
EXCLUSION_REASONS = ("unsupported_extension", "non_production_path", "dependency_tree", "generated_build")
SKIP_REASONS = (
    "file_size_limit", "file_limit", "finding_limit", "read_error", "decode_error", "parse_error", "ast_limit",
    "analysis_limit",
)
_COUNTS = ("files_total", "eligible_files", "attempted_files", "analyzed_files", "excluded_files", "skipped_files")
_ANALYSIS_LIMITS: ContextVar[set[str] | None] = ContextVar("rule_analysis_limits", default=None)


@contextmanager
def track_analysis_limits() -> Iterator[set[str]]:
    """Record bounded-expression gaps for this file without interrupting other traces.

    Context-local state keeps concurrent scans and nested invocations separate;
    the finally block also resets it after parse or traversal failures.
    """
    limits: set[str] = set()
    token = _ANALYSIS_LIMITS.set(limits)
    try:
        yield limits
    finally:
        _ANALYSIS_LIMITS.reset(token)


def mark_analysis_limit() -> None:
    limits = _ANALYSIS_LIMITS.get()
    if limits is not None:
        limits.add("analysis_limit")


def normalize_rule_coverage(value: object) -> dict | None:
    """Keep only known numeric records; missing or inconsistent counts stay unknown."""
    if not isinstance(value, dict):
        return None
    result = {}
    for name in RULE_COVERAGE_KEYS:
        record = value.get(name)
        if not isinstance(record, dict) or type(record.get("version")) is not int or record["version"] != 1:
            continue
        if any(type(record.get(key)) is not int or record[key] < 0 for key in _COUNTS):
            continue
        clean = {"version": 1, **{key: record[key] for key in _COUNTS}}
        for key, allowed in (("exclusion_reasons", EXCLUSION_REASONS), ("skip_reasons", SKIP_REASONS)):
            reasons = record.get(key)
            if not isinstance(reasons, dict):
                break
            if any(type(reasons.get(reason, 0)) is not int or reasons.get(reason, 0) < 0 for reason in allowed):
                break
            clean[key] = {reason: reasons[reason] for reason in allowed if reasons.get(reason, 0)}
        else:
            if (clean["files_total"] != clean["eligible_files"] + clean["excluded_files"]
                    or clean["eligible_files"] != clean["analyzed_files"] + clean["skipped_files"]
                    or not 0 <= clean["analyzed_files"] <= clean["attempted_files"] <= clean["eligible_files"]
                    or clean["excluded_files"] != sum(clean["exclusion_reasons"].values())
                    or clean["skipped_files"] != sum(clean["skip_reasons"].values())):
                continue
            clean["partial"] = clean["skipped_files"] > 0
            result[name] = clean
    return result


class RuleCoverage:
    """Inventory before stopping, then count a completed or skipped outcome for each file.

    Eligible files are the rule's own supported source, including oversized files.
    Reading/decoding/parsing a file alone does not count it as analyzed. A safe
    negative prefilter can finish the supported check without parsing that file.
    """

    def __init__(self, archive: zipfile.ZipFile, *, extensions: tuple[str, ...],
                 max_file_bytes: int, coverage: dict | None = None):
        self.coverage = coverage
        self.files_total = 0
        self.eligible_files = 0
        self.attempted_files = 0
        self.analyzed_files = 0
        self.exclusions: Counter[str] = Counter()
        self.skips: Counter[str] = Counter()
        self.infos: list[zipfile.ZipInfo] = []
        for info in archive.infolist():
            if info.is_dir():
                continue
            self.files_total += 1
            if is_dependency_path(info.filename):
                self.exclusions["dependency_tree"] += 1
            elif is_generated_path(info.filename):
                self.exclusions["generated_build"] += 1
            elif is_non_production_path(info.filename):
                self.exclusions["non_production_path"] += 1
            elif not info.filename.endswith(extensions):
                self.exclusions["unsupported_extension"] += 1
            else:
                self.eligible_files += 1
                if info.file_size > max_file_bytes:
                    self.skips["file_size_limit"] += 1
                else:
                    self.infos.append(info)

    def files(self, findings: list, *, max_files: int, max_findings: int) -> Iterator[zipfile.ZipInfo]:
        for index, info in enumerate(self.infos):
            if len(findings) >= max_findings:
                self.skip("finding_limit", len(self.infos) - index)
                return
            if self.attempted_files >= max_files:
                self.skip("file_limit", len(self.infos) - index)
                return
            self.attempted_files += 1
            yield info

    def analyzed(self) -> None:
        self.analyzed_files += 1

    def skip(self, reason: str, count: int = 1) -> None:
        if reason not in SKIP_REASONS:
            raise ValueError("Unknown rule coverage reason")
        self.skips[reason] += count

    def finish(self) -> None:
        record = {
            "version": 1,
            "files_total": self.files_total,
            "eligible_files": self.eligible_files,
            "attempted_files": self.attempted_files,
            "analyzed_files": self.analyzed_files,
            "excluded_files": sum(self.exclusions.values()),
            "skipped_files": sum(self.skips.values()),
            "exclusion_reasons": dict(self.exclusions),
            "skip_reasons": dict(self.skips),
            "partial": bool(self.skips),
        }
        # A missing outcome is a producer bug, never evidence of a clean file.
        normalized = normalize_rule_coverage({RULE_COVERAGE_KEYS[0]: record})
        if not normalized:
            raise ValueError("Inconsistent rule coverage accounting")
        if self.coverage is not None:
            self.coverage.clear()
            self.coverage.update(normalized[RULE_COVERAGE_KEYS[0]])
