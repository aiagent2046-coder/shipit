"""Adapter over the drydock (shipit) offline advisory engine.

Scout collects public artifacts (manifests, lockfiles), hands them to
shipit's match_archive and rolls the result up for triage.

Product rules inherited from shipit and enforced here:
  - CISA KEV is an annotation source: presence escalates priority,
    absence never means safe.
  - A package/version match is evidence, not proof of exploitability;
    every report carries the engine's limitations verbatim.
"""
from __future__ import annotations

import hashlib
import io
import zipfile
from dataclasses import dataclass, field

from scout import paths

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class ScanResult:
    findings: list[dict]
    coverage: dict
    limitations: list[str]
    engine_commit: str | None
    catalog_digest: str
    target: str = ""
    artifacts: list[str] = field(default_factory=list)
    stack_hints: list[str] = field(default_factory=list)

    @property
    def kev_listed(self) -> list[dict]:
        return [f for f in self.findings if _exploitation(f) == "listed"]

    @property
    def critical(self) -> list[dict]:
        return [f for f in self.findings if _effective_severity(f) == "critical"]


def _claim(finding: dict) -> dict:
    return finding.get("claim_evidence") or {}


def _exploitation(finding: dict) -> str:
    ev = _claim(finding).get("exploitation") or {}
    return ev.get("status") or "unknown"


def _effective_severity(finding: dict) -> str:
    """KEV-listed exploitation raises severity to critical (product rule)."""
    if _exploitation(finding) == "listed":
        return "critical"
    return finding.get("severity") or "info"


def rank(findings: list[dict]) -> list[dict]:
    """KEV-listed first, then by effective severity, stable within a group."""
    return sorted(
        findings,
        key=lambda f: (
            0 if _exploitation(f) == "listed" else 1,
            SEVERITY_ORDER.get(_effective_severity(f), 5),
            f.get("title") or "",
        ),
    )


class Engine:
    """Loads the pinned offline catalogs once and matches archives against them."""

    def __init__(self) -> None:
        root = paths.bootstrap()
        from app.local_store import decode_catalog
        from app.scan.cve_match import match_archive

        self._match_archive = match_archive
        self.commit = paths.engine_commit()
        self.root = root
        raw = (root / "app" / "data" / "cve-catalog.json").read_bytes()
        checksum = (root / "app" / "data" / "cve-catalog.json.sha256").read_text().split()[0]
        self.catalog, self.catalog_digest = decode_catalog(raw, checksum)

    def scan_files(self, files: dict[str, bytes], target: str = "") -> ScanResult:
        """Match a set of manifest/lockfile paths -> bytes against the snapshot."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name, data in files.items():
                zf.writestr(name, data)
        raw_result = self._match_archive(buf.getvalue(), self.catalog)
        coverage = raw_result.get("coverage") or {}
        findings = rank(raw_result.get("findings") or [])
        return ScanResult(
            findings=findings,
            coverage=coverage,
            limitations=list(coverage.get("limitations") or raw_result.get("limitations") or []),
            engine_commit=self.commit,
            catalog_digest=self.catalog_digest,
            target=target,
            artifacts=sorted(files),
        )


def artifact_fingerprint(files: dict[str, bytes]) -> str:
    """Stable fingerprint of what was analyzed: dedup key for outreach."""
    digest = hashlib.sha256()
    for name in sorted(files):
        digest.update(name.encode("utf-8", "replace") + b"\0" + files[name])
    return digest.hexdigest()
