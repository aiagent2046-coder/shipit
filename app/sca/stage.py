"""The SCA stage: known vulnerabilities in the dependencies an archive ships.

WHY THIS IS A STAGE AND NOT A SCANNER. run_static_scan is deterministic and
offline: the same bytes give the same findings on any machine, which is what
lets its results be cached against an archive digest. This stage asks a
database over the network, so the same bytes can answer differently tomorrow
and not at all on a laptop with no connection. Mixing the two would make the
static stage's cache a lie and its offline promise false. It is deliberately
shaped like the LLM stage instead: it runs when a client is supplied, it
degrades to a recorded reason when the network is gone, and the audit it
belongs to continues either way.

WHAT IT CLAIMS, AND WHAT IT DOES NOT. A finding here says: this exact version
is listed as affected by this advisory. It does not say the vulnerable code
path is reachable from the application -- that needs the call graph, not a
database. The wording of every finding keeps that boundary visible, because
"your dependency has a CVE" and "your application is exploitable" are
different claims and only the first one was verified.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.scan.checks import CheckFinding
from app.sca.lockfiles import Dependency, collect_dependencies
from app.sca.osv import OsvClient, OsvUnavailable

# One rule id for the whole stage: the reader's action is the same for every
# advisory -- find out whether this dependency is used and upgrade it -- and a
# rule id per CVE would put thousands of ids into the report's vocabulary.
RULE_ID = "dependency-known-vulnerability"
SCA_RULE_IDS = (RULE_ID,)

# The key this stage contributes to the audit's execution facts, beside the
# static checks and the LLM rubrics. A reader must be able to tell "no known
# vulnerabilities were found" from "the database was never asked".
CHECKS_RUN_KEY = "sca_dependencies"

# Severity floor. Low-severity advisories in transitive dependencies are
# volume without a decision: they would bury the two findings that matter and
# cost the reader the same attention for each. Filtered, counted, and reported.
SEVERITY_ORDER = ("low", "medium", "high", "critical")
MIN_SEVERITY = "medium"

# GitHub advisories spell the middle rung differently from everyone else, and
# an unmapped rating would silently become the default.
_SOURCE_SEVERITY = {
    "low": "low", "moderate": "medium", "medium": "medium",
    "high": "high", "important": "high", "critical": "critical",
}

# Bounded because one ancient dependency tree can match hundreds of advisories.
MAX_FINDINGS = 25


def _version_key(version: str) -> tuple[int, ...]:
    """Numeric parts of a version, for comparing upgrade targets.

    Deliberately crude: it only has to decide which of two upgrades is the
    further one, and a version this cannot parse sorts as (0,) rather than
    raising inside a report.
    """
    parts = [int(p) for p in re.findall(r"\d+", version)]
    return tuple(parts) if parts else (0,)


def _rank(severity: str) -> int:
    return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 0


def _identifier(record: dict) -> str:
    """A CVE is the identifier an owner can search for, so it wins over the
    database-local GHSA id when the record carries both."""
    aliases = [a for a in record.get("aliases", []) if isinstance(a, str)]
    for alias in aliases:
        if alias.startswith("CVE-"):
            return alias
    return str(record.get("id", ""))


def _severity(record: dict) -> tuple[str, bool]:
    """(severity, whether the source declared it). The flag travels into the
    finding's confidence: a rating we had to assume is weaker evidence than one
    the advisory states."""
    database_specific = record.get("database_specific")
    if isinstance(database_specific, dict):
        declared = database_specific.get("severity")
        if isinstance(declared, str):
            mapped = _SOURCE_SEVERITY.get(declared.strip().lower())
            if mapped:
                return mapped, True
    return "medium", False


def _fixed_versions(record: dict, dependency: Dependency) -> list[str]:
    """Versions the advisory says fix this package, as written in the record."""
    fixed: list[str] = []
    for affected in record.get("affected", []) or []:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package")
        if isinstance(package, dict):
            name = str(package.get("name", ""))
            ecosystem = str(package.get("ecosystem", ""))
            if name and (name.lower(), ecosystem) != (dependency.name.lower(),
                                                     dependency.ecosystem):
                continue
        for span in affected.get("ranges", []) or []:
            if not isinstance(span, dict):
                continue
            for event in span.get("events", []) or []:
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    fixed.append(event["fixed"])
    seen: dict[str, None] = {}
    for version in fixed:
        seen.setdefault(version, None)
    return list(seen)[:4]


def _advisory_url(record: dict) -> str:
    for reference in record.get("references", []) or []:
        if not isinstance(reference, dict):
            continue
        url = reference.get("url")
        if isinstance(url, str) and url.startswith("http"):
            return url
    return f"https://osv.dev/vulnerability/{record.get('id', '')}"


@dataclass
class Reported:
    """One vulnerability OF one dependency, after merging the records that
    describe it.

    Two database entries frequently carry the same CVE alias -- measured
    against the live API: lodash 4.17.21 matched two records that both resolve
    to CVE-2025-13465, and reporting them separately printed the same
    identifier twice with two different upgrade targets. One vulnerability is
    one row, and the upgrade that satisfies every record is the furthest one.
    """
    dependency: Dependency
    identifier: str
    severity: str
    declared: bool
    summary: str
    published: str
    url: str = ""
    fixed: list[str] = field(default_factory=list)
    records: int = 1

    def merge(self, other: "Reported") -> None:
        if _rank(other.severity) > _rank(self.severity):
            self.severity = other.severity
        self.declared = self.declared or other.declared
        if not self.summary or self.summary == "known vulnerability":
            self.summary = other.summary
        self.published = min(filter(None, (self.published, other.published)),
                             default="")
        self.url = self.url or other.url
        for version in other.fixed:
            if version not in self.fixed:
                self.fixed.append(version)
        self.records += other.records


def _reported(dependency: Dependency, records: list[dict]) -> list[Reported]:
    """Merge the records for one dependency by the identifier a reader searches."""
    merged: dict[tuple[str, str], Reported] = {}
    for record in records:
        severity, declared = _severity(record)
        reported = Reported(
            dependency=dependency,
            identifier=_identifier(record),
            severity=severity,
            declared=declared,
            summary=str(record.get("summary") or "").strip(),
            published=str(record.get("published") or "")[:10],
            url=_advisory_url(record),
            fixed=_fixed_versions(record, dependency),
        )
        key = (reported.identifier, dependency.name.lower())
        if key in merged:
            merged[key].merge(reported)
        else:
            merged[key] = reported
    return list(merged.values())


def build_finding(reported: Reported) -> CheckFinding:
    dependency = reported.dependency
    identifier = reported.identifier
    summary = reported.summary or "known vulnerability"
    # The furthest fix among the merged records is the one that satisfies all
    # of them: upgrading to a point that clears one advisory but not its
    # neighbour would send the reader back for a second upgrade.
    fixed = sorted(reported.fixed, key=_version_key, reverse=True)[:2]
    upgrade = f" Upgrade to {', or '.join(fixed)} or later." if fixed else ""
    published = reported.published
    if reported.records > 1:
        summary += (f" ({reported.records} database entries describe this "
                    f"identifier)")

    scope = ("your project lists this dependency directly"
             if dependency.direct else
             "this dependency arrives through another one")
    how = (f"The lockfile {dependency.manifest} resolves "
           f"{dependency.name} to {dependency.version}, and the vulnerability "
           f"database lists that exact version as affected.")
    risk = (f"{scope}. {identifier}: {summary}. "
            f"A dependency with a known vulnerability is a piece of software "
            f"someone else has already been told how to break; whether the "
            f"broken part is reachable from your code was NOT checked here, so "
            f"treat this as a reason to look, not a proven exploit.")
    if published:
        risk += f" Published {published}."
    fix = (f"{upgrade.strip()} Then reinstall and run your tests: a lockfile "
           f"change reaches production only after the build that reads it. "
           f"Reference: {reported.url}")
    return CheckFinding(
        rule_id=RULE_ID,
        title=f"{identifier} in {dependency.name} {dependency.version}",
        severity=reported.severity,
        # 0.9 when the advisory itself states the rating, 0.6 when the rating
        # had to be assumed. The finding's own fact -- this version is listed
        # as affected -- is not in doubt either way.
        confidence=0.9 if reported.declared else 0.6,
        category="Security",
        file=dependency.manifest,
        line=dependency.line,
        explanation=how + " " + risk,
        fix_hint=fix,
    )


def run_sca_stage(data: bytes, client: OsvClient | None) -> tuple[list[CheckFinding], dict]:
    """(findings, stats). Never raises: an unreachable database is a recorded
    reason, not a failed audit.

    The caller decides whether to run this at all; passing no client is how it
    says no, and the stats then record that the dependencies were never asked
    about -- which the report must not present as a clean result.
    """
    stats: dict = {
        "checks_run": [CHECKS_RUN_KEY],
        "lockfiles": [],
        "dependencies": 0,
        "advisories": 0,
        "below_severity_floor": 0,
        "unreadable_advisories": 0,
        "requests": 0,
        "findings": 0,
        "truncated": 0,
        "skipped_reason": None,
    }
    dependencies, manifests = collect_dependencies(data)
    stats["lockfiles"] = manifests
    stats["dependencies"] = len(dependencies)
    if not dependencies:
        # No lockfile is not "no vulnerabilities": it is nothing to look up.
        stats["skipped_reason"] = "no_lockfile"
        return [], stats
    if client is None:
        stats["skipped_reason"] = "no_client"
        return [], stats

    try:
        hits = client.query(dependencies)
        wanted: dict[str, None] = {}
        for indexes in hits.values():
            for advisory in indexes:
                wanted.setdefault(advisory, None)
        records = client.details(list(wanted))
    except OsvUnavailable as exc:
        stats["skipped_reason"] = f"osv_unavailable: {exc}"
        stats["requests"] = client.requests_made
        return [], stats

    stats["requests"] = client.requests_made
    stats["advisories"] = len(wanted)
    stats["unreadable_advisories"] = max(0, len(wanted) - len(records))

    findings: list[CheckFinding] = []
    for index, advisories in hits.items():
        dependency = dependencies[index]
        served = [records[a] for a in advisories if a in records]
        for reported in _reported(dependency, served):
            if _rank(reported.severity) < _rank(MIN_SEVERITY):
                stats["below_severity_floor"] += 1
                continue
            findings.append(build_finding(reported))

    findings.sort(key=lambda f: (-_rank(f.severity), f.file, f.line, f.title))
    stats["truncated"] = max(0, len(findings) - MAX_FINDINGS)
    findings = findings[:MAX_FINDINGS]
    stats["findings"] = len(findings)
    return findings, stats
