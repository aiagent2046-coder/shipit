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

ONE ROW PER PACKAGE, NOT ONE PER ADVISORY. Measured against the live API:
django==2.0.0 matches 24 advisories whose fix is a single action -- upgrade
Django. Twenty-four rows bury that decision, and they also distort the score,
because every row weighs on the same category. The row names the worst
advisory, lists several, and says how many were counted, so nothing is hidden.

WHAT IT CLAIMS, AND WHAT IT DOES NOT. A finding here says: this exact version
is listed as affected by these advisories. It does not say the vulnerable code
path is reachable from the application -- that needs the call graph, not a
database. The wording of every finding keeps that boundary visible, because
"your dependency has a CVE" and "your application is exploitable" are different
claims and only the first one was verified.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.scan.checks import CheckFinding
from app.sca.lockfiles import Dependency, collect_dependency_inventory, unusable_lockfiles
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

# How many advisories a package's row names before it says "and N more".
MAX_LISTED_ADVISORIES = 4

# The dependency answer is true of the day it was asked, so a cached audit has
# to say how old its answer is. A week is a policy choice, not a measurement:
# advisory data changes on the order of days, and past this point "we checked
# your dependencies" stops being a claim a reader should lean on.
SCA_FRESHNESS_TTL_DAYS = 7


def freshness(asked_at: str | None, now: datetime | None = None) -> str:
    """'fresh' | 'stale' | 'unknown' for a recorded `asked_at`.

    Unknown is kept apart from stale: an audit from before this stage existed
    has no date at all, and reporting it as "stale" would invent one.
    """
    if not asked_at:
        return "unknown"
    try:
        asked = datetime.fromisoformat(asked_at)
    except ValueError:
        return "unknown"
    if asked.tzinfo is None:
        asked = asked.replace(tzinfo=timezone.utc)
    reference = now or datetime.now(timezone.utc)
    return "stale" if (reference - asked).days >= SCA_FRESHNESS_TTL_DAYS else "fresh"


# Deployment-level switch. Set SCA_ENABLED=0 on a host that must not contact a
# third party at all (an air-gapped or contract-bound deployment); the stage
# then records the same "nobody asked" reason the free tier produces, so the
# absence is visible rather than silent.
SCA_ENABLED_ENV = "SCA_ENABLED"


def sca_enabled(env: dict | None = None) -> bool:
    source = os.environ if env is None else env
    return str(source.get(SCA_ENABLED_ENV, "1")).strip().lower() not in {
        "0", "false", "no", "off"}


def sca_client_for(*, paid: bool, opt_out: bool = False,
                   requested: bool | None = None) -> "OsvClient | None":
    """Who gets their dependency list sent to a third party.

    One place, because three separate decisions all end in the same outward
    call: whether this audit is one the customer paid for (variant A runs the
    check only there), whether the deployment has forbidden it outright, and
    whether this caller has declined the lookup. `opt_out` is a caller-level
    hook, not a persisted account preference. `requested` is the caller's
    OWN opt-in -- None means "whatever the deployment policy says", which is
    the audit service, while an explicit True/False is a local decision (the
    CLI, where the operator is looking at someone else's repository and the
    default must be to send nothing).
    """
    if requested is False:
        return None
    if not paid or opt_out:
        return None
    if requested is None and not sca_enabled():
        return None
    return OsvClient()


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
    """Fixed version boundaries from this package's advisory ranges.

    These are source facts, not upgrade candidates: separate release lines,
    reintroductions and ecosystem-specific ordering are not resolved here.
    GIT range events contain commit IDs, not package versions.
    """
    fixed: list[str] = []
    affected_entries = record.get("affected")
    if not isinstance(affected_entries, list):
        return fixed
    for affected in affected_entries:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package")
        if not isinstance(package, dict):
            continue
        name = str(package.get("name", ""))
        ecosystem = str(package.get("ecosystem", ""))
        if (name.lower(), ecosystem) != (dependency.name.lower(), dependency.ecosystem):
            continue
        ranges = affected.get("ranges")
        if not isinstance(ranges, list):
            continue
        for span in ranges:
            if not isinstance(span, dict):
                continue
            if span.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            events = span.get("events")
            if not isinstance(events, list):
                continue
            for event in events:
                if (isinstance(event, dict) and isinstance(event.get("fixed"), str)
                        and event["fixed"].strip()):
                    fixed.append(event["fixed"])
    seen: dict[str, None] = {}
    for version in fixed:
        seen.setdefault(version, None)
    return list(seen)


def _advisory_url(record: dict) -> str:
    for reference in record.get("references", []) or []:
        if not isinstance(reference, dict):
            continue
        url = reference.get("url")
        if isinstance(url, str) and url.startswith("http"):
            return url
    return f"https://osv.dev/vulnerability/{record.get('id', '')}"


@dataclass
class Advisory:
    """One vulnerability, after the database entries that describe it are
    merged.

    Two entries frequently carry the same CVE alias -- measured against the
    live API: lodash 4.17.21 matched two records that both resolve to
    CVE-2025-13465 with different fixed versions (4.17.21 and 4.18.0). One
    vulnerability is one entry here. Its fixed version boundaries are combined
    as source facts; that does not establish a common safe upgrade target.
    """
    identifier: str
    severity: str
    declared: bool
    summary: str
    published: str
    url: str
    fixed: list[str] = field(default_factory=list)
    # True when the batch named this advisory but its record could not be
    # fetched. The match itself is confirmed -- the database listed this exact
    # version -- and only the detail is missing, so the finding stays and says
    # which part is unverified instead of disappearing.
    details_missing: bool = False

    def absorb(self, other: "Advisory") -> None:
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


def _advisories(dependency: Dependency, records: list[dict],
                missing: tuple[str, ...] = ()) -> list[Advisory]:
    """Every vulnerability of one dependency, worst first.

    `missing` names advisories the batch reported and whose records could not
    be fetched. They are kept at the floor severity, flagged as unreadable, so
    the row exists and says what is unknown instead of vanishing.
    """
    merged: dict[str, Advisory] = {}
    for record in records:
        severity, declared = _severity(record)
        advisory = Advisory(
            identifier=_identifier(record),
            severity=severity,
            declared=declared,
            summary=str(record.get("summary") or "").strip(),
            published=str(record.get("published") or "")[:10],
            url=_advisory_url(record),
            fixed=_fixed_versions(record, dependency),
        )
        if advisory.identifier in merged:
            merged[advisory.identifier].absorb(advisory)
        else:
            merged[advisory.identifier] = advisory
    for advisory_id in missing:
        merged.setdefault(advisory_id, Advisory(
            identifier=advisory_id,
            severity=MIN_SEVERITY,
            declared=False,
            summary="",
            published="",
            url=f"https://osv.dev/vulnerability/{advisory_id}",
            details_missing=True,
        ))
    return sorted(merged.values(), key=lambda a: (-_rank(a.severity), a.identifier))


def _scope_sentence(dependency: Dependency) -> str:
    """Where this package came from, in the three distinct cases.

    "Not a production dependency" and "the lockfile does not say" lead to
    different actions, so they are not collapsed into one sentence.
    """
    if dependency.development is True:
        return ("The lockfile marks this as a development dependency; its use "
                "in builds or the deployed application was not checked")
    if dependency.direct:
        return "Your project lists this dependency directly"
    return "This dependency arrives through another one"


def build_finding(dependency: Dependency, advisories: list[Advisory]) -> CheckFinding:
    worst = advisories[0]
    others = advisories[1:]
    # Fixed events belong to individual affected ranges, not to a global
    # version ordering. Preserve their attribution without choosing a target
    # or claiming that every later release is unaffected.
    fix_facts = []
    for advisory in advisories[:MAX_LISTED_ADVISORIES]:
        if advisory.details_missing:
            fact = "details unavailable; fixed versions unknown"
        elif advisory.fixed:
            fact = "fixed versions recorded by the database: " + ", ".join(advisory.fixed[:4])
            if len(advisory.fixed) > 4:
                fact += f" (and {len(advisory.fixed) - 4} more fixed versions)"
        else:
            fact = "no fixed version recorded in the available package ranges"
        fix_facts.append(f"{advisory.identifier}: {fact}.")
    if len(advisories) > MAX_LISTED_ADVISORIES:
        fix_facts.append(f"Fix details for {len(advisories) - MAX_LISTED_ADVISORIES} "
                         "additional advisories are not shown here.")

    listed = [f"{worst.identifier} ({worst.severity}): {worst.summary or 'known vulnerability'}"]
    for advisory in others[:MAX_LISTED_ADVISORIES - 1]:
        listed.append(f"{advisory.identifier} ({advisory.severity}): "
                      f"{advisory.summary or 'known vulnerability'}")
    hidden = len(others) - (len(listed) - 1)
    if hidden > 0:
        listed.append(f"and {hidden} more")

    how = (f"The lockfile {dependency.manifest} resolves {dependency.name} to "
           f"{dependency.version}, and the vulnerability database lists that "
           f"exact version as affected by {len(advisories)} "
           f"{'advisory' if len(advisories) == 1 else 'advisories'}.")
    risk = (f"{_scope_sentence(dependency)}. " + "; ".join(listed) +
            ". A dependency with a known vulnerability is software someone has "
            "already been told how to break; whether the broken part is "
            "reachable from your code was NOT checked here, so treat this as a "
            "reason to look, not a proven exploit.")
    if worst.published:
        risk += f" Worst published {worst.published}."
    if any(advisory.details_missing for advisory in advisories):
        # The batch named these advisories; the records that would say what they
        # are and what fixes them could not be fetched. Say exactly that -- an
        # unfetched detail is not a reason to drop a confirmed match, and it is
        # not a reason to invent a severity either.
        risk += (" At least one advisory's details could not be fetched from the "
                 "database, so its nature and its worst rating are unknown; the "
                 "match against your version is what was confirmed.")
    fix = (" ".join(fix_facts) + " Review every advisory's affected ranges and "
           "choose a release compatible with your project; a common safe upgrade "
           "target was not verified. Update the lockfile, reinstall, and rerun "
           f"the dependency scan and your tests. Reference: {worst.url}")

    if len(advisories) == 1:
        title = f"{worst.identifier} in {dependency.name} {dependency.version}"
    else:
        title = (f"{len(advisories)} known vulnerabilities in "
                 f"{dependency.name} {dependency.version}")

    return CheckFinding(
        rule_id=RULE_ID,
        title=title,
        severity=worst.severity,
        # 0.9 when the worst advisory states its rating, 0.6 when the rating
        # had to be assumed, 0.4 when the record itself was unreadable: the
        # match is certain, everything about it is not.
        confidence=(0.4 if worst.details_missing else 0.9 if worst.declared else 0.6),
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

    `asked_at` is recorded whenever the database actually answered, because
    this stage's answer is only true of the day it was asked. A report that
    does not say when will read as current forever.
    """
    stats: dict = {
        "checks_run": [CHECKS_RUN_KEY],
        "lockfiles": [],
        "dependencies_found": 0,
        "dependencies": 0,
        "advisories": 0,
        "reported_advisories": 0,
        "packages_reported": 0,
        "below_severity_floor": 0,
        "unreadable_advisories": 0,
        "incomplete_lockfiles": {},
        "coverage_incomplete": False,
        "requests": 0,
        "findings": 0,
        "truncated": 0,
        "asked_at": None,
        "skipped_reason": None,
    }
    try:
        inventory = collect_dependency_inventory(data)
    except Exception as exc:            # noqa: BLE001 -- see below
        # A lockfile is INPUT, and no input may abort the audit it was
        # submitted to: this stage promises the audit it belongs to that it
        # never raises, and that promise has to cover the parsing too. The
        # reason is recorded, so the result says the dependencies were not
        # examined rather than that they were fine.
        stats["skipped_reason"] = f"lockfile_unreadable: {type(exc).__name__}"
        return [], stats
    dependencies, found = inventory.dependencies, inventory.found
    stats["lockfiles"] = inventory.manifests
    stats["incomplete_lockfiles"] = inventory.incomplete_manifests
    stats["coverage_incomplete"] = bool(inventory.incomplete_manifests) or found > len(dependencies)
    # `found` and `dependencies` differ only when the cap bit. Both are
    # recorded: a repository whose 300th dependency was silently never asked
    # about must not read as a repository that was fully checked.
    stats["dependencies_found"] = found
    stats["dependencies"] = len(dependencies)
    if not dependencies:
        unusable = unusable_lockfiles(data)
        stats["unusable_lockfiles"] = unusable
        # Neither case is "no vulnerabilities": one is nothing to look up, the
        # other is a lockfile that cannot answer the question at all (go.sum
        # lists every version the build ever verified, not the build's list).
        stats["skipped_reason"] = (
            "no_resolvable_lockfile" if unusable or inventory.incomplete_manifests
            else "no_resolved_dependencies" if inventory.manifests else "no_lockfile")
        return [], stats
    if client is None:
        stats["skipped_reason"] = "no_client"
        return [], stats

    hits, records, unreadable, skip_reason = query_dependencies(dependencies, client)
    if skip_reason is not None:
        stats["skipped_reason"] = skip_reason
        stats["requests"] = client.requests_made
        return [], stats
    if not records and unreadable:
        # The batch answered, the detail lookups did not. Reporting nothing here
        # would turn a database failure into a clean dependency report, and the
        # score would IMPROVE for it -- the one direction a failure must never
        # move. So nothing is claimed at all.
        stats["skipped_reason"] = "osv_unavailable: advisory details"
        stats["requests"] = client.requests_made
        stats["unreadable_advisories"] = len(unreadable)
        return [], stats

    stats["asked_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    stats["requests"] = client.requests_made
    findings = findings_for(dependencies, hits, records, stats)
    stats["coverage_incomplete"] = bool(stats["coverage_incomplete"] or unreadable)
    return findings, stats


def query_dependencies(
    dependencies: list[Dependency], client: OsvClient
) -> tuple[dict[int, list[str]], dict[str, dict], set[str], str | None]:
    """Ask the database about a resolved list.

    Returns (hits, records, unreadable advisory ids, skip_reason). The two
    failure modes are kept apart on purpose: a batch that never answered is a
    reason to skip the stage, while a batch that answered and a detail lookup
    that did not is a PARTIAL answer the caller has to describe honestly --
    measured by reproducing an HTTP 503 on one detail fetch, which used to
    delete a confirmed vulnerability from the report and raise the score.

    Split out from run_sca_stage because a REFRESH has the dependency list and
    not the archive: the versions are stored with the audit (migration 0039),
    so re-asking is a query about a list, never a re-read of bytes this
    deployment does not keep. Never raises, for the same reason the stage never
    does -- an unreachable database is a reason, not a failed audit.
    """
    try:
        hits = client.query(dependencies)
        wanted: dict[str, None] = {}
        for indexes in hits.values():
            for advisory in indexes:
                wanted.setdefault(advisory, None)
        records = client.details(list(wanted))
    except OsvUnavailable as exc:
        return {}, {}, set(), f"osv_unavailable: {exc}"
    return hits, records, set(wanted) - set(records), None


def findings_for(
    dependencies: list[Dependency], hits: dict[int, list[str]],
    records: dict[str, dict], stats: dict,
) -> list[CheckFinding]:
    """Turn answers into rows, counting what was seen and what was filtered.

    An advisory the batch named but whose record could not be fetched is NOT
    dropped: the match is confirmed, so it becomes a row that says its details
    are missing rather than a row that does not exist.
    """
    answers = {advisory for indexes in hits.values() for advisory in indexes}
    stats["advisories"] = len(answers)
    stats["unreadable_advisories"] = len(answers - set(records))

    findings: list[CheckFinding] = []
    unreadable = answers - set(records)
    for index, advisory_ids in hits.items():
        dependency = dependencies[index]
        served = [records[a] for a in advisory_ids if a in records]
        missing = tuple(a for a in advisory_ids if a in unreadable)
        advisories = _advisories(dependency, served, missing)
        if not advisories:
            continue
        if _rank(advisories[0].severity) < _rank(MIN_SEVERITY):
            stats["below_severity_floor"] += 1
            continue
        stats["reported_advisories"] += len(advisories)
        findings.append(build_finding(dependency, advisories))

    findings.sort(key=lambda f: (-_rank(f.severity), f.file, f.line, f.title))
    stats["truncated"] = max(0, len(findings) - MAX_FINDINGS)
    findings = findings[:MAX_FINDINGS]
    stats["packages_reported"] = len(findings)
    stats["findings"] = len(findings)
    return findings
