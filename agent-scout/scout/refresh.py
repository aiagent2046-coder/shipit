"""Re-scan registry targets; mark 'fixed' when the recorded advisories are gone.

The honest signal for "fixed" is not "looks cleaner" but "none of the
advisories we reported match the currently public artifacts anymore". The
draft event stores the advisory ids it reported, so refresh can compare
like with like. Outcomes per entry:

  fixed        - none of the recorded advisories match the re-fetched set
  open         - at least one recorded advisory still matches
  unverifiable - no artifacts re-fetched; absence of evidence is NOT
                 evidence of safety, so nothing is marked
  skipped      - entry predates the advisory list; mark fixed manually

Re-fetching replays the recorded source recipe (repo:owner/name and/or
url:https://...) exactly like the original scan; entries recorded before
the recipe existed fall back to their target string.
"""
from __future__ import annotations

from scout import engine as engine_mod
from scout import recon


def advisory_ids(result) -> set[str]:
    """Advisory identifiers behind the findings (title as last resort)."""
    out = set()
    for finding in result.findings:
        claim = finding.get("claim_evidence") or {}
        out.add(claim.get("advisory_id") or finding.get("title", ""))
    return out - {""}


def sources_for_target(target: str) -> list[str]:
    """Fallback recipe for entries recorded before sources were stored."""
    if target.startswith("github.com/"):
        return ["repo:" + target[len("github.com/") :]]
    if target.startswith(("http://", "https://")):
        return ["url:" + target]
    return []


def refetch(sources: list[str]) -> dict[str, bytes]:
    """Re-fetch the recorded artifact set the way the original scan did."""
    files: dict[str, bytes] = {}
    for source in sources:
        if source.startswith("repo:"):
            owner, _, repo = source[len("repo:"):].partition("/")
            files.update(recon.manifest_archive(recon.github_manifests(owner, repo)))
        elif source.startswith("url:"):
            files.update(recon.manifest_archive(
                recon.manifests_from_site(source[len("url:"):])))
    return files


def current_advisories(files: dict[str, bytes], target: str = "") -> set[str]:
    """Advisories matching the given artifacts right now."""
    return advisory_ids(engine_mod.Engine().scan_files(files, target=target))


def discover_contact(row: dict) -> str | None:
    """Contact published in security.txt now, for drafts recorded without one.

    Probes the URL surfaces of the record (its url: sources, or a url-shaped
    target). None = still not published or no URL surface known - a repo-only
    record has no contact surface to probe."""
    urls = [s[len("url:"):] for s in (row.get("sources") or [])
            if isinstance(s, str) and s.startswith("url:")]
    target = row.get("target") or ""
    if not urls and target.startswith(("http://", "https://")):
        urls.append(target)
    for url in urls:
        try:
            _, contact = recon.fetch_security_txt(url)
        except recon.ReconError:
            continue
        if contact:
            return contact
    return None


def verify(row: dict, files: dict[str, bytes]) -> tuple[str, str]:
    """(verdict, note) for one registry entry against re-fetched artifacts."""
    recorded = set(row.get("advisories") or [])
    if not recorded:
        return "skipped", "entry predates the advisory list - mark fixed manually"
    if not files:
        return ("unverifiable",
                "no artifacts re-fetched - absence of evidence is not evidence of safety")
    still = recorded & current_advisories(files, row.get("target", ""))
    if not still:
        return "fixed", f"none of {len(recorded)} recorded advisories match anymore"
    return "open", f"still matching {len(still)} of {len(recorded)} recorded advisories"


def assess(row: dict, files: dict[str, bytes], re_record: bool = False
           ) -> tuple[str, str, list[str] | None]:
    """(verdict, note, baseline) - what to report and what to write.

    baseline is non-None only for the re-record path: the current advisory
    ids to store as the comparison anchor of a draft recorded without one.
    """
    if re_record and not row.get("advisories"):
        if not files:
            return ("unverifiable",
                    "no artifacts re-fetched - absence of evidence is not evidence of safety",
                    None)
        ids = sorted(current_advisories(files, row.get("target", "")))
        if ids:
            return ("re-recorded",
                    f"advisory baseline set from current scan ({len(ids)} advisories)",
                    ids)
        return ("skipped",
                ("current scan is clean and the draft has no advisory list - "
                 "mark fixed manually"), None)
    verdict, note = verify(row, files)
    return verdict, note, None
