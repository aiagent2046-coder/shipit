"""CVE source state and coverage, separate from package-version evidence."""
from app.scan.cve_evidence import normalize_cve_summary


def cve_rows(value: object) -> list[tuple[str, str]]:
    cve = normalize_cve_summary(value)
    if not cve:
        return [("CVE Program", "Not recorded or unreadable for this audit")]
    descriptions = {
        "disabled": "Official CVE lookup disabled; no CVE request made.",
        "not_run": "Official CVE lookup not run; no CVE request made.",
        "not_applicable": ("No CVE IDs in the available OSV answer; no CVE request made. "
                           "This is not a search of the full CVE catalogue."),
    }
    detail = descriptions.get(cve["status"])
    if detail is None:
        detail = (f"{cve['status']}: {cve['resolved']} of {cve['requested']} CVE records fetched; "
                  f"{cve['unavailable']} unavailable; {cve['not_requested']} not requested; "
                  f"{cve['rejected']} rejected. Checked: {cve['checked_at'] or 'No request made'}. "
                  "OSV supplies package-version matches. "
                  "CVE record state does not establish application exploitability.")
    rows = [("CVE Program", detail)]
    for record in cve["records"]:
        rows.append((record["id"],
                     f"{record['state']}; CNA: {record['provider'] or 'Not recorded'}; "
                     f"CWE: {', '.join(record['cwes']) or 'Not recorded'}; "
                     f"published: {record['published_at'] or 'Not recorded'}; "
                     f"updated: {record['updated_at'] or 'Not recorded'}. {record['url']}"))
    return rows


def cve_notices(value: object) -> list[tuple[str, str]]:
    cve = normalize_cve_summary(value)
    if not cve:
        return [] if value is None else [("CVE record evidence unreadable",
                                         "CVE lookup coverage could not be validated. "
                                         "This is not a complete CVE result.")]
    notices = []
    if cve["status"] in {"partial", "unavailable"}:
        notices.append(("CVE record lookup incomplete",
                        f"{cve['resolved']} of {cve['requested']} CVE records fetched. "
                        "Missing CVE records do not invalidate OSV matches "
                        "or establish the absence of vulnerabilities."))
    if cve["rejected"]:
        notices.append(("CVE source disagreement",
                        f"{cve['rejected']} CVE records referenced by OSV are REJECTED by the CVE Program. "
                        "OSV findings and ratings are retained; review the official records before acting."))
    return notices
