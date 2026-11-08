"""CLI entry point.

  scout scan --repo owner/name        passive scan of a public repository
  scout scan --url https://site       passive profile + root manifest probe
  scout hunt --query "..." --limit N [--source github|gitlab]
                                      discovery: search -> scan -> rank (passive)
  scout auth add --contract ID --scope HOST [--hours N]
                                      manual switch into active mode (contract)
  scout auth list / auth rm           authorization records

Everything except `auth` runs passive. Active scanning and DB access live in
scout.active and require a current authorization record.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from pathlib import Path

from scout import engine as engine_mod
from scout import guard, recon, refresh
from scout.active import ReadOnlyViolation
from scout.guard import ActiveModeUnauthorised, activate, revoke
from scout.registry import RegistryError

MAX_ARCHIVE_MEMBERS = 10_000
MAX_ARCHIVE_BYTES = 200 * 1024 * 1024


def _out_path(args: argparse.Namespace, name: str) -> Path:
    out = Path(args.out) if args.out else Path(".")
    out.mkdir(parents=True, exist_ok=True)
    return out / name


def _save(args: argparse.Namespace, stem: str, result: engine_mod.ScanResult,
          contact: str | None, files: dict[str, bytes]) -> None:
    from scout.registry import SentRegistry
    from scout.report import render_outreach, render_report
    report_path = _out_path(args, f"{stem}-report.md")
    report_path.write_text(render_report(result))
    print(f"findings: {len(result.findings)} "
          f"(KEV-listed: {len(result.kev_listed)}, critical: {len(result.critical)})")
    print(f"report:   {report_path}")
    reg = SentRegistry()
    fingerprint = engine_mod.artifact_fingerprint(files)
    entry = reg.seen(fingerprint)
    if entry is not None:
        print(f"outreach: not regenerated - already recorded {entry['recorded_at']} "
              f"({entry['target']}, fingerprint {fingerprint[:12]})")
        return
    letter_path = _out_path(args, f"{stem}-outreach.md")
    letter_path.write_text(render_outreach(result, contact))
    sources = []
    if args.repo:
        sources.append(f"repo:{args.repo}")
    if args.url:
        sources.append(f"url:{args.url}")
    reg.record(fingerprint, target=result.target, contact=contact,
               findings=len(result.findings), kev_listed=len(result.kev_listed),
               letter_path=str(letter_path),
               advisories=sorted(refresh.advisory_ids(result)), sources=sources)
    print(f"outreach: {letter_path}")


def cmd_scan(args: argparse.Namespace) -> int:
    """Passive scan. --repo brings public manifests, --url brings the contact
    surface (security.txt, headers); together they produce one assessment."""
    contact = None
    target = args.repo or args.url or ""
    if args.url:
        site = recon.profile_site(args.url)
        contact = site.contact
        print(f"server headers: {json.dumps(site.server_headers)}")
        print(f"security.txt contact: {contact or 'not published'}")
        target = args.url
    files: dict[str, bytes] = {}
    if args.repo:
        owner, _, repo = args.repo.partition("/")
        if not owner or not repo:
            print("error: --repo expects owner/name", file=sys.stderr)
            return 2
        files = recon.manifest_archive(recon.github_manifests(owner, repo))
        target = f"github.com/{owner}/{repo}"
    if args.url:
        files.update(recon.manifest_archive(recon.manifests_from_site(args.url)))
    if not files and args.url:
        from scout.report import render_report
        result = engine_mod.ScanResult(
            findings=[], coverage={"manifests": []},
            limitations=[
                ("No public dependency manifests were found; this profile "
                 "proves nothing about dependency safety."),
            ],
            engine_commit=engine_mod.paths.engine_commit(),
            catalog_digest="",
            target=args.url,
            stack_hints=site.stack_hints,
        )
        stem = re.sub(r"[^\w.-]", "_", args.url.split("//")[-1])
        path = _out_path(args, f"{stem}-report.md")
        path.write_text(render_report(result))
        print(f"no public lockfiles found; profile-only report: {path}")
        return 1
    if not files:
        print("no public lockfiles found at common paths "
              "(absence of evidence is not evidence of safety)", file=sys.stderr)
        return 1
    result = engine_mod.Engine().scan_files(files, target=target)
    if args.url:
        result.stack_hints = site.stack_hints
    stem = re.sub(r"[^\w.-]", "_", target.split("//")[-1])
    _save(args, stem, result, contact, files)
    return 0


def _search_body(res: recon.HttpResult, api: str) -> object | None:
    """Shared search-response gate (status + JSON decode). None = error, reported."""
    if res.status != 200:
        hint = " (rate limited - retry later)" if res.status in (403, 429) else ""
        print(f"search error: {api} search API returned HTTP {res.status}{hint}",
              file=sys.stderr)
        return None
    try:
        return json.loads(res.text)
    except json.JSONDecodeError:
        print(f"search error: {api} search API returned an unexpected body",
              file=sys.stderr)
        return None


def _github_candidates(query: str, limit: int) -> list[dict] | None:
    url = (f"https://api.github.com/search/repositories?q={query}"
           f"&sort=updated&order=desc&per_page={limit}")
    res = recon.http_get(url, timeout=20.0,
                         headers={"Accept": "application/vnd.github+json"})
    data = _search_body(res, "GitHub")
    if data is None:
        return None
    items = data.get("items") if isinstance(data, dict) else None
    if not isinstance(items, list):
        print("search error: GitHub search API returned an unexpected body",
              file=sys.stderr)
        return None
    return [{"full_name": item["full_name"], "html_url": item.get("html_url")}
            for item in items if isinstance(item, dict) and item.get("full_name")]


def _gitlab_candidates(query: str, limit: int) -> list[dict] | None:
    url = (f"https://gitlab.com/api/v4/projects?search={query}"
           f"&simple=true&order_by=last_activity_at&sort=desc&per_page={limit}")
    res = recon.http_get(url, timeout=20.0)
    data = _search_body(res, "GitLab")
    if data is None:
        return None
    if not isinstance(data, list):
        print("search error: GitLab search API returned an unexpected body",
              file=sys.stderr)
        return None
    return [{"full_name": p["path_with_namespace"], "html_url": p.get("web_url")}
            for p in data if isinstance(p, dict) and p.get("path_with_namespace")]


def cmd_hunt(args: argparse.Namespace) -> int:
    """Discovery loop: repository search -> passive scan -> KEV-first ranking.

    Search API failures (rate limit, 5xx, network, unexpected body) exit 1
    with a clear stderr message instead of a traceback.
    """
    query = urllib.parse.quote(args.query)
    if args.source == "gitlab":
        items = _gitlab_candidates(query, args.limit)
    else:
        items = _github_candidates(query, args.limit)
    if items is None:
        return 1
    eng = engine_mod.Engine()
    report_lines = [f"# Hunt report: {args.query}", ""]
    scanned = len(items)
    with_manifests = 0
    listed = 0
    for item in items:
        full = item["full_name"]
        print(f"scanning {full} ...", file=sys.stderr)
        if args.source == "gitlab":
            files = recon.manifest_archive(recon.gitlab_manifests(full))
        else:
            owner, _, repo = full.partition("/")
            files = recon.manifest_archive(recon.github_manifests(owner, repo))
        if not files:
            continue
        with_manifests += 1
        result = eng.scan_files(files, target=full)
        if not result.kev_listed and not result.critical:
            continue
        listed += 1
        report_lines.append(
            f"## {full} — {len(result.kev_listed)} KEV / "
            f"{len(result.critical)} critical ({item.get('html_url')})"
        )
        for finding in result.findings[:5]:
            report_lines.append(f"- {finding.get('title')}")
        report_lines.append("")
    report_lines.insert(2, f"Candidates scanned: {scanned}; with public manifests: "
                           f"{with_manifests}; listed below: {listed} (KEV or critical).")
    if listed == 0:
        report_lines.insert(3, "Nothing met the listing bar - absence of evidence "
                               "is not evidence of safety.")
    path = _out_path(args, "hunt-report.md")
    path.write_text("\n".join(report_lines))
    print(f"hunt report: {path}")
    return 0


def cmd_auth(args: argparse.Namespace) -> int:
    if args.action == "add":
        auth = activate(args.contract, args.scope, hours=args.hours, note=args.note)
        print(f"authorization recorded: {auth.contract_id} "
              f"until {auth.expires_at:.0f} (scope: {', '.join(auth.scope)})")
        return 0
    if args.action == "list":
        for path in sorted(guard.AUTH_DIR.glob("*.json")) if guard.AUTH_DIR.is_dir() else []:
            print(path.read_text())
        return 0
    if args.action == "rm":
        cid = args.contract.strip()
        if revoke(args.contract):
            print(f"removed {cid}")
        return 0
    return 2


def _resolve_fingerprint(reg, ref: str) -> str | None:
    """Registry lookup by fingerprint (prefix ok) or exact target. None = no unique match."""
    entries = reg.entries()
    for row in entries:
        if row["fingerprint"] == ref or row["target"] == ref:
            return row["fingerprint"]
    matches = [row["fingerprint"] for row in entries if row["fingerprint"].startswith(ref)]
    return matches[0] if len(matches) == 1 else None


def cmd_registry(args: argparse.Namespace) -> int:
    """Sent-registry: status lifecycle (drafted -> sent -> read -> fixed)."""
    from scout.registry import SentRegistry
    reg = SentRegistry()
    if args.action == "list":
        rows = reg.entries()
        if not rows:
            print("registry is empty")
            return 0
        for row in sorted(rows, key=lambda r: r["recorded_at"] or ""):
            print(f"{row['fingerprint'][:12]}  {row['status']:<7}  {row['target']}  "
                  f"findings={row['findings']} kev={row['kev_listed']}  "
                  f"updated={row['updated_at']}")
        return 0
    if args.action == "mark":
        if not args.target or not args.status:
            print("usage: scout registry mark <target|fingerprint> <sent|read|fixed>",
                  file=sys.stderr)
            return 2
        fingerprint = _resolve_fingerprint(reg, args.target)
        if fingerprint is None:
            print(f"error: no unique registry entry for {args.target!r} "
                  "(use `scout registry list`)", file=sys.stderr)
            return 2
        try:
            entry = reg.mark(fingerprint, args.status, note=args.note or None)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 3
        print(f"marked {fingerprint[:12]} -> {entry['status']}")
        return 0
    if args.action == "refresh":
        counts = {"fixed": 0, "open": 0, "unverifiable": 0, "skipped": 0,
                  "re-recorded": 0}
        contacts = 0
        for row in reg.entries():
            if row["status"] == "fixed":
                continue
            sources = row.get("sources") or refresh.sources_for_target(row["target"])
            verdict, note, baseline = refresh.assess(row, refresh.refetch(sources),
                                                     re_record=args.re_record)
            counts[verdict] += 1
            print(f"{row['fingerprint'][:12]}  {row['target']}: {verdict} - {note}")
            if baseline is not None:
                reg.re_record(row["fingerprint"], advisories=baseline, sources=sources,
                              note=note)
            elif verdict == "fixed":
                reg.mark(row["fingerprint"], "fixed", note=note)
            if not row.get("contact"):
                contact = refresh.discover_contact(row)
                if contact:
                    reg.re_record(row["fingerprint"], contact=contact,
                                  note="contact backfilled from security.txt")
                    contacts += 1
                    print(f"{row['fingerprint'][:12]}  {row['target']}: "
                          f"contact backfilled -> {contact}")
        print(f"refresh: {counts['fixed']} fixed, {counts['open']} open, "
              f"{counts['unverifiable']} unverifiable, {counts['skipped']} skipped, "
              f"{counts['re-recorded']} re-recorded, {contacts} contacts backfilled")
        return 0
    return 2


def cmd_outreach(args: argparse.Namespace) -> int:
    """Deliver drafted letters within quota. Explicit command - scanning never sends."""
    from scout import delivery
    from scout.registry import SentRegistry
    reg = SentRegistry()
    if args.action != "send":
        return 2
    rows = delivery.plan(reg, limit=args.limit or None)
    if not rows:
        print("nothing to deliver: queue is empty or quotas are reached")
        return 0
    if args.dry_run:
        for row in rows:
            print(f"would send -> {row['deliver_to']} ({row['target']}): "
                  f"{row['letter_path']}")
        print(f"dry run: {len(rows)} letter(s) within quota, nothing sent")
        return 0
    sender = delivery.smtp_sender_from_env()
    if sender is None:
        print("error: SMTP is not configured (SCOUT_SMTP_HOST, SCOUT_SMTP_PORT, "
              "SCOUT_SMTP_USER, SCOUT_SMTP_PASSWORD, SCOUT_SMTP_FROM) - "
              "nothing sent", file=sys.stderr)
        return 1
    delivered = failed = 0
    for row in rows:
        to = row["deliver_to"]
        body = Path(row["letter_path"]).read_text()
        _, subject = delivery.mail_fields(body)
        try:
            sender.send(to=to, subject=subject, body=body)
        except delivery.DeliveryError as exc:
            print(f"delivery failed: {exc} (left drafted)", file=sys.stderr)
            failed += 1
            continue
        reg.mark(row["fingerprint"], "sent", note=f"delivered to {to}")
        delivered += 1
        print(f"sent -> {to} ({row['target']})")
    print(f"delivered {delivered}/{len(rows)} letter(s)")
    return 1 if failed else 0


def cmd_db(args: argparse.Namespace) -> int:
    """Authorized DB access: scope-checked, read-only, audit-logged."""
    import os

    from scout import db as db_mod
    from scout.active import AUDIT_LOG_DIR, ActiveScanSession, ReadOnlyQueryRunner
    session = ActiveScanSession.open(args.contract)  # the gate
    session.check_scope(args.target)                 # scope before ANY connection
    dsn = os.environ.get(db_mod.DSN_ENV, "")
    if not dsn:
        print(f"error: set {db_mod.DSN_ENV} in the environment "
              "(a DSN is a credential - never a CLI argument)", file=sys.stderr)
        return 2
    connect = db_mod.postgres_connect(dsn)
    runner = ReadOnlyQueryRunner(
        auth=session.auth, connect=connect,
        statement_timeout_ms=args.timeout_ms,
        audit_path=AUDIT_LOG_DIR / f"{session.auth.contract_id}.jsonl")
    rows = runner.query(args.sql)
    for row in rows[:50]:
        print(row)
    if len(rows) > 50:
        print(f"... {len(rows) - 50} more rows (audited: "
              f"{runner.audit_log[-1].statement_sha256[:12]})")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """Active deep audit behind a contract: full drydock run, static + LLM."""
    from scout import audit
    from scout.guard import require_active
    require_active(args.contract)  # the gate, before any fetch or work
    if not args.repo and not args.url and not args.archive:
        print("error: audit needs --repo owner/name, --url https://... "
              "or --archive repo.zip", file=sys.stderr)
        return 2
    files: dict[str, bytes] = {}
    target = args.url or args.repo or ""
    if args.archive:
        import zipfile
        try:
            with zipfile.ZipFile(args.archive) as zf:
                infos = zf.infolist()
                total = sum(info.file_size for info in infos)
                if len(infos) > MAX_ARCHIVE_MEMBERS or total > MAX_ARCHIVE_BYTES:
                    print(f"error: archive exceeds the audit bound "
                          f"({len(infos)} members / {total} bytes; max "
                          f"{MAX_ARCHIVE_MEMBERS} / {MAX_ARCHIVE_BYTES})",
                          file=sys.stderr)
                    return 1
                read_bytes = 0
                for name in zf.namelist():
                    if name.endswith("/"):
                        continue
                    data = zf.read(name)
                    read_bytes += len(data)
                    if read_bytes > MAX_ARCHIVE_BYTES:
                        print(f"error: archive exceeds the audit bound "
                              f"({read_bytes} unpacked bytes; max "
                              f"{MAX_ARCHIVE_BYTES})",
                              file=sys.stderr)
                        return 1
                    files[name] = data
        except (OSError, zipfile.BadZipFile) as exc:
            print(f"error: unreadable archive {args.archive!r}: {exc}",
                  file=sys.stderr)
            return 1
        target = Path(args.archive).stem
    if args.repo:
        owner, _, repo = args.repo.partition("/")
        if not owner or not repo:
            print("error: --repo expects owner/name", file=sys.stderr)
            return 2
        files.update(recon.manifest_archive(recon.github_manifests(owner, repo)))
        target = f"github.com/{owner}/{repo}"
    if args.url:
        files.update(recon.manifest_archive(recon.manifests_from_site(args.url)))
    if not files:
        print("error: no public artifacts found to audit "
              "(absence of evidence is not evidence of safety)", file=sys.stderr)
        return 1
    from decimal import Decimal
    cap = Decimal(args.llm_cost_cap) if args.llm_cost_cap else None
    report = audit.run_audit(args.contract, files, target=target, osv=args.osv,
                             llm_cost_cap=cap)
    result = report["result"]
    llm = result.get("llm")
    if isinstance(llm, dict):
        if llm.get("failure"):
            llm_status = f"partial - {llm['failure']}"
        elif llm.get("skipped_reason"):
            llm_status = f"skipped ({llm['skipped_reason']})"
        else:
            llm_status = "ran"
    else:
        llm_status = str(llm)
    stem = re.sub(r"[^\w.-]", "_", target.split("//")[-1])
    path = _out_path(args, f"{stem}-audit.json")
    path.write_text(json.dumps(report, indent=1, default=str))
    from scout.report import render_deep_report
    evidence = None
    if args.db_evidence:
        try:
            evidence = json.loads(Path(args.db_evidence).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: unreadable --db-evidence {args.db_evidence!r}: {exc}",
                  file=sys.stderr)
            return 1
        if not isinstance(evidence, list):
            print(f"error: --db-evidence {args.db_evidence!r} must be a JSON list",
                  file=sys.stderr)
            return 1
    deep_path = _out_path(args, f"{stem}-deep-report.md")
    deep_path.write_text(render_deep_report(report, evidence))
    print(f"audit:    contract {report['contract_id']} engine {report['engine_commit']}")
    print(f"llm:      {llm_status}")
    print(f"findings: {len(result.get('findings') or [])} "
          f"(score {(result.get('score') or {}).get('total')})")
    print(f"result:   {path}")
    print(f"deep:     {deep_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scout")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="passive scan")
    p_scan.add_argument("--repo", help="github owner/name")
    p_scan.add_argument("--url", help="site base url")
    p_scan.add_argument("--out", help="output directory")

    p_hunt = sub.add_parser("hunt", help="passive discovery loop")
    p_hunt.add_argument("--query", required=True, help="repository search query")
    p_hunt.add_argument("--limit", type=int, default=10)
    p_hunt.add_argument("--source", choices=["github", "gitlab"], default="github",
                        help="candidate source (default: github)")
    p_hunt.add_argument("--out", help="output directory")

    p_auth = sub.add_parser("auth", help="authorization records (active mode)")
    p_auth.add_argument("action", choices=["add", "list", "rm"])
    p_auth.add_argument("--contract", default="")
    p_auth.add_argument("--scope", action="append", default=[])
    p_auth.add_argument("--hours", type=float, default=24)
    p_auth.add_argument("--note", default="")

    p_reg = sub.add_parser("registry", help="sent-registry: status lifecycle")
    p_reg.add_argument("action", choices=["list", "mark", "refresh"])
    p_reg.add_argument("target", nargs="?", default="",
                       help="for mark: fingerprint (prefix ok) or target")
    p_reg.add_argument("status", nargs="?", choices=["sent", "read", "fixed"],
                       help="for mark: new status (forward only)")
    p_reg.add_argument("--note", default="", help="operator note for the event")
    p_reg.add_argument("--re-record", action="store_true",
                       help="for refresh: backfill the advisory baseline of "
                            "drafts recorded without one")

    p_out = sub.add_parser("outreach", help="letter delivery with quotas")
    p_out.add_argument("action", choices=["send"])
    p_out.add_argument("--limit", type=int, default=0,
                       help="max letters this run (default: quota remainder)")
    p_out.add_argument("--dry-run", action="store_true",
                       help="show the plan, send nothing")

    p_audit = sub.add_parser("audit", help="active deep audit (contract)")
    p_audit.add_argument("--contract", required=True)
    p_audit.add_argument("--repo", help="github owner/name")
    p_audit.add_argument("--url", help="site base url")
    p_audit.add_argument("--archive",
                         help="zip of the contract's source tree "
                              "(customer-supplied under contract)")
    p_audit.add_argument("--osv", action="store_true",
                         help="opt in: send the dependency inventory to OSV")
    p_audit.add_argument("--llm-cost-cap", default="",
                         help="USD cap for the LLM stage (default: unlimited)")
    p_audit.add_argument("--db-evidence", default="",
                         help="JSON file with operator DB observations "
                              "[{label, observation}] for the deep report")
    p_audit.add_argument("--out", help="output directory")

    p_db = sub.add_parser("db", help="authorized DB access (contract)")
    p_db.add_argument("action", choices=["query"])
    p_db.add_argument("--contract", required=True)
    p_db.add_argument("--target", required=True,
                      help="DB host, must be in the contract scope")
    p_db.add_argument("--timeout-ms", type=int, default=15_000)
    p_db.add_argument("sql", help="a single read-only statement")

    args = parser.parse_args(argv)
    try:
        if args.cmd == "scan":
            return cmd_scan(args)
        if args.cmd == "hunt":
            return cmd_hunt(args)
        if args.cmd == "auth":
            return cmd_auth(args)
        if args.cmd == "registry":
            return cmd_registry(args)
        if args.cmd == "outreach":
            return cmd_outreach(args)
        if args.cmd == "audit":
            return cmd_audit(args)
        if args.cmd == "db":
            return cmd_db(args)
    except ActiveModeUnauthorised as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 3
    except ReadOnlyViolation as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 3
    except RegistryError as exc:
        print(f"registry error: {exc}", file=sys.stderr)
        return 1
    except recon.ReconError as exc:
        print(f"recon error: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
