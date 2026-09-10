"""Static scan stage: run all deterministic scanners, normalize, score."""

from __future__ import annotations

from dataclasses import replace
from typing import BinaryIO

from app.ingest.validators import validate_zip
from app.scan.auth_read import scan_auth_read
from app.scan.claim_evidence import static_claim_evidence
from app.scan.checks import run_checks
from app.scan.ci_deploy_source import scan_ci_deploy_source
from app.scan.error_boundary import scan_error_boundary
from app.scan.http_success import http_success_findings as scan_http_success
from app.scan.outbound_url import scan_outbound_url
from app.scan.rls import scan_rls
from app.scan.recommendations import prepare_recommendation
from app.scan.schema_drift import scan_schema_drift
from app.scan.scoring import ScoredFinding, compute_scores
from app.scan.secrets import scan_secrets
from app.scan.service_role import scan_service_role
from app.scan.sql_injection import scan_sql_injection
from app.scan.sql_injection_js import scan_sql_injection_js
from app.scan.source_facts import collect_source_facts


def run_static_scan(fileobj: BinaryIO) -> dict:
    """Returns {"score": {...}, "findings": [ScoredFinding-as-dict]}.

    The score here describes THIS stage only. app/scan/pipeline.py reads just
    the findings and recomputes the total once it knows whether the LLM stage
    ran, so an audit's real headline never comes from this key -- but callers
    that use it directly (the tests, and anything added later) must not be
    handed a number computed on a premise this function contradicts.
    """
    # Direct callers must meet the same input contract as uploads and jobs.
    # Otherwise repeated ZIP entries can create repeated score penalties.
    size = fileobj.seek(0, 2)
    validate_zip(fileobj, size_bytes=size)
    findings: list[ScoredFinding] = []

    fileobj.seek(0)
    file_coverage: dict = {}
    for s in scan_secrets(fileobj, coverage=file_coverage):
        findings.append(ScoredFinding(
            rule_id=s.rule_id, title=s.title, severity=s.severity,
            confidence=s.confidence, category="Security",
            file=s.file, line=s.line, masked=s.masked, context=s.context,
            claim_evidence={**static_claim_evidence(), "source_context": s.source_context},
        ))

    fileobj.seek(0)
    for r in scan_rls(fileobj):
        findings.append(ScoredFinding(
            rule_id=r.rule_id, title=r.title, severity=r.severity,
            confidence=r.confidence, category=r.category, file=r.file,
            explanation=r.explanation, fix_hint=r.fix_hint,
        ))

    fileobj.seek(0)
    for d in scan_schema_drift(fileobj):
        findings.append(ScoredFinding(
            rule_id=d.rule_id, title=d.title, severity=d.severity,
            confidence=d.confidence, category=d.category, file=d.file,
            explanation=d.explanation, fix_hint=d.fix_hint,
        ))

    fileobj.seek(0)
    for q in scan_sql_injection(fileobj):
        findings.append(ScoredFinding(
            rule_id=q.rule_id, title=q.title, severity=q.severity,
            confidence=q.confidence, category=q.category, file=q.file,
            line=q.line, explanation=q.explanation, fix_hint=q.fix_hint,
            claim_evidence=static_claim_evidence(),
        ))

    fileobj.seek(0)
    for q in scan_sql_injection_js(fileobj):
        findings.append(ScoredFinding(
            rule_id=q.rule_id, title=q.title, severity=q.severity,
            confidence=q.confidence, category=q.category, file=q.file,
            line=q.line, explanation=q.explanation, fix_hint=q.fix_hint,
            claim_evidence=static_claim_evidence(),
        ))

    fileobj.seek(0)
    for u in scan_outbound_url(fileobj):
        findings.append(ScoredFinding(
            rule_id=u.rule_id, title=u.title, severity=u.severity,
            confidence=u.confidence, category=u.category, file=u.file,
            line=u.line, explanation=u.explanation, fix_hint=u.fix_hint,
            claim_evidence=static_claim_evidence(),
        ))

    fileobj.seek(0)
    for c in run_checks(fileobj):
        findings.append(ScoredFinding(
            rule_id=c.rule_id, title=c.title, severity=c.severity,
            confidence=c.confidence, category=c.category, file=c.file,
            line=c.line, explanation=c.explanation, fix_hint=c.fix_hint, context=c.context,
        ))

    fileobj.seek(0)
    for d in scan_ci_deploy_source(fileobj):
        findings.append(ScoredFinding(
            rule_id=d.rule_id, title=d.title, severity=d.severity,
            confidence=d.confidence, category=d.category, file=d.file,
            line=d.line, explanation=d.explanation, fix_hint=d.fix_hint,
        ))

    fileobj.seek(0)
    for h in scan_service_role(fileobj):
        findings.append(ScoredFinding(
            rule_id=h.rule_id, title=h.title, severity=h.severity,
            confidence=h.confidence, category=h.category, file=h.file,
            line=h.line, explanation=h.explanation, fix_hint=h.fix_hint,
        ))

    fileobj.seek(0)
    for a in scan_auth_read(fileobj):
        findings.append(ScoredFinding(
            rule_id=a.rule_id, title=a.title, severity=a.severity,
            confidence=a.confidence, category=a.category, file=a.file,
            line=a.line, explanation=a.explanation, fix_hint=a.fix_hint,
        ))

    # The first static producer for Frontend. Wired on a number measured in
    # this repository (DRYDOCK_LENS_PLAN.md): 11 of 12 mounted apps in the
    # audited corpus ship no error boundary above their routes, the hits on
    # the most reputable repositories read by hand. The three-strata figure
    # is reproducible with `scripts/measure_error_boundary.py --strata`. This
    # is what took Frontend out of LLM_ONLY_CATEGORIES in scoring.py.
    fileobj.seek(0)
    boundary = scan_error_boundary(fileobj)
    for b in boundary.findings:
        findings.append(ScoredFinding(
            rule_id=b.rule_id, title=b.title, severity=b.severity,
            confidence=b.confidence, category=b.category, file=b.file,
            line=b.line, explanation=b.explanation, fix_hint=b.fix_hint,
        ))

    fileobj.seek(0)
    source_facts = collect_source_facts(fileobj)
    findings.extend(scan_http_success(source_facts))
    findings = [prepare_recommendation(replace(f, source="static", verification_method="source_pattern"), source_facts)
                for f in findings]
    exclusion_labels = {"file_size_limit": "over the 1 MiB file limit", "symlink": "symbolic links",
                        "excluded_directory": "dependency/build directories",
                        "excluded_extension": "excluded file types", "binary_content": "binary content"}
    excluded = ", ".join(f"{count} {exclusion_labels[reason]}"
                         for reason, count in sorted(file_coverage.get("exclusions", {}).items())) or "none"
    scope_description = (
        f"{file_coverage.get('files_scanned', 0)}/{file_coverage.get('files_total', 0)} files scanned; "
        f"excluded: {excluded}; "
        f"files with invalid UTF-8 bytes omitted: {file_coverage.get('lossy_decoded_files', 0)}. "
        "Exclusions are outside this check; no finding does not establish that excluded content is safe."
    )
    return {
        "secrets_coverage": file_coverage,
        "source_facts": source_facts,
        # llm_ran=False, not the default: no LLM stage runs inside this
        # function, so Auth and Money & Data sit at 10.0 for want of a
        # producer. Taking the default let those two vote on this mean --
        # 42% of the weight pinned at "clean" because nothing had looked --
        # which is the exact defect LLM_ONLY_CATEGORIES exists to prevent,
        # reached by leaving an argument out rather than by passing it wrong.
        "score": {
            **compute_scores(findings, llm_ran=False),
            # PERSISTED FOR THE SAME REASON `basis` IS (see pipeline.py): it
            # travels inside score_json so it reaches the DB, and every
            # consumer of the score, rather than being decided during a scan
            # and thrown away.
            #
            # MEASURED COST OF NOT HAVING IT, 2026-09-04: "should a repository
            # with no frontend at all have Frontend excluded rather than
            # counted at 10.0" is a calibration question about the stored rows,
            # and it could not be asked of them -- `mount` was computed for
            # every audit and kept for none, so answering meant re-fetching and
            # re-scanning every repository. score_json already carries
            # `unexamined` and `reported_elsewhere`, which are facts about what
            # was looked at rather than scores; this belongs beside them, and
            # in jsonb it needs no migration.
            "frontend_scan": {"mount": boundary.mount,
                              "coverage": boundary.coverage},
        },
        "findings": [dict(vars(f), source="static",
                          claim_evidence=f.claim_evidence or static_claim_evidence(),
                          verification_method="source_pattern") for f in findings],
        # Carried, not folded into a finding: `budget_exhausted` means the
        # boundary scan stopped before it could say a boundary is absent, so
        # no finding was emitted AND Frontend's clean read is unearned for this
        # repository. A scanner that found nothing and one that gave up must
        # not look identical (#392). Consuming this in the pipeline/report is
        # the follow-up; here it is preserved so it can be.
        "checks_run": ["secrets", "rls", "schema_drift", "project_files",
                       "ci_deploy_source", "service_role", "error_boundary", "auth_read_consistency",
                       "http_success", "sql_injection", "sql_injection_js", "outbound_url"],
        "coverage": {"secrets": scope_description,
                     "error_boundary": boundary.coverage,
                     "auth_read_consistency": "Local FastAPI routes in parseable Python files up to 2 MB; "
                     "test/vendor files excluded; middleware and runtime access not resolved",
                     "outbound_url": "HTTP clients called inside FastAPI route handlers in parseable Python "
                     "files up to 400 KB; the value is traced only within the handler that builds the URL, "
                     "so a URL assembled in a helper, a check in another module, a proxy or a network policy "
                     "is not resolved; TS/JS fetch calls are not covered",
                     "http_success": "Bounded React handlers with direct success effects after an unchecked fetch; "
                     "runtime fetch bindings and HTTP failures are not verified. "
                     "Parser limits: " + (", ".join(source_facts["react_async"].get("limitations", [])) or "none")},
    }
