# Plain file-loading report

The owner view turns existing saved file-loader evidence into a question the
project owner can act on: where does this file come from, and who can change it?
It does not run a scan, call a model, verify an exploit, or apply a repair.

## Scope

The first version supports import-resolved static `pickle.load` observations.
Each card explains the conditional impact, known source facts, remaining
unknowns, next action and what completes that action. The short summary covers
these locations only; unrelated findings remain visible in their existing
sections. It is not a project readiness score or a global priority ranking.

The online HTML report, web audit page and standalone browser report use the
same versioned projection. Python is in `app/report/owner_report.py` and
TypeScript is in `web/src/lib/ownerReport.ts`. The standalone JavaScript copy is
generated with `node scripts/sync_owner_report_browser.mjs` after installing the
locked web dependencies. A shared fixture corpus checks the evidence boundary
in all three implementations.

## Evidence and compatibility

- Validate saved agent records and their receipts before accepting an
  acquisition. Match the rule, file, source SHA-256 and exact call span; require
  exactly one matching observation. Check the outer archive and engine identity
  when recorded.
- A valid detector trace without a valid acquisition can explain the detected
  operation, but must not claim an established path-to-file flow. Reports with
  no supported trace keep the existing presentation.
- Recorded syntax contradictions and nonempty premise/source assessment
  arrays retain their existing specialized presentation. This narrow view does
  not reinterpret those assessments.
- File provenance, trust checks and behavior in the running application remain
  unknown. Source facts do not establish exploitation, safety or a verified fix.
- Show a partial dependency note and an unverified runtime note only when the
  corresponding context is recorded. Missing context is not a successful check.
- Keep findings, severity, scoring, evidence, JSON and SARIF unchanged. Retain
  original guidance in developer details; historical observations keep their
  original presentation.

## Verification

`tests/fixtures/owner-report.json` reuses scanner-produced synthetic reports and
includes legacy, corrupt receipt, mismatched archive/engine, adjacent call,
changed source, duplicate observation and specialized-assessment cases. It
contains no customer project source.

Python tests check the projection, HTML integration and unchanged export data.
Web tests check Python/TypeScript/browser parity, React rendering, original
evidence and keyboard access to a collapsed card. The existing Chromium report
test additionally checks the real browser upload/render/export path, next-action
links, rescan clearing and narrow-screen layout with controlled worker results.

The [project roadmap](owner-roadmap.md) builds on these cards to propose work
with dependencies, suggested owners and completion criteria. Measuring
paid-analysis contributions and running a pilot across 3–5 projects follow it.
