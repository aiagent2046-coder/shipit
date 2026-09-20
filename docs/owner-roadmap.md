# Project roadmap from recorded findings

The roadmap turns current report observations and recorded coverage gaps into
work a project owner can discuss with a developer. It reads saved data without
running another scan, making an LLM call, applying a change, or recording a task
as completed. Existing findings, scores, JSON and SARIF remain unchanged.

## Tasks and ordering

| Recorded input | Proposed work | Group |
| --- | --- | --- |
| File-loader cards supported by the existing owner projection | Identify each file's producer, write access and trust checks | First |
| Partial or unavailable dependency checking | Identify the recorded gaps and obtain the information or checking capability needed | First |
| Recorded library/advisory version matches from the dependency scanner | Group by library, ecosystem and version; distinguish application, development and unknown use; check advisory applicability before choosing an action | First |
| Static HTML insertion observation | Trace who supplies and controls the value and review its handling | First |
| Static credential-like assignment explicitly recorded in a test file | Establish whether the fixture is synthetic; involve the credential owner only if a real credential is confirmed | First |
| Static missing error-boundary observation | Review entry points, framework handling and the expected user recovery path | First |
| Static dependency-directory archive observation | Establish the files' purpose and packaging requirements before deciding what belongs in the archive | First |
| Other current observations, including legacy or specialized assessments | Review the original evidence, limits and context before choosing an action | First |
| File-origin investigation | Decide whether protection needs to change and how to test any proposed change | After clarification |
| Explicitly unverified runtime or a static Dockerfile inventory observation | If preparing a deployment, choose the hosting method and check a basic user journey | If needed |

Tasks in the first group can proceed independently. The file-loading decision
links to its prerequisite. This is an order for gathering information and making
decisions, not a ranking of confirmed production vulnerabilities. Each task has
a reason, action, suggested role, inputs, dependencies, completion criterion,
and links to the underlying current observations or coverage.

One file-origin task retains all relevant locations. Grouping the work does not
assert that those locations share a producer, trust boundary or remedy. Repeated
findings add references without duplicating tasks. Source references use original
finding indices before sorting and visual grouping; navigation opens collapsed
groups and focuses the referenced finding. Historical and included free-audit
sections do not create current tasks or duplicate reference targets.

## Evidence limits

The file task reuses `build_owner_report` / `projectOwnerReport`; receipt and
source-identity validation are unchanged. A malformed acquisition cannot turn
unknown file origin into a trusted source. Unsupported or contradicted claims
retain their original presentation and receive review work, not an instruction
to apply their suggested fix.

`dependency_coverage_gap` / `dependencyCoverageGap` supplies the same scope to
the short owner summary and the roadmap. It reads the current report's recognized
snapshot status (`checked`, `not_applicable`, `partial`, `unavailable`) first.
A completed bundled check is not made incomplete by `sca_skipped_reason: no_client`
from the separate live service. No undocumented `complete` status is treated as a
valid snapshot status. When a recognized status is absent, explicit legacy gap
limitations, typed `sca_coverage_incomplete: true`, or recorded unavailable /
unreadable / unresolved check reasons provide the fallback. Legacy `no_client`
needs a positive integer dependency count within the interoperable JSON safe
integer range; booleans and string counts are not counts. A list of filenames
alone cannot establish why a check is incomplete. Invalid fields do not crash
the projection or certify complete coverage. Historical `free_baseline` facts
never fill current fields.

`dependency_cve.status: partial` does not by itself mean that package versions
are missing. The exact-version action is added only for explicitly unresolved
manifests. Other gaps may involve catalog scope, unsupported comparisons or an
unavailable check and retain a general investigation task. Missing coverage
fields do not imply a successful check. The semantic `dependency_cve` coverage
reference targets the existing dependency coverage section for either saved
format; the projection does not rewrite or upgrade the saved schema.
Other coverage limitations remain in
the report's existing coverage sections; this version does not create specialized
tasks for every scanner limitation.

The five additional review directions require an exact recorded rule and source:
`dependency-cve-match` from `dependency`, or `xss-unsafe-html-injection`,
`generic-assignment`, `missing-error-boundary`, and `dependency-dir-committed`
from `static`. Credential assignments additionally require `context: test_file`.
The other specialized directions require no contextual qualifier. Model findings,
other contexts, malformed or specialized source assessments, and contradicted
claims remain in the generic review task with their original references.
Every eligible observation is retained exactly once in these review groups.

Dependency matches are one work item, with all advisory references retained; the
number of matches is not a count of reachable exploits. A directory in an archive
does not prove Git tracking or justify deletion. A static missing-boundary check
does not prove a blank screen or runtime outage. A credential-like test fixture
does not justify account-level rotation unless it is confirmed to be real.
Each task states the investigation's completion criterion, not that a proposed
change, revocation, deletion, or repair has happened.

`runtime_verified: false` means this report did not verify application behavior.
It does not establish that the application is broken. A Dockerfile observation
creates conditional deployment work, never a requirement to use Docker. No
tasks is not a readiness or safety verdict. Completing an investigation is not
proof of a fix; progress tracking and comparisons between scans are separate work.

## Implementation and verification

The version 1 roadmap projection lives in `app/report/owner_roadmap.py` and
`web/src/lib/ownerRoadmap.ts`. The Python HTML report, React audit page and
standalone browser scanner render the same contract. Regenerate the browser
projections with `node scripts/sync_owner_report_browser.mjs`.

`tests/fixtures/owner-roadmap.json` supplies shared synthetic cases for Python,
TypeScript and generated JavaScript. Tests exercise task dependencies,
deduplication, missing and partial scope, malformed evidence, legacy data,
specialized assessments and unchanged exports. React and Chromium tests cover
navigation to prerequisites, grouped/contextual source findings, coverage,
rescan clearing, keyboard access and narrow layouts. Saved customer reports can
be used for a presentation check without executing their projects or rescanning.
