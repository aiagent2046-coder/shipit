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

`dependency_cve.status: partial` does not by itself mean that package versions
are missing. The exact-version action is added only for explicitly unresolved
manifests. Other gaps may involve catalog scope, unsupported comparisons or an
unavailable check and retain a general investigation task. Missing coverage
fields do not imply a successful check. Other coverage limitations remain in
the report's existing coverage sections; this version does not create specialized
tasks for every scanner limitation.

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
