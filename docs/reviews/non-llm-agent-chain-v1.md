# SQL agent chain: implementation and review

Branch: `feature/non-llm-agent-chain`.
Base: `96cedf4d7e434940bea5ef46de66e6f57e314cb6` from PR #568,
`feature/agent-runtime-evidence`. PR #568 was open at implementation time;
a subsequent PR should target that branch and be retargeted after its merge.

## Result

The SQL coordinator delegates source-bound work to detector, researcher,
experimenter and verifier workers through a bounded in-process queue. Each
worker receives a copy of accepted evidence. Role-specific validation prevents
source identity changes, unauthorized proof promotion and removal of unproven
gaps. A worker failure retains earlier facts and blocks downstream work.

The explicit native executor runs the existing registered synthetic PostgreSQL
recipe once per investigation, including when several candidates select it.
The verifier consumes its scoped evidence. Browser/offline scans retain their
source-only capabilities. There are no LLM calls or automatic patches.

See [the task contract](../non-llm-agent-chain.md) for receipt fields, budgets,
execution boundaries and the native invocation.

## Review resolutions

- Reject malformed nested saved receipts without crashing report normalization.
- Enforce role-specific transitions: only verified acquisition can remove source
  gaps; the experimenter cannot promote candidate state; recipe verification
  requires the valid source-bound synthetic contract.
- Recognize task failure and invalid-journal stop reasons in Python/web summaries.
- Keep current-record tampering tests separate from historical records without
  task receipts; update the deliberate engine-version pin to `2026-09-19-4`.
- Record zero attempts for workers blocked by an upstream task failure.

A second independent review found no remaining blocking issues.

## Validation

- Targeted Python chain/source/executor/contract/report suites: **259 passed,
  5 skipped**. All five skips require a dedicated PostgreSQL database.
- Final engine-version and report checks: **68 passed**.
- Web security-agent rendering/record suite: **114 passed**.
- Native versus shipped WASM corpus: **483/483**, including continuation and
  parser probes. This was a Pyodide-in-Node run, not a Chromium run.
- Offline distribution staging succeeded, including the new stdlib-only module.
- Repository Ruff, whitespace, workflow YAML and added-secret scans passed.

The broad Python run reported 10,500 passed, 156 skipped, 1 expected failure and
19 failures while implementation/review fixes were in progress. Eight failures
were the updated version pin and old reporting expectations; their corrected
suites pass. The other 11 failures were reproduced on the unchanged base commit:
10 mocked Fix Pack tests encounter unavailable `lchown` UID mapping in this
runtime; one sandbox-client initialization test inherits a SOCKS proxy without
`socksio`. No production configuration was changed to suppress these failures.
The full suite was not rerun after focused verification of the fixes.

The dedicated PostgreSQL workflow includes the new two-candidate end-to-end
chain test (one execution/reuse, 27 cases/stages, 9 → 1 → 9 attack-control rows,
rollback and unchanged customer-runtime gaps). It has not run for this branch.

## Publication status

The initial push was blocked by automatic approval review pending explicit
permission to publish repository changes. The user subsequently authorized
publication and creation of the stacked PR. See that PR for current CI results.
No merge or production deployment is included in this step.
