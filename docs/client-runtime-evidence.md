# Importing scoped client runtime evidence

The first contract is `cumora-project-tenant-isolation-v1`: 12 real HTTP/database
observations covering project creation, owner read/update/archive, cross-tenant
list isolation, forged-tenant denial, foreign-resource denial and unchanged data
after denied writes. It is pinned to one archive and one trusted scenario script
(`scripts/runtime_contracts/cumora_project_tenant_isolation_v1.mjs`). Unknown
archives and script revisions fail closed. This is an initial narrow contract,
not a general runtime execution adapter.

## Import

Keep `scenario.json` and `run-id.txt` from the controlled run. `verdict.json` or
terminal PASS output is not sufficient. With this repository installed:

```bash
python scripts/import_client_runtime.py "$HOME/Загрузки/cumora-main.zip" \
  --evidence "$HOME/cumora-runtime-20260919T143713Z/scenario.json" \
  --run-id "$(cat "$HOME/cumora-runtime-20260919T143713Z/run-id.txt")" \
  --output /tmp/cumora-drydock-runtime.json
```

The output must be a new file. Exit 0 means this receipt was accepted for the
exact archive/run; 1 means it was rejected while retaining the static scan;
2 means input could not be processed (including malformed JSON, duplicate keys,
files missing, output already exists, or evidence exceeding 64 KiB).
No model provider is configured. No project code, shell instruction, callback,
URL, or executable from the receipt is run or contacted by this import command.
A fresh static scan is performed on the supplied ZIP.

Python callers can pass `client_runtime_evidence` and the separately selected
`client_runtime_run_id` to `run_scan` or `run_static_scan`. Ordinary browser and
server scans do not acquire runtime execution capabilities from this change.
There is no new public upload endpoint or automatic background execution.

## Chain and trust

`security_agent.client_runtime` retains bounded canonical evidence and the
state `reported_scenario_passed`, scope `project_crud_and_cross_tenant_isolation`,
trust `operator_supplied_consistency_only`. Imported raw API metadata beyond
required fields is discarded. Expected HTTP statuses and database rows are
validated by Drydock, not adopted from a producer-supplied verdict.

`client_runtime_chain` records four import stages:

1. detector: archive binding checked;
2. researcher: pinned scenario selected;
3. experimenter: operator evidence received (no new execution);
4. verifier: actual observations revalidated.

Task identifiers, dependencies and input/output SHA-256 bind the stages to the
same archive, scenario, run, evidence and scanner engine. These hashes establish
consistency, not authenticity. A forged internally consistent report cannot be
distinguished from a real operator run without a trusted execution attestation.
The separate expected run ID prevents accidental cross-run imports, not fraud.

Saved reports revalidate both evidence and receipts before displaying them.
Invalid attachments become `client_runtime_status: rejected`; static findings,
scores, their existing SQL chains and missing proof remain intact. Reports without
this optional field retain the existing output.

No import changes `runtime_verified`, `customer_project_verified`,
`automatic_patch`, `automatic_apply`, OAuth verification, or remediation proof
to true. Seeded database sessions exercise application authorization, not OAuth.
This scenario does not demonstrate SQL-injection repair or whole-project safety.

## Verification performed during implementation

Tests construct receipts to exercise the validator, tampering rejection,
chain handoffs, no-LLM pipeline integration, legacy reporting and HTML safety.
Those tests do not stand in for real Cumora execution. On 2026-09-19, the
operator supplied the raw scenario.json, pinned scenario script and separate
run-id.txt from a successful Docker run. The actual import accepted all 12
checks and preserved the attachment through saved-report normalization.
A control scan of the same archive confirmed identical findings and score,
with zero model calls in both scans. This verifies import consistency only;
execution remains operator-reported, without independent attestation.
