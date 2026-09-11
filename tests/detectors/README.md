# Deterministic detector corpus

Run with the project's test dependencies installed:

```sh
pytest tests/detectors tests/trust_boundaries -q
```

The regular `pytest -q` CI step discovers both directories. No extra workflow,
LLM calls, database or execution of fixture source is required.

Each `<rule_id>/<positive|negative>/<case>/` is a readable miniature repository.
`expected.json` declares required or forbidden findings. Every payload filename
ends in `.fixture`; the archive builder removes that suffix. This preserves
`.env` and private-key filenames without changing the repository's ignore rules,
and prevents pytest and source linters from executing/interpreting sample files.
Credential payloads use `@DRYDOCK_SAMPLE:NAME@` placeholders. The test-only
`tests/detector_samples.py` expands them using repeated characters and an invented
signing seed. No complete account credential is stored in the corpus. Secret
protection remains enabled; an interpolated URI has a line-specific explanation.

The corpus currently covers 34 rule IDs with 204 examples (107 positive, 97
negative). Both polarities are mandatory for each ID in the report vocabulary or
declared by a wired scanner. Engine wiring is independently checked by
`test_engine_version_pins_the_scanners`. This is coverage of the current rule
vocabulary, not a measure of how many real vulnerabilities Drydock can detect.

## Nested callables: which rules read them, and why

Two families disagree here on purpose, and both directions are pinned by cases
rather than left to taste:

- A LITERAL rule states something about the configuration or the call SITE it
  sees. `verify=False` inside a nested `def` is the same defect as a top-level
  one, so `tls-verification-disabled` and `unsafe-deserialization` descend into
  nested functions (`positive/config-inside-a-nested-function`,
  `positive/loader-inside-a-nested-function`).
- A VALUE-tracing rule follows request input to a sink. A local helper's
  parameter is not the handler's parameter, and that helper is callable from
  anywhere in the file, so connecting the two needs a call graph these rules do
  not build. `python-outbound-request-unvalidated-url` and
  `path-traversal-file-sink` stop at the definition boundary
  (`negative/address-inside-a-local-helper`,
  `negative/sink-inside-a-local-helper`), each with a mutation that inlines the
  helper and must fire.

Silence there is a stated boundary, not a clean bill: an inlined helper is
reported, one reached through a call is not.

Example expectations:

```json
{
  "description": "A source literal matches the rule exactly once",
  "expect": [{"rule_id": "stripe-live-key", "severity": "critical", "count": 1}],
  "forbid": []
}
```

A positive must expect its directory's rule; a negative must forbid that rule.
All fields of an expectation must match the same finding. Optional `count`
checks multiplicity; unrelated observations are allowed. The harness itself has
regressions against vacuous negatives and split matches.

`tests/trust_boundaries` adds seeded scoring properties, benign source-edit
invariants, secret masking, exclusion accounting, archive validation and the
free-result → JSON → paid HTML contract. Model output and storage in the last
test are simulated; scanners and report code run normally.

Archives with repeated canonical file paths are rejected with `duplicate_path`,
including identical entries, aliases (`./`, repeated separators, backslashes),
and file/directory or symlink/file collisions. Repeated directory records are
allowed. Traversal and absolute names remain `unsafe_path`; they are not repaired
into seemingly valid source paths. Direct static scans use the same validator.

One strict `xfail` remains: detecting a secret assembled from constant string
concatenation. This is a documented scanner coverage gap, not a passing test.
Remove that marker when bounded constant evaluation is implemented. SQL injection,
payment manipulation and runtime tenant isolation require their own detectors
and adversarial/correct examples; this corpus does not claim to cover them.
