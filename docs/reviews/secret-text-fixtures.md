# Repeated document text in secret observations

Audit `ac4f5452` reported the local `token` in the PDF wrapping test as a
credential assignment. Its value is repeated document text. Engine
`2026-10-03-2` retains this candidate as an informational test fixture when a
bounded JavaScript/TypeScript syntax check establishes the following:

- A test path outside migrations contains a function-local `const token`.
- Its initializer repeats a quoted, alphabetic text literal with an integer
  count from 2 to 100000. No expression is executed or expanded.
- At least one reference is the value of a `text` object property.
- Every other identifier reference in that function is either another such
  property or the argument to `.includes(token)` directly inside `assert.ok`.
- Rebinding, shorthand/computed use, nested capture, dynamic evaluation,
  malformed syntax and unknown uses do not receive the classification.
- Provider-specific credential formats retain ordinary detection, including
  when their bytes are repeated or placed in test data.

The scanner records `source_context.kind = repeated_test_text`, masks the
candidate as before, and keeps it separate from ordinary credential candidates
when collapsing repeated observations. JSON replay and report wording preserve
the distinction. The credential-review roadmap task does not include this
fixture. This is evidence about local syntax and use, not proof about downstream
consumers, runtime behavior, credential validity or the whole repository.

The parser reads at most 256 KiB / 40000 nodes, with a bounded reference-work
budget. Missing native parsers leave ordinary findings in place and record
`javascript_text_fixture_context_unavailable`; browser runtimes without the
parser therefore do not claim the new classification. No keyword allowlist or
generic entropy/repetition suppression was added.

The same change recognizes `.test.mjs/.spec.mjs/.test.cjs/.spec.cjs` test paths
and applies the existing non-SQL declaration handling to `.mjs/.cjs`.
`tests/test_secret_text_fixtures.py` covers the observed multi-declarator form,
UTF-8 columns, credential uses, scope boundaries, parser fallback, provider
credentials, report wording and grouping collisions.
