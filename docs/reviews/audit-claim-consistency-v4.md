# Audit claim consistency: engine 2026-09-08-4

The v3 retained audit of `aiagent2046-coder/ai-co-founder-matching` at
`87553a7ab6fcbd2815a2678d6887c0c00ef66829` exposed three problems: correct
source guards beside claims that they were absent, independent causes merged
at one line, and client-switch advice that assumed write permissions.

## Changes

- Optional model `premises` identify a supported kind, local target and source
  coordinates. The scanner independently reads the archive and constructs all
  check results. Model-supplied verification metadata is discarded.
- Five bounded checks cover a same-response HTTP return guard, a local JSON
  rejection fallback, Intl catch placement, required nested Zod objects with a
  rejection return, and the clamped value supplied to a limit/RPC argument.
- Full-finding contradiction is restricted to complete single-premise titles.
  Multiple premises, separate concerns and broader narratives remain active;
  their partial counterexamples are displayed. Targets outside the finding's
  function cannot provide counterevidence for that finding.
- Cross-rubric grouping requires matching literal titles or one recognized
  cause. Location alone and generic title similarity no longer join findings.
  Unknown paraphrases remain separate. Merged originals remain available.
- Both model and static client-switch advice receives conditional policy
  prerequisites. The original advice is retained as superseded. SELECT and
  write operations are indexed; grouped static routes retain each route's
  policy context, including archives with an export directory.
- Cost context separates metadata GET, prediction creation POST and status GET,
  exposes conditional retry gates, and links an externally refreshed loop to
  directly named helper candidates. A small arithmetic check corrects the
  reported `C(5,2) × 3 × 6 = 90` to `180` without claiming a workload bound.
- JSON, HTML and web evidence presentation preserve these distinctions. The
  engine version and prompt fingerprint invalidate cached v3 results for new
  audits. Retained reports and baselines are not rewritten.

## Offline replay observations

These checks used retained responses and fixed source, without model requests
or executing the audited repository. They are regression observations, not an
estimate of model accuracy or verification of runtime consequences.

| Retained Free claim | New bounded disposition |
| --- | --- |
| Missing HTTP status check in auto-reply generation | Syntax premise contradicted; excluded from active count |
| Zod does not enforce required nested objects | Syntax premise contradicted; excluded from active count |
| Intl validation has no error handling | Syntax premise contradicted; excluded from active count |
| Incomplete Claude response error handling | Same-response status-guard premise contradicted; broader claim retained |
| Integer overflow risk in limit parsing | Unclamped-query-value premise contradicted; broader claim retained |

The OAuth status check, response structure, lab-token, OAuth token validation
and forwarded-host observations remain unresolved by these checks. The three
v3 static unchecked-HTTP-success detections are retained.

The retained Pro metadata claim obtains a metadata GET observation. Its polling
claim obtains distinct creation/status operations and the conditional retry
gate. The experiment helper receives external-loop-progress context and the
arithmetic correction. These do not prove prices, billing, an infinite loop,
a particular concurrent schedule or a full-flow retry after an arbitrary error.

## Validation and boundaries

Synthetic paired regressions exercise the scan → JSON → HTML path with fake
provider responses and web evidence rendering. Negative cases include wrong
response bindings, nonterminal or late guards, nested callbacks, shadowing,
multiple parses, optional and overwritten schema fields, an unused clamp,
unsafe fallback bounds, arbitrary JSON catch effects, malformed model selectors,
cross-function targets and compound claims.

Parsers have byte, node, function and request budgets. Unsupported control flow,
aliases, schema factories, runtime bindings, applied migrations, grants and
policy predicates remain unverified. Grouping may retain additional unknown
paraphrases; this is preferable to removing an independent issue. No provider
requests, database migration, dependency or production deployment are needed
for these regression checks.
