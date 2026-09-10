# Production audit review regressions

Engine `2026-09-08-3` addresses source-review gaps observed after the
`v2026.09.08-2` deployment. It adds no model requests and keeps the existing
16,000-character source-index prompt budget. The engine bump prevents reuse
of results produced with the previous prompt and scanner behavior.

## Existing protections and recommendation prerequisites

Three bounded indexes accompany the existing source facts in JSON, exported
HTML, and the web report:

- `guards`: OAuth restriction syntax, domain suffix arguments, finite numeric
  clamps, Intl exception handling, and schema rejection branches.
- `cost_context`: directly imported helper slice bounds, awaited database call
  order, returned-ID branches before later calls, and Python loops whose
  condition is refreshed by another call.
- `rls_recommendations`: literal database write operations and policy command
  declarations in ordered SQL migrations. SELECT-only declarations are shown
  before advice to replace a service-role client with a user-scoped client.

These are source observations. They do not establish authorization, applied
database permissions, transaction isolation, total token cost, or absence of
duplicate requests. Unresolved imports, mutation, procedural migrations,
invalid encoding, and exhausted collection limits remain explicit limitations.
The original model recommendation is retained for review.

Automatic syntax contradiction is limited to three atomic absence claims:
a missing `@` separator, a missing nonnegative clamp bound, and a missing
catch around the supported Intl expression. Unsupported expressions or
ambiguous locations cannot dismiss a finding. Broader ownership, validation,
or availability claims remain unverified even when a nearby guard exists.

## Unchecked HTTP success

The static rule `react-unchecked-http-success` detects supported React handlers
where an awaited fetch has a discarded or unused response, followed by a
success state displayed in JSX or navigation through an imported Next router.
An HTTP error response alone does not reject standard fetch; catch therefore
does not establish HTTP success.

The rule requires a supported direct flow. Status-aware response handling,
opaque control flow, masked or hidden success UI, later state cancellation,
ambiguous bindings, and unsupported effects do not produce a finding. This
conservative scope can miss real bugs. The finding still does not verify a
live endpoint response or execute uploaded code.

Offline source review of `aiagent2046-coder/ai-co-founder-matching` at
`87553a7ab6fcbd2815a2678d6887c0c00ef66829` identifies the two intended cases:
`app/app/avatar/page.tsx:53` and `components/onboarding/BigFiveTest.tsx:90`.
The complete repository scan also observes logout navigation after an unchecked
fetch at `app/app/layout.tsx:66`; source review confirms that direct flow. This
third observation does not prove that the logout endpoint returns an error.
No production rescan or live model accuracy measurement is implied.

## Regression gates

The existing strict detector corpus remains intact. A new positive case and
a status-checked negative case exercise the real static pipeline. Dedicated
tests pair supported guards and helper bounds with ambiguous, mutated,
shadowed, malformed, hidden-UI, and unsupported alternatives.

`tests/test_audit_review_regressions.py` checks that source counterevidence
survives the scan and HTML export, cannot be forged by a model response, does
not merge away an independent claim, and leaves HTTP checks available when
model review is disabled or fails. It also checks policy prerequisites before
client-change advice and preservation of stored facts when prompts are trimmed.
Frontend evidence tests cover the same observations and limitations.

Run the existing CI gates: `python -m ruff check .`, `python -m pytest -q`,
then `npm test` and `npm run build` in `web/`. These are deterministic regression
checks, not a claim that every false positive from the reviewed live reports
has been eliminated.
