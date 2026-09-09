# Recommendation API prerequisites

`app/scan/recommendations.py` runs after static/model findings are formed,
before grouping and persistence. It composes the existing RLS client-change
check with a deterministic guard for advice mentioning the exact identifier
`timingSafeEqual`. It also composes the
[external-operation and retry-budget contracts](paid-operation-recommendation-prerequisites.md).
It adds no model calls and executes no uploaded code.

The guard replaces recognized advice, including apparently guarded snippets,
with a conditional recommendation: validate input types and a nonempty
configured secret, define and validate the expected encoding, convert each
input to a buffer once, and reject unequal **byte lengths** normally before
calling the API. Missing, malformed and unequal inputs must not produce an
uncaught conversion/length exception. Equal-length wrong inputs and valid
inputs also need tests. Byte length is checked after conversion; matching
string lengths or typed-array element counts is insufficient.

This follows the [Node.js API contract](https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b).
The API does not establish timing safety for surrounding code. ShipIt neither
confirms a timing exploit nor verifies that a suggested implementation is safe.

## Scope and evidence

This is a bounded **advice contract**, not a JavaScript verifier. Literal API
mentions in prose, calls, bracket access and named imports receive
`prerequisites_required`. Aliases or escaped names without the identifier are
outside the check. A nearby length guard, helper call, catch, or prose promise
does not prove type, encoding or control-flow correctness. Unrelated advice
is unchanged. The check scans the complete stored hint so a long prefix does
not hide a trailing API mention.

`claim_evidence.recommendation_check` keeps the legacy `result`, `detail` and
`original_fix_hint` fields. The earliest original is canonical and explicitly
`superseded`; `original_provenance` retains the source, verification metadata
and model producer when recorded. The additive `checks` list identifies each
deterministic guard and its conditional replacement. API entries also carry
scope, a documentation reference and concrete prerequisites. Earlier details
are retained. Intermediate wording that cannot remain in the active advice
is kept in `superseded_fix_hints` and rendered as superseded, never as another
fix to apply.

RLS and API checks compose without overwriting the first original or losing
policy context. Repeated preparation, including a JSON round trip, adds no
duplicate check or wording. Active advice is rebuilt from fresh known
prerequisite templates; a stored marker or arbitrary previous replacement
cannot bypass that rewrite. Legacy RLS records without `checks` retain their
detail and original; an API mention in that original still triggers the new
guard when explicitly reprocessed. Rendering an old stored report does not
rewrite it or assert that this newer check ran. HTML and web reports accept
the original three-field shape and display additional evidence when present.
Malformed optional recommendation fields are skipped during presentation;
unknown evidence fields remain stored. Malformed outer evidence explicitly
reprocessed by the guard is retained as `legacy_claim_evidence` and cannot
fabricate a source check.

Supported separate rate-limit, webhook and explicit billing-check goals in
the canonical original are retained as conditional follow-ups. This avoids
dropping a separate rate-limit goal when a crypto/RLS snippet is superseded;
it does not certify the original implementation or retain unchecked code as
an active alternative.

The guard changes recommendation text and its evidence only. Source checks,
severity, confidence, finding counts, consequence status and scoring are not
upgraded. Both static and model integration paths set provenance before
preparing advice; model-supplied check metadata is not trusted.

Synthetic regressions in `tests/test_recommendation_prerequisites.py` cover
the two unguarded buffer-comparison shapes, byte/string-length confusion,
unknown and apparently guarded forms, unrelated advice, mixed and legacy RLS
records, idempotence, provenance, model-metadata forgery, one-call model
accounting, static integration, and HTML/legacy presentation. Web evidence
tests cover the additive and legacy wire shapes. No private audit fixture is
included.
