# Source consistency after the v4 audit review

The v4 release retained reports and execution evidence correctly, but several model narratives contradicted local guards. It also scored some repeated hypotheses about one source operation more than once. This change links supported premises to bounded source checks, makes partial counterevidence visible in the main report, and groups compatible hypotheses by the actual operation.

## Scope and behavior

- HTTP status checks recognize both a terminal `!response.ok` branch and JSON parsing inside the same response's positive `.ok` branch. Coordinates distinguish different response bindings; ambiguous bindings, multiple parses and shadowing remain unchecked.
- Awaited JSON parsing can be shown to have a safe enclosing catch. Only an empty catch or a literal return is supported; unknown calls, destructuring and throwing handlers are not treated as safe.
- SQL UPDATE selectors separately check for WHERE. A WHERE clause does not disprove a concern about the business meaning of a backfill.
- A narrow Supabase message-insert check follows the authenticated user, own profile, target match, terminal participant guard and inserted identifiers in one function. It does not establish live RLS, FK behavior, successful authentication or race safety.
- React source facts distinguish an awaited fetch and its network-rejection cleanup from an HTTP-error response. The network-reset proof requires the same React state and handler, a direct first reset in the nearest catch, and no uncovered await, extra fetch, mutation or later/finally code.
- Whole network-claim dismissal requires a complete atomic title with no additional substantive narrative. A compound finding retains its unresolved claims and score penalty.
- Partial findings receive an `Assessment needs review` badge and a source-counterevidence headline. The original claim and suggestion remain in collapsed details. Both HTML and web explain that original severity still contributes to the score pending review; this is not confirmation of the remaining claim's impact. Whole contradicted claims remain excluded from active counts and score penalties.
- Included/reused Free baseline records are neither rewritten nor rescored by the renderer.

## Grouping boundaries

A scanner-owned identity contains a source digest, function/operation spans and a supported mechanism. It never contains a source literal or accepts a model-supplied identity. ZIP reads, files, nodes, depth, checks and traversal work are bounded per audit.

Supported operation families include password HMAC, administrative-client access, forwarded-host URL construction, token comparisons, query row bounds, auto-reply counts, prediction URL construction, metadata requests and polling loops. A shared line, function or client is insufficient when another entity or independent concern remains. Unsupported, cross-function, multi-operation and compound cases keep separate rows. A semicolon-separated peer-profile authorization claim is not swallowed by a generic service-role claim.

Grouping requires compatible whole/partial check kinds, results and checked targets. Distinct dispositions remain separate. Originals and producer provenance survive grouping, repeats are not presented as independent confirmation, and regrouping is idempotent, including pre-grouped input. Historical records without an attempted source identity retain the older conservative matcher; newly unresolved identities do not use the old text/near-line fallback.

## Offline replay of the retained v4 report

Reference engine: `2026-09-08-4`, release `e387b35f5921bc783fa628d9dac5de1a349959c3`.
Reference repository: `aiagent2046-coder/ai-co-founder-matching` at `87553a7ab6fcbd2815a2678d6887c0c00ef66829`.
Indices below refer to the zero-based saved findings arrays.

The replay uses the fixed source tree and saved representative narratives. It reconstructs an anchor from the saved finding line, not the wider quote-match window. Original raw model coordinate ranges/responses are unavailable. Existing grouped originals are historical context, not newly evaluated input. No provider call, target-code execution, report replacement or live rescan occurs. These counts are a deterministic review experiment, not a prediction of a new model run or a new production score.

| Saved finding | New source counterevidence | Whole finding |
| --- | --- | --- |
| Free F06, auto-reply HTTP response | Same response's positive `.ok` branch | Partial; other concerns retained |
| Free F08, avatar HTTP status | Terminal `!res.ok` guard before JSON | Contradicted |
| Free F11, message ownership | Same target match/profile participant guard before insert | Partial; race/FK assumptions unresolved |
| Free F12, GitHub user HTTP status | Positive `userRes.ok` branch, distinct from `tokenRes` | Contradicted |
| Pro P28, SQL WHERE | WHERE on the cited UPDATE | Existing contradiction preserved |
| Pro P53, SQL without a guard | WHERE on the cited UPDATE | Partial; backfill semantics unresolved |
| Pro P56, BigFive network error | Fetch is awaited and catch resets the same state | Partial; HTTP navigation issue retained |

Free keeps all 14 traceable rows; F08/F12 become whole contradicted observations. Pro's 58 saved representative rows become 46 groups in this experiment: ten groups remove 12 repeated penalties (including one four-way group). The underlying original observations remain retained.

Same-operation groups: P05/P13, P07/P14, P12/P42, P15/P39, P16/P20/P46/P47, P17/P44, P22/P50, P23/P49, P24/P51, P25/P52. P06/P36, SQL whole/partial claims, HTTP/network issues and unsupported swipe/policy claims remain separate. No claim about privacy, cost, migration state or runtime exploitability is established by grouping.

## Validation and release handling

Behavioral regression tests pair source counterexamples with wrong-binding, wrong-resource, unsafe catch, independent-concern, range, budget and idempotence cases. End-to-end tests cover scanner JSON, score accounting, HTML, web display, model-metadata forgery and Free baseline retention. Existing multi-pass/accounting fixtures now use an identifiable HMAC operation while preserving their original accounting assertions.

Local validation: the initial full Python run passed 3,959 tests, with two old generic-identity fixtures subsequently updated and passing. Eleven unrelated environment failures remain (ten unsupported ownership changes in the container, one missing SOCKS dependency). The final focused run passed 707 tests; Ruff and whitespace checks passed. All 124 web tests and TypeScript checking passed. A local production build was blocked by Google Fonts network access; GitHub Ubuntu CI provides the production build and full-suite gates.

`AUDIT_ENGINE_VERSION` is bumped to `2026-09-08-5`, with the scanner and prompt fingerprint pins updated. No tag or production deployment is performed by this change. The uploaded broad test bundle is not copied into the repository.
