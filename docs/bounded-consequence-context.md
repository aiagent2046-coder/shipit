# Bounded source context for consequence claims

Source quotes establish the presence of text, not the causal interpretation in
a model's title or explanation. This change attaches four additional source
contexts to relevant accepted observations:

- A specific local OAuth-token binding has a falsy early return before its
  later write arguments. Nonempty invalid tokens and other stored bindings are
  not proved safe by that guard.
- A React input has an empty-value entry return, is cleared before await, and
  controls the disabled state of its corresponding native button. This is not
  general request idempotency or a proof about every event entry point.
- A handler discards its sole direct awaited fetch response and contains no
  direct JSON parsing call. This does not establish successful HTTP validation
  or safe navigation, and does not assert what a called helper does.
- A route's duplicate-key error branch returns before its later same-table
  queries. The client link uses literal POST paths and Next app-directory
  conventions. Matching UNIQUE declarations are recorded as declarations only;
  applied migrations, rewrites and actual runtime duplicate responses are not
  established. Repeated client calls and UI increments remain possible.

## Interpretation contract

Free-form model text selects a topic only. The module emits `observed` for a
bounded source fact or `not_checked` when it cannot establish that fact. It
**never emits `contradicted`**: a guard on an absent value does not refute a
claim about a nonempty invalid value, and a recommendation mentioning JSON
does not assert that JSON parsing already occurs.

The records live in `claim_evidence.context_checks` with
`scope=bounded_source_context`. Their `claim` describes the checked source fact,
not an invented atomic assertion attributed to the model. Both report renderers
show the distinction and the source binding. Existing findings, penalties,
conditions, grouped originals and runtime verification statuses are retained.
There is no new typed model protocol or additional model request.

Parsing is bounded per audit: 40 selected findings, 64 files, 256 KB per file,
2 MB in total and 40,000 syntax nodes per parsed file. Ambiguous paths, parser
errors, shadowed bindings and unsupported control flow remain unknown. Evidence
records keep hashes, names and locations rather than source excerpts.

## Imported call error boundaries

`SyntaxVerifier.imported_error_context(finding)` adds neutral
`imported_call_error_boundary` context records. Error-related prose selects
this check; names in the prose never resolve calls or refute a narrative.
Finding coordinates select direct calls in the cited range or its enclosing
function. One hop links an unaliased value named import to a direct named
module export. An anchor inside an exported function can also select a bounded
subset of direct imported callers, with sibling files checked first. Omitted
caller files and exhausted budgets produce explicit `not_checked` records.
No absence observation claims that all callers have been searched.

Each checked relationship records caller and callee source hashes, function and
call spans, the import name and span, and any local configuration hash/span used
for resolution. Relative paths and a single literal local wildcard mapping in
a nearest strict-JSON tsconfig/jsconfig are supported. Exact competing mappings,
multiple candidate extensions, JavaScript/TypeScript substitution ambiguity,
custom suffixes, inherited configurations, aliases, reexports, default imports,
namespace imports, dynamic calls and ambiguous or shadowed bindings remain
unknown. These are source candidates; compiler, bundler and runtime module
resolution are not executed or established.

The caller observation follows only the exact call's lexical ancestors up to
its owning function. It records a covering try/catch and distinguishes a sole
primitive return from a direct rethrow of the caught identifier. Catch
parameter destructuring, calls/awaits before return, conditional catch exits,
nonliteral returns such as `Promise.reject(...)`, and enclosing finally clauses
are unsupported. A direct awaited call can have a recorded rejection boundary.
A call without direct await has **only a synchronous-throw observation**, even
when the imported helper is syntactically non-async: it could return a Promise.
An enclosing caller try cannot supply a boundary across a nested callback.

For the bound callee, separate records cover only its own direct awaited
`fetch` calls and direct awaited `.json()` on a single local response binding
from that fetch. Each operation has its own checked catch behavior. Nested
callbacks and non-awaited operations are excluded. Fetch/API identity at
runtime, other helper operations, code before/after the checked try, callbacks,
transport success and downstream UI cleanup remain unverified. In particular,
a helper's checked fetch/json return path never means the helper cannot throw,
that its callers cannot fail, or that a finding should be dismissed.

The new verifier has independent per-audit limits: 40 distinct selected
anchors, 64 source read/parse attempts, 256 KB per file, 2 MB total source,
40,000 AST nodes per file, 400,000 parsed AST nodes total, 4,096 archive entries,
128 imported-call checks per anchor and 512 total. A reverse lookup visits at
most 16 caller files; an anchor emits at most eight bound call records, each
with at most eight callee operations, plus an omission record when needed.
Rejected file reads are cached and consume attempts. Exact file/anchor results
are memoized before charging a new check and returned as independent copies so
repeated observations remain stable after budget exhaustion. Every cache and
budget belongs to one verifier/audit; none is shared across customers.

All input comes from the supplied ZIP. Duplicate, unsafe, symlinked, oversized,
nonproduction and unsupported source paths fail closed. Neither uploaded code,
imports nor an external API execute. Records retain names, locations and hashes;
source excerpts, URL literals and error-message literals are not copied.
Context results are exclusively `observed` or `not_checked`, remain under
`claim_evidence.context_checks` with `scope=bounded_source_context`, and do not
change premise disposition, finding acceptance, penalties or runtime status.

The integrated scanner appends these records after existing context checks;
engine `2026-09-09-8` invalidates prior cached reports. Synthetic pipeline tests
exercise one and two fake responses, retaining the original claim and conditions
while checking stable exact-repeat grouping. Private offline replay reconstructs
accepted observations from saved reports rather than replaying raw provider JSON.
Across the three dependent changes, Free retains 12 rows and Pro changes from
44 to 45 solely by separating the metadata claim group. All 12/62 underlying
originals, including 6/56 model observations, retain their substantive fields
and producer response/rubric records; original advice remains recoverable.
New context source hashes and spans are checked against the pinned archive.
This validation uses no real model requests and is not a fresh production audit.
