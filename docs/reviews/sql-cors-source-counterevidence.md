# Source-bound corrections for the Kristina SQL and CORS narratives

Follow-up to PR #605. That change groups repeated SQL hypotheses; this change
adds facts from the current archive and makes the active report consistent with
those facts. Engine/cache identity: `2026-10-02-2`.

## SQL identifiers

The six original model narratives describe three table-name interpolations.
Their conditions often require a future code edit before attacker control could
exist. Calling that condition contradicted would be misleading: future code is
not part of the current archive.

The new assessment therefore records an **observed** literal-only source path,
with `whole_finding=false`, and requests narrative review. It supports one simple
table-name slot in a SELECT call, at the first action of a literal-list/tuple loop,
optionally inside a direct try body. A named iterable must be assigned immediately
before the loop and have no other name references in its scope. Reassignment of
the loop target, aliases, mutations, escapes, branches before the call, nonliteral
elements and unsupported forms abstain. Table literals must be plain identifiers;
their values are not copied into assessment metadata.

The report says where this particular table name comes from and separates future
changes from current source. It does not certify all queries or runtime behavior.

## CORS predicate

The original report says all origins pass without `SCOUT_EXTENSION_ID`, then
retracts that statement in its explanation and substitutes an absent-Origin concern.
The new AST check binds the cited direct callback registration to the preceding
local `const`, its configuration default, a null false branch, the exact
`header && header !== origin` predicate, a direct 403 return and a later `next()`.
An earlier host rejection is supported only in a narrow, side-effect-free syntax
shape under ordinary header-reader/RegExp behavior. Other preceding work abstains.

The active wording states that a stable nonempty Origin string satisfies the
predicate when configuration is falsy and the compared value is null. An absent
Origin does not satisfy that predicate. Whether callers without Origin should be
allowed remains a separate policy question. The check does not prove middleware
execution, runtime header implementation, reachability or authentication.

## Evidence and limits

- ZIP bytes, AST ranges and source hashes supply the facts; model-supplied proof
  fields cannot authorize a rewrite.
- Original model wording and producer metadata remain in `narrative_projection`;
  SQL groups also retain every original in `grouped_originals`.
- Fresh source hashes and structural metadata are required for projection. The
  HTML report validates persisted projection consistency and labels these rows
  **Outcome needs review**.
- Severity, confidence, verification status and numerical score contribution are
  unchanged. These observations do not establish a whole-finding dismissal.
- Work, archive parsing and per-audit check budgets are bounded. Unsupported or
  ambiguous source produces no positive counterevidence.

Regression coverage includes the six SQL narratives and the original CORS
self-retraction, real pipeline admission with mock model responses, source
mutations, malformed/stale metadata, unchanged scores, preserved originals,
HTML rendering and forged model evidence. All seven original source anchors were
also checked against the Kristina checkout. No paid model request is needed.
