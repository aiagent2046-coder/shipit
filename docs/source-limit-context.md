# Bounded source limit context

`SourceLimitVerifier.checks_for(finding)` returns `observed` or `not_checked`
records for `claim_evidence.context_checks`. It does not reject a finding,
change its title, score or required conditions, or mark runtime verification
complete. The scanner does not execute uploaded code or make a model call.

## Numeric clamp to RPC syntax

`finite_clamp_rpc_argument` records an immutable same-block chain:

```ts
const raw = parseInt(request.searchParams.get('limit') ?? '20', 10);
const count = Number.isFinite(raw) ? Math.min(100, Math.max(1, raw)) : 20;
const result = await client.rpc('query', { match_count: count });
```

The finite test, both clamp operands and the literal fallback must be bound to
unambiguous `const` declarations. The fallback must lie inside the clamp.
The recorded direct RPC-syntax argument must use that exact result binding,
after its declaration, in the same immediate function block. Object spreads,
duplicate argument keys, aliases, optional calls, nested branches and deferred
calls are outside this grammar. The record contains the actual numeric bounds,
source spans and file hash. It does not resolve the receiver to a runtime RPC
implementation or say that all RPC calls use a clamp.

## Direct imported collection return cap

`imported_collection_return_cap` links a caller's direct named import and
immutable result declaration to a source candidate containing this shape:

```ts
export const MAX_FACTS = 40;
export function sanitizeFacts(facts, opts = {}) {
  const maxFacts = opts.maxFacts ?? MAX_FACTS;
  return (facts ?? []).map(normalize).filter(Boolean)
    .slice(0, maxFacts).map(format);
}
```

Only an unaliased named import and direct named export are resolved, using the
archive's literal relative path or one supported local configuration mapping.
The helper must return its map/filter/slice chain directly, without alternate
returns, output aliases, concatenation or `flatMap`. Its cap is a direct option
read with a literal or preceding module-constant fallback. A call omitting the
options argument records the default; a plain object with a numeric override
records that override, including zero. Unknown options, spreads, getters,
nonfinite/fractional/negative bounds and ambiguous imports remain unchecked.
All referenced numeric caps are bounded to at most one million.

Tracked option reads, input and cap references cannot escape through aliases,
shorthand object properties or method calls. Inherited `Object.prototype`
property names are excluded from all option reads. Visible builtin shadowing,
assignment, prototype mutation, unrecognised builtin methods and global-object
escape paths also abstain. Only a narrow set of native read-call spellings is
accepted; this is intentionally conservative and is not runtime API identity.

The caller/import/call, helper/return/slice/default/override and any local module
configuration are bound to source spans and SHA256 hashes. No source excerpts,
request strings, table names or model text are copied into context records.

A downstream slice **does not bound the preceding database query**, prove a
byte/token limit, resolve every caller or establish what actually reaches a
model. Thus a compound finding about an unbounded SQL query and an allegedly
unbounded prompt remains available for review with the added source context.

## Budgets and isolation

Each verifier owns a distinct `ImportedErrorVerifier` instance solely for the
existing safe ZIP reader, parser and one-hop resolver; its counters and caches
are not shared with imported-error context or other audits. The inherited
limits are 4096 archive entries, 64 source/configuration read attempts,
256000 bytes per file, 2000000 total bytes, 40000 nodes per file and 400000
aggregate parsed nodes. Invalid UTF-8, parse errors, duplicate paths, traversal,
symlinks and unsupported compression abstain.

This check additionally limits 40 source anchors, 16000 nodes per function,
400000 work nodes, 128 immediate local constants, 128 candidate calls per kind and
anchor, 512 calls per audit and 8 output records per kind. Exhausted budgets
and truncated output are explicit `not_checked` context. Cached records are
returned as independent copies and remain isolated to one verifier instance.

Tests use synthetic source and in-memory ZIPs. Positive cases cover the actual
finite/min/max/fallback-to-RPC pattern and the options-object/default-constant
collection chain. Negative cases cover call binding, mutation, aliases,
prototype escapes, optional paths, overrides, misleading text, source-loader
failures and budgets. Score and disposition invariance is tested separately.
