# Bounded HTML input context

Engine: `2026-10-03-3`.

The JavaScript/TypeScript HTML injection check now distinguishes fixed string
assemblies from unverified dynamic input. It does not execute source or verify
sanitizer implementations.

## Fixed input proof

String concatenation, template substitutions and visible unique `const`
initializers can remain silent only when every inserted part resolves to a
fixed string. Resolution is bounded to 12 levels and checks initializer order.

A separate proof handles `Object.entries` loops over a local literal string
table, including nested array destructuring. The table must have only its
literal declaration and the enumeration reference. Aliases, mutation, export,
shadowing, unknown values, escaping closures and unsupported patterns prevent
suppression. Only string-valued bindings at every entry are eligible. This
assumes normal native built-in semantics; external prototype modification and
cross-file behavior are not established.

## Dynamic input observations

Other findings retain their existing high severity and unverified status.
Evidence binds the source SHA-256, sink byte span and line span to bounded counts
of fixed text, unverified calls and unresolved values. It includes observed
callee names but not literal source values. Call arguments and helper bodies are
not followed. One visible local const initializer can be described; further
aliases remain unresolved. A limit flag explicitly records incomplete tracing.

At most 32 candidate contexts per file are collected; each expression walk is
bounded to 256 visits and depth 24, with at most 16 names per list. The shared
syntax tree is limited to 20,000 nodes. Vue script fragments retain the existing
finding behavior without whole-file source evidence synthesized from fragment
coordinates.

## Scout regression

The fixture is the TAGS/escapeHtml/renderDigest section of Kristina Scout.
The original file has four sinks at lines 116, 122, 125 and 131. Only line 122,
which assembles fixed labels and classes, becomes silent. The other three still
require review; observing `escapeHtml` does not establish escaping policy or
URL safety. A dynamic table value restores the fourth finding.

Controls cover mutable/aliased tables, shadowing, reassignment, closures,
unknown helpers, later initializers, dynamic string parts and proof limits.
The static pipeline must preserve the source-bound evidence on each finding.
