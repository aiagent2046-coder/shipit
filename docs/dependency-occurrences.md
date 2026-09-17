# Dependency identities and manifest locations

A resolved dependency is looked up once per `(ecosystem, name, version)`.
`dependencies_found`, `dependencies_checked`, advisory evaluations, status counts,
finding limits and severity scores continue to use these unique identities or
their advisory assessments. A second manifest does not create another assessment.

Each collected dependency also carries `occurrences`, ordered by manifest path.
One occurrence aggregates that pin within one selected manifest; it is not an
inventory of every `node_modules` installation path. It records the manifest,
minimum known positive line (otherwise zero), directness, development scope and
dependency groups. Repeated entries within a manifest combine directness with OR,
groups by sorted union, and scope conservatively: runtime overrides unknown,
which overrides development-only. These remain lockfile facts, not runtime
reachability evidence.

The legacy scalar fields all come from the same representative occurrence,
chosen by that scope precedence and then manifest path/line. They are never a
combination of a path from one manifest and metadata from another. The number
of retained locations per dependency is bounded by the existing six selected
lockfiles. Excluded, malformed, unsupported and truncated manifests retain their
existing coverage gaps; this change does not establish their contents.

Offline findings and unknown assessments carry `occurrences` with `manifest`,
`line`, `direct`, `dependency_scope` and `dependency_groups`. Online findings and
stored inventories preserve the same provenance through refresh. Additive
`occurrences_recorded` distinguishes a preserved manifest list from historical
data that only recorded a representative. It does not mean coverage is complete;
the separate coverage gaps still apply. Old stored rows cannot recover locations
that were discarded and must not invent them. Malformed new lists invalidate
the refresh instead of deleting previously reported evidence.

JSON contains the locations; terminal tasks show their separate metadata; the
human-readable explanation lists the recorded manifests; SARIF emits multiple
locations on one result. Finding and assessment counts do not grow with that
list. CLI history treats adding/removing a location or changing its scope as a
changed finding, while location order alone does not change its identity.

Synthetic regression and property tests compare inventory and report locations
with an independent per-manifest model. They cover permutation, addition and
removal, mixed scopes/directness, repeated pins and independent versions. The
bounded mutation runner deliberately discards all but the first occurrence;
the two-manifest regression must reject it without changing lookup counts.
