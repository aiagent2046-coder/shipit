# Dependency catalog review — 2026-10-04

## Snapshot provenance

The three generated catalog files are copied byte for byte from [PR #613](https://github.com/aiagent2046-coder/shipit/pull/613), commit `0c8ca463c04c93b57f1e605d867734c613cfaa2a`. No advisory ranges were manually edited.

- CVE List source: `8fffad6e07b76e5bcfe9a5a9167ffd26799edcf3`, timestamp `2026-10-04T10:46:41Z`.
- GitHub-reviewed source: `81466db00c7e5c0fad9e70fa8134826fb9849df0`, timestamp `2026-10-04T09:34:01Z`.
- Previous sources were dated 2026-09-24. Indexed packages increase from 5,194 to 5,237; entries increase from 16,689 to 17,124. These are supported catalog entries, not complete vulnerability coverage.
- Catalog SHA256: `df1d847b192c8d9de21331a0dd103a6ea3c971815c1b8ee4964f2bab96bf49df`.

## Why source-map-js still needs review

The current CVE record and the refreshed snapshot retain `CVE-2026-93749` as a published advisory affecting npm `source-map-js` through `1.2.1`. The described impact is event-loop blocking when processing attacker-controlled indexed source-map offsets. This version match does not establish that Drydock exposes an exploitable runtime path.

Read-only requests on 2026-10-04 reproduced the apparent disagreement:

1. `GET https://api.osv.dev/v1/vulns/CVE-2026-93749` returns the advisory. Its affected entry contains a Git repository range, but no npm package identity.
2. `POST https://api.osv.dev/v1/query` with the public package/version payload below returns `{}`.

```json
{"package":{"name":"source-map-js","ecosystem":"npm"},"version":"1.2.1"}
```

The absence of an npm-query result does not retract the CVE or prove the package unaffected. The observed data supports a package-index coverage difference; refreshing the catalog alone cannot remove it. Preserve the catalog observation and explain that the online package lookup did not repeat the match. Do not label it fixed, withdrawn, or safe merely because OSV returned no package match.

Sources:

- [CVE List record](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/93xxx/CVE-2026-93749.json)
- [Assigning CNA advisory](https://www.vulncheck.com/advisories/source-map-js-through-1.2.1-event-loop-denial-of-service)
- [OSV record and Git mapping](https://osv.dev/vulnerability/CVE-2026-93749)

## Validation evidence

Local review checked that the generated catalog SHA256 matches both the sidecar and learning metadata, inspected source timestamps and the relevant advisory, and confirmed that PR #613 merges without conflicts with main `742790bb99b8accaec262e581d6564b578be406c` using `git merge-tree`. Local review did not rebuild the entire upstream source databases.

The [successful generator workflow](https://github.com/aiagent2046-coder/shipit/actions/runs/37197704795) ran the deterministic rebuild check, compiler and pipeline tests, browser runtime/integrity checks, and WASM parity before opening PR #613. At review time, PR #613 itself exposed only the Vercel preview comment check, not the normal complete PR CI suite. The integration PR must run that suite against the current main and report changes before merging.
