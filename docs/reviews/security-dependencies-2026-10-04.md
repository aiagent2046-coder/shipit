# Security dependency review — 2026-10-04

The self-audit of commit `3961cae82715fa56dac9745e37e48143d2356751`
reported vulnerable Next.js and PyJWT versions. This change updates the
dependencies without changing scanner rules or the engine version.

## Next.js

- Advisory: https://github.com/vercel/next.js/security/advisories/GHSA-vcvr-r3jv-pc5j
- Update: `16.3.5` → `16.3.6`, including matching Next.js platform packages.
- The advisory concerns attacker-controlled SVG input to the Node.js
  `ImageResponse` implementation from `next/og`.
- A search of application source under `app/` and `web/src/` found no
  `next/og` imports or `ImageResponse` calls. This is a source-level
  applicability check, not proof about every transitive dependency or live
  deployment. The affected package version is removed regardless.

## PyJWT

- Advisory: https://github.com/jpadilla/pyjwt/security/advisories/GHSA-42vr-xj54-vc7v
- Update: `2.14.0` → `2.15.0` in both hash-locked dependency sets; raise the
  direct dependency floor in `pyproject.toml` to `2.15.0`.
- The confirmed issue is an uncaught recursion exception while parsing a
  deeply nested unsigned JWT payload before signature verification. The
  advisory does not demonstrate authentication bypass or a process crash.
- Application source uses `jwt.encode(..., algorithm="RS256")` in
  `app/deploypack/github_app.py` to sign GitHub App tokens. No `jwt.decode`,
  `PyJWKClient`, or `verify_signature` use was found in application source.

## Validation

- Fresh Python 3.12 environment: installed `requirements-dev.txt` with
  `--require-hashes`.
- Development lock covers all 37 runtime pins with matching versions.
- Existing GitHub App tests: 42 passed, including real RS256 signing and
  verification with a generated RSA key pair.
- Web tests: 818 passed.
- `npm run build`: passed, including browser scanner prebuild, Next.js
  compilation, TypeScript validation, and page generation.
- Only PyJWT and Next.js-family versions changed. Existing setuptools pins
  were retained after lock generation omitted them in this environment.

CI and a fresh audit after deployment remain the release checks; these
updates do not resolve or reclassify unrelated audit observations.
