"""What each static check can report, declared once and served to customers.

WHY THIS EXISTS. The only place that lists what the audit can report is a TEST
(`tests/test_engine_version_pins_the_scanners.py`), so a customer has nowhere to
read what was looked for. A scan does return `checks_run` and a `coverage`
sentence per check, but only after an audit and only for the repository that
audit read. This module is the same information, declared ahead of the scan and
served by `GET /v1/capabilities`.

WHAT IT IS. One entry per check the static stage runs: the key the report already
uses in `checks_run`, a customer-facing title, the rule ids that check can emit,
and the scope sentence -- what it reads, and what it does not resolve. The rule
ids are the ones the scanner modules declare; the scope sentences come from the
scanner that owns the claim: existing descriptions were moved here from
`app/scan/static.py` and corrected where their exclusions exceeded those
actually applied by the scanner. The remaining descriptions follow the owning
scanner's implementation and limitations.
`tests/test_capability_registry.py` guards the registry against wiring drift.

WHAT IT IS NOT. Not a promise about a repository. It says what the engine can look
at; it never says a project is clean, and never that these checks ran on a project
at all. A check that finds nothing and a check that gave up are different things,
and the scan reports which happened.
"""

from __future__ import annotations

from dataclasses import dataclass

# Shared by the declared secrets scope and by the per-scan description in
# `app/scan/static.py`, so the sentence has one home.
EXCLUSIONS_NOTE = (
    "Exclusions are outside this check; no finding does not establish that "
    "excluded content is safe."
)

# The fixed part of the React success check's scope. The scan appends the parser
# limits it actually hit, so the sentence lives here and is extended there rather
# than written twice.
HTTP_SUCCESS_SCOPE_PREFIX = (
    "Bounded React handlers with direct success effects after an unchecked fetch; "
    "runtime fetch bindings and HTTP failures are not verified. "
)


@dataclass(frozen=True)
class Capability:
    """One static check: what it can report, and what it cannot see."""

    check: str
    title: str
    rule_ids: tuple[str, ...]
    scope: str


CAPABILITIES: tuple[Capability, ...] = (
    Capability(
        "secrets",
        "Committed credentials and secret-shaped literals",
        (
            "anthropic-api-key",
            "aws-access-key-id",
            "connection-string-dev-password",
            "connection-string-local-host",
            "connection-string-password",
            "generic-assignment",
            "github-pat",
            "jwt-in-code",
            "private-key-block",
            "sql-secret-assignment",
            "stripe-live-key",
            "supabase-anon-key",
            "supabase-demo-key",
            "telegram-bot-token",
        ),
        "Text files in the archive, read as literals: API keys and tokens, private-key blocks, "
        "connection strings carrying a development password or a local host, JWT-looking values, "
        "Supabase anon and demo keys, and secret-shaped assignments. Files over the size limit, "
        "symlinks, dependency and build directories, excluded file types and binary content are "
        "outside this check, and a secret assembled at run time or split across literals is not "
        "reconstructed. " + EXCLUSIONS_NOTE,
    ),
    Capability(
        "rls",
        "Committed SQL suggesting anonymous table access",
        ("rls-table-anon-readable", "rls-table-anon-writable"),
        "Committed SQL in recognized schema/migration paths, processed in filename order: "
        "table declarations, RLS flags and supported policy expressions. Read findings use "
        "private-looking table/column heuristics and public-by-design exclusions; write findings "
        "do not share those exclusions. Missing schema produces no finding. Applied migrations, "
        "effective database grants, runtime identities and actual row access are not verified; "
        "these are source-based access candidates, not observed database exposure.",
    ),
    Capability(
        "schema_drift",
        "Tables the code names that no migration declares",
        ("schema-drift-undeclared-table",),
        "Literal table references in client code and generated-type-shaped declarations, compared "
        "with public tables in committed SQL. No comparison is reported when no public table is "
        "declared; dynamic references and views are not comprehensively resolved. This reports "
        "the GAP, not exposure: a table created outside "
        "the repository, for example through a dashboard, is invisible here, and a missing "
        "declaration does not prove a missing protection.",
    ),
    Capability(
        "project_files",
        "Repository hygiene the file listing alone shows",
        (
            "dependency-dir-committed",
            "env-file-committed",
            "gitignore-missing-secrets",
            "no-ci",
            "no-dockerfile",
            "no-tests",
        ),
        "The archive's file listing, with no code analysis: a committed .env or private-key-shaped "
        "filename, a committed dependency directory, .gitignore coverage missing for secret-bearing "
        "files, and the absence of tests, a Dockerfile or a CI workflow. Each signal yields at most "
        "one finding and describes the repository contents, not the deployment.",
    ),
    Capability(
        "ci_deploy_source",
        "CI that builds one repository and deploys another",
        ("ci-deploys-a-different-repository",),
        "Workflow files read as text: the repository a job checks out, against the deployment "
        "target a URL or identifier names. The deployed target's contents, the credentials used and "
        "the result of any run are not verified.",
    ),
    Capability(
        "service_role",
        "A request handler holding the Supabase service-role key",
        ("supabase-service-role-route",),
        "Files matching Next.js, SvelteKit or Nuxt handler path conventions that read a "
        "service-role environment variable or import a module with that read. One-hop imports "
        "are matched by module basename; equal basenames are not distinguished. General Python "
        "decorator routes, Express routing and Supabase Edge Functions are outside this check. "
        "Client construction, runtime key resolution, authentication and query access are not "
        "verified. A service-role client, if used, bypasses RLS; the source match alone does not "
        "prove a reachable vulnerability.",
    ),
    Capability(
        "error_boundary",
        "A routed React or Next application with no error boundary",
        ("missing-error-boundary",),
        "A routed React or Next application whose source contains no recognized error-boundary "
        "mechanism: no app-router error.tsx or global-error.tsx, no class boundary "
        "(getDerivedStateFromError / componentDidCatch), no react-error-boundary, no <ErrorBoundary> "
        "in the tree. A custom boundary that avoids every standard name is a miss, not a clean "
        "result, and no claim is made about whether a specific render throws. How much of the "
        "repository was read is reported with the audit.",
    ),
    Capability(
        "auth_read_consistency",
        "Object reads that differ from a protected sibling route",
        ("python-route-read-auth-consistency",),
        "Local FastAPI routes in parseable Python files up to 2 MB; "
        "object lookups compared with protected reads on the same router and repository binding, "
        "including recognized identity dependencies and imported aliases; "
        "test/vendor files excluded; middleware and runtime access not resolved",
    ),
    Capability(
        "auth_write_consistency",
        "Write routes that show no identity check their sibling shows",
        ("python-route-write-auth-consistency",),
        "Local FastAPI write routes (POST/PUT/PATCH/DELETE) in "
        "parseable Python files up to 2 MB, compared with sibling routes on the same router; "
        "potential writes are recognized by leading call-name tokens or literal mutating SQL; "
        "actual storage effects, conventionally public paths, "
        "test/vendor files, router-level dependencies and middleware are not resolved",
    ),
    Capability(
        "http_success",
        "A React handler that treats an unchecked fetch as success",
        ("react-unchecked-http-success",),
        HTTP_SUCCESS_SCOPE_PREFIX + "Parser limits are reported per audit.",
    ),
    Capability(
        "sql_injection",
        "SQL text assembled from values instead of parameters (Python)",
        ("sql-injection-string-built-query",),
        "Python statements whose SQL text is assembled from a value the function received, across "
        "expression branches, telling a fixed conditional fragment apart from an input-built query. "
        "A parameterized call is silent. Whether the value is attacker-controlled, and any "
        "database-side policy, is not verified.",
    ),
    Capability(
        "sql_injection_js",
        "SQL text assembled from values instead of parameters (TypeScript/JavaScript)",
        ("sql-injection-string-built-query",),
        "TypeScript/JavaScript statements whose SQL text is assembled from values, which is the half "
        "that runs on the Next.js repositories Drydock audits in the main. Template literals and "
        "concatenation at the call site are read; cross-file builders, ORM query construction and "
        "runtime reachability are not resolved.",
    ),
    Capability(
        "outbound_url",
        "An outbound request whose address comes from the caller",
        ("python-outbound-request-unvalidated-url",),
        "Known HTTP clients in locally declared FastAPI routes; "
        "at most 400 eligible Python files up to 400 KB each. Recognized test/example/documentation "
        "paths are skipped, except migration paths; vendor and dependency trees are not excluded; "
        "20,000 AST nodes and depth 100 per file, 16,000 template characters and 256 slots, "
        "32 findings total. Supported Request fields, locally declared Pydantic string fields, "
        "known-string strip(), URL expressions and preceding local "
        "checks are traced within one handler; complex control flow, unknown calls/helpers, "
        "validation correctness, DNS, redirects, network policy and TS/JS are not resolved",
    ),
    Capability(
        "tls_verification",
        "TLS certificate or hostname verification switched off",
        ("tls-verification-disabled",),
        "At most 400 Python and JS/TS files, each up to "
        "400 KB and 20,000 syntax nodes / depth 100; at most 32 findings. Recognized "
        "test/example/documentation paths are skipped, except migration paths; vendor and "
        "dependency trees are not excluded. Local imports and "
        "client/context aliases identify supported requests/httpx/aiohttp, ssl, urllib3, "
        "Tornado and Elasticsearch settings; JS/TS recognises Node https/tls options and "
        "process.env. Literal False/false, imported ssl.CERT_NONE and exact Node env 0 "
        "are read; hostname and certificate-chain checks have distinct explanations. "
        "Comments, strings, types, malformed/oversized files, unknown wrappers, cross-file "
        "and dynamic configuration, shell/CI YAML and runtime connections are unresolved. "
        "A clean result does not establish that every connection is verified",
    ),
    Capability(
        "unsafe_deserialization",
        "Data turned back into objects through a format that can run code",
        ("unsafe-deserialization",),
        "At most 400 Python files up to "
        "400 KB, 20,000 AST nodes and depth 100. Recognized test/example/documentation paths "
        "are skipped, except migration paths; vendor and dependency trees are not excluded. "
        "Import-resolved loads with lexical "
        "shadowing and stable outer bindings. Unsafe YAML classes must have confirmed "
        "library provenance; Base/Safe/Full loaders are silent. Marshal and missing "
        "YAML Loader produce separate, conditional risk descriptions. Input trust "
        "and dependency versions are not verified. Assignment aliases, conditional "
        "imports, mutated modules, custom YAML loaders, stored Unpickler instances, "
        "cross-file resolution, bare torch.load and TS/JS are not covered; at most "
        "32 findings are reported",
    ),
    Capability(
        "path_traversal",
        "A file path built from a value the caller sent",
        ("path-traversal-file-sink",),
        "Local FastAPI route handlers in parseable Python files up to "
        "400 KB; recognized test/example/documentation paths are skipped, except migration paths. "
        "Vendor and dependency trees are not excluded. Imported file operations and proven pathlib receivers "
        "are traced "
        "locally with bounded expansion. Path construction alone is not a sink. "
        "Containment recognizes imported secure_filename results and a resolved Path "
        "checked against a fixed absolute base on the branch reaching the operation. "
        "Unknown helpers, general control-flow joins, other validation patterns, "
        "runtime symlinks and TS/JS file handling are NOT covered",
    ),
    Capability(
        "session_cookie",
        "A session cookie set without the attributes that protect it",
        ("insecure-session-cookie-attributes",),
        "Cookie-setting calls and settings whose cookie name says it carries identity: "
        "Python `set_cookie`/`set_signed_cookie` with the name as a literal or a "
        "unambiguous module-level constant, the Django settings that decide the session cookie's "
        "flags, and in TypeScript/JavaScript `res.cookie`, a Next.js cookie store, an "
        "express-session nested cookie options, cookie-session top-level options and `document.cookie` "
        "writes. JavaScript names and option objects resolve one hop only when stable, "
        "unambiguous and visible in the current scope. Option keys are case-sensitive. "
        "Which default each API has decides whether an absent option is "
        "reported: `res.cookie` defaults HttpOnly to false, express-session defaults it "
        "to true. Not covered: a missing `secure` attribute (a developer's localhost is "
        "the ordinary reason, and browsers treat localhost as secure), a missing "
        "SameSite (browsers default to Lax; only an explicit SameSite=None removes the "
        "protection), `csrf`/`xsrf`/`state` cookie names (the double-submit pattern "
        "requires script access), raw Set-Cookie header strings, framework config "
        "files, dependency and test paths, cookies set through a wrapper, Python "
        "positional flag arguments, unknown option spreads, and any option whose value "
        "is a variable rather than a literal",
    ),
)

# The checks the static stage reports running, in stable report order.
CHECKS_RUN: tuple[str, ...] = tuple(capability.check for capability in CAPABILITIES)

# Declared scope per check, for the scan to report alongside its findings.
SCOPE: dict[str, str] = {capability.check: capability.scope for capability in CAPABILITIES}

# Every rule id the static engine can report, as declared here.
DECLARED_RULE_IDS: frozenset[str] = frozenset(
    rule_id for capability in CAPABILITIES for rule_id in capability.rule_ids
)


def manifest(engine_version: str) -> dict:
    """The customer-facing manifest: engine revision, then one entry per check."""
    return {
        "engine_version": engine_version,
        "capabilities": [
            {
                "check": capability.check,
                "title": capability.title,
                "rule_ids": list(capability.rule_ids),
                "scope": capability.scope,
            }
            for capability in CAPABILITIES
        ],
    }
