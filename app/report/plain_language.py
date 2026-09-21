"""Plain-language layer for the audit report.

Describe observations, evidence limits and conditional consequences so the
reader can decide what to verify. A pattern match does not establish that a
credential is live, that a service is reachable, or that an attack succeeded.
"""

from __future__ import annotations

from app.scan.secrets import NON_PRODUCTION_CONTEXTS, is_non_production_path

# severity -> reader-facing tier (technical severity stays in the API
# and in the collapsed developer details)
TIERS = {
    "critical": ("🔥", "Fix before launch"),
    "high": ("⚠️", "Important"),
    "medium": ("👀", "Worth fixing"),
    "low": ("📝", "Good to know"),
}

# rule_id -> (what it is, what can go wrong, what to do)
PLAIN: dict[str, tuple[str, str, str]] = {
    "unsafe-xml-parse": (
        "An XML parse explicitly enables entity resolution.",
        "If the XML is untrusted, resolve_entities=True can allow external entity access. "
        "Input trust, custom resolvers, runtime parser behavior and network controls have not "
        "been verified.",
        "For lxml.etree.parse/fromstring, pass "
        "parser=etree.XMLParser(resolve_entities=False, no_network=True). For lxml.etree.iterparse, "
        "pass resolve_entities=False, no_network=True directly. Verify whether the application "
        "needs entity expansion before changing parsing behavior.",
    ),
    "archive-extraction-fully-trusted": (
        "Archive extraction explicitly disables safety filtering.",
        "tarfile extract or extractall is called with filter=\"fully_trusted\", the explicit "
        "opt-out from extraction checks. A member named with an absolute path or ../ components "
        "then writes outside the destination on every Python with the parameter (measured on "
        "3.12.13: fully_trusted writes outside where the data and tar filters refuse the same "
        "member). Where the archive bytes come from has not been verified.",
        "Drop filter=\"fully_trusted\": pass filter=\"data\" (the 3.14 default) or "
        "filter=\"tar\", or omit the argument on Python 3.14+. Never extract untrusted "
        "archives with filtering disabled.",
    ),
    "command-injection-shell-built-command": (
        "A shell command is built from a value the caller sent.",
        "This route hands a string to a shell -- os.system, os.popen, subprocess with shell=True, "
        "or an explicit POSIX shell -c -- "
        "and that string is assembled from the request itself. A value carrying shell characters (;, "
        "&&, $(...), backticks) can run a second command the application never wrote, up to arbitrary "
        "code as the process user. Whether the route is reachable, whether anything outside this "
        "function constrains the value, and whether the call actually runs have not been verified.",
        "Pass request values as separate arguments to the intended executable, without shell=True "
        "or an explicit shell -c. In a necessary POSIX shell script, keep the script fixed and pass "
        "values as positional parameters with quoted expansions. shlex.quote applies to POSIX shells, "
        "not Windows cmd.exe; validate command and option choices separately.",
    ),
    "insecure-randomness": (
        "A secret-looking value is generated from a non-cryptographic random source.",
        "A token, password, reset link, OTP or nonce is drawn from Math.random or Python's random "
        "module. That source is predictable, so the value can be guessed or replayed -- the classic "
        "account-takeover vector. Whether the value is actually used as a secret and whether anything "
        "else re-randomizes it have not been verified.",
        "Use a cryptographically secure source: crypto.getRandomValues in JS/TS, or Python's secrets "
        "module (secrets.token_hex / secrets.token_urlsafe). Never derive a token, password, reset link, "
        "OTP, nonce or salt from Math.random or the random module.",
    ),
    "python-open-redirect-unvalidated-url": (
        "A redirect targets a URL whose authority comes from the caller.",
        "A redirect constructor sends the visitor's browser to an address whose host is built from the "
        "request itself. A caller who controls the target can redirect a signed-in user to an attacker's "
        "domain -- the open redirect that carries OAuth codes, session tokens in the Referer and phishing "
        "flows. Whether the route is reachable and whether anything outside this function constrains the "
        "target have not been verified.",
        "Validate the target before redirecting: allow only relative paths, or compare the resolved host "
        "against an allowlist of your own origins and reject everything else (including protocol-relative "
        "//host and backslashes that some parsers read as //host). Never redirect straight to a value the "
        "request supplied.",
    ),
    "xss-unsafe-html-injection": (
        "HTML is injected into the DOM from a value that is not a fixed string.",
        "A non-literal value reaches an HTML-injection sink -- dangerouslySetInnerHTML, innerHTML/outerHTML, "
        "document.write, insertAdjacentHTML or Vue v-html. If that value can carry attacker-controlled text, "
        "it injects markup and script into the page: script execution under the visitor's origin, token theft and DOM "
        "corruption. Whether the value was sanitized, whether it is reachable, and whether the sink runs "
        "have not been verified.",
        "Use textContent, React children, or Vue interpolation/v-text for plain text. If HTML must be inserted, "
        "sanitize the value first (DOMPurify with an allowlist, or an equivalent) and avoid building HTML "
        "from strings. In React, avoid dangerouslySetInnerHTML unless the content is already trusted.",
    ),
    "path-traversal-file-sink": (
        "A file path is built from a value the caller sent.",
        "This route hands a filesystem path to a file operation, and that path is assembled from the "
        "request itself. A value like ../../etc/passwd, or a name ending in a served extension, can "
        "make the application read or write files it never meant to touch. Whether anything outside "
        "this function constrains the path has not been checked.",
        "Keep only a name, not a path: pass the value through secure_filename (or whitelist its "
        "characters), join it to a fixed base directory, then confirm the result is still inside that "
        "base with resolve() and is_relative_to(). Never serve a file by a path that came straight "
        "from the request.",
    ),
    "insecure-session-cookie-attributes": (
        "A session cookie is set without the protection the browser offers.",
        "The cookie that carries the session is created without HttpOnly, which keeps it out of reach of "
        "scripts, or with SameSite=None, which tells the browser to send it on cross-site requests too. "
        "Either way a flaw elsewhere -- a script that reaches the page, or a form on another site -- can "
        "use the session. Whether the value is a live session token, whether another layer rewrites the "
        "cookie, and whether the request is reachable have not been verified.",
        "Set HttpOnly on the session cookie (httponly=True in Python, httpOnly: true in TypeScript) and "
        "leave SameSite at its default or set it to Lax/Strict. Use SameSite=None only when the cookie "
        "must cross sites, keep Secure on, and verify the request origin wherever the cookie authorizes "
        "a change.",
    ),
    "unsafe-deserialization": (
        'A deserialization call requires trusted input or an explicit loader.',
        'Pickle-family and confirmed unsafe YAML loaders can invoke code while reconstructing '
        'objects. Marshal reconstructs values or code objects without executing those objects; YAML '
        'without Loader depends on the installed version and raises TypeError in modern PyYAML. The '
        'finding describes which case was observed. Input trust and runtime exploitability have not '
        'been verified.',
        'Prefer json (or msgpack/cbor) with an explicit schema, or yaml.safe_load for YAML values. '
        'If object serialization is unavoidable, accept only trusted producers and verify an HMAC '
        'or digital signature before loading. A checksum supplied with untrusted bytes does not '
        'authenticate them; an expected digest must come from a trusted source.',
    ),
    "tls-verification-disabled": (
        "TLS certificate or hostname verification is weakened.",
        "A recognised client/context setting weakens peer-identity checks. Disabling hostname matching "
        "can leave certificate-chain validation enabled; disabling chain validation is a different "
        "setting. The finding identifies the control seen in source. Runtime use and exposure have "
        "not been verified.",
        "Restore the affected check: require a trusted certificate chain and match the expected "
        "hostname. Configure the client's supported CA/context option for private certificates "
        "instead of disabling verification.",
    ),
    "python-outbound-request-unvalidated-url": (
        "An HTTP client receives an address derived from request input.",
        "A caller-controlled value reaches the host portion of a request target or client "
        "configuration without a preceding local address check recognized by the scanner. "
        "If external controls do not restrict it, a request may reach unintended services. "
        "Runtime requests, network reachability and checks outside this handler have not been verified.",
        "Allow only approved schemes and hosts. Check resolved addresses against the permitted "
        "destinations, including private and link-local ranges, and ensure the connection uses the "
        "address that was checked. Disable redirects or validate every redirect destination too.",
    ),
    "python-route-write-auth-consistency": (
        "A route contains a call recognized as a write and shows no local identity check.",
        "A sibling write route on the same router declares an identity check. This is a local "
        "consistency signal based on calls and dependency names; actual changes to stored data, "
        "middleware, router mounting and runtime access have not been verified.",
        "Confirm whether this route is meant to be reachable without an identity -- a webhook or an "
        "onboarding step would be. If not, apply the sibling route's identity contract, then test a "
        "write with a foreign or absent credential against synthetic records.",
    ),
    "python-route-read-auth-consistency": (
        "Object lookup differs from protected sibling routes.",
        'A local route uses a different lookup from protected sibling routes. Global '
        'authorization is unresolved.',
        "Check ownership authorization and reproduce missing/wrong-token access using synthetic records.",
    ),
    'aws-access-key-id': (
        'A value matches the AWS access key ID format.',
        'An access key ID alone cannot authenticate AWS requests; a matching secret access key '
        'is also required. This scan has not checked validity or permissions.',
        'Check whether this is synthetic. If a real credential pair was exposed, revoke it and '
        'move its replacement outside the repository.',
    ),
    'github-pat': (
        'A value matches a GitHub token format.',
        'If this is a valid token, its permissions may allow access to repositories. The scan '
        'has not checked validity, scope or expiry.',
        'Confirm whether the value is synthetic. Revoke an exposed real token and store its '
        'replacement outside the repository.',
    ),
    'stripe-live-key': (
        'A value matches a Stripe live-key format.',
        'A valid key may allow payment operations within its permissions. A format match does '
        'not establish that this key works or which operations it permits.',
        'Check whether this is a fixture. Rotate an exposed real key and store its replacement '
        'in server configuration.',
    ),
    'anthropic-api-key': (
        'A value matches an Anthropic API key format.',
        'If valid, the key may permit billed API calls. This scan has not tested the credential '
        'or established access to an account.',
        'Check whether the value is synthetic. Revoke an exposed real key and store its '
        'replacement outside the repository.',
    ),
    'telegram-bot-token': (
        'A value matches a Telegram bot token format.',
        'If valid, a token may allow bot API operations. Its validity and the scope of '
        'accessible messages have not been checked.',
        'Check whether this is a fixture. Revoke an exposed real token through BotFather and '
        'store the replacement outside the repository.',
    ),
    'private-key-block': (
        'A private-key marker appears in the source.',
        'The marker may be a test string or part of a usable private key. Completeness, '
        'validity and deployment use have not been checked.',
        'Inspect the surrounding material without publishing it. Rotate an exposed real key and '
        'keep its replacement outside the repository.',
    ),
    'jwt-in-code': (
        'A value resembles a JWT in the source.',
        'A valid, unexpired token may grant its associated permissions. This scan has not '
        'verified its signature, expiry or acceptance by a service.',
        'Check whether this is a test token. Invalidate an exposed real session token and avoid '
        'committing replacements.',
    ),
    'sql-secret-assignment': (
        'A SQL-style assignment contains a credential-like value.',
        'This may be SQL code, a quoted example or a test fixture. The scan has not established '
        'that the value is real or used by a deployed database.',
        'Check the context and use of the value. Rotate an exposed real secret and read its '
        'replacement from server configuration.',
    ),
    'generic-assignment': (
        'An assignment contains a credential-like value.',
        'The name and value match a secret pattern. This does not establish that the value is a '
        'live credential or that a service accepts it.',
        'Check the value and context. Rotate an exposed real credential; synthetic test data '
        'does not require account-level rotation.',
    ),
    'connection-string-password': (
        'A connection URI contains a password-like value.',
        'If it names a reachable service and valid credentials, it may permit access within '
        "that account's permissions. Reachability, validity and grants are not "
        'checked.',
        'Check whether this is a fixture. If real service credentials were exposed, change the '
        'password and move configuration outside the repository.',
    ),
    "connection-string-dev-password": (
        "A URI contains a conventional password or placeholder.",
        "Values such as postgres or change_me are commonly used in examples. The value alone "
        "does not establish whether this is a template, local setup or live configuration. "
        "If a real service accepts it, the password is predictable.",
        "Check where the URI is used. Replace a default used by a real service; "
        "a synthetic example does not require credential rotation.",
    ),
    'env-file-committed': (
        'An environment configuration file is included in the archive.',
        'Such files may contain configuration or credentials. File presence alone does not '
        'establish that a real secret was exposed.',
        'Inspect the contents. Keep private environment files outside version control and '
        'rotate any exposed real credentials.',
    ),
    'connection-string-local-host': (
        'A local or development connection URI contains a password-like value.',
        'The hostname suggests a local or container service, but deployment and password reuse '
        'have not been checked. This is not evidence of public database access.',
        'Check whether this value is synthetic or reused on a real service. Rotate exposed real '
        'credentials where they are used.',
    ),
    "supabase-demo-key": (
        "This is Supabase's local-development demo key, which ships with "
        "every project.",
        "It is not a key to your database. `supabase start` prints this "
        "same token for every developer, and the secret it is signed with "
        "is published in Supabase's own documentation — so anyone can "
        "produce an identical one, which is what makes it open nothing. "
        "The keys that must stay secret are the service_role key and the "
        "database password from your real project's dashboard, and those "
        "look the same to the eye.",
        "Nothing to rotate — there is no account behind this token. Do "
        "check that the key your deployed app actually uses comes from an "
        "environment variable and not from a committed file, because that "
        "one would matter.",
    ),
    "supabase-anon-key": (
        "Your Supabase anon (public) key appears in the code.",
        "This particular key is meant to be public — it ships in every "
        "app's front-end by design, so this is informational, not a "
        "breach. Seeing it in many committed files usually just means "
        "the same key was pasted around; the keys that must stay secret "
        "are the service_role key and database passwords, which are NOT "
        "flagged here.",
        "No urgent action needed for the anon key itself. Do confirm "
        "your Row Level Security is on, since the anon key relies on it.",
    ),
    "gitignore-missing-secrets": (
        "An environment-file path is not covered by the repository's ignore rules.",
        "An unignored private configuration file could be added to a future commit. "
        "This is a source configuration gap, not evidence that credentials were exposed. "
        "Machine-local and global Git exclusions are not available in the archive.",
        "Add a rule for the reported private configuration path. Keep intentional public "
        "configuration and example files available; inspect already tracked files separately.",
    ),
    "no-tests": (
        "The project has no automated tests.",
        "Every change is a blind edit: things that worked yesterday can "
        "silently break today, and you'll learn it from your users.",
        "Start with a few tests for the money paths — signup, login, "
        "checkout.",
    ),
    "dependency-dir-committed": (
        "The archive includes a folder commonly used for installed libraries or generated files.",
        "These files can make a source archive larger and harder to review. "
        "Folder names alone do not establish Git tracking, how the files were "
        "created, or whether they are intentional copies of third-party source.",
        "Check whether the folder can be recreated from the project's installation "
        "instructions. If so, exclude it from future source archives. Check Git "
        "tracking separately before removing tracked copies or adding ignore rules. "
        "Keep intentional third-party source and test data when needed.",
    ),
    'no-dockerfile': (
        'No Dockerfile was found in the supplied archive.',
        'A Dockerfile is one deployment option. Its absence does not establish that the app '
        'cannot run on a server; systemd and managed platforms are other options.',
        'Review the existing deployment instructions. Add a Dockerfile only if container '
        'deployment is needed.',
    ),
    "missing-error-boundary": (
        "The static check did not find a recognized error boundary in the inspected app source.",
        "If a rendering error reaches the root without a working boundary, the "
        "affected screen may go blank. This check uses selected files and known "
        "names within read limits; custom boundaries may not be recognized. "
        "Runtime behavior was not tested.",
        "Check how the reported application entry point handles rendering errors. "
        "If a suitable boundary is missing, add one for the relevant routes or root "
        "layout. Then trigger a controlled rendering error and verify that the user "
        "sees a recovery option.",
    ),
    "react-unchecked-http-success": (
        "A handler continues to a success state or navigation without checking its HTTP response.",
        "Standard fetch resolves even on HTTP 4xx/5xx. On the observed path a rejected save could "
        "therefore appear successful. A real server failure and runtime bindings were not tested.",
        "Check response.ok before showing success or navigating. Handle failed HTTP responses "
        "and reset loading state when a network request rejects.",
    ),
    "sql-injection-string-built-query": (
        "A database query is built by joining strings together instead of passing the values "
        "as parameters.",
        "Whatever ends up in that string is read by the database as SQL, not as data. If any "
        "part of it comes from a request, a form or a URL, someone can change what the query "
        "does and read or delete rows that are not theirs. Whether this particular value is "
        "reachable from user input was not verified; the string assembly is what was observed.",
        "Pass the values as parameters and keep the query text a plain literal: "
        "cur.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,)). Where a table or column "
        "name genuinely has to vary, pick it from a fixed list in your own code.",
    ),
    "no-ci": (
        "No recognized CI configuration file was found in the archive.",
        "External CI services, repository settings and actual build runs were not checked. "
        "The absence of a configuration file does not establish that no automation runs.",
        "Check existing CI integrations. If none run the project's checks, add a workflow "
        "that builds the application and runs its tests on changes.",
    ),
}


CREDENTIAL_RULES = frozenset({
    'anthropic-api-key',
    'aws-access-key-id',
    'connection-string-local-host',
    'connection-string-dev-password',
    'connection-string-password',
    'generic-assignment',
    'github-pat',
    'jwt-in-code',
    'private-key-block',
    'sql-secret-assignment',
    'stripe-live-key',
    'telegram-bot-token',
})


def _uses_bounded_static_copy(finding: dict) -> bool:
    """Mirror the browser's narrow overlay without replacing separate assessments."""
    if (finding.get("source") != "static"
            or finding.get("verification_status") == "contradicted"
            or finding.get("context") not in (None, "")):
        return False
    evidence = finding.get("claim_evidence")
    if evidence is not None:
        if not isinstance(evidence, dict):
            return False
        syntax = evidence.get("syntax_check")
        if ((syntax is not None and not isinstance(syntax, dict))
                or isinstance(syntax, dict) and syntax.get("result") == "contradicted"
                or any(value is not None and not (isinstance(value, list) and not value)
                       for value in (evidence.get("source_assessments"), evidence.get("premise_checks")))):
            return False
    return True


def plain_fields(finding: dict) -> tuple[str, str, str]:
    """(what, risk, fix) for any finding.

    Static rules come from the hand-written dictionary; LLM findings
    (rule_id llm-*) carry their own plain-language text produced under
    the prompt contract. Falls back to the technical title so an
    unknown rule degrades to the old behavior, never to an empty row.
    """
    rid = str(finding.get("rule_id", ""))
    own_risk = str(finding.get("explanation", "")).strip()
    own_fix = str(finding.get("fix_hint", "")).strip()
    evidence = finding.get("claim_evidence")
    if (rid == "dependency-cve-match" and isinstance(evidence, dict)
            and evidence.get("remediation") is not None
            and evidence.get("snapshot_check_status") == "retained_not_reconfirmed"):
        return (finding.get("title") or "Recorded dependency match", own_risk,
                "The current check could not reconfirm this dependency match. Repeat the advisory check "
                "before choosing an upgrade; previously recorded upgrade candidates have not been reconfirmed.")
    if rid in PLAIN and rid in CREDENTIAL_RULES:
        what, risk, fix = PLAIN[rid]
        if rid == "sql-secret-assignment" and not str(finding.get("file", "")).lower().endswith((".sql", ".psql")):
            # Match the source-language boundary used by _classify_match:
            # this rule also catches ordinary code and documentation assignments.
            what, risk, fix = PLAIN["generic-assignment"]
        evidence = finding.get("claim_evidence") or {}
        source_context = finding.get("source_context") or evidence.get("source_context") or {}
        if rid == "generic-assignment" and source_context.get("kind") == "translation_label":
            return ("Credential-shaped name in a translation label",
                    "The value is label-like text in a parsed translation catalog. This is usually UI copy. "
                    "The candidate is retained because a catalog can also contain a real credential.",
                    "Check that this is display text. A label needs no credential rotation; "
                    "rotate only if you establish that the value is an exposed real credential.")
        context = finding.get("context")
        example = (context in NON_PRODUCTION_CONTEXTS if context
                   else is_non_production_path(str(finding.get("file", ""))))
        if example:
            risk = "Found in a test, example or comment context. " + risk
            fix = "Verify that this value is synthetic. " + fix
        count = finding.get("occurrence_count")
        if count and count > 1:
            risk += f" {count} occurrences are recorded; inspect each location."
            files = finding.get("occurrence_files", [])
            if files:
                risk += " Files: " + ", ".join(files) + "."
        return what, risk, fix
    if rid == "env-file-committed" and finding.get("context") == "public_configuration":
        return (
            "Public-looking environment configuration is included in the archive.",
            own_risk or "The recognized values look like public build or development settings. "
            "This does not establish whether every value is safe to publish.",
            own_fix or "Keep intentional public configuration; store private credentials separately.",
        )
    if rid == "no-dockerfile":
        what, risk, fix = PLAIN[rid]
        if finding.get("context") == "deployment_inventory":
            return what, own_risk or risk, own_fix or fix
        return PLAIN[rid]
    if rid in {"dependency-dir-committed", "missing-error-boundary"}:
        # Stored findings used to infer Git tracking or a total runtime outage.
        # Keep originals and separate model/source assessments intact.
        if _uses_bounded_static_copy(finding):
            return PLAIN[rid]
        return (finding.get("title") or "Recorded observation",
                finding.get("explanation") or "", finding.get("fix_hint") or "")
    if rid in PLAIN:
        what, risk, fix = PLAIN[rid]
        # The finding's own text wins where it has any.
        #
        # This dictionary predates #217, when static rules carried no
        # explanation at all and this was the only prose a static finding
        # had. #217 gave every rule its own explanation and fix_hint --
        # and because the branch below treated `explanation` as nothing
        # but collapse_repeats' occurrence note, the report has since been
        # printing BOTH: the dictionary's wording followed by the rule's
        # own, saying the same thing twice in different words.
        #
        # It stopped being merely repetitive once env-file-committed began
        # grading itself on the file's contents. A .env holding a build
        # path yields "nothing is exposed yet" appended to "Committing it
        # hands your entire keychain to anyone who ever sees the code" --
        # one paragraph making both claims, under a fix that says to
        # rotate every secret inside. The rule knows which case it found;
        # the dictionary cannot.
        #
        # `what` still comes from here: it is a friendlier headline than
        # the technical title, and CheckFinding has no equivalent field.
        # The occurrence note rides along inside `explanation`, so it
        # survives without special handling.
        return what, own_risk or risk, own_fix or fix
    what = str(finding.get("title", ""))
    risk = str(finding.get("explanation", ""))
    fix = str(finding.get("fix_hint", ""))
    return what, risk, fix


def tier(severity: str) -> tuple[str, str]:
    return TIERS.get(severity, ("📝", "Good to know"))
