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
        "Your project has no .gitignore rule covering secret files like "
        ".env, private keys, or credential files.",
        "Without it, the next time you run `git add` it's easy to commit "
        "your .env or a key file by accident — handing every password and "
        "API key to anyone who can see the code. This is the most common "
        "way secrets end up leaked.",
        "Add a .gitignore that lists .env, .env.*, *.pem, *.key and other "
        "credential files so they can never be committed by mistake.",
    ),
    "no-tests": (
        "The project has no automated tests.",
        "Every change is a blind edit: things that worked yesterday can "
        "silently break today, and you'll learn it from your users.",
        "Start with a few tests for the money paths — signup, login, "
        "checkout.",
    ),
    "dependency-dir-committed": (
        "Installed libraries are stored in your repository as if you wrote "
        "them.",
        "Every clone downloads all of it, every update to a library lands in "
        "your history, and what is stored slowly stops matching what your "
        "lockfile says the project needs — so the versions running in "
        "production drift away from the ones you think you have.",
        "Add the folder to .gitignore and untrack it with "
        "`git rm -r --cached <folder>`. Your local copy stays; anyone "
        "cloning reinstalls from your lockfile, which is what it is for.",
    ),
    'no-dockerfile': (
        'No Dockerfile was found in the supplied archive.',
        'A Dockerfile is one deployment option. Its absence does not establish that the app '
        'cannot run on a server; systemd and managed platforms are other options.',
        'Review the existing deployment instructions. Add a Dockerfile only if container '
        'deployment is needed.',
    ),
    "missing-error-boundary": (
        "Your app has no error boundary above its pages.",
        "When any single component hits an error while rendering, there is "
        "nothing to contain it: the whole screen goes blank and the person "
        "using it can only reload and hope. One small bug anywhere becomes a "
        "total outage of the page.",
        "Add an error boundary above your routes. In the Next.js app router, "
        "create app/error.tsx and app/global-error.tsx; in a plain React app, "
        "wrap the top-level component in an <ErrorBoundary> with a small "
        "fallback that offers a reload.",
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
        "No automated checks run when the code changes (no CI).",
        "Broken changes reach your live app with nothing in the way.",
        "Add a simple GitHub Actions workflow that runs the tests on "
        "every change.",
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
    if rid in PLAIN and rid in CREDENTIAL_RULES:
        what, risk, fix = PLAIN[rid]
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
    if rid == "no-dockerfile":
        what, risk, fix = PLAIN[rid]
        if finding.get("context") == "deployment_inventory":
            return what, own_risk or risk, own_fix or fix
        return PLAIN[rid]
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
