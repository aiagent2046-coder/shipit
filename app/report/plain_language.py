"""Plain-language layer for the audit report.

The report is read by vibe-coders — founders who built their app with
Lovable/Bolt/v0 and are often not professional developers. A finding
they don't understand doesn't scare them, doesn't get shared, and
doesn't sell a Fix Pack. Every static rule therefore gets a hand-written
translation: what it is, what can actually go wrong (a concrete harm
scenario, not a term of art), and what to do. LLM findings carry their
own plain-language explanation/fix_hint under the same contract (see
SYSTEM_PROMPT in app/scan/llm_scan.py).
"""

from __future__ import annotations

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
    "aws-access-key-id": (
        "An Amazon Web Services key is written directly in your code.",
        "Anyone who sees your code can use your AWS account: run servers "
        "on your credit card, read your stored files, or delete them. "
        "Leaked AWS keys are typically abused within minutes of reaching "
        "a public repo.",
        "Remove the key from the code, revoke it in AWS right away, and "
        "keep the new one in environment variables.",
    ),
    "github-pat": (
        "A GitHub access token is written directly in your code.",
        "Whoever finds it can read and change your repositories as you — "
        "including pushing malicious code your users would then run.",
        "Revoke the token on GitHub and move the new one to environment "
        "variables.",
    ),
    "stripe-live-key": (
        "A live Stripe payment key is written directly in your code.",
        "This key moves real money. Anyone who finds it can issue "
        "refunds, read customer payment data, or create charges.",
        "Roll the key in the Stripe dashboard immediately and keep the "
        "new one in environment variables.",
    ),
    "anthropic-api-key": (
        "An AI provider (Anthropic) key is written directly in your code.",
        "Anyone who finds it can make AI requests on your account and "
        "run up your bill until the provider blocks it.",
        "Revoke the key and keep the new one in environment variables.",
    ),
    "telegram-bot-token": (
        "A Telegram bot token is written directly in your code.",
        "Whoever finds it fully controls your bot: they can read its "
        "messages and impersonate it to your users.",
        "Revoke the token via @BotFather and keep the new one in "
        "environment variables.",
    ),
    "private-key-block": (
        "A private cryptographic key is committed inside the repository.",
        "Private keys are the master secret behind encryption or server "
        "access. Anyone with your code can decrypt what it protects or "
        "log in to what it opens.",
        "Remove it from the repository, rotate the key, and store keys "
        "outside the codebase.",
    ),
    "jwt-in-code": (
        "A login token (JWT) is committed inside the repository.",
        "Depending on the token's power, someone could act as a logged-in "
        "user — or as an administrator — of your app without a password.",
        "Remove it, invalidate the session it belongs to, and never "
        "commit real tokens.",
    ),
    "sql-secret-assignment": (
        "A password or secret is written inside a database migration file.",
        "Migration files live in your code forever — everyone with the "
        "code gets the secret, and 'deleting' it later doesn't remove it "
        "from the project's history.",
        "Move the secret to server-side configuration and rotate it; the "
        "migration should read it from settings, not contain it.",
    ),
    "generic-assignment": (
        "A password or secret appears to be written directly in your code.",
        "Anything committed to code ends up in backups, on GitHub, and on "
        "every laptop that clones the project. It's like taping the "
        "office key to the front door.",
        "Move it to environment variables and rotate the leaked value.",
    ),
    "env-file-committed": (
        # Deliberately says nothing about what is inside. The rule grades
        # itself on the contents now, and this headline sits above both
        # verdicts: "the file that holds ALL your secrets" reads as a lie
        # over a .env that holds a build path.
        "Your .env file is inside the repository.",
        "The .env file usually contains database passwords and API keys "
        "in one place. Committing it hands your entire keychain to "
        "anyone who ever sees the code.",
        "Remove it from the repository, add .env to .gitignore, and "
        "rotate every secret that was inside.",
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
    "no-dockerfile": (
        "The app isn't packaged to run on a server (no Dockerfile).",
        "It runs on the builder's platform, but moving to your own "
        "hosting — often needed for cost or control — will be a wall.",
        "Add a Dockerfile; our Deploy Pack generates a working one "
        "automatically.",
    ),
    "no-ci": (
        "No automated checks run when the code changes (no CI).",
        "Broken changes reach your live app with nothing in the way.",
        "Add a simple GitHub Actions workflow that runs the tests on "
        "every change.",
    ),
}


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
