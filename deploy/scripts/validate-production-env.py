#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

# A value that STARTS with something shaped like an environment variable name
# followed by '=' is a line that got glued onto the one above it. On 2026-07-31
# a nano paste did exactly that:
#
#     USDT_TRC20_ADDRESS=USDT_POLL_TOKEN=a9f5b6c4...
#
# and USDT_POLL_TOKEN was restored from a backup afterwards, so BOTH names were
# present and non-empty. Every check in this file passed. The address was
# garbage, POST /internal/billing/poll-usdt answered 503 on every run for two
# days, and no USDT payment was confirmed in that window -- a customer who paid
# just saw an invoice stay `pending`.
#
# Only the start of the value is examined. An '=' further along is ordinary --
# connection strings and base64 padding are full of them.
GLUED_LINE = re.compile(r"^([A-Z][A-Z0-9_]{2,})=")

# Variables that configured a payment rail this product no longer has. Kept as
# a list rather than deleted with the code, because the .env on a running host
# is not rewritten by a deploy: these lines survive the removal, and a set value
# reads to the operator as a live rail.
RETIRED_RAIL_VARIABLES = (
    "PAYPAL_CLIENT_ID",
    "PAYPAL_CLIENT_SECRET",
    "PAYPAL_ENV",
    "PAYPAL_MONITOR_PLAN_ID",
    "PAYPAL_WEBHOOK_ID",
    "USDT_POLL_TOKEN",
    "USDT_TRC20_ADDRESS",
    "TRONGRID_API_KEY",
    # Stars prices. TELEGRAM_BOT_TOKEN is NOT here and must not be: the bot
    # survived the removal of the Stars sale, and it is both the operator's
    # bank-transfer confirm button and the only notification channel there is.
    "TELEGRAM_PRO_STARS",
    "FIXPACK_STARS_PRICE",
    "SUBSCRIPTION_STARS",
    # Dollar prices, from before the product was repriced in roubles on
    # 2026-08-23. These are the most dangerous names on this list: unlike the
    # rest, which configure rails that no longer exist, these configure a rail
    # that DOES -- and the code no longer reads them. A host that still carries
    # BANK_TRANSFER_FIXPACK_PRICE_USD=10.00 does not fail, does not warn, and
    # quietly charges the rouble default while its operator believes the .env
    # is in charge of the price. The reverse would be worse still: had the new
    # accessors kept the old names, "10.00" would have been read as ten
    # ROUBLES for a 990-rouble product.
    "BANK_TRANSFER_PRO_PRICE_USD",
    "BANK_TRANSFER_FIXPACK_PRICE_USD",
)


def read_env_file(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        name, value = line.split("=", 1)
        name = name.strip()
        value = value.strip()

        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {"'", '"'}
        ):
            value = value[1:-1]

        result[name] = value

    return result


def duplicate_assignments(path: Path) -> dict[str, list[tuple[int, str]]]:
    """Names assigned more than once, with each line number and value.

    read_env_file returns a dict, so a repeated name is silently collapsed to
    whichever line came last -- and the collapse is the danger, because
    SYSTEMD PARSES THIS FILE TOO and nothing here guarantees the two agree
    about which assignment wins.

    Both halves of this happened on 2026-08-28, in one hand edit:

        5:  FREE_TIER_LLM_MODEL=glm-5.3-flash
        59: FREE_TIER_LLM_MODEL=claude-haiku-4.5
        40: SANDBOX_RUNNER_TOKEN=<x>
        41: SANDBOX_RUNNER_TOKEN=<the same x>

    and this script printed "Production configuration is valid" over both.

    A duplicate is never intentional -- an env file has no use for saying the
    same name twice -- so it is always worth reporting. What it costs depends
    on whether the values differ; see main().
    """
    seen: dict[str, list[tuple[int, str]]] = {}
    for number, raw_line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        seen.setdefault(name.strip(), []).append((number, value.strip()))
    return {name: hits for name, hits in seen.items() if len(hits) > 1}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", type=Path)
    args = parser.parse_args()

    if args.env_file:
        if not args.env_file.exists():
            print(f"Environment file not found: {args.env_file}", file=sys.stderr)
            return 78

        # The file, and nothing but the file. This process is not the service:
        # under systemd it runs as ExecStartPre with root's environment, while
        # shipit.service starts with EnvironmentFile= alone. Merging os.environ
        # in meant the validator could pass on values the service would never
        # see -- and it did. A nano edit deleted USDT_POLL_TOKEN from .env;
        # systemd's run correctly refused to start, while the identical command
        # typed by hand printed "Production configuration is valid", because
        # the operator's shell happened to export it. The one check that exists
        # to catch a broken config reported green about a broken config.
        values = read_env_file(args.env_file)
    else:
        # No file given: validating the ambient environment IS the request.
        values = dict(os.environ)

    if "ENVIRONMENT" not in values:
        if args.env_file:
            # Not silent. Skipping every check is the most dangerous outcome
            # this script has, so it may not happen quietly -- that would just
            # be the same false green wearing a different hat.
            print(
                f"Warning: {args.env_file} defines no ENVIRONMENT; "
                "production checks skipped",
                file=sys.stderr,
            )
        return 0

    if values["ENVIRONMENT"] != "production":
        return 0

    errors: list[str] = []
    # Two severities on purpose. An `errors` entry exits 78, which fails the
    # ExecStartPre and so refuses to start shipit.service -- correct for a value
    # whose absence breaks the service, wrong for one whose absence only costs
    # visibility. Warnings are printed and ignored by the exit code, so adding
    # one can never take a host down that was up before.
    warnings: list[str] = []

    required = (
        "DATABASE_URL",
        "API_KEY_PEPPER",
        "PREVIEW_REAP_TOKEN",
        "FIXPACK_PROCESS_TOKEN",
        "MONITORING_PROCESS_TOKEN",
        "SERVICE_FLAGS_TOKEN",
        "CORS_ALLOWED_ORIGINS",
    )

    for name in required:
        if not values.get(name, "").strip():
            errors.append(f"{name} is required in production")

    # Split by whether the two assignments actually disagree, because the two
    # cases cost different amounts and only one of them is worth refusing a
    # boot over.
    #
    # DIFFERENT values are an error: the config is ambiguous, and which one
    # takes effect depends on a parser nobody here chose. On 2026-08-28
    # FREE_TIER_LLM_MODEL was glm-5.3-flash on line 5 and claude-haiku-4.5 on
    # line 59, which is the difference between the free preview costing $0.008
    # and $0.12 -- decided by tie-break.
    #
    # IDENTICAL values are a warning: redundant, certainly an editing slip,
    # but the service gets the same value whichever line wins. Erroring here
    # would refuse to start a host that is running correctly, which is a worse
    # failure than the one being prevented.
    if args.env_file:
        for name, hits in sorted(duplicate_assignments(args.env_file).items()):
            lines = ", ".join(str(number) for number, _ in hits)
            if len({value for _, value in hits}) > 1:
                errors.append(
                    f"{name} is assigned {len(hits)} times with DIFFERENT "
                    f"values (lines {lines}); which one takes effect depends "
                    "on the parser -- keep exactly one"
                )
            else:
                warnings.append(
                    f"{name} is assigned {len(hits)} times with the same "
                    f"value (lines {lines}); harmless, but it is an editing "
                    "slip -- keep exactly one"
                )

    # An OpenAI-compatible provider with no model name pinned.
    #
    # app/llm/client.py falls back to DEFAULT_MODEL, which is Anthropic's
    # canonical DASHED spelling (claude-sonnet-4-6). AITunnel wants the dotted
    # one and answers 400 to the other:
    #
    #     Указанная модель (claude-sonnet-4-6) не найдена
    #
    # Nothing crashes. The API serves, the queue drains, jobs finish
    # `succeeded` with no error_code -- and every paid audit comes back
    # static-only under a paid basis, because the LLM stage failed and
    # degraded exactly as designed. Measured on 2026-08-28, when a hand edit
    # replaced the LLM_MODEL line and the next restart picked the code default
    # up. The only visible trace was a `basis` field inside score_json.
    #
    # An error rather than a warning: this is not lost visibility, it is the
    # product's paid path returning the free tier's output. It can only fire
    # on a deployment that configured this provider and pinned no model, which
    # is the broken state itself -- a host that is working has one of these
    # set, so this cannot refuse a boot that would have succeeded.
    if values.get("AITUNNEL_BASE_URL", "").strip() and not (
        values.get("LLM_MODEL", "").strip()
        or values.get("AITUNNEL_LLM_MODEL", "").strip()
    ):
        errors.append(
            "AITUNNEL_BASE_URL is set but neither LLM_MODEL nor "
            "AITUNNEL_LLM_MODEL is: the code falls back to its default model "
            "name, which this provider rejects with a 400 -- every paid audit "
            "would silently return static-only"
        )

    # A warning, not a requirement: every token above gates a side-effecting
    # /internal endpoint that a systemd timer drives, so a missing one silently
    # stops real work. AUDIT_JOBS_STATS_TOKEN only gates the two read-only
    # stats endpoints -- unset means they 503 and an operator loses a dashboard,
    # which is not worth refusing to boot the API over.
    if not values.get("AUDIT_JOBS_STATS_TOKEN", "").strip():
        warnings.append(
            "AUDIT_JOBS_STATS_TOKEN is not set; GET /internal/stats and "
            "GET /internal/audit-jobs/stats are disabled (queue depth, LLM "
            "spend and error rate are unreadable)"
        )

    # A configured payment rail with no way to confirm a payment is the worst
    # shape this file can let through, because every part of it fails closed
    # correctly and so nothing complains.
    #
    # Bank transfer is the live rail. The payer gets the details, pays, and
    # presses "I've paid"; that pages the operator on Telegram, and access is
    # granted only when the operator taps Confirm on that message. With
    # TELEGRAM_BOT_TOKEN or TELEGRAM_ADMIN_CHAT_ID unset, notify_operator
    # returns False and sends nothing (app/alerts.py), and _is_operator
    # returns False for EVERYONE including the operator
    # (app/billing/telegram_stars.py) -- both by design, both silent. Money
    # arrives and no one can act on it.
    #
    # TELEGRAM_WEBHOOK_SECRET is the same story one step later: the webhook
    # 503s without it, so the Confirm tap never reaches the application.
    #
    # An error rather than a warning: a checkout that cannot deliver what it
    # sells should not boot. It only fires when a rail is actually configured,
    # so a deployment selling nothing is unaffected.
    bank_configured = any(
        values.get(name, "").strip() for name in (
            "BANK_TRANSFER_CARD", "BANK_TRANSFER_ACCOUNT",
        )
    )
    rails_configured = bank_configured

    if rails_configured:
        for name in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_ADMIN_CHAT_ID",
                     "TELEGRAM_WEBHOOK_SECRET"):
            if not values.get(name, "").strip():
                errors.append(
                    f"{name} is required when a payment rail is configured: "
                    "without it a paid invoice can never be confirmed, and "
                    "nothing reports the failure"
                )

    # A WARNING, NOT AN ERROR, and the difference is what it costs to be
    # missing: the bot still delivers keys and still receives /link, it just
    # cannot be OFFERED. Without a username the site can build no deep link, so
    # the "get updates in Telegram" button never renders and a buyer who would
    # have taken that channel is silently given only email. Refusing to boot
    # over a convenience channel would be worse than the gap it closes.
    if values.get("TELEGRAM_BOT_TOKEN", "").strip() and not values.get(
        "TELEGRAM_BOT_USERNAME", ""
    ).strip():
        warnings.append(
            "TELEGRAM_BOT_USERNAME is not set: the bot works, but the site "
            "cannot build t.me/<bot>?start=… so no customer is ever offered "
            "Telegram. scripts/set_telegram_commands.py prints the name"
        )

    aitunnel_key = bool(values.get("AITUNNEL_API_KEY", "").strip())
    aitunnel_url = bool(values.get("AITUNNEL_BASE_URL", "").strip())

    if aitunnel_key != aitunnel_url:
        errors.append(
            "AITUNNEL_API_KEY and AITUNNEL_BASE_URL must be configured together"
        )

    # Format checks. These never print the offending value: on 2026-08-02 an
    # error message that echoed USDT_TRC20_ADDRESS put a live bearer token --
    # which is what the variable wrongly held -- into the journal and into an
    # HTTP response body. A check that names the variable is just as actionable
    # and cannot leak what it is looking at.
    for name, value in sorted(values.items()):
        glued = GLUED_LINE.match(value)
        if glued and glued.group(1) != name:
            errors.append(
                f"{name} starts with '{glued.group(1)}=', so the line for "
                f"{glued.group(1)} was appended to it instead of standing on "
                f"its own; both {name} and {glued.group(1)} are wrong"
            )

    # HALF A DELIVERY CHANNEL, which is indistinguishable from none except
    # that it looks configured.
    #
    # app/notify/email.py returns False and raises nothing when SMTP_HOST or
    # SMTP_FROM is missing -- deliberately, so a deployment without mail does
    # not fail a refund it could not announce. The cost of that contract is
    # that a TYPO looks exactly like a decision: a customer is never told
    # their money came back, and the only sign is an operator alert saying
    # nobody could be reached.
    #
    # So the pair is checked the way USDT_POLL_TOKEN was, and for the reason
    # that outage taught: a value that is required only because another one is
    # set is the kind nobody notices is missing.
    smtp_host = bool(values.get("SMTP_HOST", "").strip())
    smtp_from = bool(values.get("SMTP_FROM", "").strip())
    if smtp_host != smtp_from:
        errors.append(
            "SMTP_HOST and SMTP_FROM must be configured together; with only "
            "one set, email is silently off and a customer who is not on "
            "Telegram is never told their refund was sent"
        )

    # Same shape one level down. A username with no password authenticates as
    # nobody: every send fails, and it fails inside a best-effort call whose
    # whole contract is not to complain.
    smtp_user = bool(values.get("SMTP_USERNAME", "").strip())
    smtp_pass = bool(values.get("SMTP_PASSWORD", "").strip())
    if smtp_user != smtp_pass:
        errors.append(
            "SMTP_USERNAME and SMTP_PASSWORD must be configured together "
            "(set neither for a relay that authenticates by IP)"
        )

    # ЮKassa, same shape again and the highest stakes of the three. A shop id
    # with no secret key cannot sign a request, so every attempt to open a
    # payment 503s -- at the checkout, in front of a buyer who was ready to pay.
    shop_id = bool(values.get("YOOKASSA_SHOP_ID", "").strip())
    secret_key = bool(values.get("YOOKASSA_SECRET_KEY", "").strip())
    if shop_id != secret_key:
        errors.append(
            "YOOKASSA_SHOP_ID and YOOKASSA_SECRET_KEY must be configured "
            "together; with only one set the card checkout answers 503 to "
            "every buyer"
        )

    # A live shop holding a test key takes no money at all, and the symptom is
    # "nobody is buying" rather than anything that looks like a misconfiguration
    # -- so it is worth saying out loud on a production host. A warning, not an
    # error: a deployment deliberately running against the test shop is a
    # legitimate state, and refusing to boot would make testing impossible.
    if secret_key and values.get("YOOKASSA_SECRET_KEY", "").strip().startswith(
        "test_"
    ):
        warnings.append(
            "YOOKASSA_SECRET_KEY is a test key (test_…): payments opened on "
            "this host are not real and no money will arrive"
        )

    # Receipts are a legal position rather than a technical one, and the code
    # sends none without this. Saying so is the difference between a decision
    # and an omission nobody remembers making.
    if not values.get("YOOKASSA_VAT_CODE", "").strip():
        warnings.append(
            "YOOKASSA_VAT_CODE is not set: payments are opened without a "
            "54-ФЗ receipt. Correct if this merchant does not issue them"
        )

    # A variable belonging to a rail that no longer exists. Not an error --
    # a leftover line hurts nothing and refusing to boot over it would be an
    # outage caused by tidiness -- but it must be SAID, because an operator who
    # sees USDT_TRC20_ADDRESS in .env has every reason to believe that rail is
    # live and that money sent to it will be noticed. It will not be. Nothing
    # reads these any more.
    for name in sorted(RETIRED_RAIL_VARIABLES):
        if values.get(name, "").strip():
            warnings.append(
                f"{name} is set, but the payment rail it configured was "
                "removed: nothing reads it, and money arriving on that rail "
                "will not be seen by anything. Delete the line."
            )

    database_url = values.get("DATABASE_URL", "").strip()
    if database_url and not database_url.startswith(("postgresql://", "postgres://")):
        errors.append(
            "DATABASE_URL does not start with postgresql:// or postgres://"
        )

    # A warning, not an error. The convention is `openssl rand -hex 32`, but
    # nothing enforces it, and refusing to boot over a short-but-working token
    # would turn a note about strength into an outage.
    for name, value in sorted(values.items()):
        if name.endswith("_TOKEN") and 0 < len(value.strip()) < 16:
            warnings.append(
                f"{name} is shorter than 16 characters; the convention for "
                "these is `openssl rand -hex 32`"
            )

    for name, value in values.items():
        if " #" in value and (
            "KEY" in name
            or "TOKEN" in name
            or "SECRET" in name
            or name.endswith("_URL")
        ):
            errors.append(
                f"{name} appears to contain an inline comment; "
                "systemd treats it as part of the value"
            )

    for warning in warnings:
        print(f"Warning: {warning}", file=sys.stderr)

    if errors:
        print("Invalid production configuration:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 78

    print("Production configuration is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
