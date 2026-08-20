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
