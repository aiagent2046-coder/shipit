#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


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

    values = dict(os.environ)

    if args.env_file:
        if not args.env_file.exists():
            print(f"Environment file not found: {args.env_file}", file=sys.stderr)
            return 78

        values.update(read_env_file(args.env_file))

    if values.get("ENVIRONMENT", "development") != "production":
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

    aitunnel_key = bool(values.get("AITUNNEL_API_KEY", "").strip())
    aitunnel_url = bool(values.get("AITUNNEL_BASE_URL", "").strip())

    if aitunnel_key != aitunnel_url:
        errors.append(
            "AITUNNEL_API_KEY and AITUNNEL_BASE_URL must be configured together"
        )

    paypal_id = bool(values.get("PAYPAL_CLIENT_ID", "").strip())
    paypal_secret = bool(values.get("PAYPAL_CLIENT_SECRET", "").strip())

    if paypal_id != paypal_secret:
        errors.append(
            "PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET must be configured together"
        )

    if values.get("PAYPAL_ENV", "").strip().lower() == "live":
        if not values.get("PAYPAL_WEBHOOK_ID", "").strip():
            errors.append("PAYPAL_WEBHOOK_ID is required when PAYPAL_ENV=live")

    if values.get("USDT_TRC20_ADDRESS", "").strip():
        if not values.get("USDT_POLL_TOKEN", "").strip():
            errors.append(
                "USDT_POLL_TOKEN is required when USDT_TRC20_ADDRESS is configured"
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
