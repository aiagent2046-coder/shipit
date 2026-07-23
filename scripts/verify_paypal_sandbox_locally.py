"""Run this YOURSELF, locally, once real PayPal credentials exist. Unlike the
USDT verify script this one NEEDS secrets: PayPal's REST API requires an OAuth2
client id + secret. So point it ONLY at a PayPal SANDBOX app's credentials --
never live keys, never anything you commit. Export them into your shell for the
run; this script reads them from the environment and prints nothing sensitive.

What it proves for real, against live PayPal SANDBOX (no mocks): the exact
code in app/billing/paypal.py can mint an OAuth2 token, create a CAPTURE-intent
Order carrying our routing custom_id, and (if a sandbox billing plan id is
given) create a Subscription against it -- i.e. that our hand-rolled httpx REST
client speaks the real Orders/Subscriptions API shape. It prints the buyer
`approve` links so you can optionally click through a sandbox buyer account.

What it does NOT prove (and cannot, without a full browser approval + webhook
round trip): that a captured order or an activated subscription then flows
through POST /v1/webhooks/paypal and grants. That dispatch + granting logic is
covered by the mocked tests in tests/test_billing_paypal.py; it only truly
closes when a real sandbox buyer approves and PayPal delivers a verified webhook
to a reachable deployment.

Usage:
    export PAYPAL_CLIENT_ID=...          # a SANDBOX app's client id
    export PAYPAL_CLIENT_SECRET=...      # its secret
    export PAYPAL_ENV=sandbox            # anything != "live" is sandbox
    # optional, to also exercise the Subscriptions API:
    export PAYPAL_MONITOR_PLAN_ID=P-XXXX # a sandbox billing plan id
    python scripts/verify_paypal_sandbox_locally.py
    python scripts/verify_paypal_sandbox_locally.py --repo owner/repo
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from app.billing import paypal


def _approve_link(resource: dict) -> str | None:
    for link in resource.get("links") or []:
        if link.get("rel") == "approve":
            return link.get("href")
    return None


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo", default="owner/repo",
        help="repo full name to encode in a monitoring subscription's custom_id "
             "(only used if PAYPAL_MONITOR_PLAN_ID is set)",
    )
    args = parser.parse_args()

    if not paypal.is_configured():
        print("FAIL: set PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET (a SANDBOX "
              "app's) in your environment first.", file=sys.stderr)
        return 1
    if (os.environ.get("PAYPAL_ENV") or "sandbox").strip().lower() == "live":
        print("REFUSING to run against PAYPAL_ENV=live. This is a sandbox "
              "verification script; unset PAYPAL_ENV or set it to 'sandbox'.",
              file=sys.stderr)
        return 1

    print(f"=== PayPal REST, base={paypal.api_base()} ===")

    # 1. OAuth2 token (exercised implicitly by the calls below, but surface it
    # first so an auth problem is reported as an auth problem).
    try:
        token = await paypal._access_token()
    except paypal.PayPalError as exc:
        print(f"FAIL (oauth token): {exc}", file=sys.stderr)
        return 1
    print(f"OK: minted an OAuth2 token ({len(token)} chars).")

    # 2. Create a Pro order (CAPTURE intent, custom_id 'pro').
    try:
        pro = await paypal.create_order(
            custom_id=paypal.PRO_CUSTOM_ID, amount_usd=paypal.pro_price_usd(),
            description=paypal.PRO_DESCRIPTION,
        )
    except paypal.PayPalError as exc:
        print(f"FAIL (create pro order): {exc}", file=sys.stderr)
        return 1
    print(f"OK: created Pro order {pro.get('id')} status={pro.get('status')} "
          f"amount={paypal.pro_price_usd()} USD")
    if (link := _approve_link(pro)):
        print(f"     approve as a sandbox buyer: {link}")

    # 3. Create a Fix Pack order (custom_id 'fixpack:<audit_id>').
    try:
        fp = await paypal.create_order(
            custom_id=paypal.fixpack_custom_id("aud_demo"),
            amount_usd=paypal.fixpack_price_usd(),
            description="Drydock Fix Pack (sandbox verification)",
        )
    except paypal.PayPalError as exc:
        print(f"FAIL (create fixpack order): {exc}", file=sys.stderr)
        return 1
    print(f"OK: created Fix Pack order {fp.get('id')} "
          f"amount={paypal.fixpack_price_usd()} USD")

    # 4. Subscriptions API -- only if a sandbox plan id is provided.
    plan_id = paypal.monitor_plan_id_from_env()
    if plan_id:
        try:
            sub = await paypal.create_subscription(
                plan_id=plan_id, custom_id=paypal.monitor_custom_id(args.repo),
            )
        except paypal.PayPalError as exc:
            print(f"FAIL (create subscription): {exc}", file=sys.stderr)
            return 1
        print(f"OK: created subscription {sub.get('id')} "
              f"status={sub.get('status')} plan={plan_id}")
        if (link := paypal.approve_url_from_subscription(sub)):
            print(f"     approve as a sandbox buyer: {link}")
    else:
        print("SKIP: PAYPAL_MONITOR_PLAN_ID unset -- Subscriptions API not "
              "exercised (create a sandbox billing plan to test it).")

    print("\nThe OAuth + Orders (+ optional Subscriptions) REST shapes are "
          "proven against real sandbox PayPal. Webhook verification + granting "
          "is NOT exercised here (needs a real buyer approval + a reachable "
          "webhook); see tests/test_billing_paypal.py for that logic mocked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
