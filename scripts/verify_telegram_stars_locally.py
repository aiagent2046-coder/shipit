"""Run this YOURSELF, locally, with your own TELEGRAM_BOT_TOKEN. Never
send that token to anyone else, including an AI assistant helping you
build this -- same boundary as the GitHub App private key in
scripts/verify_github_app_locally.py. A bot token is a bearer credential
for your bot; anyone holding it controls it.

What it proves for real, against the live Telegram Bot API (no mocks):
the exact send_invoice() code in app/billing/telegram_stars.py can mint
a real Stars invoice. It calls getMe first (cheap auth check), then
sendInvoice with currency XTR and an empty provider_token to a chat you
name -- if it returns ok, open that chat in Telegram and you'll see a
real Pay-with-Stars button.

What it does NOT prove (and cannot, from a script): the webhook half --
pre_checkout_query and successful_payment arrive only when a real user
actually pays, delivered to a public HTTPS webhook you've registered
with setWebhook. That path is covered by the mocked tests in
tests/test_billing_telegram.py and only truly closes when you take a real
Stars payment end to end.

Usage:
    export TELEGRAM_BOT_TOKEN="123456:ABC-..."
    # a chat that has messaged your bot (your own user id works after you
    # /start the bot); Stars invoices can be sent to a private chat.
    python scripts/verify_telegram_stars_locally.py --chat-id 123456789
    python scripts/verify_telegram_stars_locally.py --chat-id 123456789 --stars 250
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import httpx

from app.billing import telegram_stars


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chat-id", required=True,
                        help="Telegram chat id to send the test invoice to")
    parser.add_argument("--stars", type=int, default=telegram_stars.pro_stars_price(),
                        help="Star price for the test invoice")
    parser.add_argument("--subscription", action="store_true",
                        help="Send a RECURRING subscription invoice "
                             "(subscription_period=30 days) instead of the "
                             "one-shot Pro invoice. Uses the test-monitoring "
                             "tier; --stars defaults to 1 in this mode.")
    args = parser.parse_args()

    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        print("FAIL: TELEGRAM_BOT_TOKEN is not set -- export it first, see "
              "this script's docstring", file=sys.stderr)
        return 1

    try:
        print("=== getMe (auth check) ===")
        async with httpx.AsyncClient(
            base_url=f"{telegram_stars.TELEGRAM_API}/bot{token}", timeout=30
        ) as client:
            resp = await client.get("/getMe")
            data = resp.json()
        if not data.get("ok"):
            print(f"FAIL: getMe rejected the token: {data}", file=sys.stderr)
            return 1
        print(f"OK: authenticated as @{data['result'].get('username')}")

        if args.subscription:
            stars = 1 if args.stars == telegram_stars.pro_stars_price() else args.stars
            # A subscription invoice CANNOT be sent with sendInvoice (Telegram
            # returns SUBSCRIPTION_EXPORT_MISSING); it must be exported as a
            # deep link via createInvoiceLink -- this proves that real call.
            print("\n=== createInvoiceLink (real RECURRING Stars invoice) ===")
            result = await telegram_stars.create_invoice_link(
                title=telegram_stars.SUBSCRIPTION_TITLE,
                description=telegram_stars.SUBSCRIPTION_DESCRIPTION,
                payload=telegram_stars.SUBSCRIPTION_PAYLOAD,
                stars=stars,
                subscription_period=telegram_stars.SUBSCRIPTION_PERIOD_SECONDS,
                token=token,
            )
            link = result["result"]
            print(f"OK: subscription invoice link created: {link}\nOpen it in "
                  f"Telegram — you should see a Subscribe {stars} ⭐/month "
                  "button (30-day period).")
        else:
            stars = args.stars
            print("\n=== sendInvoice (real Stars invoice) ===")
            result = await telegram_stars.send_invoice(
                chat_id=args.chat_id,
                title="Drydock Pro",
                description="Drydock pro tier — higher audit limits and more.",
                payload="verify-script-test",
                stars=stars,
                token=token,
            )
            msg_id = result["result"].get("message_id")
            print(f"OK: invoice sent (message_id={msg_id}). Open that chat in "
                  f"Telegram — you should see a Pay {stars} ⭐ button.")
        print("\nThe send half is proven against the real API. The webhook "
              "half (pre_checkout_query / successful_payment / subscription) "
              "only fires on a real payment to a registered HTTPS webhook — "
              "not testable here.")
        return 0
    except telegram_stars.TelegramError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
