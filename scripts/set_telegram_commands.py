"""Publish the bot's command menu, and prove the token in .env is the bot you think.

WHY A SCRIPT. Telegram's command menu -- the "/" button in the chat, and the
list a new user sees before typing anything -- is server-side state held by
Telegram, not by us. It is set once with setMyCommands and then persists;
nothing in this repository can make it appear, and no deploy will. So it is a
step an operator runs, like scripts/verify_smtp_locally.py, rather than
something to hope somebody remembers to do by hand in BotFather.

WHAT IT ALSO ANSWERS. It prints the bot's own username from getMe. That is the
name a deep link has to use, and reading it off the token means it cannot
disagree with the token that will actually receive the tap -- a link to the
wrong bot is a "start" button that opens a chat with somebody else's bot and
sits there.

    python3 scripts/set_telegram_commands.py           # show what would be set
    python3 scripts/set_telegram_commands.py --apply   # set it

THE TOKEN IS NEVER PRINTED, and this reads /opt/shipit/.env itself rather than
asking anyone to source it -- see scripts/env_file.py for what that habit cost
here.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
sys.path.insert(0, str(SCRIPT_DIR.parent))

import env_file  # noqa: E402

from app.logging_config import redact  # noqa: E402

API = "https://api.telegram.org"

# WHAT THE MENU SAYS, and what it deliberately does not.
#
# Only commands the bot actually handles. A menu entry for something the
# dispatcher ignores is worse than no menu: the user taps it, nothing happens,
# and they conclude the bot is broken rather than that the button was wrong.
#
# /start carries no argument here because a menu tap sends it bare -- the
# reference form is for the deep link the site builds, and the bare form
# answers with what the bot is for.
COMMANDS: tuple[tuple[str, str], ...] = (
    ("start", "What this bot does"),
    ("mykey", "Your API key, if your purchase came with one"),
    ("rotatekey", "Replace your API key"),
    ("link", "Collect what an order bought: /link DRY-XXXXXX"),
    ("unsubscribe", "Stop a monitoring subscription renewing"),
)


def call(token: str, method: str, payload: dict | None = None) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        f"{API}/bot{token}/{method}", data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        # Telegram puts the reason in the body, and the body is worth having --
        # "Unauthorized" and "Bad Request: BOT_COMMAND_INVALID" send you to
        # completely different places. Through redact() because the URL that
        # produced it carries the token and some errors echo it back.
        raise SystemExit(
            f"{method} failed: {exc.code} "
            f"{redact(exc.read().decode('utf-8', 'replace')[:300])}"
        ) from None


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true",
                        help="actually set the menu (default: show it)")
    args = parser.parse_args(argv[1:])

    source = env_file.fill_environment("TELEGRAM_")
    from app.notify import telegram

    token = telegram.bot_token_from_env()
    if not token:
        print(f"TELEGRAM_BOT_TOKEN is not set, and {source} "
              f"{'has none' if source.is_file() else 'is not there'}.",
              file=sys.stderr)
        return 78

    me = call(token, "getMe")["result"]
    print(f"bot      : @{me['username']} (id {me['id']})")
    print(f"env file : {source}")
    print()
    for name, description in COMMANDS:
        print(f"  /{name:<12} {description}")
    print()

    if not args.apply:
        print("Nothing was changed. Re-run with --apply to set this menu.")
        return 0

    call(token, "setMyCommands", {
        "commands": [{"command": n, "description": d} for n, d in COMMANDS],
    })
    print("Menu set. Open the bot and check the / button; Telegram caches the "
          "old list for a few minutes in an already-open chat.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
