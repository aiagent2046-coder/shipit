"""Run this YOURSELF, locally. Unlike the DB and Telegram verify scripts,
this one needs no secret: a TRON address is public and the TronGrid read
endpoint works unauthenticated (a TRONGRID_API_KEY only raises your rate
limit). So this is safe to run against any address.

What it proves for real, against live TronGrid (no mocks): the exact
fetch_transfers() code in app/billing/usdt_trc20.py can reach TronGrid,
parse the real response shape, and list incoming USDT/TRC20 transfers to
an address. Point it at a busy public address (the USDT contract address
itself receives constantly) to see real rows, or at your own configured
USDT_TRC20_ADDRESS.

What it does NOT prove (and cannot, without spending real USDT): that a
payment of a specific invoice amount is matched and grants pro. That
matching logic is covered by the mocked tests in
tests/test_billing_usdt.py and only truly closes when a real transfer of
an invoice's exact amount lands and a real poll picks it up.

Note on scope: the Drydock dev sandbox reached api.trongrid.io
unauthenticated and got HTTP 200 with the documented response shape
during development (recorded in the README) — but that was a raw curl,
not this code path. This script is how you exercise the actual
fetch_transfers() code against the live API yourself.

Usage:
    # default: the mainnet USDT contract address (always has traffic)
    python scripts/verify_usdt_trc20_locally.py
    python scripts/verify_usdt_trc20_locally.py --address TYOUR...ADDRESS
    export TRONGRID_API_KEY=...   # optional, only for higher rate limits
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from app.billing import usdt_trc20


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--address",
        default=os.environ.get("USDT_TRC20_ADDRESS") or usdt_trc20.usdt_contract_from_env(),
        help="TRON address to read incoming USDT transfers for "
             "(default: USDT_TRC20_ADDRESS, else the mainnet USDT contract)",
    )
    parser.add_argument("--limit", type=int, default=5)
    args = parser.parse_args()

    api_key = usdt_trc20.trongrid_api_key_from_env()
    print(f"=== fetch_transfers({args.address}) "
          f"[{'with' if api_key else 'no'} API key] ===")
    try:
        transfers = await usdt_trc20.fetch_transfers(
            args.address, api_key=api_key, limit=args.limit
        )
    except usdt_trc20.TronGridError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    print(f"OK: TronGrid reachable, {len(transfers)} transfer(s) returned "
          f"and parsed by the real code path.")
    for tr in transfers[:args.limit]:
        value = tr.get("value")
        try:
            human = usdt_trc20._micros_to_amount(int(value))
        except (TypeError, ValueError):
            human = "?"
        sym = (tr.get("token_info") or {}).get("symbol")
        print(f"  {tr.get('transaction_id', '?')[:16]}…  "
              f"{tr.get('from', '?')} -> {tr.get('to', '?')}  {human} {sym}")

    print("\nThe read path is proven against the real API. Matching a real "
          "payment to an invoice amount is NOT exercised here (would cost real "
          "USDT); see tests/test_billing_usdt.py for the mocked matching logic.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
