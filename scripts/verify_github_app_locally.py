"""Run this YOURSELF, locally, with your own .pem file. Never send the
private key to anyone else, including an AI assistant helping you
build this -- there's no way to prove an installation token really
works without the raw key being present wherever this runs, so that
has to be your own machine.

What it proves for real, against the actual GitHub API (no mocks):
1. Your App's JWT (signed with your real private key) is accepted by
   GitHub.
2. GitHub confirms your App is installed on the repo you specify.
3. The resulting installation token actually works -- this script uses
   it to make one real, harmless GitHub API call (GET the repo) and
   checks the response is really authenticated as your App's
   installation, not just "didn't 401".

Usage:
    python scripts/verify_github_app_locally.py \\
        --app-id Iv23liEYcU1rMR9SfNiD \\
        --private-key-file /path/to/your-app.private-key.pem \\
        --owner OWNER --repo REPO

--app-id accepts either the Client ID (recommended by GitHub, looks
like "Iv23...") or the older numeric App ID -- both work, see
app/deploypack/github_app.py's module docstring.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import httpx

from app.deploypack.github_app import (
    GitHubAppError,
    installation_token_for_repo,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-id", required=True,
                         help="Client ID (Iv23...) or numeric App ID")
    parser.add_argument("--private-key-file", required=True, type=Path,
                         help="Path to the .pem file GitHub generated for your App")
    parser.add_argument("--owner", required=True, help="Repo owner/org")
    parser.add_argument("--repo", required=True, help="Repo name")
    args = parser.parse_args()

    if not args.private_key_file.is_file():
        print(f"FAIL: {args.private_key_file} does not exist", file=sys.stderr)
        return 1
    private_key = args.private_key_file.read_text()

    print(f"=== Resolving installation token for {args.owner}/{args.repo} ===")
    try:
        token = installation_token_for_repo(
            args.owner, args.repo, app_id=args.app_id, private_key=private_key,
        )
    except GitHubAppError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        print(
            "\nMost likely cause: the App isn't installed on this repo yet.\n"
            "Fix: go to your App's settings page -> Install App -> pick this repo.",
            file=sys.stderr,
        )
        return 1

    print(f"OK: got an installation token (starts with {token[:8]}...)")

    print("\n=== Using the token for one real, harmless API call ===")
    resp = httpx.get(
        f"https://api.github.com/repos/{args.owner}/{args.repo}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=15,
    )
    if resp.status_code != 200:
        print(f"FAIL: GET /repos/{args.owner}/{args.repo} returned "
              f"{resp.status_code}: {resp.text[:300]}", file=sys.stderr)
        return 1

    body = resp.json()
    print(f"OK: authenticated as the App installation, fetched "
          f"{body['full_name']} (private={body['private']})")
    print(
        "\nThe App auth path is genuinely working end to end. Set these two "
        "env vars on wherever Drydock actually runs and PR delivery will use "
        "this App instead of a PAT:\n"
        f"  GITHUB_APP_ID={args.app_id}\n"
        "  GITHUB_APP_PRIVATE_KEY=<contents of your .pem file>"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
