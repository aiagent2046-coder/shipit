"""PR delivery for a verified Deploy Pack — GitHub REST (Git Data API).

Accepts whatever token the caller passes in. app/main.py resolves that
token: a GitHub App installation token when GITHUB_APP_ID +
GITHUB_APP_PRIVATE_KEY are configured (see app/deploypack/github_app.py
— works for any repo the App is installed on), falling back to the
single-operator GITHUB_PR_TOKEN below otherwise. This module itself
stays auth-agnostic — it doesn't know or care which kind of token it got.

Never pushes to the base branch directly: creates a new branch, commits
there, opens a PR. Merge stays with the repo owner (HITL), same
principle as everywhere else in this codebase. A caller MUST only call
this after sandbox verification succeeds — see app/main.py, which
refuses to deliver an unverified Pack.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import httpx

GITHUB_API = "https://api.github.com"
_HEADERS_BASE = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


class DeliveryError(Exception):
    """A GitHub API call failed; message includes which step and why."""


@dataclass
class PullRequestResult:
    html_url: str
    branch: str


def token_from_env() -> str | None:
    return os.environ.get("GITHUB_PR_TOKEN") or None


def render_pr_body(pack: str, files: dict[str, str], detail: str) -> str:
    """Human-readable PR description — non-technical users need to
    understand what changed and why before they merge anything."""
    file_list = "\n".join(f"- `{path}`" for path in sorted(files))
    return (
        f"## Drydock {pack.title()} Pack\n\n"
        f"Verified in a sandbox before this PR was opened: `docker build` "
        f"+ `docker run` + a real HTTP request confirmed the app boots.\n\n"
        f"**Verification result:** {detail}\n\n"
        f"### Files added or changed\n{file_list}\n\n"
        "### How to check it yourself\n"
        "```bash\ndocker compose up --build\n```\n"
        "Merge is entirely up to you — nothing here touches your base "
        "branch until you press merge.\n"
    )


def open_pull_request(
    owner: str,
    repo: str,
    files: dict[str, str],
    *,
    base_branch: str = "main",
    branch_prefix: str = "shipit/deploy-pack",
    title: str = "Drydock: add Deploy Pack (Dockerfile, compose, CI)",
    body: str = "",
    token: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> PullRequestResult:
    token = token or token_from_env()
    if not token:
        raise DeliveryError("no GitHub token configured (GITHUB_PR_TOKEN)")

    headers = {**_HEADERS_BASE, "Authorization": f"Bearer {token}"}
    with httpx.Client(base_url=GITHUB_API, headers=headers, timeout=30,
                       transport=transport) as client:
        base_ref = client.get(f"/repos/{owner}/{repo}/git/ref/heads/{base_branch}")
        _check(base_ref, "resolve base branch")
        base_sha = base_ref.json()["object"]["sha"]

        base_commit = client.get(f"/repos/{owner}/{repo}/git/commits/{base_sha}")
        _check(base_commit, "resolve base commit")
        base_tree_sha = base_commit.json()["tree"]["sha"]

        tree_entries = []
        for path, content in files.items():
            blob = client.post(
                f"/repos/{owner}/{repo}/git/blobs",
                json={"content": content, "encoding": "utf-8"},
            )
            _check(blob, f"create blob for {path}")
            tree_entries.append({
                "path": path, "mode": "100644", "type": "blob",
                "sha": blob.json()["sha"],
            })

        tree = client.post(
            f"/repos/{owner}/{repo}/git/trees",
            json={"base_tree": base_tree_sha, "tree": tree_entries},
        )
        _check(tree, "create tree")

        commit = client.post(
            f"/repos/{owner}/{repo}/git/commits",
            json={"message": title, "tree": tree.json()["sha"],
                  "parents": [base_sha]},
        )
        _check(commit, "create commit")
        commit_sha = commit.json()["sha"]

        branch = f"{branch_prefix}-{commit_sha[:8]}"
        ref = client.post(
            f"/repos/{owner}/{repo}/git/refs",
            json={"ref": f"refs/heads/{branch}", "sha": commit_sha},
        )
        _check(ref, "create branch")

        pr = client.post(
            f"/repos/{owner}/{repo}/pulls",
            json={"title": title, "head": branch, "base": base_branch, "body": body},
        )
        _check(pr, "open pull request")

        return PullRequestResult(html_url=pr.json()["html_url"], branch=branch)


def _check(resp: httpx.Response, action: str) -> None:
    if resp.status_code >= 300:
        raise DeliveryError(f"{action} failed: {resp.status_code} {resp.text[:300]}")
