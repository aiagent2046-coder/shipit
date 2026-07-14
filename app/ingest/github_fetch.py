"""Download a public GitHub repo as a zip, for URL-based audit intake.

The alternative to the file-upload path on POST /v1/audits: given a
github.com repo URL (validated in app/main.py before we get here — the
strict host/scheme/owner/repo check is the SSRF guard), download that
repo's default-branch zipball from GitHub and hand the bytes to the
exact same validate_zip/detect_stack/scan pipeline the upload path uses.
No second validation path.

Talks only to the hardcoded api.github.com, and only with the two
already-validated owner/repo path segments — never any other part of the
user-supplied URL. Public repos only: no Authorization header, by design
(an unauthenticated 404 for a private repo is a feature — no
exists-but-private oracle).
"""

from __future__ import annotations

import httpx

from app.ingest.validators import MAX_ARCHIVE_BYTES

GITHUB_API = "https://api.github.com"
# 30s outbound-call timeout, same convention as app/deploypack/delivery.py.
TIMEOUT = httpx.Timeout(30.0, connect=10.0)
_READ_CHUNK = 64 * 1024


class RepoFetchError(Exception):
    """Download failed. `reason` is a stable machine-readable code:
    repo_not_found, too_large, github_error, github_unreachable."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


def fetch_repo_zip(owner: str, repo: str,
                   transport: httpx.BaseTransport | None = None) -> bytes:
    """Return the zipball bytes for a public repo's default branch.

    owner/repo are already validated by the caller. GitHub's zipball
    endpoint with no ref serves the default branch and 302-redirects to
    codeload.github.com, so redirects are followed (the first hop's host
    is still the fixed api.github.com). A 404 means not-found-or-private
    (GitHub returns 404, not 403, to unauthenticated requests for private
    repos). Size is capped both up front (Content-Length, when present)
    and during the streamed read, using the same MAX_ARCHIVE_BYTES as the
    upload path — Content-Length alone isn't trusted (it can be absent on
    a chunked codeload response, or wrong).
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        with httpx.Client(base_url=GITHUB_API, headers=headers,
                          timeout=TIMEOUT, follow_redirects=True,
                          transport=transport) as client:
            with client.stream("GET", f"/repos/{owner}/{repo}/zipball") as resp:
                if resp.status_code == 404:
                    raise RepoFetchError(
                        "repo_not_found",
                        "repo not found or private — only public GitHub "
                        "repos are supported",
                    )
                if resp.status_code >= 300:
                    raise RepoFetchError(
                        "github_error", f"GitHub returned {resp.status_code}"
                    )

                declared = resp.headers.get("content-length")
                if declared is not None and int(declared) > MAX_ARCHIVE_BYTES:
                    raise RepoFetchError(
                        "too_large", f"{declared} > {MAX_ARCHIVE_BYTES}"
                    )

                chunks = bytearray()
                for chunk in resp.iter_bytes(_READ_CHUNK):
                    chunks += chunk
                    if len(chunks) > MAX_ARCHIVE_BYTES:
                        raise RepoFetchError(
                            "too_large",
                            f"download exceeded {MAX_ARCHIVE_BYTES} bytes",
                        )
                return bytes(chunks)
    except httpx.HTTPError as exc:
        raise RepoFetchError("github_unreachable", str(exc)) from exc
