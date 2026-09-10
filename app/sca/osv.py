"""Ask the OSV database what is known about a set of resolved versions.

THE API, AS MEASURED (2026-09-10), NOT AS REMEMBERED.

    POST /v1/querybatch   {"queries": [{"package": {"ecosystem", "name"},
                                        "version": ...}, ...]}
    ->  {"results": [{"vulns": [{"id": "GHSA-...", "modified": "..."}]}, ...]}

The batch answer carries the ID and the modification time and nothing else, so
a second call per ID is required to learn what the advisory says:

    GET /v1/vulns/GHSA-35jh-r3h4-6jhm
    ->  {"id", "summary", "details", "aliases": ["CVE-..."],
         "database_specific": {"severity": "HIGH", "cwe_ids": [...]},
         "affected": [{"package": {...}, "ranges": [{"events": [{"fixed": "..."}]}]}],
         "references": [{"type": "ADVISORY", "url": ...}]}

Two calls is the honest cost of an accurate answer: a summary inferred from an
ID's prefix would be a guess about a database we are querying precisely because
we do not have its contents.

THE TRANSPORT IS INJECTABLE, so the whole stage can be tested without a
socket -- an audit that reaches the network in a unit test is an audit with a
suite that fails on a plane.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

import httpx

from app.sca.lockfiles import Dependency

OSV_BASE = "https://api.osv.dev"

# One request per this many packages. The API accepts large batches, but a
# single oversized body is all-or-nothing: a 300-package batch that fails on a
# timeout has to be retried whole, while 250s fail in pieces a caller can
# reason about.
BATCH_SIZE = 250

# Detail lookups are the expensive half (one request per advisory). Bounded
# because a repository with an ancient dependency tree can match hundreds of
# advisories, and an audit must not turn into an unbounded crawl.
MAX_DETAILS = 60


class OsvUnavailable(RuntimeError):
    """The database could not be reached or did not answer as documented."""


class Transport(Protocol):
    """The slice of httpx.Client this module uses, so a test can replace it."""

    def post(self, url: str, *, json: dict | None = None) -> "Response": ...
    def get(self, url: str) -> "Response": ...


class Response(Protocol):
    status_code: int

    def json(self) -> object: ...


@dataclass
class OsvClient:
    transport: Transport | None = None
    timeout: float = 20.0
    batch_size: int = BATCH_SIZE
    max_details: int = MAX_DETAILS
    base_url: str = OSV_BASE
    requests_made: int = field(default=0, init=False)

    # -- transport ---------------------------------------------------------

    def _call(self, method: str, path: str, payload: dict | None = None) -> dict:
        if self.transport is not None:
            return self._send(self.transport, method, path, payload)
        # A client per call, not one held open: this stage runs a handful of
        # requests inside a request handler, and a pooled client would have to
        # be closed by whoever owns the stage's lifetime.
        with httpx.Client(timeout=self.timeout) as client:
            return self._send(client, method, path, payload)

    def _send(self, transport: Transport, method: str, path: str,
              payload: dict | None) -> dict:
        url = f"{self.base_url}{path}"
        try:
            response = (transport.post(url, json=payload) if payload is not None
                        and method == "POST" else transport.get(url))
            self.requests_made += 1
            status = getattr(response, "status_code", 0)
            if status >= 400:
                raise OsvUnavailable(f"{method} {path} -> HTTP {status}")
            body = response.json()
        except OsvUnavailable:
            raise
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            # A refused connection, a timeout, a truncated body: all one thing
            # to the caller -- no answer, so no claim may be made.
            raise OsvUnavailable(f"{type(exc).__name__}: {exc}") from exc
        if not isinstance(body, dict):
            raise OsvUnavailable(f"{method} {path} -> unexpected body type")
        return body

    # -- api ---------------------------------------------------------------

    def query(self, dependencies: list[Dependency]) -> dict[int, list[str]]:
        """index -> advisory IDs, for every batch that answered."""
        hits: dict[int, list[str]] = {}
        for start in range(0, len(dependencies), self.batch_size):
            chunk = dependencies[start:start + self.batch_size]
            queries = [{"package": {"ecosystem": d.ecosystem, "name": d.name},
                        "version": d.version} for d in chunk]
            body = self._call("POST", "/v1/querybatch", {"queries": queries})
            results = body.get("results")
            if not isinstance(results, list):
                raise OsvUnavailable("querybatch answered without a results list")
            for offset, result in enumerate(results):
                if not isinstance(result, dict):
                    continue
                ids: list[str] = []
                for vuln in result.get("vulns", []):
                    if isinstance(vuln, dict) and isinstance(vuln.get("id"), str):
                        ids.append(vuln["id"])
                if ids:
                    hits[start + offset] = ids
        return hits

    def details(self, ids: list[str]) -> dict[str, dict]:
        """Advisory ID -> its record. IDs that fail to load are left out.

        One unreadable advisory must not discard the ones that loaded: the
        stage reports what it could verify, and says how many it could not.
        """
        records: dict[str, dict] = {}
        for advisory in ids[:self.max_details]:
            try:
                records[advisory] = self._call("GET", f"/v1/vulns/{advisory}")
            except OsvUnavailable:
                continue
        return records
