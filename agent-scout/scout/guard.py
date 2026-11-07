"""Mode guard. The legal contour lives here in code, not in caller discipline.

passive (default): OSINT and public artifacts only. HTTP GET/HEAD, no payloads,
   no authentication bypass, no exploitation, no reading of third-party data.
active (manual switch): full engine + target-side access. Requires a recorded
   authorization (signed contract) with an explicit scope and an expiry.

Switching to active is always a deliberate human act: `scout auth add ...`
creates the record, and every active entry point checks it before doing
anything. An expired or missing record refuses the operation.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path

AUTH_DIR: Path = Path.home() / ".agent-scout" / "authorizations"
PASSIVE_METHODS = frozenset({"GET", "HEAD"})
MAX_AUTH_HOURS: int = 24 * 90  # a contract run may not silently live forever
CONTRACT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class ActiveModeUnauthorised(RuntimeError):
    """Raised for any active-mode action without a current authorization record."""


def _validate_contract_id(contract_id: str) -> str:
    """Contract ids name record files; path separators must never survive."""
    cid = (contract_id or "").strip()
    if not cid:
        raise ActiveModeUnauthorised("contract_id is required")
    if not CONTRACT_ID.match(cid):
        raise ActiveModeUnauthorised(
            "contract_id must be alphanumeric (plus . _ -), no path separators")
    return cid


@dataclass
class Authorization:
    contract_id: str
    scope: list[str]
    expires_at: float
    created_at: float
    note: str = ""

    @property
    def expired(self) -> bool:
        return time.time() > self.expires_at

    def as_dict(self) -> dict:
        return {
            "contract_id": self.contract_id,
            "scope": self.scope,
            "expires_at": self.expires_at,
            "created_at": self.created_at,
            "note": self.note,
        }


def activate(contract_id: str, scope: list[str], hours: float = 24, note: str = "") -> Authorization:
    """Record the human decision to enter active mode for one contract."""
    cid = _validate_contract_id(contract_id)
    if not scope:
        raise ActiveModeUnauthorised("scope is required (target hosts/DBs in the contract)")
    hours = min(hours, MAX_AUTH_HOURS)
    auth = Authorization(
        contract_id=cid,
        scope=[s.strip() for s in scope if s.strip()],
        expires_at=time.time() + hours * 3600,
        created_at=time.time(),
        note=note,
    )
    AUTH_DIR.mkdir(parents=True, exist_ok=True)
    (AUTH_DIR / f"{auth.contract_id}.json").write_text(json.dumps(auth.as_dict(), indent=1))
    return auth


def require_active(contract_id: str) -> Authorization:
    """The single gate every active-mode entry point must call first."""
    cid = _validate_contract_id(contract_id)
    path = AUTH_DIR / f"{cid}.json"
    if not path.is_file():
        raise ActiveModeUnauthorised(
            f"no authorization record for contract '{contract_id}'; "
            "active mode requires `scout auth add`"
        )
    data = json.loads(path.read_text())
    auth = Authorization(**data)
    if auth.expired:
        raise ActiveModeUnauthorised(
            f"authorization for contract '{auth.contract_id}' expired; renew it explicitly"
        )
    return auth


def enforce_passive_http(method: str) -> None:
    if method.upper() not in PASSIVE_METHODS:
        raise ActiveModeUnauthorised(
            f"passive mode allows only GET/HEAD, got {method!r}"
        )
