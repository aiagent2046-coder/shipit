"""A direct message on X, and an honest account of what that costs.

READ THIS BEFORE RELYING ON IT. Of the three channels, this is the one most
likely to be quietly unavailable, and the reasons are not ours to fix:

  * A DM needs a USER-context token with the `dm.write` scope. An app-only
    bearer token cannot send one, whatever else it can do. `X_DM_TOKEN` must
    be an OAuth 2.0 user access token for the account the message comes from.
  * Write access to the X API is a paid tier. A deployment without one gets
    403s, and this module reports that as "not delivered" rather than
    pretending.
  * The recipient must accept DMs from accounts they do not follow. Many
    people do not, and X refuses the send. That refusal is a fact about their
    settings, not a bug here, and it is invisible until we try.
  * A handle is not an id. `POST /2/dm_conversations/with/{id}/messages` wants
    the numeric user id, so a handle costs a lookup first.

So this channel MUST NOT be the only one anything important travels on, and
app/notify/router.py is built on that: it sends on every channel the customer
gave, records which ones actually landed, and pages the operator when none of
them did. A refund the customer never hears about is the failure mode worth
engineering against, and X is the likeliest cause of it.

NOT EXERCISED AGAINST THE LIVE API. This deployment holds no X credentials.
The request shapes below are from the documented v2 endpoints and the outbound
calls are injectable (`transport=`), the same seam the Bot API client uses. The
first real send will be the first proof, and until then the module says so
rather than implying otherwise.
"""

from __future__ import annotations

import logging
import os
import re

import httpx

logger = logging.getLogger(__name__)

X_API = "https://api.x.com"

# X handles: 1-15 characters, letters, digits and underscore. The leading @ is
# how people write one and is stripped rather than rejected -- a customer
# typing their own handle into a form will type the @.
_HANDLE = re.compile(r"^@?([A-Za-z0-9_]{1,15})$")

# Short, like the Telegram pre-checkout answer and for a related reason: this
# runs on a path where the thing being announced has already happened, and a
# slow third party must not hold the request open.
_TIMEOUT_S = 15.0


def token_from_env() -> str | None:
    """The OAuth 2.0 user access token, or None. Unset -> the channel is off,
    quietly, exactly like SMTP_HOST and TELEGRAM_BOT_TOKEN."""
    return os.environ.get("X_DM_TOKEN") or None


def normalize_handle(handle: str | None) -> str | None:
    """`@drydock` and `drydock` both become `drydock`. None for anything that
    is not a handle, so a caller cannot put a URL or an email in this field and
    have it silently attempted."""
    if not handle:
        return None
    match = _HANDLE.match(handle.strip())
    return match.group(1) if match else None


async def _resolve_user_id(
    handle: str, *, token: str, transport: httpx.BaseTransport | None = None,
) -> str | None:
    """The numeric id behind a handle, or None if X will not tell us.

    None covers three different things -- no such account, our token cannot
    look it up, X is down -- and the caller treats all of them the same way,
    because from the customer's side they are the same thing: the message did
    not arrive.
    """
    async with httpx.AsyncClient(
        base_url=X_API, timeout=_TIMEOUT_S, transport=transport,
    ) as client:
        resp = await client.get(
            f"/2/users/by/username/{handle}",
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code >= 300:
            logger.warning("X user lookup failed: %s", resp.status_code)
            return None
        data = resp.json()
    user_id = (data.get("data") or {}).get("id")
    return str(user_id) if user_id else None


async def send_dm(
    handle: str,
    text: str,
    *,
    token: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> bool:
    """Send one DM. True only if X accepted it.

    Never raises, and every quiet outcome is a False: no token, an unusable
    handle, a handle that does not resolve, a refusal because the recipient
    does not take DMs from strangers. The caller is announcing something that
    already happened; see the module docstring for why this channel in
    particular must never be trusted on its own.
    """
    resolved_token = token if token is not None else token_from_env()
    if not resolved_token:
        return False

    account = normalize_handle(handle)
    if not account:
        logger.warning("refusing to DM something that is not an X handle")
        return False

    try:
        user_id = await _resolve_user_id(
            account, token=resolved_token, transport=transport)
        if not user_id:
            return False
        async with httpx.AsyncClient(
            base_url=X_API, timeout=_TIMEOUT_S, transport=transport,
        ) as client:
            resp = await client.post(
                f"/2/dm_conversations/with/{user_id}/messages",
                headers={"Authorization": f"Bearer {resolved_token}"},
                json={"text": text},
            )
        if resp.status_code >= 300:
            # 403 here is the common and expected case: the recipient does not
            # accept DMs from accounts they do not follow. Logged at warning
            # rather than error because it is their setting, not our fault, and
            # an error level would train the operator to ignore the log.
            logger.warning("X DM refused: %s", resp.status_code)
            return False
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("X DM failed (%s)", type(exc).__name__)
        return False
