"""Tests for the Telegram Stars provider (paywall Stage 2).

No real Telegram and no real Postgres: outbound Bot API calls are faked
with httpx.MockTransport (same pattern as tests/test_github_app.py), and
in-memory Fake*Repo stand-ins replace the DB repositories (same idea as
tests/test_accounts.py's FakeAccountRepo). What is NOT covered here is a
real payment round trip — that needs a real bot token and a real user
tapping Pay; see scripts/verify_telegram_stars_locally.py.
"""

from __future__ import annotations

import datetime
import re
import uuid

import httpx

from app.accounts import api_key_prefix
from app.billing import deliver_key_once, telegram_stars
from app.main import (
    app,
    get_account_repo,
    get_billing_transport,
    get_payment_repo,
)
from fastapi.testclient import TestClient
from tests.conftest import (
    enable_monitoring,
    FakeAccountRepo,
    FakeCompletionCasMixin,
    FakeKeyDeliveryMixin,
)

client = TestClient(app)


# --- in-memory repo fakes ---

class FakePaymentRepo(FakeKeyDeliveryMixin, FakeCompletionCasMixin):
    def __init__(self):
        self.rows: dict[str, dict] = {}

    async def create(self, *, account_id, provider, external_ref, amount,
                     currency, status, tier_granted, product="pro_tier",
                     audit_id=None):
        row = {
            "id": str(uuid.uuid4()), "account_id": account_id, "provider": provider,
            "external_ref": external_ref, "amount": amount, "currency": currency,
            "status": status, "tier_granted": tier_granted, "product": product,
            "audit_id": audit_id,
            "created_at": datetime.datetime.now(datetime.timezone.utc),
        }
        self.rows[row["id"]] = row
        return row

    async def get(self, payment_id: str):
        return self.rows.get(payment_id)

    async def get_by_external_ref(self, provider: str, external_ref: str):
        for r in self.rows.values():
            if r["provider"] == provider and r["external_ref"] == external_ref:
                return r
        return None

    async def get_completed_by_telegram_chat_id(self, telegram_chat_id: str):
        found = [
            r for r in self.rows.values()
            if r["status"] == "completed"
            and r.get("telegram_chat_id") == telegram_chat_id
        ]
        return found[-1] if found else None

    async def link_telegram_chat_id(self, payment_id: str, telegram_chat_id: str):
        r = self.rows[payment_id]
        # First-wins: only stamp if unset (or already the same chat) -- mirrors
        # the DB method's WHERE clause so tests exercise the real guard.
        if r.get("telegram_chat_id") in (None, telegram_chat_id):
            r["telegram_chat_id"] = telegram_chat_id
        return r


def _telegram_transport(calls: list):
    """MockTransport that records (method, body) and returns ok for every
    Bot API call."""
    def handler(request: httpx.Request) -> httpx.Response:
        method = request.url.path.rsplit("/", 1)[-1]
        import json
        calls.append((method, json.loads(request.content) if request.content else {}))
        # createInvoiceLink returns a bare string link in `result`; every other
        # method here returns a small object. Match the real Bot API so callers
        # that read resp["result"] as a URL (e.g. /subscribe) work.
        if method == "createInvoiceLink":
            result: object = "https://t.me/$test_invoice_link"
        else:
            result = {"message_id": 1}
        return httpx.Response(200, json={"ok": True, "result": result})
    return httpx.MockTransport(handler)


def _successful_payment_update(charge_id: str, chat_id: int = 555):
    return {
        "update_id": 1,
        "message": {
            "chat": {"id": chat_id},
            "from": {"id": chat_id},
            "successful_payment": {
                "currency": "XTR", "total_amount": 250,
                "invoice_payload": "pro", "telegram_payment_charge_id": charge_id,
                "provider_payment_charge_id": "prov_1",
            },
        },
    }


# --- 1. nothing mints an invoice ---

def test_no_function_here_can_mint_a_stars_invoice():
    """Stars is no longer a way to pay. The test is on ABSENCE, because that
    is the property a diff cannot show: any one of these names coming back
    means something can charge a Star again."""
    for name in ("build_invoice_payload", "create_invoice_link", "send_invoice",
                 "pro_stars_price", "fixpack_stars_price",
                 "subscription_stars_price"):
        assert not hasattr(telegram_stars, name), (
            f"telegram_stars.{name} is back, and with it the ability to mint "
            "a Stars invoice"
        )


# --- 2. pre_checkout_query refusal ---

async def test_pre_checkout_query_is_declined_with_a_reason():
    """The last moment before the charge, and the ONLY point in the flow where
    refusing spares the payer money instead of merely withholding what they
    bought. An invoice can still reach here: Telegram holds it once minted, and
    an exported deep link sits in a chat until someone taps it."""
    calls: list = []
    transport = _telegram_transport(calls)
    update = {"update_id": 1, "pre_checkout_query": {
        "id": "pcq_1", "from": {"id": 555}, "currency": "XTR",
        "total_amount": 250, "invoice_payload": "pro"}}

    result = await telegram_stars.handle_update(
        update, account_repo=FakeAccountRepo(), payment_repo=FakePaymentRepo(),
        token="t", transport=transport,
    )
    assert result["handled"] == "pre_checkout_query"
    assert result["result"] == "declined_withdrawn"
    assert len(calls) == 1
    method, body = calls[0]
    assert method == "answerPreCheckoutQuery"
    assert body["ok"] is False
    # Telegram shows this string to the payer verbatim, so it has to say they
    # were not charged and where to go instead.
    assert "not been charged" in body["error_message"]
    assert "drydock.co" in body["error_message"]
    # The Bot API caps error_message at 255 characters; a longer one is
    # rejected and the payer sees Telegram's generic failure instead.
    assert len(body["error_message"]) <= 255


class _ExplodingRepo:
    """A repo whose every awaited method raises. Stands in for a slow or
    broken DB (Supabase latency, pool exhaustion): if the pre_checkout path
    consulted a repo before answering Telegram, that round trip is exactly
    what would blow the ~10s deadline in production -- here it raises loudly
    so the regression is caught deterministically instead of as a flaky
    timeout."""

    def __getattr__(self, name):
        async def _boom(*args, **kwargs):
            raise AssertionError(
                f"pre_checkout must not touch the DB before answering "
                f"(called {name})"
            )
        return _boom


async def test_pre_checkout_answers_without_touching_the_db():
    # The incident: a Fix Pack pre_checkout timed out (BOT_PRECHECKOUT_TIMEOUT)
    # while the Pro one was fine, because that path did a DB round trip first.
    # The answer is now a refusal rather than an approval, and the deadline is
    # unchanged: Telegram still cancels at ~10s, and a decline that arrives
    # late is as bad as an approval that does -- the payer gets Telegram's
    # generic failure instead of the sentence explaining where to pay.
    #
    # Exploding repos prove no repo is touched on this path.
    calls: list = []
    transport = _telegram_transport(calls)
    update = {"update_id": 1, "pre_checkout_query": {
        "id": "pcq_fp", "from": {"id": 555}, "currency": "XTR",
        "total_amount": 600, "invoice_payload": "fixpack:aud_deadbeef"}}

    result = await telegram_stars.handle_update(
        update, account_repo=_ExplodingRepo(), payment_repo=_ExplodingRepo(),
        audit_repo=_ExplodingRepo(), fixpack_repo=_ExplodingRepo(),
        token="t", transport=transport,
    )
    assert result["handled"] == "pre_checkout_query"
    assert calls[0][0] == "answerPreCheckoutQuery"
    assert calls[0][1]["pre_checkout_query_id"] == "pcq_fp"
    assert calls[0][1]["ok"] is False


async def test_pre_checkout_answer_uses_timeout_under_telegram_deadline(monkeypatch):
    # The outbound answerPreCheckoutQuery must be bounded well under Telegram's
    # ~10s deadline; the generic 30s _call timeout would let a slow Bot API
    # response sail past it and cancel the charge. Fails on the old code
    # (answer used the default 30s), passes on the new (short bound).
    seen: dict = {}

    async def spy_call(method, body, *, token, transport=None, timeout=30):
        seen["method"] = method
        seen["timeout"] = timeout
        return {"ok": True}

    monkeypatch.setattr(telegram_stars, "_call", spy_call)
    update = {"update_id": 1, "pre_checkout_query": {
        "id": "pcq_2", "from": {"id": 555}, "currency": "XTR",
        "total_amount": 600, "invoice_payload": "fixpack:aud_x"}}

    await telegram_stars.handle_update(
        update, account_repo=FakeAccountRepo(), payment_repo=FakePaymentRepo(),
        token="t",
    )
    assert seen["method"] == "answerPreCheckoutQuery"
    assert seen["timeout"] < 10


# --- 3. successful_payment grants pro + is idempotent on retry ---

async def test_successful_payment_grants_pro_and_dms_key():
    calls: list = []
    transport = _telegram_transport(calls)
    accounts, payments = FakeAccountRepo(), FakePaymentRepo()

    result = await telegram_stars.handle_update(
        _successful_payment_update("charge_abc"),
        account_repo=accounts, payment_repo=payments,
        token="t", transport=transport,
    )
    assert result == {"ok": True, "handled": "successful_payment",
                      "persisted": True, "key_delivered": True}
    # exactly one account, tier pro, key delivered by sendMessage
    assert len(accounts.by_id) == 1
    account = next(iter(accounts.by_id.values()))
    assert account["tier"] == "pro"
    send_calls = [c for c in calls if c[0] == "sendMessage"]
    assert len(send_calls) == 1
    text = send_calls[0][1]["text"]
    # The key is delivered straight out of the grant that minted it, in this
    # same handler. It is never re-read from the account row, because the row
    # does not have it (migration 0019) -- assert that absence directly, since
    # a fake that carried the key here is what hid this bug in the first place.
    assert "api_key" not in account
    assert api_key_prefix(_delivered_key(text)) == account["key_prefix"]
    # Pro is a general subscription, not tied to any one audit, so the DM
    # must NOT dangle a report link (there is no report for this purchase);
    # it points at the run-an-audit landing page instead.
    assert "Open your report" not in text
    assert "Run an audit: https://drydock.co" in text
    # one completed payment recorded, keyed by the charge id
    assert len(payments.rows) == 1
    pay = next(iter(payments.rows.values()))
    assert pay["status"] == "completed"
    assert pay["external_ref"] == "charge_abc"


async def test_duplicate_successful_payment_is_idempotent():
    calls: list = []
    transport = _telegram_transport(calls)
    accounts, payments = FakeAccountRepo(), FakePaymentRepo()

    for _ in range(2):  # Telegram retries the webhook until it gets 200
        await telegram_stars.handle_update(
            _successful_payment_update("charge_dup"),
            account_repo=accounts, payment_repo=payments,
            token="t", transport=transport,
        )
    # No second account, no second payment — same charge id.
    assert len(accounts.by_id) == 1
    assert len(payments.rows) == 1
    # The retry cannot re-deliver the key: it was minted once, in the first
    # call, and is stored nowhere. So instead of crashing on a key that isn't
    # there (the bug this replaced) the payer gets a plain explanation and the
    # /rotatekey recovery path -- which works, because the chat_id was stamped.
    send_calls = [c for c in calls if c[0] == "sendMessage"]
    assert len(send_calls) == 2
    first, second = send_calls[0][1]["text"], send_calls[1][1]["text"]
    assert _delivered_key(first) is not None
    assert _delivered_key(second) is None
    assert "already delivered" in second
    assert "/rotatekey" in second


# --- 4. webhook endpoint rejects wrong/missing secret token ---

def _override(accounts, payments, transport):
    app.dependency_overrides[get_account_repo] = lambda: accounts
    app.dependency_overrides[get_payment_repo] = lambda: payments
    app.dependency_overrides[get_billing_transport] = lambda: transport


def _clear():
    for dep in (get_account_repo, get_payment_repo, get_billing_transport):
        app.dependency_overrides.pop(dep, None)


def test_webhook_rejects_missing_and_wrong_secret(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.setenv("TELEGRAM_WEBHOOK_SECRET", "s3cret")
    _override(FakeAccountRepo(), FakePaymentRepo(), _telegram_transport([]))
    try:
        # missing header
        r = client.post("/v1/webhooks/telegram", json={"update_id": 1})
        assert r.status_code == 401
        # wrong secret
        r = client.post("/v1/webhooks/telegram", json={"update_id": 1},
                        headers={"X-Telegram-Bot-Api-Secret-Token": "wrong"})
        assert r.status_code == 401
    finally:
        _clear()


def test_webhook_503_when_not_configured(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_WEBHOOK_SECRET", raising=False)
    _override(FakeAccountRepo(), FakePaymentRepo(), _telegram_transport([]))
    try:
        r = client.post("/v1/webhooks/telegram", json={"update_id": 1},
                        headers={"X-Telegram-Bot-Api-Secret-Token": "s"})
        assert r.status_code == 503
        assert r.json()["detail"]["reason"] == "telegram_not_configured"
    finally:
        _clear()


def test_webhook_correct_secret_processes_payment(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.setenv("TELEGRAM_WEBHOOK_SECRET", "s3cret")
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    _override(accounts, payments, _telegram_transport(calls))
    try:
        r = client.post(
            "/v1/webhooks/telegram",
            json=_successful_payment_update("charge_endpoint"),
            headers={"X-Telegram-Bot-Api-Secret-Token": "s3cret"},
        )
        assert r.status_code == 200
        assert r.json()["handled"] == "successful_payment"
        assert len(accounts.by_id) == 1
    finally:
        _clear()


# --- 5. /mykey key recovery ---

def _text_update(text: str, chat_id: int = 555):
    return {"update_id": 1, "message": {
        "chat": {"id": chat_id}, "from": {"id": chat_id}, "text": text}}


async def _send(update, accounts, payments, calls):
    return await telegram_stars.handle_update(
        update, account_repo=accounts, payment_repo=payments,
        token="t", transport=_telegram_transport(calls),
    )


def _last_text(calls):
    sends = [c for c in calls if c[0] == "sendMessage"]
    return sends[-1][1]["text"] if sends else None


def _delivered_key(msg):
    """The API key a bot message actually handed over, or None if it handed
    over none. Read out of the message text on purpose: the key exists only in
    what was delivered, never in the account row (migration 0019), so scraping
    the DM is the only way to assert on it -- and a test that reaches into the
    repo for it would be asserting against a fake that lies."""
    found = re.search(r"sk_live_[A-Za-z0-9_-]+", msg or "")
    return found.group(0) if found else None


async def test_mykey_shows_prefix_and_never_the_full_key():
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    # A Stars purchase links this chat_id (555) to the account automatically.
    await _send(_successful_payment_update("charge_mykey", 555),
                accounts, payments, calls)
    account = next(iter(accounts.by_id.values()))
    purchase_key = _delivered_key(_last_text(calls))

    calls.clear()
    result = await _send(_text_update("/mykey", 555), accounts, payments, calls)
    assert result["handled"] == "mykey" and result["found"] is True
    msg = _last_text(calls)
    # The full secret is never re-sent; only the safe prefix is shown, and the
    # user is pointed at /rotatekey to recover a lost key.
    assert purchase_key not in msg
    assert account["key_prefix"] in msg
    assert "/rotatekey" in msg


async def test_mykey_no_account_returns_helpful_message():
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    result = await _send(_text_update("/mykey", 999), accounts, payments, calls)
    assert result["handled"] == "mykey" and result["found"] is False
    msg = _last_text(calls)
    # Explains both recovery paths, leaks no key.
    assert "Stars" in msg and "/link" in msg
    assert "sk_live_" not in msg


async def test_rotatekey_mints_new_key_for_linked_account():
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    await _send(_successful_payment_update("charge_rot", 555),
                accounts, payments, calls)
    account = next(iter(accounts.by_id.values()))
    old_key = _delivered_key(_last_text(calls))

    calls.clear()
    result = await _send(_text_update("/rotatekey", 555), accounts, payments, calls)
    assert result["handled"] == "rotatekey" and result["found"] is True
    msg = _last_text(calls)
    # The freshly minted key is delivered; it is not the old one, and it is now
    # the account's current key (the stored prefix moved with it).
    new_key = _delivered_key(msg)
    assert new_key != old_key
    assert old_key not in msg
    assert api_key_prefix(new_key) == account["key_prefix"]


async def test_rotatekey_no_account_returns_helpful_message():
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    result = await _send(_text_update("/rotatekey", 999), accounts, payments, calls)
    assert result["handled"] == "rotatekey" and result["found"] is False
    assert "sk_live_" not in _last_text(calls)


# --- 6. /link payment claiming ---
#
# The fixtures below are USDT payments, and USDT is no longer a way to pay.
# They are still the right fixture: /link's job is to hand over the key a
# COMPLETED payment already bought, and a completed USDT invoice from before
# the rail was withdrawn is exactly that -- someone's money, and a key they
# have not collected. The lookup survived the removal deliberately; these
# tests are what says it still works.


async def _completed_usdt_payment(payments, accounts, tx_hash, *, chat_id=None):
    """A credited USDT payment as the poller left it: status completed,
    external_ref = tx hash, linked to a real account."""
    acct = await accounts.create(api_key="sk_live_usdtkey", tier="pro")
    row = await payments.create(
        account_id=acct["id"], provider=telegram_stars.RETIRED_USDT_PROVIDER,
        external_ref=tx_hash, amount=5.5, currency="USDT",
        status="completed", tier_granted="pro",
    )
    if chat_id is not None:
        row["telegram_chat_id"] = chat_id
    return acct, row


async def test_link_valid_unlinked_payment_links_and_returns_key():
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    acct, row = await _completed_usdt_payment(payments, accounts, "0xabc")

    result = await _send(_text_update("/link 0xabc", 777),
                         accounts, payments, calls)
    assert result["result"] == "linked"
    # /link mints the key it hands over. The plaintext the poller minted when
    # it credited this payment was discarded and is NOT what gets sent -- it
    # could not be, since nothing stored it.
    delivered = _delivered_key(_last_text(calls))
    assert delivered != acct["api_key"]
    assert acct["api_key"] not in _last_text(calls)
    assert api_key_prefix(delivered) == accounts.by_id[acct["id"]]["key_prefix"]
    # Persisted the association so a later /mykey works.
    assert row["telegram_chat_id"] == "777"


async def test_link_is_idempotent_for_same_chat():
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    await _completed_usdt_payment(payments, accounts, "0xdup")
    first = await _send(_text_update("/link 0xdup", 777), accounts, payments, calls)
    assert first["result"] == "linked"
    delivered = _delivered_key(_last_text(calls))
    assert delivered is not None

    # Re-running /link is safe but delivers no second key: the payment's one
    # delivery was already spent above. Rotating again here would silently kill
    # the key the payer is already holding.
    second = await _send(_text_update("/link 0xdup", 777), accounts, payments, calls)
    assert second["result"] == "already_delivered"
    assert _delivered_key(_last_text(calls)) is None
    assert "/rotatekey" in _last_text(calls)
    assert accounts.rotations == [next(iter(accounts.by_id))]


async def test_link_after_another_door_already_took_the_key():
    """Two doors to one payment. If the key already went out somewhere else,
    /link must not hand out a second one -- and must not blow up reaching for a
    key that was never stored (the original bug: /link read api_key straight
    off get_by_id).

    The other door used to be the USDT invoice poll. That endpoint is gone, so
    the test goes through deliver_key_once directly, which is what BOTH doors
    always called: the one-shot claim is the invariant, not the endpoint that
    happened to be on the other side of it."""
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    acct, row = await _completed_usdt_payment(payments, accounts, "0xweb")

    # Somewhere else claimed the delivery first and was handed the key.
    web_key = await deliver_key_once(
        account_repo=accounts, payment_repo=payments, payment=row)
    assert web_key is not None
    web = {"api_key": web_key}

    result = await _send(_text_update("/link 0xweb", 777), accounts, payments, calls)
    assert result["result"] == "already_delivered"
    msg = _last_text(calls)
    assert _delivered_key(msg) is None
    assert "/rotatekey" in msg
    # The claim still linked the chat, so /rotatekey really is usable from here.
    assert row["telegram_chat_id"] == "777"
    rotate = await _send(_text_update("/rotatekey", 777), accounts, payments, calls)
    assert rotate["found"] is True
    assert _delivered_key(_last_text(calls)) not in (None, web["api_key"])


async def test_link_already_claimed_by_other_chat_is_rejected():
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    acct, _ = await _completed_usdt_payment(
        payments, accounts, "0xowned", chat_id="111")

    result = await _send(_text_update("/link 0xowned", 222),
                         accounts, payments, calls)
    assert result["result"] == "already_claimed"
    msg = _last_text(calls)
    # No key leaked, and crucially no leak of the owning chat_id ("111").
    assert acct["api_key"] not in msg
    assert "111" not in msg


async def test_link_unknown_hash_reports_not_found():
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    result = await _send(_text_update("/link 0xnope", 333),
                         accounts, payments, calls)
    assert result["result"] == "not_found"
    assert "wasn't found" in _last_text(calls)


async def test_link_pending_payment_reports_pending():
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    # A payment row that carries the tx hash but isn't credited yet.
    await payments.create(
        account_id=None, provider=telegram_stars.RETIRED_USDT_PROVIDER, external_ref="0xpending",
        amount=5.5, currency="USDT", status="pending", tier_granted="pro",
    )
    result = await _send(_text_update("/link 0xpending", 444),
                         accounts, payments, calls)
    assert result["result"] == "pending"
    # It will never be confirmed now -- the poller that would have gone with
    # the rail. The message must send the payer to a human rather than tell
    # them to wait for something that is not coming.
    text = _last_text(calls).lower()
    assert "never confirmed" in text and "support" in text


async def test_link_without_hash_shows_usage():
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    result = await _send(_text_update("/link", 555), accounts, payments, calls)
    assert result["result"] == "missing_hash"
    assert "Usage" in _last_text(calls)


# --- 7. the commands that used to sell ---

async def test_upgrade_mints_nothing_and_says_where_to_pay():
    """/pricing told people to run /upgrade to get a Pay button. It now says
    where the Pay button is. Saying WHY matters: "not available" reads as an
    outage, and a payer who thinks the bot is broken retries here instead of
    going to the site."""
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    result = await _send(_text_update("/upgrade", 888), accounts, payments, calls)

    assert result == {"ok": True, "handled": "upgrade",
                      "result": "not_for_sale"}
    assert not any(c[0] in ("sendInvoice", "createInvoiceLink") for c in calls)
    dm = _last_text(calls)
    assert "no longer accepted" in dm
    assert "drydock.co" in dm
    # The two things that still work for someone who has already paid.
    assert "/mykey" in dm and "/link" in dm


async def test_fixpack_command_points_at_the_report_for_that_audit():
    """The audit lookup is kept even though nothing is sold here: a deep link
    to the wrong audit, or to a zip upload with no repository behind it, wastes
    the payer's time at the site rather than here."""
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []

    class Audits:
        async def get(self, audit_id):
            return {"id": audit_id, "repo_url": "https://github.com/acme/widget"}

    result = await telegram_stars.handle_update(
        _text_update("/fixpack aud_1234", 888),
        account_repo=accounts, payment_repo=payments, audit_repo=Audits(),
        token="t", transport=_telegram_transport(calls),
    )
    assert result["result"] == "not_for_sale"
    assert not any(c[0] == "sendInvoice" for c in calls)
    assert "/audit/aud_1234" in _last_text(calls)


async def test_fixpack_command_still_refuses_a_zip_audit():
    """The gate that would be confusing at the far end. A zip upload has no
    repository to open a pull request against, and the site would refuse it --
    but only after the payer had gone there expecting to buy."""
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []

    class Audits:
        async def get(self, audit_id):
            return {"id": audit_id, "repo_url": None}

    result = await telegram_stars.handle_update(
        _text_update("/fixpack aud_zip", 888),
        account_repo=accounts, payment_repo=payments, audit_repo=Audits(),
        token="t", transport=_telegram_transport(calls),
    )
    assert result["result"] == "not_github_audit"
    assert "/audit/aud_zip" not in _last_text(calls)


# --- 8. recurring subscriptions (Telegram Stars) ---

class FakeSubscriptionRepo:
    """In-memory stand-in for SubscriptionRepository, mirroring the natural-key
    (telegram_user_id, invoice_payload) behavior of the real repo so tests
    exercise the same upsert/renew/status logic."""

    def __init__(self):
        self.rows: dict[str, dict] = {}

    def _find(self, telegram_user_id, invoice_payload):
        for r in self.rows.values():
            if (r["telegram_user_id"] == telegram_user_id
                    and r["invoice_payload"] == invoice_payload):
                return r
        return None

    async def get_by_user_and_payload(self, telegram_user_id, invoice_payload):
        return self._find(telegram_user_id, invoice_payload)

    async def get_active_by_user(self, telegram_user_id):
        active = [
            r for r in self.rows.values()
            if r["telegram_user_id"] == telegram_user_id and r["status"] == "active"
        ]
        return active[-1] if active else None

    async def upsert_first(self, *, telegram_user_id, invoice_payload, tier,
                           telegram_chat_id, telegram_payment_charge_id, expires_at,
                           repo_full_name=None):
        existing = self._find(telegram_user_id, invoice_payload)
        if existing is not None:
            existing.update(
                tier=tier, telegram_chat_id=telegram_chat_id,
                telegram_payment_charge_id=telegram_payment_charge_id,
                status="active", expires_at=expires_at,
                repo_full_name=repo_full_name,
            )
            return existing
        row = {
            "id": str(uuid.uuid4()), "account_id": None,
            "telegram_user_id": telegram_user_id,
            "telegram_chat_id": telegram_chat_id, "tier": tier,
            "invoice_payload": invoice_payload,
            "telegram_payment_charge_id": telegram_payment_charge_id,
            "status": "active", "expires_at": expires_at,
            "repo_full_name": repo_full_name,
        }
        self.rows[row["id"]] = row
        return row

    async def renew(self, subscription_id, *, expires_at, telegram_payment_charge_id):
        r = self.rows[subscription_id]
        r.update(expires_at=expires_at,
                 telegram_payment_charge_id=telegram_payment_charge_id,
                 status="active")
        return r

    async def set_status(self, subscription_id, status):
        r = self.rows[subscription_id]
        r["status"] = status
        return r


async def _send_sub(update, *, accounts=None, payments=None, subs=None, calls=None):
    calls = calls if calls is not None else []
    return await telegram_stars.handle_update(
        update, account_repo=accounts or FakeAccountRepo(),
        payment_repo=payments or FakePaymentRepo(),
        subscription_repo=subs if subs is not None else FakeSubscriptionRepo(),
        token="t", transport=_telegram_transport(calls),
    )


def _sub_payment_update(charge_id, *, chat_id=555, user_id=555,
                        expires_at=1000, is_first=False, is_recurring=True):
    sp = {
        "currency": "XTR", "total_amount": 1,
        "invoice_payload": telegram_stars.SUBSCRIPTION_PAYLOAD,
        "telegram_payment_charge_id": charge_id,
        "subscription_expiration_date": expires_at,
        "is_recurring": is_recurring,
    }
    if is_first:
        sp["is_first_recurring"] = True
    return {"update_id": 1, "message": {
        "chat": {"id": chat_id}, "from": {"id": user_id},
        "successful_payment": sp}}


def _sub_updated_update(state, *, user_id=555,
                        invoice_payload=None):
    return {"update_id": 1, "subscription": {
        "user": {"id": user_id},
        "invoice_payload": invoice_payload or telegram_stars.SUBSCRIPTION_PAYLOAD,
        "state": state}}


async def test_subscribe_mints_no_invoice_while_monitoring_is_withdrawn():
    """The refusal used to come before createInvoiceLink, because a
    subscription link is a payable deep link -- once minted it lives in a chat
    and can be tapped later, long after we decided not to sell it. There is no
    createInvoiceLink any more, so the property is now structural; the
    assertions stay because what they check is the OUTCOME, not the branch."""
    calls: list = []
    result = await _send_sub(_text_update("/subscribe", 888), calls=calls)

    assert result == {"ok": True, "handled": "subscribe",
                     "result": "not_for_sale"}
    assert not any(c[0] == "createInvoiceLink" for c in calls)
    assert not any(c[0] == "sendInvoice" for c in calls)
    dm = [c for c in calls if c[0] == "sendMessage"][-1][1]["text"]
    assert "isn't on sale" in dm
    assert "haven't been charged" in dm


async def test_monitor_command_mints_no_invoice_while_withdrawn():
    """The other sale surface. /monitor takes an audit id, but the refusal must
    not depend on that lookup succeeding -- there is nothing to validate for a
    product we will not sell."""
    calls: list = []
    result = await _send_sub(_text_update("/monitor some-audit-id", 888),
                             calls=calls)

    assert result == {"ok": True, "handled": "monitor",
                     "result": "not_for_sale"}
    assert not any(c[0] == "createInvoiceLink" for c in calls)


async def test_the_for_sale_flag_cannot_put_monitoring_back_on_the_bot(monkeypatch):
    """monitor.MONITORING_FOR_SALE still gates the monitoring RUNNER, and
    turning it back on is the right way to resume that work. What it can no
    longer do is put /subscribe or /monitor back into business: the code that
    minted a subscription invoice went with the Stars rail.

    Asserted rather than assumed, because the flag reads like a kill switch
    for the whole feature and the next person to flip it will expect a sale."""
    enable_monitoring(monkeypatch)
    calls: list = []

    for command, handled in (("/subscribe", "subscribe"),
                             ("/monitor some-audit-id", "monitor")):
        result = await _send_sub(_text_update(command, 888), calls=calls)
        assert result == {"ok": True, "handled": handled,
                          "result": "not_for_sale"}

    assert not any(c[0] in ("sendInvoice", "createInvoiceLink") for c in calls)


# (a) first payment -> creates one subscriptions row with the right expires_at
async def test_subscription_first_payment_creates_row():
    subs, payments, calls = FakeSubscriptionRepo(), FakePaymentRepo(), []
    result = await _send_sub(
        _sub_payment_update("charge_1", expires_at=1234, is_first=True),
        subs=subs, payments=payments, calls=calls)
    assert result["handled"] == "subscription_payment"
    assert result["persisted"] is True and result["first"] is True
    assert len(subs.rows) == 1
    row = next(iter(subs.rows.values()))
    assert row["status"] == "active"
    assert row["expires_at"] == 1234
    assert row["telegram_payment_charge_id"] == "charge_1"
    assert row["tier"] == telegram_stars.SUBSCRIPTION_TIER
    # First charge DMs a confirmation; a completed payment row is recorded.
    assert any(c[0] == "sendMessage" for c in calls)
    assert len(payments.rows) == 1
    assert next(iter(payments.rows.values()))["product"] == "subscription"


# (b) renewal -> extends the SAME row's expires_at, no second row
async def test_subscription_renewal_extends_same_row():
    subs, payments, calls = FakeSubscriptionRepo(), FakePaymentRepo(), []
    await _send_sub(_sub_payment_update("charge_1", expires_at=1000, is_first=True),
                    subs=subs, payments=payments, calls=calls)
    result = await _send_sub(
        _sub_payment_update("charge_2", expires_at=2000, is_first=False),
        subs=subs, payments=payments, calls=calls)
    assert result["first"] is False
    assert len(subs.rows) == 1                       # no new row
    row = next(iter(subs.rows.values()))
    assert row["expires_at"] == 2000                 # extended
    assert row["telegram_payment_charge_id"] == "charge_2"  # rotated
    # Renewal does NOT re-DM the payer (only the first charge does).
    assert sum(1 for c in calls if c[0] == "sendMessage") == 1
    assert len(payments.rows) == 2                   # both charges recorded


async def test_duplicate_subscription_charge_records_one_payment():
    subs, payments, calls = FakeSubscriptionRepo(), FakePaymentRepo(), []
    upd = _sub_payment_update("charge_dup", expires_at=1000, is_first=True)
    await _send_sub(upd, subs=subs, payments=payments, calls=calls)
    await _send_sub(upd, subs=subs, payments=payments, calls=calls)
    assert len(subs.rows) == 1
    assert len(payments.rows) == 1                   # idempotent on external_ref


# (c) BotSubscriptionUpdated state=canceled -> status updated, access kept
async def test_subscription_updated_canceled_sets_status_keeps_access():
    subs, calls = FakeSubscriptionRepo(), []
    await _send_sub(_sub_payment_update("c1", expires_at=5000, is_first=True),
                    subs=subs, calls=calls)
    result = await _send_sub(_sub_updated_update("canceled"), subs=subs)
    assert result == {"ok": True, "handled": "subscription_updated",
                      "state": "canceled", "status": "canceled", "updated": True}
    row = next(iter(subs.rows.values()))
    assert row["status"] == "canceled"
    assert row["expires_at"] == 5000                 # access boundary untouched


# (d) state=failed -> status updated, access NOT revoked immediately
async def test_subscription_updated_failed_does_not_revoke_access():
    subs = FakeSubscriptionRepo()
    await _send_sub(_sub_payment_update("c1", expires_at=5000, is_first=True),
                    subs=subs)
    result = await _send_sub(_sub_updated_update("failed"), subs=subs)
    assert result["status"] == "failed" and result["updated"] is True
    row = next(iter(subs.rows.values()))
    assert row["status"] == "failed"
    assert row["expires_at"] == 5000                 # NOT revoked


async def test_subscription_updated_active_reenables():
    subs = FakeSubscriptionRepo()
    await _send_sub(_sub_payment_update("c1", expires_at=5000, is_first=True),
                    subs=subs)
    await _send_sub(_sub_updated_update("canceled"), subs=subs)
    result = await _send_sub(_sub_updated_update("active"), subs=subs)
    assert result["status"] == "active"
    assert next(iter(subs.rows.values()))["status"] == "active"


async def test_subscription_updated_unknown_row_is_benign():
    subs = FakeSubscriptionRepo()
    result = await _send_sub(_sub_updated_update("canceled", user_id=999), subs=subs)
    assert result["updated"] is False


async def test_unsubscribe_cancels_and_flips_status():
    subs, calls = FakeSubscriptionRepo(), []
    await _send_sub(_sub_payment_update("c1", chat_id=777, user_id=777,
                                        expires_at=9000, is_first=True),
                    subs=subs, calls=calls)
    calls.clear()
    result = await _send_sub(_text_update("/unsubscribe", 777), subs=subs, calls=calls)
    assert result == {"ok": True, "handled": "unsubscribe", "found": True}
    # editUserStarSubscription called with is_canceled=True and the stored charge.
    edits = [c for c in calls if c[0] == "editUserStarSubscription"]
    assert len(edits) == 1
    assert edits[0][1] == {"user_id": "777",
                           "telegram_payment_charge_id": "c1",
                           "is_canceled": True}
    assert next(iter(subs.rows.values()))["status"] == "canceled"


async def test_unsubscribe_without_active_subscription():
    subs, calls = FakeSubscriptionRepo(), []
    result = await _send_sub(_text_update("/unsubscribe", 111), subs=subs, calls=calls)
    assert result == {"ok": True, "handled": "unsubscribe", "found": False}
    assert not any(c[0] == "editUserStarSubscription" for c in calls)


async def test_subscription_pre_checkout_is_declined_too():
    """Product-agnostic, and deliberately so: the payload is not read on this
    path. A subscription's FIRST charge emits a pre-checkout, so declining it
    stops a subscription from starting on a rail we no longer accept. Renewals
    of an existing subscription do not come through here -- they arrive as
    successful_payment and are honoured."""
    calls: list = []
    update = {"update_id": 1, "pre_checkout_query": {
        "id": "pcq_sub", "from": {"id": 555}, "currency": "XTR",
        "total_amount": 1, "invoice_payload": telegram_stars.SUBSCRIPTION_PAYLOAD}}
    result = await _send_sub(update, calls=calls)
    assert result["handled"] == "pre_checkout_query"
    assert calls[0][0] == "answerPreCheckoutQuery"
    assert calls[0][1]["ok"] is False


async def test_subscription_payment_not_configured_reports_gracefully():
    class NoneSubs(FakeSubscriptionRepo):
        async def upsert_first(self, **kwargs):
            return None
    calls: list = []
    result = await _send_sub(
        _sub_payment_update("c1", is_first=True),
        subs=NoneSubs(), calls=calls)
    assert result == {"ok": True, "handled": "subscription_payment",
                      "persisted": False}
    assert any(c[0] == "sendMessage" for c in calls)


# --- /link with a Fix Pack reference ---
#
# A Fix Pack payment is completed and matches a DRY- reference like any other,
# but grants no account: it is delivered as a pull request. /link used to stamp
# the chat onto it FIRST and discover that second, which is what broke a Pro
# payer's key recovery -- see tests/test_billing_concurrency_postgres.py for
# the half of this that needs a real database.


async def _completed_fixpack_payment(payments, reference: str):
    row = await payments.create(
        account_id=None, provider="bank_transfer", external_ref=reference,
        amount=29.07, currency="USD", status="completed",
        tier_granted=None, product="fixpack",
    )
    return row


async def test_link_with_a_fixpack_reference_claims_nothing():
    """The order is the fix. The chat must not end up on a payment that has no
    key to give -- once stamped, nothing ever removes it."""
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    row = await _completed_fixpack_payment(payments, "DRY-FXPK23")

    result = await _send(_text_update("/link DRY-FXPK23", 777),
                         accounts, payments, calls)

    assert result["result"] == "no_account"
    assert row.get("telegram_chat_id") is None, "the chat was stamped anyway"


async def test_link_with_a_fixpack_reference_explains_instead_of_alarming():
    """The old text said the account 'could not be loaded' and sent the payer
    to support -- describing a failure to someone whose payment worked, about a
    key that was never meant to exist."""
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    await _completed_fixpack_payment(payments, "DRY-FXPK24")

    await _send(_text_update("/link DRY-FXPK24", 777), accounts, payments, calls)

    text = _last_text(calls)
    assert "Fix Pack" in text
    assert "pull request" in text
    assert "contact support" not in text
    # The reassurance is the point: someone who typed a command and got an
    # unexpected answer assumes they broke something.
    assert "/mykey" in text and "still work" in text


async def test_a_pro_link_is_untouched_by_the_new_check():
    """The guard sits above the claim, so it must not intercept the ordinary
    path -- a Pro payment still links and still delivers exactly one key."""
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    _acct, row = await _completed_usdt_payment(payments, accounts, "0xpro")

    result = await _send(_text_update("/link 0xpro", 777),
                         accounts, payments, calls)

    assert result["result"] == "linked"
    assert row["telegram_chat_id"] == "777"
    assert _delivered_key(_last_text(calls)) is not None


# --- 12. a charge that arrives after the rail was withdrawn -----------------

async def test_a_stars_charge_is_still_honoured_after_the_withdrawal():
    """The asymmetry that shapes handle_update. Nothing here can mint an
    invoice, but by the time successful_payment arrives Telegram has already
    moved the money -- refusing to handle it does not refund anybody, it only
    means the payer gets nothing for what they paid."""
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []

    result = await _send(_successful_payment_update("charge_after_withdrawal"),
                         accounts, payments, calls)

    assert result["handled"] == "successful_payment"
    assert result["persisted"] is True
    assert result["key_delivered"] is True
    assert _delivered_key(_last_text(calls)) is not None


async def test_that_charge_pages_the_operator(monkeypatch):
    """Handled correctly is not the same as expected. A Stars charge landing
    after the rail was withdrawn means an invoice minted before it is still
    out there, or a subscription is still renewing -- either way a human has a
    decision to make about a refund or a cancellation, and only they can make
    it."""
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.setenv("TELEGRAM_ADMIN_CHAT_ID", "999")
    seen: list = []

    async def fake_notify(text, **kwargs):
        seen.append((text, kwargs))
        return True

    monkeypatch.setattr("app.alerts.notify_operator", fake_notify)

    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    await _send(_successful_payment_update("charge_paged"), accounts, payments, calls)

    assert len(seen) == 1
    text, kwargs = seen[0]
    assert "WITHDRAWN" in text
    assert "charge_paged" in text
    # Deduped on the charge id: Telegram retries the webhook until it gets a
    # 200, and one charge is one thing for the operator to look at.
    assert kwargs["dedupe_key"] == "stars-withdrawn:charge_paged"


async def test_the_alert_cannot_cost_the_payer_their_key(monkeypatch):
    """The alert runs on a path where the money has already moved. If it could
    raise, a Telegram outage on OUR alert channel would turn a paid charge into
    a 5xx, Telegram would retry, and the payer would still have nothing."""
    async def exploding_notify(text, **kwargs):
        raise RuntimeError("alert channel down")

    monkeypatch.setattr("app.alerts.notify_operator", exploding_notify)

    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    result = await _send(_successful_payment_update("charge_alert_broken"),
                         accounts, payments, calls)

    assert result["key_delivered"] is True
