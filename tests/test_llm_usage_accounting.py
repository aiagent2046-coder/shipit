"""Stage 4 step 1: LLM cost accounting is observability only.

Covers the write path end to end with fake repos -- through the worker, which
is where the scan (and so the spend) happens since the queue cutover -- plus the
two invariants the accounting must never violate:
  * a real LLM run records exactly ONE row with the summed tokens and the cost
    computed from app/llm/pricing.py;
  * a content-hash cache hit (reused_from_prior_audit) records NOTHING -- a
    reused audit costs $0 and must not double-charge.
No enforcement/blocking is exercised: nothing here caps or rejects a request.
"""

import io
import json
import uuid
import zipfile
from decimal import Decimal

from fastapi.testclient import TestClient

from app.llm import pricing
from app.llm.client import (LLMClient, LLMUsage, Provider,
                             supports_sampling_params)
from app.main import app, get_audit_repo
from tests.conftest import (drain_audit_queue, force_pro_account,
                           run_audit_job)

# Only a paying account reaches the provider: the free tier is static-only.
_ACCOUNT_ID = "33333333-3333-3333-3333-333333333333"

client = TestClient(app)

NEXT_PKG = json.dumps({"dependencies": {"next": "15.0.0", "react": "19.0.0"}}).encode()


def make_zip(entries: dict[str, bytes]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    buf.seek(0)
    return buf


class FakeAuditRepo:
    """In-memory AuditRepository keyed by content_hash (mirrors the one in
    tests/test_audit_determinism.py) so the cache-hit branch is reachable."""

    def __init__(self):
        self.rows: list[dict] = []

    async def create(self, *, stack, file_count, score_total, score_json,
                     findings_json, repo_url=None, content_hash=None,
                     engine_version=None):
        row = {
            "id": str(uuid.uuid4()), "stack": stack, "status": "completed",
            "file_count": file_count, "score_total": score_total,
            "score_json": score_json, "findings_json": findings_json,
            "repo_url": repo_url, "content_hash": content_hash,
            "engine_version": engine_version, "access_token": "tok",
        }
        self.rows.append(row)
        return row

    async def get_by_content_hash(self, content_hash, engine_version, basis):
        matches = [r for r in self.rows
                   if r["content_hash"] == content_hash
                   and r["engine_version"] == engine_version
                   and r["status"] == "completed"]
        return matches[-1] if matches else None


class FakeUsageRepo:
    """Captures every llm_usage row create() is asked to write."""

    def __init__(self):
        self.rows: list[dict] = []

    async def create(self, **kwargs):
        self.rows.append(kwargs)
        return {"id": str(uuid.uuid4()), **kwargs}

    async def sum_anon_spend_today(self):
        # Enforcement (Stage 4 step 2) reads this before an anonymous scan.
        # These accounting tests stay well under any cap, so report $0.
        return Decimal("0")


class FakeLLM(LLMClient):
    def __init__(self, response: str):
        super().__init__(providers=[Provider("anthropic", "https://x", "k", "m")])
        self._response = response

    def complete(self, system, user, max_tokens=4096):
        # AITunnel (primary provider) reports the dotted name in data["model"];
        # mirror that here so the accounting is exercised against the real
        # response spelling, not the dashed request name.
        return self._response, LLMUsage(
            model="claude-sonnet-4.6", input_tokens=1000, output_tokens=200)


def _auth_zip() -> io.BytesIO:
    # auth.ts matches the 'auth' rubric so the LLM stage actually runs.
    return make_zip({
        "package.json": NEXT_PKG,
        "app/auth.ts": b"const password = 'x'  // check auth token",
    })


def test_pricing_cost_matches_published_sonnet_rates():
    # Both provider spellings price identically: 1M in @ $3 + 1M out @ $15 = $18.
    for model in ("claude-sonnet-4.6", "claude-sonnet-4-6"):
        assert pricing.cost_usd(model, 1_000_000, 1_000_000) == Decimal("18.00")
        assert pricing.cost_usd(model, 0, 0) == Decimal("0")  # zero tokens -> $0


def test_both_provider_spellings_priced_from_real_row_not_default():
    """The dot/dash regression guard: AITunnel returns "claude-sonnet-4.6" and
    the direct Anthropic fallback "claude-sonnet-4-6" for the same model. Both
    must resolve to the actual table row, not merely coincide with DEFAULT_PRICE.
    Asserting identity with the row (not just an equal number) is what catches a
    key that stopped matching."""
    for name in ("claude-sonnet-4.6", "claude-sonnet-4-6"):
        assert name in pricing.PRICE_TABLE
        assert pricing.price_for(name) is pricing.PRICE_TABLE[name]


def test_price_for_matches_by_key_not_accidental_default(monkeypatch):
    """With two DIFFERENT-priced models in the table, each must resolve to ITS
    OWN row and an unknown model to the (distinct) default. This fails if
    price_for ever silently rode on DEFAULT_PRICE — the failure mode that hid
    the dot/dash miss when the default happened to equal the only row."""
    cheap = {"input": Decimal("1.00"), "output": Decimal("2.00")}
    dear = {"input": Decimal("10.00"), "output": Decimal("40.00")}
    default = {"input": Decimal("99.00"), "output": Decimal("99.00")}
    monkeypatch.setattr(pricing, "PRICE_TABLE",
                        {"cheap-model": cheap, "dear-model": dear})
    monkeypatch.setattr(pricing, "DEFAULT_PRICE", default)

    assert pricing.price_for("cheap-model") is cheap
    assert pricing.price_for("dear-model") is dear
    assert pricing.price_for("unknown-model") is default
    # And the costs are all distinct, proving each matched its own row.
    assert pricing.cost_usd("cheap-model", 1_000_000, 1_000_000) == Decimal("3.00")
    assert pricing.cost_usd("dear-model", 1_000_000, 1_000_000) == Decimal("50.00")
    assert pricing.cost_usd("unknown-model", 1_000_000, 1_000_000) == Decimal("198.00")


def test_pricing_unknown_model_uses_fail_safe_high_default():
    # An unknown model must never under-count: it prices at DEFAULT_PRICE, the
    # most expensive known rates, so cost >= any known model's cost.
    unknown = pricing.cost_usd("some-future-model", 1000, 1000)
    known = pricing.cost_usd("claude-sonnet-4.6", 1000, 1000)
    assert unknown >= known


def test_pricing_negative_tokens_clamped_to_zero():
    assert pricing.cost_usd("claude-sonnet-4.6", -5, -5) == Decimal("0")


async def test_audit_records_one_usage_row_with_cost():
    audit_repo = FakeAuditRepo()
    usage_repo = FakeUsageRepo()
    await run_audit_job(
        _auth_zip().getvalue(), llm_client=FakeLLM("[]"),
        audit_repo=audit_repo, llm_usage_repo=usage_repo,
        account_id=_ACCOUNT_ID,
    )

    assert len(usage_repo.rows) == 1
    row = usage_repo.rows[0]
    assert row["job_type"] == "audit"
    # Attributed to the payer. An anonymous caller would produce no row at all:
    # the free tier is static-only and never reaches the provider.
    assert row["account_id"] == _ACCOUNT_ID
    assert row["model"] == "claude-sonnet-4.6"
    # Only the 'auth' rubric matches this content, so one .complete() call.
    assert row["calls"] == 1
    assert row["input_tokens"] == 1000
    assert row["output_tokens"] == 200
    # cost = (1000/1e6)*3 + (200/1e6)*15 = 0.003 + 0.003 = 0.006
    assert row["cost_usd"] == Decimal("0.006")
    # job_id links to the audit that was just persisted.
    assert row["job_id"] == audit_repo.rows[0]["id"]


async def test_cache_hit_records_no_usage_row(audit_queue, monkeypatch):
    # Driven through the endpoint, because the cache hit IS an endpoint
    # behaviour: it answers inline, queues no job, and so reaches no scan.
    audit_repo = FakeAuditRepo()
    usage_repo = FakeUsageRepo()
    # As a payer: an anonymous first request would record no usage row either,
    # and the test would pass without demonstrating anything about the cache.
    force_pro_account(monkeypatch)
    app.dependency_overrides[get_audit_repo] = lambda: audit_repo
    try:
        r1 = client.post(
            "/v1/audits",
            files={"archive": ("app.zip", _auth_zip(), "application/zip")},
        )
        assert r1.status_code == 202
        await drain_audit_queue(
            audit_queue, audit_repo=audit_repo, llm_client=FakeLLM("[]"),
            llm_usage_repo=usage_repo,
        )
        assert len(usage_repo.rows) == 1

        # Second audit of byte-identical content: cache hit, no LLM call.
        r2 = client.post(
            "/v1/audits",
            files={"archive": ("app.zip", _auth_zip(), "application/zip")},
        )
        assert r2.status_code == 202
        assert r2.json()["llm"] == {"reused_from_prior_audit": True}
    finally:
        app.dependency_overrides.pop(get_audit_repo, None)

    # Still exactly one row: the reused audit recorded nothing.
    assert len(usage_repo.rows) == 1


async def test_no_usage_row_when_llm_stage_skipped():
    # No providers configured -> the stage never runs (calls=0) -> no row,
    # even though the audit itself succeeds.
    usage_repo = FakeUsageRepo()
    row = await run_audit_job(
        _auth_zip().getvalue(), llm_client=LLMClient(providers=[]),
        audit_repo=FakeAuditRepo(), llm_usage_repo=usage_repo,
    )

    assert row["score_json"]["basis"] == "static_only"
    assert usage_repo.rows == []


# --- models that reject the sampling parameters -----------------------------

def test_sonnet_5_is_priced_from_its_own_row_at_list_not_promo():
    """A promotional rate must not enter the table.

    Sonnet 5 runs an introductory $2/$10 to 2026-08-31. This table feeds the
    spend cap and the cost accounting, where a guard that reads LOW is the
    dangerous direction: when the promotion lapses, every audit would be
    under-counted silently. List price over-estimates during the promotion,
    which is the safe error.
    """
    from decimal import Decimal

    assert "claude-sonnet-5" in pricing.PRICE_TABLE
    assert pricing.price_for("claude-sonnet-5") is pricing.PRICE_TABLE["claude-sonnet-5"]
    # 1M in + 1M out at list = $3 + $15. At the promo rate this would be $12.
    assert pricing.cost_usd("claude-sonnet-5", 1_000_000, 1_000_000) == Decimal("18.00")


def test_a_model_without_sampling_params_gets_no_temperature():
    """`temperature: 0` is a 400 on Claude 5, not a quality knob.

    The scanner has sent it on every call since it was written, so pointing
    LLM_MODEL at Sonnet 5 without this branch fails EVERY request -- the LLM
    stage dies and the audit silently delivers static-only results under a
    paid basis. Asserted on both wire formats because both carried the
    parameter, and a fix to one is a 400 on the other.
    """
    from app.llm.client import LLMClient, Provider

    old = Provider(kind="anthropic", base_url="x", api_key="k",
                   model="claude-sonnet-4-6")
    new = Provider(kind="anthropic", base_url="x", api_key="k",
                   model="claude-sonnet-5")

    assert LLMClient._payload_anthropic(old, "s", "u", 4096)["temperature"] == 0
    assert "temperature" not in LLMClient._payload_anthropic(new, "s", "u", 4096)
    assert LLMClient._payload_openai(old, "s", "u", 4096)["temperature"] == 0
    assert "temperature" not in LLMClient._payload_openai(new, "s", "u", 4096)


def test_thinking_is_disabled_only_where_it_would_otherwise_switch_on():
    """max_tokens bounds thinking AND text together.

    Sonnet 4.6 ran without thinking when the key was absent; Claude 5 turns
    adaptive thinking on in that same case. The rubric path sends 8192
    (app/scan/llm_scan.py) — not the 4096 default — and a long think eats
    that budget and truncates the JSON the rubric parser reads, so the new
    behaviour is declined explicitly rather than inherited.

    Absent on the OpenAI-compatible body on purpose: `thinking` is not part of
    that wire format, and sending an unknown key is the provider's error to
    raise.
    """
    from app.llm.client import LLMClient, Provider

    old = Provider(kind="anthropic", base_url="x", api_key="k",
                   model="claude-sonnet-4-6")
    new = Provider(kind="anthropic", base_url="x", api_key="k",
                   model="claude-sonnet-5")

    assert "thinking" not in LLMClient._payload_anthropic(old, "s", "u", 4096)
    assert LLMClient._payload_anthropic(new, "s", "u", 4096)["thinking"] == {
        "type": "disabled"}
    assert "thinking" not in LLMClient._payload_openai(new, "s", "u", 4096)


def test_every_priced_model_is_classified_for_sampling_support():
    """The two hand-maintained tables must not drift apart.

    Adding a model to PRICE_TABLE without deciding whether it accepts
    `temperature` is how the 400 arrives in production: the cost is right and
    every request fails. This does not assert WHICH answer is correct -- only
    that someone made the call deliberately for Claude 5 names, where the
    default (send temperature) is the failing one.
    """
    from app.llm.client import (MODELS_WITH_SAMPLING_PARAMS,
                                MODELS_WITHOUT_SAMPLING_PARAMS)

    # This started as `if "-5" in name`, meaning "a Claude 5 model". It is not:
    # that substring also matches "claude-haiku-4-5", which takes temperature
    # perfectly well, and the test failed the moment Haiku was priced. Version
    # numbers are not a grammar. Both sets are now explicit and every priced
    # model must appear in exactly one -- which is the decision itself, not a
    # guess about it.
    for name in pricing.PRICE_TABLE:
        in_without = name in MODELS_WITHOUT_SAMPLING_PARAMS
        in_with = name in MODELS_WITH_SAMPLING_PARAMS
        assert in_without != in_with, (
            f"{name} is priced but not classified for sampling support: add it "
            "to exactly one of MODELS_WITH_SAMPLING_PARAMS / "
            "MODELS_WITHOUT_SAMPLING_PARAMS in app/llm/client.py. Guessing "
            "wrong in one direction is a 400 on every call.")

    # And the classification has to agree with the function that acts on it.
    for name in MODELS_WITH_SAMPLING_PARAMS:
        assert supports_sampling_params(name)
    for name in MODELS_WITHOUT_SAMPLING_PARAMS:
        assert not supports_sampling_params(name)


def test_with_model_gives_the_preview_its_own_model_and_leaves_the_original():
    """The free tier runs a cheaper model than the paid one in the same worker.

    `LLM_MODEL` is process-wide, so one env var cannot serve two tiers. Two
    ways this goes wrong, and both are silent: returning the chain unchanged
    bills the preview at Sonnet rates while the operator believes it is on
    Haiku, and mutating in place switches the paid audit running beside it
    down to the cheap model. Neither raises; both are only visible on the
    invoice or in the findings.
    """
    base = LLMClient(providers=[
        Provider("openai_compat", "https://reseller/v1", "k", "claude-sonnet-4-6"),
        Provider("anthropic", "https://api.anthropic.com", "k", "claude-sonnet-4-6"),
    ])
    preview = base.with_model("claude-haiku-4-5")

    assert [p.model for p in preview.providers] == ["claude-haiku-4-5"] * 2
    assert [p.model for p in base.providers] == ["claude-sonnet-4-6"] * 2
    # The chain itself must survive intact -- same providers, same order, same
    # credentials. A preview that silently lost the fallback provider would
    # degrade to static-only on the first outage instead of failing over.
    assert [(p.kind, p.base_url, p.api_key) for p in preview.providers] == [
        (p.kind, p.base_url, p.api_key) for p in base.providers]


def test_with_model_on_an_empty_chain_stays_empty():
    """No providers configured is a real state (it is what the free tier looks
    like on a deployment with no keys), and it must not become a crash inside
    the tier that is given away."""
    assert LLMClient(providers=[]).with_model("claude-haiku-4-5").providers == []
