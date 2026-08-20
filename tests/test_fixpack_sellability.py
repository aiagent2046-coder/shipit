"""Do not sell a Fix Pack we can already prove will deliver nothing.

TWICE NOW. Audit 05fa18f5 was sold one with no eligible finding at all, which
`has_auto_fixable_findings` was written to stop. Audit bd970b2b
(devtools-aggregator, 2026-08-20) got past it: the audit DID carry an eligible
finding — `users` readable with the anon key — and the generator still had no
move, because the table looks like this:

    create table public.users (id uuid, github_id bigint, github_login text);
    alter table public.users enable row level security;
    create policy "Users viewable by all" on public.users
      for select using (true);

No foreign key to scope by, no sibling policy to copy, and nothing to narrow
`using (true)` down to. propose_read_policy refuses, correctly. The customer
paid $10 and got "Nothing to auto-fix — see the recommendations above."

The rule id was never the whole question. For a secret or a committed .env,
the rule and the file's context settle it. For the RLS read rule the answer
lives in the customer's schema, and the gate runs in a request handler that
has none. So the question is answered at audit time, while the repository is
still in memory, and the answer travels with the finding.

WHAT THESE TESTS PIN is the property that makes it safe: the stamp must agree
with the plan builder, in both directions. Stamping something the plan would
have fixed costs a sale we could have honoured; not stamping something it
refuses costs a customer their money and us their trust.
"""

from __future__ import annotations

import io
import zipfile

from app.fixpack.generate import (
    build_fixpack_plan,
    has_auto_fixable_findings,
    mark_unfixable_findings,
)
from app.scan.collapse import collapse_repeats
from app.scan.static import run_static_scan


def make_zip(entries: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in entries.items():
            zf.writestr(name, body)
    return buf.getvalue()


def audit(entries: dict[str, str]) -> tuple[bytes, list[dict]]:
    """The repo bytes and the findings as the pipeline would store them."""
    data = make_zip(entries)
    findings = collapse_repeats(run_static_scan(io.BytesIO(data))["findings"])
    return data, mark_unfixable_findings(data, findings)


# Present in both fixtures because the real repository has one. Without it
# `gitignore-missing-secrets` fires, and that rule IS fixable — so the sale
# would go through for a reason that has nothing to do with what is being
# tested here. The first version of this file omitted it and passed the
# has_auto_fixable_findings check on the wrong finding.
GITIGNORE = {"r/.gitignore": "/node_modules\n.env\n.env*.local\n"}

# The customer's schema, reduced to what decides the outcome.
UNFIXABLE = {**GITIGNORE, "r/supabase/migrations/001.sql": """
    create table public.users (
      id uuid primary key default gen_random_uuid(),
      github_id bigint unique not null,
      github_login text not null,
      email text
    );
    alter table public.users enable row level security;
    create policy "Users viewable by all" on public.users for select using (true);
"""}

# The same rule, on a table the generator CAN close: the policy is already
# there and correctly scoped, and only `enable row level security` is missing.
FIXABLE = {**GITIGNORE, "r/supabase/migrations/001.sql": """
    create table public.notes (
      id uuid primary key,
      user_id uuid references auth.users(id),
      email text
    );
    create policy own on public.notes for select using (auth.uid() = user_id);
"""}


# --- the sale ---------------------------------------------------------------

def test_an_eligible_rule_the_generator_cannot_act_on_is_not_sellable() -> None:
    """The exact shape that was sold. The rule is in the fixable set and the
    finding is real; the generator has nothing to write."""
    _data, findings = audit(UNFIXABLE)
    assert [f["rule_id"] for f in findings if f["rule_id"].startswith("rls-")] \
        == ["rls-table-anon-readable"]
    assert has_auto_fixable_findings(findings) is False


def test_a_rule_the_generator_can_act_on_stays_sellable() -> None:
    """The other direction, and the one that costs money if this overshoots:
    refusing every RLS sale would be a cheap way to pass the test above."""
    _data, findings = audit(FIXABLE)
    assert has_auto_fixable_findings(findings) is True


def test_the_stamp_agrees_with_the_plan_builder() -> None:
    """The property the whole thing rests on. Two readers of "can this be
    fixed" is what #132 was about; here the second reader decides whether we
    take somebody's money, so it has to be the same answer as the first."""
    for entries in (UNFIXABLE, FIXABLE):
        data, findings = audit(entries)
        plan = build_fixpack_plan(data, findings)
        produced = bool([p for p in plan.files if "enable_rls" in p])
        stamped_ok = any(
            f.get("fixpack_eligible") is not False
            for f in findings if f["rule_id"] == "rls-table-anon-readable"
        )
        assert produced == stamped_ok, entries


# --- what the stamp must NOT do ---------------------------------------------

def test_the_finding_still_appears_in_the_report() -> None:
    """`users` IS readable by anyone holding the public key. That we cannot
    write the fix changes nothing about whether the customer should be told —
    the stamp decides what we sell, never what we report."""
    _data, findings = audit(UNFIXABLE)
    exposed = [f for f in findings if f["rule_id"] == "rls-table-anon-readable"]
    assert len(exposed) == 1
    assert exposed[0]["severity"] == "high"
    assert "users" in exposed[0]["title"]


def test_findings_from_other_rules_are_left_alone() -> None:
    """Only propose_read_policy reads the schema, so only its rule can
    disagree with the rule id. Stamping anything else would be this function
    inventing a second opinion about rules it does not consult."""
    _data, findings = audit({**UNFIXABLE, "r/.env": "STRIPE_SECRET_KEY=sk_live_" + "a" * 30})
    for f in findings:
        if f["rule_id"] != "rls-table-anon-readable":
            assert "fixpack_eligible" not in f, f["rule_id"]


def test_an_unreadable_schema_does_not_refuse_the_sale() -> None:
    """Fails open on purpose. This exists to refuse a sale we KNOW is empty,
    never one we merely cannot confirm — the customer-facing cost of the two
    is not symmetric, and neither is the honesty of the claim."""
    findings = [{"rule_id": "rls-table-anon-readable", "severity": "high",
                 "title": "Table `notes` is readable with your public key",
                 "file": "x.sql", "line": 0}]
    assert mark_unfixable_findings(b"not a zip at all", findings) == findings
    assert has_auto_fixable_findings(findings) is True


# --- stored audits from before this existed ---------------------------------

def test_an_unstamped_finding_keeps_the_old_behaviour() -> None:
    """Every audit already in the database predates the stamp. Absence of the
    key means "nobody asked", and reading it as "not eligible" would make
    every one of them unsellable overnight."""
    old = [{"rule_id": "rls-table-anon-readable", "severity": "high",
            "title": "Table `notes` is readable with your public key",
            "file": "supabase/migrations/001.sql", "line": 0}]
    assert "fixpack_eligible" not in old[0]
    assert has_auto_fixable_findings(old) is True


def test_an_explicit_true_is_not_needed_to_sell() -> None:
    """The stamp is one-directional: only `False` means anything. A `True`
    would be a promise this cannot keep — the repository is re-fetched before
    the plan runs and may have moved on since."""
    marked = [{"rule_id": "rls-table-anon-readable", "severity": "high",
               "title": "Table `notes` is readable with your public key",
               "file": "a.sql", "line": 0, "fixpack_eligible": True}]
    assert has_auto_fixable_findings(marked) is True


# --- the seam, which is where a fix like this goes decorative ---------------

def test_the_scan_pipeline_stamps_what_it_stores() -> None:
    """Everything above tests mark_unfixable_findings. None of it notices if
    nobody CALLS it — a mutation deleting the pipeline's one line survived the
    whole file until this test existed, and the shipped behaviour would have
    been unchanged: the gate reads what run_scan stored, so an unstamped
    audit sells exactly like before.
    """
    from app.llm.client import LLMClient
    from app.scan.pipeline import run_scan

    scan = run_scan(make_zip(UNFIXABLE), LLMClient(providers=[]))
    exposed = [f for f in scan["findings"]
               if f.get("rule_id") == "rls-table-anon-readable"]
    assert exposed, [f.get("rule_id") for f in scan["findings"]]
    assert exposed[0].get("fixpack_eligible") is False
    assert has_auto_fixable_findings(scan["findings"]) is False


def test_the_scan_pipeline_leaves_a_sellable_audit_sellable() -> None:
    from app.llm.client import LLMClient
    from app.scan.pipeline import run_scan

    scan = run_scan(make_zip(FIXABLE), LLMClient(providers=[]))
    assert has_auto_fixable_findings(scan["findings"]) is True
