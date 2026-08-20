"""Was this Fix Pack wrong? Answered from our own records, not the customer's.

WHAT THIS IS FOR, AND WHAT IT IS NOT FOR. It is easy to build this backwards.
A "was the customer right to complain" checker becomes, within a week, a
machine for saying no: every ambiguous case rounds to "we delivered", the
operator has a printout to point at, and the refund conversation is now an
argument the customer loses to a program.

So the question this module answers is the other one:

    Does the evidence WE ALREADY HOLD show that we were wrong?

Nothing here can deny a refund. `Verdict.conclusion` has three values and only
one of them is an answer about the customer's claim at all:

    OWED          our own records show the Fix Pack did not deliver what it
                  was sold as. Refund without argument -- and, better, without
                  waiting to be asked.
    DELIVERED     our records show it did the thing. NOT a finding that the
                  customer is wrong: they may have been sold a fix that was
                  correct and useless to them, and that is still a refund a
                  human may decide to make.
    UNDETERMINED  we cannot tell from here. The common case, and it must stay
                  a real answer rather than quietly collapsing into DELIVERED.

WHY THIS EXISTS AT ALL. Audit 05fa18f5 was sold a Fix Pack with zero fixable
findings; the job ran, found nothing, and the payer was charged for "Nothing to
auto-fix". A different customer's Fix Pack changed one line and opened an empty
pull request. Both were visible in our own tables at the time and nobody
looked, because looking meant reading four tables by hand. That is the whole
gap: the evidence was there and the question had no answer that a person could
ask in one step.

THE EVIDENCE, and what each piece can and cannot say:

  outcome        `failed` means the customer paid and got nothing. That is not
                 a judgement call.
  is_regression  our OWN semantic gate said the patch broke something. The
                 strongest signal here, because it is us disagreeing with us.
  rule_ids       what the Fix Pack claims it fixed. Empty, on a delivered job,
                 means a pull request that fixed nothing was handed over as
                 the product.
  verified       the verifier's verdict. False means we shipped something we
                 had already judged broken.
  pr_merged      the weakest, and deliberately NOT treated as proof. A closed
                 pull request can mean the fix was wrong, or that the customer
                 fixed it themselves, or preferred their own patch, or never
                 looked. It moves the answer to UNDETERMINED and names itself
                 as a reason for a human to read; it never decides.

EVERY VERDICT CARRIES ITS REASONS. A conclusion with no reasons attached is
worse than no mechanism: it is an authority nobody can check.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# The three conclusions. Strings rather than an enum, matching every other
# status in this codebase, and so a value can be added without a migration
# reaching for it.
OWED = "owed"
DELIVERED = "delivered"
UNDETERMINED = "undetermined"


@dataclass(frozen=True)
class Reason:
    """One piece of evidence, and what it is evidence OF.

    `code` is for a machine, `detail` for the operator reading the refund
    screen. `decisive` marks a reason that settled the conclusion on its own,
    so a list of six reasons does not read as six equal facts.
    """

    code: str
    detail: str
    decisive: bool = False


@dataclass(frozen=True)
class Verdict:
    conclusion: str
    reasons: tuple[Reason, ...] = field(default_factory=tuple)

    @property
    def owed(self) -> bool:
        return self.conclusion == OWED

    def as_dict(self) -> dict[str, Any]:
        return {
            "conclusion": self.conclusion,
            "reasons": [
                {"code": r.code, "detail": r.detail, "decisive": r.decisive}
                for r in self.reasons
            ],
        }


def assess(
    *,
    job: dict[str, Any] | None,
    outcome: dict[str, Any] | None,
    audit: dict[str, Any] | None = None,
) -> Verdict:
    """Judge one paid Fix Pack from the rows we hold for it.

    `job` is a fixpack_jobs row, `outcome` a fix_outcomes row, `audit` the
    audit it was bought for. Any of them may be None -- a Fix Pack that was
    paid for and never ran leaves no job at all, which is itself the loudest
    evidence there is.

    Pure: no database, no network, no clock. Everything it needs is in the
    three dicts, which is what makes the verdict reproducible when somebody
    disputes it six weeks later.
    """
    reasons: list[Reason] = []

    # --- paid and nothing happened -----------------------------------------
    if job is None:
        return Verdict(OWED, (Reason(
            "no_job",
            "This Fix Pack was paid for and no job exists for it. Nothing "
            "was ever generated, so nothing was delivered.",
            decisive=True,
        ),))

    status = (job.get("status") or "").strip()
    if status == "failed":
        detail = (job.get("detail") or "").strip()
        return Verdict(OWED, (Reason(
            "job_failed",
            "The Fix Pack job failed"
            + (f": {detail}" if detail else "")
            + ". The customer paid and received nothing.",
            decisive=True,
        ),))

    if job.get("verified") is False:
        # `is False`, not falsy: NULL means the verifier never ran, which is a
        # different and much weaker fact than the verifier saying no.
        reasons.append(Reason(
            "verifier_rejected",
            "Our own verifier rejected this Fix Pack"
            + (f": {(job.get('detail') or '').strip()}" if job.get("detail") else "")
            + ". Whatever the customer thinks of it, we had already judged it "
              "broken.",
            decisive=True,
        ))

    # --- the semantic gate disagreed with us -------------------------------
    if outcome is not None and outcome.get("is_regression"):
        reasons.append(Reason(
            "regression",
            "The semantic check flagged this patch as a regression: it "
            "changed behaviour beyond the fix it was sold as.",
            decisive=True,
        ))

    # --- delivered, but empty ----------------------------------------------
    outcome_kind = ((outcome or {}).get("outcome") or "").strip()
    rule_ids = list((outcome or {}).get("rule_ids") or [])

    if outcome_kind == "no_fix_needed":
        reasons.append(Reason(
            "nothing_to_fix",
            "The job found nothing it could fix. The audit's findings should "
            "have been checked before the sale, not after -- this is our "
            "mistake, not a disappointing result.",
            decisive=True,
        ))
    elif outcome_kind == "delivered" and not rule_ids:
        reasons.append(Reason(
            "delivered_nothing",
            "A pull request was opened that fixes no finding. An empty diff "
            "is not the product.",
            decisive=True,
        ))
    elif outcome_kind == "blocked":
        reasons.append(Reason(
            "blocked",
            "The job was blocked before it could open a pull request, so the "
            "customer received nothing for their money.",
            decisive=True,
        ))

    if any(r.decisive for r in reasons):
        return Verdict(OWED, tuple(reasons))

    # --- nothing is decisive: say so, with what is known --------------------
    if outcome is None:
        reasons.append(Reason(
            "no_outcome_recorded",
            "No terminal outcome was recorded for this job, so there is "
            "nothing here that says what the customer received.",
        ))
        return Verdict(UNDETERMINED, tuple(reasons))

    if outcome.get("pr_merged") is False:
        # Deliberately not decisive, in either direction. See the module
        # docstring: a closed pull request has at least four readings and only
        # one of them is "the fix was wrong".
        reasons.append(Reason(
            "pr_closed_unmerged",
            "The customer closed the pull request without merging it. That "
            "may mean the fix was wrong, or that they fixed it another way, "
            "or that they never looked. It is worth reading; it decides "
            "nothing.",
        ))
        return Verdict(UNDETERMINED, tuple(reasons))

    if outcome_kind == "delivered" and rule_ids:
        reasons.append(Reason(
            "delivered_fixes",
            "A pull request was delivered fixing "
            + ", ".join(sorted(rule_ids)[:6])
            + (f" and {len(rule_ids) - 6} more" if len(rule_ids) > 6 else "")
            + ". Our records show the product was produced. Whether it was "
              "worth what it cost is a question these records cannot answer.",
        ))
        if outcome.get("pr_merged") is True:
            reasons.append(Reason(
                "pr_merged",
                "The customer merged the pull request.",
            ))
        return Verdict(DELIVERED, tuple(reasons))

    reasons.append(Reason(
        "unrecognised_state",
        f"The job is in state {status or 'unknown'!r} with outcome "
        f"{outcome_kind or 'unknown'!r}, which this check has no rule for. "
        "Read it by hand rather than assuming either answer.",
    ))
    return Verdict(UNDETERMINED, tuple(reasons))
