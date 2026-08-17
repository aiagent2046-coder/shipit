"""Before/after comparison and the single entry point for a proof pair."""

from __future__ import annotations

from app.proof.registry import get_template
from app.proof.types import ExploitAttempt, ProofReport, TemplateId


def build_proof_report(
    before: ExploitAttempt,
    after: ExploitAttempt,
    *,
    informational: bool = True,
) -> ProofReport:
    """Compare two attempts from the same template.

    ``verified`` requires a real success-then-failure pair. Skipped or
    errored attempts never count as verified — that would invent confidence.
    """
    if before.template_id != after.template_id:
        raise ValueError(
            f"template mismatch: before={before.template_id!r} "
            f"after={after.template_id!r}"
        )

    verified = (
        before.status == "success"
        and before.success
        and after.status == "failure"
        and not after.success
    )

    if before.status == "skipped" or after.status == "skipped":
        detail = (
            f"proof skipped ({before.template_id}): "
            f"before={before.status}, after={after.status}"
        )
    elif before.status == "error" or after.status == "error":
        detail = (
            f"proof error ({before.template_id}): "
            f"before={before.status}, after={after.status}"
        )
    elif verified:
        detail = (
            f"verified ({before.template_id}): exploit succeeded before, "
            f"failed after"
        )
    elif before.success and after.success:
        detail = (
            f"not verified ({before.template_id}): exploit still succeeds "
            f"after patch"
        )
    elif not before.success and not after.success:
        detail = (
            f"not verified ({before.template_id}): exploit did not reproduce "
            f"on original workspace"
        )
    else:
        detail = (
            f"not verified ({before.template_id}): "
            f"before.success={before.success}, after.success={after.success}"
        )

    return ProofReport(
        template_id=before.template_id,
        before=before,
        after=after,
        verified=verified,
        informational=informational,
        detail=detail,
    )


def run_proof_pair(
    template_id: TemplateId,
    original_zip: bytes,
    patched_zip: bytes,
    *,
    informational: bool = True,
    **template_kwargs: object,
) -> ProofReport:
    """Run one template on original and patched workspaces, then compare.

    Keyword extras are forwarded to the template (e.g. finding filters).
    """
    run = get_template(template_id)
    before = run(original_zip, **template_kwargs)
    after = run(patched_zip, **template_kwargs)
    return build_proof_report(before, after, informational=informational)
