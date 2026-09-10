"""Turn bounded React response/UI syntax observations into static findings."""
from app.scan.claim_evidence import static_claim_evidence
from app.scan.scoring import ScoredFinding


RULE_ID = "react-unchecked-http-success"


def http_success_findings(source_facts: dict) -> list[ScoredFinding]:
    """No source parsing, model calls or uploaded-code execution at this stage.

    The collector requires discarded/unused responses and a supported direct
    effect. A missing Response.ok observation by itself never becomes a finding.
    Archive path normalization is performed by the scan pipeline.
    """
    findings, seen = [], set()
    for record in (source_facts.get("react_async") or {}).get("records", [])[:64]:
        for check in record.get("checks", [])[:16]:
            if check.get("kind") != "react_async_http_success" or check.get("result") != "observed":
                continue
            effect = check.get("effect")
            if effect not in {"success_state", "navigation"}:
                continue
            key = (record.get("file"), check.get("fetch_line"), check.get("effect_line"))
            if key in seen:
                continue
            seen.add(key)
            title = ("Saved state follows fetch without checking HTTP success" if effect == "success_state"
                     else "Navigation follows fetch without checking HTTP success")
            action = ("a state rendered with a success label is set true" if effect == "success_state"
                      else "the imported Next router is instructed to navigate")
            observation = (f"Fetch at line {check['fetch_line']} has a discarded or unused response; "
                           f"at line {check['effect_line']}, {action} in the same supported block.")
            findings.append(ScoredFinding(
                rule_id=RULE_ID, title=title, severity="medium", confidence=0.90, category="Frontend",
                file=record["file"], line=check["fetch_line"], source="static",
                verification_method="source_pattern",
                explanation=observation + " Standard fetch resolves normally for HTTP 4xx/5xx responses. "
                "If such a response reaches this path, HTTP failure alone does not stop the UI effect. "
                "An enclosing catch handles a rejected request, not an unchecked HTTP error response. "
                "The actual server response, runtime entry and global fetch behavior outside this file "
                "have not been verified.",
                fix_hint="Retain the Response and gate the success state or navigation on response.ok "
                "or the endpoint's explicitly accepted HTTP statuses. Handle the error path before the "
                "UI effect; use catch for rejected requests and finally for loading cleanup. Add a "
                "regression with a resolved HTTP 500 Response as well as a rejected request.",
                claim_evidence={**static_claim_evidence(), "observation": observation,
                                "required_conditions": ["The handler reaches the observed fetch and UI effect.",
                                                        "fetch retains standard Response semantics.",
                                                        "The server returns an HTTP error response."],
                                "context_checks": [check]},
            ))
    return findings
