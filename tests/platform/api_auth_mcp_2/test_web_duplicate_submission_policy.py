"""Guard the policy that caused the saved Luna chat false positive.

These are prompt-contract checks, not a simulation of an LLM. They prevent
reintroducing the instruction that every concurrent message send is critical;
they cannot establish that a future model response will follow the policy.
"""

from app.scan.llm_scan import RUBRICS


def test_duplicate_submission_requires_the_same_operation_without_new_input():
    instructions = RUBRICS["web"]["instructions"]
    assert "same operation without new user input" in instructions
    assert "not sufficient evidence of duplicate submission" in instructions
    assert "Trace the submitted value, entry guard, state updates and rendered control" in instructions


def test_consumed_draft_is_distinguished_from_a_duplicate_without_claiming_safety():
    instructions = RUBRICS["web"]["instructions"]
    assert "rejects empty input" in instructions
    assert "captures the current draft for its request" in instructions
    assert "clears that same state before its first await" in instructions
    assert "button's empty-input disabled binding" in instructions
    assert "new content after that clear makes a distinct submission" in instructions
    assert "Concurrent distinct submissions are not a defect by themselves" in instructions
    assert "does not prove server idempotency" in instructions


def test_severity_requires_a_consequence_and_keeps_critical_available():
    instructions = RUBRICS["web"]["instructions"]
    # This exact instruction in the saved request caused the critical label.
    assert "CRITICAL when the request spends money, creates an order or sends a message" not in instructions
    assert "Severity follows the source-supported consequence" in instructions
    assert "Reserve critical for a concrete path" in instructions
    assert "name the causal chain and unresolved conditions" in instructions
    assert "Do not infer server-side effects from two browser requests" in instructions
    assert "medium for bounded, recoverable duplicates" in instructions
