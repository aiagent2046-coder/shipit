"""Choose and run bounded evidence actions, then re-plan from validated facts.

Collectors only inspect the original snapshot. A completed source goal cannot
establish authorization, deployed reachability, intended semantics or runtime
behavior, and never authorizes a patch.
"""
from __future__ import annotations

from copy import deepcopy

from app.scan.source_snapshot import SourceUnavailable, source_span

MAX_EVIDENCE_WORK = 640_000
MAX_EVIDENCE_ACTIONS = 512
MAX_CANDIDATE_STEPS = 4
SOURCE_GOALS = frozenset({"request_input_source", "local_input_flow", "sql_value_position", "value_constraints"})


class EvidenceLimit(Exception):
    pass


class EvidenceBudget:
    def __init__(self, *, max_work=None, max_actions=None):
        self.maximum = MAX_EVIDENCE_WORK if max_work is None else max_work
        self.remaining = self.maximum
        self.max_actions = MAX_EVIDENCE_ACTIONS if max_actions is None else max_actions
        self.actions = 0

    def spend(self, amount=1):
        if amount > self.remaining:
            self.remaining = 0
            raise EvidenceLimit("work_budget_exhausted")
        self.remaining -= amount

    def action(self):
        if self.actions >= self.max_actions:
            raise EvidenceLimit("step_budget_exhausted")
        self.actions += 1


def _next_action(record, trace, analysis):
    attempted = {step["action"] for step in record["attempts"]}
    facts = {fact["id"] for fact in record["facts"]}
    if "locate_source" not in attempted:
        return "locate_source"
    if "sink_span" not in record["source"]:
        return None
    if "trace_request_input" not in attempted:
        return "trace_request_input"
    if (trace["driver_status"] == "source_resolved" and analysis.get("parts") is not None
            and "inspect_sql_slots" not in attempted):
        return "inspect_sql_slots"
    if ({"request_input_source", "local_input_flow"} <= facts
            and "collect_value_constraints" not in attempted):
        return "collect_value_constraints"
    return None


def acquire_sql_evidence(trace, snapshot, budget):
    """Keep a reproducible journal; no action repeats for the same source sink."""
    key = (trace["file"], trace["source_sha256"], trace["sink_line"], trace["sink_method"], trace["driver_status"])
    if snapshot is not None and key in snapshot.acquisitions:
        return deepcopy(snapshot.acquisitions[key])
    record = {
        "version": 1, "status": "unsupported", "stop_reason": "no_further_action",
        "source": {"file": trace["file"], "source_sha256": trace["source_sha256"]},
        "facts": [], "attempts": [],
        "budget": {"max_steps": MAX_CANDIDATE_STEPS, "steps": 0, "work_units": 0},
    }
    initial_work = budget.remaining
    analysis = {}
    document = sink = None
    while (action := _next_action(record, trace, analysis)) is not None:
        if len(record["attempts"]) >= MAX_CANDIDATE_STEPS:
            record.update(status="partial", stop_reason="budget_exhausted")
            break
        old_facts = deepcopy(record["facts"])
        step = {"action": action, "result": "unknown", "reason": "collector_failed", "produced": []}
        try:
            budget.action()
            budget.spend()
            if action == "locate_source":
                if snapshot is None:
                    raise SourceUnavailable("source_unavailable")
                document, sink = snapshot.locate(trace, spend=budget.spend)
                record["source"]["sink_span"] = source_span(sink)
                result = {"status": "established", "facts": []}
                reason = "source_snapshot_matched"
            elif action == "trace_request_input":
                from app.scan.sql_input_evidence import analyze_query_input

                analysis = analyze_query_input(document.tree, sink, spend=budget.spend)
                if snapshot.framework_shadowed:
                    # Visible local modules prevent claiming the imported
                    # framework's HTTP semantics. Symbolic SQL remains usable.
                    analysis = {**analysis, "status": "unknown", "reason": "framework_import_shadowed",
                                "facts": [], "constraints": [], "constraint_status": "unknown"}
                result = analysis
                reason = ("request_flow_established" if result["status"] == "established"
                          else "request_flow_not_established")
            elif action == "inspect_sql_slots":
                from app.scan.sql_slot_evidence import classify_sql_slots

                result = classify_sql_slots(analysis["parts"], spend=budget.spend)
                reason = ("sql_value_positions_established" if result["status"] == "established"
                          else "sql_slots_not_established")
            else:
                constraints = analysis.get("constraints", [])
                established = bool(constraints) and analysis.get("constraint_status") == "established"
                result = {"status": "established" if established else "unknown", "facts": [
                    {"id": "value_constraints", "method": "python_ast_constraints", "constraints": constraints}
                ] if established else []}
                budget.spend(len(constraints) + 1)
                reason = "value_constraints_recorded" if established else "value_constraints_unknown"
            step.update(result=result["status"], reason=reason)
            if action in {"trace_request_input", "inspect_sql_slots"}:
                step["detail"] = result["reason"]
            if result["status"] == "established":
                step["produced"] = [fact["id"] for fact in result["facts"]]
                record["facts"].extend(deepcopy(result["facts"]))
            record["attempts"].append(step)
            record["budget"].update(steps=len(record["attempts"]), work_units=initial_work - budget.remaining)
            if SOURCE_GOALS <= {fact["id"] for fact in record["facts"]}:
                record.update(status="completed", stop_reason="source_goal_reached")
            # Each result must satisfy the same schema used for saved reports
            # before a later action or recipe prerequisite can consume it.
            from app.scan.evidence_record import normalize_acquisition

            if normalize_acquisition(record, trace) is None:
                raise ValueError("invalid_collector_record")
        except SourceUnavailable as exc:
            step.update(result="unsupported", reason=exc.reason)
            record["attempts"].append(step)
            record.update(stop_reason=exc.reason, status="partial" if exc.reason == "source_limit" else "unsupported")
            break
        except EvidenceLimit as exc:
            step.update(result="budget_exhausted", reason=str(exc))
            record["attempts"].append(step)
            record["facts"] = old_facts
            record.update(status="partial", stop_reason="budget_exhausted")
            break
        except Exception:  # Type-only public outcome; collector messages may contain source values.
            step.update(result="error", reason="collector_failed", produced=[])
            step.pop("detail", None)
            if not record["attempts"] or record["attempts"][-1] is not step:
                record["attempts"].append(step)
            record["facts"] = old_facts
            record.update(status="partial", stop_reason="collector_error")
            break
    else:
        if SOURCE_GOALS <= {fact["id"] for fact in record["facts"]}:
            record.update(status="completed", stop_reason="source_goal_reached")
    record["budget"].update(steps=len(record["attempts"]), work_units=initial_work - budget.remaining)
    if snapshot is not None:
        snapshot.acquisitions[key] = deepcopy(record)
    return record
