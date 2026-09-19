"""Bounded in-process task queue with source-bound, copied hand-offs.

Workers are trusted code supplied by the coordinator, never names or commands
from an archive/report. Receipts establish consistency, not authenticity.
"""
from collections import deque
from copy import deepcopy
import hashlib
import json

from app.scan.evidence_record import normalize_acquisition
from app.scan.synthetic_record import normalize_synthetic_contract

ROLES = ("detector", "researcher", "experimenter", "verifier")
GOALS = {
    "detector": "classify_static_sql_observation",
    "researcher": "collect_missing_sql_source_facts",
    "experimenter": "obtain_selected_synthetic_contract",
    "verifier": "validate_evidence_and_identify_remaining_gaps",
}
MAX_TASKS = 4
IDENTITY_FIELDS = ("id", "pattern_id", "pattern_revision", "title", "weaknesses", "rule_id", "file", "line", "recipe",
                   "evidence")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def candidate_digest(value):
    return digest({key: item for key, item in value.items() if key != "agent_chain"})


def _matches(value, binding):
    trace = value.get("evidence", {}).get("sql_observation", {})
    return (value.get("id") == binding["observation_id"]
            and trace.get("source_sha256") == binding["source_sha256"]
            and value.get("file") == trace.get("file")
            and value.get("line") == trace.get("sink_line")
            and value.get("recipe", {}).get("automatic_apply") is False)


def _valid_transition(role, before, after, binding):
    if before == after:
        return True
    allowed = {
        "detector": set(),
        "researcher": {"acquisition", "missing_evidence", "state", "next_action"},
        "experimenter": {"_pending_contract", "steps"},
        "verifier": {"_pending_contract", "synthetic_contract", "steps", "state", "next_action"},
    }
    changed = {key for key in before.keys() | after.keys() if before.get(key) != after.get(key)}
    if not changed <= allowed[role]:
        return False
    if role == "researcher":
        record = normalize_acquisition(after.get("acquisition"), before["evidence"]["sql_observation"])
        if record is None:
            return False
        facts = {fact["id"] for fact in record["facts"]}
        state = (("source_evidence_collected", "review_runtime_contract") if record["status"] == "completed"
                 else (before["state"], before["next_action"]))
        return (after["missing_evidence"] == [key for key in before["missing_evidence"] if key not in facts]
                and (after["state"], after["next_action"]) == state)
    if role == "verifier" and after.get("state") == "synthetic_recipe_verified":
        source = {key: binding[key] for key in ("archive_sha256", "engine_version")}
        return normalize_synthetic_contract(after.get("synthetic_contract"), after, source,
                                             {"sha256": binding["catalog_sha256"]}) is not None
    return True


def run_chain(seed, binding, workers):
    """One attempt per role; failed workers cannot mutate accepted evidence.

The detector seed is an already classified fallback observation. Its worker
revalidates scanner evidence. Every next task consumes the accepted output of
its predecessor. Unsupported evidence is an explicit blocked task, not proof.
"""
    accepted = deepcopy(seed)
    queue = deque([ROLES[0]])
    receipts = []
    while queue and len(receipts) < MAX_TASKS:
        role = queue.popleft()
        before = candidate_digest(accepted)
        status, reason = "error", "worker_failed"
        attempts = 0
        try:
            if role != "verifier" and any(row["status"] == "error" for row in receipts):
                proposed, status, reason = deepcopy(accepted), "blocked", "upstream_task_failed"
            else:
                attempts = 1
                proposed, status, reason = workers[role](deepcopy(accepted))
            if (status not in {"completed", "blocked"} or not isinstance(reason, str)
                    or not reason.isascii() or not reason.replace("_", "").isalnum() or len(reason) > 80
                    or not isinstance(proposed, dict) or not _matches(proposed, binding)
                    or any(proposed.get(key) != seed.get(key) for key in IDENTITY_FIELDS)
                    or not _valid_transition(role, accepted, proposed, binding)):
                raise ValueError("Invalid worker hand-off")
            # Materialize/copy before commit: a retained worker reference is not
            # permission to change the next task's input after returning.
            proposed = deepcopy(proposed)
            candidate_digest(proposed)
            accepted = proposed
        except Exception:
            status, reason = "error", "worker_failed"
        if role == "verifier":
            accepted.pop("_pending_contract", None)
        receipts.append({
            "id": digest([binding, role]), "agent": role, "goal": GOALS[role],
            "source": deepcopy(binding), "depends_on": [receipts[-1]["id"]] if receipts else [],
            "input_sha256": before, "output_sha256": candidate_digest(accepted),
            "attempts": attempts, "max_attempts": 1, "status": status, "reason": reason,
        })
        if len(receipts) < len(ROLES):
            queue.append(ROLES[len(receipts)])
    accepted["agent_chain"] = {
        "version": 1, "mode": "in_process_queue", "scope": "synthetic_recipe",
        "status": ("error" if any(row["status"] == "error" for row in receipts)
                   else "waiting_for_evidence" if any(row["status"] == "blocked" for row in receipts)
                   else "completed"),
        "max_tasks": MAX_TASKS, "tasks": receipts,
    }
    return accepted


def normalize_chain(value, observation, source, catalog):
    """Reject edited/cross-source receipts; never execute a saved task."""
    try:
        return _normalize_chain(value, observation, source, catalog)
    except (AttributeError, KeyError, TypeError, ValueError, RecursionError):
        return None


def _normalize_chain(value, observation, source, catalog):
    if (not isinstance(value, dict) or set(value) != {"version", "mode", "scope", "status", "max_tasks", "tasks"}
            or type(value["version"]) is not int or value["version"] != 1
            or value["mode"] != "in_process_queue" or value["scope"] != "synthetic_recipe"
            or type(value["max_tasks"]) is not int or value["max_tasks"] != MAX_TASKS
            or not isinstance(value["tasks"], list) or len(value["tasks"]) != len(ROLES)
            or not isinstance(source, dict) or not isinstance(catalog, dict)):
        return None
    trace = observation.get("evidence", {}).get("sql_observation", {})
    binding = {**source, "catalog_sha256": catalog.get("sha256"),
               "source_sha256": trace.get("source_sha256"), "observation_id": observation.get("id")}
    previous = None
    for role, task in zip(ROLES, value["tasks"]):
        if (not isinstance(task, dict) or set(task) != {
                "id", "agent", "goal", "source", "depends_on", "input_sha256", "output_sha256",
                "attempts", "max_attempts", "status", "reason"}
                or task["id"] != digest([binding, role]) or task["agent"] != role
                or task["source"] != binding or task["goal"] != GOALS[role]
                or task["depends_on"] != ([previous["id"]] if previous else [])
                or type(task["attempts"]) is not int or task["attempts"] != (
                    0 if task["status"] == "blocked" and task["reason"] == "upstream_task_failed" else 1)
                or type(task["max_attempts"]) is not int or task["max_attempts"] != 1
                or task["status"] not in ("completed", "blocked", "error")
                or not isinstance(task["reason"], str) or len(task["reason"]) > 80
                or not task["reason"].isascii() or not task["reason"].replace("_", "").isalnum()
                or any(not isinstance(task[key], str) or len(task[key]) != 64
                       or any(char not in "0123456789abcdef" for char in task[key])
                       for key in ("input_sha256", "output_sha256"))
                or (previous is not None and task["input_sha256"] != previous["output_sha256"])):
            return None
        previous = task
    expected = ("error" if any(row["status"] == "error" for row in value["tasks"])
                else "waiting_for_evidence" if any(row["status"] == "blocked" for row in value["tasks"])
                else "completed")
    if value["status"] != expected or previous["output_sha256"] != candidate_digest(observation):
        return None
    return deepcopy(value)
