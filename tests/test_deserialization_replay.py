"""Shared saved-report mutations must revoke the same proof in all renderers."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from app.report.evidence import security_agent_rows
from app.scan.security_agent import agent_record


FIXTURES = Path(__file__).parent / "fixtures"
BASE = json.loads((FIXTURES / "deserialization-agent.json").read_text())[0]["report"]["security_agent"]
CASES = json.loads((FIXTURES / "deserialization-agent-replay.json").read_text())


@pytest.mark.parametrize("scenario", CASES, ids=lambda item: item["name"])
def test_saved_deserialization_replay_matches_web_and_browser(scenario):
    saved = deepcopy(BASE)
    for change in scenario["changes"]:
        target = saved
        for key in change["path"][:-1]:
            target = target[int(key) if isinstance(target, list) else key]
        key = change["path"][-1]
        key = int(key) if isinstance(target, list) else key
        if change.get("delete"):
            del target[key]
        else:
            target[key] = deepcopy(change["value"])
    before = deepcopy(saved)
    normalized = agent_record(saved)
    rows = dict(security_agent_rows(saved))
    if scenario["valid"]:
        assert normalized == saved
        assert normalized["status"] == scenario["status"]
        assert rows["Source investigation"].startswith(scenario["acquisition_status"] + ";")
    else:
        assert normalized["status"] == "partial"
        assert normalized["stop_reason"] == "source_evidence_invalid"
        observation, = normalized["observations"]
        assert observation["state"] == "needs_evidence"
        assert observation["next_action"] == "manual_review"
        assert observation["missing_evidence"] == [
            "request_input_source", "local_input_flow", "input_trust_boundary", "loader_runtime_contract"]
        assert "acquisition" not in observation
        assert "agent_chain" not in observation
        assert "Source fact: request input source" not in rows
        assert "Source fact: local input flow" not in rows
        assert "Source investigation" not in rows
        assert rows["Review state"].startswith("Needs evidence;")
    assert saved == before
