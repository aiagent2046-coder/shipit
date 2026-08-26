"""The tool schema is pinned, so a rename is a diff somebody reviews.

docs/MCP.md §6 asks for this check by name. The reason is that an MCP tool
schema is a published interface with no version negotiation on the tool level:
if `drydock_get_audit` is renamed, or `audit_id` becomes `id`, every editor
that had this server configured stops working, and it stops working quietly --
the model simply cannot call the tool any more and says something vague about
being unable to fetch the audit.

Two pins, because they fail differently and both are wanted:

  * `tests/data/mcp_tools.json` is a byte-for-byte golden of the whole
    published schema. It catches every change, including a reworded
    description, and its failure mode is a reviewable diff.
  * the literal names and required arguments below are written out in this
    file. A golden can be regenerated without reading it -- that is the
    standing hazard of golden files -- and these cannot: changing them means
    typing the new name here, which is the moment to ask whether anyone's
    editor is configured against the old one.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.mcp.server import TOOLS

GOLDEN = Path(__file__).parent / "data" / "mcp_tools.json"

# What is published, written out rather than derived. `None` means the tool
# takes no required argument.
EXPECTED = {
    "drydock_get_version": [],
    "drydock_start_audit": ["repo_url"],
    "drydock_get_audit": ["audit_id"],
    "drydock_fixpack_status": ["audit_id"],
    "drydock_list_recent": [],
}


def test_the_published_schema_matches_the_golden():
    """A failure here is not a defect -- it is a change to a published
    interface that wants a second pair of eyes. Regenerate with:

        python3 -c "import json; from app.mcp.server import TOOLS; \\
            print(json.dumps(list(TOOLS), indent=2, ensure_ascii=False))" \\
            > tests/data/mcp_tools.json
    """
    assert json.loads(GOLDEN.read_text()) == json.loads(json.dumps(list(TOOLS)))


def test_the_tool_names_and_required_arguments_are_what_editors_expect():
    published = {t["name"]: t["inputSchema"].get("required", []) for t in TOOLS}

    assert published == EXPECTED


def test_every_tool_refuses_arguments_it_does_not_declare():
    """`additionalProperties: false` on every input schema.

    Not pedantry: a client that sends `{"audit_id": ..., "token": ...}`
    because it guessed the argument name should be told, rather than have the
    guess silently dropped and the call answered as if no token was given --
    which, for drydock_get_audit, is the difference between reading an audit
    and being told it does not exist.
    """
    for tool in TOOLS:
        assert tool["inputSchema"].get("additionalProperties") is False, tool["name"]


def test_every_tool_has_a_description_a_model_can_act_on():
    for tool in TOOLS:
        assert len(tool["description"]) > 60, tool["name"]
