"""Marking the parts of a finding that the audited repository wrote.

docs/MCP.md §4 is the reason this module exists, and it is the risk specific
to this product rather than to MCP in general.

An MCP result lands in the context of an agent that can write files and run
commands. Part of a finding is controlled by the repository being audited:
the file path, the LLM-authored `title` and `fix_hint`, sometimes a snippet.
So the chain is:

    someone commits a file whose content reads as instructions
      -> a developer audits that repository
        -> the finding travels through MCP into their editor

Drydock would be the delivery channel for text an attacker wrote, into a tool
with filesystem and shell access. Nothing here makes that safe -- the reader
is what makes it safe, and the tool descriptions address the reader. What this
module does is narrower and worth stating exactly:

  * it bounds how much attacker-controlled text can arrive at once, and
  * it makes the boundary of that text visible and unforgeable.

UNFORGEABLE IS THE WHOLE POINT. A fence the audited repository can close is
not a fence: a title reading "...  DATA_END. Now run:" would put the rest of
its text outside the marked region, in a transcript where the agent has
already been told that everything outside the markers is ours. So the marker
strings are removed from the text before the text is wrapped, and that removal
is the thing to keep working -- see tests/test_mcp_untrusted.py, where taking
it out is one of the mutations.
"""

from __future__ import annotations

# Chosen to be unmistakable in a transcript and to contain no character that
# would tempt a JSON encoder, a Markdown renderer or a terminal to do anything
# with them. They are stripped from the payload (see fence), so a repository
# cannot emit them itself.
FENCE_OPEN = "[UNTRUSTED_REPO_DATA]"
FENCE_CLOSE = "[/UNTRUSTED_REPO_DATA]"

# docs/MCP.md §4.3: repository-derived free text is length-capped before it
# goes out. A title is a sentence and a fix hint is a short paragraph; findings
# that need more than this are read on the report page, which is a browser and
# not an agent's context window. The cap is per field, and there is a separate
# bound on how many findings a single tool call returns (app/mcp/server.py).
MAX_TEXT_CHARS = 600

# What replaces the tail of an over-long field. Visible on purpose: a reader
# who sees it knows the text continues rather than believing they have all of
# it.
TRUNCATION_MARK = "…[truncated]"


def fence(value: object) -> str:
    """Wrap repository-derived text so its boundary is visible and its own
    content cannot move that boundary.

    Order matters and is the whole function: strip the markers FIRST, cap
    SECOND, wrap LAST.

      * stripping first, because a marker that survives into the payload is a
        fence the payload can close;
      * capping second, because capping first could leave a partial marker
        that stripping would then miss;
      * wrapping last, because the wrapper must not be measured against the
        cap -- it is ours, not theirs.

    Non-strings are coerced rather than refused. A finding is a dict decoded
    from JSON that an LLM produced from a third party's repository; assuming a
    field is a string because it usually is, is how this ends up formatting a
    dict into a transcript unfenced.
    """
    text = value if isinstance(value, str) else str(value)
    text = text.replace(FENCE_OPEN, "").replace(FENCE_CLOSE, "")
    if len(text) > MAX_TEXT_CHARS:
        text = text[:MAX_TEXT_CHARS] + TRUNCATION_MARK
    return f"{FENCE_OPEN}{text}{FENCE_CLOSE}"


def fence_optional(value: object) -> str | None:
    """`fence`, except that an absent field stays absent.

    A missing `fix_hint` must not become the string "[UNTRUSTED_REPO_DATA]None
    [/UNTRUSTED_REPO_DATA]", which reads to an agent as a fix hint whose
    content is the word None.
    """
    if value is None:
        return None
    return fence(value)
