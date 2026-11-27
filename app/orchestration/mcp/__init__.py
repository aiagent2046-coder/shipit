"""Drydock over MCP: what an agent inside an editor may ask for.

The contract this implements is docs/MCP.md, written before any of it. The
two decisions that shape every file here:

  * A key is free, self-service and carries no tier. It is NOT an account --
    see the migration 0036 header for why reusing `accounts` would have meant
    "MCP is for the one existing Pro customer".
  * A key reads only the audits it asked for. `audits.access_token` is a
    per-row capability precisely so that knowing an audit_id is not enough,
    and a key that could fetch any audit by id would step around it. What it
    would expose is a map of somebody else's vulnerabilities -- a broken
    object-level authorisation in the tool that reports broken object-level
    authorisation.
"""
