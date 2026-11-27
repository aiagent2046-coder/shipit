"""Fix Pack generation + delivery.

Turns a paid `fixpack_jobs` row into a real, safe pull request: re-fetch
the audited repo, relocate the eligible findings in the fresh source, and
open a PR that removes hardcoded secrets and secures repo config. See
app/fixpack/generate.py for the generation logic and app/main.py's
POST /internal/fixpack/process-paid for the trigger.
"""
