# Shipit (Drydock) — Agent Notes

## Project brain (NotebookLM, grounded Q&A over docs/)

A persistent NotebookLM notebook ("shipit-brain", id `ab2e5925-d365-4d87-953b-c4a4502d8d5f`)
holds the full `docs/` corpus (48 docs, snapshot 2026-11-14). It answers
architecture/decision questions **with citations back to the doc files**.

Before writing code that touches an area documented in `docs/`, ask the brain
instead of reading the whole corpus into context:

```bash
~/.venvs/notebooklm/bin/notebooklm -p pilot ask --new --yes \
  -n ab2e5925 --json "YOUR QUESTION"
```

- stdout is JSON (`answer`, `references[]` with `source_id` + `cited_text`);
  CLI status lines like `Matched: ...` go to stderr.
- Check `references[]` to see which docs support the answer; open the original
  doc before acting on anything load-bearing.
- For multi-question work use one conversation: drop `--new` on follow-ups.

Refresh (when `docs/` changes materially): re-upload changed files with
`notebooklm -p pilot source add <file> -n ab2e5925`. Full workflow + pitfalls:
Hermes skill `notebooklm-workflows`.

If commands fail with `rpc_code=5` right after setup, the Google account needs
one-time provisioning (see the skill's P1 pitfall — `provision_account.py`).