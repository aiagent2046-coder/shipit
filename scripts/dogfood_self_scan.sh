#!/usr/bin/env bash
# Dogfood run: scan aiagent2046-coder/shipit@main with the local Ollama model
# behind the OpenAI-compatible provider slot. Paid fallbacks are removed from
# the environment so a failing Ollama degrades to static-only, never to a bill.
set -a
# shellcheck source=/dev/null
. /home/syndiai/shipit/.env
set +a
unset ANTHROPIC_API_KEY
export AITUNNEL_BASE_URL=http://127.0.0.1:11434/v1
# Quoted: the *** stub is a literal (a glob-shaped bare assignment is
# exactly what shellcheck SC2125 flags).
export AITUNNEL_API_KEY="***"
export AITUNNEL_LLM_MODEL=qwen2.5-coder:7b
cd /home/syndiai/shipit || exit
exec .venv/bin/python scripts/audit_one_repo.py aiagent2046-coder/shipit main
