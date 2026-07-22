#!/usr/bin/env bash
set -Eeuo pipefail

base_url="${1:-http://127.0.0.1:8000}"

curl \
    --fail \
    --silent \
    --show-error \
    "${base_url}/healthz" |
    jq -e '.status == "ok"' >/dev/null

curl \
    --fail \
    --silent \
    --show-error \
    "${base_url}/readyz" |
    jq -e '.status == "ready" and .db == true' >/dev/null

curl \
    --fail \
    --silent \
    --show-error \
    "${base_url}/version" |
    jq -e '.release != null and .environment == "production"' >/dev/null

headers="$(mktemp)"
trap 'rm -f "$headers"' EXIT

curl \
    --silent \
    --show-error \
    --output /dev/null \
    --dump-header "$headers" \
    "${base_url}/healthz"

grep -qi '^x-content-type-options: nosniff' "$headers"
grep -qi '^x-frame-options: DENY' "$headers"
grep -qi '^referrer-policy: no-referrer' "$headers"
grep -qi '^cache-control: private, no-store' "$headers"

echo "Smoke tests passed"
