#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "Usage: $0 <endpoint> <token-env-name> [max-time]" >&2
    exit 64
fi

endpoint="$1"
token_env_name="$2"
max_time="${3:-300}"

token="${!token_env_name:-}"

if [[ -z "$token" ]]; then
    echo "Required token is missing: $token_env_name" >&2
    exit 78
fi

base_url="${SHIPIT_INTERNAL_BASE_URL:-http://127.0.0.1:8000}"

curl_config="$(mktemp)"
response_file="$(mktemp)"

cleanup() {
    rm -f "$curl_config" "$response_file"
}
trap cleanup EXIT

chmod 0600 "$curl_config" "$response_file"

# Keep the bearer token out of the process command line.
printf 'header = "Authorization: Bearer %s"\n' "$token" > "$curl_config"

status="$(
    curl \
        --config "$curl_config" \
        --silent \
        --show-error \
        --output "$response_file" \
        --write-out "%{http_code}" \
        --connect-timeout 5 \
        --max-time "$max_time" \
        --retry 2 \
        --retry-connrefused \
        --retry-all-errors \
        --request POST \
        "${base_url}${endpoint}"
)"

if [[ "$status" -lt 200 || "$status" -ge 300 ]]; then
    echo "Internal call failed: ${endpoint}, HTTP ${status}" >&2
    cat "$response_file" >&2
    exit 1
fi

cat "$response_file"
echo
