#!/bin/sh
set -eu
export AGENT_RUNTIME_SECRET="$(node -e 'process.stdout.write(require("node:crypto").randomBytes(32).toString("hex"))')"
timeout --kill-after=5s 180 node --import tsx server/src/migrate-bin.ts
exec timeout --kill-after=5s 600 node --import tsx server/src/index.ts
