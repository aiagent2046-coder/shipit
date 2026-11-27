# syntax=docker/dockerfile:1
FROM node:24-bookworm-slim
WORKDIR /app
COPY source/package.json source/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY source/ ./
# Execute project build without outbound networking or provider credentials.
RUN --network=none npm run build
COPY scenario.mjs /app/control-scenario.mjs
COPY boot.sh /control/boot.sh
COPY probe.mjs /control/probe.mjs
COPY source-manifest.json /control/source-manifest.json
COPY verify-source.mjs /control/verify-source.mjs
ENV NODE_ENV=production DOTENV_CONFIG_PATH=/dev/null
USER node
CMD ["sh", "/control/boot.sh"]
