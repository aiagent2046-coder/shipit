#!/usr/bin/env bash
# Create the audit payload spool on a host, once.
#
# An uploaded zip has never been persisted anywhere (migration 0001: no S3, no
# s3_key), which is exactly why POST /v1/audits cannot hand work to another
# process today. app/audit_spool.py stages those bytes here so the worker in
# shipit-audit-worker.service can read them after the request is gone.
#
# Host state, not release state, so this is NOT part of deploy-production.sh:
# it survives every release swap and only needs running when a host is built
# (or when shipit-audit-worker.service fails its ExecStartPre -w check).
# Idempotent -- safe to re-run.
#
#   sudo deploy/scripts/provision-audit-spool.sh

set -Eeuo pipefail

SPOOL_DIR="${AUDIT_SPOOL_DIR:-/srv/shipit/spool}"
SPOOL_USER="${SHIPIT_SERVICE_USER:-shipit-ops}"

if [[ "$EUID" -ne 0 ]]; then
    echo "ERROR: must run as root to chown ${SPOOL_DIR} to ${SPOOL_USER}" >&2
    exit 1
fi

if ! id -u "$SPOOL_USER" >/dev/null 2>&1; then
    echo "ERROR: user ${SPOOL_USER} does not exist" >&2
    exit 1
fi

# install -d is the house pattern for provisioned directories (see
# backup-postgres.sh, backup-postgres-offsite.sh) and sets the mode atomically
# rather than leaving a window at the umask default.
#
# 0700, and owned by the service user rather than root: the directory holds
# users' private source code, and both writers -- the API staging an upload and
# the worker reading it back -- run as ${SPOOL_USER}. Nothing else on the box
# has any reason to list it.
install -d -m 0700 -o "$SPOOL_USER" -g "$SPOOL_USER" "$SPOOL_DIR"

echo "Provisioned ${SPOOL_DIR} (0700 ${SPOOL_USER}:${SPOOL_USER})"
