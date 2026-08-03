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
# 2770, group ${SPOOL_USER}. The setgid bit is the load-bearing part: the two
# services that share this directory do NOT run as the same user. shipit.service
# has no User= and so stages uploads as root, while shipit-audit-worker.service
# runs as ${SPOOL_USER} and reads them back. Setgid makes every file created
# here inherit the directory's group regardless of who created it, which is what
# lets the worker's group-read bit actually match. Without it a root-written
# archive lands root:root and the worker gets EACCES on every zip audit.
#
# Still no bits for others: the directory holds users' private source code, and
# exactly two service identities have any business reading it.
install -d -m 2770 -o "$SPOOL_USER" -g "$SPOOL_USER" "$SPOOL_DIR"

# install -d applies the mode to an existing directory too, but only on GNU
# coreutils and only for the permission bits it is given. This chmod is the
# explicit guarantee for the case this fix exists to repair: a host where the
# directory was already provisioned at 0700 by an earlier release, or created
# on demand by stage_archive() before this script ever ran.
chmod 2770 "$SPOOL_DIR"

echo "Provisioned ${SPOOL_DIR} (2770 ${SPOOL_USER}:${SPOOL_USER})"
