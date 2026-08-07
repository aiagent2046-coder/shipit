#!/usr/bin/env bash
set -Eeuo pipefail

# Forced command for the CI deployment key.
#
# Installed in root's authorized_keys as:
#
#   command="/opt/shipit/deploy/scripts/ci-deploy-command.sh",no-agent-forwarding,\
#   no-port-forwarding,no-pty,no-user-rc,no-X11-forwarding ssh-ed25519 AAAA... ci-deploy
#
# WHY THIS EXISTS
#
# deploy-production.sh must run as root: it drives systemctl, writes into
# /srv/shipit, and reads a 0640 root:shipit-ops env file. Handing CI a root
# key without restriction would mean that anyone who can reach the Actions
# secret store gets a root shell on production -- and that includes reading
# /opt/shipit/.env, which holds every payment and GitHub credential the
# service owns.
#
# A forced command collapses that blast radius. sshd ignores whatever the
# client asked to run and executes this script instead, passing the client's
# request in SSH_ORIGINAL_COMMAND as data. So a leaked key can do exactly one
# thing: deploy a release tag that is already an ancestor of origin/main. It
# cannot open a shell, read a file, or run anything else.
#
# THIS SCRIPT IS A SECURITY BOUNDARY. Every path must either match the one
# permitted shape exactly, or refuse. Never interpolate SSH_ORIGINAL_COMMAND
# into another command; only ever compare it against a strict pattern and
# pass the extracted tag as a single argv element.

DEPLOY="${SHIPIT_DEPLOY_SCRIPT:-/opt/shipit/deploy/scripts/deploy-production.sh}"

# Release tags only, in the CalVer shape tag-release.sh produces. Not SHAs:
# a tag must already exist, which means it went through tag-release.sh and its
# ancestor-of-main gate, whereas an arbitrary SHA is anything the caller can
# name. Deploying an untagged commit stays a deliberate act at the console.
TAG_RE='^v[0-9]{4}\.[0-9]{2}\.[0-9]{2}-[0-9]+$'

deny() {
  # Deliberately terse to the client, detailed to the host's journal: the
  # caller is untrusted and does not need to learn the shape of what it got
  # wrong, but an operator investigating a refusal does.
  echo "refused" >&2
  logger -t shipit-ci-deploy "refused SSH_ORIGINAL_COMMAND=${SSH_ORIGINAL_COMMAND:-<unset>} from ${SSH_CONNECTION:-unknown}" 2>/dev/null || true
  exit 1
}

REQUEST="${SSH_ORIGINAL_COMMAND:-}"

if [[ -z "$REQUEST" ]]; then
  deny
fi

# Exactly two whitespace-free words: the literal verb, then the tag. Anything
# else -- extra arguments, shell metacharacters, newlines, a second command
# chained with ; or && -- fails this match and is refused.
if [[ ! "$REQUEST" =~ ^deploy\ ([^[:space:]]+)$ ]]; then
  deny
fi

TAG="${BASH_REMATCH[1]}"

if [[ ! "$TAG" =~ $TAG_RE ]]; then
  deny
fi

if [[ ! -x "$DEPLOY" ]]; then
  echo "ERROR: deploy script missing or not executable: $DEPLOY" >&2
  exit 1
fi

logger -t shipit-ci-deploy "deploying $TAG from ${SSH_CONNECTION:-unknown}" 2>/dev/null || true

# $TAG is a single argv element and has been validated against TAG_RE, so it
# cannot introduce another argument or reach a shell.
exec "$DEPLOY" --revision "$TAG"
