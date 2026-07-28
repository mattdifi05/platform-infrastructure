#!/usr/bin/env sh
set -eu
umask 077

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
CLIENT="$ROOT/scripts/docker-action-client.mjs"

if [ "$#" -lt 1 ]; then
  echo "Usage: ./scripts/infra-ops.sh <fixed-action> [fixed parameters]" >&2
  exit 64
fi

case "$1" in
  backup-platform-catalog|execute-backup-job|prune-manifest-backups-plan|prune-manifest-backups-apply|full-restore-drill|offsite-backup-restic|runtime-docker-snapshot)
    exec node "$CLIENT" "$@"
    ;;
  *)
    echo "Operation '$1' has no admitted fixed-action implementation; refusing without mutation." >&2
    exit 78
    ;;
esac
