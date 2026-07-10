#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
SECRET_FILE=${ALERTMANAGER_WEBHOOK_TOKEN_HOST_FILE:-$ROOT/secrets/alertmanager_webhook_token.txt}
EXPECTED_GID=${ALERTMANAGER_SECRET_GID:-$(id -g)}
APPLY=0
CONFIRM=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --file)
      [ "$#" -ge 2 ] || { echo "--file requires a path" >&2; exit 2; }
      SECRET_FILE=$2
      shift 2
      ;;
    --gid)
      [ "$#" -ge 2 ] || { echo "--gid requires a numeric group id" >&2; exit 2; }
      EXPECTED_GID=$2
      shift 2
      ;;
    --apply)
      APPLY=1
      shift
      ;;
    --confirm)
      [ "$#" -ge 2 ] || { echo "--confirm requires a value" >&2; exit 2; }
      CONFIRM=$2
      shift 2
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
  esac
done

case "$EXPECTED_GID" in
  ""|*[!0-9]*) echo "Alertmanager secret gid must be numeric." >&2; exit 2 ;;
esac

[ "$(basename -- "$SECRET_FILE")" = "alertmanager_webhook_token.txt" ] || {
  echo "Refusing to manage a file other than alertmanager_webhook_token.txt." >&2
  exit 2
}
[ ! -L "$SECRET_FILE" ] || { echo "Alertmanager token path must not be a symlink." >&2; exit 1; }
[ -f "$SECRET_FILE" ] || { echo "Alertmanager token file is missing or not regular." >&2; exit 1; }

CURRENT_UID=$(id -u)
FILE_UID=$(stat -c %u "$SECRET_FILE")
if [ "$CURRENT_UID" -ne 0 ] && [ "$FILE_UID" -ne "$CURRENT_UID" ]; then
  echo "Alertmanager token must be owned by the current operator before permissions can be managed." >&2
  exit 1
fi

if [ "$APPLY" -eq 1 ]; then
  [ "$CONFIRM" = "APPLY-ALERTMANAGER-SECRET-PERMISSIONS" ] || {
    echo "Apply requires --confirm APPLY-ALERTMANAGER-SECRET-PERMISSIONS." >&2
    exit 2
  }
  chgrp "$EXPECTED_GID" "$SECRET_FILE"
  chmod 0640 "$SECRET_FILE"
fi

ACTUAL_MODE=$(stat -c %a "$SECRET_FILE")
ACTUAL_GID=$(stat -c %g "$SECRET_FILE")
[ "$ACTUAL_MODE" = "640" ] || { echo "Alertmanager token mode must be 640; found $ACTUAL_MODE." >&2; exit 1; }
[ "$ACTUAL_GID" = "$EXPECTED_GID" ] || { echo "Alertmanager token gid must be $EXPECTED_GID; found $ACTUAL_GID." >&2; exit 1; }

printf '{"status":"passed","mode":"%s","gid":%s,"contentRead":false,"changed":%s}\n' \
  "$ACTUAL_MODE" "$ACTUAL_GID" "$([ "$APPLY" -eq 1 ] && printf true || printf false)"
