#!/usr/bin/env sh
set -eu

STATE_ROOT=${PLATFORM_STATE_DIR:?Set PLATFORM_STATE_DIR}
DATA_ROOT=${LOCAL_PRIVATE_BACKUP_DATA_DIR:?Set LOCAL_PRIVATE_BACKUP_DATA_DIR}
EXPECTED_UID=${LOCAL_PRIVATE_BACKUP_UID:-1000}
EXPECTED_GID=${LOCAL_PRIVATE_BACKUP_GID:-1000}

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

case "$EXPECTED_UID:$EXPECTED_GID" in
  *[!0-9:]*|:*|*:) fail "Backup UID/GID must be numeric." ;;
esac
[ "$(id -u)" = "$EXPECTED_UID" ] || fail "Run the backup filesystem preflight as UID $EXPECTED_UID."
[ "$(id -g)" = "$EXPECTED_GID" ] || fail "Run the backup filesystem preflight as GID $EXPECTED_GID."

for root in "$STATE_ROOT" "$DATA_ROOT"; do
  case "$root" in
    /*) ;;
    *) fail "Backup filesystem roots must be absolute paths." ;;
  esac
  case "$root" in
    /|/home|/opt|/srv|/usr|/var) fail "Refusing a broad backup filesystem root: $root" ;;
  esac
done

[ -d "$STATE_ROOT" ] || fail "Control Center state root does not exist."
[ ! -L "$STATE_ROOT" ] || fail "Control Center state root must not be a symlink."
state_physical=$(CDPATH= cd -- "$STATE_ROOT" && pwd -P)
[ "$state_physical" = "$STATE_ROOT" ] || fail "Control Center state root is not its canonical physical path."

data_parent=$(dirname -- "$DATA_ROOT")
[ -d "$data_parent" ] || fail "Backup data parent must exist before preflight."
[ ! -L "$data_parent" ] || fail "Backup data parent must not be a symlink."
data_parent_physical=$(CDPATH= cd -- "$data_parent" && pwd -P)
[ "$DATA_ROOT" = "$data_parent_physical/$(basename -- "$DATA_ROOT")" ] || fail "Backup data root is not below its canonical physical parent."

install -d -m 0700 \
  "$DATA_ROOT" \
  "$DATA_ROOT/backups" \
  "$DATA_ROOT/reports" \
  "$DATA_ROOT/.tmp" \
  "$DATA_ROOT/runtime-state" \
  "$DATA_ROOT/runtime-state/node-exporter-textfile" \
  "$DATA_ROOT/backup-jobs" \
  "$DATA_ROOT/backup-jobs/queued" \
  "$DATA_ROOT/backup-jobs/running" \
  "$DATA_ROOT/backup-jobs/done" \
  "$DATA_ROOT/backup-jobs/failed" \
  "$DATA_ROOT/scheduler-logs"

data_physical=$(CDPATH= cd -- "$DATA_ROOT" && pwd -P)
[ "$data_physical" = "$DATA_ROOT" ] || fail "Backup data root is not its canonical physical path."
case "$data_physical/" in "$state_physical/"*) fail "Backup data root must be separate from Control Center state." ;; esac
case "$state_physical/" in "$data_physical/"*) fail "Control Center state must be separate from backup data root." ;; esac

for root in "$STATE_ROOT" "$DATA_ROOT"; do
  unsafe=$(find "$root" -xdev \( -type l -o ! -uid "$EXPECTED_UID" -o ! -gid "$EXPECTED_GID" \) -print -quit)
  [ -z "$unsafe" ] || fail "Unsafe ownership or symlink in backup filesystem root: $unsafe"
done

[ "$(stat -c '%a' "$STATE_ROOT")" = 700 ] || fail "Control Center state root must have mode 0700."
for directory in \
  "$DATA_ROOT" "$DATA_ROOT/backups" "$DATA_ROOT/reports" "$DATA_ROOT/.tmp" \
  "$DATA_ROOT/runtime-state" "$DATA_ROOT/runtime-state/node-exporter-textfile" \
  "$DATA_ROOT/backup-jobs" "$DATA_ROOT/backup-jobs/queued" "$DATA_ROOT/backup-jobs/running" \
  "$DATA_ROOT/backup-jobs/done" "$DATA_ROOT/backup-jobs/failed" "$DATA_ROOT/scheduler-logs"
do
  [ "$(stat -c '%a' "$directory")" = 700 ] || fail "Backup data directory must have mode 0700: $directory"
done

state_probe="$STATE_ROOT/.local-private-backup-preflight-$$"
data_probe="$DATA_ROOT/.local-private-backup-preflight-$$"
cleanup() {
  rm -f -- "$state_probe" "$state_probe.renamed" "$data_probe" "$data_probe.renamed"
}
trap cleanup EXIT HUP INT TERM
for probe in "$state_probe" "$data_probe"; do
  [ ! -e "$probe" ] || fail "Backup write probe path already exists."
  (umask 077 && printf '%s\n' preflight > "$probe")
  mv -- "$probe" "$probe.renamed"
  rm -- "$probe.renamed"
done
trap - EXIT HUP INT TERM

printf '%s\n' 'LOCAL_PRIVATE_BACKUP_FILESYSTEM_PREFLIGHT=PASS'
