#!/bin/sh
# Root local installation only; never starts a capture or enables a timer.
set -eu
[ "$(id -u)" = 0 ] || exit 1
src=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
dest=/usr/local/libexec/platform-vps-backup
install -d -o root -g root -m 0755 "$dest/deployment/vps-backup" "$dest/control-center/backup" "$dest/scripts"
for name in platform-vps-backup-runner.py ftps-sync.py platform_ftps_shared_quota.py native-manifest.mjs enroll.py panel-queue.py; do
 install -o root -g root -m 0755 "$src/deployment/vps-backup/$name" "$dest/deployment/vps-backup/$name"
done
for name in contracts.mjs queue-admission.mjs queue-operation-adapter.mjs; do
 install -o root -g root -m 0644 "$src/control-center/backup/$name" "$dest/control-center/backup/$name"
done
install -o root -g root -m 0644 "$src/scripts/backup-queue-control.mjs" "$dest/scripts/backup-queue-control.mjs"
install -o root -g root -m 0644 "$src/deployment/vps-backup/platform-vps-backup.service" /etc/systemd/system/platform-vps-backup.service
install -o root -g root -m 0644 "$src/deployment/vps-backup/platform-vps-backup.timer" /etc/systemd/system/platform-vps-backup.timer
install -o root -g root -m 0644 "$src/deployment/vps-backup/platform-vps-backup-queue.service" /etc/systemd/system/platform-vps-backup-queue.service
install -o root -g root -m 0644 "$src/deployment/vps-backup/platform-vps-backup-queue.timer" /etc/systemd/system/platform-vps-backup-queue.timer
if [ -d /var/lib/platform-vps-backup ]; then
 install -d -o 1000 -g 1000 -m 0700 /var/lib/platform-vps-backup/queue
fi
systemctl daemon-reload
printf '%s\n' 'Installed protected VPS backup runtime; no capture, timer or FTP action started.'
