#!/bin/sh
# Explicit host install; never invoked by enrollment or Compose.
set -eu
[ "$(id -u)" = 0 ] || { echo 'Run as root on the intended VPS' >&2; exit 1; }
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
getent group docker >/dev/null || { echo 'Install Docker first' >&2; exit 1; }
if ! getent passwd platform-observer-proxy >/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin --gid docker platform-observer-proxy
fi
install -o root -g root -m 0755 "$repo/deployment/host/libexec/platform-docker-observer-proxy.py" /usr/local/libexec/platform-docker-observer-proxy.py
install -o root -g root -m 0644 "$repo/deployment/host/systemd/platform-docker-observer-proxy.service" /etc/systemd/system/platform-docker-observer-proxy.service
systemctl daemon-reload
systemctl enable --now platform-docker-observer-proxy.service
systemctl is-active --quiet platform-docker-observer-proxy.service
attempt=0
while [ ! -S /run/platform-docker-observer/docker.sock ]; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 10 ] || { echo 'Observer proxy socket did not become ready' >&2; exit 1; }
  systemctl is-active --quiet platform-docker-observer-proxy.service
  sleep 1
done
stat -c 'Observer proxy socket group ID: %g' /run/platform-docker-observer/docker.sock
