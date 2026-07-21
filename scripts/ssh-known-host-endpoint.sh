#!/usr/bin/env sh
set -eu

host=${1:-}
port=${2:-}
known_hosts=${3:-}

case "$host" in [A-Za-z0-9]*) ;; *) echo "SSH host is invalid." >&2; exit 1 ;; esac
case "$host" in *[!A-Za-z0-9.-]*|*..*|*-|*.) echo "SSH host is invalid." >&2; exit 1 ;; esac
case "$port" in ''|*[!0-9]*) echo "SSH port is invalid." >&2; exit 1 ;; esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || { echo "SSH port is invalid." >&2; exit 1; }
[ -f "$known_hosts" ] && [ -r "$known_hosts" ] && [ -s "$known_hosts" ] && [ ! -L "$known_hosts" ] || {
  echo "Owner-approved known_hosts must be a readable, non-empty regular file, not a symlink." >&2
  exit 1
}

lookup=$host
[ "$port" = 22 ] || lookup="[$host]:$port"
matches=$(mktemp "${TMPDIR:-/tmp}/ssh-known-host-endpoint.XXXXXX")
trap 'rm -f "$matches"' EXIT HUP INT TERM
ssh-keygen -F "$lookup" -f "$known_hosts" > "$matches" 2>/dev/null || {
  echo "Owner-approved known_hosts has no pin for the exact SSH host and port." >&2
  exit 1
}
records=$(awk 'NF && $1 !~ /^#/ { count++ } END { print count + 0 }' "$matches")
[ "$records" -eq 1 ] || {
  echo "Owner-approved known_hosts must contain exactly one active key for the exact SSH host and port; replace the old key atomically during rotation." >&2
  exit 1
}
awk -v lookup="$lookup" '
  NF && $1 !~ /^#/ {
    hostField=$1
    if (hostField ~ /^@/) exit 1
    if (hostField ~ /^\|1\|/) next
    if (hostField ~ /[*?!,]/ || hostField != lookup) exit 1
  }
' "$matches" || {
  echo "SSH host pin must be one literal exact host:port (or its hashed exact form), without wildcard, negation, marker, or CA rules." >&2
  exit 1
}
