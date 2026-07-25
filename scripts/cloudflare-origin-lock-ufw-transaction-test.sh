#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/origin-lock-transaction-test.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
SSH_PORT=65002
PASS_COUNT=0

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf 'PASS\t%s\n' "$1"
}

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

printf '%s\n' '173.245.48.0/20' > "$TMP/ips-v4"
printf '%s\n' '2400:cb00::/32' > "$TMP/ips-v6"
printf '%s\n' 'origin-lock-transaction-test-machine' > "$TMP/machine-id"
cat > "$TMP/compose.json" <<'EOF'
{"services":{"edge":{"ports":[{"published":"80","target":8080,"protocol":"tcp","host_ip":"0.0.0.0"},{"published":"443","target":8443,"protocol":"tcp","host_ip":"::"},{"published":"8443","target":9443,"protocol":"tcp","host_ip":"192.0.2.10"}]}}}
EOF
python3 "$SCRIPT_DIR/cloudflare-origin-lock-policy.py" create \
  --ipv4 "$TMP/ips-v4" --ipv6 "$TMP/ips-v6" --ports '80 443 8443' \
  --ssh-port "$SSH_PORT" --receipt "$TMP/receipt.json"

cat > "$TMP/rules.initial" <<'EOF'
80/tcp ALLOW IN Anywhere
443/tcp ALLOW IN Anywhere
8443/tcp ALLOW IN Anywhere
80/tcp ALLOW IN 203.0.113.0/24 # cloudflare-origin-80
80/tcp ALLOW IN 203.0.113.0/24 # cloudflare-origin-80
9443/tcp (v6) ALLOW IN 2001:db8:ffff::/48 # cloudflare-origin-9443
65002/tcp ALLOW IN Anywhere
65002/tcp (v6) ALLOW IN Anywhere (v6)
EOF

cat > "$TMP/ufw" <<'SH'
#!/usr/bin/env sh
set -eu

log() {
  printf '%s\n' "$*" >> "$FAKE_UFW_LOG"
}

after_mutation() {
  count=$(cat "$FAKE_UFW_MUTATION_COUNT")
  count=$((count + 1))
  printf '%s\n' "$count" > "$FAKE_UFW_MUTATION_COUNT"
  log "MUTATION $count: $*"
  if [ "${FAKE_UFW_SIGNAL_AFTER:-}" = "$count" ]; then
    kill -TERM "$PPID"
    exit 0
  fi
  if [ "${FAKE_UFW_FAIL_AFTER:-}" = "$count" ]; then
    exit 97
  fi
}

show_status() {
  policy=$(cat "$FAKE_UFW_POLICY")
  printf 'Status: active\n'
  printf 'Default: %s (incoming), allow (outgoing), disabled (routed)\n' "$policy"
  awk '{ printf "[%2d] %s\n", NR, $0 }' "$FAKE_UFW_RULES"
}

log "$*"
if [ "$1 ${2:-}" = "status numbered" ] || [ "$1 ${2:-}" = "status verbose" ]; then
  show_status
  exit 0
fi

if [ "$1 ${2:-}" = "--force delete" ]; then
  if [ "$3" = allow ]; then
    target=${4:?missing generic target}
    awk -v target="$target" '
      index($0, target " ALLOW IN Anywhere") != 1 &&
      index($0, target " (v6) ALLOW IN Anywhere") != 1
    ' "$FAKE_UFW_RULES" > "$FAKE_UFW_RULES.next"
    mv "$FAKE_UFW_RULES.next" "$FAKE_UFW_RULES"
    after_mutation "delete-generic:$target"
    exit 0
  fi
  number=$3
  awk -v drop="$number" 'NR != drop' "$FAKE_UFW_RULES" > "$FAKE_UFW_RULES.next"
  mv "$FAKE_UFW_RULES.next" "$FAKE_UFW_RULES"
  after_mutation "delete-number:$number"
  exit 0
fi

if [ "$1" = allow ]; then
  [ "$2 $3 $4 $6 $7 $8 ${10}" = "proto tcp from to any port comment" ] || exit 96
  cidr=$5
  port=$9
  comment=${11}
  case "$cidr" in
    *:*) target="${port}/tcp (v6)" ;;
    *) target="${port}/tcp" ;;
  esac
  printf '%s ALLOW IN %s # %s\n' "$target" "$cidr" "$comment" >> "$FAKE_UFW_RULES"
  after_mutation "add-managed:$port:$cidr:$comment"
  exit 0
fi

if [ "$1 ${2:-} ${3:-}" = "default deny incoming" ]; then
  printf '%s\n' deny > "$FAKE_UFW_POLICY"
  after_mutation default-deny-incoming
  exit 0
fi

if [ "$1" = reload ]; then
  after_mutation reload
  exit 0
fi

exit 95
SH
chmod 700 "$TMP/ufw"

fake_env() {
  env \
    PATH="$TMP:$PATH" \
    PLATFORM_ORIGIN_LOCK_TEST_MODE=1 \
    FAKE_UFW_RULES="$TMP/rules.current" \
    FAKE_UFW_POLICY="$TMP/policy.current" \
    FAKE_UFW_LOG="$TMP/ufw.log" \
    FAKE_UFW_MUTATION_COUNT="$TMP/mutation-count" \
    FAKE_UFW_FAIL_AFTER="${FAKE_UFW_FAIL_AFTER:-}" \
    FAKE_UFW_SIGNAL_AFTER="${FAKE_UFW_SIGNAL_AFTER:-}" \
    "$@"
}

reset_firewall() {
  cp "$TMP/rules.initial" "$TMP/rules.current"
  printf '%s\n' allow > "$TMP/policy.current"
  printf '%s\n' 0 > "$TMP/mutation-count"
  : > "$TMP/ufw.log"
  rm -rf "$TMP/state"
  fake_env "$TMP/ufw" status numbered > "$TMP/status.before"
}

capture_current_status() {
  fake_env "$TMP/ufw" status numbered > "$1"
}

normalize_owned() {
  sed -E 's/^[[:space:]]*\[[[:space:]]*[0-9]+\][[:space:]]*//' "$1" \
    | grep -E '# cloudflare-origin-[0-9]+$' \
    | LC_ALL=C sort
}

normalize_ssh() {
  sed -E 's/^[[:space:]]*\[[[:space:]]*[0-9]+\][[:space:]]*//' "$1" \
    | grep -E "^${SSH_PORT}/tcp( \\(v6\\))?[[:space:]]+ALLOW IN Anywhere" \
    | LC_ALL=C sort
}

assert_rollback_boundary() {
  boundary=$1
  label=$2
  reset_firewall
  FAKE_UFW_FAIL_AFTER=$boundary
  export FAKE_UFW_FAIL_AFTER
  set +e
  fake_env sh "$SCRIPT_DIR/cloudflare-origin-lock-ufw.sh" --apply \
    --compose-json "$TMP/compose.json" \
    --ipv4-file "$TMP/ips-v4" --ipv6-file "$TMP/ips-v6" \
    --receipt-file "$TMP/receipt.json" --ssh-port "$SSH_PORT" \
    --state-dir "$TMP/state" --machine-id-file "$TMP/machine-id" \
    > "$TMP/failure-$boundary.out" 2>&1
  rc=$?
  set -e
  unset FAKE_UFW_FAIL_AFTER
  [ "$rc" -ne 0 ] || fail "$label failure was accepted"
  capture_current_status "$TMP/status.after"
  normalize_owned "$TMP/status.before" > "$TMP/owned.before"
  normalize_owned "$TMP/status.after" > "$TMP/owned.after"
  cmp "$TMP/owned.before" "$TMP/owned.after" >/dev/null \
    || fail "$label did not restore the exact prior owned-rule multiset"
  normalize_ssh "$TMP/status.before" > "$TMP/ssh.before"
  normalize_ssh "$TMP/status.after" > "$TMP/ssh.after"
  cmp "$TMP/ssh.before" "$TMP/ssh.after" >/dev/null \
    || fail "$label changed the SSH recovery rules"
  grep -Fq 'Default: deny (incoming)' "$TMP/status.after" \
    || fail "$label rollback did not leave incoming policy fail-closed"
  grep -Fq 'Origin lock rollback verified' "$TMP/failure-$boundary.out" \
    || fail "$label did not report verified rollback"
  pass "$label"
}

while IFS='|' read -r boundary label; do
  assert_rollback_boundary "$boundary" "$label"
done <<'EOF'
1|rollback-after-first-managed-delete
2|rollback-after-second-managed-delete
3|rollback-after-third-managed-delete
4|rollback-after-first-managed-add
5|rollback-after-second-managed-add
6|rollback-after-third-managed-add
7|rollback-after-fourth-managed-add
8|rollback-after-fifth-managed-add
9|rollback-after-sixth-managed-add
10|rollback-after-first-generic-delete
11|rollback-after-second-generic-delete
12|rollback-after-third-generic-delete
13|rollback-after-default-policy-change
14|rollback-after-reload
EOF

reset_firewall
FAKE_UFW_SIGNAL_AFTER=1
export FAKE_UFW_SIGNAL_AFTER
set +e
fake_env sh "$SCRIPT_DIR/cloudflare-origin-lock-ufw.sh" --apply \
  --compose-json "$TMP/compose.json" \
  --ipv4-file "$TMP/ips-v4" --ipv6-file "$TMP/ips-v6" \
  --receipt-file "$TMP/receipt.json" --ssh-port "$SSH_PORT" \
  --state-dir "$TMP/state" --machine-id-file "$TMP/machine-id" \
  > "$TMP/signal.out" 2>&1
signal_rc=$?
set -e
unset FAKE_UFW_SIGNAL_AFTER
[ "$signal_rc" -ne 0 ] || fail "TERM during mutation was accepted"
capture_current_status "$TMP/status.after-signal"
normalize_owned "$TMP/status.before" > "$TMP/owned.before-signal"
normalize_owned "$TMP/status.after-signal" > "$TMP/owned.after-signal"
cmp "$TMP/owned.before-signal" "$TMP/owned.after-signal" >/dev/null \
  || fail "TERM did not restore the exact prior owned-rule multiset"
normalize_ssh "$TMP/status.before" > "$TMP/ssh.before-signal"
normalize_ssh "$TMP/status.after-signal" > "$TMP/ssh.after-signal"
cmp "$TMP/ssh.before-signal" "$TMP/ssh.after-signal" >/dev/null \
  || fail "TERM changed the SSH recovery rules"
grep -Fq 'Origin lock rollback verified' "$TMP/signal.out" \
  || fail "TERM did not report verified rollback"
pass signal-runs-verified-rollback

reset_firewall
fake_env sh "$SCRIPT_DIR/cloudflare-origin-lock-ufw.sh" --apply \
  --compose-json "$TMP/compose.json" \
  --ipv4-file "$TMP/ips-v4" --ipv6-file "$TMP/ips-v6" \
  --receipt-file "$TMP/receipt.json" --ssh-port "$SSH_PORT" \
  --state-dir "$TMP/state" --machine-id-file "$TMP/machine-id" \
  > "$TMP/success.out" 2>&1
[ "$(cat "$TMP/mutation-count")" -eq 14 ] \
  || fail "success path did not exercise all 14 primary mutation boundaries"
capture_current_status "$TMP/status.success"
grep -Fq 'Default: deny (incoming)' "$TMP/status.success" \
  || fail "success path did not enforce default deny"
grep -Fq '173.245.48.0/20 # cloudflare-origin-80' "$TMP/status.success" \
  || fail "success path did not install the desired IPv4 rule"
grep -Fq '2400:cb00::/32 # cloudflare-origin-443' "$TMP/status.success" \
  || fail "success path did not install the desired IPv6 rule"
normalize_ssh "$TMP/status.before" > "$TMP/ssh.before-success"
normalize_ssh "$TMP/status.success" > "$TMP/ssh.after-success"
cmp "$TMP/ssh.before-success" "$TMP/ssh.after-success" >/dev/null \
  || fail "success path changed the SSH recovery rules"
pass successful-transaction-preserves-ssh-and-publishes-state

printf 'Cloudflare origin lock transaction tests passed %s/%s\n' "$PASS_COUNT" "$PASS_COUNT"
