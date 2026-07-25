#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/origin-lock-test.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
SSH_PORT=65002
PASS_COUNT=0
export PLATFORM_ORIGIN_LOCK_TEST_MODE=1

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf 'PASS\t%s\n' "$1"
}

expect_reject() {
  label=$1
  shift
  if "$@" >/dev/null 2>&1; then echo "FAIL: $label was accepted" >&2; exit 1; fi
  pass "$label"
}

printf '%s\n' '173.245.48.0/20' > "$TMP/ips-v4"
printf '%s\n' '2400:cb00::/32' > "$TMP/ips-v6"
printf '%s\n' 'origin-lock-test-machine' > "$TMP/machine-id"
cat > "$TMP/compose.json" <<'EOF'
{"services":{"edge":{"ports":[{"published":"80","target":8080,"protocol":"tcp","host_ip":"0.0.0.0"},{"published":"443","target":8443,"protocol":"tcp","host_ip":"::"},{"published":"8443","target":9443,"protocol":"tcp","host_ip":"192.0.2.10"}]},"db":{"ports":[{"published":"5432","target":5432,"protocol":"tcp","host_ip":"127.0.0.1"}]}}}
EOF
cat > "$TMP/status-good" <<'EOF'
Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)
[ 1] 80/tcp ALLOW IN 173.245.48.0/20 # cloudflare-origin-80
[ 2] 80/tcp (v6) ALLOW IN 2400:cb00::/32 # cloudflare-origin-80
[ 3] 443/tcp ALLOW IN 173.245.48.0/20 # cloudflare-origin-443
[ 4] 443/tcp (v6) ALLOW IN 2400:cb00::/32 # cloudflare-origin-443
[ 5] 8443/tcp ALLOW IN 173.245.48.0/20 # cloudflare-origin-8443
[ 6] 8443/tcp (v6) ALLOW IN 2400:cb00::/32 # cloudflare-origin-8443
[ 7] 65002/tcp ALLOW IN Anywhere
[ 8] 65002/tcp (v6) ALLOW IN Anywhere (v6)
EOF

python3 "$SCRIPT_DIR/cloudflare-origin-lock-policy.py" create \
  --ipv4 "$TMP/ips-v4" --ipv6 "$TMP/ips-v6" --ports '80 443 8443' \
  --ssh-port "$SSH_PORT" --receipt "$TMP/receipt.json"

verify() {
  status=$1
  shift
  sh "$SCRIPT_DIR/cloudflare-origin-lock-ufw.sh" --verify --compose-json "$TMP/compose.json" \
    --ipv4-file "$TMP/ips-v4" --ipv6-file "$TMP/ips-v6" --receipt-file "$TMP/receipt.json" \
    --ssh-port "$SSH_PORT" --status-file "$status" --machine-id-file "$TMP/machine-id" "$@"
}

verify "$TMP/status-good" >/dev/null
pass complete-ipv4-ipv6-origin-lock

expect_reject explicit-cidr-input-is-test-only env PLATFORM_ORIGIN_LOCK_TEST_MODE=0 \
  sh "$SCRIPT_DIR/cloudflare-origin-lock-ufw.sh" --verify --compose-json "$TMP/compose.json" \
    --ipv4-file "$TMP/ips-v4" --ipv6-file "$TMP/ips-v6" --receipt-file "$TMP/receipt.json" \
    --ssh-port "$SSH_PORT" --status-file "$TMP/status-good"

expect_reject production-status-file-override env -u PLATFORM_ORIGIN_LOCK_TEST_MODE \
  sh "$SCRIPT_DIR/cloudflare-origin-lock-ufw.sh" --verify --compose-json "$TMP/compose.json" \
    --ssh-port "$SSH_PORT" --status-file "$TMP/status-good"
expect_reject production-state-dir-argument-override env -u PLATFORM_ORIGIN_LOCK_TEST_MODE \
  sh "$SCRIPT_DIR/cloudflare-origin-lock-ufw.sh" --verify --compose-json "$TMP/compose.json" \
    --ssh-port "$SSH_PORT" --state-dir "$TMP/state"
expect_reject production-state-dir-environment-override env -u PLATFORM_ORIGIN_LOCK_TEST_MODE \
  ORIGIN_LOCK_STATE_DIR="$TMP/state" sh "$SCRIPT_DIR/cloudflare-origin-lock-ufw.sh" --verify \
    --compose-json "$TMP/compose.json" --ssh-port "$SSH_PORT"
expect_reject production-freshness-override env -u PLATFORM_ORIGIN_LOCK_TEST_MODE \
  sh "$SCRIPT_DIR/cloudflare-origin-lock-ufw.sh" --verify --compose-json "$TMP/compose.json" \
    --ssh-port "$SSH_PORT" --max-cidr-age-seconds 999999999
expect_reject production-machine-id-override env -u PLATFORM_ORIGIN_LOCK_TEST_MODE \
  sh "$SCRIPT_DIR/cloudflare-origin-lock-ufw.sh" --verify --compose-json "$TMP/compose.json" \
    --ssh-port "$SSH_PORT" --machine-id-file "$TMP/ips-v4"

sed 's/Default: deny (incoming)/Default: allow (incoming)/' "$TMP/status-good" > "$TMP/status-default-allow"
expect_reject default-incoming-allow verify "$TMP/status-default-allow"

cp "$TMP/status-good" "$TMP/status-generic"
printf '%s\n' '[ 9] 443/tcp ALLOW IN Anywhere' >> "$TMP/status-generic"
expect_reject generic-public-allow verify "$TMP/status-generic"

sed '/2400:cb00::\/32.*443/d' "$TMP/status-good" > "$TMP/status-missing-v6"
expect_reject missing-ipv6-rule verify "$TMP/status-missing-v6"

cp "$TMP/status-good" "$TMP/status-stale"
printf '%s\n' '[ 9] 80/tcp ALLOW IN 203.0.113.0/24 # cloudflare-origin-80' >> "$TMP/status-stale"
expect_reject stale-managed-rule verify "$TMP/status-stale"

cp "$TMP/status-good" "$TMP/status-profile"
printf '%s\n' '[ 9] Nginx Full ALLOW IN Anywhere' >> "$TMP/status-profile"
expect_reject named-profile-bypass verify "$TMP/status-profile"

cp "$TMP/status-good" "$TMP/status-comma"
printf '%s\n' '[ 9] 80,443/tcp ALLOW IN Anywhere' >> "$TMP/status-comma"
expect_reject comma-port-bypass verify "$TMP/status-comma"

cp "$TMP/status-good" "$TMP/status-range"
printf '%s\n' '[ 9] 80:443/tcp ALLOW IN Anywhere' >> "$TMP/status-range"
expect_reject range-port-bypass verify "$TMP/status-range"

cat > "$TMP/status-comment-spoof" <<'EOF'
Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)
[ 1] 80/tcp ALLOW IN Anywhere # cloudflare-origin-80 173.245.48.0/20
[ 2] 80/tcp (v6) ALLOW IN Anywhere (v6) # cloudflare-origin-80 2400:cb00::/32
[ 3] 443/tcp ALLOW IN Anywhere # cloudflare-origin-443 173.245.48.0/20
[ 4] 443/tcp (v6) ALLOW IN Anywhere (v6) # cloudflare-origin-443 2400:cb00::/32
[ 5] 8443/tcp ALLOW IN Anywhere # cloudflare-origin-8443 173.245.48.0/20
[ 6] 8443/tcp (v6) ALLOW IN Anywhere (v6) # cloudflare-origin-8443 2400:cb00::/32
[ 7] 65002/tcp ALLOW IN Anywhere
[ 8] 65002/tcp (v6) ALLOW IN Anywhere (v6)
EOF
expect_reject comment-spoofed-source-bypass verify "$TMP/status-comment-spoof"

sed '/65002\/tcp ALLOW/d' "$TMP/status-good" > "$TMP/status-missing-ssh-v4"
expect_reject missing-ssh-ipv4-recovery verify "$TMP/status-missing-ssh-v4"
sed '/65002\/tcp (v6)/d' "$TMP/status-good" > "$TMP/status-missing-ssh-v6"
expect_reject missing-ssh-ipv6-recovery verify "$TMP/status-missing-ssh-v6"

cat > "$TMP/status-authoritative-false-green" <<'EOF'
Status: active
Default: allow (incoming), allow (outgoing), disabled (routed)
[ 1] 80/tcp ALLOW IN 173.245.48.0/20 # cloudflare-origin-80
# [ 2] 80/tcp (v6) ALLOW IN 2400:cb00::/32 # cloudflare-origin-80
EOF
expect_reject authoritative-default-allow-comment-only-v6-no-ssh verify "$TMP/status-authoritative-false-green"

printf '%s\n' '# 2400:cb00::/32' > "$TMP/comment-only-v6"
expect_reject comment-only-ipv6-cidr sh "$SCRIPT_DIR/cloudflare-origin-lock-ufw.sh" --verify \
  --compose-json "$TMP/compose.json" --ipv4-file "$TMP/ips-v4" --ipv6-file "$TMP/comment-only-v6" \
  --receipt-file "$TMP/receipt.json" --ssh-port "$SSH_PORT" --status-file "$TMP/status-good"

printf '%s\n' '999.245.48.0/20' > "$TMP/malformed-v4"
expect_reject malformed-ipv4-octet sh "$SCRIPT_DIR/cloudflare-origin-lock-ufw.sh" --verify \
  --compose-json "$TMP/compose.json" --ipv4-file "$TMP/malformed-v4" --ipv6-file "$TMP/ips-v6" \
  --receipt-file "$TMP/receipt.json" --ssh-port "$SSH_PORT" --status-file "$TMP/status-good"

printf '%s\n' '173.245.48.0/99' > "$TMP/malformed-prefix-v4"
expect_reject malformed-ipv4-prefix sh "$SCRIPT_DIR/cloudflare-origin-lock-ufw.sh" --verify \
  --compose-json "$TMP/compose.json" --ipv4-file "$TMP/malformed-prefix-v4" --ipv6-file "$TMP/ips-v6" \
  --receipt-file "$TMP/receipt.json" --ssh-port "$SSH_PORT" --status-file "$TMP/status-good"

printf '%s\n' '173.245.48.0/20' '173.245.48.0/21' > "$TMP/overlap-v4"
expect_reject overlapping-ipv4-cidrs sh "$SCRIPT_DIR/cloudflare-origin-lock-ufw.sh" --verify \
  --compose-json "$TMP/compose.json" --ipv4-file "$TMP/overlap-v4" --ipv6-file "$TMP/ips-v6" \
  --receipt-file "$TMP/receipt.json" --ssh-port "$SSH_PORT" --status-file "$TMP/status-good"

python3 "$SCRIPT_DIR/cloudflare-origin-lock-policy.py" create \
  --ipv4 "$TMP/ips-v4" --ipv6 "$TMP/ips-v6" --ports '80 443 8443' --ssh-port "$SSH_PORT" \
  --fetched-at '2000-01-01T00:00:00Z' --receipt "$TMP/stale-receipt.json"
expect_reject stale-cidr-receipt sh "$SCRIPT_DIR/cloudflare-origin-lock-ufw.sh" --verify \
  --compose-json "$TMP/compose.json" --ipv4-file "$TMP/ips-v4" --ipv6-file "$TMP/ips-v6" \
  --receipt-file "$TMP/stale-receipt.json" --ssh-port "$SSH_PORT" --status-file "$TMP/status-good"

jq '.ipv4Sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' \
  "$TMP/receipt.json" > "$TMP/wrong-hash-receipt.json"
expect_reject mismatched-cidr-receipt-hash sh "$SCRIPT_DIR/cloudflare-origin-lock-ufw.sh" --verify \
  --compose-json "$TMP/compose.json" --ipv4-file "$TMP/ips-v4" --ipv6-file "$TMP/ips-v6" \
  --receipt-file "$TMP/wrong-hash-receipt.json" --ssh-port "$SSH_PORT" --status-file "$TMP/status-good"

jq '.source.ipv6Url = "https://example.invalid/ips-v6"' "$TMP/receipt.json" > "$TMP/wrong-source-receipt.json"
expect_reject mismatched-cidr-receipt-source sh "$SCRIPT_DIR/cloudflare-origin-lock-ufw.sh" --verify \
  --compose-json "$TMP/compose.json" --ipv4-file "$TMP/ips-v4" --ipv6-file "$TMP/ips-v6" \
  --receipt-file "$TMP/wrong-source-receipt.json" --ssh-port "$SSH_PORT" --status-file "$TMP/status-good"

cat > "$TMP/status-before" <<'EOF'
Status: active
Default: allow (incoming), allow (outgoing), disabled (routed)
[ 1] 80/tcp ALLOW IN Anywhere
[ 2] 443/tcp ALLOW IN Anywhere
[ 3] 80/tcp ALLOW IN 203.0.113.0/24 # cloudflare-origin-80
[ 4] 65002/tcp ALLOW IN Anywhere
[ 5] 65002/tcp (v6) ALLOW IN Anywhere (v6)
EOF
cat > "$TMP/ufw" <<'SH'
#!/usr/bin/env sh
set -eu
printf '%s\n' "$*" >> "$FAKE_UFW_LOG"
if [ "$1 ${2:-}" = "status numbered" ] || [ "$1 ${2:-}" = "status verbose" ]; then
  if [ -f "$FAKE_UFW_RELOADED" ]; then
    cat "$FAKE_UFW_AFTER"
  elif [ -f "$FAKE_UFW_DELETED" ]; then
    cat "$FAKE_UFW_BEFORE_DELETED"
  else
    cat "$FAKE_UFW_BEFORE"
  fi
elif [ "$1 ${2:-}" = "--force delete" ] && [ "$3" != allow ]; then
  : > "$FAKE_UFW_DELETED"
elif [ "$1" = reload ]; then
  : > "$FAKE_UFW_RELOADED"
fi
SH
chmod 700 "$TMP/ufw"
sed '/cloudflare-origin-/d' "$TMP/status-before" > "$TMP/status-before-deleted"
PATH="$TMP:$PATH" PLATFORM_ORIGIN_LOCK_TEST_MODE=1 \
FAKE_UFW_LOG="$TMP/ufw.log" FAKE_UFW_RELOADED="$TMP/reloaded" \
FAKE_UFW_DELETED="$TMP/deleted" FAKE_UFW_BEFORE_DELETED="$TMP/status-before-deleted" \
FAKE_UFW_BEFORE="$TMP/status-before" FAKE_UFW_AFTER="$TMP/status-good" \
  sh "$SCRIPT_DIR/cloudflare-origin-lock-ufw.sh" --apply --compose-json "$TMP/compose.json" \
    --ipv4-file "$TMP/ips-v4" --ipv6-file "$TMP/ips-v6" --receipt-file "$TMP/receipt.json" \
    --ssh-port "$SSH_PORT" --state-dir "$TMP/state" --machine-id-file "$TMP/machine-id" >/dev/null
grep -Fx -- '--force delete 3' "$TMP/ufw.log" >/dev/null
grep -F 'allow proto tcp from 173.245.48.0/20 to any port 80 comment cloudflare-origin-80' "$TMP/ufw.log" >/dev/null
grep -Fx -- '--force delete allow 80/tcp' "$TMP/ufw.log" >/dev/null
grep -Fx 'default deny incoming' "$TMP/ufw.log" >/dev/null
grep -Fx 'reload' "$TMP/ufw.log" >/dev/null
cmp "$TMP/ips-v4" "$TMP/state/ips-v4"
cmp "$TMP/ips-v6" "$TMP/state/ips-v6"
cmp "$TMP/receipt.json" "$TMP/state/cidr-receipt.json"
pass reconcile-removes-stale-generic-and-enforces-default-deny
[ "$(tr '\n' ' ' < "$TMP/state/ports" | awk '{$1=$1; print}')" = "80 443 8443" ]
pass ports-derived-from-wildcard-and-specific-public-bindings
jq -e '
  .version == 1 and
  .kind == "platform-cloudflare-origin-lock-effective-verification/v1" and
  .status == "passed" and .result == "passed" and
  .verifierVersion == "cloudflare-origin-lock-ufw/v2" and
  .addressFamilies == ["ipv4", "ipv6"] and
  .publicTcpPorts == [80, 443, 8443] and
  .sshPort == 65002 and
  .defaultIncoming == "deny" and
  (.host.hostname | type == "string" and length > 0) and
  (.host.machineIdSha256 | test("^[a-f0-9]{64}$")) and
  (.effectiveRulesetSha256 | test("^[a-f0-9]{64}$")) and
  (.cidrReceiptSha256 | test("^[a-f0-9]{64}$")) and
  (.cidrRulesetDigest | test("^[a-f0-9]{64}$"))
' "$TMP/state/effective-verification.json" >/dev/null
pass effective-receipt-binds-host-families-version-result-and-digests
sh "$SCRIPT_DIR/cloudflare-origin-lock-ufw.sh" --verify --compose-json "$TMP/compose.json" \
  --state-dir "$TMP/state" --ssh-port "$SSH_PORT" --status-file "$TMP/status-good" \
  --machine-id-file "$TMP/machine-id" >/dev/null
pass saved-receipt-binds-verified-state

cp "$TMP/state/effective-verification.json" "$TMP/effective-verification.good.json"
jq '.effectiveRulesetSha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' \
  "$TMP/effective-verification.good.json" > "$TMP/state/effective-verification.json"
expect_reject effective-ruleset-receipt-drift sh "$SCRIPT_DIR/cloudflare-origin-lock-ufw.sh" --verify \
  --compose-json "$TMP/compose.json" --state-dir "$TMP/state" --ssh-port "$SSH_PORT" \
  --status-file "$TMP/status-good" --machine-id-file "$TMP/machine-id"
cp "$TMP/effective-verification.good.json" "$TMP/state/effective-verification.json"
printf '%s\n' 'different-machine-id' > "$TMP/different-machine-id"
expect_reject effective-receipt-host-replay sh "$SCRIPT_DIR/cloudflare-origin-lock-ufw.sh" --verify \
  --compose-json "$TMP/compose.json" --state-dir "$TMP/state" --ssh-port "$SSH_PORT" \
  --status-file "$TMP/status-good" --machine-id-file "$TMP/different-machine-id"

sed '/65002\/tcp (v6)/d' "$TMP/status-before" > "$TMP/status-before-unsafe"
rm -f "$TMP/reloaded" "$TMP/deleted" "$TMP/unsafe-ufw.log"
expect_reject apply-refuses-before-missing-ssh-recovery env PATH="$TMP:$PATH" PLATFORM_ORIGIN_LOCK_TEST_MODE=1 \
  FAKE_UFW_LOG="$TMP/unsafe-ufw.log" FAKE_UFW_RELOADED="$TMP/reloaded" \
  FAKE_UFW_DELETED="$TMP/deleted" FAKE_UFW_BEFORE_DELETED="$TMP/status-before-deleted" \
  FAKE_UFW_BEFORE="$TMP/status-before-unsafe" FAKE_UFW_AFTER="$TMP/status-good" \
  sh "$SCRIPT_DIR/cloudflare-origin-lock-ufw.sh" --apply --compose-json "$TMP/compose.json" \
    --ipv4-file "$TMP/ips-v4" --ipv6-file "$TMP/ips-v6" --receipt-file "$TMP/receipt.json" \
    --ssh-port "$SSH_PORT" --state-dir "$TMP/unsafe-state" --machine-id-file "$TMP/machine-id"
if grep -Eq '^(--force delete|allow |default |reload)' "$TMP/unsafe-ufw.log"; then
  echo "FAIL: unsafe recovery preflight mutated UFW" >&2
  exit 1
fi
pass missing-recovery-preflight-is-non-mutating

if grep -E 'ufw allow (80|443)/tcp' "$SCRIPT_DIR/vps-hardening-ubuntu.sh" >/dev/null; then
  echo "FAIL: hardening still opens generic web ports" >&2
  exit 1
fi
pass hardening-does-not-open-web-bypass
printf 'Cloudflare origin lock tests passed %s/%s\n' "$PASS_COUNT" "$PASS_COUNT"
