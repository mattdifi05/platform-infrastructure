#!/usr/bin/env sh
set -eu

MODE=plan
PORTS=""
COMPOSE_JSON=""
IPV4_FILE=""
IPV6_FILE=""
STATUS_FILE=""
RECEIPT_FILE=""
SSH_PORT=""
MAX_CIDR_AGE_SECONDS=604800
EXPLICIT_CIDR_INPUT=0
TEST_MODE=${PLATFORM_ORIGIN_LOCK_TEST_MODE:-0}
STATE_DIR=/etc/platform/origin-lock
STATE_DIR_OVERRIDE=0
MAX_AGE_OVERRIDE=0
HOST_ID_FILE=/etc/machine-id
HOST_ID_OVERRIDE=0
[ "${ORIGIN_LOCK_STATE_DIR+x}" = x ] && { STATE_DIR=${ORIGIN_LOCK_STATE_DIR}; STATE_DIR_OVERRIDE=1; }
[ "${ORIGIN_LOCK_HOST_ID_FILE+x}" = x ] && { HOST_ID_FILE=${ORIGIN_LOCK_HOST_ID_FILE}; HOST_ID_OVERRIDE=1; }
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

usage() {
  cat <<'EOF'
Usage: cloudflare-origin-lock-ufw.sh [--apply|--verify] --compose-json FILE
       --ssh-port PORT [--ipv4-file FILE --ipv6-file FILE --receipt-file FILE]
       [--state-dir DIR] [--status-file FILE] [--max-cidr-age-seconds N]

--apply reconciles the managed Cloudflare rules, removes generic public web
allows, verifies the resulting ruleset, and only then updates the local CIDR
state. --verify is non-mutating and fails closed against the saved/explicit
CIDR set. The default plan mode prints the intended operations.
Public TCP ports are derived from the rendered Compose JSON. --ports is
available only to the isolated test harness. State/status/age/host path
overrides are also test-only; production uses canonical root-owned state.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --apply|--verify) MODE=${1#--} ;;
    --ports) shift; PORTS=${1:?Missing value for --ports} ;;
    --compose-json) shift; COMPOSE_JSON=${1:?Missing value for --compose-json} ;;
    --ipv4-file) shift; IPV4_FILE=${1:?Missing value for --ipv4-file}; EXPLICIT_CIDR_INPUT=1 ;;
    --ipv6-file) shift; IPV6_FILE=${1:?Missing value for --ipv6-file}; EXPLICIT_CIDR_INPUT=1 ;;
    --state-dir) shift; STATE_DIR=${1:?Missing value for --state-dir}; STATE_DIR_OVERRIDE=1 ;;
    --status-file) shift; STATUS_FILE=${1:?Missing value for --status-file} ;;
    --receipt-file) shift; RECEIPT_FILE=${1:?Missing value for --receipt-file}; EXPLICIT_CIDR_INPUT=1 ;;
    --ssh-port) shift; SSH_PORT=${1:?Missing value for --ssh-port} ;;
    --max-cidr-age-seconds) shift; MAX_CIDR_AGE_SECONDS=${1:?Missing value for --max-cidr-age-seconds}; MAX_AGE_OVERRIDE=1 ;;
    --machine-id-file) shift; HOST_ID_FILE=${1:?Missing value for --machine-id-file}; HOST_ID_OVERRIDE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

if [ "$TEST_MODE" != 1 ] && { [ "$STATE_DIR_OVERRIDE" -eq 1 ] || [ "$MAX_AGE_OVERRIDE" -eq 1 ] || [ "$HOST_ID_OVERRIDE" -eq 1 ] || [ -n "$STATUS_FILE" ]; }; then
  echo "State, UFW status, freshness and host-identity path overrides are test-only; production uses canonical root-owned inputs." >&2
  exit 1
fi
if [ -n "$PORTS" ] && [ "$TEST_MODE" != 1 ]; then
  echo "--ports is test-only; production origin-lock ports must come from --compose-json or saved verified state." >&2
  exit 1
fi
if [ "$EXPLICIT_CIDR_INPUT" -eq 1 ] && [ "$TEST_MODE" != 1 ]; then
  echo "Explicit CIDR/receipt inputs are test-only; production must fetch the exact HTTPS sources on apply or consume saved verified state." >&2
  exit 1
fi

require_root_owned_state() {
  [ "$TEST_MODE" = 1 ] && return 0
  [ "$STATE_DIR" = /etc/platform/origin-lock ] && [ -d "$STATE_DIR" ] && [ ! -L "$STATE_DIR" ] || {
    echo "Canonical origin-lock state directory is missing or unsafe." >&2
    return 1
  }
  [ "$(stat -c %u "$STATE_DIR")" = 0 ] || { echo "Canonical origin-lock state directory is not root-owned." >&2; return 1; }
  if find "$STATE_DIR" -maxdepth 0 -perm /022 -print -quit | grep -q .; then
    echo "Canonical origin-lock state directory is group/world writable." >&2
    return 1
  fi
  for state_file in ips-v4 ips-v6 cidr-receipt.json ports effective-verification.json; do
    pathname="$STATE_DIR/$state_file"
    [ -f "$pathname" ] && [ ! -L "$pathname" ] || { echo "Canonical origin-lock state file is missing or unsafe: $state_file" >&2; return 1; }
    [ "$(stat -c %u "$pathname")" = 0 ] || { echo "Canonical origin-lock state file is not root-owned: $state_file" >&2; return 1; }
    if find "$pathname" -maxdepth 0 -perm /022 -print -quit | grep -q .; then
      echo "Canonical origin-lock state file is group/world writable: $state_file" >&2
      return 1
    fi
  done
}

if [ "$MODE" = verify ] && [ "$EXPLICIT_CIDR_INPUT" -eq 0 ]; then
  require_root_owned_state
fi
if [ -n "$COMPOSE_JSON" ]; then
  [ -r "$COMPOSE_JSON" ] || { echo "Rendered Compose JSON is missing or unreadable." >&2; exit 1; }
  PORTS=$(jq -er '
    [
      .services[]?.ports[]?
      | select(type == "object")
      | select((.protocol // "tcp") == "tcp")
      | select(
          ((.host_ip // "") | tostring) as $host
          | ($host != "127.0.0.1")
            and ($host | startswith("127.") | not)
            and ($host != "::1")
            and ($host != "[::1]")
        )
      | (.published | tonumber)
      | select(. >= 1 and . <= 65535)
    ] | unique | if length > 0 then map(tostring) | join(" ") else error("no public TCP ports") end
  ' "$COMPOSE_JSON") || { echo "Could not derive public TCP ports from rendered Compose JSON." >&2; exit 1; }
elif [ -z "$PORTS" ] && [ "$MODE" = verify ] && [ -s "$STATE_DIR/ports" ]; then
  PORTS=$(tr '\n' ' ' < "$STATE_DIR/ports" | awk '{$1=$1; print}')
elif [ -z "$PORTS" ]; then
  echo "Pass --compose-json with the current rendered Compose configuration." >&2
  exit 1
fi

for port in $PORTS; do
  case "$port" in ''|*[!0-9]*) echo "Origin lock ports must be numeric." >&2; exit 1 ;; esac
  [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || { echo "Origin lock port out of range: $port" >&2; exit 1; }
done
[ -n "$PORTS" ] || { echo "At least one origin lock port is required." >&2; exit 1; }
case "$SSH_PORT" in ''|*[!0-9]*) echo "An exact numeric SSH recovery port is required." >&2; exit 1 ;; esac
[ "$SSH_PORT" -ge 1 ] && [ "$SSH_PORT" -le 65535 ] || { echo "SSH recovery port is out of range." >&2; exit 1; }
for port in $PORTS; do [ "$port" != "$SSH_PORT" ] || { echo "SSH recovery port must differ from public application ports." >&2; exit 1; }; done
case "$MAX_CIDR_AGE_SECONDS" in ''|*[!0-9]*) echo "CIDR max age must be numeric." >&2; exit 1 ;; esac
[ "$MAX_CIDR_AGE_SECONDS" -ge 1 ] || { echo "CIDR max age must be positive." >&2; exit 1; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/origin-lock.XXXXXX")
TRANSACTION_ACTIVE=0
TRANSACTION_COMMITTED=0
ROLLBACK_RUNNING=0
LOCK_HELD=0
DELETE_SEQUENCE=0
if [ "$TEST_MODE" = 1 ]; then
  LOCK_DIR="${STATE_DIR}.apply-lock"
else
  LOCK_DIR=/run/lock/platform-origin-lock-ufw
fi

on_exit() {
  exit_status=$1
  trap - EXIT
  trap '' HUP INT TERM
  if [ "$TRANSACTION_ACTIVE" -eq 1 ] && [ "$TRANSACTION_COMMITTED" -eq 0 ] && [ "$ROLLBACK_RUNNING" -eq 0 ]; then
    [ "$exit_status" -ne 0 ] || exit_status=1
    if ! rollback_firewall; then
      exit_status=1
    fi
  fi
  if [ "$LOCK_HELD" -eq 1 ]; then
    if ! rmdir "$LOCK_DIR"; then
      echo "Origin lock transaction lock could not be released safely: $LOCK_DIR" >&2
      exit_status=1
    fi
    LOCK_HELD=0
  fi
  rm -rf "$TMP"
  exit "$exit_status"
}

on_signal() {
  exit "$1"
}

trap 'on_exit $?' EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

if [ "$TEST_MODE" = 1 ]; then
  UFW_BIN=$(command -v ufw || true)
else
  UFW_BIN=/usr/sbin/ufw
fi
if [ "$MODE" != plan ] && [ -z "$STATUS_FILE" ] && [ ! -x "$UFW_BIN" ]; then
  echo "Canonical UFW executable is unavailable: $UFW_BIN" >&2
  exit 1
fi

if [ -z "$IPV4_FILE" ] && [ -z "$IPV6_FILE" ]; then
  if [ "$MODE" = apply ]; then
    IPV4_FILE="$TMP/ips-v4"
    IPV6_FILE="$TMP/ips-v6"
    curl --fail --silent --show-error --proto '=https' --tlsv1.2 --max-redirs 0 --max-filesize 1048576 \
      https://www.cloudflare.com/ips-v4 -o "$IPV4_FILE"
    curl --fail --silent --show-error --proto '=https' --tlsv1.2 --max-redirs 0 --max-filesize 1048576 \
      https://www.cloudflare.com/ips-v6 -o "$IPV6_FILE"
    RECEIPT_FILE="$TMP/cidr-receipt.json"
    python3 "$SCRIPT_DIR/cloudflare-origin-lock-policy.py" create \
      --ipv4 "$IPV4_FILE" --ipv6 "$IPV6_FILE" --ports "$PORTS" --ssh-port "$SSH_PORT" --receipt "$RECEIPT_FILE"
  else
    IPV4_FILE="$STATE_DIR/ips-v4"
    IPV6_FILE="$STATE_DIR/ips-v6"
    RECEIPT_FILE=${RECEIPT_FILE:-$STATE_DIR/cidr-receipt.json}
  fi
elif [ -z "$IPV4_FILE" ] || [ -z "$IPV6_FILE" ]; then
  echo "Pass both --ipv4-file and --ipv6-file." >&2
  exit 1
fi
[ -n "$RECEIPT_FILE" ] || { echo "A source-bound CIDR/ruleset receipt is required with explicit test fixtures." >&2; exit 1; }
python3 "$SCRIPT_DIR/cloudflare-origin-lock-policy.py" validate \
  --ipv4 "$IPV4_FILE" --ipv6 "$IPV6_FILE" --ports "$PORTS" --ssh-port "$SSH_PORT" \
  --receipt "$RECEIPT_FILE" --max-age-seconds "$MAX_CIDR_AGE_SECONDS"

capture_status() {
  output=$1
  if [ -n "$STATUS_FILE" ]; then
    [ "$MODE" = verify ] || { echo "--status-file is only valid with --verify." >&2; exit 1; }
    cp "$STATUS_FILE" "$output"
  elif [ "$TEST_MODE" = 1 ]; then
    "$UFW_BIN" status numbered > "$output"
  elif [ "$(id -u)" -eq 0 ]; then
    "$UFW_BIN" status numbered > "$output"
  elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    sudo -n "$UFW_BIN" status numbered > "$output"
  else
    "$UFW_BIN" status numbered > "$output"
  fi
}

capture_policy() {
  output=$1
  if [ -n "$STATUS_FILE" ]; then
    cp "$STATUS_FILE" "$output"
  elif [ "$TEST_MODE" = 1 ]; then
    "$UFW_BIN" status verbose > "$output"
  elif [ "$(id -u)" -eq 0 ]; then
    "$UFW_BIN" status verbose > "$output"
  elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    sudo -n "$UFW_BIN" status verbose > "$output"
  else
    "$UFW_BIN" status verbose > "$output"
  fi
}

acquire_transaction_lock() {
  if ! (umask 077 && mkdir "$LOCK_DIR") 2>/dev/null; then
    echo "Origin lock apply refused: another origin lock apply owns the transaction lock." >&2
    return 1
  fi
  LOCK_HELD=1
}

snapshot_boundary_status() {
  status=$1
  owned_output=$2
  ssh_output=$3
  nonowned_output=$4
  : > "$owned_output"
  : > "$ssh_output"
  : > "$nonowned_output"
  if ! awk -v owned="$owned_output" -v ssh_rules="$ssh_output" -v nonowned="$nonowned_output" -v ssh_port="$SSH_PORT" '
    /^[[:space:]]*\[[[:space:]]*[0-9]+\]/ {
      raw=$0
      line=$0
      sub(/^[[:space:]]*\[[[:space:]]*/, "", line)
      number=line
      sub(/\].*$/, "", number)
      gsub(/[[:space:]]/, "", number)
      sub(/^[^]]*\][[:space:]]*/, "", line)
      sub(/[[:space:]]+$/, "", line)

      comment=""
      hash=index(line, "#")
      body=line
      if (hash) {
        comment=substr(line, hash + 1)
        sub(/^[[:space:]]+/, "", comment)
        sub(/[[:space:]]+$/, "", comment)
        body=substr(line, 1, hash - 1)
      }
      count=split(body, fields, /[[:space:]]+/)
      allow=0
      for (i=1; i<=count; i++) if (fields[i] == "ALLOW") { allow=i; break }
      if (!allow) {
        if (index(raw, "cloudflare-origin-")) exit 42
        print line > nonowned
        next
      }
      target=fields[1]
      for (i=2; i<allow; i++) target=target " " fields[i]
      direction=fields[allow + 1]
      source=fields[allow + 2]
      numeric_target=target
      sub(/ \(v6\)$/, "", numeric_target)

      if (comment ~ /^cloudflare-origin-[0-9]+$/) {
        port=comment
        sub(/^cloudflare-origin-/, "", port)
        if (number !~ /^[0-9]+$/ || port !~ /^[0-9]+$/ ||
            (port + 0) < 1 || (port + 0) > 65535 || numeric_target != port "/tcp" ||
            direction != "IN" ||
            source !~ /^([0-9.]+|[0-9A-Fa-f:]+)\/[0-9]+$/ ||
            ((index(source, ":") > 0) != (target ~ / \(v6\)$/))) exit 42
        print number "|" port "|" source "|" comment > owned
        next
      }
      if (index(raw, "cloudflare-origin-")) exit 42
      if (numeric_target == ssh_port "/tcp" && direction == "IN" && source == "Anywhere") {
        print target "|" direction "|" source "|" comment > ssh_rules
      }
      print line > nonowned
    }
  ' "$status"; then
    echo "Origin lock apply refused: the current managed UFW rules cannot be snapshotted exactly." >&2
    return 1
  fi
}

status_has_generic_public_allow() {
  status=$1
  requested_port=$2
  sed -E 's/^[[:space:]]*\[[[:space:]]*[0-9]+\][[:space:]]*//' "$status" \
    | awk -v requested="${requested_port}/tcp" '
      {
        comment=""
        hash=index($0, "#")
        body=$0
        if (hash) {
          comment=substr($0, hash + 1)
          sub(/^[[:space:]]+/, "", comment)
          sub(/[[:space:]]+$/, "", comment)
          body=substr($0, 1, hash - 1)
        }
        count=split(body, fields, /[[:space:]]+/)
        allow=0
        for (i=1; i<=count; i++) if (fields[i] == "ALLOW") { allow=i; break }
        if (!allow) next
        target=fields[1]
        for (i=2; i<allow; i++) target=target " " fields[i]
        sub(/ \(v6\)$/, "", target)
        if (target == requested && fields[allow + 1] == "IN" &&
            fields[allow + 2] == "Anywhere" &&
            comment !~ /^cloudflare-origin-[0-9]+$/) found=1
      }
      END { exit !found }
    '
}

normalize_owned_snapshot() {
  input=$1
  output=$2
  awk -F '|' '{ print $2 "|" $3 "|" $4 }' "$input" | LC_ALL=C sort > "$output"
}

normalize_ssh_snapshot() {
  input=$1
  output=$2
  LC_ALL=C sort "$input" > "$output"
}

normalize_nonowned_snapshot() {
  input=$1
  output=$2
  LC_ALL=C sort "$input" > "$output"
}

verify_unique_owned_snapshot() {
  input=$1
  if ! awk -F '|' '
    {
      identity=$2 SUBSEP $3 SUBSEP $4
      if (++seen[identity] > 1) exit 1
    }
  ' "$input"; then
    echo "Origin lock apply refused: duplicate managed UFW rule semantics must be resolved before mutation." >&2
    return 1
  fi
}

normalize_non_ssh_nonowned_snapshot() {
  input=$1
  output=$2
  awk -v target4="${SSH_PORT}/tcp" -v target6="${SSH_PORT}/tcp (v6)" '
    {
      body=$0
      hash=index(body, "#")
      if (hash) body=substr(body, 1, hash - 1)
      count=split(body, fields, /[[:space:]]+/)
      allow=0
      for (i=1; i<=count; i++) if (fields[i] == "ALLOW") { allow=i; break }
      target=fields[1]
      for (i=2; i<allow; i++) target=target " " fields[i]
      if (allow && (target == target4 || target == target6) &&
          fields[allow + 1] == "IN" && fields[allow + 2] == "Anywhere") next
      print
    }
  ' "$input" | LC_ALL=C sort > "$output"
}

verify_canonical_ssh_snapshot() {
  input=$1
  {
    printf '%s|IN|Anywhere|\n' "${SSH_PORT}/tcp"
    printf '%s|IN|Anywhere|\n' "${SSH_PORT}/tcp (v6)"
  } | LC_ALL=C sort > "$TMP/canonical-ssh-expected"
  normalize_ssh_snapshot "$input" "$TMP/canonical-ssh-actual"
  if ! cmp "$TMP/canonical-ssh-expected" "$TMP/canonical-ssh-actual" >/dev/null; then
    echo "Origin lock apply refused: SSH recovery rules must be the exact canonical IPv4/IPv6 allow pair without comments." >&2
    return 1
  fi
}

delete_one_owned_rule() {
  delete_port=$1
  delete_source=$2
  delete_comment=$3
  required_nonowned=${4:-}
  DELETE_SEQUENCE=$((DELETE_SEQUENCE + 1))
  delete_prefix="$TMP/delete-owned-${DELETE_SEQUENCE}"

  if ! capture_status "${delete_prefix}.before" ||
     ! snapshot_boundary_status "${delete_prefix}.before" \
       "${delete_prefix}.owned-before" "${delete_prefix}.ssh-before" "${delete_prefix}.nonowned-before"; then
    echo "Origin lock could not capture the current rule identity before deletion." >&2
    return 1
  fi
  normalize_ssh_snapshot "${delete_prefix}.ssh-before" "${delete_prefix}.ssh-before-normalized"
  normalize_nonowned_snapshot "${delete_prefix}.nonowned-before" "${delete_prefix}.nonowned-before-normalized"

  if [ -n "$required_nonowned" ] &&
     ! cmp "$required_nonowned" "${delete_prefix}.nonowned-before-normalized" >/dev/null; then
    echo "Origin lock apply refused: non-owned UFW rules changed after the transaction snapshot." >&2
    return 1
  fi

  delete_matches=$(awk -F '|' -v port="$delete_port" -v source="$delete_source" -v comment="$delete_comment" '
    $2 == port && $3 == source && $4 == comment { count++ }
    END { print count + 0 }
  ' "${delete_prefix}.owned-before")
  [ "$delete_matches" -eq 1 ] || {
    echo "Origin lock managed-rule identity is missing or duplicated before deletion." >&2
    return 1
  }

  if ! awk -F '|' -v port="$delete_port" -v source="$delete_source" -v comment="$delete_comment" '
    $2 == port && $3 == source && $4 == comment && !removed { removed=1; next }
    { print $2 "|" $3 "|" $4 }
    END { if (!removed) exit 1 }
  ' "${delete_prefix}.owned-before" | LC_ALL=C sort > "${delete_prefix}.owned-expected"; then
    echo "Origin lock could not construct the exact managed-rule deletion expectation." >&2
    return 1
  fi

  delete_rc=0
  "$UFW_BIN" --force delete allow proto tcp from "$delete_source" to any \
    port "$delete_port" comment "$delete_comment" || delete_rc=$?

  if ! capture_status "${delete_prefix}.after" ||
     ! snapshot_boundary_status "${delete_prefix}.after" \
       "${delete_prefix}.owned-after" "${delete_prefix}.ssh-after" "${delete_prefix}.nonowned-after"; then
    echo "Origin lock could not capture the effective rule identity after deletion." >&2
    return 1
  fi
  normalize_owned_snapshot "${delete_prefix}.owned-after" "${delete_prefix}.owned-after-normalized"
  normalize_ssh_snapshot "${delete_prefix}.ssh-after" "${delete_prefix}.ssh-after-normalized"
  normalize_nonowned_snapshot "${delete_prefix}.nonowned-after" "${delete_prefix}.nonowned-after-normalized"

  delete_verified=1
  if ! cmp "${delete_prefix}.owned-expected" "${delete_prefix}.owned-after-normalized" >/dev/null; then
    echo "Origin lock managed-rule deletion verification failed: a different rule was removed." >&2
    delete_verified=0
  fi
  if ! cmp "${delete_prefix}.ssh-before-normalized" "${delete_prefix}.ssh-after-normalized" >/dev/null; then
    echo "Origin lock managed-rule deletion verification failed: SSH recovery rules changed." >&2
    delete_verified=0
  fi
  if ! cmp "${delete_prefix}.nonowned-before-normalized" "${delete_prefix}.nonowned-after-normalized" >/dev/null; then
    echo "Origin lock managed-rule deletion verification failed: non-owned UFW rules changed." >&2
    delete_verified=0
  fi
  if [ "$delete_rc" -ne 0 ]; then
    echo "Origin lock managed-rule deletion command returned an error." >&2
    delete_verified=0
  fi
  [ "$delete_verified" -eq 1 ]
}

restore_ssh_boundary() {
  if ! capture_status "$TMP/rollback-ssh-before" ||
     ! snapshot_boundary_status "$TMP/rollback-ssh-before" \
       "$TMP/rollback-ssh-owned-before" "$TMP/rollback-ssh-rules-before" "$TMP/rollback-ssh-nonowned-before"; then
    echo "Origin lock rollback could not capture the SSH recovery boundary." >&2
    return 1
  fi
  normalize_ssh_snapshot "$TMP/rollback-ssh-rules-before" "$TMP/rollback-ssh-before-normalized"
  normalize_ssh_snapshot "$TMP/prior-ssh-rules" "$TMP/prior-ssh-normalized"
  if cmp "$TMP/prior-ssh-normalized" "$TMP/rollback-ssh-before-normalized" >/dev/null; then
    return 0
  fi

  normalize_non_ssh_nonowned_snapshot "$TMP/rollback-ssh-nonowned-before" "$TMP/rollback-non-ssh-before-normalized"
  if ! "$UFW_BIN" --force delete allow "${SSH_PORT}/tcp"; then
    echo "Origin lock rollback warning: canonical SSH rule deletion returned an error; restoration verification remains authoritative." >&2
  fi
  if ! "$UFW_BIN" allow "${SSH_PORT}/tcp"; then
    echo "Origin lock rollback could not recreate the canonical SSH recovery pair." >&2
    return 1
  fi

  if ! capture_status "$TMP/rollback-ssh-after" ||
     ! snapshot_boundary_status "$TMP/rollback-ssh-after" \
       "$TMP/rollback-ssh-owned-after" "$TMP/rollback-ssh-rules-after" "$TMP/rollback-ssh-nonowned-after"; then
    echo "Origin lock rollback could not verify the recreated SSH recovery boundary." >&2
    return 1
  fi
  normalize_ssh_snapshot "$TMP/rollback-ssh-rules-after" "$TMP/rollback-ssh-after-normalized"
  normalize_non_ssh_nonowned_snapshot "$TMP/rollback-ssh-nonowned-after" "$TMP/rollback-non-ssh-after-normalized"
  if ! cmp "$TMP/prior-ssh-normalized" "$TMP/rollback-ssh-after-normalized" >/dev/null; then
    echo "Origin lock rollback could not restore the exact SSH recovery boundary." >&2
    return 1
  fi
  if ! cmp "$TMP/rollback-non-ssh-before-normalized" "$TMP/rollback-non-ssh-after-normalized" >/dev/null; then
    echo "Origin lock rollback SSH restoration changed another non-owned UFW rule." >&2
    return 1
  fi
}

rollback_firewall() {
  ROLLBACK_RUNNING=1
  echo "Origin lock apply failed; restoring the exact prior managed UFW rules." >&2
  rollback_parse_ok=1

  if ! capture_status "$TMP/rollback-current"; then
    echo "Origin lock rollback could not capture the partially applied UFW state." >&2
    rollback_parse_ok=0
  elif ! snapshot_boundary_status "$TMP/rollback-current" \
    "$TMP/rollback-current-owned" "$TMP/rollback-current-ssh" "$TMP/rollback-current-nonowned"; then
    rollback_parse_ok=0
  fi
  owned_cleanup_possible=$rollback_parse_ok

  if [ "$owned_cleanup_possible" -eq 1 ]; then
    while IFS='|' read -r _number port source comment; do
      [ -n "$port" ] || continue
      if ! delete_one_owned_rule "$port" "$source" "$comment"; then
        echo "Origin lock rollback warning: identity-checked managed rule deletion failed; exact final verification remains authoritative." >&2
      fi
    done < "$TMP/rollback-current-owned"
  fi

  if ! restore_ssh_boundary; then
    rollback_parse_ok=0
  fi
  if [ "$owned_cleanup_possible" -eq 1 ]; then
    while IFS='|' read -r _number port source comment; do
      [ -n "$port" ] || continue
      if ! "$UFW_BIN" allow proto tcp from "$source" to any port "$port" comment "$comment"; then
        echo "Origin lock rollback warning: prior managed rule restoration returned an error; exact final verification remains authoritative." >&2
      fi
    done < "$TMP/prior-owned-rules"
  fi

  if ! "$UFW_BIN" default deny incoming; then
    echo "Origin lock rollback could not enforce default-deny incoming policy." >&2
    rollback_parse_ok=0
  fi
  if ! "$UFW_BIN" reload; then
    echo "Origin lock rollback could not reload UFW." >&2
    rollback_parse_ok=0
  fi

  rollback_verified=1
  if [ "$rollback_parse_ok" -ne 1 ]; then
    rollback_verified=0
  fi
  if ! capture_status "$TMP/rollback-restored" || ! capture_policy "$TMP/rollback-policy"; then
    echo "Origin lock rollback verification could not capture effective UFW state." >&2
    rollback_verified=0
  elif ! snapshot_boundary_status "$TMP/rollback-restored" \
    "$TMP/rollback-restored-owned" "$TMP/rollback-restored-ssh" "$TMP/rollback-restored-nonowned"; then
    rollback_verified=0
  else
    normalize_owned_snapshot "$TMP/prior-owned-rules" "$TMP/prior-owned-normalized"
    normalize_owned_snapshot "$TMP/rollback-restored-owned" "$TMP/rollback-restored-owned-normalized"
    normalize_ssh_snapshot "$TMP/prior-ssh-rules" "$TMP/prior-ssh-normalized"
    normalize_ssh_snapshot "$TMP/rollback-restored-ssh" "$TMP/rollback-restored-ssh-normalized"
    if ! cmp "$TMP/prior-owned-normalized" "$TMP/rollback-restored-owned-normalized" >/dev/null; then
      echo "Origin lock rollback verification failed: prior managed rules were not restored exactly." >&2
      rollback_verified=0
    fi
    if ! cmp "$TMP/prior-ssh-normalized" "$TMP/rollback-restored-ssh-normalized" >/dev/null; then
      echo "Origin lock rollback verification failed: SSH recovery rules changed." >&2
      rollback_verified=0
    fi
    if ! verify_recovery_before_mutation "$TMP/rollback-restored"; then
      rollback_verified=0
    fi
    if ! grep -qi '^Status: active' "$TMP/rollback-restored" ||
       ! grep -Eqi '^Default:[[:space:]]+deny[[:space:]]+\(incoming\)' "$TMP/rollback-policy"; then
      echo "Origin lock rollback verification failed: UFW is not active with default-deny incoming policy." >&2
      rollback_verified=0
    fi
  fi

  ROLLBACK_RUNNING=0
  if [ "$rollback_verified" -eq 1 ]; then
    echo "Origin lock rollback verified: exact prior managed rules and SSH recovery rules restored with default-deny incoming." >&2
    return 0
  fi
  echo "CRITICAL: origin lock rollback could not be verified; keep deployment blocked and use an independent recovery channel." >&2
  return 1
}

verify_status() {
  status=$1
  policy=$2
  grep -qi '^Status: active' "$status" || { echo "Origin lock verification failed: UFW is not active." >&2; return 1; }
  grep -Eqi '^Default:[[:space:]]+deny[[:space:]]+\(incoming\)' "$policy" || {
    echo "Origin lock verification failed: UFW default incoming policy is not deny." >&2
    return 1
  }
  expected=0
  normalized="$TMP/status-normalized"
  sed -E 's/^[[:space:]]*\[[[:space:]]*[0-9]+\][[:space:]]*//' "$status" > "$normalized"
  parsed="$TMP/status-parsed"
  awk '
    {
      comment=""
      hash=index($0, "#")
      body=$0
      if (hash) {
        comment=substr($0, hash + 1)
        sub(/^[[:space:]]+/, "", comment)
        sub(/[[:space:]]+$/, "", comment)
        body=substr($0, 1, hash - 1)
      }
      count=split(body, fields, /[[:space:]]+/)
      allow=0
      for (i=1; i<=count; i++) if (fields[i] == "ALLOW") { allow=i; break }
      if (!allow) next
      target=fields[1]
      for (i=2; i<allow; i++) target=target " " fields[i]
      direction=fields[allow + 1]
      source=fields[allow + 2]
      print target "|" direction "|" source "|" comment
    }
  ' "$normalized" > "$parsed"
  managed=0
  ssh_v4=0
  ssh_v6=0
  while IFS='|' read -r target direction source comment; do
    [ "$direction" = IN ] && [ -n "$source" ] || {
      echo "Origin lock verification failed: unrecognized ALLOW rule direction/source for target: $target" >&2
      return 1
    }
    numeric_target=${target% (v6)}
    if printf '%s\n' "$comment" | grep -Eq '^cloudflare-origin-[0-9]+$'; then
      managed_port=${comment#cloudflare-origin-}
      [ "$numeric_target" = "${managed_port}/tcp" ] || {
        echo "Origin lock verification failed: managed comment does not match rule target: $target" >&2
        return 1
      }
      approved_port=0
      for port in $PORTS; do [ "$managed_port" = "$port" ] && approved_port=1; done
      [ "$approved_port" -eq 1 ] || {
        echo "Origin lock verification failed: stale managed port remains: $managed_port" >&2
        return 1
      }
      if ! grep -Fqx -- "$source" "$IPV4_FILE" && ! grep -Fqx -- "$source" "$IPV6_FILE"; then
        echo "Origin lock verification failed: managed rule source is not an approved Cloudflare CIDR: $source" >&2
        return 1
      fi
      managed=$((managed + 1))
      continue
    fi
    if [ "$numeric_target" = "${SSH_PORT}/tcp" ] && [ "$source" = Anywhere ]; then
      case "$target" in
        *' (v6)') ssh_v6=$((ssh_v6 + 1)) ;;
        *) ssh_v4=$((ssh_v4 + 1)) ;;
      esac
      continue
    fi
    echo "Origin lock verification failed: unexpected unmanaged inbound allow remains: $target from $source" >&2
    return 1
  done < "$parsed"
  for port in $PORTS; do
    family=4
    for file in "$IPV4_FILE" "$IPV6_FILE"; do
      while IFS= read -r cidr; do
        case "$cidr" in ''|'#'*) continue ;; esac
        expected=$((expected + 1))
        matches=$(awk -F '|' -v p="$port" -v c="$cidr" -v family="$family" '
          (((family == 4) && $1 == p "/tcp") || ((family == 6) && $1 == p "/tcp (v6)")) && $2 == "IN" && $3 == c && $4 == "cloudflare-origin-" p { count++ }
          END { print count + 0 }
        ' "$parsed")
        [ "$matches" -eq 1 ] || { echo "Origin lock verification failed: expected one exact ${cidr} -> ${port}/tcp rule, found $matches." >&2; return 1; }
      done < "$file"
      family=6
    done
  done
  [ "$managed" -eq "$expected" ] || { echo "Origin lock verification failed: expected $expected managed rules, found $managed (duplicate or stale rules)." >&2; return 1; }
  [ "$ssh_v4" -eq 1 ] && [ "$ssh_v6" -eq 1 ] || {
    echo "Origin lock verification failed: expected one IPv4 and one IPv6 SSH recovery allow for ${SSH_PORT}/tcp." >&2
    return 1
  }
  {
    printf '%s\n' 'status=active' 'defaultIncoming=deny'
    LC_ALL=C sort "$parsed"
  } > "$TMP/effective-rules"
  return 0
}

create_effective_receipt() {
  output=$1
  cidr_receipt=$2
  python3 "$SCRIPT_DIR/cloudflare-origin-lock-effective-policy.py" create \
    --effective-rules "$TMP/effective-rules" \
    --cidr-receipt "$cidr_receipt" \
    --ports "$PORTS" \
    --ssh-port "$SSH_PORT" \
    --machine-id "$HOST_ID_FILE" \
    --receipt "$output"
}

validate_effective_receipt() {
  receipt=$1
  cidr_receipt=$2
  python3 "$SCRIPT_DIR/cloudflare-origin-lock-effective-policy.py" validate \
    --effective-rules "$TMP/effective-rules" \
    --cidr-receipt "$cidr_receipt" \
    --ports "$PORTS" \
    --ssh-port "$SSH_PORT" \
    --machine-id "$HOST_ID_FILE" \
    --receipt "$receipt" \
    --max-age-seconds "$MAX_CIDR_AGE_SECONDS"
}

verify_recovery_before_mutation() {
  status=$1
  normalized="$TMP/recovery-status-normalized"
  sed -E 's/^[[:space:]]*\[[[:space:]]*[0-9]+\][[:space:]]*//' "$status" > "$normalized"
  counts=$(awk -v target4="${SSH_PORT}/tcp" -v target6="${SSH_PORT}/tcp (v6)" '
    {
      hash=index($0, "#")
      body=(hash ? substr($0, 1, hash - 1) : $0)
      count=split(body, fields, /[[:space:]]+/)
      allow=0
      for (i=1; i<=count; i++) if (fields[i] == "ALLOW") { allow=i; break }
      if (!allow || fields[allow + 1] != "IN" || fields[allow + 2] != "Anywhere") next
      target=fields[1]
      for (i=2; i<allow; i++) target=target " " fields[i]
      if (target == target4) ipv4++
      if (target == target6) ipv6++
    }
    END { print ipv4 + 0, ipv6 + 0 }
  ' "$normalized")
  [ "$counts" = "1 1" ] || {
    echo "Origin lock apply refused: preserve exactly one IPv4 and one IPv6 SSH recovery allow for ${SSH_PORT}/tcp before changing the default policy." >&2
    return 1
  }
}

if [ "$MODE" = verify ]; then
  capture_status "$TMP/status"
  capture_policy "$TMP/policy"
  verify_status "$TMP/status" "$TMP/policy"
  if [ "$EXPLICIT_CIDR_INPUT" -eq 0 ]; then
    validate_effective_receipt "$STATE_DIR/effective-verification.json" "$STATE_DIR/cidr-receipt.json"
  fi
  echo "Cloudflare origin lock verified for ports: $PORTS"
  exit 0
fi

if [ "$MODE" = plan ]; then
  echo "PLAN: replace all managed cloudflare-origin-* UFW rules with the supplied IPv4/IPv6 CIDRs"
  for port in $PORTS; do echo "PLAN: remove generic public allow ${port}/tcp"; done
  echo "PLAN: reload and fail-closed verify before updating $STATE_DIR"
  exit 0
fi

if [ "$(id -u)" -ne 0 ] && [ "$TEST_MODE" != 1 ]; then
  echo "Run --apply as root." >&2
  exit 1
fi

acquire_transaction_lock
capture_status "$TMP/before"
verify_recovery_before_mutation "$TMP/before"
snapshot_boundary_status "$TMP/before" \
  "$TMP/prior-owned-rules" "$TMP/prior-ssh-rules" "$TMP/prior-nonowned-rules"
verify_unique_owned_snapshot "$TMP/prior-owned-rules"
verify_canonical_ssh_snapshot "$TMP/prior-ssh-rules"
normalize_nonowned_snapshot "$TMP/prior-nonowned-rules" "$TMP/prior-nonowned-normalized"
TRANSACTION_ACTIVE=1
while IFS='|' read -r _number port source comment; do
  [ -n "$port" ] || continue
  delete_one_owned_rule "$port" "$source" "$comment" "$TMP/prior-nonowned-normalized"
done < "$TMP/prior-owned-rules"

for port in $PORTS; do
  for file in "$IPV4_FILE" "$IPV6_FILE"; do
    while IFS= read -r cidr; do
      case "$cidr" in ''|'#'*) continue ;; esac
      "$UFW_BIN" allow proto tcp from "$cidr" to any port "$port" comment "cloudflare-origin-${port}"
    done < "$file"
  done
  if status_has_generic_public_allow "$TMP/before" "$port"; then
    "$UFW_BIN" --force delete allow "${port}/tcp"
  fi
done
"$UFW_BIN" default deny incoming
"$UFW_BIN" reload
capture_status "$TMP/after"
capture_policy "$TMP/policy-after"
verify_status "$TMP/after" "$TMP/policy-after"

if [ "$TEST_MODE" = 1 ]; then
  install -d -m 0755 "$STATE_DIR"
  install -m 0644 "$IPV4_FILE" "$STATE_DIR/ips-v4"
  install -m 0644 "$IPV6_FILE" "$STATE_DIR/ips-v6"
  install -m 0644 "$RECEIPT_FILE" "$STATE_DIR/cidr-receipt.json"
  printf '%s\n' $PORTS > "$STATE_DIR/ports"
  chmod 0644 "$STATE_DIR/ports"
  create_effective_receipt "$TMP/effective-verification.json" "$STATE_DIR/cidr-receipt.json"
  install -m 0644 "$TMP/effective-verification.json" "$STATE_DIR/effective-verification.json"
else
  install -d -o root -g root -m 0755 "$STATE_DIR"
  install -o root -g root -m 0644 "$IPV4_FILE" "$STATE_DIR/ips-v4"
  install -o root -g root -m 0644 "$IPV6_FILE" "$STATE_DIR/ips-v6"
  install -o root -g root -m 0644 "$RECEIPT_FILE" "$STATE_DIR/cidr-receipt.json"
  printf '%s\n' $PORTS > "$TMP/ports"
  install -o root -g root -m 0644 "$TMP/ports" "$STATE_DIR/ports"
  create_effective_receipt "$TMP/effective-verification.json" "$STATE_DIR/cidr-receipt.json"
  install -o root -g root -m 0644 "$TMP/effective-verification.json" "$STATE_DIR/effective-verification.json"
  require_root_owned_state
fi
TRANSACTION_COMMITTED=1
TRANSACTION_ACTIVE=0
echo "Cloudflare origin lock reconciled and verified for ports: $PORTS"
