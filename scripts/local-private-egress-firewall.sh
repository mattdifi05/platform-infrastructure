#!/usr/bin/env sh
set -eu
umask 077

MODE=check
CONFIRM=
MANIFEST=/etc/platform-infrastructure/local-private-egress.manifest.json
TABLE=platform_local_private_egress
LOCK_FILE=/run/lock/platform-local-private-egress.lock
NFT_BIN=/usr/sbin/nft

usage() {
  cat <<'EOF'
Usage: local-private-egress-firewall.sh [--check|--kernel-roundtrip|--apply|--verify] [--manifest ABSOLUTE_PATH] [--confirm TOKEN]

check is the default and performs no firewall mutation. apply requires root and
--confirm APPLY-LOCAL-PRIVATE-EGRESS. The helper owns only the dedicated
inet/platform_local_private_egress table and never flushes a ruleset or edits a
Docker/UFW table.

kernel-roundtrip creates a temporary Linux network namespace and performs the
real nft apply/list/normalized-hash verification only inside that namespace.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --check) MODE=check ;;
    --kernel-roundtrip) MODE=kernel-roundtrip ;;
    --apply) MODE=apply ;;
    --verify) MODE=verify ;;
    --manifest)
      shift
      MANIFEST=${1:?Missing value for --manifest}
      ;;
    --confirm)
      shift
      CONFIRM=${1:?Missing value for --confirm}
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

require_command() {
  command -v "$1" >/dev/null 2>&1 || { echo "$1 command not found" >&2; exit 1; }
}

case "$MANIFEST" in
  /*) ;;
  *) echo "--manifest must be an absolute path" >&2; exit 2 ;;
esac
case "$MANIFEST" in
  *[!A-Za-z0-9_./-]*|*//*|*/../*|*/..) echo "Invalid --manifest path" >&2; exit 2 ;;
esac

[ "$(id -u)" -eq 0 ] || { echo "Local-private egress firewall operations require root" >&2; exit 1; }
for command_name in "$NFT_BIN" jq sha256sum flock mktemp stat readlink find sed tr; do
  require_command "$command_name"
done

if [ "$MODE" = kernel-roundtrip ]; then
  require_command unshare
  SCRIPT_PATH=$(readlink -f -- "$0")
  exec unshare --net -- "$SCRIPT_PATH" --apply --manifest "$MANIFEST" --confirm APPLY-LOCAL-PRIVATE-EGRESS
fi

assert_root_owned_path() {
  target=$1
  [ -e "$target" ] && [ ! -L "$target" ] || { echo "Manifest path is missing or symbolic" >&2; exit 1; }
  resolved=$(readlink -f -- "$target")
  [ "$resolved" = "$target" ] || { echo "Manifest path is not canonical" >&2; exit 1; }
  current=$target
  while :; do
    [ "$(stat -c '%u' -- "$current")" -eq 0 ] || { echo "Manifest path is not root-owned: $current" >&2; exit 1; }
    [ -z "$(find "$current" -maxdepth 0 -perm /022 -print -quit)" ] \
      || { echo "Manifest path is group/world writable: $current" >&2; exit 1; }
    [ "$current" = / ] && break
    current=$(dirname -- "$current")
  done
  [ -f "$target" ] && [ "$(stat -c '%h' -- "$target")" -eq 1 ] \
    || { echo "Manifest must be one regular single-link file" >&2; exit 1; }
}

assert_root_owned_path "$MANIFEST"

temporary=$(mktemp -d /run/local-private-egress.XXXXXX)
chmod 0700 "$temporary"
cleanup() {
  rm -f "$temporary/program.nft" "$temporary/transaction.nft" "$temporary/current.nft"
  rmdir "$temporary" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

exec 9>"$LOCK_FILE"
flock -x 9

jq -e --arg table "$TABLE" '
  type == "object"
  and ((keys | sort) == ["applications", "binding", "integrity", "nftables", "policy", "schema", "status"])
  and .schema == "platform.local-private-app-egress-manifest/v1"
  and .status == "admitted"
  and (.applications | type == "array" and length > 0)
  and all(.applications[];
    ((keys | sort) == ["admittedFromState", "allowedConsumers", "network", "owner", "requiredInternalNetworks", "runtimeNetworkId"])
    and .admittedFromState == "proposed"
    and (.owner | type == "string" and test("^[a-z][a-z0-9-]{0,60}$"))
    and (.allowedConsumers | type == "array" and length > 0 and . == (unique | sort))
    and (.requiredInternalNetworks | type == "object")
    and ((.requiredInternalNetworks | keys | sort) == .allowedConsumers)
    and all(.requiredInternalNetworks[];
      type == "array"
      and . == (unique | sort)
      and all(.[]; type == "string" and test("^[a-z][a-z0-9_-]{0,127}$")))
    and (.runtimeNetworkId == null or (.runtimeNetworkId | test("^[a-f0-9]{64}$")))
    and (.network.bridgeName | type == "string" and test("^[a-z][a-z0-9-]{0,14}$"))
    and (.network.subnet | type == "string" and test("^([0-9]{1,3}\\.){3}[0-9]{1,3}/28$")))
  and .binding.dockerHost == "unix:///var/run/docker.sock"
  and (.binding.daemonId | type == "string" and length >= 3)
  and (.binding.renderSha256 | test("^[a-f0-9]{64}$"))
  and (.binding.runtimeInventorySha256 | test("^[a-f0-9]{64}$"))
  and .nftables.family == "inet"
  and .nftables.table == $table
  and (.nftables.program | type == "string" and startswith("table inet " + $table + " {"))
  and (.nftables.program | contains("flush ruleset") | not)
  and (.nftables.program | contains("docker") | not)
  and (.nftables.programSha256 | test("^[a-f0-9]{64}$"))
  and (.nftables.normalizedSha256 | test("^[a-f0-9]{64}$"))
  and (.nftables.expectedPreimageNormalizedSha256 == null
    or (.nftables.expectedPreimageNormalizedSha256 | test("^[a-f0-9]{64}$")))
  and (.integrity.canonicalSha256 | test("^[a-f0-9]{64}$"))
' "$MANIFEST" >/dev/null || { echo "Local-private egress manifest shape is invalid" >&2; exit 1; }

claimed_integrity=$(jq -r '.integrity.canonicalSha256' "$MANIFEST")
canonical_core=$(jq -cS 'del(.integrity)' "$MANIFEST")
actual_integrity=$(printf '%s' "$canonical_core" | sha256sum | awk '{print $1}')
[ "$actual_integrity" = "$claimed_integrity" ] || { echo "Manifest integrity digest mismatch" >&2; exit 1; }

jq -j '.nftables.program' "$MANIFEST" > "$temporary/program.nft"
claimed_program=$(jq -r '.nftables.programSha256' "$MANIFEST")
actual_program=$(sha256sum "$temporary/program.nft" | awk '{print $1}')
[ "$actual_program" = "$claimed_program" ] || { echo "nftables program digest mismatch" >&2; exit 1; }

normalize_nft() {
  tr '\n\r\t' '   ' \
    | sed -E 's/[[:space:]]+/ /g; s/[[:space:]]*([{};,=])[[:space:]]*/\1/g; s/^ //; s/ $//'
}

normalized_hash() {
  normalize_nft | sha256sum | awk '{print $1}'
}

desired_hash=$(normalize_nft < "$temporary/program.nft" | sha256sum | awk '{print $1}')
claimed_normalized=$(jq -r '.nftables.normalizedSha256' "$MANIFEST")
[ "$desired_hash" = "$claimed_normalized" ] || { echo "Normalized nftables program digest mismatch" >&2; exit 1; }

table_exists=0
current_hash=
if "$NFT_BIN" -y -nn list table inet "$TABLE" > "$temporary/current.nft" 2>/dev/null; then
  table_exists=1
  current_hash=$(normalized_hash < "$temporary/current.nft")
fi

if [ "$MODE" = verify ]; then
  [ "$table_exists" -eq 1 ] && [ "$current_hash" = "$desired_hash" ] \
    || { echo "Installed local-private egress table differs from admitted manifest" >&2; exit 1; }
  echo "Local-private egress nftables table verified."
  exit 0
fi

if [ "$table_exists" -eq 1 ] && [ "$current_hash" != "$desired_hash" ]; then
  expected_preimage=$(jq -r '.nftables.expectedPreimageNormalizedSha256 // empty' "$MANIFEST")
  [ -n "$expected_preimage" ] && [ "$current_hash" = "$expected_preimage" ] \
    || { echo "Refusing to replace an unknown same-name nftables table" >&2; exit 1; }
fi

if [ "$table_exists" -eq 1 ]; then
  printf 'delete table inet %s\n' "$TABLE" > "$temporary/transaction.nft"
fi
cat "$temporary/program.nft" >> "$temporary/transaction.nft"
"$NFT_BIN" -c -f "$temporary/transaction.nft"

if [ "$MODE" = check ]; then
  echo "Local-private egress manifest and atomic nftables transaction check passed; no mutation executed."
  exit 0
fi

[ "$CONFIRM" = APPLY-LOCAL-PRIVATE-EGRESS ] \
  || { echo "--apply requires --confirm APPLY-LOCAL-PRIVATE-EGRESS" >&2; exit 1; }
if [ "$table_exists" -eq 1 ] && [ "$current_hash" = "$desired_hash" ]; then
  echo "Local-private egress nftables table already matches the admitted manifest."
  exit 0
fi

# One nft input file is one atomic netlink transaction. It deletes only the
# exact expected preimage in this helper's dedicated table and never flushes a
# ruleset or changes Docker/UFW-owned chains.
"$NFT_BIN" -f "$temporary/transaction.nft"
"$NFT_BIN" -y -nn list table inet "$TABLE" > "$temporary/current.nft"
installed_hash=$(normalized_hash < "$temporary/current.nft")
[ "$installed_hash" = "$desired_hash" ] \
  || { echo "Installed nftables table failed normalized verification" >&2; exit 1; }
echo "Local-private egress nftables table atomically applied and verified."
