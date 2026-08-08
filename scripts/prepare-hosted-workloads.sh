#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INFRA_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
ENV_FILE=${COMPOSE_ENV_FILE:-$INFRA_ROOT/.env}
PROJECT_NAME=${COMPOSE_PROJECT_NAME:-platform_infra_vps}
TMP=$(mktemp -d "${TMPDIR:-/tmp}/hosted-workloads.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

trusted_host_os() {
  if [[ -x /usr/bin/uname ]]; then
    /usr/bin/uname -s
  elif [[ -x /bin/uname ]]; then
    /bin/uname -s
  else
    return 1
  fi
}

HOST_OS=$(trusted_host_os) || {
  printf '%s\n' "Hosted workload preparation cannot determine the host OS safely." >&2
  exit 1
}
case "$HOST_OS" in Linux|Darwin) ;; *) printf 'Unsupported host OS: %s\n' "$HOST_OS" >&2; exit 1 ;; esac

[[ "$ENV_FILE" = /* ]] || ENV_FILE="$INFRA_ROOT/$ENV_FILE"
[[ -f "$ENV_FILE" ]] || {
  printf '%s\n' "Compose env file must exist: $ENV_FILE" >&2
  exit 1
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  else
    shasum -a 256 "$1" | awk '{ print $1 }'
  fi
}

authority_identity() {
  local raw device inode uid gid mode links size modified changed
  if stat -c '%d|%i|%u|%g|%a|%h|%s|%Y|%Z' "$1" >/dev/null 2>&1; then
    raw=$(stat -c '%d|%i|%u|%g|%a|%h|%s|%Y|%Z' "$1")
  else
    raw=$(stat -f '%d|%i|%u|%g|%Lp|%l|%z|%m|%c' "$1")
  fi
  IFS='|' read -r device inode uid gid mode links size modified changed <<< "$raw"
  printf '%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
    "$device" "$inode" "$uid" "$gid" "$((8#$mode))" "$links" "$size" "$modified" "$changed"
}

assert_safe_authority_path() {
  local value=$1 remainder cursor component
  [[ "$value" = /*
      && "$value" != *[!A-Za-z0-9_./-]*
      && "$value" != *//*
      && "$value" != */../*
      && "$value" != */..
      && "$value" != */./*
      && "$value" != */. ]] || {
    printf 'Target-local authority path is not canonical: %s\n' "$value" >&2
    exit 1
  }
  remainder=${value#/}
  cursor=
  while [[ -n "$remainder" ]]; do
    if [[ "$remainder" = */* ]]; then
      component=${remainder%%/*}
      remainder=${remainder#*/}
    else
      component=$remainder
      remainder=
    fi
    cursor=$cursor/$component
    [[ -e "$cursor" && ! -L "$cursor" ]] || {
      printf 'Target-local authority path has a missing or symlinked component: %s\n' "$cursor" >&2
      exit 1
    }
  done
}

assert_authority_directory() {
  local directory=$1 expected_owner=$2 label=$3 identity device inode uid gid mode links size modified changed
  assert_safe_authority_path "$directory"
  [[ -d "$directory" && "$(CDPATH= cd -- "$directory" && pwd -P)" = "$directory" ]] || {
    printf '%s must be one canonical directory.\n' "$label" >&2
    exit 1
  }
  identity=$(authority_identity "$directory")
  IFS='|' read -r device inode uid gid mode links size modified changed <<< "$identity"
  [[ "$uid" = "$expected_owner" && $((mode & 18)) -eq 0 ]] || {
    printf '%s must be authority-owned and non-group/world-writable.\n' "$label" >&2
    exit 1
  }
  PREPARE_AUTHORITY_PATHS+=("$directory")
  PREPARE_AUTHORITY_IDENTITIES+=("$identity")
}

PREPARE_AUTHORITY_PATHS=()
PREPARE_AUTHORITY_IDENTITIES=()
env_mount_args=()
if [[ "$ENV_FILE" != "$INFRA_ROOT/.env" ]]; then
  case "$HOST_OS" in
    Linux)
      authority_root=/srv/platform-infrastructure
      authority_owner=0
      ;;
    Darwin)
      authority_root=${HOSTED_TEST_INFRASTRUCTURE_ROOT:-}
      authority_owner=$(id -u)
      [[ -n "$authority_root" ]] || {
        printf '%s\n' "Target-local Compose env authority is unavailable outside Linux." >&2
        exit 1
      }
      ;;
    *)
      printf '%s\n' "Target-local Compose env authority cannot determine a supported host OS." >&2
      exit 1
      ;;
  esac
  release_id=$(basename -- "$INFRA_ROOT")
  [[ "$release_id" =~ ^([a-f0-9]{40}|[a-f0-9]{64})-[a-f0-9]{64}$ ]] || {
    printf '%s\n' "Target-local release identifier is invalid." >&2
    exit 1
  }
  expected_release_root=$authority_root/releases/$release_id
  assert_safe_authority_path "$ENV_FILE"
  environment_before=$(authority_identity "$ENV_FILE")
  environment_sha256=$(sha256_file "$ENV_FILE")
  expected_state_root=$authority_root/release-states/$release_id-$environment_sha256
  IFS='|' read -r _device _inode environment_uid environment_gid environment_mode environment_links \
    _size _modified _changed <<< "$environment_before"
  [[ "$INFRA_ROOT" = "$expected_release_root"
      && "$ENV_FILE" = "$expected_state_root/environment.env"
      && "$environment_uid" = "$authority_owner"
      && "$environment_gid" = "$(id -g)"
      && "$environment_mode" = 416
      && "$environment_links" = 1
      && -f "$ENV_FILE" && ! -L "$ENV_FILE" && -r "$ENV_FILE"
      && "$(authority_identity "$ENV_FILE")" = "$environment_before" ]] || {
    printf '%s\n' "Non-default Compose env is not the exact readable target-local release-state authority." >&2
    exit 1
  }
  assert_authority_directory "$(dirname -- "$authority_root")" "$authority_owner" "Platform service root"
  assert_authority_directory "$authority_root" "$authority_owner" "Platform infrastructure root"
  assert_authority_directory "$authority_root/releases" "$authority_owner" "Immutable release store"
  assert_authority_directory "$INFRA_ROOT" "$authority_owner" "Immutable release root"
  assert_authority_directory "$authority_root/release-states" "$authority_owner" "Release-state store"
  assert_authority_directory "$expected_state_root" "$authority_owner" "Release-state root"
  PREPARE_AUTHORITY_PATHS+=("$ENV_FILE")
  PREPARE_AUTHORITY_IDENTITIES+=("$environment_before")
  env_mount_args=(-v "$ENV_FILE:$ENV_FILE:ro")
fi

revalidate_prepare_authority() {
  local index
  for ((index = 0; index < ${#PREPARE_AUTHORITY_PATHS[@]}; index += 1)); do
    [[ "${PREPARE_AUTHORITY_IDENTITIES[$index]}" = "$(authority_identity "${PREPARE_AUTHORITY_PATHS[$index]}")" ]] || {
      printf 'Target-local preparation authority changed: %s\n' "${PREPARE_AUTHORITY_PATHS[$index]}" >&2
      exit 1
    }
  done
}

env_path_value() {
  local key=$1 value
  value=$(awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$ENV_FILE")
  [[ -z "$value" || "$value" =~ ^[A-Za-z0-9_./-]+$ ]] || {
    printf 'Invalid path value for %s in %s\n' "$key" "$ENV_FILE" >&2
    exit 1
  }
  printf '%s' "$value"
}

CATALOG=${HOSTED_WORKLOAD_CATALOG:-$(env_path_value HOSTED_WORKLOAD_CATALOG)}
WORKLOAD_ROOT=${HOSTED_WORKLOAD_ROOT:-$(env_path_value HOSTED_WORKLOAD_ROOT)}
OUTPUT=${HOSTED_WORKLOAD_LOCK:-$(env_path_value HOSTED_WORKLOAD_LOCK)}
CATALOG=${CATALOG:-$INFRA_ROOT/config/hosted-workloads.example.json}
WORKLOAD_ROOT=${WORKLOAD_ROOT:-$INFRA_ROOT/../src}
PRIVATE_STATE_BASE=${XDG_STATE_HOME:-${HOME:?HOME is required}/.local/state}
OUTPUT=${OUTPUT:-$PRIVATE_STATE_BASE/platform-infrastructure/hosted-workloads/hosted-workloads.lock.json}

for path_var in CATALOG WORKLOAD_ROOT OUTPUT; do
  value=${!path_var}
  [[ "$value" = /* ]] || value="$INFRA_ROOT/$value"
  printf -v "$path_var" '%s' "$value"
done

[[ -f "$CATALOG" && -d "$WORKLOAD_ROOT" ]] || {
  printf '%s\n' "Catalog, workload root and Compose env file must exist." >&2
  exit 1
}

ensure_private_directory() {
  local directory=$1 remainder cursor component mode owner
  [[ "$directory" = /* ]] || {
    printf 'Deployment-private directory must be absolute: %s\n' "$directory" >&2
    exit 1
  }
  remainder=${directory#/}
  cursor=
  while [[ -n "$remainder" ]]; do
    if [[ "$remainder" = */* ]]; then
      component=${remainder%%/*}
      remainder=${remainder#*/}
    else
      component=$remainder
      remainder=
    fi
    cursor=$cursor/$component
    if [[ -e "$cursor" || -L "$cursor" ]]; then
      [[ -d "$cursor" && ! -L "$cursor" ]] || {
        printf 'Deployment-private path component is not a real directory: %s\n' "$cursor" >&2
        exit 1
      }
    else
      mkdir -m 700 -- "$cursor"
    fi
  done
  if stat -c '%a' "$directory" >/dev/null 2>&1; then
    mode=$(stat -c '%a' "$directory")
    owner=$(stat -c '%u' "$directory")
  else
    mode=$(stat -f '%Lp' "$directory")
    owner=$(stat -f '%u' "$directory")
  fi
  [[ "$mode" = 700 && "$owner" = "$(id -u)" ]] || {
    printf 'Deployment-private directory must be owned by the deployment identity with mode 0700: %s\n' "$directory" >&2
    exit 1
  }
}

# The provider-authenticated deployment receipt is the only source of the ops
# image reference and local image ID. No caller-selected image, local build,
# mutable tag, or implicit pull is accepted.
admitted=$(sh "$SCRIPT_DIR/ops-image-trust.sh")
OPS_IMAGE=$(printf '%s' "$admitted" | jq -er '.image')
OPS_IMAGE_ID=$(printf '%s' "$admitted" | jq -er '.imageId')
ADMITTED_SOURCE_ARCHIVE_SHA256=$(printf '%s' "$admitted" | jq -er '.sourceArchiveSha256')

assert_admitted_checkout() {
  local current current_image current_image_id current_archive_sha256
  current=$(sh "$SCRIPT_DIR/ops-image-trust.sh") || {
    printf '%s\n' "Hosted workload source/admission authority changed after ops admission." >&2
    exit 1
  }
  current_image=$(printf '%s' "$current" | jq -er '.image')
  current_image_id=$(printf '%s' "$current" | jq -er '.imageId')
  current_archive_sha256=$(printf '%s' "$current" | jq -er '.sourceArchiveSha256')
  [[ "$current_image" = "$OPS_IMAGE"
      && "$current_image_id" = "$OPS_IMAGE_ID"
      && "$current_archive_sha256" = "$ADMITTED_SOURCE_ARCHIVE_SHA256" ]] || {
    printf '%s\n' "Hosted workload source/admission identity changed after ops admission." >&2
    exit 1
  }
  revalidate_prepare_authority
}

core_files=(
  "$INFRA_ROOT/compose.yaml"
  "$INFRA_ROOT/compose.secrets.yaml"
  "$INFRA_ROOT/compose.waf.yaml"
  "$INFRA_ROOT/compose.vps.yaml"
  "$INFRA_ROOT/compose.vps-waf.yaml"
  "$INFRA_ROOT/compose.backup-scheduler.yaml"
  "$INFRA_ROOT/compose.runtime.yaml"
  "$INFRA_ROOT/compose.networks.yaml"
  "$INFRA_ROOT/compose.runtime-isolation.yaml"
)
core_csv=$(IFS=,; printf '%s' "${core_files[*]}")

output_directory=$(dirname "$OUTPUT")
case "$output_directory/" in
  "$INFRA_ROOT/projects-portal/state/"*)
    printf '%s\n' "Hosted workload activation state cannot use the service-writable projects-portal/state tree." >&2
    exit 1
    ;;
esac
ensure_private_directory "$output_directory"
snapshot_root="$output_directory/snapshots"
resolved="$TMP/hosted-workloads.resolved.json"
core_render="$TMP/core-render.json"
combined_render="$TMP/combined-render.json"

assert_admitted_checkout
docker run --rm --pull=never --network none --user "$(id -u):$(id -g)" \
  -v "$INFRA_ROOT:$INFRA_ROOT:ro" \
  "${env_mount_args[@]}" \
  -v "$WORKLOAD_ROOT:$WORKLOAD_ROOT:ro" \
  -v "$(dirname "$CATALOG"):$(dirname "$CATALOG"):ro" \
  -v "$(dirname "$OUTPUT"):$(dirname "$OUTPUT")" \
  -v "$TMP:$TMP" \
  "$OPS_IMAGE_ID" hosted-workload-contract resolve \
    --catalog "$CATALOG" \
    --workloadRoot "$WORKLOAD_ROOT" \
    --envFile "$ENV_FILE" \
    --projectName "$PROJECT_NAME" \
    --coreFiles "$core_csv" \
    --snapshotRoot "$snapshot_root" \
    --activationLock "$OUTPUT" \
    --output "$resolved"
revalidate_prepare_authority

docker run --rm --pull=never --network none --user "$(id -u):$(id -g)" --entrypoint ruby \
  -v "$INFRA_ROOT:$INFRA_ROOT:ro" \
  -v "$(dirname "$OUTPUT"):$(dirname "$OUTPUT"):ro" \
  -v "$TMP:$TMP" \
  -w "$INFRA_ROOT" \
  "$OPS_IMAGE_ID" scripts/hosted-workload-source-policy.rb --lock "$resolved"
revalidate_prepare_authority

[[ ! -L "$OUTPUT" && ( ! -e "$OUTPUT" || -f "$OUTPUT" ) ]] || {
  printf '%s\n' "Hosted workload activation output must be absent or a regular non-symlink file: $OUTPUT" >&2
  exit 1
}
install -m 0600 "$resolved" "$OUTPUT"

COMPOSE_ENV_FILE="$ENV_FILE" COMPOSE_PROJECT_NAME="$PROJECT_NAME" HOSTED_WORKLOAD_LOCK= HOSTED_WORKLOAD_MODE=hosted \
HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE="$OUTPUT" HOSTED_WORKLOAD_PREPARE_RESOLVED=1 \
  bash "$SCRIPT_DIR/compose-vps.sh" config --format json > "$core_render"
revalidate_prepare_authority

COMPOSE_ENV_FILE="$ENV_FILE" COMPOSE_PROJECT_NAME="$PROJECT_NAME" \
HOSTED_WORKLOAD_LOCK="$OUTPUT" HOSTED_WORKLOAD_MODE=hosted HOSTED_WORKLOAD_PREPARE_RESOLVED=1 \
HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE="$OUTPUT" \
  bash "$SCRIPT_DIR/compose-vps.sh" config --format json > "$combined_render"
revalidate_prepare_authority

assert_admitted_checkout
docker run --rm --pull=never --network none --user "$(id -u):$(id -g)" \
  -v "$INFRA_ROOT:$INFRA_ROOT:ro" \
  "${env_mount_args[@]}" \
  -v "$WORKLOAD_ROOT:$WORKLOAD_ROOT:ro" \
  -v "$TMP:$TMP:ro" \
  -v "$(dirname "$OUTPUT"):$(dirname "$OUTPUT")" \
  "$OPS_IMAGE_ID" hosted-workload-contract verify-render \
    --lock "$OUTPUT" \
    --coreRender "$core_render" \
    --combinedRender "$combined_render" \
    --output "$OUTPUT"
revalidate_prepare_authority

chmod 600 "$OUTPUT"
sh "$SCRIPT_DIR/hosted-workload-lock.sh" "$OUTPUT" verify
printf 'Verified hosted workload lock with admitted ops image %s: %s\n' "$OPS_IMAGE" "$OUTPUT"
