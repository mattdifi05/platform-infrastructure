#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INFRA_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
ENV_FILE=${COMPOSE_ENV_FILE:-$INFRA_ROOT/.env}
PROJECT_NAME=${COMPOSE_PROJECT_NAME:-platform_infra_vps}
OPS_IMAGE=${PLATFORM_OPS_IMAGE:-platform/ops:local}
TMP=$(mktemp -d "${TMPDIR:-/tmp}/hosted-workloads.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

[[ "$ENV_FILE" = /* ]] || ENV_FILE="$INFRA_ROOT/$ENV_FILE"
[[ -f "$ENV_FILE" ]] || {
  printf '%s\n' "Compose env file must exist: $ENV_FILE" >&2
  exit 1
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

docker run --rm --network none --user "$(id -u):$(id -g)" --entrypoint node \
  -v "$INFRA_ROOT:$INFRA_ROOT:ro" \
  -v "$WORKLOAD_ROOT:$WORKLOAD_ROOT:ro" \
  -v "$(dirname "$CATALOG"):$(dirname "$CATALOG"):ro" \
  -v "$(dirname "$OUTPUT"):$(dirname "$OUTPUT")" \
  -v "$TMP:$TMP" \
  -w "$INFRA_ROOT" \
  "$OPS_IMAGE" scripts/hosted-workload-contract.mjs resolve \
    --catalog "$CATALOG" \
    --workloadRoot "$WORKLOAD_ROOT" \
    --envFile "$ENV_FILE" \
    --projectName "$PROJECT_NAME" \
    --coreFiles "$core_csv" \
    --snapshotRoot "$snapshot_root" \
    --activationLock "$OUTPUT" \
    --output "$resolved"

docker run --rm --network none --user "$(id -u):$(id -g)" --entrypoint ruby \
  -v "$INFRA_ROOT:$INFRA_ROOT:ro" \
  -v "$(dirname "$OUTPUT"):$(dirname "$OUTPUT"):ro" \
  -v "$TMP:$TMP" \
  -w "$INFRA_ROOT" \
  "$OPS_IMAGE" scripts/hosted-workload-source-policy.rb --lock "$resolved"

[[ ! -L "$OUTPUT" && ( ! -e "$OUTPUT" || -f "$OUTPUT" ) ]] || {
  printf '%s\n' "Hosted workload activation output must be absent or a regular non-symlink file: $OUTPUT" >&2
  exit 1
}
install -m 0600 "$resolved" "$OUTPUT"

COMPOSE_ENV_FILE="$ENV_FILE" COMPOSE_PROJECT_NAME="$PROJECT_NAME" HOSTED_WORKLOAD_LOCK= \
HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE="$OUTPUT" HOSTED_WORKLOAD_PREPARE_RESOLVED=1 \
  bash "$SCRIPT_DIR/compose-vps.sh" config --format json > "$core_render"

COMPOSE_ENV_FILE="$ENV_FILE" COMPOSE_PROJECT_NAME="$PROJECT_NAME" \
HOSTED_WORKLOAD_LOCK="$OUTPUT" HOSTED_WORKLOAD_ALLOW_RESOLVED=1 \
HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE="$OUTPUT" \
  bash "$SCRIPT_DIR/compose-vps.sh" config --format json > "$combined_render"

docker run --rm --network none --user "$(id -u):$(id -g)" --entrypoint node \
  -v "$INFRA_ROOT:$INFRA_ROOT:ro" \
  -v "$WORKLOAD_ROOT:$WORKLOAD_ROOT:ro" \
  -v "$TMP:$TMP:ro" \
  -v "$(dirname "$OUTPUT"):$(dirname "$OUTPUT")" \
  -w "$INFRA_ROOT" \
  "$OPS_IMAGE" scripts/hosted-workload-contract.mjs verify-render \
    --lock "$OUTPUT" \
    --coreRender "$core_render" \
    --combinedRender "$combined_render" \
    --output "$OUTPUT"

chmod 600 "$OUTPUT"
sh "$SCRIPT_DIR/hosted-workload-lock.sh" "$OUTPUT" verify
printf 'Verified hosted workload lock: %s\n' "$OUTPUT"
