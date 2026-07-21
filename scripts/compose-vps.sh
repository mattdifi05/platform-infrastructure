#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ENV_FILE=${COMPOSE_ENV_FILE:-$ROOT_DIR/.env}
PROJECT_NAME=${COMPOSE_PROJECT_NAME:-platform_infra_vps}

case "$ENV_FILE" in
  /*) ;;
  *) ENV_FILE="$ROOT_DIR/$ENV_FILE" ;;
esac

if [ ! -f "$ENV_FILE" ]; then
  echo "Compose env file not found: $ENV_FILE" >&2
  exit 1
fi

env_path_value() {
  local key=$1 value
  value=$(awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$ENV_FILE")
  [[ -z "$value" || "$value" =~ ^[A-Za-z0-9_./-]+$ ]] || {
    echo "Invalid path value for $key in $ENV_FILE" >&2
    exit 1
  }
  printf '%s' "$value"
}

cd "$ROOT_DIR"

compose=(
  docker compose
  --env-file "$ENV_FILE"
)

workload_lock=${HOSTED_WORKLOAD_LOCK:-$(env_path_value HOSTED_WORKLOAD_LOCK)}
if [[ -n "$workload_lock" ]]; then
  [[ "$workload_lock" = /* ]] || workload_lock="$ROOT_DIR/$workload_lock"
  export HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE=${HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE:-$workload_lock}
  locked_core_env=$(HOSTED_WORKLOAD_ALLOW_RESOLVED=${HOSTED_WORKLOAD_ALLOW_RESOLVED:-0} sh "$ROOT_DIR/scripts/hosted-workload-lock.sh" "$workload_lock" core-env-file)
  locked_project_name=$(HOSTED_WORKLOAD_ALLOW_RESOLVED=${HOSTED_WORKLOAD_ALLOW_RESOLVED:-0} sh "$ROOT_DIR/scripts/hosted-workload-lock.sh" "$workload_lock" project-name)
  [[ "$locked_core_env" = "$ENV_FILE" ]] || {
    echo "Hosted workload lock was prepared for a different core env file." >&2
    exit 1
  }
  [[ "$locked_project_name" = "$PROJECT_NAME" ]] || {
    echo "Hosted workload lock was prepared for a different Compose project name." >&2
    exit 1
  }
  mapfile -t workload_env_files < <(
    HOSTED_WORKLOAD_ALLOW_RESOLVED=${HOSTED_WORKLOAD_ALLOW_RESOLVED:-0} \
      sh "$ROOT_DIR/scripts/hosted-workload-lock.sh" "$workload_lock" env-files
  )
  for workload_env_file in "${workload_env_files[@]}"; do
    [[ -n "$workload_env_file" ]] || continue
    compose+=(--env-file "$workload_env_file")
  done
else
  export HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE=${HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE:-$ROOT_DIR/config/no-hosted-workloads.lock.json}
fi

compose+=(
  -p "$PROJECT_NAME"
  -f compose.yaml
  -f compose.secrets.yaml
  -f compose.waf.yaml
  -f compose.vps.yaml
  -f compose.vps-waf.yaml
  -f compose.backup-scheduler.yaml
  -f compose.runtime.yaml
  -f compose.networks.yaml
  -f compose.runtime-isolation.yaml
)

if [[ -n "$workload_lock" ]]; then
  mapfile -t workload_files < <(
    HOSTED_WORKLOAD_ALLOW_RESOLVED=${HOSTED_WORKLOAD_ALLOW_RESOLVED:-0} \
      sh "$ROOT_DIR/scripts/hosted-workload-lock.sh" "$workload_lock" compose-files
  )
  for workload_file in "${workload_files[@]}"; do
    [[ -n "$workload_file" ]] || continue
    compose+=(-f "$workload_file")
  done
fi

runtime_identity_variables=(
  PLATFORM_RUNTIME_CANDIDATE_ID
  PLATFORM_RUNTIME_COMMIT
  PLATFORM_RUNTIME_TREE
  PLATFORM_RUNTIME_DEPLOYMENT_ID
  PLATFORM_RUNTIME_RENDER_SHA256
  PLATFORM_RUNTIME_WORKLOAD_LOCK_SHA256
)
runtime_identity_count=0
for runtime_identity_variable in "${runtime_identity_variables[@]}"; do
  [[ -z "${!runtime_identity_variable:-}" ]] || ((runtime_identity_count += 1))
done
if (( runtime_identity_count != 0 && runtime_identity_count != ${#runtime_identity_variables[@]} )); then
  echo "Runtime identity labels require the complete approved candidate/deployment tuple." >&2
  exit 1
fi
if (( runtime_identity_count == ${#runtime_identity_variables[@]} )); then
  [[ "$PLATFORM_RUNTIME_CANDIDATE_ID" =~ ^[a-f0-9]{64}$ ]] || { echo "Invalid runtime candidate ID." >&2; exit 1; }
  [[ "$PLATFORM_RUNTIME_COMMIT" =~ ^([a-f0-9]{40}|[a-f0-9]{64})$ ]] || { echo "Invalid runtime commit." >&2; exit 1; }
  [[ "$PLATFORM_RUNTIME_TREE" =~ ^([a-f0-9]{40}|[a-f0-9]{64})$ ]] || { echo "Invalid runtime tree." >&2; exit 1; }
  [[ "$PLATFORM_RUNTIME_DEPLOYMENT_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$ ]] || { echo "Invalid runtime deployment ID." >&2; exit 1; }
  [[ "$PLATFORM_RUNTIME_RENDER_SHA256" =~ ^[a-f0-9]{64}$ ]] || { echo "Invalid runtime render SHA256." >&2; exit 1; }
  [[ "$PLATFORM_RUNTIME_WORKLOAD_LOCK_SHA256" =~ ^[a-f0-9]{64}$ ]] || { echo "Invalid runtime workload lock SHA256." >&2; exit 1; }
  compose+=(-f compose.runtime-identity.yaml)
fi

if [[ "${1:-}" == "up" ]]; then
  "${compose[@]}" --profile backup run --rm --no-deps broker-auth-bootstrap
fi

exec "${compose[@]}" --profile backup "$@"
