#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ENV_FILE=${COMPOSE_ENV_FILE:-$ROOT_DIR/.env}
PROJECT_NAME=${COMPOSE_PROJECT_NAME:-platform_infra_vps}

for argument in "$@"; do
  case "$argument" in
    --scale|--scale=*|scale)
      printf '%s\n' "Caller-controlled scaling is forbidden; regenerate and verify the hosted workload contract." >&2
      exit 2
      ;;
  esac
done

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

sha256_file() {
  local target=$1
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$target" | awk '{ print $1 }'
  else
    shasum -a 256 "$target" | awk '{ print $1 }'
  fi
}

fd_identity() {
  local target=$1 raw device inode uid mode
  if stat -c '%d|%i|%u|%a' "$target" >/dev/null 2>&1; then
    raw=$(stat -c '%d|%i|%u|%a' "$target")
  else
    raw=$(stat -f '%d|%i|%u|%Lp' "$target")
  fi
  IFS='|' read -r device inode uid mode <<< "$raw"
  [[ "$OSTYPE" != darwin* ]] || device='*'
  printf '%s|%s|%s|%s\n' "$device" "$inode" "$uid" "$((8#$mode))"
}

next_handoff_fd=50
handoff_files=()
handoff_directory=
HANDOFF_REFERENCE=

cleanup_handoff() {
  local item
  for item in "${handoff_files[@]:-}"; do
    [[ ! -e "$item" ]] || /bin/rm -- "$item" >/dev/null 2>&1 || true
  done
  [[ -z "$handoff_directory" || ! -d "$handoff_directory" ]] || /bin/rmdir -- "$handoff_directory" >/dev/null 2>&1 || true
}

open_locked_handoff() {
  local source=$1 expected_sha=$2 expected_device=$3 expected_inode=$4 expected_uid=$5 expected_mode=$6
  local source_fd source_reference before after actual_device actual_inode actual_uid actual_mode handoff_file actual_sha handoff_fd
  [[ "$source" = /* && "$source" != *[!A-Za-z0-9_./-]* && "$source" != *//* && "$source" != */../* && "$source" != */.. ]] || {
    printf 'Invalid locked handoff path: %s\n' "$source" >&2
    return 1
  }
  source_fd=$next_handoff_fd
  next_handoff_fd=$((next_handoff_fd + 1))
  eval "exec ${source_fd}<\"\$source\""
  source_reference=/dev/fd/$source_fd
  before=$(fd_identity "$source_reference")
  IFS='|' read -r actual_device actual_inode actual_uid actual_mode <<< "$before"
  [[ ( "$actual_device" = '*' || "$actual_device" = "$expected_device" )
      && "$actual_inode" = "$expected_inode" && "$actual_uid" = "$expected_uid" && "$actual_mode" = "$expected_mode" ]] || {
    printf 'Locked handoff object identity changed: %s\n' "$source" >&2
    return 1
  }
  handoff_file=$handoff_directory/object-$next_handoff_fd
  handoff_files+=("$handoff_file")
  /bin/cat <&$source_fd > "$handoff_file"
  after=$(fd_identity "$source_reference")
  [[ "$before" = "$after" ]] || {
    printf 'Locked handoff object changed while being copied: %s\n' "$source" >&2
    return 1
  }
  eval "exec ${source_fd}<&-"
  chmod 400 "$handoff_file"
  actual_sha=$(sha256_file "$handoff_file")
  [[ "$actual_sha" = "$expected_sha" ]] || {
    printf 'Locked handoff digest changed: %s\n' "$source" >&2
    return 1
  }
  handoff_fd=$next_handoff_fd
  next_handoff_fd=$((next_handoff_fd + 1))
  eval "exec ${handoff_fd}<\"\$handoff_file\""
  /bin/rm -- "$handoff_file"
  HANDOFF_REFERENCE=/dev/fd/$handoff_fd
}

cd "$ROOT_DIR"

compose=(
  docker compose
  --env-file "$ENV_FILE"
)

workload_lock=${HOSTED_WORKLOAD_LOCK:-$(env_path_value HOSTED_WORKLOAD_LOCK)}
if [[ -n "$workload_lock" ]]; then
  [[ "$workload_lock" = /* ]] || workload_lock="$ROOT_DIR/$workload_lock"
  handoff_directory=$(mktemp -d "${TMPDIR:-/tmp}/hosted-compose-handoff.XXXXXX")
  chmod 700 "$handoff_directory"
  trap cleanup_handoff EXIT
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
  workload_env_records=$(
    HOSTED_WORKLOAD_ALLOW_RESOLVED=${HOSTED_WORKLOAD_ALLOW_RESOLVED:-0} \
      sh "$ROOT_DIR/scripts/hosted-workload-lock.sh" "$workload_lock" env-records
  )
  while IFS=$'\t' read -r source expected_sha expected_device expected_inode expected_uid expected_mode; do
    [[ -n "$source" ]] || continue
    open_locked_handoff "$source" "$expected_sha" "$expected_device" "$expected_inode" "$expected_uid" "$expected_mode"
    compose+=(--env-file "$HANDOFF_REFERENCE")
  done <<< "$workload_env_records"
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
  workload_compose_records=$(
    HOSTED_WORKLOAD_ALLOW_RESOLVED=${HOSTED_WORKLOAD_ALLOW_RESOLVED:-0} \
      sh "$ROOT_DIR/scripts/hosted-workload-lock.sh" "$workload_lock" compose-records
  )
  while IFS=$'\t' read -r source expected_sha expected_device expected_inode expected_uid expected_mode; do
    [[ -n "$source" ]] || continue
    open_locked_handoff "$source" "$expected_sha" "$expected_device" "$expected_inode" "$expected_uid" "$expected_mode"
    compose+=(-f "$HANDOFF_REFERENCE")
  done <<< "$workload_compose_records"
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

cleanup_handoff
trap - EXIT
exec "${compose[@]}" --profile backup "$@"
