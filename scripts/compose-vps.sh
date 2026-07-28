#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ENV_FILE=${COMPOSE_ENV_FILE:-$ROOT_DIR/.env}
PROJECT_NAME=${COMPOSE_PROJECT_NAME:-platform_infra_vps}
PREPARE_RESOLVED=${HOSTED_WORKLOAD_PREPARE_RESOLVED:-0}
CANONICAL_DOCKER_HOST=unix:///var/run/docker.sock

case "${DOCKER_HOST:-}" in
  ""|"$CANONICAL_DOCKER_HOST") ;;
  *) printf 'Caller-selected DOCKER_HOST is forbidden: %s\n' "$DOCKER_HOST" >&2; exit 2 ;;
esac
case "${DOCKER_CONTEXT:-}" in
  ""|default) ;;
  *) printf 'Caller-selected DOCKER_CONTEXT is forbidden: %s\n' "$DOCKER_CONTEXT" >&2; exit 2 ;;
esac
unset DOCKER_CONTEXT
export DOCKER_HOST=$CANONICAL_DOCKER_HOST

[[ "$PROJECT_NAME" == platform_infra_vps ]] || {
  printf '%s\n' "The VPS Compose wrapper is bound to canonical project platform_infra_vps." >&2
  exit 2
}

case "$PREPARE_RESOLVED" in
  0) ;;
  1)
    if (( $# != 3 )) || [[ "$1" != config || "$2" != --format || "$3" != json ]]; then
      printf '%s\n' "Resolved hosted workload locks are limited to the exact prepare-time config render." >&2
      exit 2
    fi
    ;;
  *)
    printf '%s\n' "HOSTED_WORKLOAD_PREPARE_RESOLVED must be 0 or 1." >&2
    exit 2
    ;;
esac

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

if [[ ${HOSTED_WORKLOAD_LOCK+x} ]]; then
  workload_lock=$HOSTED_WORKLOAD_LOCK
else
  workload_lock=$(env_path_value HOSTED_WORKLOAD_LOCK)
fi
for argument in "$@"; do
  case "$argument" in
    -f|-f?*|--file|--file=*|--env-file|--env-file=*|-p|-p?*|--project-name|--project-name=*|--project-directory|--project-directory=*|--profile|--profile=*)
      printf '%s\n' "Caller-controlled Compose files, environment, project and profiles are forbidden." >&2
      exit 2
      ;;
    --scale|--scale=*|scale)
      printf '%s\n' "Caller-controlled scaling is forbidden; regenerate and verify the hosted workload contract." >&2
      exit 2
      ;;
  esac
done
if (( $# != 3 )) || [[ "$1" != config || "$2" != --format || "$3" != json ]]; then
  printf '%s\n' "The VPS Compose wrapper is render-only in every hosted/no-hosted state; use the global activation transaction for runtime mutation." >&2
  exit 2
fi

canonical_existing_file() {
  local candidate=$1 parent base
  [[ "$candidate" = /* ]] || candidate="$ROOT_DIR/$candidate"
  parent=$(dirname -- "$candidate")
  base=$(basename -- "$candidate")
  [[ -d "$parent" && ! -L "$candidate" && -f "$candidate" ]] || {
    printf 'Runtime lock source must be an existing regular non-symlink file: %s\n' "$candidate" >&2
    return 1
  }
  parent=$(CDPATH= cd -- "$parent" && pwd -P)
  printf '%s/%s\n' "$parent" "$base"
}

sha256_stream() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{ print $1 }'
  else
    shasum -a 256 | awk '{ print $1 }'
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
  printf '%s|%s|%s|%s\n' "$device" "$inode" "$uid" "$((8#$mode))"
}

fd_object_identity() {
  local identity device inode uid mode
  identity=$(fd_identity "$1")
  IFS='|' read -r device inode uid mode <<< "$identity"
  printf '%s|%s\n' "$inode" "$uid"
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
  local source_fd source_reference path_before before after actual_device actual_inode actual_uid actual_mode handoff_file
  local writer_fd hash_fd handoff_fd path_identity path_device path_inode path_uid path_mode
  local writer_identity hash_identity handoff_identity actual_sha
  [[ "$source" = /* && "$source" != *[!A-Za-z0-9_./-]* && "$source" != *//* && "$source" != */../* && "$source" != */.. ]] || {
    printf 'Invalid locked handoff path: %s\n' "$source" >&2
    return 1
  }
  path_before=$(fd_identity "$source")
  [[ "$path_before" = "$expected_device|$expected_inode|$expected_uid|$expected_mode" ]] || {
    printf 'Locked handoff path identity changed: %s\n' "$source" >&2
    return 1
  }
  source_fd=$next_handoff_fd
  next_handoff_fd=$((next_handoff_fd + 1))
  if ! eval "exec ${source_fd}<\"\$source\""; then
    printf 'Locked handoff object could not be opened: %s\n' "$source" >&2
    return 1
  fi
  source_reference=/dev/fd/$source_fd
  before=$(fd_identity "$source_reference")
  IFS='|' read -r actual_device actual_inode actual_uid actual_mode <<< "$before"
  [[ "$actual_inode" = "$expected_inode" && "$actual_uid" = "$expected_uid"
      && ( "$OSTYPE" = darwin* || "$actual_device" = "$expected_device" ) ]] || {
    printf 'Locked handoff object identity changed: %s\n' "$source" >&2
    return 1
  }
  handoff_file=$handoff_directory/object-$next_handoff_fd
  handoff_files+=("$handoff_file")
  writer_fd=$next_handoff_fd
  next_handoff_fd=$((next_handoff_fd + 1))
  set -C
  if ! eval "exec ${writer_fd}>\"\$handoff_file\""; then
    set +C
    printf 'Could not exclusively create locked handoff object: %s\n' "$source" >&2
    return 1
  fi
  set +C
  hash_fd=$next_handoff_fd
  next_handoff_fd=$((next_handoff_fd + 1))
  eval "exec ${hash_fd}<\"\$handoff_file\""
  handoff_fd=$next_handoff_fd
  next_handoff_fd=$((next_handoff_fd + 1))
  eval "exec ${handoff_fd}<\"\$handoff_file\""
  path_identity=$(fd_identity "$handoff_file")
  IFS='|' read -r path_device path_inode path_uid path_mode <<< "$path_identity"
  writer_identity=$(fd_object_identity "/dev/fd/$writer_fd")
  hash_identity=$(fd_object_identity "/dev/fd/$hash_fd")
  handoff_identity=$(fd_object_identity "/dev/fd/$handoff_fd")
  [[ "$path_mode" = 384 && "$writer_identity" = "$path_inode|$path_uid"
      && "$writer_identity" = "$hash_identity" && "$writer_identity" = "$handoff_identity" ]] || {
    printf 'Locked handoff descriptors do not reference one object: %s\n' "$source" >&2
    return 1
  }
  /bin/rm -- "$handoff_file"
  /bin/cat <&$source_fd >&$writer_fd
  after=$(fd_identity "$source_reference")
  [[ "$before" = "$after" ]] || {
    printf 'Locked handoff object changed while being copied: %s\n' "$source" >&2
    return 1
  }
  eval "exec ${source_fd}<&-"
  eval "exec ${writer_fd}>&-"
  actual_sha=$(sha256_stream <&$hash_fd)
  eval "exec ${hash_fd}<&-"
  [[ "$actual_sha" = "$expected_sha" ]] || {
    printf 'Locked handoff digest changed: %s\n' "$source" >&2
    return 1
  }
  HANDOFF_REFERENCE=/dev/fd/$handoff_fd
}

open_generated_handoff() {
  local content=$1 handoff_file writer_fd handoff_fd path_identity path_device path_inode path_uid path_mode
  local writer_identity handoff_identity
  handoff_file=$handoff_directory/generated-$next_handoff_fd
  writer_fd=$next_handoff_fd
  next_handoff_fd=$((next_handoff_fd + 1))
  set -C
  if ! eval "exec ${writer_fd}>\"\$handoff_file\""; then
    set +C
    printf '%s\n' "Could not exclusively create generated hosted workload overlay." >&2
    return 1
  fi
  set +C
  handoff_fd=$next_handoff_fd
  next_handoff_fd=$((next_handoff_fd + 1))
  eval "exec ${handoff_fd}<\"\$handoff_file\""
  path_identity=$(fd_identity "$handoff_file")
  IFS='|' read -r path_device path_inode path_uid path_mode <<< "$path_identity"
  writer_identity=$(fd_object_identity "/dev/fd/$writer_fd")
  handoff_identity=$(fd_object_identity "/dev/fd/$handoff_fd")
  [[ "$path_mode" = 384 && "$writer_identity" = "$path_inode|$path_uid" && "$writer_identity" = "$handoff_identity" ]] || {
    printf '%s\n' "Generated hosted workload overlay descriptors do not reference one private object." >&2
    return 1
  }
  printf '%s\n' "$content" >&$writer_fd
  eval "exec ${writer_fd}>&-"
  /bin/rm -- "$handoff_file"
  HANDOFF_REFERENCE=/dev/fd/$handoff_fd
}

cd "$ROOT_DIR"

declare -a compose=()

if [[ -n "$workload_lock" ]]; then
  [[ "$workload_lock" = /* ]] || workload_lock="$ROOT_DIR/$workload_lock"
  workload_lock=$(canonical_existing_file "$workload_lock")
  handoff_directory=$(mktemp -d "${TMPDIR:-/tmp}/hosted-compose-handoff.XXXXXX")
  chmod 700 "$handoff_directory"
  umask 077
  trap cleanup_handoff EXIT
  runtime_lock_source=$(canonical_existing_file "${HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE:-$workload_lock}")
  [[ "$runtime_lock_source" = "$workload_lock" ]] || {
    printf '%s\n' "Runtime lock mount source must be the exact verified activation lock." >&2
    exit 1
  }
  export HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE=$runtime_lock_source
  activation_bundle=$(
    HOSTED_WORKLOAD_ALLOW_RESOLVED=$PREPARE_RESOLVED \
      sh "$ROOT_DIR/scripts/hosted-workload-lock.sh" "$workload_lock" activation-bundle
  )
  printf '%s' "$activation_bundle" | jq -e --arg prepare "$PREPARE_RESOLVED" '
    def record:
      type == "object"
      and ((keys | sort) == ["device", "inode", "mode", "path", "sha256", "uid"])
      and (.path | type == "string" and length > 0)
      and (.sha256 | type == "string" and test("^[a-f0-9]{64}$"))
      and (.device | type == "string" and test("^[0-9]+$"))
      and (.inode | type == "string" and test("^[0-9]+$"))
      and (.uid | type == "string" and test("^[0-9]+$"))
      and .mode == 256;
    def core_record:
      . as $record
      | type == "object"
      and ((keys | sort) == ["device", "inode", "mode", "path", "sha256", "uid"])
      and (.path | type == "string" and length > 0)
      and (.sha256 | type == "string" and test("^[a-f0-9]{64}$"))
      and (.device | type == "string" and test("^[0-9]+$"))
      and (.inode | type == "string" and test("^[0-9]+$"))
      and (.uid | type == "string" and test("^[0-9]+$"))
      and ([256, 384] | index($record.mode)) != null;
    def network_record($projectName):
      type == "object"
      and ((keys | sort) == ["logicalName", "physicalName", "workloadId"])
      and (.workloadId | type == "string" and test("^[a-z0-9][a-z0-9-]*$"))
      and (.logicalName | type == "string" and test("^[a-z0-9][a-z0-9_]*(ingress|postgres|cache|bus|identity|storage|observability|egress)$"))
      and .logicalName == ((.workloadId | gsub("-"; "_")) + "_" + (.logicalName | split("_") | last))
      and .physicalName == ($projectName + "_" + .logicalName);
    def service_record:
      . as $record
      | type == "object"
      and ((keys | sort) == ["serviceName", "workloadId"])
      and (.workloadId | type == "string" and test("^[a-z0-9][a-z0-9-]*$"))
      and (.serviceName | type == "string" and test("^[a-z][a-z0-9-]{1,62}$"))
      and ($record.serviceName | startswith($record.workloadId + "-"));
    def route_record:
      . as $record
      | type == "object"
      and ((keys | sort) == ["port", "serviceName", "slug", "upstream", "workloadId"])
      and (.workloadId | type == "string" and test("^[a-z0-9][a-z0-9-]*$"))
      and (.slug | type == "string" and test("^[a-z0-9][a-z0-9-]*$"))
      and (.serviceName | type == "string" and startswith($record.workloadId + "-"))
      and (.port | type == "number" and . >= 1 and . <= 65535 and floor == .)
      and .upstream == ("http://" + .serviceName + ":" + (.port | tostring));
    . as $bundle
    | type == "object"
    and ((keys | sort) == ["combinedRenderSha256", "composeRecords", "coreEnvFile", "coreEnvironmentRecord", "coreRenderSha256", "environmentRecords", "lockSha256", "networkRecords", "platformExtensionRecords", "projectName", "protectedNetworkNames", "routeRecords", "serviceRecords", "version", "workloadIds"])
    and .version == 2
    and (.lockSha256 | type == "string" and test("^[a-f0-9]{64}$"))
    and (if $prepare == "1" then
      .coreRenderSha256 == null and .combinedRenderSha256 == null
    else
      (.coreRenderSha256 | type == "string" and test("^[a-f0-9]{64}$"))
      and (.combinedRenderSha256 | type == "string" and test("^[a-f0-9]{64}$"))
    end)
    and (.coreEnvFile | type == "string" and length > 0)
    and (.coreEnvironmentRecord | core_record)
    and (.projectName | type == "string" and test("^[a-z0-9][a-z0-9_-]*$"))
    and ($bundle.workloadIds | type == "array" and length > 0 and . == (unique | sort) and all(.[]; type == "string" and test("^[a-z0-9][a-z0-9-]*$")))
    and ($bundle.protectedNetworkNames | type == "array" and . == (unique | sort) and all(.[]; type == "string" and length > 0))
    and ($bundle.networkRecords | type == "array" and length >= ($bundle.workloadIds | length))
    and ($bundle.networkRecords == ($bundle.networkRecords | unique_by(.workloadId, .logicalName) | sort_by(.workloadId, .logicalName)))
    and all($bundle.networkRecords[]; network_record($bundle.projectName))
    and all($bundle.networkRecords[]; . as $record | ($bundle.protectedNetworkNames | index($record.logicalName)) == null)
    and ([$bundle.networkRecords[].workloadId] | unique | sort) == $bundle.workloadIds
    and ($bundle.serviceRecords | type == "array" and length >= ($bundle.workloadIds | length))
    and ($bundle.serviceRecords == ($bundle.serviceRecords | unique_by(.serviceName) | sort_by(.workloadId, .serviceName)))
    and all($bundle.serviceRecords[]; service_record)
    and ([$bundle.serviceRecords[].workloadId] | unique | sort) == $bundle.workloadIds
    and ($bundle.routeRecords | type == "array")
    and ($bundle.routeRecords == ($bundle.routeRecords | unique_by(.slug) | sort_by(.workloadId, .slug)))
    and all($bundle.routeRecords[]; route_record)
    and all($bundle.routeRecords[]; . as $route | any($bundle.serviceRecords[]; .workloadId == $route.workloadId and .serviceName == $route.serviceName))
    and ($bundle.platformExtensionRecords | type == "array")
    and ($bundle.platformExtensionRecords == ($bundle.platformExtensionRecords | unique_by(.workloadId, .serviceName) | sort_by(.workloadId, .serviceName)))
    and all($bundle.platformExtensionRecords[];
      ((keys | sort) == ["networkNames", "serviceName", "workloadId"])
      and (.workloadId | type == "string" and test("^[a-z0-9][a-z0-9-]*$"))
      and (.serviceName | IN("project-router", "postgres", "redis", "nats", "keycloak", "minio", "prometheus"))
      and (.networkNames | type == "array" and length > 0 and . == (unique | sort))
      and all(.networkNames[]; type == "string"))
    and (.environmentRecords | type == "array" and all(.[]; record))
    and (.composeRecords | type == "array" and all(.[]; record))
  ' >/dev/null || {
    echo "Hosted workload activation bundle is invalid." >&2
    exit 1
  }
  locked_core_env=$(printf '%s' "$activation_bundle" | jq -r '.coreEnvFile')
  locked_project_name=$(printf '%s' "$activation_bundle" | jq -r '.projectName')
  workload_env_records=$(printf '%s' "$activation_bundle" | jq -r '.environmentRecords[] | [.path, .sha256, .device, .inode, .uid, (.mode | tostring)] | @tsv')
  workload_compose_records=$(printf '%s' "$activation_bundle" | jq -r '.composeRecords[] | [.path, .sha256, .device, .inode, .uid, (.mode | tostring)] | @tsv')
  [[ "$locked_core_env" = "$ENV_FILE" ]] || {
    echo "Hosted workload lock was prepared for a different core env file." >&2
    exit 1
  }
  [[ "$locked_project_name" = "$PROJECT_NAME" ]] || {
    echo "Hosted workload lock was prepared for a different Compose project name." >&2
    exit 1
  }
  IFS=$'\t' read -r core_env_source core_env_sha core_env_device core_env_inode core_env_uid core_env_mode < <(
    printf '%s' "$activation_bundle" | jq -r '.coreEnvironmentRecord | [.path, .sha256, .device, .inode, .uid, (.mode | tostring)] | @tsv'
  )
  [[ "$core_env_source" = "$ENV_FILE" ]] || {
    printf '%s\n' "Hosted workload core environment record differs from the selected env file." >&2
    exit 1
  }
  [[ "$core_env_uid" = "$(id -u)" && ( "$core_env_mode" = 256 || "$core_env_mode" = 384 ) ]] || {
    printf '%s\n' "Hosted workload core environment must be deployment-owned with mode 0400 or 0600." >&2
    exit 1
  }
  open_locked_handoff "$core_env_source" "$core_env_sha" "$core_env_device" "$core_env_inode" "$core_env_uid" "$core_env_mode"
  compose=(docker compose --env-file "$HANDOFF_REFERENCE")
  while IFS=$'\t' read -r source expected_sha expected_device expected_inode expected_uid expected_mode; do
    [[ -n "$source" ]] || continue
    open_locked_handoff "$source" "$expected_sha" "$expected_device" "$expected_inode" "$expected_uid" "$expected_mode"
    compose+=(--env-file "$HANDOFF_REFERENCE")
  done <<< "$workload_env_records"
else
  runtime_lock_source=$(canonical_existing_file "${HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE:-$ROOT_DIR/config/no-hosted-workloads.lock.json}")
  if [[ "$PREPARE_RESOLVED" = 1 ]]; then
    HOSTED_WORKLOAD_ALLOW_RESOLVED=1 sh "$ROOT_DIR/scripts/hosted-workload-lock.sh" "$runtime_lock_source" verify
  else
    no_workload_lock=$(canonical_existing_file "$ROOT_DIR/config/no-hosted-workloads.lock.json")
    [[ "$runtime_lock_source" = "$no_workload_lock" ]] || {
      printf '%s\n' "A non-empty HOSTED_WORKLOAD_LOCK is required for a hosted runtime lock source." >&2
      exit 1
    }
    jq -e '
      type == "object"
      and ((keys | sort) == ["brokerPolicySha256", "routes", "state", "validatorVersion", "version", "workloads"])
      and .version == 4
      and .validatorVersion == "hosted-contract-v4"
      and .state == "verified"
      and .routes == []
      and .workloads == []
      and .brokerPolicySha256 == "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
    ' "$runtime_lock_source" >/dev/null || {
      printf '%s\n' "Canonical no-hosted-workloads runtime lock is invalid." >&2
      exit 1
    }
  fi
  export HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE=$runtime_lock_source
  compose=(docker compose --env-file "$ENV_FILE")
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
  PLATFORM_RUNTIME_SOURCE_RENDER_SHA256
  PLATFORM_RUNTIME_WORKLOAD_LOCK_SHA256
)
runtime_identity_count=0
for runtime_identity_variable in "${runtime_identity_variables[@]}"; do
  [[ -z "${!runtime_identity_variable:-}" ]] || runtime_identity_count=$((runtime_identity_count + 1))
done
if (( runtime_identity_count != 0 && runtime_identity_count != ${#runtime_identity_variables[@]} )); then
  printf '%s\n' "Runtime identity labels require the complete approved candidate/deployment tuple." >&2
  exit 1
fi
if (( runtime_identity_count == ${#runtime_identity_variables[@]} )); then
  [[ "$PLATFORM_RUNTIME_CANDIDATE_ID" =~ ^[a-f0-9]{64}$ ]] || { printf '%s\n' "Invalid runtime candidate ID." >&2; exit 1; }
  [[ "$PLATFORM_RUNTIME_COMMIT" =~ ^([a-f0-9]{40}|[a-f0-9]{64})$ ]] || { printf '%s\n' "Invalid runtime commit." >&2; exit 1; }
  [[ "$PLATFORM_RUNTIME_TREE" =~ ^([a-f0-9]{40}|[a-f0-9]{64})$ ]] || { printf '%s\n' "Invalid runtime tree." >&2; exit 1; }
  [[ "$PLATFORM_RUNTIME_DEPLOYMENT_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$ ]] || { printf '%s\n' "Invalid runtime deployment ID." >&2; exit 1; }
  [[ "$PLATFORM_RUNTIME_SOURCE_RENDER_SHA256" =~ ^[a-f0-9]{64}$ ]] || { printf '%s\n' "Invalid runtime source render SHA256." >&2; exit 1; }
  [[ "$PLATFORM_RUNTIME_WORKLOAD_LOCK_SHA256" =~ ^[a-f0-9]{64}$ ]] || { printf '%s\n' "Invalid runtime workload lock SHA256." >&2; exit 1; }
  compose+=(-f compose.runtime-identity.yaml)
  if [[ -n "$workload_lock" ]]; then
    runtime_identity_override=$(printf '%s' "$activation_bundle" | jq -c \
      --arg candidateId "$PLATFORM_RUNTIME_CANDIDATE_ID" \
      --arg commit "$PLATFORM_RUNTIME_COMMIT" \
      --arg tree "$PLATFORM_RUNTIME_TREE" \
      --arg deploymentId "$PLATFORM_RUNTIME_DEPLOYMENT_ID" \
      --arg sourceRenderSha256 "$PLATFORM_RUNTIME_SOURCE_RENDER_SHA256" \
      --arg workloadLockSha256 "$PLATFORM_RUNTIME_WORKLOAD_LOCK_SHA256" '
        {
          services: (
            .serviceRecords
            | map({
                key: .serviceName,
                value: {
                  labels: {
                    "com.platform.runtime.candidate-id": $candidateId,
                    "com.platform.runtime.commit": $commit,
                    "com.platform.runtime.tree": $tree,
                    "com.platform.runtime.deployment-id": $deploymentId,
                    "com.platform.runtime.source-render-sha256": $sourceRenderSha256,
                    "com.platform.runtime.workload-lock-sha256": $workloadLockSha256
                  }
                }
              })
            | from_entries
          )
        }
      ')
    open_generated_handoff "$runtime_identity_override"
    compose+=(-f "$HANDOFF_REFERENCE")
  fi
fi

if [[ "${1:-}" == "up" ]]; then
  "${compose[@]}" --profile backup run --rm --no-deps broker-auth-bootstrap
fi

cleanup_handoff
trap - EXIT
exec "${compose[@]}" --profile backup "$@"
