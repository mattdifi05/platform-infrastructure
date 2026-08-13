#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INFRA_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
SYSTEM_NAME=$(/usr/bin/uname -s)
if [[ "$SYSTEM_NAME" == Linux ]]; then
  PRIVILEGED_STATE_BROKER=/usr/local/libexec/platform-activation-broker
else
  PRIVILEGED_STATE_BROKER=$SCRIPT_DIR/platform-activation-broker.py
fi
PRIVILEGED_STATE_BROKER_SHA256=
ACTION=activate
PROJECT_NAME=
ENV_FILE=
RELEASE_CONTEXT=
RELEASE_CONTEXT_JSON=
RELEASE_CONTEXT_SHA256=
RELEASE_ENVIRONMENT_FILE=
RELEASE_ENVIRONMENT_SHA256=
LOCK=
NO_HOSTED=0
CONFIRM=
ACTIVATION_TIMEOUT=${CORE_ACTIVATION_TIMEOUT_SECONDS:-600}
VERIFY_TIMEOUT=${CORE_VERIFY_TIMEOUT_SECONDS:-120}
STOP_TIMEOUT=${CORE_STOP_TIMEOUT_SECONDS:-120}
CANONICAL_DOCKER_HOST=unix:///var/run/docker.sock
CANONICAL_DOCKER_CONTEXT=default
DAEMON_ID=
PARENT_TRANSACTION_ID=${PLATFORM_ACTIVATION_TRANSACTION_ID:-}
PARENT_EXPECTED_DAEMON_ID=${PLATFORM_ACTIVATION_EXPECTED_DAEMON_ID:-}
PARENT_STATE_DIR=${PLATFORM_ACTIVATION_STATE_DIR:-}
BROKER_FD=${PLATFORM_ACTIVATION_BROKER_FD:-}
BROKER_TOKEN=${PLATFORM_ACTIVATION_BROKER_TOKEN:-}
TEMP_DIRECTORY=
CORE_MODEL=
CORE_MODEL_SHA256=
EXPECTED_CORE_MODEL_SHA256=
LOCK_BUNDLE=
MUTATION_STARTED=0
GATE_COMPLETE=0
FAIL_CLOSED_RUNNING=0
declare -a CORE_SERVICES=()

usage() {
  cat >&2 <<'EOF'
Usage: core-stack-activation-gate.sh --project-name NAME --env-file FILE
       --release-context ABSOLUTE_TRUSTED_RELEASE_CONTEXT
       (--lock ABSOLUTE_VERIFIED_LOCK | --no-hosted-workloads)
       [--action validate|activate|stop]
       --confirm ACTIVATE-CORE-STACK

The gate renders the repository-owned core Compose model internally. Compose
files, project directories, profiles and service selections are not
caller-extensible. A verified hosted lock binds the fresh core render to its
coreRenderSha256 receipt. --no-hosted-workloads selects the canonical
zero-workload runtime lock but still activates or stops the core stack.
EOF
  exit 64
}

while (($#)); do
  case "$1" in
    --action)
      (($# >= 2)) || usage
      ACTION=$2
      shift 2
      ;;
    --project-name)
      (($# >= 2)) || usage
      PROJECT_NAME=$2
      shift 2
      ;;
    --env-file)
      (($# >= 2)) || usage
      ENV_FILE=$2
      shift 2
      ;;
    --release-context)
      (($# >= 2)) || usage
      RELEASE_CONTEXT=$2
      shift 2
      ;;
    --lock)
      (($# >= 2)) || usage
      LOCK=$2
      shift 2
      ;;
    --no-hosted-workloads)
      NO_HOSTED=1
      shift
      ;;
    --confirm)
      (($# >= 2)) || usage
      CONFIRM=$2
      shift 2
      ;;
    *) usage ;;
  esac
done

[[ "$ACTION" == validate || "$ACTION" == activate || "$ACTION" == stop ]] || usage
[[ "$PROJECT_NAME" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || usage
[[ "$PROJECT_NAME" == platform_infra_vps ]] || {
  printf '%s\n' "Core activation requires the canonical global project platform_infra_vps." >&2
  exit 64
}
[[ -n "$ENV_FILE" ]] || usage
[[ -n "$RELEASE_CONTEXT" ]] || usage
[[ "$CONFIRM" == ACTIVATE-CORE-STACK ]] || {
  printf '%s\n' "Core activation gate requires --confirm ACTIVATE-CORE-STACK." >&2
  exit 64
}
[[ "$ACTIVATION_TIMEOUT" =~ ^[1-9][0-9]{0,3}$ \
    && "$VERIFY_TIMEOUT" =~ ^[1-9][0-9]{0,3}$ \
    && "$STOP_TIMEOUT" =~ ^[1-9][0-9]{0,3}$ ]] || {
  printf '%s\n' "Core activation timeouts must be bounded positive integers." >&2
  exit 64
}
if (( NO_HOSTED == 1 )); then
  [[ -z "$LOCK" ]] || usage
else
  [[ -n "$LOCK" ]] || {
    printf '%s\n' "A verified hosted lock or explicit --no-hosted-workloads selection is required." >&2
    exit 64
  }
fi
[[ "$PARENT_TRANSACTION_ID" =~ ^[a-f0-9]{64}$ \
    && "$PARENT_EXPECTED_DAEMON_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$ \
    && -n "$PARENT_STATE_DIR" && -n "$BROKER_FD" && -n "$BROKER_TOKEN" ]] || {
  printf '%s\n' "Core activation is internal to one authenticated platform transaction." >&2
  exit 64
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'Required command is unavailable: %s\n' "$1" >&2
    exit 70
  }
}

canonical_file() {
  local candidate=$1 parent base canonical_parent
  [[ "$candidate" == /* \
      && "$candidate" != *[!A-Za-z0-9_./-]* \
      && "$candidate" != *//* \
      && "$candidate" != */../* \
      && "$candidate" != */.. \
      && "$candidate" != */./* \
      && "$candidate" != */. ]] || return 1
  [[ -f "$candidate" && ! -L "$candidate" ]] || return 1
  parent=$(dirname -- "$candidate")
  base=$(basename -- "$candidate")
  canonical_parent=$(CDPATH= cd -- "$parent" && pwd -P) || return 1
  [[ "$canonical_parent/$base" == "$candidate" ]] || return 1
  printf '%s/%s\n' "$canonical_parent" "$base"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{ print $1 }'
  else
    printf '%s\n' "A SHA-256 utility is required." >&2
    return 1
  fi
}

verify_privileged_broker() {
  local identity uid mode links
  [[ -f "$PRIVILEGED_STATE_BROKER" && ! -L "$PRIVILEGED_STATE_BROKER" ]] || return 1
  if [[ "$SYSTEM_NAME" == Linux ]]; then
    [[ "$PRIVILEGED_STATE_BROKER" == /usr/local/libexec/platform-activation-broker ]] || return 1
  else
    [[ "$PRIVILEGED_STATE_BROKER" == "$INFRA_ROOT"/scripts/platform-activation-broker.py ]] || return 1
  fi
  if identity=$(stat -c '%u|%a|%h' "$PRIVILEGED_STATE_BROKER" 2>/dev/null); then
    :
  elif identity=$(stat -f '%u|%Lp|%l' "$PRIVILEGED_STATE_BROKER" 2>/dev/null); then
    :
  else
    return 1
  fi
  IFS='|' read -r uid mode links <<< "$identity"
  if [[ "$SYSTEM_NAME" == Linux ]]; then
    [[ "$uid" == 0 ]] || return 1
  else
    [[ "$uid" == "$(id -u)" ]] || return 1
  fi
  (( (8#$mode & 8#022) == 0 )) || return 1
  [[ "$links" == 1 && "$(sha256_file "$PRIVILEGED_STATE_BROKER")" == "$PRIVILEGED_STATE_BROKER_SHA256" ]]
}

broker_client() {
  local action=$1
  shift
  verify_privileged_broker || return 1
  "$PRIVILEGED_STATE_BROKER" client "$BROKER_FD" "$BROKER_TOKEN" "$action" "$@"
}

assert_broker_session() {
  local response
  response=$(broker_client ping) || return 1
  printf '%s' "$response" | jq -e \
    --arg coordinator "$PARENT_STATE_DIR" \
    --arg version "platform-activation-broker/v1" '
      .version == $version
      and .coordinator == $coordinator
      and (.supervisorPid | type == "number" and . > 1)
    ' >/dev/null
}

verify_release_context_unchanged() {
  local current current_context_sha current_environment_sha canonical_environment
  current=$(node "$SCRIPT_DIR/platform-release-context.mjs" read "$RELEASE_CONTEXT") || return 1
  current_context_sha=$(sha256_file "$RELEASE_CONTEXT") || return 1
  canonical_environment=$(canonical_file "$ENV_FILE") || return 1
  current_environment_sha=$(sha256_file "$ENV_FILE") || return 1
  [[ "$current" == "$RELEASE_CONTEXT_JSON" \
      && "$current_context_sha" == "$RELEASE_CONTEXT_SHA256" \
      && "$canonical_environment" == "$RELEASE_ENVIRONMENT_FILE" \
      && "$ENV_FILE" == "$RELEASE_ENVIRONMENT_FILE" \
      && "$current_environment_sha" == "$RELEASE_ENVIRONMENT_SHA256" ]] || {
    printf '%s\n' "Trusted release context or environment changed between core activation stages." >&2
    return 1
  }
}

load_lock_bundle() {
  HOSTED_WORKLOAD_ALLOW_RESOLVED=0 \
    sh "$SCRIPT_DIR/hosted-workload-lock.sh" "$LOCK" activation-bundle
}

validate_lock_bundle() {
  local bundle=$1
  printf '%s' "$bundle" | jq -e --arg projectName "$PROJECT_NAME" '
    type == "object"
    and .projectName == $projectName
    and (.lockSha256 | type == "string" and test("^[a-f0-9]{64}$"))
    and (.coreRenderSha256 | type == "string" and test("^[a-f0-9]{64}$"))
    and (.combinedRenderSha256 | type == "string" and test("^[a-f0-9]{64}$"))
    and (.workloadIds | type == "array" and length > 0)
    and (.workloadIds == (.workloadIds | unique | sort))
    and all(.workloadIds[]; type == "string" and test("^[a-z][a-z0-9-]{1,60}$"))
    and (.serviceRecords | type == "array" and length > 0)
  ' >/dev/null
}

render_core_model() {
  local output=$1
  if (( NO_HOSTED == 1 )); then
    PLATFORM_TRUSTED_RELEASE_CONTEXT="$RELEASE_CONTEXT" \
    COMPOSE_ENV_FILE="$ENV_FILE" \
    COMPOSE_PROJECT_NAME="$PROJECT_NAME" \
    HOSTED_WORKLOAD_LOCK= \
    HOSTED_WORKLOAD_MODE=no-hosted \
    HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE="$INFRA_ROOT/config/no-hosted-workloads.lock.json" \
    HOSTED_WORKLOAD_ALLOW_RESOLVED=0 \
    HOSTED_WORKLOAD_PREPARE_RESOLVED=0 \
      bash "$SCRIPT_DIR/compose-vps.sh" config --format json > "$output"
  else
    PLATFORM_TRUSTED_RELEASE_CONTEXT="$RELEASE_CONTEXT" \
    COMPOSE_ENV_FILE="$ENV_FILE" \
    COMPOSE_PROJECT_NAME="$PROJECT_NAME" \
    HOSTED_WORKLOAD_LOCK= \
    HOSTED_WORKLOAD_MODE=no-hosted \
    HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE="$INFRA_ROOT/config/no-hosted-workloads.lock.json" \
    HOSTED_WORKLOAD_ALLOW_RESOLVED=0 \
    HOSTED_WORKLOAD_PREPARE_RESOLVED=0 \
      bash "$SCRIPT_DIR/compose-vps.sh" config --format json > "$output"
  fi
  chmod 600 "$output"
}

validate_core_model() {
  local model=$1
  jq -e '
    type == "object"
    and (.services | type == "object" and length > 0)
    and all(.services | to_entries[];
      (.key | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9_.-]*$"))
      and (.value | type == "object")
      and (
        (.value.labels? == null)
        or (
          (.value.labels | type == "object")
          and ((.value.labels | has("com.platform.workload-id")) | not)
        )
      )
    )
  ' "$model" >/dev/null
}

verify_model() {
  local actual_sha
  [[ -f "$CORE_MODEL" && ! -L "$CORE_MODEL" ]] || return 1
  actual_sha=$(sha256_file "$CORE_MODEL") || return 1
  [[ "$actual_sha" == "$CORE_MODEL_SHA256" \
      && "$actual_sha" == "$EXPECTED_CORE_MODEL_SHA256" ]] || return 1
  validate_core_model "$CORE_MODEL"
}

verify_inputs() {
  local current_bundle
  assert_broker_session || return 1
  verify_release_context_unchanged || return 1
  verify_model || {
    printf '%s\n' "Pinned core Compose model changed or is no longer core-only." >&2
    return 1
  }
  if (( NO_HOSTED == 0 )); then
    current_bundle=$(load_lock_bundle) || return 1
    [[ "$current_bundle" == "$LOCK_BUNDLE" ]] || {
      printf '%s\n' "Verified hosted lock changed between core activation stages." >&2
      return 1
    }
  fi
}

validate_docker_transport() {
  case "${DOCKER_HOST:-}" in
    ""|"$CANONICAL_DOCKER_HOST") ;;
    *)
      printf 'Non-local DOCKER_HOST is forbidden: %s\n' "$DOCKER_HOST" >&2
      return 1
      ;;
  esac
  case "${DOCKER_CONTEXT:-}" in
    ""|"$CANONICAL_DOCKER_CONTEXT") ;;
    *)
      printf 'Non-default DOCKER_CONTEXT is forbidden: %s\n' "$DOCKER_CONTEXT" >&2
      return 1
      ;;
  esac
  export DOCKER_HOST=$CANONICAL_DOCKER_HOST
  export DOCKER_CONTEXT=$CANONICAL_DOCKER_CONTEXT
}

read_daemon_id() {
  local daemon_id
  daemon_id=$(
    timeout "$VERIFY_TIMEOUT" \
      docker --host "$CANONICAL_DOCKER_HOST" info --format '{{.ID}}'
  ) || return 1
  [[ "$daemon_id" =~ ^[A-Za-z0-9][A-Za-z0-9_.:-]{5,127}$ ]] || {
    printf '%s\n' "The canonical local Docker daemon returned an invalid identity." >&2
    return 1
  }
  printf '%s\n' "$daemon_id"
}

verify_daemon() {
  local current_daemon_id
  current_daemon_id=$(read_daemon_id) || return 1
  [[ "$current_daemon_id" == "$DAEMON_ID" ]] || {
    printf '%s\n' "Docker daemon identity changed during core activation." >&2
    return 1
  }
}

create_core_services() {
  (("${#CORE_SERVICES[@]}" > 0)) || return 1
  verify_daemon || return 1
  timeout "$ACTIVATION_TIMEOUT" \
    docker --host "$CANONICAL_DOCKER_HOST" compose \
      --project-directory "$INFRA_ROOT" --profile backup \
      -p "$PROJECT_NAME" -f "$CORE_MODEL" \
      create --no-build --pull never --no-deps "${CORE_SERVICES[@]}" || return 1
  verify_daemon
}

start_core_services() {
  local ids
  (("${#CORE_SERVICES[@]}" > 0)) || return 1
  verify_daemon || return 1
  ids=$(
    timeout "$VERIFY_TIMEOUT" \
      docker --host "$CANONICAL_DOCKER_HOST" compose \
        --project-directory "$INFRA_ROOT" --profile backup \
        -p "$PROJECT_NAME" -f "$CORE_MODEL" \
        ps -aq "${CORE_SERVICES[@]}"
  ) || return 1
  [[ "$(printf '%s\n' "$ids" | awk 'NF { count += 1 } END { print count + 0 }')" -eq "${#CORE_SERVICES[@]}" ]] || return 1
  timeout "$ACTIVATION_TIMEOUT" \
    docker --host "$CANONICAL_DOCKER_HOST" start $ids >/dev/null || return 1
  verify_daemon
}

verify_core_running() {
  local ids inspections deadline
  ids=$(
    timeout "$VERIFY_TIMEOUT" \
      docker --host "$CANONICAL_DOCKER_HOST" compose \
        --project-directory "$INFRA_ROOT" --profile backup \
        -p "$PROJECT_NAME" -f "$CORE_MODEL" \
        ps -aq "${CORE_SERVICES[@]}"
  ) || return 1
  [[ "$(printf '%s\n' "$ids" | awk 'NF { count += 1 } END { print count + 0 }')" -eq "${#CORE_SERVICES[@]}" ]] || return 1
  deadline=$((SECONDS + VERIFY_TIMEOUT))
  while :; do
    verify_daemon || return 1
    inspections=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" inspect $ids) || return 1
    if printf '%s' "$inspections" | jq -e --arg project "$PROJECT_NAME" --slurpfile model "$CORE_MODEL" '
      length == ($model[0].services | with_entries(select(.key as $name | ["project-router", "postgres", "redis", "nats", "keycloak", "minio", "prometheus"] | index($name) | not)) | length)
      and all(.[];
        .Config.Labels["com.docker.compose.project"] == $project
        and (.Config.Labels["com.docker.compose.service"] as $service
          | .Config.Image == $model[0].services[$service].image)
        and .State.Running == true
        and (if .Config.Healthcheck? != null then .State.Health.Status == "healthy" else true end))
    ' >/dev/null; then
      return 0
    fi
    (( SECONDS < deadline )) || return 1
    sleep 1
  done
}

stop_and_prove_core() {
  local running
  (("${#CORE_SERVICES[@]}" > 0)) || return 1
  verify_daemon || return 1
  timeout "$STOP_TIMEOUT" \
    docker --host "$CANONICAL_DOCKER_HOST" compose \
      --project-directory "$INFRA_ROOT" --profile backup \
      -p "$PROJECT_NAME" -f "$CORE_MODEL" \
      stop --timeout 30 "${CORE_SERVICES[@]}" || return 1
  verify_daemon || return 1
  running=$(
    timeout "$VERIFY_TIMEOUT" \
      docker --host "$CANONICAL_DOCKER_HOST" compose \
        --project-directory "$INFRA_ROOT" --profile backup \
        -p "$PROJECT_NAME" -f "$CORE_MODEL" \
        ps --status running -q "${CORE_SERVICES[@]}"
  ) || return 1
  verify_daemon || return 1
  [[ -z "$running" ]] || {
    printf '%s\n' "Core service stop could not be proven." >&2
    return 1
  }
}

cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  set +e
  if (( status != 0 && MUTATION_STARTED == 1 && GATE_COMPLETE == 0 && FAIL_CLOSED_RUNNING == 0 )); then
    FAIL_CLOSED_RUNNING=1
    if stop_and_prove_core; then
      status=72
      printf '%s\n' "Core activation failed; every exact core service is proven stopped." >&2
    else
      status=73
      printf '%s\n' "Core activation failed and a complete core stop is not proven." >&2
    fi
  elif (( status != 0 )); then
    status=70
  fi
  [[ -z "$TEMP_DIRECTORY" || ! -d "$TEMP_DIRECTORY" ]] || rm -rf "$TEMP_DIRECTORY"
  exit "$status"
}
signal_failure() {
  local signal_status=$1
  trap - HUP INT TERM
  exit "$signal_status"
}
trap cleanup EXIT
trap 'signal_failure 129' HUP
trap 'signal_failure 130' INT
trap 'signal_failure 143' TERM

for command in awk bash docker jq node sh sleep stat timeout; do
  require_command "$command"
done

PRIVILEGED_STATE_BROKER_SHA256=$(sha256_file "$PRIVILEGED_STATE_BROKER") || exit 70
verify_privileged_broker || {
  printf '%s\n' "Privileged activation broker is not the immutable fixed helper." >&2
  exit 70
}
assert_broker_session || {
  printf '%s\n' "Core activation did not inherit the authenticated platform broker session." >&2
  exit 70
}

RELEASE_CONTEXT_JSON=$(node "$SCRIPT_DIR/platform-release-context.mjs" read "$RELEASE_CONTEXT") || exit 70
RELEASE_CONTEXT_SHA256=$(sha256_file "$RELEASE_CONTEXT") || exit 70
RELEASE_ENVIRONMENT_FILE=$(printf '%s' "$RELEASE_CONTEXT_JSON" | jq -er '.environmentFile') || exit 70
if [[ "$ENV_FILE" != /* ]]; then
  ENV_FILE="$INFRA_ROOT/$ENV_FILE"
fi
[[ "$ENV_FILE" == "$RELEASE_ENVIRONMENT_FILE" ]] || {
  printf '%s\n' "Compose env file is not the exact environment file authenticated by the trusted release context." >&2
  exit 70
}
ENV_FILE=$(canonical_file "$ENV_FILE") || {
  printf '%s\n' "Trusted release environment must be an exact canonical regular file." >&2
  exit 70
}
[[ "$ENV_FILE" == "$RELEASE_ENVIRONMENT_FILE" ]] || {
  printf '%s\n' "Trusted release environment canonical identity changed." >&2
  exit 70
}
RELEASE_ENVIRONMENT_SHA256=$(sha256_file "$ENV_FILE") || exit 70
printf '%s' "$RELEASE_CONTEXT_JSON" | jq -e \
  --arg releaseRoot "$INFRA_ROOT" \
  --arg environmentFile "$ENV_FILE" \
  --arg environmentSha256 "$RELEASE_ENVIRONMENT_SHA256" \
  --arg projectName "$PROJECT_NAME" \
  --arg coordinator "$PARENT_STATE_DIR" '
    .releaseRoot == $releaseRoot
    and .environmentFile == $environmentFile
    and .environmentSha256 == $environmentSha256
    and .projectName == $projectName
    and .activationCoordinatorRoot == $coordinator
  ' >/dev/null || {
    printf '%s\n' "Trusted release context does not bind this exact core release, environment, project and coordinator." >&2
    exit 70
  }

broker_snapshot=$(broker_client snapshot) || exit 70
printf '%s' "$broker_snapshot" | jq -e \
  --arg transactionId "$PARENT_TRANSACTION_ID" \
  --arg project "$PROJECT_NAME" \
  --arg releaseContextPath "$RELEASE_CONTEXT" \
  --arg releaseContextSha256 "$RELEASE_CONTEXT_SHA256" '
    .journal.version == 2 and .journal.state == "pending"
    and .journal.transactionId == $transactionId
    and .journal.projectName == $project
    and .journal.releaseContextPath == $releaseContextPath
    and .journal.releaseContextSha256 == $releaseContextSha256
    and .journal.phase == "intent"
  ' >/dev/null || {
    printf '%s\n' "Core activation parent journal does not match this transaction." >&2
    exit 70
  }

if (( NO_HOSTED == 0 )); then
  LOCK=$(canonical_file "$LOCK") || {
    printf '%s\n' "Hosted workload lock must be an exact canonical absolute regular file." >&2
    exit 70
  }
  LOCK_BUNDLE=$(load_lock_bundle) || {
    printf '%s\n' "Hosted workload lock is not verified." >&2
    exit 70
  }
  validate_lock_bundle "$LOCK_BUNDLE" || {
    printf '%s\n' "Hosted workload activation bundle is invalid for core activation." >&2
    exit 70
  }
  EXPECTED_CORE_MODEL_SHA256=$(printf '%s' "$LOCK_BUNDLE" | jq -r '.coreRenderSha256')
fi

validate_docker_transport || exit 70
DAEMON_ID=$(read_daemon_id) || {
  printf '%s\n' "Canonical local Docker daemon identity could not be pinned." >&2
  exit 70
}
[[ "$DAEMON_ID" == "$PARENT_EXPECTED_DAEMON_ID" ]] || {
  printf '%s\n' "Core activation daemon differs from the parent transaction." >&2
  exit 70
}
verify_daemon || exit 70

umask 077
TEMP_DIRECTORY=$(mktemp -d "${TMPDIR:-/tmp}/core-activation-gate.XXXXXX")
chmod 700 "$TEMP_DIRECTORY"
CORE_MODEL=$TEMP_DIRECTORY/core-compose.json
render_core_model "$CORE_MODEL"
CORE_MODEL_SHA256=$(sha256_file "$CORE_MODEL")
if (( NO_HOSTED == 1 )); then
  EXPECTED_CORE_MODEL_SHA256=$CORE_MODEL_SHA256
fi
verify_inputs || {
  printf '%s\n' "Fresh Compose render is not the expected exact core-only model." >&2
  exit 70
}
verify_daemon || exit 70

while IFS= read -r service_name; do
  [[ -n "$service_name" ]] && CORE_SERVICES+=("$service_name")
done < <(jq -r '.services | keys[] | select(IN("project-router", "postgres", "redis", "nats", "keycloak", "minio", "prometheus") | not)' "$CORE_MODEL")
(("${#CORE_SERVICES[@]}" > 0)) || {
  printf '%s\n' "The exact rendered core service set is empty." >&2
  exit 70
}

verify_daemon || exit 70

if [[ "$ACTION" == validate ]]; then
  printf 'Core model validation completed inside transaction %s.\n' "$PARENT_TRANSACTION_ID"
  exit 0
fi

if [[ "$ACTION" == stop ]]; then
  verify_inputs
  MUTATION_STARTED=1
  stop_and_prove_core
  verify_inputs
  GATE_COMPLETE=1
  MUTATION_STARTED=0
  printf 'Proven stopped core service set for project %s: %s\n' "$PROJECT_NAME" "${CORE_SERVICES[*]}"
  exit 0
fi

verify_inputs
MUTATION_STARTED=1
create_core_services
verify_inputs
start_core_services
verify_inputs
verify_daemon
verify_core_running
verify_inputs
verify_daemon
GATE_COMPLETE=1
MUTATION_STARTED=0
printf 'Core activation gate completed for project %s and services: %s\n' "$PROJECT_NAME" "${CORE_SERVICES[*]}"
