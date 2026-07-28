#!/usr/bin/env bash
set -euo pipefail

ORIGINAL_ARGUMENTS=("$@")
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INFRA_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
SYSTEM_NAME=$(/usr/bin/uname -s)
if [[ "$SYSTEM_NAME" == Linux ]]; then
  PRIVILEGED_STATE_BROKER=/usr/local/libexec/platform-activation-broker
  PRIVILEGED_FIREWALL_HELPER=/usr/local/libexec/platform-workload-egress-firewall
else
  PRIVILEGED_STATE_BROKER=$SCRIPT_DIR/platform-activation-broker.py
  PRIVILEGED_FIREWALL_HELPER=$SCRIPT_DIR/workload-egress-firewall.sh
fi
PRIVILEGED_STATE_BROKER_SHA256=
PRIVILEGED_FIREWALL_HELPER_SHA256=
ACTION=activate
PROJECT_NAME=
ENV_FILE=
RELEASE_CONTEXT=
LOCK=
PREVIOUS_LOCK=
NO_HOSTED=0
RECOVER_PENDING=0
RUN_POSTDEPLOY=0
CONFIRM=
ACTIVATION_TIMEOUT=${HOSTED_ACTIVATION_TIMEOUT_SECONDS:-600}
VERIFY_TIMEOUT=${HOSTED_VERIFY_TIMEOUT_SECONDS:-120}
STOP_TIMEOUT=${HOSTED_STOP_TIMEOUT_SECONDS:-120}
MUTATION_STARTED=0
GATE_COMPLETE=0
ROLLBACK_RUNNING=0
TEMP_DIRECTORY=
CURRENT_MODEL=
PREVIOUS_MODEL=
CURRENT_RUNTIME_MODEL=
PREVIOUS_RUNTIME_MODEL=
FALLBACK_MODEL=
FALLBACK_RUNTIME_MODEL=
CURRENT_MODEL_SHA256=
PREVIOUS_MODEL_SHA256=
CURRENT_LOCK_SHA256=
PREVIOUS_LOCK_SHA256=
CURRENT_CORE_SHA256=
CURRENT_COMBINED_SHA256=
CURRENT_BUNDLE=
PREVIOUS_BUNDLE=
CANONICAL_DOCKER_HOST=unix:///var/run/docker.sock
EXPECTED_DAEMON_ID=
RELEASE_CONTEXT_JSON=
RELEASE_CONTEXT_SHA256=
RELEASE_REPOSITORY=
RELEASE_COMMIT_SHA=
RELEASE_TREE_SHA=
RELEASE_SOURCE_ARCHIVE_SHA256=
RELEASE_ID=
RELEASE_STATE_ID=
RELEASE_STATE_ROOT=
RELEASE_DECISION_ID=
RUNTIME_CANDIDATE_ID=
RUNTIME_SOURCE_RENDER_SHA256=
RUNTIME_WORKLOAD_LOCK_SHA256=
STATE_DIR=${PLATFORM_ACTIVATION_STATE_DIR:-${XDG_STATE_HOME:-${HOME:?HOME is required}/.local/state}/platform-infrastructure/activation}
TRANSACTION_ID=
JOURNAL=
ACTIVE_RECEIPT=
BROKER_FD=${PLATFORM_ACTIVATION_BROKER_FD:-}
BROKER_TOKEN=${PLATFORM_ACTIVATION_BROKER_TOKEN:-}
JOURNAL_PHASE=
CONTAINER_RECEIPTS='[]'
NETWORK_RECEIPTS='[]'
VOLUME_RECEIPTS='[]'
NO_HOSTED_LOCK=$INFRA_ROOT/config/no-hosted-workloads.lock.json
PLATFORM_EXTENSION_NAMES=(project-router postgres redis nats keycloak minio prometheus)
declare -a CURRENT_SERVICES=()
declare -a PREVIOUS_SERVICES=()
declare -a CURRENT_EXTENSIONS=()
declare -a PREVIOUS_EXTENSIONS=()
declare -a CURRENT_ALL_SERVICES=()
declare -a PREVIOUS_ALL_SERVICES=()

usage() {
  cat >&2 <<'EOF'
Usage: hosted-workload-activation-gate.sh --project-name NAME --env-file FILE
       --release-context ABSOLUTE_TRUSTED_RELEASE_CONTEXT
       (--lock ABSOLUTE_VERIFIED_LOCK | --no-hosted-workloads)
       [--previous-lock ABSOLUTE_VERIFIED_LOCK]
       [--action activate|stop] [--recover-pending] [--run-postdeploy]
       --confirm ACTIVATE-HOSTED-WORKLOADS

The gate renders the repository-owned Compose model internally. Compose files,
project directories, profiles, environment overlays and service selections are
not caller-extensible. A missing lock is an error; zero hosted workloads must
be stated explicitly and transitions to the canonical empty v4 model.
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
    --previous-lock)
      (($# >= 2)) || usage
      PREVIOUS_LOCK=$2
      shift 2
      ;;
    --no-hosted-workloads)
      NO_HOSTED=1
      shift
      ;;
    --recover-pending)
      RECOVER_PENDING=1
      shift
      ;;
    --run-postdeploy)
      RUN_POSTDEPLOY=1
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

[[ "$ACTION" == activate || "$ACTION" == stop ]] || usage
[[ "$PROJECT_NAME" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || usage
[[ "$CONFIRM" == ACTIVATE-HOSTED-WORKLOADS ]] || {
  printf '%s\n' "Activation gate requires --confirm ACTIVATE-HOSTED-WORKLOADS." >&2
  exit 64
}
[[ "$ACTIVATION_TIMEOUT" =~ ^[1-9][0-9]{0,3}$ && "$VERIFY_TIMEOUT" =~ ^[1-9][0-9]{0,3}$ && "$STOP_TIMEOUT" =~ ^[1-9][0-9]{0,3}$ ]] || {
  printf '%s\n' "Hosted workload timeouts must be bounded positive integers." >&2
  exit 64
}
[[ -n "$ENV_FILE" ]] || usage
[[ -n "$RELEASE_CONTEXT" ]] || usage
if (( NO_HOSTED == 1 )); then
  [[ -z "$LOCK" && "$ACTION" == activate ]] || usage
fi
if (( NO_HOSTED == 0 )) && [[ -z "$LOCK" ]]; then
  printf '%s\n' "A verified hosted workload lock is required; use --no-hosted-workloads explicitly for the canonical empty state." >&2
  exit 64
fi
[[ "$PROJECT_NAME" == platform_infra_vps ]] || {
  printf '%s\n' "Hosted activation is global and requires the canonical project platform_infra_vps." >&2
  exit 64
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'Required command is unavailable: %s\n' "$1" >&2
    exit 70
  }
}

bind_local_docker_transport() {
  case "${DOCKER_HOST:-}" in
    ""|"$CANONICAL_DOCKER_HOST") ;;
    *) printf 'Caller-selected DOCKER_HOST is forbidden: %s\n' "$DOCKER_HOST" >&2; return 1 ;;
  esac
  case "${DOCKER_CONTEXT:-}" in
    ""|default) ;;
    *) printf 'Caller-selected DOCKER_CONTEXT is forbidden: %s\n' "$DOCKER_CONTEXT" >&2; return 1 ;;
  esac
  unset DOCKER_CONTEXT
  export DOCKER_HOST=$CANONICAL_DOCKER_HOST
}

daemon_id() {
  timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" info --format '{{.ID}}'
}

assert_daemon_identity() {
  local current
  current=$(daemon_id) || return 1
  [[ -n "$EXPECTED_DAEMON_ID" && "$current" == "$EXPECTED_DAEMON_ID" ]] || {
    printf 'Docker daemon identity changed: expected=%s actual=%s\n' "$EXPECTED_DAEMON_ID" "${current:-unavailable}" >&2
    return 1
  }
}

canonical_file() {
  local candidate=$1 parent base canonical_parent
  [[ "$candidate" == /* && "$candidate" != *[!A-Za-z0-9_./-]* && "$candidate" != *//* && "$candidate" != */../* && "$candidate" != */.. ]] || return 1
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
  else
    shasum -a 256 "$1" | awk '{ print $1 }'
  fi
}

broker_client() {
  local action=$1
  shift
  verify_privileged_helpers || return 1
  "$PRIVILEGED_STATE_BROKER" client "$BROKER_FD" "$BROKER_TOKEN" "$action" "$@"
}

assert_broker_session() {
  local response
  response=$(broker_client ping) || return 1
  printf '%s' "$response" | jq -e \
    --arg coordinator "$STATE_DIR" \
    --arg version "platform-activation-broker/v1" '
      .version == $version
      and .coordinator == $coordinator
      and (.supervisorPid | type == "number" and . > 1)
    ' >/dev/null
}

verify_privileged_helper() {
  local helper=$1 expected_sha=$2 identity uid mode links
  [[ -f "$helper" && ! -L "$helper" ]] || return 1
  if [[ "$SYSTEM_NAME" == Linux ]]; then
    [[ "$helper" == /usr/local/libexec/platform-activation-broker \
      || "$helper" == /usr/local/libexec/platform-workload-egress-firewall ]] || return 1
  else
    [[ "$helper" == "$INFRA_ROOT"/scripts/* ]] || return 1
  fi
  identity=$(stat -f '%u|%Lp|%l' "$helper" 2>/dev/null || stat -c '%u|%a|%h' "$helper") || return 1
  IFS='|' read -r uid mode links <<< "$identity"
  if [[ "$SYSTEM_NAME" == Linux ]]; then
    [[ "$uid" == 0 ]] || return 1
  else
    [[ "$uid" == "$(id -u)" ]] || return 1
  fi
  (( (8#$mode & 8#022) == 0 )) || return 1
  [[ "$links" == 1 && "$(sha256_file "$helper")" == "$expected_sha" ]] || return 1
}

verify_privileged_helpers() {
  verify_privileged_helper "$PRIVILEGED_STATE_BROKER" "$PRIVILEGED_STATE_BROKER_SHA256" \
    && verify_privileged_helper "$PRIVILEGED_FIREWALL_HELPER" "$PRIVILEGED_FIREWALL_HELPER_SHA256"
}

journal_phase() {
  local phase=$1 detail=${2:-}
  if [[ "$phase" == intent ]]; then
    local expected_previous_sha=
    [[ -z "$ACTIVE_RECEIPT" ]] || expected_previous_sha=$(printf '%s' "$ACTIVE_RECEIPT" | jq -r '.releaseContextSha256')
    JOURNAL=$(broker_client begin \
      "$TRANSACTION_ID" "$RELEASE_CONTEXT" "$EXPECTED_DAEMON_ID" \
      "$([[ "$NO_HOSTED" == 1 ]] && printf no-hosted || printf hosted)" \
      "$LOCK" "$PREVIOUS_LOCK" "$detail" "$expected_previous_sha") || return 1
  else
    [[ -n "$JOURNAL_PHASE" && "$phase" != complete && "$phase" != recovered ]] || return 1
    JOURNAL=$(broker_client advance "$TRANSACTION_ID" "$JOURNAL_PHASE" "$phase" "$detail") || return 1
  fi
  JOURNAL_PHASE=$phase
}

unique_array() {
  printf '%s\n' "$@" | awk 'NF && !seen[$0]++'
}

model_extension_services() {
  local model=$1 service
  for service in "${PLATFORM_EXTENSION_NAMES[@]}"; do
    jq -e --arg service "$service" '.services[$service] | type == "object"' "$model" >/dev/null \
      && printf '%s\n' "$service"
  done
}

load_bundle() {
  local lock_path=$1
  HOSTED_WORKLOAD_ALLOW_RESOLVED=0 \
    sh "$SCRIPT_DIR/hosted-workload-lock.sh" "$lock_path" activation-bundle
}

validate_bundle() {
  local bundle=$1
  printf '%s' "$bundle" | jq -e --arg projectName "$PROJECT_NAME" '
    def prefix_disjoint:
      . as $ids
      | all($ids[];
          . as $left
          | all($ids[];
              . as $right
              | $left == $right
                or (((($left | startswith($right + "-")) | not))
                  and ((($right | startswith($left + "-")) | not)))));
    def protected_resource_names:
      type == "object"
      and ((keys | sort) == ["configs", "networks", "secrets", "services", "volumes"])
      and all(.[]; type == "array" and . == (unique | sort) and all(.[]; type == "string" and length > 0));
    def service_owner($name; $ids):
      [$ids[] as $id | select($name | startswith($id + "-")) | $id]
      | if length == 1 then .[0] else null end;
    def network_owner($name; $ids):
      [$ids[] as $id | select($name | startswith(($id | gsub("-"; "_")) + "_")) | $id]
      | if length == 1 then .[0] else null end;
    def service_record($ids):
      . as $record
      | type == "object"
      and ((keys | sort) == ["serviceName", "workloadId"])
      and (.workloadId | type == "string" and test("^[a-z][a-z0-9-]{1,62}$"))
      and (.serviceName | type == "string" and test("^[a-z][a-z0-9-]{1,62}$"))
      and $record.workloadId == service_owner($record.serviceName; $ids);
    def network_record($ids; $projectName):
      . as $record
      | type == "object"
      and ((keys | sort) == ["logicalName", "physicalName", "workloadId"])
      and (.workloadId | type == "string" and test("^[a-z][a-z0-9-]{1,62}$"))
      and (.logicalName | type == "string" and test("^[a-z0-9][a-z0-9_]*$"))
      and $record.workloadId == network_owner($record.logicalName; $ids)
      and (($record.logicalName | split("_") | last) as $zone
        | ($zone | IN("ingress", "postgres", "cache", "bus", "identity", "storage", "observability", "egress"))
        and $record.logicalName == (($record.workloadId | gsub("-"; "_")) + "_" + $zone))
      and $record.physicalName == ($projectName + "_" + $record.logicalName);
    def extension_record:
      type == "object"
      and ((keys | sort) == ["networkNames", "serviceName", "workloadId"])
      and (.workloadId | type == "string" and test("^[a-z][a-z0-9-]{1,62}$"))
      and (.serviceName | IN("project-router", "postgres", "redis", "nats", "keycloak", "minio", "prometheus"))
      and (.networkNames | type == "array" and length > 0 and . == (unique | sort))
      and all(.networkNames[]; type == "string" and length > 0);
    def route_record($ids):
      . as $record
      | type == "object"
      and ((keys | sort) == ["port", "serviceName", "slug", "upstream", "workloadId"])
      and (.workloadId | type == "string" and test("^[a-z][a-z0-9-]{1,62}$"))
      and (.slug | type == "string" and test("^[a-z][a-z0-9-]{1,62}$"))
      and (.serviceName | type == "string" and test("^[a-z][a-z0-9-]{1,62}$"))
      and (.port | type == "number" and floor == . and . >= 1 and . <= 65535)
      and $record.workloadId == service_owner($record.serviceName; $ids)
      and $record.upstream == ("http://" + $record.serviceName + ":" + ($record.port | tostring));
    . as $bundle
    | type == "object"
    and $bundle.version == 2
    and $bundle.projectName == $projectName
    and ($bundle.lockSha256 | type == "string" and test("^[a-f0-9]{64}$"))
    and ($bundle.coreRenderSha256 | type == "string" and test("^[a-f0-9]{64}$"))
    and ($bundle.combinedRenderSha256 | type == "string" and test("^[a-f0-9]{64}$"))
    and ($bundle.workloadIds | type == "array" and length > 0 and . == (unique | sort)
      and prefix_disjoint and all(.[]; type == "string" and test("^[a-z][a-z0-9-]{1,62}$")))
    and ($bundle.protectedNetworkNames | type == "array" and . == (unique | sort)
      and all(.[]; type == "string" and length > 0))
    and ($bundle.protectedResourceNames | protected_resource_names)
    and ($bundle.protectedResourceNames.networks == $bundle.protectedNetworkNames)
    and ($bundle.networkRecords | type == "array" and length >= ($bundle.workloadIds | length))
    and ($bundle.networkRecords == ($bundle.networkRecords | unique_by(.logicalName) | sort_by(.workloadId, .logicalName)))
    and all($bundle.networkRecords[]; network_record($bundle.workloadIds; $projectName))
    and (([$bundle.networkRecords[].workloadId] | unique | sort) == $bundle.workloadIds)
    and all($bundle.networkRecords[];
      . as $record | ($bundle.protectedResourceNames.networks | index($record.logicalName)) == null)
    and ($bundle.serviceRecords | type == "array" and length >= ($bundle.workloadIds | length))
    and ($bundle.serviceRecords == ($bundle.serviceRecords | unique_by(.serviceName) | sort_by(.workloadId, .serviceName)))
    and all($bundle.serviceRecords[]; service_record($bundle.workloadIds))
    and (([$bundle.serviceRecords[].workloadId] | unique | sort) == $bundle.workloadIds)
    and all($bundle.serviceRecords[];
      . as $record | ($bundle.protectedResourceNames.services | index($record.serviceName)) == null)
    and ($bundle.platformExtensionRecords | type == "array" and length > 0)
    and ($bundle.platformExtensionRecords == ($bundle.platformExtensionRecords | unique_by(.workloadId, .serviceName) | sort_by(.workloadId, .serviceName)))
    and all($bundle.platformExtensionRecords[]; extension_record)
    and (([$bundle.platformExtensionRecords[].workloadId] | unique | sort) == $bundle.workloadIds)
    and all($bundle.platformExtensionRecords[];
      . as $record
      | all($record.networkNames[];
          . as $networkName
          | any($bundle.networkRecords[];
              .workloadId == $record.workloadId and .logicalName == $networkName)))
    and ($bundle.routeRecords | type == "array")
    and ($bundle.routeRecords == ($bundle.routeRecords | unique_by(.slug) | sort_by(.workloadId, .slug)))
    and all($bundle.routeRecords[]; route_record($bundle.workloadIds))
    and all($bundle.routeRecords[];
      . as $route
      | any($bundle.serviceRecords[];
          .workloadId == $route.workloadId and .serviceName == $route.serviceName))
  ' >/dev/null
}

verify_extension_records() {
  local bundle=$1 core_model=$2 combined_model=$3
  printf '%s' "$bundle" | jq -e \
    --slurpfile core "$core_model" \
    --slurpfile combined "$combined_model" '
      . as $bundle
      | ($bundle.networkRecords
          | map({key: .logicalName, value: .workloadId})
          | from_entries) as $lockedNetworkOwners
      | [
          .platformExtensionRecords[] as $record
          | $record.networkNames[]
          | {
              workloadId: $record.workloadId,
              serviceName: $record.serviceName,
              networkName: .
            }
        ] | sort_by(.workloadId, .serviceName, .networkName) as $expected
      | [
          $combined[0].services
          | to_entries[]
          | select(.key | IN("project-router", "postgres", "redis", "nats", "keycloak", "minio", "prometheus"))
          | . as $service
          | (($core[0].services[$service.key].networks // {}) | keys) as $coreNetworks
          | (($service.value.networks // {}) | keys[])
          | . as $networkName
          | select(($coreNetworks | index($networkName)) == null)
          | {
              workloadId: ($lockedNetworkOwners[$networkName] // null),
              serviceName: $service.key,
              networkName: $networkName
            }
        ] | sort_by(.workloadId, .serviceName, .networkName) as $actual
      | $expected == $actual
      and ($actual | length) > 0
  ' >/dev/null || {
    printf '%s\n' "Platform extension records do not exactly bind the signed core-to-combined network crosswalk." >&2
    return 1
  }
}

render_model() {
  local lock_path=$1 output=$2
  COMPOSE_ENV_FILE="$ENV_FILE" \
  COMPOSE_PROJECT_NAME="$PROJECT_NAME" \
  HOSTED_WORKLOAD_LOCK="$lock_path" \
  HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE="$lock_path" \
  HOSTED_WORKLOAD_ALLOW_RESOLVED=0 \
  HOSTED_WORKLOAD_PREPARE_RESOLVED=0 \
    bash "$SCRIPT_DIR/compose-vps.sh" config --format json > "$output"
  chmod 600 "$output"
}

render_core_model() {
  local lock_path=$1 output=$2
  COMPOSE_ENV_FILE="$ENV_FILE" \
  COMPOSE_PROJECT_NAME="$PROJECT_NAME" \
  HOSTED_WORKLOAD_LOCK= \
  HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE="$lock_path" \
  HOSTED_WORKLOAD_ALLOW_RESOLVED=1 \
  HOSTED_WORKLOAD_PREPARE_RESOLVED=1 \
    bash "$SCRIPT_DIR/compose-vps.sh" config --format json > "$output"
  chmod 600 "$output"
}

render_no_hosted_model() {
  local output=$1
  COMPOSE_ENV_FILE="$ENV_FILE" \
  COMPOSE_PROJECT_NAME="$PROJECT_NAME" \
  HOSTED_WORKLOAD_LOCK= \
  HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE="$NO_HOSTED_LOCK" \
  HOSTED_WORKLOAD_ALLOW_RESOLVED=0 \
  HOSTED_WORKLOAD_PREPARE_RESOLVED=0 \
    bash "$SCRIPT_DIR/compose-vps.sh" config --format json > "$output"
  chmod 600 "$output"
}

runtime_model() {
  local signed_model=$1 expected_lock_sha=$2 output=$3
  jq --arg expectedLockSha "$expected_lock_sha" \
    --arg candidateId "$RUNTIME_CANDIDATE_ID" \
    --arg commit "$RELEASE_COMMIT_SHA" \
    --arg tree "$RELEASE_TREE_SHA" \
    --arg deploymentId "$RELEASE_DECISION_ID" \
    --arg sourceRenderSha256 "$RUNTIME_SOURCE_RENDER_SHA256" \
    --arg workloadLockSha256 "$RUNTIME_WORKLOAD_LOCK_SHA256" '
    .services |= with_entries(
      .value = (
        if .value.labels["com.platform.workload-id"]? != null then
          .value
          | .labels += {
              "com.platform.runtime.candidate-id": $candidateId,
              "com.platform.runtime.commit": $commit,
              "com.platform.runtime.tree": $tree,
              "com.platform.runtime.deployment-id": $deploymentId,
              "com.platform.runtime.source-render-sha256": $sourceRenderSha256,
              "com.platform.runtime.workload-lock-sha256": $workloadLockSha256
            }
        else .value end
      )
    )
    | .services["project-router"].environment = (
        (.services["project-router"].environment // {})
        + {PROJECT_ROUTER_WORKLOAD_LOCK_SHA256: $expectedLockSha}
      )
  ' "$signed_model" > "$output"
  chmod 600 "$output"
  jq -e --arg expectedLockSha "$expected_lock_sha" \
    --arg candidateId "$RUNTIME_CANDIDATE_ID" \
    --arg commit "$RELEASE_COMMIT_SHA" \
    --arg tree "$RELEASE_TREE_SHA" \
    --arg deploymentId "$RELEASE_DECISION_ID" \
    --arg sourceRenderSha256 "$RUNTIME_SOURCE_RENDER_SHA256" \
    --arg workloadLockSha256 "$RUNTIME_WORKLOAD_LOCK_SHA256" \
    --slurpfile signed "$signed_model" '
    . as $runtime
    | all($runtime.services | to_entries[] | select(.value.labels["com.platform.workload-id"]? != null);
        (.value.labels | with_entries(select(.key | startswith("com.platform.runtime.")))) == {
          "com.platform.runtime.candidate-id": $candidateId,
          "com.platform.runtime.commit": $commit,
          "com.platform.runtime.tree": $tree,
          "com.platform.runtime.deployment-id": $deploymentId,
          "com.platform.runtime.source-render-sha256": $sourceRenderSha256,
          "com.platform.runtime.workload-lock-sha256": $workloadLockSha256
        })
    and ($runtime.services["project-router"].environment.PROJECT_ROUTER_WORKLOAD_LOCK_SHA256 == $expectedLockSha)
    and (
      $runtime
      | .services |= with_entries(
          if .value.labels["com.platform.workload-id"]? != null then
            .value.labels |= with_entries(select(.key | startswith("com.platform.runtime.") | not))
          else . end
        )
      | del(.services["project-router"].environment.PROJECT_ROUTER_WORKLOAD_LOCK_SHA256)
      | if $signed[0].services["project-router"].environment == null then
          del(.services["project-router"].environment)
        else . end
    ) == $signed[0]
  ' "$output" >/dev/null
}

verify_release_context_unchanged() {
  local current
  current=$(node "$SCRIPT_DIR/platform-release-context.mjs" read "$RELEASE_CONTEXT") || return 1
  [[ "$current" == "$RELEASE_CONTEXT_JSON" ]] || {
    printf '%s\n' "Trusted release context changed between transaction stages." >&2
    return 1
  }
  assert_mutex_identity
}

verify_release_subjects() {
  local model=$1 exact=${2:-1} expected actual selected subject service image_reference image_id
  expected=$(jq -c '[.services | to_entries[] | {serviceName: .key, imageReference: .value.image}] | sort_by(.serviceName)' "$model") || return 1
  actual=$(printf '%s' "$RELEASE_CONTEXT_JSON" | jq -c '.subjects') || return 1
  selected=$(printf '%s' "$actual" | jq -c --argjson expected "$expected" '
    [.[] as $subject
      | $expected[]
      | select(.serviceName == $subject.serviceName and .imageReference == $subject.imageReference)
      | $subject]
    | sort_by(.serviceName)
  ') || return 1
  jq -en --argjson expected "$expected" --argjson actual "$actual" --argjson selected "$selected" --arg exact "$exact" '
    ($selected | map({serviceName, imageReference})) == $expected
    and ($exact != "1" or $actual == $selected)
  ' >/dev/null || {
    printf '%s\n' "Trusted release subjects do not exactly match the pinned Compose service/image map." >&2
    return 1
  }
  while IFS=$'\t' read -r service image_reference image_id; do
    [[ -n "$service" && -n "$image_reference" && -n "$image_id" ]] || return 1
    assert_daemon_identity || return 1
    subject=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" image inspect \
      --format '{{.Id}}' "$image_reference") || return 1
    [[ "$subject" == "$image_id" ]] || {
      printf 'Trusted release image subject mismatch for %s: expected=%s actual=%s\n' \
        "$service" "$image_id" "${subject:-unavailable}" >&2
      return 1
    }
  done < <(printf '%s' "$selected" | jq -r '.[] | [.serviceName, .imageReference, .imageId] | @tsv')
  assert_daemon_identity
}

verify_model_for_bundle() {
  local model=$1 expected_sha=$2 bundle=$3 lock_path=$4 core_model=$5
  [[ -f "$model" && ! -L "$model" && "$(sha256_file "$model")" == "$expected_sha" ]] || return 1
  [[ -f "$core_model" && ! -L "$core_model" ]] || return 1
  node "$SCRIPT_DIR/hosted-workload-contract.mjs" verify-activation-render \
    --lock "$lock_path" \
    --coreRender "$core_model" \
    --combinedRender "$model" || return 1
  printf '%s' "$bundle" | jq -e \
    --arg expectedSha "$expected_sha" \
    --arg coreSha "$(sha256_file "$core_model")" \
    --slurpfile model "$model" '
    (.serviceRecords | map(.serviceName) | sort) as $lockedServices
    | (.serviceRecords | map({ key: .serviceName, value: .workloadId }) | from_entries) as $lockedOwners
    | .combinedRenderSha256 == $expectedSha
    and .coreRenderSha256 == $coreSha
    and (
        $model[0].services
        | to_entries
        | map(select(.value.labels["com.platform.workload-id"]? != null))
        | map(.key)
        | sort
      ) == $lockedServices
    and all(.serviceRecords[];
      $model[0].services[.serviceName].labels["com.platform.workload-id"] == .workloadId
      and ($lockedOwners[.serviceName] == .workloadId))
  ' >/dev/null
}

verify_inputs() {
  local lock_path=$1 initial_bundle=$2 model=$3 model_sha=$4 core_model=$5 current_bundle
  verify_model_for_bundle "$model" "$model_sha" "$initial_bundle" "$lock_path" "$core_model" || {
    printf '%s\n' "Pinned Compose model is no longer exact for its verified lock." >&2
    return 1
  }
  current_bundle=$(load_bundle "$lock_path") || return 1
  [[ "$current_bundle" == "$initial_bundle" ]] || {
    printf '%s\n' "Hosted workload activation lock changed between gate stages." >&2
    return 1
  }
}

create_services() {
  local model=$1
  shift
  (("$#" > 0)) || return 1
  assert_daemon_identity || return 1
  timeout "$ACTIVATION_TIMEOUT" \
    bash -c 'endpoint=$1; model=$2; root=$3; project=$4; shift 4; exec docker --host "$endpoint" compose --project-directory "$root" --profile backup -p "$project" -f "$model" create --no-build --pull never --no-deps "$@"' \
    hosted-create "$CANONICAL_DOCKER_HOST" "$model" "$INFRA_ROOT" "$PROJECT_NAME" "$@" \
    || return 1
  assert_daemon_identity
}

start_services() {
  local model=$1
  shift
  local ids count
  (("$#" > 0)) || return 1
  assert_daemon_identity || return 1
  ids=$(timeout "$VERIFY_TIMEOUT" \
    bash -c 'endpoint=$1; model=$2; root=$3; project=$4; shift 4; exec docker --host "$endpoint" compose --project-directory "$root" --profile backup -p "$project" -f "$model" ps -aq "$@"' \
    hosted-ids "$CANONICAL_DOCKER_HOST" "$model" "$INFRA_ROOT" "$PROJECT_NAME" "$@") || return 1
  count=$(printf '%s\n' "$ids" | awk 'NF { count += 1 } END { print count + 0 }')
  [[ "$count" -eq "$#" && "$(printf '%s\n' "$ids" | awk 'NF && !seen[$0]++ { count += 1 } END { print count + 0 }')" -eq "$#" ]] || {
    printf '%s\n' "Created service container IDs are not exact." >&2
    return 1
  }
  # Word splitting is intentional after the strict one-ID-per-line count above.
  timeout "$ACTIVATION_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" start $ids >/dev/null || return 1
  assert_daemon_identity
}

stop_and_prove() {
  local model=$1
  shift
  local ids inspections
  (("$#" > 0)) || return 1
  assert_daemon_identity || return 1
  timeout "$STOP_TIMEOUT" \
    bash -c 'endpoint=$1; model=$2; root=$3; project=$4; shift 4; exec docker --host "$endpoint" compose --project-directory "$root" --profile backup -p "$project" -f "$model" stop --timeout 30 "$@"' \
    hosted-stop "$CANONICAL_DOCKER_HOST" "$model" "$INFRA_ROOT" "$PROJECT_NAME" "$@" || return 1
  assert_daemon_identity || return 1
  ids=$(
    timeout "$VERIFY_TIMEOUT" \
      bash -c 'endpoint=$1; model=$2; root=$3; project=$4; shift 4; exec docker --host "$endpoint" compose --project-directory "$root" --profile backup -p "$project" -f "$model" ps -aq "$@"' \
      hosted-ps "$CANONICAL_DOCKER_HOST" "$model" "$INFRA_ROOT" "$PROJECT_NAME" "$@"
  ) || return 1
  assert_daemon_identity || return 1
  [[ -z "$ids" ]] && return 0
  # Word splitting is intentional for validated Docker IDs.
  inspections=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" inspect $ids) || return 1
  printf '%s' "$inspections" | jq -e '
    length > 0
    and all(.[]; .State.Running == false and .State.Paused == false and .State.Restarting == false)
  ' >/dev/null || {
      printf '%s\n' "Hosted/core stop could not be proven for running, paused and restarting states." >&2
      return 1
    }
}

verify_running_services() {
  local model=$1 expected_lock_sha=$2
  shift 2
  local ids count inspections deadline
  (("$#" > 0)) || return 1
  ids=$(timeout "$VERIFY_TIMEOUT" \
    bash -c 'endpoint=$1; model=$2; root=$3; project=$4; shift 4; exec docker --host "$endpoint" compose --project-directory "$root" --profile backup -p "$project" -f "$model" ps -aq "$@"' \
    hosted-verify-ids "$CANONICAL_DOCKER_HOST" "$model" "$INFRA_ROOT" "$PROJECT_NAME" "$@") || return 1
  count=$(printf '%s\n' "$ids" | awk 'NF { count += 1 } END { print count + 0 }')
  [[ "$count" -eq "$#" && "$(printf '%s\n' "$ids" | awk 'NF && !seen[$0]++ { count += 1 } END { print count + 0 }')" -eq "$#" ]] || return 1
  deadline=$((SECONDS + VERIFY_TIMEOUT))
  while :; do
    assert_daemon_identity || return 1
    # Word splitting is intentional after the strict ID validation above.
    inspections=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" inspect $ids) || return 1
    if printf '%s' "$inspections" | jq -e \
      --arg project "$PROJECT_NAME" \
      --arg expectedLockSha "$expected_lock_sha" \
      --arg candidateId "$RUNTIME_CANDIDATE_ID" \
      --arg commit "$RELEASE_COMMIT_SHA" \
      --arg tree "$RELEASE_TREE_SHA" \
      --arg deploymentId "$RELEASE_DECISION_ID" \
      --arg sourceRenderSha256 "$RUNTIME_SOURCE_RENDER_SHA256" \
      --arg workloadLockSha256 "$RUNTIME_WORKLOAD_LOCK_SHA256" \
      --argjson subjects "$(printf '%s' "$RELEASE_CONTEXT_JSON" | jq -c '.subjects')" \
      --argjson expectedServices "$(printf '%s\n' "$@" | jq -Rsc 'split("\n") | map(select(length > 0)) | sort')" \
      --slurpfile model "$model" '
        length == ($expectedServices | length)
        and ([.[].Config.Labels["com.docker.compose.service"]] | sort) == $expectedServices
        and all(.[];
          . as $container
          | .Config.Labels["com.docker.compose.project"] == $project
          and (.Config.Labels["com.docker.compose.service"] as $service
            | ($expectedServices | index($service)) != null
            and .Config.Image == $model[0].services[$service].image
            and .Image == ($subjects[] | select(.serviceName == $service) | .imageId)
            and (.Config.Labels["com.docker.compose.config-hash"] | type == "string" and length > 0)
            and (
              [.NetworkSettings.Networks | keys[]] | sort
            ) == (
              [$model[0].services[$service].networks | keys[] as $network
                | ($model[0].networks[$network].name // ($project + "_" + $network))]
              | sort
            )
            and (if .Config.Labels["com.platform.workload-id"]? != null then
              .HostConfig.RestartPolicy.Name == "no"
              and .HostConfig.ReadonlyRootfs == true
              and .HostConfig.Privileged == false
              and (.HostConfig.PidMode != "host")
              and ((.HostConfig.CapDrop // []) | index("ALL")) != null
              and (
                .Config.Labels
                | with_entries(select(.key | startswith("com.platform.runtime.")))
              ) == {
                "com.platform.runtime.candidate-id": $candidateId,
                "com.platform.runtime.commit": $commit,
                "com.platform.runtime.tree": $tree,
                "com.platform.runtime.deployment-id": $deploymentId,
                "com.platform.runtime.source-render-sha256": $sourceRenderSha256,
                "com.platform.runtime.workload-lock-sha256": $workloadLockSha256
              }
            else true end)
            and .State.Running == true
            and (if .Config.Healthcheck? != null then .State.Health.Status == "healthy" else true end)
            and (if $service == "project-router" then
              ([.Config.Env[] | select(startswith("PROJECT_ROUTER_WORKLOAD_LOCK_SHA256="))] == ["PROJECT_ROUTER_WORKLOAD_LOCK_SHA256=" + $expectedLockSha])
            else true end)
          )
        )
      ' >/dev/null; then
      break
    fi
    (( SECONDS < deadline )) || {
      printf '%s\n' "Exact service running/health receipt did not converge." >&2
      return 1
    }
    sleep 1
  done
  assert_daemon_identity
}

start_services_ordered() {
  local model=$1 expected_lock_sha=$2
  shift 2
  local order_file layer service
  local -a layer_services=()
  (("$#" > 0)) || return 1
  order_file=$(mktemp "$TEMP_DIRECTORY/start-order.XXXXXX")
  node "$SCRIPT_DIR/compose-start-order.mjs" "$model" "$@" > "$order_file" || return 1
  while IFS= read -r layer; do
    layer_services=()
    while IFS=$'\t' read -r _ service; do
      [[ -n "$service" ]] && layer_services+=("$service")
    done < <(awk -F'\t' -v layer="$layer" '$1 == layer { print $1 "\t" $2 }' "$order_file")
    (("${#layer_services[@]}" > 0)) || return 1
    start_services "$model" "${layer_services[@]}" || return 1
    verify_running_services "$model" "$expected_lock_sha" "${layer_services[@]}" || return 1
  done < <(awk -F'\t' '!seen[$1]++ { print $1 }' "$order_file")
}

verify_exact_workload_inventory() {
  local ids inspections expected_json
  if (("${#CURRENT_SERVICES[@]}" == 0)); then
    expected_json='[]'
  else
    expected_json=$(printf '%s\n' "${CURRENT_SERVICES[@]}" | jq -Rsc 'split("\n") | map(select(length > 0)) | sort')
  fi
  ids=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" ps -aq \
    --filter "label=com.docker.compose.project=$PROJECT_NAME") || return 1
  if [[ -z "$ids" ]]; then
    [[ "$expected_json" == "[]" ]]
    return
  fi
  # Word splitting is intentional for Docker IDs returned one per line.
  inspections=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" inspect $ids) || return 1
  printf '%s' "$inspections" | jq -e --argjson expected "$expected_json" '
    ([.[] | select(.Config.Labels["com.platform.workload-id"]? != null)
      | .Config.Labels["com.docker.compose.service"]] | sort) == $expected
    and all(.[] | select(.Config.Labels["com.platform.workload-id"]? != null);
      .State.Running == true and .State.Paused == false and .State.Restarting == false)
  ' >/dev/null
}

verify_ownership() {
  local lock_path=$1 model=$2
  HOSTED_WORKLOAD_ALLOW_RESOLVED=0 \
    timeout "$VERIFY_TIMEOUT" bash "$SCRIPT_DIR/hosted-workload-network-ownership.sh" \
      --lock "$lock_path" --project-name "$PROJECT_NAME" \
      --expected-daemon-id "$EXPECTED_DAEMON_ID" --expected-model "$model"
}

firewall() {
  local mode=$1 lock_path=${2:-}
  case "$mode" in
    preflight)
      [[ -n "$lock_path" ]] || return 1
      verify_privileged_helpers || return 1
      timeout "$VERIFY_TIMEOUT" sudo -n sh "$PRIVILEGED_FIREWALL_HELPER" \
        --privilege-preflight --lock "$lock_path" --project-name "$PROJECT_NAME" \
        --expected-daemon-id "$EXPECTED_DAEMON_ID"
      ;;
    apply)
      [[ -n "$lock_path" ]] || return 1
      verify_privileged_helpers || return 1
      timeout "$VERIFY_TIMEOUT" sudo -n sh "$PRIVILEGED_FIREWALL_HELPER" \
        --apply --lock "$lock_path" --project-name "$PROJECT_NAME" \
        --expected-daemon-id "$EXPECTED_DAEMON_ID" \
        --confirm APPLY-WORKLOAD-EGRESS-FIREWALL
      ;;
    verify)
      [[ -n "$lock_path" ]] || return 1
      verify_privileged_helpers || return 1
      timeout "$VERIFY_TIMEOUT" sudo -n sh "$PRIVILEGED_FIREWALL_HELPER" \
        --verify --lock "$lock_path" --project-name "$PROJECT_NAME" \
        --expected-daemon-id "$EXPECTED_DAEMON_ID"
      ;;
    deactivate)
      verify_privileged_helpers || return 1
      timeout "$VERIFY_TIMEOUT" sudo -n sh "$PRIVILEGED_FIREWALL_HELPER" \
        --rollback --project-name "$PROJECT_NAME" \
        --expected-daemon-id "$EXPECTED_DAEMON_ID" \
        --confirm ROLLBACK-WORKLOAD-EGRESS-FIREWALL
      ;;
    *) return 1 ;;
  esac
}

stop_entire_project_for_recovery() {
  local ids running
  assert_daemon_identity || return 1
  ids=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" ps -aq \
    --filter "label=com.docker.compose.project=$PROJECT_NAME") || return 1
  if [[ -n "$ids" ]]; then
    # Word splitting is intentional for Docker IDs returned one per line.
    timeout "$STOP_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" stop --time 30 $ids >/dev/null || return 1
  fi
  assert_daemon_identity || return 1
  running=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" ps -q \
    --filter "label=com.docker.compose.project=$PROJECT_NAME") || return 1
  [[ -z "$running" ]] || {
    printf '%s\n' "Pending activation recovery could not prove the project stopped." >&2
    return 1
  }
}

remove_stale_project_containers() {
  local ids inspections stale expected_json
  expected_json=$(printf '%s\n' "${CURRENT_ALL_SERVICES[@]}" | jq -Rsc 'split("\n") | map(select(length > 0)) | sort')
  ids=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" ps -aq \
    --filter "label=com.docker.compose.project=$PROJECT_NAME") || return 1
  [[ -n "$ids" ]] || return 0
  # Word splitting is intentional for Docker IDs returned one per line.
  inspections=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" inspect $ids) || return 1
  stale=$(printf '%s' "$inspections" | jq -r --argjson expected "$expected_json" '
    .[]
    | select((.Config.Labels["com.docker.compose.service"] // "") as $service
      | ($expected | index($service)) == null)
    | .Id
  ') || return 1
  if [[ -n "$stale" ]]; then
    # Word splitting is intentional for validated Docker IDs.
    timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" rm $stale >/dev/null || return 1
  fi
}

write_active_receipt() {
  local target_state=$1 lock_sha=$2 core_sha=$3 combined_sha=$4 model=$5
  shift 5
  local services_json receipt
  services_json=$(printf '%s\n' "$@" | jq -Rsc 'split("\n") | map(select(length > 0)) | unique | sort')
  receipt=$(jq -cn \
    --arg state "$target_state" \
    --arg projectName "$PROJECT_NAME" \
    --arg daemonId "$EXPECTED_DAEMON_ID" \
    --arg releaseContextSha256 "$RELEASE_CONTEXT_SHA256" \
    --arg releaseContextPath "$RELEASE_CONTEXT" \
    --arg repository "$RELEASE_REPOSITORY" \
    --arg commitSha "$RELEASE_COMMIT_SHA" \
    --arg treeSha "$RELEASE_TREE_SHA" \
    --arg sourceArchiveSha256 "$RELEASE_SOURCE_ARCHIVE_SHA256" \
    --arg releaseId "$RELEASE_ID" \
    --arg stateId "$RELEASE_STATE_ID" \
    --arg decisionId "$RELEASE_DECISION_ID" \
    --arg runtimeIntentSha256 "$RUNTIME_CANDIDATE_ID" \
    --arg lockPath "$LOCK" \
    --arg lockSha256 "$lock_sha" \
    --arg coreRenderSha256 "$core_sha" \
    --arg combinedRenderSha256 "$combined_sha" \
    --arg modelSha256 "$(sha256_file "$model")" \
    --argjson serviceNames "$services_json" \
    '{
      version: 2,
      state: $state,
      projectName: $projectName,
      daemonId: $daemonId,
      releaseContextSha256: $releaseContextSha256,
      releaseContextPath: $releaseContextPath,
      repository: $repository,
      commitSha: $commitSha,
      treeSha: $treeSha,
      sourceArchiveSha256: $sourceArchiveSha256,
      releaseId: $releaseId,
      stateId: $stateId,
      decisionId: $decisionId,
      runtimeIntentSha256: $runtimeIntentSha256,
      lockPath: (if $lockPath == "" then null else $lockPath end),
      lockSha256: $lockSha256,
      coreRenderSha256: $coreRenderSha256,
      combinedRenderSha256: $combinedRenderSha256,
      modelSha256: $modelSha256,
      serviceNames: $serviceNames
    }')
  state_write active.json "$receipt"
  ACTIVE_RECEIPT=$receipt
}

recover_pending_transaction() {
  local previous_journal=$1 previous_state_id retained_context_path retained_context retained_context_sha
  [[ "$RECOVER_PENDING" == 1 ]] || {
    printf '%s\n' "A durable pending activation exists; rerun with --recover-pending for fail-closed reconciliation." >&2
    return 1
  }
  printf '%s' "$previous_journal" | jq -e \
    --arg project "$PROJECT_NAME" '
    .version == 2 and .state == "pending" and .projectName == $project
    and (.transactionId | type == "string" and test("^[a-f0-9]{64}$"))
    and (.stateId | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$"))
  ' >/dev/null || return 1
  previous_state_id=$(printf '%s' "$previous_journal" | jq -r '.stateId')
  retained_context_path=$(dirname -- "$RELEASE_STATE_ROOT")/$previous_state_id/trusted-release-context.json
  retained_context=$(node "$SCRIPT_DIR/platform-release-context.mjs" read "$retained_context_path") || {
    printf '%s\n' "Pending activation retained release context cannot be authenticated." >&2
    return 1
  }
  retained_context_sha=$(sha256_file "$retained_context_path") || return 1
  printf '%s' "$previous_journal" | jq -e \
    --arg retainedContextSha256 "$retained_context_sha" \
    --argjson retained "$retained_context" \
    --arg coordinator "$STATE_DIR" '
      .releaseContextSha256 == $retainedContextSha256
      and .repository == $retained.repository
      and .commitSha == $retained.commitSha
      and .treeSha == $retained.treeSha
      and .sourceArchiveSha256 == $retained.sourceArchiveSha256
      and .releaseId == $retained.releaseId
      and .stateId == $retained.stateId
      and .decisionId == $retained.decisionId
      and .runtimeIntentSha256 == $retained.runtimeIntentSha256
      and .projectName == $retained.projectName
      and $retained.activationCoordinatorRoot == $coordinator
    ' >/dev/null || {
      printf '%s\n' "Pending activation journal does not match its retained trusted release context." >&2
      return 1
    }
  stop_entire_project_for_recovery || return 1
  TRANSACTION_ID=$(node "$SCRIPT_DIR/platform-activation-state.mjs" nonce)
  journal_phase recovered "pending transaction was fail-closed by proving the entire Compose project stopped"
  ACTIVE_RECEIPT=$(jq -cn \
    --arg projectName "$PROJECT_NAME" \
    --arg daemonId "$EXPECTED_DAEMON_ID" \
    --arg releaseContextSha256 "$RELEASE_CONTEXT_SHA256" \
    --arg releaseContextPath "$RELEASE_CONTEXT" \
    --arg repository "$RELEASE_REPOSITORY" \
    --arg commitSha "$RELEASE_COMMIT_SHA" \
    --arg treeSha "$RELEASE_TREE_SHA" \
    --arg sourceArchiveSha256 "$RELEASE_SOURCE_ARCHIVE_SHA256" \
    --arg releaseId "$RELEASE_ID" \
    --arg stateId "$RELEASE_STATE_ID" \
    --arg decisionId "$RELEASE_DECISION_ID" \
    --arg runtimeIntentSha256 "$RUNTIME_CANDIDATE_ID" '
    {version: 2, state: "stopped", projectName: $projectName, daemonId: $daemonId,
     releaseContextSha256: $releaseContextSha256, releaseContextPath: $releaseContextPath,
     repository: $repository,
     commitSha: $commitSha, treeSha: $treeSha, sourceArchiveSha256: $sourceArchiveSha256,
     releaseId: $releaseId, stateId: $stateId, decisionId: $decisionId,
     runtimeIntentSha256: $runtimeIntentSha256,
     lockPath: null, lockSha256: null, coreRenderSha256: null,
     combinedRenderSha256: null, modelSha256: null, serviceNames: []}')
  state_write active.json "$ACTIVE_RECEIPT"
}

rollback_previous() {
  [[ -n "$PREVIOUS_LOCK" ]] || return 1
  printf '%s\n' "Previous-release rollback requires its retained trusted release context and is not admitted by the current release context." >&2
  return 1
  # The code below remains unreachable until the retained release-context
  # interface supplies the previous immutable root and image subjects.
  verify_inputs "$PREVIOUS_LOCK" "$PREVIOUS_BUNDLE" "$PREVIOUS_MODEL" "$PREVIOUS_MODEL_SHA256" "$PREVIOUS_CORE_MODEL" || return 1
  stop_and_prove "$CURRENT_RUNTIME_MODEL" "${CURRENT_ALL_SERVICES[@]}" || return 1
  create_services "$PREVIOUS_RUNTIME_MODEL" "${PREVIOUS_ALL_SERVICES[@]}" || return 1
  verify_inputs "$PREVIOUS_LOCK" "$PREVIOUS_BUNDLE" "$PREVIOUS_MODEL" "$PREVIOUS_MODEL_SHA256" "$PREVIOUS_CORE_MODEL" || return 1
  verify_ownership "$PREVIOUS_LOCK" "$PREVIOUS_RUNTIME_MODEL" || return 1
  firewall apply "$PREVIOUS_LOCK" || return 1
  firewall verify "$PREVIOUS_LOCK" || return 1
  verify_ownership "$PREVIOUS_LOCK" "$PREVIOUS_RUNTIME_MODEL" || return 1
  start_services_ordered "$PREVIOUS_RUNTIME_MODEL" \
    "$(printf '%s' "$PREVIOUS_BUNDLE" | jq -r '.lockSha256')" \
    "${PREVIOUS_ALL_SERVICES[@]}" || return 1
  verify_running_services "$PREVIOUS_RUNTIME_MODEL" \
    "$(printf '%s' "$PREVIOUS_BUNDLE" | jq -r '.lockSha256')" \
    "${PREVIOUS_ALL_SERVICES[@]}" || return 1
  verify_inputs "$PREVIOUS_LOCK" "$PREVIOUS_BUNDLE" "$PREVIOUS_MODEL" "$PREVIOUS_MODEL_SHA256" "$PREVIOUS_CORE_MODEL" || return 1
  verify_ownership "$PREVIOUS_LOCK" "$PREVIOUS_RUNTIME_MODEL" || return 1
  firewall verify "$PREVIOUS_LOCK" || return 1
}

rollback_no_hosted() {
  local no_hosted_sha service
  local -a fallback_services=()
  [[ -n "$FALLBACK_RUNTIME_MODEL" ]] || return 1
  no_hosted_sha=$(sha256_file "$NO_HOSTED_LOCK") || return 1
  stop_and_prove "$CURRENT_RUNTIME_MODEL" "${CURRENT_ALL_SERVICES[@]}" || return 1
  while IFS= read -r service; do
    [[ -n "$service" ]] && fallback_services+=("$service")
  done < <(jq -r '.services | keys[]' "$FALLBACK_RUNTIME_MODEL")
  verify_release_context_unchanged || return 1
  verify_release_subjects "$FALLBACK_MODEL" 0 || return 1
  create_services "$FALLBACK_RUNTIME_MODEL" "${fallback_services[@]}" || return 1
  firewall deactivate || return 1
  start_services_ordered "$FALLBACK_RUNTIME_MODEL" "$no_hosted_sha" "${fallback_services[@]}" || return 1
  verify_running_services "$FALLBACK_RUNTIME_MODEL" "$no_hosted_sha" "${fallback_services[@]}" || return 1
}

stop_all_known_and_prove() {
  local current_ok=1 previous_ok=1
  stop_and_prove "$CURRENT_RUNTIME_MODEL" "${CURRENT_ALL_SERVICES[@]}" || current_ok=0
  if [[ -n "$PREVIOUS_LOCK" ]]; then
    stop_and_prove "$PREVIOUS_RUNTIME_MODEL" "${PREVIOUS_ALL_SERVICES[@]}" || previous_ok=0
  fi
  (( current_ok == 1 && previous_ok == 1 ))
}

cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  set +e
  if (( status != 0 && MUTATION_STARTED == 1 && GATE_COMPLETE == 0 && ROLLBACK_RUNNING == 0 )) && [[ "$ACTION" == activate ]]; then
    ROLLBACK_RUNNING=1
    if rollback_previous || rollback_no_hosted; then
      status=71
      printf '%s\n' "Activation failed; the previous verified or canonical no-hosted state was restored." >&2
    elif stop_all_known_and_prove; then
      status=72
      printf '%s\n' "Activation and verified rollback failed; every known hosted service is proven stopped and firewall enforcement was retained." >&2
    else
      status=73
      printf '%s\n' "Activation failed and a complete hosted stop is not proven; existing firewall enforcement remains active." >&2
    fi
  elif (( status != 0 && MUTATION_STARTED == 1 )); then
    status=73
    printf '%s\n' "Hosted stop failed and is not proven; firewall enforcement remains active." >&2
  elif (( status != 0 )); then
    status=70
  fi
  if [[ -n "$TRANSACTION_ID" && -d "$STATE_DIR" ]] && { (( GATE_COMPLETE == 1 )) || [[ "$status" == 71 || "$status" == 72 ]]; }; then
    journal_phase complete "process-exit-status=$status gate-complete=$GATE_COMPLETE" >/dev/null 2>&1 || true
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

for command in awk bash docker id jq node python3 sh sleep stat sudo timeout uname; do require_command "$command"; done
bind_local_docker_transport || exit 70
EXPECTED_DAEMON_ID=$(daemon_id) || {
  printf '%s\n' "Canonical local Docker daemon is unavailable." >&2
  exit 70
}
[[ "$EXPECTED_DAEMON_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$ ]] || {
  printf '%s\n' "Canonical local Docker daemon returned an invalid identity." >&2
  exit 70
}
assert_daemon_identity || exit 70

if [[ "$ENV_FILE" != /* ]]; then
  ENV_FILE="$INFRA_ROOT/$ENV_FILE"
fi
ENV_FILE=$(canonical_file "$ENV_FILE") || {
  printf '%s\n' "Compose env file must be an exact canonical regular file under the repository-owned project directory." >&2
  exit 70
}
case "$ENV_FILE" in
  "$INFRA_ROOT"/*) ;;
  *) printf '%s\n' "Compose env file is outside the repository-owned project directory." >&2; exit 70 ;;
esac

RELEASE_CONTEXT_JSON=$(node "$SCRIPT_DIR/platform-release-context.mjs" read "$RELEASE_CONTEXT") || exit 70
RELEASE_CONTEXT_SHA256=$(sha256_file "$RELEASE_CONTEXT") || exit 70
printf '%s' "$RELEASE_CONTEXT_JSON" | jq -e \
  --arg releaseRoot "$INFRA_ROOT" \
  --arg environmentFile "$ENV_FILE" \
  --arg environmentSha256 "$(sha256_file "$ENV_FILE")" \
  --arg projectName "$PROJECT_NAME" '
    .releaseRoot == $releaseRoot
    and .environmentFile == $environmentFile
    and .environmentSha256 == $environmentSha256
    and .projectName == $projectName
  ' >/dev/null || {
    printf '%s\n' "Trusted release context does not bind this exact release root, environment or project." >&2
    exit 70
  }
RELEASE_REPOSITORY=$(printf '%s' "$RELEASE_CONTEXT_JSON" | jq -r '.repository')
RELEASE_COMMIT_SHA=$(printf '%s' "$RELEASE_CONTEXT_JSON" | jq -r '.commitSha')
RELEASE_TREE_SHA=$(printf '%s' "$RELEASE_CONTEXT_JSON" | jq -r '.treeSha')
RELEASE_SOURCE_ARCHIVE_SHA256=$(printf '%s' "$RELEASE_CONTEXT_JSON" | jq -r '.sourceArchiveSha256')
RELEASE_ID=$(printf '%s' "$RELEASE_CONTEXT_JSON" | jq -r '.releaseId')
RELEASE_STATE_ID=$(printf '%s' "$RELEASE_CONTEXT_JSON" | jq -r '.stateId')
RELEASE_STATE_ROOT=$(printf '%s' "$RELEASE_CONTEXT_JSON" | jq -r '.stateRoot')
RELEASE_DECISION_ID=$(printf '%s' "$RELEASE_CONTEXT_JSON" | jq -r '.decisionId')
RUNTIME_CANDIDATE_ID=$(printf '%s' "$RELEASE_CONTEXT_JSON" | jq -r '.runtimeIntentSha256')
RUNTIME_SOURCE_RENDER_SHA256=$(printf '%s' "$RELEASE_CONTEXT_JSON" | jq -r '.sourceRenderSha256')
RUNTIME_WORKLOAD_LOCK_SHA256=$(printf '%s' "$RELEASE_CONTEXT_JSON" | jq -r '.hostedLockSha256')
EXPECTED_STATE_DIR=$(printf '%s' "$RELEASE_CONTEXT_JSON" | jq -r '.activationCoordinatorRoot')
if [[ -n "${PLATFORM_ACTIVATION_STATE_DIR:-}" && "$PLATFORM_ACTIVATION_STATE_DIR" != "$EXPECTED_STATE_DIR" ]]; then
  printf '%s\n' "Activation state directory must be the single host-private global coordinator path." >&2
  exit 70
fi
STATE_DIR=$EXPECTED_STATE_DIR
PRIVILEGED_STATE_BROKER_SHA256=$(sha256_file "$PRIVILEGED_STATE_BROKER") || exit 70
PRIVILEGED_FIREWALL_HELPER_SHA256=$(sha256_file "$PRIVILEGED_FIREWALL_HELPER") || exit 70
verify_privileged_helpers || {
  printf '%s\n' "Privileged activation helpers are not immutable release-owned files." >&2
  exit 70
}
if [[ -z "${PLATFORM_ACTIVATION_LOCK_FD:-}" ]]; then
  exec sudo -n "$PRIVILEGED_STATE_BROKER" acquire \
    "$STATE_DIR" "$0" "${ORIGINAL_ARGUMENTS[@]}"
fi
assert_mutex_identity || exit 75
previous_journal=$(state_read_optional journal.json) || exit 70
if [[ -n "$previous_journal" ]] && printf '%s' "$previous_journal" | jq -e '.state == "pending"' >/dev/null; then
  recover_pending_transaction "$previous_journal" || exit 75
fi
ACTIVE_RECEIPT=$(state_read_optional active.json) || exit 70

if (( NO_HOSTED == 0 )); then
  LOCK=$(canonical_file "$LOCK") || {
    printf '%s\n' "Hosted workload lock must be an exact canonical absolute regular file." >&2
    exit 70
  }
fi
if [[ -n "$PREVIOUS_LOCK" ]]; then
  PREVIOUS_LOCK=$(canonical_file "$PREVIOUS_LOCK") || {
    printf '%s\n' "Previous hosted workload lock must be an exact canonical absolute regular file." >&2
    exit 70
  }
  [[ "$PREVIOUS_LOCK" != "$LOCK" ]] || {
    printf '%s\n' "Current and previous hosted workload locks must be distinct objects." >&2
    exit 70
  }
fi

TEMP_DIRECTORY=$(mktemp -d "${TMPDIR:-/tmp}/hosted-activation-gate.XXXXXX")
chmod 700 "$TEMP_DIRECTORY"
CURRENT_MODEL=$TEMP_DIRECTORY/current-compose.json
CURRENT_CORE_MODEL=$TEMP_DIRECTORY/current-core-compose.json
CURRENT_RUNTIME_MODEL=$TEMP_DIRECTORY/current-runtime-compose.json
FALLBACK_MODEL=$TEMP_DIRECTORY/no-hosted-compose.json
FALLBACK_RUNTIME_MODEL=$TEMP_DIRECTORY/no-hosted-runtime-compose.json
PREVIOUS_CORE_MODEL=

if (( NO_HOSTED == 1 )); then
  NO_HOSTED_LOCK=$(canonical_file "$NO_HOSTED_LOCK") || {
    printf '%s\n' "Canonical no-hosted v4 lock is unavailable." >&2
    exit 70
  }
  render_no_hosted_model "$CURRENT_MODEL"
  cp "$CURRENT_MODEL" "$CURRENT_CORE_MODEL"
  CURRENT_MODEL_SHA256=$(sha256_file "$CURRENT_MODEL")
  CURRENT_LOCK_SHA256=$(sha256_file "$NO_HOSTED_LOCK")
  CURRENT_CORE_SHA256=$CURRENT_MODEL_SHA256
  CURRENT_COMBINED_SHA256=$CURRENT_MODEL_SHA256
  runtime_model "$CURRENT_MODEL" "$CURRENT_LOCK_SHA256" "$CURRENT_RUNTIME_MODEL" || exit 70
  cp "$CURRENT_MODEL" "$FALLBACK_MODEL"
  cp "$CURRENT_RUNTIME_MODEL" "$FALLBACK_RUNTIME_MODEL"
else
  CURRENT_BUNDLE=$(load_bundle "$LOCK") || {
    printf '%s\n' "Current hosted workload lock is not verified." >&2
    exit 70
  }
  validate_bundle "$CURRENT_BUNDLE" || {
    printf '%s\n' "Current hosted workload activation bundle is invalid." >&2
    exit 70
  }
  while IFS= read -r service_name; do
    [[ -n "$service_name" ]] && CURRENT_SERVICES+=("$service_name")
  done < <(printf '%s' "$CURRENT_BUNDLE" | jq -r '.serviceRecords[].serviceName')
  render_core_model "$LOCK" "$CURRENT_CORE_MODEL"
  render_model "$LOCK" "$CURRENT_MODEL"
  assert_daemon_identity
  CURRENT_MODEL_SHA256=$(sha256_file "$CURRENT_MODEL")
  verify_model_for_bundle "$CURRENT_MODEL" "$CURRENT_MODEL_SHA256" "$CURRENT_BUNDLE" "$LOCK" "$CURRENT_CORE_MODEL" || {
    printf '%s\n' "Current Compose model is not exact for the verified hosted lock." >&2
    exit 70
  }
  CURRENT_LOCK_SHA256=$(printf '%s' "$CURRENT_BUNDLE" | jq -r '.lockSha256')
  CURRENT_CORE_SHA256=$(printf '%s' "$CURRENT_BUNDLE" | jq -r '.coreRenderSha256')
  CURRENT_COMBINED_SHA256=$(printf '%s' "$CURRENT_BUNDLE" | jq -r '.combinedRenderSha256')
  runtime_model "$CURRENT_MODEL" "$CURRENT_LOCK_SHA256" "$CURRENT_RUNTIME_MODEL" || exit 70
  render_no_hosted_model "$FALLBACK_MODEL"
  runtime_model "$FALLBACK_MODEL" "$(sha256_file "$NO_HOSTED_LOCK")" "$FALLBACK_RUNTIME_MODEL" || exit 70
fi

if (( NO_HOSTED == 0 )); then
  verify_extension_records "$CURRENT_BUNDLE" "$FALLBACK_MODEL" "$CURRENT_MODEL" || exit 70
fi

while IFS= read -r service_name; do
  [[ -n "$service_name" ]] && CURRENT_EXTENSIONS+=("$service_name")
done < <(model_extension_services "$CURRENT_MODEL")
while IFS= read -r service_name; do
  [[ -n "$service_name" ]] && CURRENT_ALL_SERVICES+=("$service_name")
done < <(jq -r '.services | keys[]' "$CURRENT_MODEL")
[[ "${#CURRENT_EXTENSIONS[@]}" -eq "${#PLATFORM_EXTENSION_NAMES[@]}" ]] || {
  printf '%s\n' "The signed model does not contain the exact seven platform extension services." >&2
  exit 70
}

if [[ -n "$PREVIOUS_LOCK" ]]; then
  PREVIOUS_BUNDLE=$(load_bundle "$PREVIOUS_LOCK") || {
    printf '%s\n' "Previous hosted workload lock is not verified in the current immutable release root." >&2
    exit 70
  }
  validate_bundle "$PREVIOUS_BUNDLE" || {
    printf '%s\n' "Previous hosted workload activation bundle is invalid." >&2
    exit 70
  }
  while IFS= read -r service_name; do
    [[ -n "$service_name" ]] && PREVIOUS_SERVICES+=("$service_name")
  done < <(printf '%s' "$PREVIOUS_BUNDLE" | jq -r '.serviceRecords[].serviceName')
  PREVIOUS_MODEL=$TEMP_DIRECTORY/previous-compose.json
  PREVIOUS_CORE_MODEL=$TEMP_DIRECTORY/previous-core-compose.json
  PREVIOUS_RUNTIME_MODEL=$TEMP_DIRECTORY/previous-runtime-compose.json
  render_core_model "$PREVIOUS_LOCK" "$PREVIOUS_CORE_MODEL"
  render_model "$PREVIOUS_LOCK" "$PREVIOUS_MODEL"
  PREVIOUS_MODEL_SHA256=$(sha256_file "$PREVIOUS_MODEL")
  verify_model_for_bundle "$PREVIOUS_MODEL" "$PREVIOUS_MODEL_SHA256" "$PREVIOUS_BUNDLE" "$PREVIOUS_LOCK" "$PREVIOUS_CORE_MODEL" || {
    printf '%s\n' "Previous Compose model is not exact; cross-release rollback requires the retained immutable release-root dependency." >&2
    exit 70
  }
  PREVIOUS_LOCK_SHA256=$(printf '%s' "$PREVIOUS_BUNDLE" | jq -r '.lockSha256')
  runtime_model "$PREVIOUS_MODEL" "$PREVIOUS_LOCK_SHA256" "$PREVIOUS_RUNTIME_MODEL" || exit 70
  while IFS= read -r service_name; do
    [[ -n "$service_name" ]] && PREVIOUS_EXTENSIONS+=("$service_name")
  done < <(model_extension_services "$PREVIOUS_MODEL")
  while IFS= read -r service_name; do
    [[ -n "$service_name" ]] && PREVIOUS_ALL_SERVICES+=("$service_name")
  done < <(jq -r '.services | keys[]' "$PREVIOUS_MODEL")
  [[ "$(printf '%s' "$PREVIOUS_BUNDLE" | jq -r '.coreRenderSha256')" == "$CURRENT_CORE_SHA256" ]] || {
    printf '%s\n' "Previous and current core renders differ; retained immutable release-root rollback is not integrated." >&2
    exit 70
  }
  if [[ -n "$ACTIVE_RECEIPT" ]]; then
    printf '%s' "$ACTIVE_RECEIPT" | jq -e \
      --arg previousSha "$PREVIOUS_LOCK_SHA256" \
      --arg project "$PROJECT_NAME" \
      --arg daemonId "$EXPECTED_DAEMON_ID" '
      .version == 2 and .state == "hosted" and .projectName == $project
      and .daemonId == $daemonId and .lockSha256 == $previousSha
    ' >/dev/null || {
      printf '%s\n' "Previous lock does not match the authenticated active receipt." >&2
      exit 70
    }
  fi
elif [[ -n "$ACTIVE_RECEIPT" ]] && printf '%s' "$ACTIVE_RECEIPT" | jq -e '.state == "hosted"' >/dev/null; then
  active_sha=$(printf '%s' "$ACTIVE_RECEIPT" | jq -r '.lockSha256')
  [[ "$active_sha" == "$CURRENT_LOCK_SHA256" ]] || {
    printf '%s\n' "A different hosted state is active; its exact previous lock is required." >&2
    exit 70
  }
fi

printf '%s' "$RELEASE_CONTEXT_JSON" | jq -e \
  --argjson noHosted "$([[ "$NO_HOSTED" == 1 ]] && printf true || printf false)" \
  --arg lockSha256 "$CURRENT_LOCK_SHA256" \
  --arg coreRenderSha256 "$CURRENT_CORE_SHA256" \
  --arg combinedRenderSha256 "$CURRENT_COMBINED_SHA256" '
    .noHosted == $noHosted
    and .hostedLockSha256 == $lockSha256
    and .coreRenderSha256 == $coreRenderSha256
    and .combinedRenderSha256 == $combinedRenderSha256
  ' >/dev/null || {
    printf '%s\n' "Trusted release context does not bind the exact hosted/no-hosted lock and renders." >&2
    exit 70
  }
verify_release_context_unchanged || exit 70
verify_release_subjects "$CURRENT_MODEL" 1 || exit 70
model_paths=("$CURRENT_CORE_MODEL" "$CURRENT_MODEL" "$CURRENT_RUNTIME_MODEL" "$FALLBACK_MODEL" "$FALLBACK_RUNTIME_MODEL")
[[ -z "$PREVIOUS_CORE_MODEL" ]] || model_paths+=("$PREVIOUS_CORE_MODEL")
[[ -z "$PREVIOUS_MODEL" ]] || model_paths+=("$PREVIOUS_MODEL")
[[ -z "$PREVIOUS_RUNTIME_MODEL" ]] || model_paths+=("$PREVIOUS_RUNTIME_MODEL")
node "$SCRIPT_DIR/platform-activation-state.mjs" assert-unmounted "$STATE_DIR" "${model_paths[@]}" || exit 70
assert_mutex_identity || exit 75

if [[ "$ACTION" == stop ]]; then
  TRANSACTION_ID=$(node "$SCRIPT_DIR/platform-activation-state.mjs" nonce)
  journal_phase intent "stop exact current service set"
  MUTATION_STARTED=1
  stop_and_prove "$CURRENT_RUNTIME_MODEL" "${CURRENT_ALL_SERVICES[@]}"
  write_active_receipt stopped "$CURRENT_LOCK_SHA256" "$CURRENT_CORE_SHA256" "$CURRENT_COMBINED_SHA256" "$CURRENT_RUNTIME_MODEL"
  journal_phase complete "exact current service set proven stopped"
  GATE_COMPLETE=1
  MUTATION_STARTED=0
  printf 'Proven stopped hosted/extension service set: %s\n' "${CURRENT_ALL_SERVICES[*]}"
  exit 0
fi

if (( NO_HOSTED == 0 )); then
  verify_inputs "$LOCK" "$CURRENT_BUNDLE" "$CURRENT_MODEL" "$CURRENT_MODEL_SHA256" "$CURRENT_CORE_MODEL"
  firewall preflight "$LOCK"
fi
TRANSACTION_ID=$(node "$SCRIPT_DIR/platform-activation-state.mjs" nonce)
journal_phase intent "core, platform extension and hosted union transition"
MUTATION_STARTED=1
assert_mutex_identity

core_arguments=(--action validate --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" --confirm ACTIVATE-CORE-STACK)
if (( NO_HOSTED == 1 )); then
  core_arguments+=(--no-hosted-workloads)
else
  core_arguments+=(--lock "$LOCK")
fi
PLATFORM_ACTIVATION_TRANSACTION_ID="$TRANSACTION_ID" \
PLATFORM_ACTIVATION_EXPECTED_DAEMON_ID="$EXPECTED_DAEMON_ID" \
PLATFORM_ACTIVATION_STATE_DIR="$STATE_DIR" \
  bash "$SCRIPT_DIR/core-stack-activation-gate.sh" "${core_arguments[@]}"
assert_daemon_identity
journal_phase core-validated "signed core render validated inside the global transaction"

if [[ -n "$PREVIOUS_RUNTIME_MODEL" ]]; then
  stop_and_prove "$PREVIOUS_RUNTIME_MODEL" "${PREVIOUS_ALL_SERVICES[@]}"
fi
stop_and_prove "$CURRENT_RUNTIME_MODEL" "${CURRENT_ALL_SERVICES[@]}"
stop_entire_project_for_recovery
remove_stale_project_containers
assert_mutex_identity
journal_phase quiesced "entire project plus current/previous union proven stopped; stale services removed"

create_services "$CURRENT_RUNTIME_MODEL" "${CURRENT_ALL_SERVICES[@]}"
assert_mutex_identity
journal_phase created "exact current hosted/extension containers created stopped"
if (( NO_HOSTED == 0 )); then
  verify_inputs "$LOCK" "$CURRENT_BUNDLE" "$CURRENT_MODEL" "$CURRENT_MODEL_SHA256" "$CURRENT_CORE_MODEL"
  verify_ownership "$LOCK" "$CURRENT_RUNTIME_MODEL"
  firewall apply "$LOCK"
  firewall verify "$LOCK"
  journal_phase firewall-active "current egress inventory enforced before start"
else
  firewall deactivate
  journal_phase firewall-inactive "hosted egress chain removed while the full project was quiesced"
fi
start_services_ordered "$CURRENT_RUNTIME_MODEL" "$CURRENT_LOCK_SHA256" "${CURRENT_ALL_SERVICES[@]}"
verify_running_services "$CURRENT_RUNTIME_MODEL" "$CURRENT_LOCK_SHA256" "${CURRENT_ALL_SERVICES[@]}"
verify_exact_workload_inventory
if (( NO_HOSTED == 0 )); then
  verify_inputs "$LOCK" "$CURRENT_BUNDLE" "$CURRENT_MODEL" "$CURRENT_MODEL_SHA256" "$CURRENT_CORE_MODEL"
  verify_ownership "$LOCK" "$CURRENT_RUNTIME_MODEL"
  firewall verify "$LOCK"
fi
journal_phase runtime-verified "exact running, image, health and router lock-SHA receipt"
if (( RUN_POSTDEPLOY == 1 )); then
  sh "$SCRIPT_DIR/vps-postdeploy.sh" "$ENV_FILE"
  journal_phase postdeploy-verified "fixed repository postdeploy verification completed under the activation mutex"
fi
write_active_receipt \
  "$([[ "$NO_HOSTED" == 1 ]] && printf no-hosted || printf hosted)" \
  "$CURRENT_LOCK_SHA256" "$CURRENT_CORE_SHA256" "$CURRENT_COMBINED_SHA256" \
  "$CURRENT_RUNTIME_MODEL" "${CURRENT_ALL_SERVICES[@]}"
journal_phase complete "active receipt committed"
GATE_COMPLETE=1
MUTATION_STARTED=0
printf 'Platform activation transaction completed for project %s: %s\n' "$PROJECT_NAME" "${CURRENT_ALL_SERVICES[*]}"
