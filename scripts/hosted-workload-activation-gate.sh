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
COMMIT_ATTEMPTED=0
COMMIT_TARGET_STATE=
COMMIT_EXPECTED_MODEL_SHA=
COMMIT_EXPECTED_SERVICES='[]'
COMMIT_RECONCILIATION=none
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
RELEASE_ENVIRONMENT_FILE=
RELEASE_ENVIRONMENT_SHA256=
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
TRANSACTION_LABEL=com.platform.activation.transaction-id
TRANSACTION_MODEL_LABEL=com.platform.activation.source-model-sha256
TRANSACTION_SOURCE_MODEL_SHA256=
TRANSACTION_RUNTIME_MODEL=
TRANSACTION_CONTAINER_CAS='[]'
TRANSACTION_VOLUME_CAS='[]'
TRANSACTION_NETWORK_CAS='[]'
TRANSACTION_RESOURCE_PROJECTION='{"volumes":[],"networks":[]}'
TRANSACTION_RESOURCE_MODE=none
TRANSACTION_CONTAINERS_REMOVABLE=0
RESUME_CREATING=0
PENDING_JOURNAL=
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
declare -a TRANSACTION_CREATED_CONTAINER_IDS=()

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

canonical_host_path() {
  /usr/bin/python3 -I - "$1" <<'PY'
import os
import sys

value = sys.argv[1]
if (not value.startswith("/") or "//" in value or "\x00" in value
    or any(ord(character) < 32 or ord(character) == 127 for character in value)
    or (len(value) > 1 and value.endswith("/"))):
    raise SystemExit(1)
normalized = os.path.normpath(value)
if normalized != value:
    raise SystemExit(1)
resolved = os.path.realpath(value)
if not resolved.startswith("/") or os.path.normpath(resolved) != resolved:
    raise SystemExit(1)
print(resolved)
PY
}

host_path_has_docker_authority() {
  local candidate=$1 docker_root=$2
  case "$candidate" in
    /|/run|/var/run|/run/docker.sock|/var/run/docker.sock) return 0 ;;
  esac
  [[ "$candidate" == "$docker_root" \
      || "$docker_root" == "$candidate/"* ]]
}

assert_candidate_broker_socket_contract() {
  local model=$1 service=$2 source=$3 target=$4 read_only=$5 create_host_path=$6
  [[ "$service" == docker-action-broker \
      && "$source" == /var/run/docker.sock \
      && "$target" == /var/run/docker.sock \
      && "$read_only" == true \
      && "$create_host_path" == false \
      && -n "${RELEASE_CONTEXT_JSON:-}" ]] || return 1
  printf '%s' "$RELEASE_CONTEXT_JSON" | jq -e --slurpfile model "$model" '
    . as $release
    | $model[0] as $candidate
    | ($candidate.services["docker-action-broker"] // null) as $broker
    | ($broker.volumes // []) as $mounts
    | ($broker.environment // {}) as $environment
    | ($release.subjects // []
        | map(select(.serviceName == "docker-action-broker"))) as $subjects
    | ($broker | type) == "object"
    and ($candidate.name == "platform_infra_vps")
    and ($broker.image | type == "string"
      and test("^[A-Za-z0-9][A-Za-z0-9._/:+-]*@sha256:[a-f0-9]{64}$"))
    and (($broker | has("build")) | not)
    and ($broker.init == true)
    and ($broker.user == "0:0")
    and ($broker.read_only == true)
    and ($broker.pids_limit == 256)
    and ($broker.restart == "unless-stopped")
    and ($broker.network_mode == "none")
    and (($broker.networks // {}) | length) == 0
    and (($broker.ports // []) | length) == 0
    and (($broker.expose // []) | length) == 0
    and (($broker.cap_drop // []) == ["ALL"])
    and (($broker.cap_add // []) | length) == 0
    and (($broker.group_add // []) | length) == 0
    and (($broker.security_opt // []) == ["no-new-privileges:true"])
    and (($broker.entrypoint // []) == [
      "node",
      "/opt/platform-docker-broker/docker-action-broker.mjs"
    ])
    and ($environment.DOCKER_ACTION_BROKER_SOCKET
      == "/run/platform/docker-action-broker/broker.sock")
    and (($environment | has("DOCKER_HOST")) | not)
    and (($environment | has("DOCKER_API_VERSION")) | not)
    and (($broker.healthcheck.test // []) == [
      "CMD",
      "node",
      "/opt/platform-docker-broker/docker-action-readiness.mjs",
      "--require-trusted-activation"
    ])
    and ([$mounts[]
      | select(.type == "bind"
        and (.source == "/var/run/docker.sock" or .target == "/var/run/docker.sock"))]
      == [{
        type: "bind",
        source: "/var/run/docker.sock",
        target: "/var/run/docker.sock",
        read_only: true,
        bind: {create_host_path: false}
      }])
    and ([$candidate.services
      | to_entries[]
      | select(any((.value.volumes // [])[];
          .type == "bind"
          and (.source == "/var/run/docker.sock"
            or .source == "/run/docker.sock"
            or .target == "/var/run/docker.sock"
            or .target == "/run/docker.sock")))
      | .key] == ["docker-action-broker"])
    and ($subjects | length) == 1
    and ($subjects[0].imageReference == $broker.image)
    and ($subjects[0].imageId | type == "string"
      and test("^sha256:[a-f0-9]{64}$"))
  ' >/dev/null
}

assert_global_docker_authority_boundary() {
  local transaction_model=${1:-}
  local docker_root_raw docker_root inventory_before inventory_after inspections mount_records
  local id duplicate candidate record source target rw read_only service canonical_source authority_id= authority_source=
  local registered authorized
  local before_json after_json
  local -a before_ids=() after_ids=()
  docker_root_raw=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" \
    info --format '{{.DockerRootDir}}') || {
      printf '%s\n' "Docker root identity could not be obtained safely." >&2
      return 70
    }
  [[ "$docker_root_raw" == /* && "$docker_root_raw" != *$'\n'* && "$docker_root_raw" != *$'\r'* ]] || {
    printf '%s\n' "Docker root identity is ambiguous." >&2
    return 70
  }
  docker_root=$(canonical_host_path "$docker_root_raw") || {
    printf '%s\n' "Docker root identity is not a canonical absolute path." >&2
    return 70
  }
  inventory_before=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" \
    ps -aq --no-trunc) || {
      printf '%s\n' "Global container inventory could not be enumerated safely." >&2
      return 70
    }
  while IFS= read -r id; do
    [[ -z "$id" ]] && continue
    [[ "$id" =~ ^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$ ]] || {
      printf '%s\n' "Global container inventory returned an invalid identity." >&2
      return 70
    }
    duplicate=0
    for candidate in "${before_ids[@]:-}"; do [[ "$candidate" != "$id" ]] || duplicate=1; done
    (( duplicate == 0 )) || {
      printf '%s\n' "Global container inventory returned duplicate identities." >&2
      return 70
    }
    before_ids+=("$id")
  done <<< "$inventory_before"
  before_json=$(printf '%s\n' "${before_ids[@]:-}" \
    | jq -Rsc 'split("\n") | map(select(length > 0)) | sort') || return 70
  if ((${#before_ids[@]} != 0)); then
    inspections=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" inspect \
      "${before_ids[@]}") || {
        printf '%s\n' "Global container inventory could not be inspected safely." >&2
        return 70
      }
    printf '%s' "$inspections" | jq -e --argjson expected "$before_json" '
      type == "array"
      and length == ($expected | length)
      and ([.[].Id] | sort) == $expected
      and ([.[].Id] | unique | length) == ($expected | length)
      and all(.[];
        (type == "object")
        and (.Id | type == "string")
        and (.Mounts | type == "array")
        and all(.Mounts[];
          (type == "object")
          and (.Type | type == "string")
          and (if .Type == "bind" then
            (.Source | type == "string"
              and startswith("/")
              and (contains("\u0009") | not)
              and (contains("\u000a") | not)
              and (contains("\u000d") | not))
            and (.Destination | type == "string" and startswith("/"))
            and (.RW | type == "boolean")
          else true end))
      )
    ' >/dev/null || {
      printf '%s\n' "Global container inspection is malformed or differs from inventory." >&2
      return 70
    }
    mount_records=$(printf '%s' "$inspections" | jq -c '
      .[] | .Id as $id | .Mounts[]
      | select(.Type == "bind")
      | {id: $id, source: .Source, target: .Destination, rw: .RW}
    ') || return 70
    while IFS= read -r record; do
      [[ -z "$record" ]] && continue
      id=$(printf '%s' "$record" | jq -er '.id') || return 70
      source=$(printf '%s' "$record" | jq -er '.source') || return 70
      target=$(printf '%s' "$record" | jq -er '.target') || return 70
      rw=$(printf '%s' "$record" | jq -r '.rw') || return 70
      [[ "$rw" == true || "$rw" == false ]] || return 70
      canonical_source=$(canonical_host_path "$source") || {
        printf 'Container %s has a non-canonical bind source; preserving it and refusing activation.\n' "$id" >&2
        return 70
      }
      if host_path_has_docker_authority "$source" "$docker_root_raw" \
          || host_path_has_docker_authority "$canonical_source" "$docker_root"; then
        authorized=0
        registered=0
        for candidate in "${TRANSACTION_CREATED_CONTAINER_IDS[@]:-}"; do
          [[ "$candidate" != "$id" ]] || registered=1
        done
        if (( registered == 1 )) && [[ -n "$transaction_model" \
            && "$source" == /var/run/docker.sock \
            && ( "$canonical_source" == /var/run/docker.sock || "$canonical_source" == /run/docker.sock ) \
            && ! -L "$source" && -S "$source" ]]; then
          service=$(printf '%s' "$inspections" | jq -er --arg id "$id" '
            [.[] | select(.Id == $id) | .Config.Labels["com.docker.compose.service"]]
            | if length == 1 then .[0] else error("ambiguous service") end
          ') || return 70
          if [[ "$rw" == false ]]; then read_only=true; else read_only=false; fi
          if [[ "$service" == docker-action-broker ]] \
              && assert_candidate_broker_socket_contract \
                "$transaction_model" "$service" "$source" "$target" "$read_only" false; then
            authorized=1
          fi
        fi
        if (( authorized == 0 )); then
          authority_id=$id
          authority_source=$source
        fi
      fi
    done <<< "$mount_records"
  fi
  inventory_after=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" \
    ps -aq --no-trunc) || {
      printf '%s\n' "Global container inventory could not be revalidated safely." >&2
      return 70
    }
  while IFS= read -r id; do
    [[ -z "$id" ]] && continue
    [[ "$id" =~ ^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$ ]] || return 70
    duplicate=0
    for candidate in "${after_ids[@]:-}"; do [[ "$candidate" != "$id" ]] || duplicate=1; done
    (( duplicate == 0 )) || return 70
    after_ids+=("$id")
  done <<< "$inventory_after"
  after_json=$(printf '%s\n' "${after_ids[@]:-}" \
    | jq -Rsc 'split("\n") | map(select(length > 0)) | sort') || return 70
  [[ "$after_json" == "$before_json" ]] || {
    printf '%s\n' "Global container inventory changed during authority inspection; refusing activation." >&2
    return 70
  }
  [[ -z "$authority_id" ]] || {
    printf 'Pre-existing container %s has Docker socket or host-parent authority through %s; preserving it and refusing activation.\n' \
      "$authority_id" "$authority_source" >&2
    return 70
  }
}

assert_project_preservation_boundary() {
  local inventory id expected found count=0 inspections
  local -a live_ids=()
  inventory=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" ps -aq --no-trunc \
    --filter "label=com.docker.compose.project=$PROJECT_NAME") || {
      printf '%s\n' "Project container inventory could not be enumerated safely." >&2
      return 70
    }
  while IFS= read -r id; do
    [[ -z "$id" ]] && continue
    [[ "$id" =~ ^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$ ]] || {
      printf '%s\n' "Project container inventory returned an invalid identity." >&2
      return 70
    }
    live_ids+=("$id")
  done <<< "$inventory"
  if ((${#TRANSACTION_CREATED_CONTAINER_IDS[@]} == 0)); then
    if ((${#live_ids[@]} != 0)); then
      printf 'Pre-existing project containers are not transaction-owned; preserving %s container(s) and refusing activation.\n' \
        "${#live_ids[@]}" >&2
      return 70
    fi
    return 0
  fi
  for expected in "${TRANSACTION_CREATED_CONTAINER_IDS[@]}"; do
    [[ "$expected" =~ ^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$ ]] || {
      printf '%s\n' "A registered transaction container identity is invalid; refusing cleanup." >&2
      return 70
    }
  done
  ((${#live_ids[@]} == ${#TRANSACTION_CREATED_CONTAINER_IDS[@]})) || {
    printf '%s\n' "Project container inventory differs from the transaction-owned set; preserving unknown containers." >&2
    return 70
  }
  for id in "${live_ids[@]}"; do
    found=0
    for expected in "${TRANSACTION_CREATED_CONTAINER_IDS[@]}"; do
      if [[ "$id" == "$expected" ]]; then
        found=1
        break
      fi
    done
    (( found == 1 )) || {
      printf '%s\n' "Project inventory contains a container not registered by this transaction; preserving it." >&2
      return 70
    }
    count=$((count + 1))
  done
  (( count == ${#TRANSACTION_CREATED_CONTAINER_IDS[@]} )) || {
    printf '%s\n' "Transaction-owned project container inventory is incomplete; refusing mutation." >&2
    return 70
  }
  [[ "$TRANSACTION_SOURCE_MODEL_SHA256" =~ ^[a-f0-9]{64}$ ]] || {
    printf '%s\n' "Transaction source-model CAS is unavailable; refusing mutation." >&2
    return 70
  }
  printf '%s' "$TRANSACTION_CONTAINER_CAS" | jq -e \
    --argjson expectedCount "${#TRANSACTION_CREATED_CONTAINER_IDS[@]}" '
      type == "array"
      and length == $expectedCount
      and ([.[].id] | unique | length) == $expectedCount
      and all(.[];
        (keys | sort) == ["configHash", "id", "mounts", "networks"]
        and (.id | type == "string" and length >= 3)
        and (.configHash | type == "string" and test("^[a-f0-9]{64}$"))
        and (.mounts | type == "array")
        and (.networks | type == "array"))
    ' >/dev/null || {
      printf '%s\n' "Transaction container CAS set is invalid; refusing mutation." >&2
      return 70
    }
  inspections=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" inspect \
    "${TRANSACTION_CREATED_CONTAINER_IDS[@]}") || {
      printf '%s\n' "Transaction container CAS identities cannot be inspected." >&2
      return 70
    }
  printf '%s' "$inspections" | jq -e \
    --arg project "$PROJECT_NAME" \
    --arg transactionId "$TRANSACTION_ID" \
    --arg transactionLabel "$TRANSACTION_LABEL" \
    --arg sourceModelSha256 "$TRANSACTION_SOURCE_MODEL_SHA256" \
    --arg sourceModelLabel "$TRANSACTION_MODEL_LABEL" \
    --argjson expectedCas "$TRANSACTION_CONTAINER_CAS" '
      def normalized_mounts:
        [(.Mounts // [])[]
          | if .Type == "volume" then
              {type: "volume", source: (.Name // ""), target: .Destination,
               rw: (.RW == true), propagation: ""}
            elif .Type == "bind" then
              {type: "bind", source: .Source, target: .Destination,
               rw: (.RW == true), propagation: (.Propagation // "rprivate")}
            elif .Type == "tmpfs" then
              {type: "tmpfs", source: "", target: .Destination,
               rw: (.RW == true), propagation: ""}
            else error("unsupported Engine mount type") end]
        | sort_by(.type, .target, .source);
      ([.[] | {
        id: .Id,
        configHash: .Config.Labels["com.docker.compose.config-hash"],
        mounts: normalized_mounts,
        networks: ((.NetworkSettings.Networks // {}) | keys | unique | sort)
      }] | sort_by(.id)) == ($expectedCas | sort_by(.id))
      and all(.[];
        .Config.Labels["com.docker.compose.project"] == $project
        and .Config.Labels[$transactionLabel] == $transactionId
        and .Config.Labels[$sourceModelLabel] == $sourceModelSha256)
    ' >/dev/null || {
      printf '%s\n' "Transaction container identity/config CAS changed; refusing mutation." >&2
      return 70
    }
}

normalize_transaction_volume_inspection() {
  jq -c '
    if type != "array" or length != 1 then error("volume inspection is not singular") else .[0] end
    | {
        name: .Name,
        driver: .Driver,
        scope: .Scope,
        labels: (.Labels // {}),
        options: (.Options // {}),
        mountpoint: .Mountpoint,
        createdAt: .CreatedAt
      }
  '
}

normalize_transaction_network_inspection() {
  jq -c '
    if type != "array" or length != 1 then error("network inspection is not singular") else .[0] end
    | {
        id: .Id,
        name: .Name,
        driver: .Driver,
        scope: .Scope,
        internal: .Internal,
        attachable: .Attachable,
        ingress: .Ingress,
        configOnly: (.ConfigOnly // false),
        enableIPv4: (.EnableIPv4 // true),
        enableIPv6: (.EnableIPv6 // false),
        labels: (.Labels // {}),
        options: (.Options // {}),
        ipam: (.IPAM // {})
      }
  '
}

transaction_resource_projection() {
  local model=$1 selected_services
  shift
  (( $# > 0 )) || return 1
  selected_services=$(printf '%s\n' "$@" \
    | jq -Rsc 'split("\n") | map(select(length > 0)) | unique | sort') || return 1
  jq -c --arg project "$PROJECT_NAME" --argjson selected "$selected_services" '
    . as $model
    | ($selected | map(
        . as $service
        | if ($model.services[$service] | type) == "object" then $service
          else error("selected service missing from transaction model") end
      )) as $services
    | ([$services[] as $service
        | ($model.services[$service].volumes // [])[]
        | if type == "object" then . else error("non-object service mount") end
        | select(.type == "volume")
        | (.source // "") as $logical
        | if ($logical | type == "string" and length > 0) then $logical
          else error("anonymous named volume is not transaction-projectable") end
      ] | unique | sort) as $volume_logical_names
    | ([$services[] as $service
        | ($model.services[$service].networks // {})
        | if type == "object" then keys[]
          elif type == "array" then .[]
          else error("service networks are not projectable") end
      ] | unique | sort) as $network_logical_names
    | {
        volumes: [$volume_logical_names[] as $logical
          | ($model.volumes[$logical] // null) as $definition
          | if ($definition | type) != "object" then error("used volume missing from model")
            elif ($definition.external // false) == true then empty
            else {
              logicalName: $logical,
              physicalName: ($definition.name // ($project + "_" + $logical)),
              definition: $definition
            } end],
        networks: [$network_logical_names[] as $logical
          | ($model.networks[$logical] // null) as $definition
          | if ($definition | type) != "object" then error("used network missing from model")
            elif ($definition.external // false) == true then empty
            else {
              logicalName: $logical,
              physicalName: ($definition.name // ($project + "_" + $logical)),
              definition: $definition
            } end]
      }
    | if (([.volumes[].physicalName] | unique | length) == (.volumes | length)
        and ([.networks[].physicalName] | unique | length) == (.networks | length))
      then . else error("transaction resource projection has an alias collision") end
  ' "$model"
}

assert_transaction_resource_projection() {
  local model=$1 mode=$2
  shift 2
  local projection expected actual kind
  [[ "$mode" == exact || "$mode" == subset ]] || return 1
  projection=$(transaction_resource_projection "$model" "$@") || return 1
  for kind in volume network; do
    if [[ "$kind" == volume ]]; then
      expected=$(printf '%s' "$projection" | jq -c '[.volumes[] | {logicalName, physicalName}] | sort_by(.physicalName)') || return 1
      actual=$(printf '%s' "$TRANSACTION_VOLUME_CAS" | jq -c '[.[] | {logicalName, physicalName}] | sort_by(.physicalName)') || return 1
    else
      expected=$(printf '%s' "$projection" | jq -c '[.networks[] | {logicalName, physicalName}] | sort_by(.physicalName)') || return 1
      actual=$(printf '%s' "$TRANSACTION_NETWORK_CAS" | jq -c '[.[] | {logicalName, physicalName}] | sort_by(.physicalName)') || return 1
    fi
    if [[ "$mode" == exact ]]; then
      [[ "$actual" == "$expected" ]] || {
        printf 'Transaction %s CAS is missing an exact used model resource.\n' "$kind" >&2
        return 1
      }
    else
      jq -en --argjson expected "$expected" --argjson actual "$actual" '
        all($actual[]; . as $record | ($expected | index($record)) != null)
      ' >/dev/null || {
        printf 'Transaction %s CAS is outside the authorized resource projection.\n' "$kind" >&2
        return 1
      }
    fi
  done
}

assert_registered_transaction_resources() {
  local kind cas record name expected inspection actual
  local resource_mode=${TRANSACTION_RESOURCE_MODE:-none}
  local resource_projection=${TRANSACTION_RESOURCE_PROJECTION:-'{"volumes":[],"networks":[]}'}
  jq -en --arg mode "$resource_mode" \
    --argjson projection "$resource_projection" \
    --argjson volumes "$TRANSACTION_VOLUME_CAS" \
    --argjson networks "$TRANSACTION_NETWORK_CAS" '
      def identities($records):
        [$records[] | {logicalName, physicalName}] | sort_by(.physicalName);
      ($mode == "none" or $mode == "subset" or $mode == "exact")
      and (($projection | keys | sort) == ["networks", "volumes"])
      and (($projection.volumes | type) == "array")
      and (($projection.networks | type) == "array")
      and (if $mode == "none" then
        $volumes == [] and $networks == []
        and $projection == {volumes: [], networks: []}
      elif $mode == "exact" then
        identities($volumes) == identities($projection.volumes)
        and identities($networks) == identities($projection.networks)
      else
        all(identities($volumes)[]; . as $record | identities($projection.volumes) | index($record) != null)
        and all(identities($networks)[]; . as $record | identities($projection.networks) | index($record) != null)
      end)
    ' >/dev/null || return 1
  for kind in volume network; do
    if [[ "$kind" == volume ]]; then cas=$TRANSACTION_VOLUME_CAS; else cas=$TRANSACTION_NETWORK_CAS; fi
    printf '%s' "$cas" | jq -e '
      type == "array"
      and ([.[].physicalName] | unique | length) == length
      and all(.[];
        (keys | sort) == ["inspection", "logicalName", "physicalName"]
        and (.logicalName | type == "string" and length > 0)
        and (.physicalName | type == "string" and length > 0)
        and (.inspection | type == "object"))
    ' >/dev/null || return 1
    while IFS= read -r record; do
      [[ -z "$record" ]] && continue
      name=$(printf '%s' "$record" | jq -er '.physicalName') || return 1
      expected=$(printf '%s' "$record" | jq -c '.inspection') || return 1
      inspection=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" \
        "$kind" inspect "$name") || return 1
      if [[ "$kind" == volume ]]; then
        actual=$(printf '%s' "$inspection" | normalize_transaction_volume_inspection) || return 1
      else
        actual=$(printf '%s' "$inspection" | normalize_transaction_network_inspection) || return 1
      fi
      [[ "$actual" == "$expected" ]] || {
        printf 'Registered transaction %s CAS changed for %s; preserving it and refusing mutation.\n' \
          "$kind" "$name" >&2
        return 1
      }
    done < <(printf '%s' "$cas" | jq -c '.[]')
  done
}

register_transaction_resources() {
  local model=$1 mode=$2
  shift 2
  local live_volume_names live_network_names record definition logical name inspection normalized cas_record
  local projection existing existing_count live found old_volumes old_networks old_projection old_mode
  local transaction_volumes=$TRANSACTION_VOLUME_CAS transaction_networks=$TRANSACTION_NETWORK_CAS
  [[ "$model" == /* && -f "$model" && ! -L "$model" \
      && "$TRANSACTION_ID" =~ ^[a-f0-9]{64}$ \
      && "$TRANSACTION_SOURCE_MODEL_SHA256" =~ ^[a-f0-9]{64}$ ]] || return 1
  [[ "$mode" == exact || "$mode" == subset ]] || return 1
  (( $# > 0 )) || return 1
  assert_registered_transaction_resources || return 1
  assert_transaction_resource_projection "$model" subset "$@" || return 1
  projection=$(transaction_resource_projection "$model" "$@") || return 1
  old_projection=${TRANSACTION_RESOURCE_PROJECTION:-'{"volumes":[],"networks":[]}'}
  old_mode=${TRANSACTION_RESOURCE_MODE:-none}
  if [[ "$old_mode" != none && "$projection" != "$old_projection" ]]; then
    printf '%s\n' "Transaction resource projection changed; refusing CAS refresh." >&2
    return 1
  fi
  [[ "$old_mode" != exact || "$mode" == exact ]] || {
    printf '%s\n' "Exact transaction resource CAS cannot regress to subset." >&2
    return 1
  }
  live_volume_names=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" \
    volume ls --format '{{.Name}}') || return 1
  live_network_names=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" \
    network ls --format '{{.Name}}') || return 1
  while IFS= read -r record; do
    [[ -z "$record" ]] && continue
    logical=$(printf '%s' "$record" | jq -er '.logicalName') || return 1
    name=$(printf '%s' "$record" | jq -er '.physicalName') || return 1
    definition=$(printf '%s' "$record" | jq -c '.definition') || return 1
    found=0
    while IFS= read -r live; do [[ "$live" != "$name" ]] || found=1; done <<< "$live_volume_names"
    if (( found == 0 )); then
      [[ "$mode" == subset ]] && continue
      printf 'Transaction volume %s is missing from Engine state after successful create.\n' "$name" >&2
      return 1
    fi
    inspection=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" \
      volume inspect "$name") || return 1
    printf '%s' "$inspection" | jq -e \
      --arg project "$PROJECT_NAME" \
      --arg logical "$logical" \
      --arg name "$name" \
      --arg transactionId "$TRANSACTION_ID" \
      --arg transactionLabel "$TRANSACTION_LABEL" \
      --arg sourceModelSha256 "$TRANSACTION_SOURCE_MODEL_SHA256" \
      --arg sourceModelLabel "$TRANSACTION_MODEL_LABEL" \
      --argjson definition "$definition" '
        type == "array" and length == 1
        and (.[0] as $resource
          | ($definition | type == "object")
          and (($definition | keys - ["driver", "driver_opts", "labels", "name"]) | length == 0)
          and ($resource.Name == $name)
          and ($resource.Driver == ($definition.driver // "local"))
          and (($resource.Options // {}) == ($definition.driver_opts // {}))
          and ($resource.Scope | type == "string" and length > 0)
          and ($resource.Mountpoint | type == "string" and startswith("/"))
          and ($resource.CreatedAt | type == "string" and length > 0)
          and (($resource.Labels // {})["com.docker.compose.project"] == $project)
          and (($resource.Labels // {})["com.docker.compose.volume"] == $logical)
          and (($resource.Labels // {})[$transactionLabel] == $transactionId)
          and (($resource.Labels // {})[$sourceModelLabel] == $sourceModelSha256)
          and all(($definition.labels // {}) | to_entries[];
            . as $label | ($resource.Labels // {})[$label.key] == $label.value)
          and ((($resource.Labels // {}) | with_entries(select(.key != "com.docker.compose.version")))
            == (($definition.labels // {}) + {
              "com.docker.compose.project": $project,
              "com.docker.compose.volume": $logical
            }))
          and (($resource.Labels // {})["com.docker.compose.version"] | type == "string" and length > 0)
        )
      ' >/dev/null || {
        printf 'Candidate volume %s is not exact transaction-owned state; preserving it.\n' "$name" >&2
        return 1
      }
    normalized=$(printf '%s' "$inspection" | normalize_transaction_volume_inspection) || return 1
    cas_record=$(jq -cn --arg logicalName "$logical" --arg physicalName "$name" \
      --argjson inspection "$normalized" \
      '{logicalName: $logicalName, physicalName: $physicalName, inspection: $inspection}') || return 1
    existing=$(printf '%s' "$transaction_volumes" | jq -c --arg name "$name" \
      '[.[] | select(.physicalName == $name)]') || return 1
    existing_count=$(printf '%s' "$existing" | jq -r 'length') || return 1
    if (( existing_count == 1 )); then
      [[ "$(printf '%s' "$existing" | jq -c '.[0]')" == "$cas_record" ]] || {
        printf 'Registered transaction volume CAS cannot be refreshed for %s.\n' "$name" >&2
        return 1
      }
    elif (( existing_count == 0 )); then
      transaction_volumes=$(jq -cn --argjson current "$transaction_volumes" --argjson record "$cas_record" \
        '$current + [$record] | sort_by(.physicalName)') || return 1
    else
      return 1
    fi
  done < <(printf '%s' "$projection" | jq -c '.volumes[]')
  while IFS= read -r record; do
    [[ -z "$record" ]] && continue
    logical=$(printf '%s' "$record" | jq -er '.logicalName') || return 1
    name=$(printf '%s' "$record" | jq -er '.physicalName') || return 1
    definition=$(printf '%s' "$record" | jq -c '.definition') || return 1
    found=0
    while IFS= read -r live; do [[ "$live" != "$name" ]] || found=1; done <<< "$live_network_names"
    if (( found == 0 )); then
      [[ "$mode" == subset ]] && continue
      printf 'Transaction network %s is missing from Engine state after successful create.\n' "$name" >&2
      return 1
    fi
    inspection=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" \
      network inspect "$name") || return 1
    printf '%s' "$inspection" | jq -e \
      --arg project "$PROJECT_NAME" \
      --arg logical "$logical" \
      --arg name "$name" \
      --arg transactionId "$TRANSACTION_ID" \
      --arg transactionLabel "$TRANSACTION_LABEL" \
      --arg sourceModelSha256 "$TRANSACTION_SOURCE_MODEL_SHA256" \
      --arg sourceModelLabel "$TRANSACTION_MODEL_LABEL" \
      --argjson definition "$definition" '
        type == "array" and length == 1
        and (.[0] as $resource
          | ($definition | type == "object")
          and (($definition | keys - ["attachable", "driver", "driver_opts", "enable_ipv4", "enable_ipv6", "internal", "labels", "name"]) | length == 0)
          and ($resource.Id | type == "string" and length > 0)
          and ($resource.Name == $name)
          and ($resource.Driver == ($definition.driver // "bridge"))
          and (($resource.Options // {}) == ($definition.driver_opts // {}))
          and ($resource.Internal == ($definition.internal // false))
          and ($resource.Attachable == ($definition.attachable // false))
          and (if $definition.enable_ipv4 == null then true else ($resource.EnableIPv4 // true) == $definition.enable_ipv4 end)
          and (if $definition.enable_ipv6 == null then true else ($resource.EnableIPv6 // false) == $definition.enable_ipv6 end)
          and ($resource.Ingress == false)
          and (($resource.ConfigOnly // false) == false)
          and (($resource.Labels // {})["com.docker.compose.project"] == $project)
          and (($resource.Labels // {})["com.docker.compose.network"] == $logical)
          and (($resource.Labels // {})[$transactionLabel] == $transactionId)
          and (($resource.Labels // {})[$sourceModelLabel] == $sourceModelSha256)
          and all(($definition.labels // {}) | to_entries[];
            . as $label | ($resource.Labels // {})[$label.key] == $label.value)
          and ((($resource.Labels // {}) | with_entries(select(.key != "com.docker.compose.version")))
            == (($definition.labels // {}) + {
              "com.docker.compose.project": $project,
              "com.docker.compose.network": $logical
            }))
          and (($resource.Labels // {})["com.docker.compose.version"] | type == "string" and length > 0)
        )
      ' >/dev/null || {
        printf 'Candidate network %s is not exact transaction-owned state; preserving it.\n' "$name" >&2
        return 1
      }
    normalized=$(printf '%s' "$inspection" | normalize_transaction_network_inspection) || return 1
    cas_record=$(jq -cn --arg logicalName "$logical" --arg physicalName "$name" \
      --argjson inspection "$normalized" \
      '{logicalName: $logicalName, physicalName: $physicalName, inspection: $inspection}') || return 1
    existing=$(printf '%s' "$transaction_networks" | jq -c --arg name "$name" \
      '[.[] | select(.physicalName == $name)]') || return 1
    existing_count=$(printf '%s' "$existing" | jq -r 'length') || return 1
    if (( existing_count == 1 )); then
      [[ "$(printf '%s' "$existing" | jq -c '.[0]')" == "$cas_record" ]] || {
        printf 'Registered transaction network CAS cannot be refreshed for %s.\n' "$name" >&2
        return 1
      }
    elif (( existing_count == 0 )); then
      transaction_networks=$(jq -cn --argjson current "$transaction_networks" --argjson record "$cas_record" \
        '$current + [$record] | sort_by(.physicalName)') || return 1
    else
      return 1
    fi
  done < <(printf '%s' "$projection" | jq -c '.networks[]')
  old_volumes=$TRANSACTION_VOLUME_CAS
  old_networks=$TRANSACTION_NETWORK_CAS
  TRANSACTION_VOLUME_CAS=$transaction_volumes
  TRANSACTION_NETWORK_CAS=$transaction_networks
  TRANSACTION_RESOURCE_PROJECTION=$projection
  TRANSACTION_RESOURCE_MODE=$mode
  if ! assert_registered_transaction_resources \
      || ! assert_transaction_resource_projection "$model" "$mode" "$@"; then
    TRANSACTION_VOLUME_CAS=$old_volumes
    TRANSACTION_NETWORK_CAS=$old_networks
    TRANSACTION_RESOURCE_PROJECTION=$old_projection
    TRANSACTION_RESOURCE_MODE=$old_mode
    return 1
  fi
}

transaction_resource_collision_is_registered() {
  local kind=$1 name=$2 cas matches inspection actual expected
  if [[ "$kind" == volume ]]; then cas=$TRANSACTION_VOLUME_CAS; else cas=$TRANSACTION_NETWORK_CAS; fi
  matches=$(printf '%s' "$cas" | jq -c --arg name "$name" '[.[] | select(.physicalName == $name)]') || return 1
  [[ "$(printf '%s' "$matches" | jq -r 'length')" == 1 ]] || return 1
  expected=$(printf '%s' "$matches" | jq -c '.[0].inspection') || return 1
  inspection=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" \
    "$kind" inspect "$name") || return 1
  if [[ "$kind" == volume ]]; then
    actual=$(printf '%s' "$inspection" | normalize_transaction_volume_inspection) || return 1
  else
    actual=$(printf '%s' "$inspection" | normalize_transaction_network_inspection) || return 1
  fi
  [[ "$actual" == "$expected" ]]
}

assert_candidate_resource_boundary() {
  local model=$1 names name live candidate collision_type=
  local external_volumes bind_records service source target read_only create_host_path
  local docker_root_raw= docker_root= canonical_source protected
  local -a candidate_volumes=() candidate_networks=() live_volumes=() live_networks=()
  [[ "$model" == /* && -f "$model" && ! -L "$model" ]] || return 70
  assert_registered_transaction_resources || return 70
  external_volumes=$(jq -r --arg project "$PROJECT_NAME" '
    (.volumes // {})
    | to_entries[]
    | select((.value.external // false) == true)
    | (.value.name // ($project + "_" + .key))
  ' "$model") || return 70
  if [[ -n "$external_volumes" ]]; then
    printf '%s\n' "Candidate external persistent volume has no authoritative rebuild-backup receipt; refusing activation." >&2
    return 70
  fi
  bind_records=$(jq -r '
    .services
    | to_entries[] as $service
    | ($service.value.volumes // [])[]
    | if type != "object" then error("non-object mount") else . end
    | select(.type == "bind")
    | [
        $service.key,
        (.source // ""),
        (.target // ""),
        ((.read_only // false) | tostring),
        ((if (.bind.create_host_path | type) == "boolean"
          then .bind.create_host_path else true end) | tostring)
      ]
    | @tsv
  ' "$model") || return 70
  if [[ -n "$bind_records" ]]; then
    docker_root_raw=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" \
      info --format '{{.DockerRootDir}}') || return 70
    [[ "$docker_root_raw" == /* && "$docker_root_raw" != *$'\n'* && "$docker_root_raw" != *$'\r'* ]] || return 70
    docker_root=$(canonical_host_path "$docker_root_raw") || return 70
  fi
  while IFS=$'\t' read -r service source target read_only create_host_path; do
    [[ -z "$service$source$target$read_only$create_host_path" ]] && continue
    [[ -n "$service" && "$source" == /* && "$target" == /* \
        && "$source" != *$'\n'* && "$source" != *$'\r'* \
        && "$target" != *$'\n'* && "$target" != *$'\r'* ]] || return 70
    [[ "$read_only" == true || "$read_only" == false ]] || return 70
    [[ "$create_host_path" == true || "$create_host_path" == false ]] || return 70
    if [[ "$read_only" != true ]]; then
      printf 'Candidate writable bind has no authoritative rebuild-backup receipt for service %s; refusing activation.\n' \
        "$service" >&2
      return 70
    fi
    canonical_source=$(canonical_host_path "$source") || {
      printf 'Candidate bind source is not canonical for service %s; refusing activation.\n' "$service" >&2
      return 70
    }
    protected=0
    if host_path_has_docker_authority "$source" "$docker_root_raw" \
        || host_path_has_docker_authority "$canonical_source" "$docker_root"; then
      protected=1
    fi
    if (( protected == 1 )); then
      if ! assert_candidate_broker_socket_contract \
          "$model" "$service" "$source" "$target" "$read_only" "$create_host_path" \
          || [[ ! -S "$source" || -L "$source" ]]; then
        printf 'Candidate Docker socket or host-parent bind is not the release-bound exact broker contract and socket identity for service %s; refusing activation.\n' \
          "$service" >&2
        return 70
      fi
    else
      [[ -e "$source" && ! -L "$source" && "$source" == "$canonical_source" \
          && ( -f "$source" || -d "$source" ) ]] || {
        printf 'Candidate read-only bind source is absent, aliased, or has an unsupported identity for service %s; refusing activation.\n' \
          "$service" >&2
        return 70
      }
    fi
  done <<< "$bind_records"
  names=$(jq -r --arg project "$PROJECT_NAME" '
    (.volumes // {})
    | to_entries[]
    | select((.value.external // false) != true)
    | (.value.name // ($project + "_" + .key))
  ' "$model") || return 70
  while IFS= read -r name; do
    [[ -z "$name" ]] && continue
    [[ ${#name} -le 255 && "$name" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || return 70
    candidate_volumes+=("$name")
  done <<< "$names"
  names=$(jq -r --arg project "$PROJECT_NAME" '
    (.networks // {})
    | to_entries[]
    | select((.value.external // false) != true)
    | (.value.name // ($project + "_" + .key))
  ' "$model") || return 70
  while IFS= read -r name; do
    [[ -z "$name" ]] && continue
    [[ ${#name} -le 255 && "$name" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || return 70
    candidate_networks+=("$name")
  done <<< "$names"
  names=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" \
    volume ls --format '{{.Name}}') || return 70
  while IFS= read -r name; do [[ -z "$name" ]] || live_volumes+=("$name"); done <<< "$names"
  names=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" \
    network ls --format '{{.Name}}') || return 70
  while IFS= read -r name; do [[ -z "$name" ]] || live_networks+=("$name"); done <<< "$names"
  for candidate in "${candidate_volumes[@]:-}"; do
    [[ -n "$candidate" ]] || continue
    for live in "${live_volumes[@]:-}"; do
      if [[ "$candidate" == "$live" ]] \
          && ! transaction_resource_collision_is_registered volume "$candidate"; then
        collision_type=volume
      fi
    done
  done
  for candidate in "${candidate_networks[@]:-}"; do
    [[ -n "$candidate" ]] || continue
    for live in "${live_networks[@]:-}"; do
      if [[ "$candidate" == "$live" ]] \
          && ! transaction_resource_collision_is_registered network "$candidate"; then
        collision_type=network
      fi
    done
  done
  [[ -z "$collision_type" ]] || {
    printf 'Candidate-owned %s already exists without transaction ownership; preserving it and refusing activation.\n' \
      "$collision_type" >&2
    return 70
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

assert_mutex_identity() {
  # The privileged supervisor, not this unprivileged gate, owns the mutex
  # descriptor. A challenge-bound ping proves this process is still attached
  # to that supervisor and the exact global coordinator.
  assert_broker_session
}

state_read_optional() {
  local name=$1 snapshot selector
  case "$name" in
    journal.json) selector=.journal ;;
    active.json) selector=.active ;;
    *) return 1 ;;
  esac
  snapshot=$(broker_client snapshot) || return 1
  printf '%s' "$snapshot" | jq -c "$selector // empty"
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
  assert_project_preservation_boundary || return 70
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

commit_active_receipt() {
  local target_state=$1 model=$2 detail=$3 lock_path= model_sha= result services_json
  shift 3
  assert_project_preservation_boundary || return 70
  services_json=$(printf '%s\n' "$@" | jq -Rsc 'split("\n") | map(select(length > 0)) | unique | sort') || return 1
  if [[ "$target_state" == hosted ]]; then
    lock_path=$LOCK
  fi
  if [[ "$target_state" != stopped ]]; then
    model_sha=$(sha256_file "$model") || return 1
  fi
  COMMIT_ATTEMPTED=1
  COMMIT_TARGET_STATE=$target_state
  COMMIT_EXPECTED_MODEL_SHA=$model_sha
  COMMIT_EXPECTED_SERVICES=$services_json
  if ! result=$(jq -cn \
    --argjson serviceNames "$services_json" \
    --argjson containerReceipts "$CONTAINER_RECEIPTS" \
    --argjson networkReceipts "$NETWORK_RECEIPTS" \
    --argjson volumeReceipts "$VOLUME_RECEIPTS" \
    '{serviceNames: $serviceNames, containerReceipts: $containerReceipts,
      networkReceipts: $networkReceipts, volumeReceipts: $volumeReceipts}' \
    | broker_client commit \
      "$TRANSACTION_ID" "$JOURNAL_PHASE" "$RELEASE_CONTEXT" "$EXPECTED_DAEMON_ID" \
      "$target_state" "$lock_path" "$model_sha" "$detail"); then
    reconcile_commit_outcome && return 0
    return 1
  fi
  JOURNAL=$(printf '%s' "$result" | jq -c '.journal') || return 1
  ACTIVE_RECEIPT=$(printf '%s' "$result" | jq -c '.active') || return 1
  JOURNAL_PHASE=complete
}

reconcile_commit_outcome() {
  local snapshot
  COMMIT_RECONCILIATION=ambiguous
  if [[ "$SYSTEM_NAME" != Linux && "${HOSTED_TEST_COMMIT_SNAPSHOT_UNAVAILABLE:-0}" == 1 ]]; then
    return 2
  fi
  snapshot=$(broker_client snapshot) || return 2
  if printf '%s' "$snapshot" | jq -e \
    --arg transactionId "$TRANSACTION_ID" \
    --arg targetState "$COMMIT_TARGET_STATE" \
    --arg contextPath "$RELEASE_CONTEXT" \
    --arg contextSha256 "$RELEASE_CONTEXT_SHA256" \
    --arg daemonId "$EXPECTED_DAEMON_ID" \
    --arg modelSha256 "$COMMIT_EXPECTED_MODEL_SHA" \
    --argjson services "$COMMIT_EXPECTED_SERVICES" '
      .journal.version == 2
      and .journal.state == "complete"
      and .journal.phase == "complete"
      and .journal.transactionId == $transactionId
      and .journal.actualState == $targetState
      and .active.version == 2
      and .active.state == $targetState
      and .active.releaseContextPath == $contextPath
      and .active.releaseContextSha256 == $contextSha256
      and .active.daemonId == $daemonId
      and .active.serviceNames == $services
      and (if $targetState == "stopped" then
        .active.modelSha256 == null
      else
        .active.modelSha256 == $modelSha256
      end)
    ' >/dev/null; then
    JOURNAL=$(printf '%s' "$snapshot" | jq -c '.journal') || return 2
    ACTIVE_RECEIPT=$(printf '%s' "$snapshot" | jq -c '.active') || return 2
    JOURNAL_PHASE=complete
    COMMIT_RECONCILIATION=committed
    return 0
  fi
  if printf '%s' "$snapshot" | jq -e \
    --arg transactionId "$TRANSACTION_ID" '
      .journal.version == 2
      and .journal.state == "pending"
      and .journal.transactionId == $transactionId
    ' >/dev/null; then
    COMMIT_RECONCILIATION=pending
    return 1
  fi
  return 2
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
      and (.workloadId | type == "string" and test("^[a-z][a-z0-9-]{1,60}$"))
      and (.serviceName | type == "string" and test("^[a-z][a-z0-9-]{1,62}$"))
      and $record.workloadId == service_owner($record.serviceName; $ids);
    def network_record($ids; $projectName):
      . as $record
      | type == "object"
      and ((keys | sort) == ["logicalName", "physicalName", "workloadId"])
      and (.workloadId | type == "string" and test("^[a-z][a-z0-9-]{1,60}$"))
      and (.logicalName | type == "string" and test("^[a-z0-9][a-z0-9_]*$"))
      and $record.workloadId == network_owner($record.logicalName; $ids)
      and (($record.logicalName | split("_") | last) as $zone
        | ($zone | IN("ingress", "postgres", "cache", "bus", "identity", "storage", "observability", "egress"))
        and $record.logicalName == (($record.workloadId | gsub("-"; "_")) + "_" + $zone))
      and $record.physicalName == ($projectName + "_" + $record.logicalName);
    def extension_record:
      type == "object"
      and ((keys | sort) == ["networkNames", "serviceName", "workloadId"])
      and (.workloadId | type == "string" and test("^[a-z][a-z0-9-]{1,60}$"))
      and (.serviceName | IN("project-router", "postgres", "redis", "nats", "keycloak", "minio", "prometheus"))
      and (.networkNames | type == "array" and length > 0 and . == (unique | sort))
      and all(.networkNames[]; type == "string" and length > 0);
    def route_record($ids):
      . as $record
      | type == "object"
      and ((keys | sort) == ["port", "serviceName", "slug", "upstream", "workloadId"])
      and (.workloadId | type == "string" and test("^[a-z][a-z0-9-]{1,60}$"))
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
      and prefix_disjoint and all(.[]; type == "string" and test("^[a-z][a-z0-9-]{1,60}$")))
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
  PLATFORM_TRUSTED_RELEASE_CONTEXT="$RELEASE_CONTEXT" \
  COMPOSE_ENV_FILE="$ENV_FILE" \
  COMPOSE_PROJECT_NAME="$PROJECT_NAME" \
  HOSTED_WORKLOAD_LOCK="$lock_path" \
  HOSTED_WORKLOAD_MODE=hosted \
  HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE="$lock_path" \
  HOSTED_WORKLOAD_ALLOW_RESOLVED=0 \
  HOSTED_WORKLOAD_PREPARE_RESOLVED=0 \
    bash "$SCRIPT_DIR/compose-vps.sh" config --format json > "$output"
  chmod 600 "$output"
}

render_core_model() {
  local lock_path=$1 output=$2
  PLATFORM_TRUSTED_RELEASE_CONTEXT="$RELEASE_CONTEXT" \
  COMPOSE_ENV_FILE="$ENV_FILE" \
  COMPOSE_PROJECT_NAME="$PROJECT_NAME" \
  HOSTED_WORKLOAD_LOCK= \
  HOSTED_WORKLOAD_MODE=hosted \
  HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE="$lock_path" \
  HOSTED_WORKLOAD_ALLOW_RESOLVED=1 \
  HOSTED_WORKLOAD_PREPARE_RESOLVED=1 \
    bash "$SCRIPT_DIR/compose-vps.sh" config --format json > "$output"
  chmod 600 "$output"
}

render_no_hosted_model() {
  local output=$1
  PLATFORM_TRUSTED_RELEASE_CONTEXT="$RELEASE_CONTEXT" \
  COMPOSE_ENV_FILE="$ENV_FILE" \
  COMPOSE_PROJECT_NAME="$PROJECT_NAME" \
  HOSTED_WORKLOAD_LOCK= \
  HOSTED_WORKLOAD_MODE=no-hosted \
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

bind_transaction_runtime_model() {
  local source_model=$1 output=$2 source_model_sha
  [[ "$TRANSACTION_ID" =~ ^[a-f0-9]{64}$ ]] || {
    printf '%s\n' "Activation transaction identity is invalid." >&2
    return 1
  }
  [[ "$source_model" == /* && "$output" == /* && "$source_model" != "$output" ]] || return 1
  source_model_sha=$(sha256_file "$source_model") || return 1
  [[ "$source_model_sha" =~ ^[a-f0-9]{64}$ ]] || return 1
  jq --arg transactionId "$TRANSACTION_ID" \
    --arg transactionLabel "$TRANSACTION_LABEL" \
    --arg sourceModelSha256 "$source_model_sha" \
    --arg sourceModelLabel "$TRANSACTION_MODEL_LABEL" '
    def bind_labels:
      if (((.labels // {}) | has($transactionLabel))
          or ((.labels // {}) | has($sourceModelLabel))) then
        error("activation CAS label is already present")
      else
        .labels = ((.labels // {}) + {
          ($transactionLabel): $transactionId,
          ($sourceModelLabel): $sourceModelSha256
        })
      end;
    .services |= with_entries(
      if (((.value.labels // {}) | has($transactionLabel))
          or ((.value.labels // {}) | has($sourceModelLabel))) then
        error("activation CAS label is already present")
      else
        .value.labels = ((.value.labels // {}) + {
          ($transactionLabel): $transactionId,
          ($sourceModelLabel): $sourceModelSha256
        })
      end
    )
    | .volumes = ((.volumes // {}) | with_entries(
        if (.value.external // false) == true then .
        else .value = ((.value // {}) | bind_labels)
        end
      ))
    | .networks = ((.networks // {}) | with_entries(
        if (.value.external // false) == true then .
        else .value = ((.value // {}) | bind_labels)
        end
      ))
  ' "$source_model" > "$output" || return 1
  chmod 600 "$output"
  jq -e --arg transactionId "$TRANSACTION_ID" \
    --arg transactionLabel "$TRANSACTION_LABEL" \
    --arg sourceModelSha256 "$source_model_sha" \
    --arg sourceModelLabel "$TRANSACTION_MODEL_LABEL" \
    --slurpfile source "$source_model" '
      . as $runtime
      | $source[0] as $original
      | (($runtime | del(.services, .volumes, .networks)) == ($original | del(.services, .volumes, .networks)))
      and (($runtime.services | keys | sort) == ($original.services | keys | sort))
      and all($runtime.services | to_entries[];
        .key as $service
        | (.value.labels[$transactionLabel] == $transactionId)
        and (.value.labels[$sourceModelLabel] == $sourceModelSha256)
        and ((
          .value
          | .labels |= del(.[$transactionLabel])
          | .labels |= del(.[$sourceModelLabel])
          | if ($original.services[$service] | has("labels")) then . else del(.labels) end
        ) == $original.services[$service])
      )
      and (["volumes", "networks"] | all(.[];
        . as $kind
        | (($runtime[$kind] // {}) | to_entries | all(.[];
          .key as $resource
          | ($original[$kind][$resource] // {}) as $originalDefinition
          | if ($originalDefinition.external // false) == true then
              .value == $originalDefinition
            else
              (.value.labels[$transactionLabel] == $transactionId)
              and (.value.labels[$sourceModelLabel] == $sourceModelSha256)
              and ((
                .value
                | .labels |= del(.[$transactionLabel])
                | .labels |= del(.[$sourceModelLabel])
                | if ($originalDefinition | has("labels")) then . else del(.labels) end
              ) == $originalDefinition)
            end
        ))
      ))
      and (($runtime.volumes // {} | keys | sort) == ($original.volumes // {} | keys | sort))
      and (($runtime.networks // {} | keys | sort) == ($original.networks // {} | keys | sort))
    ' "$output" >/dev/null || {
      printf '%s\n' "Transaction-labelled runtime model is not an exact derived model." >&2
      return 1
    }
  TRANSACTION_SOURCE_MODEL_SHA256=$source_model_sha
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

register_transaction_created_containers() {
  local model=$1 mode=$2
  shift 2
  local ids id candidate duplicate inspections expected_ids expected_services expected_subjects candidate_cas
  local project_inventory project_json
  local -a candidate_ids=() project_ids=()
  ((${#TRANSACTION_CREATED_CONTAINER_IDS[@]} == 0)) || {
    printf '%s\n' "Transaction container identities may be registered only once." >&2
    return 1
  }
  [[ "$mode" == exact || "$mode" == subset ]] || return 1
  ids=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" ps -aq --no-trunc \
    --filter "label=com.docker.compose.project=$PROJECT_NAME" \
    --filter "label=$TRANSACTION_LABEL=$TRANSACTION_ID") || return 1
  while IFS= read -r id; do
    [[ -z "$id" ]] && continue
    [[ "$id" =~ ^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$ ]] || {
      printf '%s\n' "Compose returned an invalid created container identity." >&2
      return 1
    }
    duplicate=0
    for candidate in "${candidate_ids[@]:-}"; do
      [[ "$candidate" != "$id" ]] || duplicate=1
    done
    (( duplicate == 0 )) || {
      printf '%s\n' "Compose returned duplicate created container identities." >&2
      return 1
    }
    candidate_ids+=("$id")
  done <<< "$ids"
  if [[ "$mode" == exact ]]; then
    ((${#candidate_ids[@]} == $#)) || {
      printf '%s\n' "Created service container identities are not exact; refusing unowned cleanup." >&2
      return 1
    }
  else
    ((${#candidate_ids[@]} <= $#)) || {
      printf '%s\n' "Partial create returned more transaction containers than authorized services." >&2
      return 1
    }
  fi
  if ((${#candidate_ids[@]} == 0)); then
    [[ "$mode" == subset ]] || {
      printf '%s\n' "Created service container identities are not exact; refusing unowned cleanup." >&2
      return 1
    }
    assert_project_preservation_boundary
    return
  fi
  expected_ids=$(printf '%s\n' "${candidate_ids[@]}" | jq -Rsc 'split("\n") | map(select(length > 0)) | sort') || return 1
  expected_services=$(printf '%s\n' "$@" | jq -Rsc 'split("\n") | map(select(length > 0)) | sort') || return 1
  expected_subjects=$(printf '%s' "$RELEASE_CONTEXT_JSON" | jq -c '.subjects') || return 1
  inspections=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" inspect \
    "${candidate_ids[@]}") || return 1
  printf '%s' "$inspections" | jq -e \
    --arg project "$PROJECT_NAME" \
    --arg transactionId "$TRANSACTION_ID" \
    --arg transactionLabel "$TRANSACTION_LABEL" \
    --argjson expectedIds "$expected_ids" \
    --argjson expectedServices "$expected_services" \
    --argjson subjects "$expected_subjects" \
    --arg mode "$mode" \
    --slurpfile model "$model" '
      def actual_mounts:
        [(.Mounts // [])[]
          | if .Type == "volume" then
              {type: "volume", source: (.Name // ""), target: .Destination,
               rw: (.RW == true), propagation: ""}
            elif .Type == "bind" then
              {type: "bind", source: .Source, target: .Destination,
               rw: (.RW == true), propagation: (.Propagation // "rprivate")}
            elif .Type == "tmpfs" then
              {type: "tmpfs", source: "", target: .Destination,
               rw: (.RW == true), propagation: ""}
            else error("unsupported Engine mount type") end]
        | sort_by(.type, .target, .source);
      def expected_mounts($definition; $model; $project):
        [($definition.volumes // [])[]
          | if type != "object" then error("non-object model mount")
            elif .type == "volume" then
              (.source // "") as $logical
              | if ($logical | type == "string" and length > 0)
                  and (($model.volumes[$logical] | type) == "object")
                then {type: "volume",
                      source: ($model.volumes[$logical].name // ($project + "_" + $logical)),
                      target: .target, rw: ((.read_only // false) != true), propagation: ""}
                else error("anonymous or missing model volume") end
            elif .type == "bind" then
              {type: "bind", source: .source, target: .target,
               rw: ((.read_only // false) != true), propagation: (.bind.propagation // "rprivate")}
            elif .type == "tmpfs" then
              {type: "tmpfs", source: "", target: .target,
               rw: ((.read_only // false) != true), propagation: ""}
            else error("unsupported model mount type") end]
        | sort_by(.type, .target, .source);
      def expected_networks($definition; $model; $project):
        [($definition.networks // {})
          | if type == "object" then keys[]
            elif type == "array" then .[]
            else error("invalid model networks") end
          | . as $logical
          | if ($model.networks[$logical] | type) == "object"
            then ($model.networks[$logical].name // ($project + "_" + $logical))
            else error("missing model network") end]
        | unique | sort;
      type == "array"
      and length == ($expectedIds | length)
      and ([.[].Id] | sort) == $expectedIds
      and ([.[].Config.Labels["com.docker.compose.service"]] | unique | length) == length
      and all(.[];
        .Config.Labels["com.docker.compose.service"] as $service
        | $expectedServices | index($service) != null)
      and all(.[];
        . as $container
        | ($container.Config.Labels["com.docker.compose.service"] // "") as $service
        | ($model[0].services[$service] // null) as $definition
        | ([$subjects[] | select(.serviceName == $service)]) as $matchingSubjects
        | (($definition.labels // {}) | to_entries) as $expectedLabels
        | (expected_mounts($definition; $model[0]; $project)) as $expectedMounts
        | (expected_networks($definition; $model[0]; $project)) as $expectedNetworks
        | ((($definition | type) == "object")
        and (($matchingSubjects | length) == 1)
        and ($container.Config.Labels["com.docker.compose.project"] == $project)
        and ($container.Config.Labels[$transactionLabel] == $transactionId)
        and ($container.Config.Labels["com.docker.compose.config-hash"] | type == "string" and test("^[a-f0-9]{64}$"))
        and ($container.Config.Image == $definition.image)
        and ($container.Image == $matchingSubjects[0].imageId)
        and ($matchingSubjects[0].imageReference == $definition.image)
        and all($expectedLabels[];
            . as $expectedLabel
            | $container.Config.Labels[$expectedLabel.key] == $expectedLabel.value)
        and ($container.State.Running == false)
        and ($container.State.Paused == false)
        and ($container.State.Restarting == false)
        and (($container | actual_mounts) == $expectedMounts)
        and (((($container.NetworkSettings.Networks // {}) | keys | unique | sort)) == $expectedNetworks)
        and (if $mode == "subset" then
          $container.State.Status == "created"
          and $container.State.StartedAt == "0001-01-01T00:00:00Z"
          and $container.State.FinishedAt == "0001-01-01T00:00:00Z"
        else true end))
      )
    ' >/dev/null || {
      printf '%s\n' "Created container identities and transaction ownership are not exact; refusing cleanup." >&2
      return 1
    }
  candidate_cas=$(printf '%s' "$inspections" | jq -c '
    def normalized_mounts:
      [(.Mounts // [])[]
        | if .Type == "volume" then
            {type: "volume", source: (.Name // ""), target: .Destination,
             rw: (.RW == true), propagation: ""}
          elif .Type == "bind" then
            {type: "bind", source: .Source, target: .Destination,
             rw: (.RW == true), propagation: (.Propagation // "rprivate")}
          elif .Type == "tmpfs" then
            {type: "tmpfs", source: "", target: .Destination,
             rw: (.RW == true), propagation: ""}
          else error("unsupported Engine mount type") end]
      | sort_by(.type, .target, .source);
    [.[] | {
      id: .Id,
      configHash: .Config.Labels["com.docker.compose.config-hash"],
      mounts: normalized_mounts,
      networks: ((.NetworkSettings.Networks // {}) | keys | unique | sort)
    }] | sort_by(.id)
  ') || return 1
  project_inventory=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" ps -aq --no-trunc \
    --filter "label=com.docker.compose.project=$PROJECT_NAME") || return 1
  while IFS= read -r id; do
    [[ -z "$id" ]] && continue
    [[ "$id" =~ ^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$ ]] || return 1
    for candidate in "${project_ids[@]:-}"; do
      [[ "$candidate" != "$id" ]] || {
        printf '%s\n' "Project inventory contains duplicate identities; refusing transaction registration." >&2
        return 1
      }
    done
    project_ids+=("$id")
  done <<< "$project_inventory"
  project_json=$(printf '%s\n' "${project_ids[@]:-}" \
    | jq -Rsc 'split("\n") | map(select(length > 0)) | sort') || return 1
  [[ "$project_json" == "$expected_ids" ]] || {
    printf '%s\n' "Project inventory contains an unknown container; transaction subset was not registered." >&2
    return 1
  }
  TRANSACTION_CREATED_CONTAINER_IDS=("${candidate_ids[@]}")
  TRANSACTION_CONTAINER_CAS=$candidate_cas
  assert_project_preservation_boundary || return 1
  if [[ "$mode" == subset ]]; then TRANSACTION_CONTAINERS_REMOVABLE=1; fi
}

create_services() {
  local model=$1
  shift
  local create_status=0 registration_mode=exact
  (("$#" > 0)) || return 1
  assert_daemon_identity || return 1
  assert_project_preservation_boundary || return 70
  assert_candidate_resource_boundary "$model" || return 70
  assert_daemon_identity || return 1
  assert_global_docker_authority_boundary || return 70
  assert_daemon_identity || return 1
  timeout "$ACTIVATION_TIMEOUT" \
    bash -c 'endpoint=$1; model=$2; root=$3; project=$4; shift 4; unset COMPOSE_REMOVE_ORPHANS; exec docker --host "$endpoint" compose --project-directory "$root" --profile backup -p "$project" -f "$model" create --no-build --pull never --no-deps --no-recreate "$@"' \
    hosted-create "$CANONICAL_DOCKER_HOST" "$model" "$INFRA_ROOT" "$PROJECT_NAME" "$@" \
    || create_status=$?
  if (( create_status != 0 )); then registration_mode=subset; fi
  register_transaction_resources "$model" "$registration_mode" "$@" || return 1
  register_transaction_created_containers "$model" "$registration_mode" "$@" || return 1
  (( create_status == 0 )) || return "$create_status"
  assert_daemon_identity || return 1
  assert_global_docker_authority_boundary "$model" || return 70
  assert_registered_transaction_resources || return 1
  assert_daemon_identity
}

start_services() {
  local model=$1
  shift
  local ids count
  (("$#" > 0)) || return 1
  assert_daemon_identity || return 1
  assert_project_preservation_boundary || return 70
  ids=$(timeout "$VERIFY_TIMEOUT" \
    bash -c 'endpoint=$1; model=$2; root=$3; project=$4; shift 4; exec docker --host "$endpoint" compose --project-directory "$root" --profile backup -p "$project" -f "$model" ps -aq "$@"' \
    hosted-ids "$CANONICAL_DOCKER_HOST" "$model" "$INFRA_ROOT" "$PROJECT_NAME" "$@") || return 1
  count=$(printf '%s\n' "$ids" | awk 'NF { count += 1 } END { print count + 0 }')
  [[ "$count" -eq "$#" && "$(printf '%s\n' "$ids" | awk 'NF && !seen[$0]++ { count += 1 } END { print count + 0 }')" -eq "$#" ]] || {
    printf '%s\n' "Created service container IDs are not exact." >&2
    return 1
  }
  assert_project_preservation_boundary || return 70
  assert_registered_transaction_resources || return 70
  assert_daemon_identity || return 1
  assert_global_docker_authority_boundary "$model" || return 70
  assert_daemon_identity || return 1
  # Word splitting is intentional after the strict one-ID-per-line count above.
  timeout "$ACTIVATION_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" start $ids >/dev/null || return 1
  assert_daemon_identity || return 1
  assert_project_preservation_boundary || return 70
  assert_registered_transaction_resources || return 70
  assert_global_docker_authority_boundary "$model" || return 70
  assert_daemon_identity
}

stop_and_prove() {
  local model=$1
  shift
  local ids inspections
  (("$#" > 0)) || return 1
  assert_daemon_identity || return 1
  assert_project_preservation_boundary || return 70
  assert_registered_transaction_resources || return 70
  timeout "$STOP_TIMEOUT" \
    bash -c 'endpoint=$1; model=$2; root=$3; project=$4; shift 4; exec docker --host "$endpoint" compose --project-directory "$root" --profile backup -p "$project" -f "$model" stop --timeout 30 "$@"' \
    hosted-stop "$CANONICAL_DOCKER_HOST" "$model" "$INFRA_ROOT" "$PROJECT_NAME" "$@" || return 1
  assert_daemon_identity || return 1
  assert_registered_transaction_resources || return 70
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
  assert_registered_transaction_resources
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
    assert_project_preservation_boundary || return 70
    assert_registered_transaction_resources || return 70
    assert_global_docker_authority_boundary "$model" || return 70
    assert_daemon_identity || return 1
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
  assert_project_preservation_boundary || return 70
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

recover_pending_transaction() {
  local previous_journal=$1 source_model=$2 transaction_model=$3
  local previous_state_id retained_context_path retained_context retained_context_sha
  local pending_transaction pending_phase recovery
  [[ "$RECOVER_PENDING" == 1 ]] || {
    printf '%s\n' "A durable pending activation exists; rerun with --recover-pending for fail-closed reconciliation." >&2
    return 1
  }
  printf '%s' "$previous_journal" | jq -e \
    --arg project "$PROJECT_NAME" '
    .version == 2 and .state == "pending" and .projectName == $project
    and (.transactionId | type == "string" and test("^[a-f0-9]{64}$"))
    and (.stateId | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9._:-]{7,254}$"))
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
  pending_transaction=$(printf '%s' "$previous_journal" | jq -r '.transactionId') || return 1
  pending_phase=$(printf '%s' "$previous_journal" | jq -r '.phase') || return 1
  [[ "$RELEASE_CONTEXT" == "$retained_context_path" \
      && "$RELEASE_CONTEXT_SHA256" == "$retained_context_sha" \
      && "$RELEASE_CONTEXT_JSON" == "$retained_context" ]] || {
    printf '%s\n' "Pending activation belongs to a different trusted release context; adoption is forbidden." >&2
    return 1
  }
  if [[ "$pending_phase" == creating ]]; then
    [[ "$ACTION" == activate ]] || {
      printf '%s\n' "A pending create transaction can only be resumed by the activation action." >&2
      return 1
    }
    [[ "$source_model" == /* && "$transaction_model" == /* \
        && -f "$source_model" && ! -L "$source_model" ]] || return 1
    TRANSACTION_ID=$pending_transaction
    bind_transaction_runtime_model "$source_model" "$transaction_model" || return 1
    register_transaction_created_containers \
      "$transaction_model" subset "${CURRENT_ALL_SERVICES[@]}" || {
        printf '%s\n' "Pending partial-create containers are not the exact never-started transaction subset; preserving them." >&2
        return 1
      }
    register_transaction_resources "$transaction_model" subset "${CURRENT_ALL_SERVICES[@]}" || {
      printf '%s\n' "Pending partial-create resources are not exact transaction-owned identities; preserving them." >&2
      return 1
    }
    assert_candidate_resource_boundary "$transaction_model" || return 1
    assert_global_docker_authority_boundary "$transaction_model" || return 1
    assert_daemon_identity || return 1
    if ((${#TRANSACTION_CREATED_CONTAINER_IDS[@]} > 0)); then
      MUTATION_STARTED=1
      stop_transaction_created_and_prove || return 1
      remove_transaction_created_and_prove || return 1
      MUTATION_STARTED=0
    fi
    assert_project_preservation_boundary || return 1
    assert_registered_transaction_resources || return 1
    JOURNAL=$previous_journal
    JOURNAL_PHASE=creating
    RESUME_CREATING=1
    return 0
  fi
  assert_project_preservation_boundary || {
    printf '%s\n' "Pending recovery has no authenticated transaction-owned container ID set; preserving the project." >&2
    return 1
  }
  assert_global_docker_authority_boundary || return 1
  recovery=$(broker_client recover-stop \
    "$pending_transaction" "$pending_phase" "$retained_context_path" "$EXPECTED_DAEMON_ID" \
    "pending transaction was fail-closed after proving the project inventory empty") || return 1
  JOURNAL=$(printf '%s' "$recovery" | jq -c '.journal') || return 1
  ACTIVE_RECEIPT=$(printf '%s' "$recovery" | jq -c '.active') || return 1
  JOURNAL_PHASE=complete
}

stop_transaction_created_and_prove() {
  local inspections expected_ids
  ((${#TRANSACTION_CREATED_CONTAINER_IDS[@]} > 0)) || return 0
  assert_daemon_identity || return 1
  assert_project_preservation_boundary || return 1
  assert_registered_transaction_resources || return 1
  expected_ids=$(printf '%s\n' "${TRANSACTION_CREATED_CONTAINER_IDS[@]}" \
    | jq -Rsc 'split("\n") | map(select(length > 0)) | sort') || return 1
  inspections=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" inspect \
    "${TRANSACTION_CREATED_CONTAINER_IDS[@]}") || return 1
  printf '%s' "$inspections" | jq -e \
    --arg project "$PROJECT_NAME" \
    --arg transactionId "$TRANSACTION_ID" \
    --arg transactionLabel "$TRANSACTION_LABEL" \
    --arg sourceModelSha256 "$TRANSACTION_SOURCE_MODEL_SHA256" \
    --arg sourceModelLabel "$TRANSACTION_MODEL_LABEL" \
    --argjson expectedCas "$TRANSACTION_CONTAINER_CAS" \
    --argjson expectedIds "$expected_ids" \
    --argjson expectedCount "${#TRANSACTION_CREATED_CONTAINER_IDS[@]}" '
      length == $expectedCount
      and ([.[].Id] | sort) == $expectedIds
      and ([.[] | {
        id: .Id,
        configHash: .Config.Labels["com.docker.compose.config-hash"]
      }] | sort_by(.id)) == ($expectedCas | map({id, configHash}) | sort_by(.id))
      and all(.[];
        .Config.Labels["com.docker.compose.project"] == $project
        and .Config.Labels[$transactionLabel] == $transactionId
        and .Config.Labels[$sourceModelLabel] == $sourceModelSha256)
    ' >/dev/null || {
    printf '%s\n' "Registered container ownership could not be revalidated; refusing cleanup." >&2
    return 1
  }
  assert_registered_transaction_resources || return 1
  timeout "$STOP_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" stop --time 30 \
    "${TRANSACTION_CREATED_CONTAINER_IDS[@]}" >/dev/null || return 1
  assert_daemon_identity || return 1
  assert_project_preservation_boundary || return 1
  assert_registered_transaction_resources || return 1
  inspections=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" inspect \
    "${TRANSACTION_CREATED_CONTAINER_IDS[@]}") || return 1
  printf '%s' "$inspections" | jq -e \
    --arg project "$PROJECT_NAME" \
    --arg transactionId "$TRANSACTION_ID" \
    --arg transactionLabel "$TRANSACTION_LABEL" \
    --arg sourceModelSha256 "$TRANSACTION_SOURCE_MODEL_SHA256" \
    --arg sourceModelLabel "$TRANSACTION_MODEL_LABEL" \
    --argjson expectedCas "$TRANSACTION_CONTAINER_CAS" \
    --argjson expectedIds "$expected_ids" '
    ([.[].Id] | sort) == $expectedIds
    and ([.[] | {
      id: .Id,
      configHash: .Config.Labels["com.docker.compose.config-hash"]
    }] | sort_by(.id)) == ($expectedCas | map({id, configHash}) | sort_by(.id))
    and all(.[];
      .Config.Labels["com.docker.compose.project"] == $project
      and .Config.Labels[$transactionLabel] == $transactionId
      and .Config.Labels[$sourceModelLabel] == $sourceModelSha256
      and .State.Running == false
      and .State.Paused == false
      and .State.Restarting == false)
  ' >/dev/null || return 1
  assert_registered_transaction_resources
}

remove_transaction_created_and_prove() {
  local inspections expected_ids remaining post_inspect
  ((${#TRANSACTION_CREATED_CONTAINER_IDS[@]} > 0)) || return 0
  (( TRANSACTION_CONTAINERS_REMOVABLE == 1 )) || {
    printf '%s\n' "Transaction containers were not proven never-started; refusing writable-layer removal." >&2
    return 1
  }
  assert_daemon_identity || return 1
  assert_project_preservation_boundary || return 1
  assert_registered_transaction_resources || return 1
  expected_ids=$(printf '%s\n' "${TRANSACTION_CREATED_CONTAINER_IDS[@]}" \
    | jq -Rsc 'split("\n") | map(select(length > 0)) | sort') || return 1
  inspections=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" inspect \
    "${TRANSACTION_CREATED_CONTAINER_IDS[@]}") || return 1
  printf '%s' "$inspections" | jq -e \
    --arg project "$PROJECT_NAME" \
    --arg transactionId "$TRANSACTION_ID" \
    --arg transactionLabel "$TRANSACTION_LABEL" \
    --arg sourceModelSha256 "$TRANSACTION_SOURCE_MODEL_SHA256" \
    --arg sourceModelLabel "$TRANSACTION_MODEL_LABEL" \
    --argjson expectedCas "$TRANSACTION_CONTAINER_CAS" \
    --argjson expectedIds "$expected_ids" '
      ([.[].Id] | sort) == $expectedIds
      and ([.[] | {
        id: .Id,
        configHash: .Config.Labels["com.docker.compose.config-hash"]
      }] | sort_by(.id)) == ($expectedCas | map({id, configHash}) | sort_by(.id))
      and all(.[];
        .Config.Labels["com.docker.compose.project"] == $project
        and .Config.Labels[$transactionLabel] == $transactionId
        and .Config.Labels[$sourceModelLabel] == $sourceModelSha256
        and .State.Running == false
        and .State.Paused == false
        and .State.Restarting == false
        and .State.Status == "created"
        and .State.StartedAt == "0001-01-01T00:00:00Z"
        and .State.FinishedAt == "0001-01-01T00:00:00Z")
    ' >/dev/null || {
    printf '%s\n' "Never-started transaction container CAS could not be revalidated; refusing removal." >&2
    return 1
  }
  assert_registered_transaction_resources || return 1
  timeout "$STOP_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" rm \
    "${TRANSACTION_CREATED_CONTAINER_IDS[@]}" >/dev/null || return 1
  assert_daemon_identity || return 1
  assert_registered_transaction_resources || return 1
  remaining=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" ps -aq --no-trunc \
    --filter "label=com.docker.compose.project=$PROJECT_NAME") || return 1
  [[ -z "$remaining" ]] || {
    printf '%s\n' "Project inventory is not empty after exact transaction removal; preserving remaining containers." >&2
    return 1
  }
  if post_inspect=$(timeout "$VERIFY_TIMEOUT" docker --host "$CANONICAL_DOCKER_HOST" inspect \
      "${TRANSACTION_CREATED_CONTAINER_IDS[@]}" 2>/dev/null); then
    printf '%s' "$post_inspect" | jq -e 'type == "array" and length == 0' >/dev/null || return 1
  fi
  TRANSACTION_CREATED_CONTAINER_IDS=()
  TRANSACTION_CONTAINER_CAS='[]'
  TRANSACTION_CONTAINERS_REMOVABLE=0
  assert_registered_transaction_resources
}

cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  set +e
  if (( status != 0 && COMMIT_ATTEMPTED == 1 && GATE_COMPLETE == 0 )); then
    if reconcile_commit_outcome; then
      GATE_COMPLETE=1
      MUTATION_STARTED=0
      status=0
      printf '%s\n' "Lost activation commit acknowledgement was reconciled from the durable broker snapshot." >&2
    fi
  fi
  if [[ "$COMMIT_RECONCILIATION" == ambiguous ]]; then
    status=75
    printf '%s\n' "Activation commit outcome is ambiguous; runtime rollback is forbidden until broker state is reconciled." >&2
  elif (( status != 0 && MUTATION_STARTED == 1 && GATE_COMPLETE == 0 && ROLLBACK_RUNNING == 0 )) && [[ "$ACTION" == activate ]]; then
    ROLLBACK_RUNNING=1
    if ((${#TRANSACTION_CREATED_CONTAINER_IDS[@]} == 0)); then
      status=73
      printf '%s\n' "Activation failed without an authenticated transaction-owned container ID set; runtime cleanup was refused." >&2
    elif stop_transaction_created_and_prove; then
      if (( TRANSACTION_CONTAINERS_REMOVABLE == 1 )); then
        if remove_transaction_created_and_prove; then
          status=72
          printf '%s\n' "Activation create failed; only exact never-started transaction containers were stopped and removed without volumes." >&2
        else
          status=73
          printf '%s\n' "Activation create failed and exact never-started removal could not be proven; preserved state remains pending." >&2
        fi
      else
        status=72
        printf '%s\n' "Activation failed; only containers registered as created by this transaction were stopped and firewall enforcement was retained." >&2
      fi
    else
      status=73
      printf '%s\n' "Activation failed and transaction-owned cleanup could not be proven; unknown containers and firewall state were preserved." >&2
    fi
  elif (( status != 0 && MUTATION_STARTED == 1 )); then
    status=73
    printf '%s\n' "Hosted stop failed and is not proven; firewall enforcement remains active." >&2
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
if (( RECOVER_PENDING == 0 )); then
  assert_project_preservation_boundary || exit 70
  assert_global_docker_authority_boundary || exit 70
fi
assert_daemon_identity || exit 70

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
if [[ -z "$BROKER_FD" || -z "$BROKER_TOKEN" ]]; then
  exec sudo -n "$PRIVILEGED_STATE_BROKER" supervise \
    "$STATE_DIR" "$0" "${ORIGINAL_ARGUMENTS[@]}"
fi
assert_mutex_identity || exit 75
previous_journal=$(state_read_optional journal.json) || exit 70
if [[ -n "$previous_journal" ]] && printf '%s' "$previous_journal" | jq -e '.state == "pending"' >/dev/null; then
  [[ "$RECOVER_PENDING" == 1 ]] || {
    printf '%s\n' "A durable pending activation exists; rerun with --recover-pending for fail-closed reconciliation." >&2
    exit 75
  }
  PENDING_JOURNAL=$previous_journal
elif (( RECOVER_PENDING == 1 )); then
  printf '%s\n' "--recover-pending requires an authenticated pending activation journal." >&2
  exit 75
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
  --arg combinedRenderSha256 "$CURRENT_COMBINED_SHA256" '
    .noHosted == $noHosted
    and (if $noHosted then .hostedLockSha256 == null else .hostedLockSha256 == $lockSha256 end)
    and .combinedRenderSha256 == $combinedRenderSha256
  ' >/dev/null || {
    printf '%s\n' "Trusted release context does not bind the exact hosted/no-hosted lock and renders." >&2
    exit 70
  }
verify_release_context_unchanged || exit 70
verify_release_subjects "$CURRENT_MODEL" 1 || exit 70
if [[ -n "$PENDING_JOURNAL" ]]; then
  TRANSACTION_RUNTIME_MODEL=$TEMP_DIRECTORY/pending-transaction-compose.json
  recover_pending_transaction \
    "$PENDING_JOURNAL" "$CURRENT_RUNTIME_MODEL" "$TRANSACTION_RUNTIME_MODEL" || exit 75
  if (( RESUME_CREATING == 1 )); then
    CURRENT_RUNTIME_MODEL=$TRANSACTION_RUNTIME_MODEL
    node "$SCRIPT_DIR/platform-activation-state.mjs" assert-unmounted \
      "$STATE_DIR" "$CURRENT_RUNTIME_MODEL" || exit 70
  fi
fi
model_paths=("$CURRENT_CORE_MODEL" "$CURRENT_MODEL" "$CURRENT_RUNTIME_MODEL" "$FALLBACK_MODEL" "$FALLBACK_RUNTIME_MODEL")
[[ -z "$PREVIOUS_CORE_MODEL" ]] || model_paths+=("$PREVIOUS_CORE_MODEL")
[[ -z "$PREVIOUS_MODEL" ]] || model_paths+=("$PREVIOUS_MODEL")
[[ -z "$PREVIOUS_RUNTIME_MODEL" ]] || model_paths+=("$PREVIOUS_RUNTIME_MODEL")
node "$SCRIPT_DIR/platform-activation-state.mjs" assert-unmounted "$STATE_DIR" "${model_paths[@]}" || exit 70
assert_mutex_identity || exit 75
assert_candidate_resource_boundary "$CURRENT_RUNTIME_MODEL" || exit 70

if [[ "$ACTION" == stop ]]; then
  assert_project_preservation_boundary || exit 70
  TRANSACTION_ID=$(node "$SCRIPT_DIR/platform-activation-state.mjs" nonce)
  journal_phase intent "record exact empty project state"
  MUTATION_STARTED=1
  commit_active_receipt stopped "$CURRENT_RUNTIME_MODEL" "project inventory proven empty without container mutation"
  GATE_COMPLETE=1
  MUTATION_STARTED=0
  printf 'Proven stopped hosted/extension service set: %s\n' "${CURRENT_ALL_SERVICES[*]}"
  exit 0
fi

if (( NO_HOSTED == 0 )); then
  verify_inputs "$LOCK" "$CURRENT_BUNDLE" "$CURRENT_MODEL" "$CURRENT_MODEL_SHA256" "$CURRENT_CORE_MODEL"
  assert_project_preservation_boundary || exit 70
  firewall preflight "$LOCK"
fi
assert_project_preservation_boundary || exit 70
if (( RESUME_CREATING == 0 )); then
  TRANSACTION_ID=$(node "$SCRIPT_DIR/platform-activation-state.mjs" nonce)
  TRANSACTION_RUNTIME_MODEL=$TEMP_DIRECTORY/current-transaction-compose.json
  bind_transaction_runtime_model "$CURRENT_RUNTIME_MODEL" "$TRANSACTION_RUNTIME_MODEL" || exit 70
  CURRENT_RUNTIME_MODEL=$TRANSACTION_RUNTIME_MODEL
  node "$SCRIPT_DIR/platform-activation-state.mjs" assert-unmounted "$STATE_DIR" "$CURRENT_RUNTIME_MODEL" || exit 70
  assert_project_preservation_boundary || exit 70
  journal_phase intent "core, platform extension and hosted union transition"
else
  [[ "$JOURNAL_PHASE" == creating && "$TRANSACTION_ID" =~ ^[a-f0-9]{64}$ ]] || exit 75
  assert_registered_transaction_resources || exit 75
fi
MUTATION_STARTED=1
assert_mutex_identity

if (( RESUME_CREATING == 0 )); then
  core_arguments=(
    --action validate
    --project-name "$PROJECT_NAME"
    --env-file "$ENV_FILE"
    --release-context "$RELEASE_CONTEXT"
    --confirm ACTIVATE-CORE-STACK
  )
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
  assert_project_preservation_boundary || exit 70
  assert_mutex_identity
  journal_phase quiesced "greenfield project inventory proven empty; unknown and orphan containers are preservation-blocking"
  journal_phase creating "exact current hosted/extension container creation authorized"
else
  assert_project_preservation_boundary || exit 70
  assert_registered_transaction_resources || exit 75
fi
create_services "$CURRENT_RUNTIME_MODEL" "${CURRENT_ALL_SERVICES[@]}"
assert_project_preservation_boundary || exit 70
assert_registered_transaction_resources || exit 75
assert_global_docker_authority_boundary "$CURRENT_RUNTIME_MODEL" || exit 70
assert_mutex_identity
journal_phase created "exact current hosted/extension containers created stopped"
if (( NO_HOSTED == 0 )); then
  assert_project_preservation_boundary || exit 70
  assert_registered_transaction_resources || exit 75
  assert_global_docker_authority_boundary "$CURRENT_RUNTIME_MODEL" || exit 70
  verify_inputs "$LOCK" "$CURRENT_BUNDLE" "$CURRENT_MODEL" "$CURRENT_MODEL_SHA256" "$CURRENT_CORE_MODEL"
  verify_ownership "$LOCK" "$CURRENT_RUNTIME_MODEL"
  assert_registered_transaction_resources || exit 75
  assert_global_docker_authority_boundary "$CURRENT_RUNTIME_MODEL" || exit 70
  firewall apply "$LOCK"
  firewall verify "$LOCK"
  journal_phase firewall-active "current egress inventory enforced before start"
  assert_registered_transaction_resources || exit 75
  assert_global_docker_authority_boundary "$CURRENT_RUNTIME_MODEL" || exit 70
else
  assert_registered_transaction_resources || exit 75
  assert_global_docker_authority_boundary "$CURRENT_RUNTIME_MODEL" || exit 70
  firewall deactivate
  journal_phase firewall-inactive "hosted egress chain removed while the full project was quiesced"
fi
assert_project_preservation_boundary || exit 70
assert_registered_transaction_resources || exit 75
assert_global_docker_authority_boundary "$CURRENT_RUNTIME_MODEL" || exit 70
start_services_ordered "$CURRENT_RUNTIME_MODEL" "$CURRENT_LOCK_SHA256" "${CURRENT_ALL_SERVICES[@]}"
assert_project_preservation_boundary || exit 70
assert_registered_transaction_resources || exit 75
assert_global_docker_authority_boundary "$CURRENT_RUNTIME_MODEL" || exit 70
verify_running_services "$CURRENT_RUNTIME_MODEL" "$CURRENT_LOCK_SHA256" "${CURRENT_ALL_SERVICES[@]}"
verify_exact_workload_inventory
assert_registered_transaction_resources || exit 75
assert_global_docker_authority_boundary "$CURRENT_RUNTIME_MODEL" || exit 70
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
assert_project_preservation_boundary || exit 70
assert_registered_transaction_resources || exit 75
assert_global_docker_authority_boundary "$CURRENT_RUNTIME_MODEL" || exit 70
commit_active_receipt \
  "$([[ "$NO_HOSTED" == 1 ]] && printf no-hosted || printf hosted)" \
  "$CURRENT_RUNTIME_MODEL" "active receipt committed" "${CURRENT_ALL_SERVICES[@]}"
GATE_COMPLETE=1
MUTATION_STARTED=0
printf 'Platform activation transaction completed for project %s: %s\n' "$PROJECT_NAME" "${CURRENT_ALL_SERVICES[*]}"
