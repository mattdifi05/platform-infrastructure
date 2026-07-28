#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LOCK=
PROJECT_NAME=
ALLOW_ABSENT=0
EXPECTED_DAEMON_ID=
EXPECTED_MODEL=
CANONICAL_DOCKER_HOST=unix:///var/run/docker.sock

usage() {
  printf '%s\n' "Usage: hosted-workload-network-ownership.sh --lock ABSOLUTE_PATH --project-name NAME --expected-daemon-id ID [--expected-model ABSOLUTE_JSON] [--allow-absent]" >&2
  exit 64
}

while (($#)); do
  case "$1" in
    --lock)
      (($# >= 2)) || usage
      LOCK=$2
      shift 2
      ;;
    --project-name)
      (($# >= 2)) || usage
      PROJECT_NAME=$2
      shift 2
      ;;
    --allow-absent)
      ALLOW_ABSENT=1
      shift
      ;;
    --expected-daemon-id)
      (($# >= 2)) || usage
      EXPECTED_DAEMON_ID=$2
      shift 2
      ;;
    --expected-model)
      (($# >= 2)) || usage
      EXPECTED_MODEL=$2
      shift 2
      ;;
    *) usage ;;
  esac
done

[[ "$LOCK" = /* && "$LOCK" != *[!A-Za-z0-9_./-]* && "$LOCK" != *//* && "$LOCK" != */../* && "$LOCK" != */.. ]] || usage
[[ "$PROJECT_NAME" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || usage
[[ "$EXPECTED_DAEMON_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$ ]] || usage
case "${DOCKER_HOST:-}" in ""|"$CANONICAL_DOCKER_HOST") ;; *) usage ;; esac
case "${DOCKER_CONTEXT:-}" in ""|default) ;; *) usage ;; esac
unset DOCKER_CONTEXT
export DOCKER_HOST=$CANONICAL_DOCKER_HOST
[[ -f "$LOCK" ]] || {
  printf 'Hosted workload lock does not exist: %s\n' "$LOCK" >&2
  exit 1
}
if [[ -n "$EXPECTED_MODEL" ]]; then
  [[ "$EXPECTED_MODEL" == /* && -f "$EXPECTED_MODEL" && ! -L "$EXPECTED_MODEL" ]] || usage
  jq -e '.services | type == "object"' "$EXPECTED_MODEL" >/dev/null || usage
fi

assert_daemon_identity() {
  local current
  current=$(docker --host "$CANONICAL_DOCKER_HOST" info --format '{{.ID}}') || return 1
  [[ "$current" == "$EXPECTED_DAEMON_ID" ]] || {
    printf 'Docker daemon identity changed: expected=%s actual=%s\n' "$EXPECTED_DAEMON_ID" "${current:-unavailable}" >&2
    return 1
  }
}

assert_daemon_identity

activation_bundle=$(
  HOSTED_WORKLOAD_ALLOW_RESOLVED=0 \
    sh "$SCRIPT_DIR/hosted-workload-lock.sh" "$LOCK" activation-bundle
)
printf '%s' "$activation_bundle" | jq -e --arg projectName "$PROJECT_NAME" '
  def network_record:
    type == "object"
    and ((keys | sort) == ["logicalName", "physicalName", "workloadId"])
    and (.workloadId | type == "string" and test("^[a-z][a-z0-9-]{1,60}$"))
    and (.logicalName | type == "string")
    and (.logicalName == ((.workloadId | gsub("-"; "_")) + "_" + (.logicalName | split("_") | last)))
    and (.logicalName | test("_(ingress|postgres|cache|bus|identity|storage|observability|egress)$"))
    and (.physicalName == ($projectName + "_" + .logicalName));
  . as $bundle
  | type == "object"
  and .projectName == $projectName
  and ($bundle.workloadIds | type == "array" and length > 0 and . == (unique | sort))
  and ($bundle.protectedNetworkNames | type == "array" and . == (unique | sort) and all(.[]; type == "string" and length > 0))
  and ($bundle.networkRecords | type == "array" and length >= ($bundle.workloadIds | length))
  and ($bundle.networkRecords == ($bundle.networkRecords | unique_by(.workloadId, .logicalName) | sort_by(.workloadId, .logicalName)))
  and all($bundle.networkRecords[]; network_record)
  and all($bundle.networkRecords[]; . as $record | ($bundle.protectedNetworkNames | index($record.logicalName)) == null)
  and ([$bundle.networkRecords[].workloadId] | unique | sort) == $bundle.workloadIds
' >/dev/null || {
  printf '%s\n' "Hosted workload network ownership receipt is invalid." >&2
  exit 1
}

network_records=$(printf '%s' "$activation_bundle" | jq -r '.networkRecords[] | [.workloadId, .logicalName, .physicalName] | @tsv')
project_inspections='[]'
if [[ -n "$EXPECTED_MODEL" ]]; then
  project_ids=$(docker --host "$CANONICAL_DOCKER_HOST" ps -aq --filter "label=com.docker.compose.project=$PROJECT_NAME") || exit 1
  if [[ -n "$project_ids" ]]; then
    # Word splitting is intentional for Engine IDs after Docker produces one ID per line.
    project_inspections=$(docker --host "$CANONICAL_DOCKER_HOST" inspect $project_ids) || exit 1
  fi
fi
while IFS=$'\t' read -r workload_id logical_name physical_name; do
  [[ -n "$physical_name" ]] || continue
  assert_daemon_identity
  if inspection=$(docker --host "$CANONICAL_DOCKER_HOST" network inspect "$physical_name" 2>/dev/null); then
    expected_internal=true
    [[ "$logical_name" != *_egress ]] || expected_internal=false
    expected_ids='[]'
    if [[ -n "$EXPECTED_MODEL" ]]; then
      expected_services=$(jq -c --arg logicalName "$logical_name" '
        [.services | to_entries[]
          | select(((.value.networks // {}) | keys | index($logicalName)) != null)
          | .key] | sort
      ' "$EXPECTED_MODEL") || exit 1
      expected_ids=$(printf '%s' "$project_inspections" | jq -c --arg projectName "$PROJECT_NAME" --argjson expectedServices "$expected_services" '
        [
          .[]
          | select(.Config.Labels["com.docker.compose.project"] == $projectName)
          | select((.Config.Labels["com.docker.compose.service"] // "") as $service
              | ($expectedServices | index($service)) != null)
          | .Id
        ] | sort
      ') || exit 1
      printf '%s' "$project_inspections" | jq -e --arg projectName "$PROJECT_NAME" --argjson expectedServices "$expected_services" '
        [
          .[]
          | select(.Config.Labels["com.docker.compose.project"] == $projectName)
          | select((.Config.Labels["com.docker.compose.service"] // "") as $service
              | ($expectedServices | index($service)) != null)
          | .Config.Labels["com.docker.compose.service"]
        ] | sort == $expectedServices
      ' >/dev/null || {
        printf 'Hosted workload network expected container inventory is incomplete: %s\n' "$physical_name" >&2
        exit 1
      }
    fi
    printf '%s' "$inspection" | jq -e \
      --arg physicalName "$physical_name" \
      --arg projectName "$PROJECT_NAME" \
      --arg logicalName "$logical_name" \
      --argjson expectedInternal "$expected_internal" \
      --argjson expectedIds "$expected_ids" \
      --argjson projectContainers "$project_inspections" '
        type == "array"
        and length == 1
        and (.[0] as $network
          | $network.Name == $physicalName
          and $network.Driver == "bridge"
          and $network.Scope == "local"
          and $network.Internal == $expectedInternal
          and $network.Attachable == false
          and $network.Ingress == false
          and $network.EnableIPv6 == false
          and (($network.Options == null) or ($network.Options == {}))
          and ($network.IPAM | type == "object")
          and $network.IPAM.Driver == "default"
          and (($network.IPAM.Options == null) or ($network.IPAM.Options == {}))
          and ($network.IPAM.Config | type == "array" and length == 1)
          and (($network.IPAM.Config[0] | keys | sort) == ["Gateway", "Subnet"])
          and ($network.IPAM.Config[0].Subnet | type == "string" and test("^([0-9]{1,3}\\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$"))
          and ($network.IPAM.Config[0].Gateway | type == "string" and test("^([0-9]{1,3}\\.){3}[0-9]{1,3}$"))
          and $network.Labels["com.docker.compose.project"] == $projectName
          and $network.Labels["com.docker.compose.network"] == $logicalName
          and ($network.Labels["com.docker.compose.version"] | type == "string" and length > 0)
          and (($network.Labels | keys | sort) == [
            "com.docker.compose.network",
            "com.docker.compose.project",
            "com.docker.compose.version"
          ])
          and (($network.Containers | keys | sort) == $expectedIds)
          and all($network.Containers | to_entries[];
            (.value | keys | sort) == ["EndpointID", "IPv4Address", "IPv6Address", "MacAddress", "Name"]
            and (.value.EndpointID | type == "string" and test("^[a-f0-9]{64}$"))
            and (.value.MacAddress | type == "string" and test("^([a-f0-9]{2}:){5}[a-f0-9]{2}$"))
            and (.value.IPv4Address | type == "string" and test("^([0-9]{1,3}\\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$"))
            and .value.IPv6Address == ""
            and (.key as $containerId
              | ($projectContainers[] | select(.Id == $containerId)) as $container
              | .value.Name == ($container.Name | ltrimstr("/"))
              and .value.EndpointID == $container.NetworkSettings.Networks[$physicalName].EndpointID
              and .value.MacAddress == $container.NetworkSettings.Networks[$physicalName].MacAddress
              and .value.IPv4Address == $container.NetworkSettings.Networks[$physicalName].IPAddress + "/" + ($container.NetworkSettings.Networks[$physicalName].IPPrefixLen | tostring)
              and $container.NetworkSettings.Networks[$physicalName].NetworkID == $network.Id)))
      ' >/dev/null || {
        printf 'Hosted workload network has invalid Engine ownership: %s\n' "$physical_name" >&2
        exit 1
      }
    continue
  fi
  if [[ "$ALLOW_ABSENT" != 1 ]]; then
    printf 'Hosted workload network is missing or cannot be inspected: %s\n' "$physical_name" >&2
    exit 1
  fi
  assert_daemon_identity
  if ! network_names=$(docker --host "$CANONICAL_DOCKER_HOST" network ls --format '{{.Name}}'); then
    printf '%s\n' "Docker network inventory could not be read." >&2
    exit 1
  fi
  if grep -Fqx -- "$physical_name" <<< "$network_names"; then
    printf 'Hosted workload network exists but cannot be inspected: %s\n' "$physical_name" >&2
    exit 1
  fi
done <<< "$network_records"

assert_daemon_identity
printf 'Verified Engine ownership for %s hosted workload network(s).\n' "$(printf '%s\n' "$network_records" | awk 'NF { count += 1 } END { print count + 0 }')"
