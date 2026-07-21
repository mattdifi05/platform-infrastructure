#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LOCK=
PROJECT_NAME=
ALLOW_ABSENT=0

usage() {
  printf '%s\n' "Usage: hosted-workload-network-ownership.sh --lock ABSOLUTE_PATH --project-name NAME [--allow-absent]" >&2
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
    *) usage ;;
  esac
done

[[ "$LOCK" = /* && "$LOCK" != *[!A-Za-z0-9_./-]* && "$LOCK" != *//* && "$LOCK" != */../* && "$LOCK" != */.. ]] || usage
[[ "$PROJECT_NAME" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || usage
[[ -f "$LOCK" ]] || {
  printf 'Hosted workload lock does not exist: %s\n' "$LOCK" >&2
  exit 1
}

activation_bundle=$(sh "$SCRIPT_DIR/hosted-workload-lock.sh" "$LOCK" activation-bundle)
printf '%s' "$activation_bundle" | jq -e --arg projectName "$PROJECT_NAME" '
  def network_record:
    type == "object"
    and ((keys | sort) == ["logicalName", "physicalName", "workloadId"])
    and (.workloadId | type == "string" and test("^[a-z0-9][a-z0-9-]*$"))
    and (.logicalName | type == "string")
    and (.logicalName == ((.workloadId | gsub("-"; "_")) + "_" + (.logicalName | split("_") | last)))
    and (.logicalName | test("_(ingress|postgres|cache|bus|identity|storage|observability|egress)$"))
    and (.physicalName == ($projectName + "_" + .logicalName));
  . as $bundle
  | type == "object"
  and .projectName == $projectName
  and ($bundle.workloadIds | type == "array" and length > 0 and . == (unique | sort))
  and ($bundle.networkRecords | type == "array" and length >= ($bundle.workloadIds | length))
  and ($bundle.networkRecords == ($bundle.networkRecords | unique_by(.workloadId, .logicalName) | sort_by(.workloadId, .logicalName)))
  and all($bundle.networkRecords[]; network_record)
  and ([$bundle.networkRecords[].workloadId] | unique | sort) == $bundle.workloadIds
' >/dev/null || {
  printf '%s\n' "Hosted workload network ownership receipt is invalid." >&2
  exit 1
}

network_records=$(printf '%s' "$activation_bundle" | jq -r '.networkRecords[] | [.workloadId, .logicalName, .physicalName] | @tsv')
while IFS=$'\t' read -r workload_id logical_name physical_name; do
  [[ -n "$physical_name" ]] || continue
  if inspection=$(docker network inspect "$physical_name" 2>/dev/null); then
    printf '%s' "$inspection" | jq -e \
      --arg physicalName "$physical_name" \
      --arg projectName "$PROJECT_NAME" \
      --arg logicalName "$logical_name" '
        type == "array"
        and length == 1
        and .[0].Name == $physicalName
        and .[0].Labels["com.docker.compose.project"] == $projectName
        and .[0].Labels["com.docker.compose.network"] == $logicalName
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
  if ! network_names=$(docker network ls --format '{{.Name}}'); then
    printf '%s\n' "Docker network inventory could not be read." >&2
    exit 1
  fi
  if grep -Fqx -- "$physical_name" <<< "$network_names"; then
    printf 'Hosted workload network exists but cannot be inspected: %s\n' "$physical_name" >&2
    exit 1
  fi
done <<< "$network_records"

printf 'Verified Engine ownership for %s hosted workload network(s).\n' "$(printf '%s\n' "$network_records" | awk 'NF { count += 1 } END { print count + 0 }')"
