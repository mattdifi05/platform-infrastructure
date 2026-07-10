#!/usr/bin/env sh
set -eu

OUT_FILE="${PROJECT_DOCKER_STATS_FILE:-projects-portal/state/docker-stats.json}"
PROM_FILE="${PLATFORM_CONTAINER_METRICS_FILE:-projects-portal/state/node-exporter-textfile/platform-container.prom}"
INTERVAL_SECONDS="${PROJECT_DOCKER_STATS_INTERVAL_SECONDS:-5}"
WATCH_MODE="false"

if [ "${1:-}" = "--watch" ]; then
  WATCH_MODE="true"
elif [ "$#" -gt 0 ]; then
  echo "Usage: write-docker-stats-json.sh [--watch]" >&2
  exit 2
fi

case "$INTERVAL_SECONDS" in
  ''|*[!0-9]*)
    echo "PROJECT_DOCKER_STATS_INTERVAL_SECONDS must be a positive integer" >&2
    exit 2
    ;;
esac
if [ "$INTERVAL_SECONDS" -lt 1 ]; then
  echo "PROJECT_DOCKER_STATS_INTERVAL_SECONDS must be at least 1" >&2
  exit 2
fi

for command_name in docker jq; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "$command_name command not found" >&2
    exit 1
  fi
done

OUT_DIR=$(dirname "$OUT_FILE")
PROM_DIR=$(dirname "$PROM_FILE")
mkdir -p "$OUT_DIR" "$PROM_DIR"

write_snapshot() {
  work_dir=$(mktemp -d "${TMPDIR:-/tmp}/platform-container-metrics.XXXXXX")
  stats_raw="$work_dir/stats.jsonl"
  inspect_raw="$work_dir/inspect.json"
  running_ids_raw="$work_dir/running-ids.txt"
  snapshot_tmp="${OUT_FILE}.tmp.$$"
  prom_tmp="${PROM_FILE}.tmp.$$"
  cleanup_snapshot() {
    rm -rf "$work_dir" "$snapshot_tmp" "$prom_tmp"
  }
  trap cleanup_snapshot EXIT HUP INT TERM

  captured_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  captured_epoch=$(date -u +%s)
  docker ps --no-trunc --format '{{.ID}}' > "$running_ids_raw"
  docker stats --no-stream --no-trunc --format '{{json .}}' > "$stats_raw"

  set --
  while IFS= read -r container_id; do
    [ -n "$container_id" ] || continue
    set -- "$@" "$container_id"
  done < "$running_ids_raw"
  if [ "$#" -gt 0 ]; then
    docker inspect --format '{"Id":{{json .Id}},"Name":{{json .Name}},"Config":{"Labels":{{json .Config.Labels}}},"State":{"Status":{{json .State.Status}}},"HostConfig":{"NanoCpus":{{json .HostConfig.NanoCpus}},"CpuQuota":{{json .HostConfig.CpuQuota}},"CpuPeriod":{{json .HostConfig.CpuPeriod}},"Memory":{{json .HostConfig.Memory}},"MemoryReservation":{{json .HostConfig.MemoryReservation}},"PidsLimit":{{json .HostConfig.PidsLimit}}}}' "$@" \
      | jq -s '.' > "$inspect_raw"
  else
    printf '[]\n' > "$inspect_raw"
  fi

  jq -s \
    --slurpfile inspected "$inspect_raw" \
    --rawfile runningIds "$running_ids_raw" \
    --arg capturedAt "$captured_at" \
    --argjson capturedAtEpoch "$captured_epoch" '
      def percent_number:
        tostring | sub("%$"; "") | tonumber?;
      def size_bytes:
        tostring
        | split("/")[0]
        | gsub("^[[:space:]]+|[[:space:]]+$"; "")
        | capture("^(?<amount>[0-9]+(?:[.][0-9]+)?)(?<unit>[KMGTPE]?i?B)$"; "i")? as $part
        | if $part == null then null else
            ($part.amount | tonumber) *
            ({B: 1, KB: 1000, MB: 1000000, GB: 1000000000, TB: 1000000000000,
              KIB: 1024, MIB: 1048576, GIB: 1073741824, TIB: 1099511627776}[$part.unit | ascii_upcase] // 1)
          end;
      def meta_for($container_id):
        (($inspected[0] // []) | map(select(.Id == $container_id)) | first) // {};
      def cpu_limit($meta):
        if (($meta.HostConfig.NanoCpus // 0) | tonumber) > 0 then
          (($meta.HostConfig.NanoCpus | tonumber) / 1000000000)
        elif (($meta.HostConfig.CpuQuota // 0) | tonumber) > 0 and (($meta.HostConfig.CpuPeriod // 0) | tonumber) > 0 then
          (($meta.HostConfig.CpuQuota | tonumber) / ($meta.HostConfig.CpuPeriod | tonumber))
        else null end;
      ($runningIds | split("\n") | map(select(length > 0))) as $running
      | map(. as $stat
          | meta_for($stat.Container // "") as $meta
          | {
              id: ($stat.Container // ""),
              name: ($stat.Name // ($meta.Name // "") | sub("^/"; "")),
              service: ($meta.Config.Labels["com.docker.compose.service"] // ""),
              composeProject: ($meta.Config.Labels["com.docker.compose.project"] // ""),
              status: ($meta.State.Status // "unknown"),
              cpuPercent: (($stat.CPUPerc // "") | percent_number),
              cpuCores: (((($stat.CPUPerc // "") | percent_number) // 0) / 100),
              memoryUsageBytes: (($stat.MemUsage // "") | size_bytes),
              cpuLimitCores: cpu_limit($meta),
              memoryLimitBytes: (if (($meta.HostConfig.Memory // 0) | tonumber) > 0 then ($meta.HostConfig.Memory | tonumber) else null end),
              memoryReservationBytes: (if (($meta.HostConfig.MemoryReservation // 0) | tonumber) > 0 then ($meta.HostConfig.MemoryReservation | tonumber) else null end),
              pidsLimit: (if (($meta.HostConfig.PidsLimit // 0) | tonumber) > 0 then ($meta.HostConfig.PidsLimit | tonumber) else null end)
            }) as $containers
      | ($containers | map(.id)) as $observed
      | ($running - $observed) as $missing
      | {
          schemaVersion: 2,
          capturedAt: $capturedAt,
          capturedAtEpoch: $capturedAtEpoch,
          source: "docker stats --no-stream + docker inspect",
          collector: {
            healthy: (($running | length) > 0 and ($missing | length) == 0 and ($containers | length) == ($running | length)),
            expectedRunning: ($running | length),
            observed: ($containers | length),
            missingRunningContainerIds: $missing
          },
          containers: $containers
        }
    ' "$stats_raw" > "$snapshot_tmp"

  jq -r '
    def label_escape: tostring | gsub("\\\\"; "\\\\\\\\") | gsub("\""; "\\\\\"") | gsub("\n"; "\\\\n");
    def labels($item):
      "container=\"\($item.name | label_escape)\",compose_project=\"\($item.composeProject | label_escape)\",compose_service=\"\($item.service | label_escape)\"";
    . as $root
    | [
      "# HELP platform_container_metrics_collector_healthy Whether the host collector produced a complete snapshot.",
      "# TYPE platform_container_metrics_collector_healthy gauge",
      "platform_container_metrics_collector_healthy \(if .collector.healthy then 1 else 0 end)",
      "# HELP platform_container_metrics_collector_last_attempt_timestamp_seconds Unix timestamp of the latest collection attempt.",
      "# TYPE platform_container_metrics_collector_last_attempt_timestamp_seconds gauge",
      "platform_container_metrics_collector_last_attempt_timestamp_seconds \(.capturedAtEpoch)",
      "# HELP platform_container_metrics_collector_expected_running Number of running containers reported by Docker.",
      "# TYPE platform_container_metrics_collector_expected_running gauge",
      "platform_container_metrics_collector_expected_running \(.collector.expectedRunning)",
      "# HELP platform_container_metrics_collector_observed Number of running containers with a stats sample.",
      "# TYPE platform_container_metrics_collector_observed gauge",
      "platform_container_metrics_collector_observed \(.collector.observed)",
      "# HELP platform_container_cpu_percent Instantaneous container CPU usage in Docker percent units.",
      "# TYPE platform_container_cpu_percent gauge",
      (.containers[] | select(.cpuPercent != null) | "platform_container_cpu_percent{\(labels(.))} \(.cpuPercent)"),
      "# HELP platform_container_cpu_cores Instantaneous container CPU usage expressed as cores.",
      "# TYPE platform_container_cpu_cores gauge",
      (.containers[] | select(.cpuCores != null) | "platform_container_cpu_cores{\(labels(.))} \(.cpuCores)"),
      "# HELP platform_container_memory_usage_bytes Container memory usage reported by Docker.",
      "# TYPE platform_container_memory_usage_bytes gauge",
      (.containers[] | select(.memoryUsageBytes != null) | "platform_container_memory_usage_bytes{\(labels(.))} \(.memoryUsageBytes | floor)"),
      "# HELP platform_container_last_seen_timestamp_seconds Unix timestamp of the latest container sample.",
      "# TYPE platform_container_last_seen_timestamp_seconds gauge",
      (.containers[] | "platform_container_last_seen_timestamp_seconds{\(labels(.))} \($root.capturedAtEpoch)"),
      "# HELP platform_container_cpu_limit_cores Effective cgroup CPU limit in cores; absent when unlimited.",
      "# TYPE platform_container_cpu_limit_cores gauge",
      (.containers[] | select(.cpuLimitCores != null) | "platform_container_cpu_limit_cores{\(labels(.))} \(.cpuLimitCores)"),
      "# HELP platform_container_cpu_limit_configured Whether an effective cgroup CPU limit is configured.",
      "# TYPE platform_container_cpu_limit_configured gauge",
      (.containers[] | "platform_container_cpu_limit_configured{\(labels(.))} \(if .cpuLimitCores == null then 0 else 1 end)"),
      "# HELP platform_container_memory_limit_bytes Effective cgroup memory limit; absent when unlimited.",
      "# TYPE platform_container_memory_limit_bytes gauge",
      (.containers[] | select(.memoryLimitBytes != null) | "platform_container_memory_limit_bytes{\(labels(.))} \(.memoryLimitBytes | floor)"),
      "# HELP platform_container_memory_limit_configured Whether an effective cgroup memory limit is configured.",
      "# TYPE platform_container_memory_limit_configured gauge",
      (.containers[] | "platform_container_memory_limit_configured{\(labels(.))} \(if .memoryLimitBytes == null then 0 else 1 end)"),
      "# HELP platform_container_memory_reservation_bytes Effective container memory reservation; absent when unset.",
      "# TYPE platform_container_memory_reservation_bytes gauge",
      (.containers[] | select(.memoryReservationBytes != null) | "platform_container_memory_reservation_bytes{\(labels(.))} \(.memoryReservationBytes | floor)"),
      "# HELP platform_container_pids_limit Effective container PID limit; absent when unlimited.",
      "# TYPE platform_container_pids_limit gauge",
      (.containers[] | select(.pidsLimit != null) | "platform_container_pids_limit{\(labels(.))} \(.pidsLimit | floor)")
    ] | .[]
  ' "$snapshot_tmp" > "$prom_tmp"

  chmod 0644 "$snapshot_tmp" "$prom_tmp"
  mv -f "$snapshot_tmp" "$OUT_FILE"
  mv -f "$prom_tmp" "$PROM_FILE"

  healthy=$(jq -r '.collector.healthy' "$OUT_FILE")
  trap - EXIT HUP INT TERM
  rm -rf "$work_dir"
  if [ "$healthy" != "true" ]; then
    echo "container metrics snapshot is incomplete" >&2
    return 1
  fi
}

if [ "$WATCH_MODE" = "true" ]; then
  while :; do
    write_snapshot
    sleep "$INTERVAL_SECONDS"
  done
fi

write_snapshot
