#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/platform-container-metrics-test.XXXXXX")
cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$WORK_DIR/bin" "$WORK_DIR/state" "$WORK_DIR/textfile"

cat > "$WORK_DIR/bin/docker" <<'EOF'
#!/usr/bin/env sh
set -eu
id_one=1111111111111111111111111111111111111111111111111111111111111111
id_two=2222222222222222222222222222222222222222222222222222222222222222
case "${1:-}" in
  ps)
    printf '%s\n%s\n' "$id_one" "$id_two"
    ;;
  stats)
    printf '{"Container":"%s","Name":"php-zero","CPUPerc":"0.00%%","MemUsage":"24MiB / 512MiB"}\n' "$id_one"
    if [ "${FAKE_DOCKER_MISSING:-false}" != true ]; then
      printf '{"Container":"%s","Name":"node-limited","CPUPerc":"3.50%%","MemUsage":"96MiB / 512MiB"}\n' "$id_two"
    fi
    ;;
  inspect)
    cat <<JSON
{"Id":"$id_one","Name":"/php-zero","Config":{"Labels":{"com.docker.compose.project":"platform","com.docker.compose.service":"php-zero"}},"State":{"Status":"running"},"HostConfig":{"NanoCpus":0,"CpuQuota":0,"CpuPeriod":0,"Memory":0,"MemoryReservation":0,"PidsLimit":512}}
{"Id":"$id_two","Name":"/node-limited","Config":{"Labels":{"com.docker.compose.project":"platform","com.docker.compose.service":"node-limited"}},"State":{"Status":"running"},"HostConfig":{"NanoCpus":2000000000,"CpuQuota":0,"CpuPeriod":0,"Memory":536870912,"MemoryReservation":268435456,"PidsLimit":256}}
JSON
    ;;
  *)
    echo "unsupported fake docker command: ${1:-}" >&2
    exit 2
    ;;
esac
EOF
chmod 0755 "$WORK_DIR/bin/docker"

PATH="$WORK_DIR/bin:$PATH" \
PROJECT_DOCKER_STATS_FILE="$WORK_DIR/state/docker-stats.json" \
PLATFORM_CONTAINER_METRICS_FILE="$WORK_DIR/textfile/platform-container.prom" \
  sh "$ROOT_DIR/scripts/write-docker-stats-json.sh"

jq -e '
  .schemaVersion == 2
  and .collector.healthy == true
  and .collector.expectedRunning == 2
  and .collector.observed == 2
  and ([.containers[] | select(.name == "php-zero" and .cpuPercent == 0 and .cpuCores == 0 and .cpuLimitCores == null and .memoryLimitBytes == null)] | length) == 1
  and ([.containers[] | select(.name == "node-limited" and .cpuLimitCores == 2 and .memoryLimitBytes == 536870912 and .memoryReservationBytes == 268435456 and .pidsLimit == 256)] | length) == 1
' "$WORK_DIR/state/docker-stats.json" >/dev/null

assert_metric() {
  expected_line="$1"
  if ! grep -Fqx "$expected_line" "$WORK_DIR/textfile/platform-container.prom"; then
    echo "Missing exact metric: $expected_line" >&2
    sed -n '1,160p' "$WORK_DIR/textfile/platform-container.prom" >&2
    exit 1
  fi
}

assert_metric 'platform_container_metrics_collector_healthy 1'
assert_metric 'platform_container_cpu_percent{container="php-zero",compose_project="platform",compose_service="php-zero"} 0.00'
assert_metric 'platform_container_cpu_limit_configured{container="php-zero",compose_project="platform",compose_service="php-zero"} 0'
assert_metric 'platform_container_cpu_limit_cores{container="node-limited",compose_project="platform",compose_service="node-limited"} 2'
assert_metric 'platform_container_memory_limit_bytes{container="node-limited",compose_project="platform",compose_service="node-limited"} 536870912'

if PATH="$WORK_DIR/bin:$PATH" \
  FAKE_DOCKER_MISSING=true \
  PROJECT_DOCKER_STATS_FILE="$WORK_DIR/state/incomplete.json" \
  PLATFORM_CONTAINER_METRICS_FILE="$WORK_DIR/textfile/incomplete.prom" \
    sh "$ROOT_DIR/scripts/write-docker-stats-json.sh" >/dev/null 2>&1; then
  echo "Incomplete Docker stats unexpectedly passed" >&2
  exit 1
fi

jq -e '
  .collector.healthy == false
  and .collector.expectedRunning == 2
  and .collector.observed == 1
  and (.collector.missingRunningContainerIds | length) == 1
' "$WORK_DIR/state/incomplete.json" >/dev/null
grep -Fqx 'platform_container_metrics_collector_healthy 0' "$WORK_DIR/textfile/incomplete.prom"

echo "Container metrics sandbox passed: exact zero, limits, complete inventory and fail-closed coverage verified."
