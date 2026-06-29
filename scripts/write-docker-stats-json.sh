#!/usr/bin/env sh
set -eu

OUT_FILE="${PROJECT_DOCKER_STATS_FILE:-projects-portal/state/docker-stats.json}"
OUT_DIR="$(dirname "$OUT_FILE")"
TMP_FILE="${OUT_FILE}.tmp"
INTERVAL_SECONDS="${PROJECT_DOCKER_STATS_INTERVAL_SECONDS:-1}"
WATCH_MODE="false"

if [ "${1:-}" = "--watch" ]; then
  WATCH_MODE="true"
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker command not found" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq command not found" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

write_snapshot() {
  captured_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  docker stats --no-stream --format '{{json .}}' \
    | jq -s --arg capturedAt "$captured_at" '{
        capturedAt: $capturedAt,
        source: "docker stats --no-stream",
        containers: map({
          name: (.Name // .Container // ""),
          cpuPercent: (.CPUPerc // ""),
          memoryUsage: (.MemUsage // "")
        })
      }' > "$TMP_FILE"

  mv "$TMP_FILE" "$OUT_FILE"
}

if [ "$WATCH_MODE" = "true" ]; then
  while :; do
    write_snapshot
    sleep "$INTERVAL_SECONDS"
  done
fi

write_snapshot
