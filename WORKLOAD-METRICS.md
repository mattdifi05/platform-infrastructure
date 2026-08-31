# Workload Metrics and Capacity Evidence

## Scope

The production single-node profile collects truthful per-container CPU, memory
and effective cgroup limits without mounting the Docker socket in an additional
container. The host service has Docker group read access and can write only the
non-secret metrics paths under `projects-portal/state`.

This collector complements node-exporter host metrics. The Dell V1.1 render
does not start or scrape cAdvisor; workload evidence comes only from the
collector's `platform_container_*` series.

## Data flow

1. The system service, or the Dell `--user-cron` runner, executes the installed
   copy of `scripts/write-docker-stats-json.sh`. The Dell runner samples at
   seconds 0, 20 and 40 of each minute.
2. The collector reconciles `docker ps`, `docker stats --no-stream` and
   `docker inspect`. A sample is unhealthy when any running container is not
   represented by stats.
3. An atomic versioned JSON snapshot is written to
   `projects-portal/state/docker-stats.json` for Control Center.
4. Atomic Prometheus textfile metrics are written to
   `projects-portal/state/node-exporter-textfile/platform-container.prom`.
5. node-exporter reads that directory through a read-only bind mount;
   Prometheus, alert rules and Grafana consume the `platform_container_*`
   series.

No environment values, container environment, secret contents or mounted file
contents are collected.

## Truthfulness rules

- A real CPU sample of `0.000%` is a measured zero, not missing data.
- JSON snapshots older than the configured freshness ceiling are unavailable
  to Control Center; Dell V1.1 sets that ceiling to 30 seconds.
- Prometheus workload rows are accepted only while the collector health series
  is `1` and its latest attempt is no more than the same freshness ceiling old.
- Missing Docker stats for any running container makes the collector unhealthy.
- `cpuLimitCores`, `memoryLimitBytes`, `memoryReservationBytes` and `pidsLimit`
  are read from effective Docker `HostConfig`. `null` means no effective limit;
  the portal must not substitute planned quota metadata.
- The T10 collector observes limits. T13 owns enforcement and rollout of limits.

## Installation

Preview only:

```bash
sudo sh ./scripts/install-container-metrics-collector.sh \
  --plan \
  --deploy-user platform_infrastructure \
  --repo-root /home/platform_infrastructure/platform-infrastructure
```

During an approved maintenance window, after the target branch and Compose
configuration have been deployed:

```bash
sudo sh ./scripts/install-container-metrics-collector.sh \
  --apply \
  --deploy-user platform_infrastructure \
  --repo-root /home/platform_infrastructure/platform-infrastructure

sudo sh ./scripts/install-container-metrics-collector.sh \
  --verify \
  --repo-root /home/platform_infrastructure/platform-infrastructure
```

Then recreate only node-exporter, Prometheus and Control Center with the
canonical production overlays. Do not use `docker compose down` and never use
`docker compose down -v`.

## Verification

```bash
sh ./scripts/container-metrics-sandbox-test.sh
sudo systemctl is-active platform-container-metrics.service
jq '{capturedAt, collector, containers: [.containers[] | {name, cpuPercent, memoryUsageBytes, cpuLimitCores, memoryLimitBytes, pidsLimit}]}' \
  projects-portal/state/docker-stats.json
grep '^platform_container_metrics_collector_healthy 1$' \
  projects-portal/state/node-exporter-textfile/platform-container.prom
sh ./scripts/vps-host-readiness.sh --enforce --ssh-port 22
```

The JSON inspection above contains no secrets, but evidence should still be
stored outside Git under a private `0700` remediation directory.

## Rollback

Rollback does not remove data or volumes:

```bash
sudo systemctl disable --now platform-container-metrics.service
```

Restore the previous Compose revision and recreate only node-exporter,
Prometheus and Control Center. Keep the last JSON/textfile outputs as incident
evidence until the rollback is validated; stale-data guards prevent them from
being presented as current workload measurements.
