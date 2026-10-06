#!/usr/bin/env bash
# Source before a first-install retry or core completion touches Docker state.
check_empty_vps_host_ownership() {
  local cid project service volume owner marker
  docker info >/dev/null || return 1
  for cid in $(docker ps -aq); do
    project=$(docker inspect --format '{{with index .Config.Labels "com.docker.compose.project"}}{{.}}{{end}}' "$cid") || return 1
    service=$(docker inspect --format '{{with index .Config.Labels "com.docker.compose.service"}}{{.}}{{end}}' "$cid") || return 1
    case "$project:$service" in
      platform_infra_vps:traefik|platform_infra_vps:waf|platform_infra_vps:waf-loopback-proxy|\
      platform_infra_vps:broker-auth-bootstrap|platform_infra_vps:postgres|platform_infra_vps:redis|\
      platform_infra_vps:control-center|platform_infra_vps:mariadb|platform_infra_vps:nats|\
      platform_infra_vps:nats-volume-init|platform_infra_vps:keycloak|platform_infra_vps:project-router|\
      platform_infra_vps:rustfs-volume-init|platform_infra_vps:rustfs-backend|platform_infra_vps:rustfs-gateway|\
      platform_infra_vps:platform-alert-dispatcher|platform_infra_vps:alertmanager|platform_infra_vps:prometheus|\
      platform_infra_vps:node-exporter|\
      platform_infra_vps:grafana|platform_infra_vps:loki|platform_infra_vps:promtail|\
      platform_server_ai:server-ai-controller|platform_server_ai:searxng|platform_server_ai:server-ai-observer) ;;
      *) echo "Unexpected Docker container $cid ($project:$service); refusing empty-VPS retry." >&2; return 1 ;;
    esac
  done
  for volume in $(docker volume ls -q); do
    owner=$(docker volume inspect --format '{{with index .Labels "com.docker.compose.project"}}{{.}}{{end}}' "$volume") || return 1
    marker=$(docker volume inspect --format '{{with index .Labels "com.platform.empty-vps-first-install"}}{{.}}{{end}}' "$volume") || return 1
    case "$volume:$owner:$marker" in
      enterprise_mariadb_data::true|\
      enterprise_alertmanager_data:platform_infra_vps:|enterprise_grafana_data:platform_infra_vps:|\
      enterprise_keycloak_data:platform_infra_vps:|enterprise_loki_data:platform_infra_vps:|\
      enterprise_nats_auth_config:platform_infra_vps:|enterprise_nats_data:platform_infra_vps:|\
      enterprise_postgres_data:platform_infra_vps:|enterprise_prometheus_data:platform_infra_vps:|\
      enterprise_redis_auth_config:platform_infra_vps:|enterprise_redis_data:platform_infra_vps:|\
      platform_rustfs_data:platform_infra_vps:|platform_rustfs_logs:platform_infra_vps:) ;;
      *:platform_server_ai:) ;;
      *) echo "Unexpected Docker volume $volume (owner $owner); refusing empty-VPS retry." >&2; return 1 ;;
    esac
  done
}
