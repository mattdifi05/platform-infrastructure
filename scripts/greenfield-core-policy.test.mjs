import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { evaluateGreenfieldCoreAuthority } from "./greenfield-core-policy.mjs";
import {
  GREENFIELD_ALL_SERVICES,
  GREENFIELD_CORE_SERVICES,
  GREENFIELD_PROJECT_NAME,
} from "./greenfield-namespace.mjs";

const ROOT_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const POLICY_PATH = path.join(ROOT_DIR, "scripts", "greenfield-core-policy.mjs");
const WRAPPER_PATH = path.join(ROOT_DIR, "scripts", "compose-greenfield.sh");
const LOCK_PATH = path.join(ROOT_DIR, "config", "no-hosted-workloads.greenfield.lock.json");
const LOCK = JSON.parse(fs.readFileSync(LOCK_PATH, "utf8"));
const SECRETS_ROOT = "/srv/platform/state/secrets";
const STATE_DIR = "/srv/platform/state";
const TRUST_DIR = "/srv/platform/trust";
const ACTIVATION_INBOX = "/srv/platform/provider-activation/inbox";

function digestOf(seed) {
  return crypto.createHash("sha256").update(seed).digest("hex");
}

function image(name) {
  return `registry.internal/platform/${name}@sha256:${digestOf(`image:${name}`)}`;
}

function volumeMount(source, target, readOnly = false) {
  return { type: "volume", source, target, read_only: readOnly };
}

function bindMount(source, target, readOnly = true) {
  return { type: "bind", source, target, read_only: readOnly };
}

function secretGrant(logicalName) {
  return { source: logicalName, target: logicalName };
}

function capabilitySecretGrant(logicalName) {
  return { source: logicalName, target: logicalName, uid: "0", gid: "0", mode: 256 };
}

function coreResources(cpus, memory, reservation, pids) {
  return {
    cpu_shares: 768,
    ulimits: { nofile: { soft: 16384, hard: 16384 } },
    blkio_config: { weight: 600 },
    cpus,
    mem_limit: memory,
    mem_reservation: reservation,
    pids_limit: pids,
  };
}

function controlResources(cpus, memory, reservation, pids) {
  return {
    cpu_shares: 1024,
    ulimits: { nofile: { soft: 16384, hard: 16384 } },
    blkio_config: { weight: 700 },
    cpus,
    mem_limit: memory,
    mem_reservation: reservation,
    pids_limit: pids,
  };
}

function observabilityResources(cpus, memory, reservation, pids) {
  return {
    cpu_shares: 512,
    ulimits: { nofile: { soft: 8192, hard: 8192 } },
    blkio_config: { weight: 400 },
    cpus,
    mem_limit: memory,
    mem_reservation: reservation,
    pids_limit: pids,
  };
}

// Minimal-but-complete projection of the full LOCAL_PRIVATE + backup overlay
// chain rendered for platform_infra_greenfield. Service shapes mirror what
// `docker compose config --format json` emits (normalized maps, long-form
// mounts and grants).
function buildAcceptRender() {
  const services = {
    traefik: {
      image: image("traefik"),
      container_name: "gf-traefik",
      init: true,
      logging: { driver: "json-file", options: { "max-size": "10m", "max-file": "5" } },
      security_opt: ["no-new-privileges:true"],
      restart: "always",
      ...controlResources("0.50", "256m", "64m", 192),
      command: ["--configFile=/etc/traefik/traefik.yml"],
      ports: [],
      configs: [{ source: "enterprise_traefik_routes", target: "/etc/traefik/dynamic/routes.yml" }],
      volumes: [
        bindMount("./traefik/traefik.yml", "/etc/traefik/traefik.yml"),
        bindMount("./traefik/dynamic/middlewares.yml", "/etc/traefik/dynamic/middlewares.yml"),
        bindMount("./traefik/dynamic/tls-local.yml", "/etc/traefik/dynamic/tls-local.yml"),
        bindMount("./traefik/certs", "/etc/traefik/certs"),
      ],
      networks: {
        platform_edge: { ipv4_address: "172.30.250.3" },
        platform_routing: null,
        platform_observability: null,
        platform_egress: null,
      },
      healthcheck: { test: ["CMD", "traefik", "healthcheck", "--ping"], interval: "15s", timeout: "5s", retries: 5 },
    },
    waf: {
      image: image("waf"),
      container_name: "gf-waf",
      init: true,
      security_opt: ["no-new-privileges:true"],
      restart: "always",
      group_add: ["1000"],
      ...controlResources("1.00", "384m", "96m", 384),
      ports: ["0.0.0.0:18080:8080", "0.0.0.0:18443:8443"],
      depends_on: { traefik: { condition: "service_healthy" } },
      volumes: [
        bindMount("./waf/REQUEST-900-VPS-RULES-BEFORE-CRS.conf", "/etc/modsecurity.d/owasp-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"),
        bindMount("./waf/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf", "/etc/modsecurity.d/owasp-crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf"),
        bindMount(`${STATE_DIR}/certs/local-cert.pem`, "/etc/nginx/conf/server.crt"),
        bindMount(`${STATE_DIR}/certs/local-key.pem`, "/etc/nginx/conf/server.key"),
      ],
      networks: { platform_edge: { ipv4_address: "172.30.250.2" } },
      healthcheck: { test: ["CMD-SHELL", "nginx -t"], interval: "20s", timeout: "5s", retries: 10 },
    },
    postgres: {
      image: image("postgres"),
      container_name: "gf-postgres",
      init: true,
      security_opt: ["no-new-privileges:true"],
      restart: "always",
      ...coreResources("1.00", "1024m", "256m", 768),
      entrypoint: ["/usr/local/bin/platform-postgres-entrypoint"],
      environment: { POSTGRES_DB: "postgres", POSTGRES_USER: "postgres", POSTGRES_PASSWORD_FILE: "/run/secrets/postgres_superuser_password" },
      secrets: [secretGrant("postgres_superuser_password"), secretGrant("keycloak_db_password")],
      volumes: [
        volumeMount("enterprise_postgres_data", "/var/lib/postgresql"),
        bindMount("./postgres/init", "/platform-postgres-init"),
        bindMount("./postgres/entrypoint-with-init-secrets.sh", "/usr/local/bin/platform-postgres-entrypoint"),
      ],
      networks: { platform_db_admin: null, platform_postgres: null },
      healthcheck: { test: ["CMD-SHELL", "pg_isready"], interval: "10s", timeout: "5s", retries: 10 },
    },
    "broker-auth-bootstrap": {
      image: image("broker-auth-bootstrap"),
      container_name: "gf-broker-auth-bootstrap",
      init: true,
      read_only: true,
      security_opt: ["no-new-privileges:true"],
      cap_drop: ["ALL"],
      cap_add: ["CHOWN", "DAC_READ_SEARCH"],
      restart: "no",
      network_mode: "none",
      ...coreResources("0.25", "128m", "32m", 64),
      entrypoint: ["node", "/broker/render-workload-broker-config.mjs"],
      command: ["all", "--lock", "/run/platform/hosted-workloads.lock.json", "--secretsRoot", "/run/secrets"],
      secrets: [secretGrant("redis_password"), secretGrant("nats_password")],
      volumes: [
        bindMount("./scripts/render-workload-broker-config.mjs", "/broker/render-workload-broker-config.mjs"),
        bindMount("./scripts/workload-broker-policy.mjs", "/broker/workload-broker-policy.mjs"),
        bindMount(`${ROOT_DIR}/config/no-hosted-workloads.local-private.lock.json`, "/run/platform/hosted-workloads.lock.json"),
        volumeMount("redis_auth_config", "/out/redis"),
        volumeMount("nats_auth_config", "/out/nats"),
      ],
    },
    redis: {
      image: image("redis"),
      container_name: "gf-redis",
      init: true,
      security_opt: ["no-new-privileges:true"],
      restart: "always",
      ...coreResources("0.50", "256m", "64m", 192),
      environment: { REDIS_USERNAME: "platform", REDIS_PASSWORD_FILE: "/run/secrets/redis_password" },
      command: ["sh", "-ec", "cd /run/platform-broker && sha256sum -c redis-users.acl.sha256 >/dev/null && cd /data && exec redis-server --appendonly yes --aclfile /run/platform-broker/redis-users.acl"],
      depends_on: { "broker-auth-bootstrap": { condition: "service_completed_successfully" } },
      secrets: [secretGrant("redis_password")],
      volumes: [volumeMount("enterprise_redis_data", "/data"), volumeMount("redis_auth_config", "/run/platform-broker", true)],
      networks: { platform_cache: null },
      healthcheck: { test: ["CMD-SHELL", "redis-cli ping"], interval: "10s", timeout: "5s", retries: 10 },
    },
    keycloak: {
      image: image("keycloak"),
      container_name: "gf-keycloak",
      init: true,
      security_opt: ["no-new-privileges:true"],
      restart: "always",
      labels: { "traefik.enable": "false" },
      ...coreResources("1.50", "1280m", "384m", 768),
      entrypoint: ["/bin/sh", "-ec"],
      command: ['export KC_BOOTSTRAP_ADMIN_PASSWORD="$(cat "$${KC_BOOTSTRAP_ADMIN_PASSWORD_FILE}")"; exec /opt/keycloak/bin/kc.sh start --http-port=8080 --import-realm'],
      environment: { KC_DB: "postgres", KC_DB_PASSWORD_FILE: "/run/secrets/keycloak_db_password", KC_HOSTNAME_STRICT: "true" },
      depends_on: { postgres: { condition: "service_healthy" } },
      secrets: [secretGrant("keycloak_admin_password"), secretGrant("keycloak_db_password")],
      volumes: [
        volumeMount("enterprise_keycloak_data", "/opt/keycloak/data"),
        bindMount("./keycloak/import", "/opt/keycloak/data/import"),
      ],
      networks: { platform_routing: null, platform_postgres: null, platform_observability: null, platform_egress: null },
      healthcheck: { test: ["CMD-SHELL", "true"], interval: "20s", timeout: "5s", retries: 15 },
    },
    nats: {
      image: image("nats"),
      container_name: "gf-nats",
      init: true,
      security_opt: ["no-new-privileges:true"],
      restart: "always",
      user: "1000:1000",
      ...coreResources("0.25", "128m", "32m", 192),
      entrypoint: ["/bin/sh", "-ec"],
      command: ["cd /run/platform-broker && sha256sum -c nats-server.conf.sha256 >/dev/null && exec /nats-server --config /run/platform-broker/nats-server.conf"],
      depends_on: { "broker-auth-bootstrap": { condition: "service_completed_successfully" } },
      volumes: [volumeMount("enterprise_nats_data", "/data"), volumeMount("nats_auth_config", "/run/platform-broker", true)],
      networks: { platform_bus: null },
      healthcheck: { test: ["CMD-SHELL", "wget -q http://127.0.0.1:8222/healthz"], interval: "10s", timeout: "5s", retries: 10 },
    },
    minio: {
      image: image("minio"),
      container_name: "gf-minio",
      init: true,
      security_opt: ["no-new-privileges:true"],
      restart: "always",
      labels: { "traefik.enable": "false" },
      ...coreResources("1.00", "768m", "192m", 384),
      entrypoint: ["/bin/sh", "-ec"],
      command: ['export MINIO_ROOT_PASSWORD="$(cat "$${MINIO_ROOT_PASSWORD_FILE}")"; exec minio server /data'],
      environment: { MINIO_ROOT_USER: "minio_admin", MINIO_ROOT_PASSWORD_FILE: "/run/secrets/minio_root_password" },
      secrets: [secretGrant("minio_root_password")],
      volumes: [volumeMount("enterprise_minio_data", "/data")],
      networks: { platform_storage: null },
      healthcheck: { test: ["CMD-SHELL", "curl -fsS http://127.0.0.1:9000/minio/health/live"], interval: "15s", timeout: "5s", retries: 10 },
    },
    "control-center": {
      image: image("control-center"),
      container_name: "gf-control-center",
      init: true,
      security_opt: ["no-new-privileges:true"],
      restart: "always",
      read_only: true,
      working_dir: "/app",
      ...controlResources("1.00", "512m", "128m", 384),
      command: ["node", "/app/server.mjs"],
      expose: ["8080"],
      environment: { CONTROL_CENTER_PORT: "8080", CONTROL_CENTER_ENV: "local_private" },
      tmpfs: ["/tmp:rw,noexec,nosuid,nodev,size=64m"],
      secrets: [
        secretGrant("projects_gateway_signing_keys"),
        secretGrant("control_center_vault_keys"),
        secretGrant("control_center_database_url"),
        secretGrant("mariadb_root_password"),
        secretGrant("postgres_superuser_password"),
        secretGrant("control_center_first_configuration_bootstrap_token"),
        secretGrant("control_center_first_configuration_keycloak_client_secret"),
      ],
      volumes: [
        bindMount(".", "/var/www/infra-docs"),
        bindMount(`${STATE_DIR}/projects`, "/var/www/projects"),
        bindMount(`${STATE_DIR}/project-state`, "/var/www/project-state", false),
      ],
      depends_on: { keycloak: { condition: "service_healthy" }, postgres: { condition: "service_healthy" } },
      networks: { platform_routing: null, platform_db_admin: null, platform_observability: null, platform_egress: null },
      healthcheck: { test: ["CMD-SHELL", "true"], interval: "15s", timeout: "5s", retries: 10 },
    },
    "project-router": {
      image: image("project-router"),
      container_name: "gf-project-router",
      init: true,
      security_opt: ["no-new-privileges:true"],
      restart: "always",
      read_only: true,
      ...controlResources("0.50", "192m", "48m", 192),
      command: ["node", "/app/server.mjs"],
      expose: ["8080"],
      environment: { PROJECT_ROUTER_PORT: "8080" },
      tmpfs: ["/tmp:rw,noexec,nosuid,nodev,size=32m"],
      volumes: [
        bindMount(`${STATE_DIR}/projects`, "/var/www/projects"),
        bindMount(`${STATE_DIR}/project-state`, "/var/www/project-state"),
        bindMount(`${ROOT_DIR}/config/no-hosted-workloads.local-private.lock.json`, "/run/platform/hosted-workloads.lock.json"),
      ],
      depends_on: { "control-center": { condition: "service_healthy" } },
      networks: { platform_routing: null },
      healthcheck: { test: ["CMD-SHELL", "true"], interval: "15s", timeout: "5s", retries: 10 },
    },
    mariadb: {
      image: image("mariadb"),
      container_name: "gf-mariadb",
      init: true,
      security_opt: ["no-new-privileges:true"],
      restart: "always",
      ...coreResources("1.50", "1024m", "256m", 768),
      environment: { MARIADB_ROOT_PASSWORD_FILE: "/run/secrets/mariadb_root_password" },
      secrets: [secretGrant("mariadb_root_password")],
      volumes: [
        volumeMount("enterprise_mariadb_data", "/var/lib/mysql"),
        bindMount("./mariadb/initdb", "/docker-entrypoint-initdb.d"),
        bindMount("./mariadb/conf.d", "/etc/mysql/conf.d"),
        bindMount(`${STATE_DIR}/certs`, "/etc/mysql/ssl"),
      ],
      networks: { platform_db_admin: { aliases: ["platform.local"] } },
      healthcheck: { test: ["CMD-SHELL", "mariadb -uroot -e 'select 1'"], interval: "5s", timeout: "3s", retries: 30 },
    },
    alertmanager: {
      image: image("alertmanager"),
      container_name: "gf-alertmanager",
      init: true,
      security_opt: ["no-new-privileges:true"],
      restart: "always",
      group_add: ["1000"],
      ...observabilityResources("0.25", "128m", "32m", 128),
      command: ["--config.file=/etc/alertmanager/alertmanager.yml", "--storage.path=/alertmanager"],
      depends_on: { "platform-alert-dispatcher": { condition: "service_healthy" } },
      secrets: [secretGrant("alertmanager_webhook_token")],
      volumes: [
        volumeMount("enterprise_alertmanager_data", "/alertmanager"),
        bindMount("./alertmanager/alertmanager.yml", "/etc/alertmanager/alertmanager.yml"),
      ],
      networks: { platform_observability: null },
      healthcheck: { test: ["CMD-SHELL", "wget -q http://127.0.0.1:9093/-/ready"], interval: "15s", timeout: "5s", retries: 10 },
    },
    "platform-alert-dispatcher": {
      image: image("platform-alert-dispatcher"),
      container_name: "gf-platform-alert-dispatcher",
      init: true,
      security_opt: ["no-new-privileges:true"],
      cap_drop: ["ALL"],
      restart: "always",
      read_only: true,
      user: "1000:1000",
      ...observabilityResources("0.20", "128m", "32m", 128),
      environment: { PORT: "3000", ALERTMANAGER_WEBHOOK_TOKEN_FILE: "/run/secrets/alertmanager_webhook_token", SMTP_PASSWORD_FILE: "/run/secrets/smtp_password" },
      expose: ["3000"],
      tmpfs: ["/tmp:rw,noexec,nosuid,nodev,size=16m"],
      secrets: [secretGrant("alertmanager_webhook_token"), secretGrant("smtp_password")],
      networks: { platform_observability: null, platform_egress: null },
      healthcheck: { test: ["CMD-SHELL", "true"], interval: "20s", timeout: "5s", retries: 10 },
    },
    prometheus: {
      image: image("prometheus"),
      container_name: "gf-prometheus",
      init: true,
      security_opt: ["no-new-privileges:true"],
      restart: "always",
      ...observabilityResources("0.50", "512m", "128m", 320),
      command: ["--config.file=/etc/prometheus/prometheus.yml", "--storage.tsdb.path=/prometheus"],
      depends_on: { alertmanager: { condition: "service_healthy" } },
      volumes: [
        volumeMount("enterprise_prometheus_data", "/prometheus"),
        bindMount("./prometheus/prometheus.yml", "/etc/prometheus/prometheus.yml"),
        bindMount("./prometheus/rules", "/etc/prometheus/rules"),
      ],
      networks: { platform_observability: null },
      healthcheck: { test: ["CMD-SHELL", "wget -q http://127.0.0.1:9090/-/ready"], interval: "15s", timeout: "5s", retries: 10 },
    },
    grafana: {
      image: image("grafana"),
      container_name: "gf-grafana",
      init: true,
      security_opt: ["no-new-privileges:true"],
      restart: "always",
      labels: { "traefik.enable": "false" },
      ...observabilityResources("0.50", "384m", "96m", 256),
      environment: { GF_USERS_ALLOW_SIGN_UP: "false", GF_SECURITY_ADMIN_PASSWORD__FILE: "/run/secrets/grafana_admin_password" },
      depends_on: { prometheus: { condition: "service_healthy" }, loki: { condition: "service_healthy" } },
      secrets: [secretGrant("grafana_admin_password")],
      volumes: [
        volumeMount("enterprise_grafana_data", "/var/lib/grafana"),
        bindMount("./grafana/provisioning", "/etc/grafana/provisioning"),
        bindMount("./grafana/dashboards", "/var/lib/grafana/dashboards"),
      ],
      networks: { platform_observability: null },
      healthcheck: { test: ["CMD-SHELL", "wget -q http://127.0.0.1:3000/api/health"], interval: "15s", timeout: "5s", retries: 10 },
    },
    loki: {
      image: image("loki"),
      container_name: "gf-loki",
      init: true,
      security_opt: ["no-new-privileges:true"],
      restart: "always",
      ...observabilityResources("0.50", "512m", "128m", 320),
      command: ["-config.file=/etc/loki/config.yml"],
      depends_on: { alertmanager: { condition: "service_healthy" } },
      volumes: [
        volumeMount("enterprise_loki_data", "/loki"),
        bindMount("./loki/config.yml", "/etc/loki/config.yml"),
        bindMount("./loki/rules", "/loki/rules"),
      ],
      networks: { platform_observability: null },
      healthcheck: { test: ["CMD", "/usr/bin/loki", "-version"], interval: "15s", timeout: "5s", retries: 15 },
    },
    promtail: {
      image: image("promtail"),
      container_name: "gf-promtail",
      init: true,
      security_opt: ["no-new-privileges:true"],
      restart: "always",
      ...observabilityResources("0.25", "192m", "48m", 192),
      command: ["-config.file=/etc/promtail/config.yml"],
      depends_on: { loki: { condition: "service_healthy" } },
      volumes: [
        bindMount("./promtail/config.yml", "/etc/promtail/config.yml"),
        bindMount("/var/lib/docker/containers", "/var/lib/docker/containers"),
      ],
      networks: { platform_observability: null },
      healthcheck: { test: ["CMD-SHELL", "true"], interval: "20s", timeout: "5s", retries: 10 },
    },
    "backup-scheduler": {
      image: image("backup-scheduler"),
      container_name: "gf-backup-scheduler",
      init: true,
      profiles: ["backup"],
      security_opt: ["no-new-privileges:true"],
      cap_drop: ["ALL"],
      restart: "unless-stopped",
      read_only: true,
      user: "0:0",
      network_mode: "none",
      ...controlResources("1.00", "512m", "128m", 256),
      entrypoint: ["/opt/platform-backup-scheduler/backup-scheduler.sh"],
      command: [],
      environment: {
        DOCKER_ACTION_BROKER_SOCKET: "/run/platform/docker-action-broker/broker.sock",
        DOCKER_ACTION_RUNTIME_INTENT_ID: "runtime-intent-1",
        DOCKER_ACTION_ACTIVE_RECEIPT_SHA256: digestOf("receipt"),
        DOCKER_ACTION_COMBINED_RENDER_SHA256: digestOf("combined-render"),
        BACKUP_SCHEDULER_JOBS_DIR: "/var/www/project-state/backup-jobs",
        BACKUP_SCHEDULER_LOG_DIR: "/var/log/platform",
        BACKUP_SCHEDULER_CRON_FILE: "/run/platform/backup-scheduler/crontabs/root",
        BACKUP_SCHEDULER_ENV_FILE: "/run/platform/backup-scheduler/backup-scheduler.env",
      },
      secrets: [
        capabilitySecretGrant("docker_action_backup_catalog"),
        capabilitySecretGrant("docker_action_backup_job_execute"),
        capabilitySecretGrant("docker_action_backup_prune_plan"),
        capabilitySecretGrant("docker_action_backup_prune_apply"),
        capabilitySecretGrant("docker_action_restore_drill_full"),
        capabilitySecretGrant("docker_action_backup_offsite_sync"),
      ],
      tmpfs: [
        "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "/run/platform/backup-scheduler:rw,noexec,nosuid,nodev,size=8m",
      ],
      volumes: [
        volumeMount("backup_scheduler_jobs", "/var/www/project-state/backup-jobs"),
        volumeMount("backup_scheduler_logs", "/var/log/platform"),
        volumeMount("docker_action_broker_socket", "/run/platform/docker-action-broker", true),
      ],
      depends_on: { "docker-action-broker": { condition: "service_healthy" } },
      healthcheck: { test: ["CMD-SHELL", "test -s /run/platform/backup-scheduler/crontabs/root"], interval: "30s", timeout: "5s", retries: 5 },
    },
    "docker-action-broker": {
      image: image("docker-action-broker"),
      container_name: "gf-docker-action-broker",
      init: true,
      profiles: ["backup"],
      security_opt: ["no-new-privileges:true"],
      cap_drop: ["ALL"],
      restart: "unless-stopped",
      read_only: true,
      user: "0:0",
      network_mode: "none",
      ...controlResources("0.50", "512m", "128m", 256),
      entrypoint: ["node", "/opt/platform-docker-broker/docker-action-broker.mjs"],
      environment: {
        DOCKER_ACTION_BROKER_SOCKET: "/run/platform/docker-action-broker/broker.sock",
        DOCKER_ACTION_RUNTIME_INTENT_FILE: "/run/platform/docker-action-trust/runtime-intent.json",
        DOCKER_ACTION_ACTIVE_RECEIPT_FILE: "/run/platform/docker-action-trust/active-receipt.json",
        DOCKER_ACTION_RUNTIME_INTENT_TRUST_KEY_FILE: "/run/secrets/docker_action_runtime_intent_trust_key",
      },
      tmpfs: [
        "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "/root:rw,noexec,nosuid,nodev,size=16m",
      ],
      secrets: [
        capabilitySecretGrant("docker_action_runtime_intent_trust_key"),
        capabilitySecretGrant("docker_action_backup_catalog"),
        capabilitySecretGrant("docker_action_backup_job_execute"),
        capabilitySecretGrant("docker_action_backup_prune_plan"),
        capabilitySecretGrant("docker_action_backup_prune_apply"),
        capabilitySecretGrant("docker_action_restore_drill_full"),
        capabilitySecretGrant("docker_action_backup_offsite_sync"),
        capabilitySecretGrant("docker_action_evidence_runtime_snapshot"),
      ],
      volumes: [
        bindMount("/var/run/docker.sock", "/var/run/docker.sock"),
        volumeMount("docker_action_broker_socket", "/run/platform/docker-action-broker"),
        volumeMount("docker_action_broker_state", "/var/lib/platform/docker-action-broker"),
        volumeMount("backup_scheduler_jobs", "/run/platform/backup-jobs", true),
        volumeMount("docker_action_activation_cas", "/run/platform/docker-action-activation/by-bundle-sha256", true),
        bindMount(`${TRUST_DIR}/runtime-intent.json`, "/run/platform/docker-action-trust/runtime-intent.json"),
        bindMount(`${TRUST_DIR}/active-receipt.json`, "/run/platform/docker-action-trust/active-receipt.json"),
      ],
      healthcheck: {
        test: ["CMD", "node", "/opt/platform-docker-broker/docker-action-readiness.mjs", "--require-trusted-activation"],
        interval: "15s",
        timeout: "5s",
        retries: 5,
      },
    },
    "docker-action-activation-sidecar": {
      image: image("docker-action-activation-sidecar"),
      container_name: "gf-docker-action-activation-sidecar",
      init: true,
      profiles: ["backup"],
      security_opt: ["no-new-privileges:true"],
      cap_drop: ["ALL"],
      restart: "no",
      read_only: true,
      user: "0:0",
      network_mode: "none",
      ...controlResources("0.25", "128m", "32m", 64),
      entrypoint: ["/opt/provider-activation/materialize-dsse-cas"],
      environment: {
        ACTIVATION_INBOX: "/run/platform/provider-activation/inbox",
        ACTIVATION_CAS: "/run/platform/docker-action-activation/by-bundle-sha256",
      },
      volumes: [
        bindMount(ACTIVATION_INBOX, "/run/platform/provider-activation/inbox"),
        volumeMount("docker_action_activation_cas", "/run/platform/docker-action-activation/by-bundle-sha256"),
      ],
    },
  };

  const networks = {
    platform_edge: { name: "platform_infra_greenfield_platform_edge", internal: true },
    platform_routing: { name: "platform_infra_greenfield_platform_routing", internal: true },
    platform_db_admin: { name: "platform_infra_greenfield_platform_db_admin", internal: true },
    platform_postgres: { name: "platform_infra_greenfield_platform_postgres", internal: true },
    platform_cache: { name: "platform_infra_greenfield_platform_cache", internal: true },
    platform_bus: { name: "platform_infra_greenfield_platform_bus", internal: true },
    platform_storage: { name: "platform_infra_greenfield_platform_storage", internal: true },
    platform_observability: { name: "platform_infra_greenfield_platform_observability", internal: true },
    platform_egress: { name: "platform_infra_greenfield_platform_egress", enable_ipv6: false },
  };

  const volumes = {};
  for (const logical of LOCK.protectedResourceNames.volumes) {
    const stripped = logical.replace(/^enterprise_/, "");
    volumes[logical] = { name: `greenfield_${stripped}`, external: false };
  }

  const secrets = {};
  for (const logical of LOCK.protectedResourceNames.secrets) {
    const file = logical.startsWith("control_center_first_configuration_bootstrap_token")
      ? `${STATE_DIR}/first-configuration/bootstrap-token.txt`
      : logical.startsWith("control_center_first_configuration_keycloak_client_secret")
        ? `${STATE_DIR}/first-configuration/keycloak-client-secret.txt`
        : `${SECRETS_ROOT}/${logical}.txt`;
    secrets[logical] = { file, name: `platform_infra_greenfield_${logical}` };
  }

  return {
    name: GREENFIELD_PROJECT_NAME,
    services,
    configs: { enterprise_traefik_routes: { content: "http:\n  routers: {}\n" } },
    networks,
    volumes,
    secrets,
  };
}

const ENVIRONMENT = new Map([
  ["PLATFORM_SECRETS_ROOT", SECRETS_ROOT],
]);

test("the complete greenfield render passes every semantic authority", () => {
  const result = evaluateGreenfieldCoreAuthority(structuredClone(LOCK), buildAcceptRender(), ENVIRONMENT);
  assert.deepEqual(result.violations, []);
  assert.deepEqual(result.normalizedSummary, {
    serviceCount: 20,
    networkCount: 9,
    volumeCount: 17,
    secretCount: 23,
  });
});

test("the committed lock stays bound to this policy file and the core service set", () => {
  const selfDigest = crypto.createHash("sha256").update(fs.readFileSync(POLICY_PATH)).digest("hex");
  assert.equal(LOCK.version, 4);
  assert.equal(LOCK.state, "verified");
  assert.equal(LOCK.projectName, GREENFIELD_PROJECT_NAME);
  assert.equal(LOCK.coreSemanticPolicy.schema, "platform-no-hosted-core-capability-policy/v2");
  assert.equal(LOCK.coreSemanticPolicy.sha256, selfDigest);
  assert.deepEqual([...LOCK.protectedResourceNames.services].sort(), [...GREENFIELD_CORE_SERVICES].sort());
  assert.equal(LOCK.protectedResourceNames.secrets.length, 23);
  assert.equal(LOCK.protectedResourceNames.volumes.length, 17);
  assert.ok(GREENFIELD_ALL_SERVICES.length === 27);
});

function rejects(label, mutate, expectedFragment) {
  test(`rejects ${label}`, () => {
    const config = buildAcceptRender();
    mutate(config);
    const result = evaluateGreenfieldCoreAuthority(
      structuredClone(LOCK),
      config,
      new Map(ENVIRONMENT),
    );
    assert.ok(result.violations.length > 0, "expected rejections");
    assert.ok(
      result.violations.some((violation) => violation.includes(expectedFragment)),
      `expected a violation containing "${expectedFragment}", got: ${JSON.stringify(result.violations)}`,
    );
  });
}

rejects("a foreign project name", (config) => {
  config.name = "platform_infra_vps";
}, "render:project-name");

rejects("a brownfield traefik container name", (config) => {
  config.services.traefik.container_name = "enterprise-traefik";
}, "service:traefik:container-name:brownfield");

rejects("a missing container_name", (config) => {
  delete config.services.redis.container_name;
}, "service:redis:container-name:missing");

rejects("an externally owned enterprise_net", (config) => {
  config.networks.enterprise_net = { name: "enterprise_net", external: true };
}, "network:enterprise_net:physical-name:brownfield");

rejects("a legacy enterprise data volume name", (config) => {
  config.volumes.enterprise_postgres_data = { name: "enterprise_postgres_data", external: false };
}, "volume:enterprise_postgres_data:physical-forbidden");

rejects("an external volume declaration", (config) => {
  config.volumes.enterprise_postgres_data = { name: "greenfield_postgres_data", external: true };
}, "volume:enterprise_postgres_data:external");

rejects("an unpinned service image", (config) => {
  config.services.minio.image = "quay.io/minio/minio:latest";
}, "service:minio:image-digest");

rejects("a privileged service", (config) => {
  config.services.grafana.privileged = true;
}, "service:grafana:privileged");

rejects("a bind mount sourcing backups material", (config) => {
  config.services.postgres.volumes.push(bindMount("/srv/platform/backups/snapshots", "/host-backups"));
}, "service:postgres:forbidden-bind-source");

rejects("a bind mount sourcing raw pem.key material", (config) => {
  config.services.postgres.volumes.push(bindMount(`${STATE_DIR}/local-cert.pem.key`, "/raw-key"));
}, "service:postgres:forbidden-bind-source");

rejects("an unowned secret declaration", (config) => {
  config.secrets.redis_password = { file: "/tmp/unowned/redis_password.txt" };
}, "secret:redis_password:authority");

rejects("a secret inventory drift", (config) => {
  delete config.secrets.smtp_password;
}, "secrets:count");

rejects("an auxiliary service without its disabling profile", (config) => {
  config.services.phpmyadmin = {
    image: image("phpmyadmin"),
    container_name: "gf-phpmyadmin",
    profiles: [],
  };
}, "service:phpmyadmin:profile-required");

rejects("an unknown extra service", (config) => {
  config.services.rogue = { image: image("rogue"), container_name: "gf-rogue" };
}, "service:rogue:unexpected");

test("rejects a policy self-digest mismatch", () => {
  const lock = structuredClone(LOCK);
  lock.coreSemanticPolicy = { schema: lock.coreSemanticPolicy.schema, sha256: "0".repeat(64) };
  const result = evaluateGreenfieldCoreAuthority(lock, buildAcceptRender(), new Map(ENVIRONMENT));
  assert.ok(result.violations.includes("policy-binding"), result.violations);
});

test("rejects a foreign lock project name", () => {
  const lock = structuredClone(LOCK);
  lock.projectName = "platform_infra_vps";
  const result = evaluateGreenfieldCoreAuthority(lock, buildAcceptRender(), new Map(ENVIRONMENT));
  assert.ok(result.violations.includes("lock:project-name"), result.violations);
});

rejects("a broker stripped of its required readonly mounts", (config) => {
  delete config.services["docker-action-broker"].volumes;
}, "runtime-isolation:docker-broker-exact-mount-targets");

test("the policy CLI accepts the canonical fixture end-to-end", () => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "greenfield-policy-"));
  try {
    const configPath = path.join(work, "render.json");
    const envPath = path.join(work, "environment.env");
    fs.writeFileSync(configPath, `${JSON.stringify(buildAcceptRender())}\n`);
    fs.writeFileSync(envPath, `PLATFORM_SECRETS_ROOT=${SECRETS_ROOT}\n`);
    const accepted = spawnSync(process.execPath, [
      POLICY_PATH, "--root", ROOT_DIR, "--lock", LOCK_PATH, "--config", configPath, "--env", envPath,
    ], { encoding: "utf8" });
    assert.equal(accepted.status, 0, accepted.stderr);
    const payload = JSON.parse(accepted.stdout);
    assert.deepEqual(payload.violations, []);
    assert.deepEqual(payload.normalizedSummary, {
      serviceCount: 20, networkCount: 9, volumeCount: 17, secretCount: 23,
    });

    fs.writeFileSync(configPath, `${JSON.stringify({
      ...buildAcceptRender(),
      name: "platform_infra_vps",
    })}\n`);
    const rejected = spawnSync(process.execPath, [
      POLICY_PATH, "--root", ROOT_DIR, "--lock", LOCK_PATH, "--config", configPath, "--env", envPath,
    ], { encoding: "utf8" });
    assert.equal(rejected.status, 65);
    assert.match(rejected.stderr, /^greenfield semantic authority rejected: .+/);

    const invalidArgs = spawnSync(process.execPath, [
      POLICY_PATH, "--lock", LOCK_PATH, "--config", configPath, "--env", envPath,
    ], { encoding: "utf8" });
    assert.equal(invalidArgs.status, 65);
    assert.equal(invalidArgs.stderr.trim(), "greenfield semantic authority input invalid");
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
});

test("the render wrapper keeps its fail-closed discipline statically", () => {
  const parsed = spawnSync("bash", ["-n", WRAPPER_PATH], { encoding: "utf8" });
  assert.equal(parsed.status, 0, parsed.stderr);
  const source = fs.readFileSync(WRAPPER_PATH, "utf8");

  const requiredFragments = [
    "PROJECT_NAME=platform_infra_greenfield",
    "COMPOSE_PROJECT_NAME overrides are forbidden",
    "canonical project platform_infra_greenfield",
    "unix:///var/run/docker.sock",
    "Caller-selected DOCKER_HOST is forbidden",
    "Caller-selected DOCKER_CONTEXT is forbidden",
    "Caller-controlled Compose files, environment, projects and profiles are forbidden",
    "render-sha256",
    "config --format json",
    "GREENFIELD_TOPOLOGY must be PARALLEL or CUTOVER",
    "0.0.0.0:18080",
    "0.0.0.0:18443",
    "0.0.0.0:80",
    "0.0.0.0:443",
    "WAF_HTTP_BIND=$WAF_HTTP_BIND",
    "MARIADB_DATA_VOLUME must be unset or exactly greenfield_mariadb_data",
    "PLATFORM_NETWORK_PREFIX is bound to the canonical greenfield namespace platform_infra_greenfield",
    "PLATFORM_TEST_DOCKER_COMPOSE_BIN",
    "5\\.3\\.",
    "/usr/bin/env",
    "GREENFIELD_RENDER_AUTHORITY=1",
    "-f compose.yaml",
    "-f compose.secrets.yaml",
    "-f compose.waf.yaml",
    "-f compose.vps.yaml",
    "-f compose.vps-waf.yaml",
    "-f compose.backup-scheduler.yaml",
    "-f compose.runtime.yaml",
    "-f compose.networks.yaml",
    "-f compose.runtime-isolation.yaml",
    "-f compose.local-private.yaml",
    "-f compose.runtime-identity.yaml",
    "-f compose.greenfield.yaml",
    "--profile backup",
    "greenfield-core-policy.mjs",
    "--lock",
    "--config",
    "--env",
  ];
  for (const fragment of requiredFragments) {
    assert.ok(source.includes(fragment), `wrapper source must contain: ${fragment}`);
  }

  // Overlay chain discipline: LOCAL_PRIVATE mandatory, identity before the
  // greenfield projection, greenfield applied LAST.
  const chainOrder = [
    "compose.yaml",
    "compose.secrets.yaml",
    "compose.waf.yaml",
    "compose.vps.yaml",
    "compose.vps-waf.yaml",
    "compose.backup-scheduler.yaml",
    "compose.runtime.yaml",
    "compose.networks.yaml",
    "compose.runtime-isolation.yaml",
    "compose.local-private.yaml",
    "compose.runtime-identity.yaml",
    "compose.greenfield.yaml",
  ].map((overlay) => source.indexOf(`-f ${overlay}`));
  assert.ok(chainOrder.every((index) => index >= 0));
  assert.deepEqual(chainOrder, [...chainOrder].sort((left, right) => left - right));

  const forbiddenArgumentPatterns = ["--env-file=*|--profile", "-p|-p?*", "--scale"];
  for (const pattern of forbiddenArgumentPatterns) {
    assert.ok(source.includes(pattern), `wrapper argument scan must cover: ${pattern}`);
  }
});
