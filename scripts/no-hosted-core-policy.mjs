#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { evaluateRuntimeIsolation } from "./runtime-isolation-policy.mjs";

export const CORE_SEMANTIC_POLICY_SCHEMA = "platform-no-hosted-core-capability-policy/v1";

const CORE_SEMANTIC_POLICY = {
  schema: CORE_SEMANTIC_POLICY_SCHEMA,
  allowedServiceFields: [
    "blkio_config",
    "build",
    "cap_drop",
    "command",
    "configs",
    "container_name",
    "cpu_shares",
    "cpus",
    "depends_on",
    "entrypoint",
    "environment",
    "expose",
    "group_add",
    "healthcheck",
    "image",
    "init",
    "labels",
    "logging",
    "mem_limit",
    "mem_reservation",
    "memswap_limit",
    "network_mode",
    "networks",
    "pid",
    "pids_limit",
    "ports",
    "profiles",
    "read_only",
    "restart",
    "secrets",
    "security_opt",
    "tmpfs",
    "ulimits",
    "user",
    "volumes",
    "working_dir",
  ],
  exactExceptions: {
    pid: { "node-exporter": "host" },
    networkMode: { "local-registry": "bridge" },
    groupAdd: { alertmanager: ["1000"] },
  },
  serviceContainerNames: {
    alertmanager: "enterprise-alertmanager",
    "backup-scheduler": "enterprise-backup-scheduler",
    cadvisor: "enterprise-cadvisor",
    "control-center": "enterprise-control-center",
    "docker-socket-proxy": "enterprise-docker-socket-proxy",
    grafana: "enterprise-grafana",
    keycloak: "enterprise-keycloak",
    "local-dns": "enterprise-local-dns",
    "local-registry": "enterprise-local-registry",
    loki: "enterprise-loki",
    mariadb: "mariadb",
    minio: "enterprise-minio",
    nats: "enterprise-nats",
    "node-exporter": "enterprise-node-exporter",
    phpmyadmin: "phpmyadmin",
    phppgadmin: "phppgadmin",
    "platform-alert-dispatcher": "enterprise-platform-alert-dispatcher",
    postgres: "enterprise-postgres",
    "project-router": "enterprise-project-router",
    prometheus: "enterprise-prometheus",
    promtail: "enterprise-promtail",
    redis: "enterprise-redis",
    traefik: "enterprise-traefik",
    waf: "enterprise-waf",
  },
  serviceRestartPolicies: {
    alertmanager: "always",
    "backup-scheduler": "unless-stopped",
    cadvisor: "unless-stopped",
    "control-center": "always",
    "docker-socket-proxy": "unless-stopped",
    grafana: "always",
    keycloak: "always",
    "local-dns": "unless-stopped",
    "local-registry": "unless-stopped",
    loki: "always",
    mariadb: "always",
    minio: "always",
    nats: "always",
    "node-exporter": "unless-stopped",
    phpmyadmin: "unless-stopped",
    phppgadmin: "unless-stopped",
    "platform-alert-dispatcher": "always",
    postgres: "always",
    "project-router": "always",
    prometheus: "always",
    promtail: "always",
    redis: "always",
    traefik: "always",
    waf: "always",
  },
  serviceProfiles: {
    "backup-scheduler": ["backup"],
  },
  serviceDependencies: {
    alertmanager: ["platform-alert-dispatcher"],
    "backup-scheduler": ["docker-socket-proxy", "keycloak", "mariadb", "minio", "postgres"],
    "control-center": ["keycloak", "postgres"],
    grafana: ["loki", "prometheus"],
    keycloak: ["postgres"],
    loki: ["alertmanager"],
    phpmyadmin: ["mariadb"],
    phppgadmin: ["postgres"],
    "project-router": ["control-center"],
    prometheus: ["alertmanager", "cadvisor", "node-exporter"],
    promtail: ["loki"],
    waf: ["traefik"],
  },
  sensitiveSourcePrefixes: ["/etc", "/home", "/opt", "/private", "/root", "/Users", "/usr"],
  topLevelAuthority: {
    configFields: ["content"],
    secretExternalNamePrefix: "platform_infra_vps_",
    networkFields: ["attachable", "driver", "enable_ipv4", "enable_ipv6", "external", "internal", "labels", "name"],
    externalNetworkNames: ["enterprise_net"],
    volumeFields: ["external", "labels", "name"],
  },
  serviceEnvironmentAuthority: {
    "services": {
      "alertmanager": {
        "present": false,
        "entries": {}
      },
      "backup-scheduler": {
        "present": true,
        "entries": {
          "AWS_ACCESS_KEY_ID": {
            "variable": "AWS_ACCESS_KEY_ID",
            "fallback": ""
          },
          "AWS_SECRET_ACCESS_KEY": {
            "variable": "AWS_SECRET_ACCESS_KEY",
            "fallback": ""
          },
          "BACKUP_LOCAL_KEEP_LAST": {
            "variable": "BACKUP_LOCAL_KEEP_LAST",
            "fallback": "42"
          },
          "BACKUP_SCHEDULER_CATALOG_CRON": {
            "variable": "BACKUP_SCHEDULER_CATALOG_CRON",
            "fallback": "5 */8 * * *"
          },
          "BACKUP_SCHEDULER_ENABLE_OFFSITE": {
            "variable": "BACKUP_SCHEDULER_ENABLE_OFFSITE",
            "fallback": "false"
          },
          "BACKUP_SCHEDULER_ENABLE_RETENTION_APPLY": {
            "variable": "BACKUP_SCHEDULER_ENABLE_RETENTION_APPLY",
            "fallback": "false"
          },
          "BACKUP_SCHEDULER_FULL_RESTORE_DRILL_AT": {
            "variable": "BACKUP_SCHEDULER_FULL_RESTORE_DRILL_AT",
            "fallback": "04:45"
          },
          "BACKUP_SCHEDULER_JOBS_DIR": {
            "literal": "/var/www/project-state/backup-jobs"
          },
          "BACKUP_SCHEDULER_OFFSITE_CRON": {
            "variable": "BACKUP_SCHEDULER_OFFSITE_CRON",
            "fallback": "35 */8 * * *"
          },
          "BACKUP_SCHEDULER_RESTORE_DRILL_WEEKDAY": {
            "variable": "BACKUP_SCHEDULER_RESTORE_DRILL_WEEKDAY",
            "fallback": "0"
          },
          "BACKUP_SCHEDULER_RETENTION_CRON": {
            "variable": "BACKUP_SCHEDULER_RETENTION_CRON",
            "fallback": "50 */8 * * *"
          },
          "BACKUP_SIGNING_KEYS_FILE": {
            "literal": "/infra/secrets/backup_signing_keys.txt"
          },
          "DOCKER_API_VERSION": {
            "literal": "1.51"
          },
          "DOCKER_HOST": {
            "literal": "tcp://docker-socket-proxy:2375"
          },
          "KEYCLOAK_DB_NAME": {
            "variable": "KEYCLOAK_DB_NAME",
            "fallback": "keycloak"
          },
          "NODE_IMAGE": {
            "variable": "NODE_IMAGE",
            "fallback": "node:26.3.1-alpine@sha256:a2dc166a387cc6ca1e62d0c8e265e49ca985d6e60abc9fe6e6c3d6ce8e63f606"
          },
          "PLATFORM_INFRA_CONTAINER_ROOT": {
            "literal": "/infra"
          },
          "PLATFORM_INFRA_HOST_ROOT": {
            "variable": "PLATFORM_INFRA_HOST_ROOT",
            "fallback": ""
          },
          "PLATFORM_INFRA_ROOT": {
            "literal": "/infra"
          },
          "PROJECT_DATABASES_FILE": {
            "literal": "/var/www/project-state/databases.json"
          },
          "PROJECT_SOURCE_HOST_ROOT": {
            "variable": "PROJECT_SOURCE_HOST_ROOT",
            "fallback": ""
          },
          "PROJECT_SOURCE_ROOT": {
            "literal": "/project"
          },
          "PROJECT_STATE_ROOT": {
            "literal": "/var/www/project-state"
          },
          "RCLONE_CONFIG": {
            "variable": "RCLONE_CONFIG",
            "fallback": "/infra/secrets/rclone/rclone.conf"
          },
          "RESTIC_HOSTNAME": {
            "variable": "RESTIC_HOSTNAME",
            "fallback": "platform-infrastructure"
          },
          "RESTIC_IMAGE": {
            "variable": "RESTIC_IMAGE",
            "fallback": ""
          },
          "RESTIC_KEEP_LAST": {
            "variable": "RESTIC_KEEP_LAST",
            "fallback": "42"
          },
          "RESTIC_MAX_REPOSITORY_BYTES": {
            "variable": "RESTIC_MAX_REPOSITORY_BYTES",
            "fallback": "2500000000000"
          },
          "RESTIC_PASSWORD_FILE": {
            "variable": "RESTIC_PASSWORD_FILE",
            "fallback": "/infra/secrets/restic_password.txt"
          },
          "RESTIC_REPOSITORY": {
            "variable": "RESTIC_REPOSITORY",
            "fallback": ""
          },
          "RESTIC_REQUIRE_IMMUTABLE_IMAGE": {
            "variable": "RESTIC_REQUIRE_IMMUTABLE_IMAGE",
            "fallback": "true"
          }
        }
      },
      "cadvisor": {
        "present": false,
        "entries": {}
      },
      "control-center": {
        "present": true,
        "entries": {
          "ADMIN_HOST": {
            "variable": "ADMIN_HOST",
            "fallback": "portal.${DOMAIN:-localhost.com}",
            "template": "${ADMIN_HOST:-portal.${DOMAIN:-localhost.com}}"
          },
          "CONTROL_CENTER_AUTH_DATABASE_URL_FILE": {
            "literal": "/run/secrets/control_center_database_url"
          },
          "CONTROL_CENTER_AUTH_MODE": {
            "literal": "oidc-passkey"
          },
          "CONTROL_CENTER_AUTH_STORE": {
            "literal": "postgres"
          },
          "CONTROL_CENTER_BIND_HOST": {
            "literal": "0.0.0.0"
          },
          "CONTROL_CENTER_DATABASE_DELETE_EVIDENCE_MAX_AGE_SECONDS": {
            "variable": "CONTROL_CENTER_DATABASE_DELETE_EVIDENCE_MAX_AGE_SECONDS",
            "fallback": "86400"
          },
          "CONTROL_CENTER_DATABASE_LIVE_APPLY": {
            "variable": "CONTROL_CENTER_DATABASE_LIVE_APPLY",
            "fallback": "true"
          },
          "CONTROL_CENTER_DISCOVER_HOSTED_PROJECTS": {
            "literal": "true"
          },
          "CONTROL_CENTER_DOCKER_STATS_MAX_AGE_SECONDS": {
            "variable": "CONTROL_CENTER_DOCKER_STATS_MAX_AGE_SECONDS",
            "fallback": "15"
          },
          "CONTROL_CENTER_DOCS_ROOT": {
            "literal": "/var/www/infra-docs"
          },
          "CONTROL_CENTER_ENV": {
            "variable": "CONTROL_CENTER_ENV",
            "fallback": "local"
          },
          "CONTROL_CENTER_EXISTING_SECRETS_DIR": {
            "literal": "/var/www/infra-docs/secrets"
          },
          "CONTROL_CENTER_FRESH_AUTH_SECONDS": {
            "variable": "CONTROL_CENTER_FRESH_AUTH_SECONDS",
            "fallback": "300"
          },
          "CONTROL_CENTER_HOST": {
            "variable": "CONTROL_CENTER_HOST",
            "fallback": "${ADMIN_HOST:-portal.${DOMAIN:-localhost.com}}",
            "template": "${CONTROL_CENTER_HOST:-${ADMIN_HOST:-portal.${DOMAIN:-localhost.com}}}"
          },
          "CONTROL_CENTER_LOGIN_LOCK_SECONDS": {
            "variable": "CONTROL_CENTER_LOGIN_LOCK_SECONDS",
            "fallback": "60"
          },
          "CONTROL_CENTER_LOGIN_MAX_ATTEMPTS": {
            "variable": "CONTROL_CENTER_LOGIN_MAX_ATTEMPTS",
            "fallback": "20"
          },
          "CONTROL_CENTER_LOGIN_WINDOW_SECONDS": {
            "variable": "CONTROL_CENTER_LOGIN_WINDOW_SECONDS",
            "fallback": "60"
          },
          "CONTROL_CENTER_MARIADB_HOST": {
            "variable": "CONTROL_CENTER_MARIADB_HOST",
            "fallback": "mariadb"
          },
          "CONTROL_CENTER_MARIADB_PORT": {
            "variable": "CONTROL_CENTER_MARIADB_PORT",
            "fallback": "3306"
          },
          "CONTROL_CENTER_MARIADB_ROOT_PASSWORD_FILE": {
            "literal": "/run/secrets/mariadb_root_password"
          },
          "CONTROL_CENTER_MARIADB_ROOT_USER": {
            "variable": "CONTROL_CENTER_MARIADB_ROOT_USER",
            "fallback": "root"
          },
          "CONTROL_CENTER_OIDC_ADMIN_ROLE": {
            "variable": "CONTROL_CENTER_OIDC_ADMIN_ROLE",
            "fallback": "admin"
          },
          "CONTROL_CENTER_OIDC_AUTHORIZATION_ENDPOINT": {
            "variable": "CONTROL_CENTER_OIDC_AUTHORIZATION_ENDPOINT",
            "fallback": "https://${AUTH_HOST:-auth.${DOMAIN:-localhost.com}}/realms/platform/protocol/openid-connect/auth",
            "template": "${CONTROL_CENTER_OIDC_AUTHORIZATION_ENDPOINT:-https://${AUTH_HOST:-auth.${DOMAIN:-localhost.com}}/realms/platform/protocol/openid-connect/auth}"
          },
          "CONTROL_CENTER_OIDC_CLIENT_ID": {
            "variable": "CONTROL_CENTER_OIDC_CLIENT_ID",
            "fallback": "platform-control-center"
          },
          "CONTROL_CENTER_OIDC_ISSUER": {
            "variable": "CONTROL_CENTER_OIDC_ISSUER",
            "fallback": "https://${AUTH_HOST:-auth.${DOMAIN:-localhost.com}}/realms/platform",
            "template": "${CONTROL_CENTER_OIDC_ISSUER:-https://${AUTH_HOST:-auth.${DOMAIN:-localhost.com}}/realms/platform}"
          },
          "CONTROL_CENTER_OIDC_JWKS_URI": {
            "variable": "CONTROL_CENTER_OIDC_JWKS_URI",
            "fallback": "http://keycloak:8080/realms/platform/protocol/openid-connect/certs"
          },
          "CONTROL_CENTER_OIDC_OWNER_ROLE": {
            "variable": "CONTROL_CENTER_OIDC_OWNER_ROLE",
            "fallback": "owner"
          },
          "CONTROL_CENTER_OIDC_REDIRECT_URI": {
            "variable": "CONTROL_CENTER_OIDC_REDIRECT_URI",
            "fallback": "https://${CONTROL_CENTER_HOST:-${ADMIN_HOST:-portal.${DOMAIN:-localhost.com}}}/auth/callback",
            "template": "${CONTROL_CENTER_OIDC_REDIRECT_URI:-https://${CONTROL_CENTER_HOST:-${ADMIN_HOST:-portal.${DOMAIN:-localhost.com}}}/auth/callback}"
          },
          "CONTROL_CENTER_OIDC_REQUIRED_ACR": {
            "variable": "CONTROL_CENTER_OIDC_REQUIRED_ACR",
            "fallback": "urn:platform:loa:passkey"
          },
          "CONTROL_CENTER_OIDC_REQUIRED_AMR": {
            "variable": "CONTROL_CENTER_OIDC_REQUIRED_AMR",
            "fallback": "webauthn"
          },
          "CONTROL_CENTER_OIDC_TOKEN_ENDPOINT": {
            "variable": "CONTROL_CENTER_OIDC_TOKEN_ENDPOINT",
            "fallback": "http://keycloak:8080/realms/platform/protocol/openid-connect/token"
          },
          "CONTROL_CENTER_OIDC_VIEWER_ROLE": {
            "variable": "CONTROL_CENTER_OIDC_VIEWER_ROLE",
            "fallback": "viewer"
          },
          "CONTROL_CENTER_PHPPGADMIN_INTERNAL_URL": {
            "variable": "CONTROL_CENTER_PHPPGADMIN_INTERNAL_URL",
            "fallback": "http://phppgadmin:80"
          },
          "CONTROL_CENTER_PORT": {
            "literal": "8080"
          },
          "CONTROL_CENTER_POSTGRES_HOST": {
            "variable": "CONTROL_CENTER_POSTGRES_HOST",
            "fallback": "postgres"
          },
          "CONTROL_CENTER_POSTGRES_PORT": {
            "variable": "CONTROL_CENTER_POSTGRES_PORT",
            "fallback": "5432"
          },
          "CONTROL_CENTER_POSTGRES_SUPERUSER": {
            "variable": "POSTGRES_SUPERUSER",
            "fallback": "postgres"
          },
          "CONTROL_CENTER_POSTGRES_SUPERUSER_PASSWORD_FILE": {
            "literal": "/run/secrets/postgres_superuser_password"
          },
          "CONTROL_CENTER_PUBLIC_ORIGIN": {
            "variable": "CONTROL_CENTER_PUBLIC_ORIGIN",
            "fallback": "https://${CONTROL_CENTER_HOST:-${ADMIN_HOST:-portal.${DOMAIN:-localhost.com}}}",
            "template": "${CONTROL_CENTER_PUBLIC_ORIGIN:-https://${CONTROL_CENTER_HOST:-${ADMIN_HOST:-portal.${DOMAIN:-localhost.com}}}}"
          },
          "CONTROL_CENTER_PUBLIC_ROOT": {
            "literal": "/app/public"
          },
          "CONTROL_CENTER_REPORTS_ROOT": {
            "literal": "/var/www/infra-docs/reports"
          },
          "CONTROL_CENTER_SESSION_IDLE_SECONDS": {
            "variable": "CONTROL_CENTER_SESSION_IDLE_SECONDS",
            "fallback": "1800"
          },
          "CONTROL_CENTER_SESSION_MAX_AGE_SECONDS": {
            "variable": "CONTROL_CENTER_SESSION_MAX_AGE_SECONDS",
            "fallback": "28800"
          },
          "CONTROL_CENTER_SESSION_POLICY_VERSION": {
            "variable": "CONTROL_CENTER_SESSION_POLICY_VERSION",
            "fallback": "1"
          },
          "CONTROL_CENTER_STATUS_CHECK_TIMEOUT_MS": {
            "variable": "CONTROL_CENTER_STATUS_CHECK_TIMEOUT_MS",
            "fallback": "30000"
          },
          "CONTROL_CENTER_STATUS_STEP_DELAY_MS": {
            "variable": "CONTROL_CENTER_STATUS_STEP_DELAY_MS",
            "fallback": "1500"
          },
          "CONTROL_CENTER_VAULT_ACTIVE_KEY_ID": {
            "variable": "CONTROL_CENTER_VAULT_ACTIVE_KEY_ID",
            "fallback": ""
          },
          "CONTROL_CENTER_VAULT_KEY_FILE": {
            "literal": "/run/secrets/control_center_vault_keys"
          },
          "CONTROL_CENTER_VAULT_LEGACY_KEY_FILE": {
            "literal": "/run/secrets/projects_gateway_signing_keys"
          },
          "DOCS_HOST": {
            "variable": "DOCS_HOST",
            "fallback": "docs.${DOMAIN:-localhost.com}",
            "template": "${DOCS_HOST:-docs.${DOMAIN:-localhost.com}}"
          },
          "DOMAIN": {
            "variable": "DOMAIN",
            "fallback": "localhost.com"
          },
          "LOCAL_DOMAIN": {
            "variable": "LOCAL_DOMAIN",
            "fallback": "localhost.com"
          },
          "NODE_PROJECT_HOSTS": {
            "variable": "NODE_PROJECT_HOSTS",
            "fallback": ""
          },
          "PLATFORM_NAME": {
            "variable": "PLATFORM_NAME",
            "fallback": "Platform Infrastructure"
          },
          "PROJECTS_HOST": {
            "variable": "PROJECTS_HOST",
            "fallback": ""
          },
          "PROJECTS_ROOT": {
            "literal": "/var/www/projects"
          },
          "PROJECT_ALERTS_FILE": {
            "literal": "/var/www/project-state/alerts.json"
          },
          "PROJECT_APPLICATIONS_FILE": {
            "literal": "/var/www/project-state/applications.json"
          },
          "PROJECT_AUDIT_FILE": {
            "literal": "/var/www/project-state/audit.jsonl"
          },
          "PROJECT_BACKUP_RECORDS_FILE": {
            "literal": "/var/www/project-state/backups.jsonl"
          },
          "PROJECT_DATABASES_FILE": {
            "literal": "/var/www/project-state/databases.json"
          },
          "PROJECT_DATABASE_DESTRUCTIVE_OPERATIONS_FILE": {
            "literal": "/var/www/project-state/database-destructive-operations.json"
          },
          "PROJECT_DATABASE_PRINCIPALS_FILE": {
            "literal": "/var/www/project-state/database-principals.json"
          },
          "PROJECT_DEPLOYMENTS_FILE": {
            "literal": "/var/www/project-state/deployments.jsonl"
          },
          "PROJECT_DOCKER_STATS_FILE": {
            "literal": "/var/www/project-state/docker-stats.json"
          },
          "PROJECT_DOMAINS_FILE": {
            "literal": "/var/www/project-state/domains.json"
          },
          "PROJECT_HOST_SUFFIX": {
            "variable": "PROJECT_HOST_SUFFIX",
            "fallback": ".localhost.com"
          },
          "PROJECT_IDENTITY_ACCESS_FILE": {
            "literal": "/var/www/project-state/identity-access.json"
          },
          "PROJECT_NAME": {
            "variable": "PROJECT_NAME",
            "fallback": "platform"
          },
          "PROJECT_NOTIFICATION_CHANNELS_FILE": {
            "literal": "/var/www/project-state/notification-channels.json"
          },
          "PROJECT_OPERATIONS_FILE": {
            "literal": "/var/www/project-state/operations.jsonl"
          },
          "PROJECT_PROVIDER_CONNECTIONS_FILE": {
            "literal": "/var/www/project-state/provider-connections.json"
          },
          "PROJECT_RESOURCE_LIMITS_FILE": {
            "literal": "/var/www/project-state/resource-limits.json"
          },
          "PROJECT_SECURITY_POLICIES_FILE": {
            "literal": "/var/www/project-state/security-policies.json"
          },
          "PROJECT_SENSITIVE_MATERIALS_FILE": {
            "literal": "/var/www/project-state/sensitive-materials.json"
          },
          "PROJECT_SETTINGS_FILE": {
            "literal": "/var/www/project-state/settings.json"
          },
          "PROJECT_STATE_FILE": {
            "literal": "/var/www/project-state/projects.json"
          },
          "PROJECT_STATUS_RUNS_FILE": {
            "literal": "/var/www/project-state/status-runs.jsonl"
          },
          "PROJECT_STATUS_RUN_EVENTS_FILE": {
            "literal": "/var/www/project-state/status-run-events.jsonl"
          },
          "PROJECT_STORAGE_BUCKETS_FILE": {
            "literal": "/var/www/project-state/storage-buckets.json"
          },
          "PROJECT_VAULT_FILE": {
            "literal": "/var/www/project-state/secret-vault.json"
          },
          "PROJECT_WEBSPACES_FILE": {
            "literal": "/var/www/project-state/webspaces.json"
          },
          "PROJECT_WORKER_JOBS_FILE": {
            "literal": "/var/www/project-state/worker-jobs.json"
          },
          "PROVIDER_PROFILE": {
            "variable": "PROVIDER_PROFILE",
            "fallback": "local"
          }
        }
      },
      "docker-socket-proxy": {
        "present": true,
        "entries": {
          "ALLOW_RESTARTS": {
            "literal": "1"
          },
          "ALLOW_START": {
            "literal": "1"
          },
          "ALLOW_STOP": {
            "literal": "1"
          },
          "AUTH": {
            "literal": "0"
          },
          "BUILD": {
            "literal": "0"
          },
          "COMMIT": {
            "literal": "0"
          },
          "CONFIGS": {
            "literal": "0"
          },
          "CONTAINERS": {
            "literal": "1"
          },
          "DISTRIBUTION": {
            "literal": "0"
          },
          "EVENTS": {
            "literal": "1"
          },
          "EXEC": {
            "literal": "1"
          },
          "GRPC": {
            "literal": "0"
          },
          "IMAGES": {
            "literal": "1"
          },
          "INFO": {
            "literal": "1"
          },
          "NETWORKS": {
            "literal": "1"
          },
          "NODES": {
            "literal": "0"
          },
          "PLUGINS": {
            "literal": "0"
          },
          "POST": {
            "literal": "1"
          },
          "SECRETS": {
            "literal": "0"
          },
          "SERVICES": {
            "literal": "0"
          },
          "SESSION": {
            "literal": "0"
          },
          "SWARM": {
            "literal": "0"
          },
          "SYSTEM": {
            "literal": "0"
          },
          "TASKS": {
            "literal": "0"
          },
          "VOLUMES": {
            "literal": "1"
          }
        }
      },
      "grafana": {
        "present": true,
        "entries": {
          "GF_ANALYTICS_CHECK_FOR_UPDATES": {
            "literal": "false"
          },
          "GF_ANALYTICS_REPORTING_ENABLED": {
            "literal": "false"
          },
          "GF_LOG_LEVEL": {
            "literal": "info"
          },
          "GF_LOG_MODE": {
            "literal": "console"
          },
          "GF_PLUGINS_PREINSTALL_DISABLED": {
            "literal": "true"
          },
          "GF_SECURITY_ADMIN_PASSWORD__FILE": {
            "literal": "/run/secrets/grafana_admin_password"
          },
          "GF_SECURITY_ADMIN_USER": {
            "variable": "GRAFANA_ADMIN_USER",
            "fallback": "admin"
          },
          "GF_SECURITY_COOKIE_SAMESITE": {
            "literal": "strict"
          },
          "GF_SERVER_ROOT_URL": {
            "variable": "GRAFANA_ROOT_URL",
            "fallback": "https://grafana.localhost.com"
          },
          "GF_USERS_ALLOW_SIGN_UP": {
            "literal": "false"
          }
        }
      },
      "keycloak": {
        "present": true,
        "entries": {
          "KC_BOOTSTRAP_ADMIN_PASSWORD_FILE": {
            "literal": "/run/secrets/keycloak_admin_password"
          },
          "KC_BOOTSTRAP_ADMIN_USERNAME": {
            "variable": "KEYCLOAK_ADMIN",
            "fallback": "admin"
          },
          "KC_DB": {
            "literal": "postgres"
          },
          "KC_DB_PASSWORD_FILE": {
            "literal": "/run/secrets/keycloak_db_password"
          },
          "KC_DB_URL": {
            "variable": "KEYCLOAK_DB_NAME",
            "fallback": "keycloak",
            "template": "jdbc:postgresql://postgres:5432/${KEYCLOAK_DB_NAME:-keycloak}"
          },
          "KC_DB_USERNAME": {
            "variable": "KEYCLOAK_DB_USER",
            "fallback": "keycloak"
          },
          "KC_EVENT_METRICS_USER_ENABLED": {
            "literal": "true"
          },
          "KC_EVENT_METRICS_USER_EVENTS": {
            "literal": "login,logout,user_disabled_by_temporary_lockout,user_disabled_by_permanent_lockout,update_credential,remove_credential"
          },
          "KC_EVENT_METRICS_USER_TAGS": {
            "literal": "realm,clientId"
          },
          "KC_HEALTH_ENABLED": {
            "literal": "true"
          },
          "KC_HOSTNAME": {
            "variable": "AUTH_HOST",
            "fallback": "keycloak.local"
          },
          "KC_HOSTNAME_STRICT": {
            "literal": "true"
          },
          "KC_HTTP_ENABLED": {
            "literal": "true"
          },
          "KC_METRICS_ENABLED": {
            "literal": "true"
          },
          "KC_PROXY_HEADERS": {
            "literal": "xforwarded"
          }
        }
      },
      "local-dns": {
        "present": false,
        "entries": {}
      },
      "local-registry": {
        "present": false,
        "entries": {}
      },
      "loki": {
        "present": false,
        "entries": {}
      },
      "mariadb": {
        "present": true,
        "entries": {
          "MARIADB_ROOT_PASSWORD_FILE": {
            "literal": "/run/secrets/mariadb_root_password"
          }
        }
      },
      "minio": {
        "present": true,
        "entries": {
          "MINIO_BROWSER_REDIRECT_URL": {
            "variable": "MINIO_BROWSER_REDIRECT_URL",
            "fallback": "https://minio.localhost.com"
          },
          "MINIO_ROOT_PASSWORD_FILE": {
            "literal": "/run/secrets/minio_root_password"
          },
          "MINIO_ROOT_USER": {
            "variable": "MINIO_ROOT_USER",
            "fallback": "minio_admin"
          },
          "MINIO_SERVER_URL": {
            "variable": "MINIO_SERVER_URL",
            "fallback": "http://localhost:9000"
          }
        }
      },
      "nats": {
        "present": true,
        "entries": {
          "NATS_PASSWORD_FILE": {
            "literal": "/run/secrets/nats_password"
          },
          "NATS_USER": {
            "variable": "NATS_USER",
            "fallback": "enterprise"
          }
        }
      },
      "node-exporter": {
        "present": false,
        "entries": {}
      },
      "phpmyadmin": {
        "present": true,
        "entries": {
          "PMA_CONTROL_PASSWORD_FILE": {
            "literal": "/run/secrets/phpmyadmin_control_password"
          },
          "PMA_HOST": {
            "literal": "platform.local"
          },
          "PMA_PORT": {
            "literal": "3306"
          },
          "PMA_SSL_CA": {
            "literal": "/etc/phpmyadmin/certs/ca.pem"
          },
          "PMA_SSL_VERIFIES": {
            "literal": "1"
          },
          "UPLOAD_LIMIT": {
            "literal": "256M"
          }
        }
      },
      "phppgadmin": {
        "present": true,
        "entries": {
          "PHPPGADMIN_HOST": {
            "variable": "CONTROL_CENTER_POSTGRES_HOST",
            "fallback": "postgres"
          },
          "PHPPGADMIN_PORT": {
            "variable": "CONTROL_CENTER_POSTGRES_PORT",
            "fallback": "5432"
          }
        }
      },
      "platform-alert-dispatcher": {
        "present": true,
        "entries": {
          "ALERTMANAGER_WEBHOOK_TOKEN_FILE": {
            "literal": "/run/secrets/alertmanager_webhook_token"
          },
          "ALERT_EMAIL_TO": {
            "variable": "ALERT_EMAIL_TO",
            "required": "Set ALERT_EMAIL_TO"
          },
          "ALERT_FORWARD_WEBHOOK_URL_FILE": {
            "variable": "ALERT_FORWARD_WEBHOOK_URL_FILE",
            "fallback": ""
          },
          "MAILER_FROM": {
            "variable": "MAILER_FROM",
            "required": "Set MAILER_FROM"
          },
          "MAILER_REPLY_TO": {
            "variable": "MAILER_REPLY_TO",
            "required": "Set MAILER_REPLY_TO"
          },
          "PORT": {
            "literal": "3000"
          },
          "SMTP_HOST": {
            "variable": "SMTP_HOST",
            "required": "Set SMTP_HOST"
          },
          "SMTP_PASSWORD_FILE": {
            "literal": "/run/secrets/smtp_password"
          },
          "SMTP_PORT": {
            "variable": "SMTP_PORT",
            "fallback": "465"
          },
          "SMTP_SECURE": {
            "variable": "SMTP_SECURE",
            "fallback": "true"
          },
          "SMTP_USER": {
            "variable": "SMTP_USER",
            "required": "Set SMTP_USER"
          }
        }
      },
      "postgres": {
        "present": true,
        "entries": {
          "KEYCLOAK_DB_NAME": {
            "variable": "KEYCLOAK_DB_NAME",
            "fallback": "keycloak"
          },
          "KEYCLOAK_DB_PASSWORD_FILE": {
            "literal": "/run/secrets/keycloak_db_password"
          },
          "KEYCLOAK_DB_USER": {
            "variable": "KEYCLOAK_DB_USER",
            "fallback": "keycloak"
          },
          "POSTGRES_DB": {
            "literal": "postgres"
          },
          "POSTGRES_PASSWORD_FILE": {
            "literal": "/run/secrets/postgres_superuser_password"
          },
          "POSTGRES_USER": {
            "variable": "POSTGRES_SUPERUSER",
            "fallback": "postgres"
          }
        }
      },
      "project-router": {
        "present": true,
        "entries": {
          "ADMIN_HOST": {
            "variable": "ADMIN_HOST",
            "fallback": "portal.${DOMAIN:-localhost.com}",
            "template": "${ADMIN_HOST:-portal.${DOMAIN:-localhost.com}}"
          },
          "CONTROL_CENTER_HOST": {
            "variable": "CONTROL_CENTER_HOST",
            "fallback": "${ADMIN_HOST:-portal.${DOMAIN:-localhost.com}}",
            "template": "${CONTROL_CENTER_HOST:-${ADMIN_HOST:-portal.${DOMAIN:-localhost.com}}}"
          },
          "CONTROL_CENTER_UPSTREAM": {
            "literal": "http://control-center:8080"
          },
          "NODE_PROJECT_HOSTS": {
            "variable": "NODE_PROJECT_HOSTS",
            "fallback": ""
          },
          "NODE_PROJECT_UPSTREAMS": {
            "variable": "NODE_PROJECT_UPSTREAMS",
            "fallback": ""
          },
          "PHP_PROJECT_UPSTREAMS": {
            "variable": "PHP_PROJECT_UPSTREAMS",
            "fallback": ""
          },
          "PROJECTS_HOST": {
            "variable": "PROJECTS_HOST",
            "fallback": ""
          },
          "PROJECTS_ROOT": {
            "literal": "/var/www/projects"
          },
          "PROJECT_HOST_SUFFIX": {
            "variable": "PROJECT_HOST_SUFFIX",
            "fallback": ".localhost.com"
          },
          "PROJECT_ROUTER_ALLOWED_UPSTREAMS": {
            "variable": "PROJECT_ROUTER_ALLOWED_UPSTREAMS",
            "fallback": "control-center:8080"
          },
          "PROJECT_ROUTER_PORT": {
            "literal": "8080"
          },
          "PROJECT_ROUTER_WORKLOAD_LOCK_FILE": {
            "literal": "/run/platform/hosted-workloads.lock.json"
          },
          "PROJECT_STATE_FILE": {
            "literal": "/var/www/project-state/projects.json"
          },
          "PROJECT_UPSTREAMS": {
            "variable": "PROJECT_UPSTREAMS",
            "fallback": ""
          },
          "STATIC_PROJECT_UPSTREAMS": {
            "variable": "STATIC_PROJECT_UPSTREAMS",
            "fallback": ""
          }
        }
      },
      "prometheus": {
        "present": false,
        "entries": {}
      },
      "promtail": {
        "present": false,
        "entries": {}
      },
      "redis": {
        "present": true,
        "entries": {
          "REDIS_PASSWORD_FILE": {
            "literal": "/run/secrets/redis_password"
          }
        }
      },
      "traefik": {
        "present": false,
        "entries": {}
      },
      "waf": {
        "present": true,
        "entries": {
          "ACCESSLOG": {
            "literal": "/dev/stdout"
          },
          "ALLOWED_HTTP_VERSIONS": {
            "variable": "WAF_ALLOWED_HTTP_VERSIONS",
            "fallback": "HTTP/1.1 HTTP/2 HTTP/2.0"
          },
          "ALLOWED_METHODS": {
            "variable": "WAF_ALLOWED_METHODS",
            "fallback": "GET HEAD POST OPTIONS PUT PATCH DELETE"
          },
          "ANOMALY_INBOUND": {
            "variable": "WAF_ANOMALY_INBOUND",
            "fallback": "5"
          },
          "ANOMALY_OUTBOUND": {
            "variable": "WAF_ANOMALY_OUTBOUND",
            "fallback": "4"
          },
          "ARG_LENGTH": {
            "variable": "WAF_ARG_LENGTH",
            "fallback": "4096"
          },
          "ARG_NAME_LENGTH": {
            "variable": "WAF_ARG_NAME_LENGTH",
            "fallback": "100"
          },
          "BACKEND": {
            "variable": "WAF_BACKEND",
            "fallback": "http://traefik:80"
          },
          "BLOCKING_PARANOIA": {
            "variable": "WAF_BLOCKING_PARANOIA",
            "fallback": "2"
          },
          "COMBINED_FILE_SIZES": {
            "variable": "WAF_COMBINED_FILE_SIZES",
            "fallback": "26214400"
          },
          "CORS_HEADER_ACCESS_CONTROL_ALLOW_HEADERS": {
            "variable": "WAF_CORS_ALLOW_HEADERS",
            "fallback": "accept,authorization,content-type,x-request-id,x-platform-csrf,x-platform-session-client"
          },
          "DETECTION_PARANOIA": {
            "variable": "WAF_DETECTION_PARANOIA",
            "fallback": "2"
          },
          "ENFORCE_BODYPROC_URLENCODED": {
            "literal": "1"
          },
          "ERRORLOG": {
            "literal": "/dev/stderr"
          },
          "LOGLEVEL": {
            "variable": "WAF_LOGLEVEL",
            "fallback": "warn"
          },
          "MAX_FILE_SIZE": {
            "variable": "WAF_MAX_FILE_SIZE",
            "fallback": "10485760"
          },
          "MAX_NUM_ARGS": {
            "variable": "WAF_MAX_NUM_ARGS",
            "fallback": "256"
          },
          "MODSEC_AUDIT_ENGINE": {
            "variable": "WAF_MODSEC_AUDIT_ENGINE",
            "fallback": "RelevantOnly"
          },
          "MODSEC_AUDIT_LOG": {
            "literal": "/dev/stdout"
          },
          "MODSEC_AUDIT_LOG_FORMAT": {
            "literal": "JSON"
          },
          "MODSEC_AUDIT_LOG_PARTS": {
            "variable": "WAF_MODSEC_AUDIT_LOG_PARTS",
            "fallback": "ABIJFHZ"
          },
          "MODSEC_PCRE_MATCH_LIMIT": {
            "variable": "WAF_MODSEC_PCRE_MATCH_LIMIT",
            "fallback": "10000"
          },
          "MODSEC_PCRE_MATCH_LIMIT_RECURSION": {
            "variable": "WAF_MODSEC_PCRE_MATCH_LIMIT_RECURSION",
            "fallback": "10000"
          },
          "MODSEC_REQ_BODY_ACCESS": {
            "literal": "On"
          },
          "MODSEC_REQ_BODY_JSON_DEPTH_LIMIT": {
            "variable": "WAF_MODSEC_REQ_BODY_JSON_DEPTH_LIMIT",
            "fallback": "128"
          },
          "MODSEC_REQ_BODY_LIMIT": {
            "variable": "WAF_MODSEC_REQ_BODY_LIMIT",
            "fallback": "13107200"
          },
          "MODSEC_REQ_BODY_NOFILES_LIMIT": {
            "variable": "WAF_MODSEC_REQ_BODY_NOFILES_LIMIT",
            "fallback": "262144"
          },
          "MODSEC_RESP_BODY_ACCESS": {
            "variable": "WAF_MODSEC_RESP_BODY_ACCESS",
            "fallback": "Off"
          },
          "MODSEC_RULE_ENGINE": {
            "variable": "WAF_MODSEC_RULE_ENGINE",
            "fallback": "On"
          },
          "NGINX_ALWAYS_TLS_REDIRECT": {
            "variable": "WAF_NGINX_ALWAYS_TLS_REDIRECT",
            "fallback": "on"
          },
          "NGINX_PORT_IN_REDIRECT": {
            "literal": "off"
          },
          "NGINX_X_FORWARDED_PROTO": {
            "variable": "WAF_X_FORWARDED_PROTO",
            "fallback": "https"
          },
          "PORT": {
            "literal": "8080"
          },
          "PROXY_SSL_VERIFY": {
            "literal": "off"
          },
          "PROXY_TIMEOUT": {
            "variable": "WAF_PROXY_TIMEOUT",
            "fallback": "60s"
          },
          "REPORTING_LEVEL": {
            "variable": "WAF_REPORTING_LEVEL",
            "fallback": "4"
          },
          "RESTRICTED_EXTENSIONS": {
            "variable": "WAF_RESTRICTED_EXTENSIONS",
            "fallback": ".asa/ .asax/ .ascx/ .backup/ .bak/ .bat/ .cdx/ .cer/ .cfg/ .cmd/ .com/ .config/ .conf/ .cs/ .csproj/ .dat/ .db/ .dll/ .dos/ .htr/ .htw/ .ida/ .idc/ .idq/ .inc/ .ini/ .key/ .licx/ .log/ .old/ .pass/ .pdb/ .pol/ .printer/ .pwd/ .resources/ .resx/ .sql/ .swp/ .sys/ .vb/ .vbs/ .vbproj/ .vsdisco/ .webinfo/"
          },
          "RESTRICTED_HEADERS": {
            "variable": "WAF_RESTRICTED_HEADERS",
            "fallback": "/proxy/ /if/ /lock-token/ /content-range/ /translate/ /via/"
          },
          "SERVER_NAME": {
            "variable": "WAF_SERVER_NAME",
            "fallback": "localhost"
          },
          "SERVER_TOKENS": {
            "literal": "off"
          },
          "SSL_CERT_FILE": {
            "literal": "/etc/nginx/conf/server.crt"
          },
          "SSL_CERT_KEY_FILE": {
            "literal": "/etc/nginx/conf/server.key"
          },
          "SSL_PORT": {
            "literal": "8443"
          },
          "TOTAL_ARG_LENGTH": {
            "variable": "WAF_TOTAL_ARG_LENGTH",
            "fallback": "32768"
          },
          "VALIDATE_UTF8_ENCODING": {
            "literal": "1"
          }
        }
      }
    },
    "counts": {
      "services": 24,
      "total": 258,
      "literals": 128,
      "projections": 130,
      "required": 5,
      "templates": 10,
      "perService": [
        {
          "service": "alertmanager",
          "count": 0,
          "present": false
        },
        {
          "service": "backup-scheduler",
          "count": 31,
          "present": true
        },
        {
          "service": "cadvisor",
          "count": 0,
          "present": false
        },
        {
          "service": "control-center",
          "count": 84,
          "present": true
        },
        {
          "service": "docker-socket-proxy",
          "count": 25,
          "present": true
        },
        {
          "service": "grafana",
          "count": 10,
          "present": true
        },
        {
          "service": "keycloak",
          "count": 15,
          "present": true
        },
        {
          "service": "local-dns",
          "count": 0,
          "present": false
        },
        {
          "service": "local-registry",
          "count": 0,
          "present": false
        },
        {
          "service": "loki",
          "count": 0,
          "present": false
        },
        {
          "service": "mariadb",
          "count": 1,
          "present": true
        },
        {
          "service": "minio",
          "count": 4,
          "present": true
        },
        {
          "service": "nats",
          "count": 2,
          "present": true
        },
        {
          "service": "node-exporter",
          "count": 0,
          "present": false
        },
        {
          "service": "phpmyadmin",
          "count": 6,
          "present": true
        },
        {
          "service": "phppgadmin",
          "count": 2,
          "present": true
        },
        {
          "service": "platform-alert-dispatcher",
          "count": 11,
          "present": true
        },
        {
          "service": "postgres",
          "count": 6,
          "present": true
        },
        {
          "service": "project-router",
          "count": 15,
          "present": true
        },
        {
          "service": "prometheus",
          "count": 0,
          "present": false
        },
        {
          "service": "promtail",
          "count": 0,
          "present": false
        },
        {
          "service": "redis",
          "count": 1,
          "present": true
        },
        {
          "service": "traefik",
          "count": 0,
          "present": false
        },
        {
          "service": "waf",
          "count": 45,
          "present": true
        }
      ]
    }
  },
  exactAuthorityShape: {
    "serviceFields": {
      "traefik": [
        "blkio_config",
        "command",
        "configs",
        "container_name",
        "cpu_shares",
        "cpus",
        "healthcheck",
        "image",
        "init",
        "logging",
        "mem_limit",
        "mem_reservation",
        "networks",
        "pids_limit",
        "ports",
        "restart",
        "security_opt",
        "ulimits",
        "volumes"
      ],
      "postgres": [
        "blkio_config",
        "container_name",
        "cpu_shares",
        "cpus",
        "entrypoint",
        "environment",
        "healthcheck",
        "image",
        "init",
        "logging",
        "mem_limit",
        "mem_reservation",
        "networks",
        "pids_limit",
        "ports",
        "restart",
        "secrets",
        "security_opt",
        "ulimits",
        "volumes"
      ],
      "redis": [
        "blkio_config",
        "command",
        "container_name",
        "cpu_shares",
        "cpus",
        "environment",
        "healthcheck",
        "image",
        "init",
        "logging",
        "mem_limit",
        "mem_reservation",
        "networks",
        "pids_limit",
        "ports",
        "restart",
        "secrets",
        "security_opt",
        "ulimits",
        "volumes"
      ],
      "keycloak": [
        "blkio_config",
        "command",
        "container_name",
        "cpu_shares",
        "cpus",
        "depends_on",
        "entrypoint",
        "environment",
        "healthcheck",
        "image",
        "init",
        "labels",
        "logging",
        "mem_limit",
        "mem_reservation",
        "networks",
        "pids_limit",
        "ports",
        "restart",
        "secrets",
        "security_opt",
        "ulimits",
        "volumes"
      ],
      "nats": [
        "blkio_config",
        "container_name",
        "cpu_shares",
        "cpus",
        "entrypoint",
        "environment",
        "healthcheck",
        "image",
        "init",
        "logging",
        "mem_limit",
        "mem_reservation",
        "networks",
        "pids_limit",
        "ports",
        "restart",
        "secrets",
        "security_opt",
        "ulimits",
        "volumes"
      ],
      "minio": [
        "blkio_config",
        "command",
        "container_name",
        "cpu_shares",
        "cpus",
        "entrypoint",
        "environment",
        "healthcheck",
        "image",
        "init",
        "labels",
        "logging",
        "mem_limit",
        "mem_reservation",
        "networks",
        "pids_limit",
        "ports",
        "restart",
        "secrets",
        "security_opt",
        "ulimits",
        "volumes"
      ],
      "control-center": [
        "blkio_config",
        "build",
        "command",
        "container_name",
        "cpu_shares",
        "cpus",
        "depends_on",
        "environment",
        "expose",
        "healthcheck",
        "image",
        "init",
        "logging",
        "mem_limit",
        "mem_reservation",
        "networks",
        "pids_limit",
        "read_only",
        "restart",
        "secrets",
        "security_opt",
        "tmpfs",
        "ulimits",
        "volumes",
        "working_dir"
      ],
      "project-router": [
        "blkio_config",
        "command",
        "container_name",
        "cpu_shares",
        "cpus",
        "depends_on",
        "environment",
        "expose",
        "healthcheck",
        "image",
        "init",
        "logging",
        "mem_limit",
        "mem_reservation",
        "networks",
        "pids_limit",
        "read_only",
        "restart",
        "security_opt",
        "tmpfs",
        "ulimits",
        "volumes",
        "working_dir"
      ],
      "mariadb": [
        "blkio_config",
        "container_name",
        "cpu_shares",
        "cpus",
        "environment",
        "healthcheck",
        "image",
        "init",
        "logging",
        "mem_limit",
        "mem_reservation",
        "networks",
        "pids_limit",
        "ports",
        "restart",
        "secrets",
        "security_opt",
        "ulimits",
        "volumes"
      ],
      "phpmyadmin": [
        "blkio_config",
        "container_name",
        "cpu_shares",
        "cpus",
        "depends_on",
        "environment",
        "expose",
        "healthcheck",
        "image",
        "init",
        "labels",
        "logging",
        "mem_limit",
        "mem_reservation",
        "networks",
        "pids_limit",
        "restart",
        "secrets",
        "security_opt",
        "ulimits",
        "volumes"
      ],
      "phppgadmin": [
        "blkio_config",
        "container_name",
        "cpu_shares",
        "cpus",
        "depends_on",
        "environment",
        "expose",
        "healthcheck",
        "image",
        "init",
        "labels",
        "logging",
        "mem_limit",
        "mem_reservation",
        "networks",
        "pids_limit",
        "restart",
        "security_opt",
        "ulimits",
        "volumes"
      ],
      "local-dns": [
        "blkio_config",
        "command",
        "container_name",
        "cpu_shares",
        "cpus",
        "expose",
        "healthcheck",
        "image",
        "init",
        "logging",
        "mem_limit",
        "mem_reservation",
        "networks",
        "pids_limit",
        "ports",
        "restart",
        "security_opt",
        "ulimits",
        "volumes"
      ],
      "prometheus": [
        "blkio_config",
        "command",
        "container_name",
        "cpu_shares",
        "cpus",
        "depends_on",
        "healthcheck",
        "image",
        "init",
        "logging",
        "mem_limit",
        "mem_reservation",
        "networks",
        "pids_limit",
        "ports",
        "restart",
        "security_opt",
        "ulimits",
        "volumes"
      ],
      "node-exporter": [
        "blkio_config",
        "command",
        "container_name",
        "cpu_shares",
        "cpus",
        "healthcheck",
        "image",
        "init",
        "logging",
        "mem_limit",
        "mem_reservation",
        "networks",
        "pid",
        "pids_limit",
        "restart",
        "security_opt",
        "ulimits",
        "volumes"
      ],
      "cadvisor": [
        "blkio_config",
        "command",
        "container_name",
        "cpu_shares",
        "cpus",
        "healthcheck",
        "image",
        "init",
        "logging",
        "mem_limit",
        "mem_reservation",
        "networks",
        "pids_limit",
        "restart",
        "security_opt",
        "ulimits",
        "volumes"
      ],
      "platform-alert-dispatcher": [
        "blkio_config",
        "build",
        "cap_drop",
        "container_name",
        "cpu_shares",
        "cpus",
        "environment",
        "expose",
        "healthcheck",
        "image",
        "init",
        "logging",
        "mem_limit",
        "mem_reservation",
        "networks",
        "pids_limit",
        "read_only",
        "restart",
        "secrets",
        "security_opt",
        "tmpfs",
        "ulimits",
        "user"
      ],
      "alertmanager": [
        "blkio_config",
        "command",
        "container_name",
        "cpu_shares",
        "cpus",
        "depends_on",
        "group_add",
        "healthcheck",
        "image",
        "init",
        "logging",
        "mem_limit",
        "mem_reservation",
        "networks",
        "pids_limit",
        "ports",
        "restart",
        "secrets",
        "security_opt",
        "ulimits",
        "volumes"
      ],
      "grafana": [
        "blkio_config",
        "container_name",
        "cpu_shares",
        "cpus",
        "depends_on",
        "environment",
        "healthcheck",
        "image",
        "init",
        "labels",
        "logging",
        "mem_limit",
        "mem_reservation",
        "networks",
        "pids_limit",
        "ports",
        "restart",
        "secrets",
        "security_opt",
        "ulimits",
        "volumes"
      ],
      "loki": [
        "blkio_config",
        "command",
        "container_name",
        "cpu_shares",
        "cpus",
        "depends_on",
        "healthcheck",
        "image",
        "init",
        "logging",
        "mem_limit",
        "mem_reservation",
        "networks",
        "pids_limit",
        "ports",
        "restart",
        "security_opt",
        "ulimits",
        "volumes"
      ],
      "promtail": [
        "blkio_config",
        "command",
        "container_name",
        "cpu_shares",
        "cpus",
        "depends_on",
        "healthcheck",
        "image",
        "init",
        "logging",
        "mem_limit",
        "mem_reservation",
        "networks",
        "pids_limit",
        "restart",
        "security_opt",
        "ulimits",
        "volumes"
      ],
      "waf": [
        "blkio_config",
        "container_name",
        "cpu_shares",
        "cpus",
        "depends_on",
        "environment",
        "healthcheck",
        "image",
        "init",
        "logging",
        "mem_limit",
        "mem_reservation",
        "networks",
        "pids_limit",
        "ports",
        "restart",
        "security_opt",
        "ulimits",
        "volumes"
      ],
      "backup-scheduler": [
        "blkio_config",
        "build",
        "container_name",
        "cpu_shares",
        "cpus",
        "depends_on",
        "entrypoint",
        "environment",
        "healthcheck",
        "image",
        "init",
        "logging",
        "mem_limit",
        "mem_reservation",
        "networks",
        "pids_limit",
        "profiles",
        "read_only",
        "restart",
        "security_opt",
        "tmpfs",
        "ulimits",
        "volumes"
      ],
      "local-registry": [
        "blkio_config",
        "container_name",
        "cpu_shares",
        "cpus",
        "healthcheck",
        "image",
        "mem_limit",
        "mem_reservation",
        "network_mode",
        "pids_limit",
        "ports",
        "restart",
        "ulimits",
        "volumes"
      ],
      "docker-socket-proxy": [
        "blkio_config",
        "container_name",
        "cpu_shares",
        "cpus",
        "environment",
        "expose",
        "healthcheck",
        "image",
        "init",
        "mem_limit",
        "mem_reservation",
        "networks",
        "pids_limit",
        "ports",
        "read_only",
        "restart",
        "security_opt",
        "ulimits",
        "volumes"
      ]
    },
    "serviceResources": {
      "traefik": {
        "init": true,
        "pids_limit": 192,
        "cpu_shares": 1024,
        "ulimits": {
          "nofile": {
            "soft": 16384,
            "hard": 16384
          }
        },
        "blkio_config": {
          "weight": 700
        },
        "cpus": 0.5,
        "mem_limit": 268435456,
        "mem_reservation": 67108864
      },
      "postgres": {
        "init": true,
        "pids_limit": 768,
        "cpu_shares": 768,
        "ulimits": {
          "nofile": {
            "soft": 16384,
            "hard": 16384
          }
        },
        "blkio_config": {
          "weight": 600
        },
        "cpus": 1.0,
        "mem_limit": 1073741824,
        "mem_reservation": 268435456
      },
      "redis": {
        "init": true,
        "pids_limit": 192,
        "cpu_shares": 768,
        "ulimits": {
          "nofile": {
            "soft": 16384,
            "hard": 16384
          }
        },
        "blkio_config": {
          "weight": 600
        },
        "cpus": 0.5,
        "mem_limit": 268435456,
        "mem_reservation": 67108864
      },
      "keycloak": {
        "init": true,
        "pids_limit": 768,
        "cpu_shares": 768,
        "ulimits": {
          "nofile": {
            "soft": 16384,
            "hard": 16384
          }
        },
        "blkio_config": {
          "weight": 600
        },
        "cpus": 1.5,
        "mem_limit": 1342177280,
        "mem_reservation": 402653184
      },
      "nats": {
        "init": true,
        "pids_limit": 192,
        "cpu_shares": 768,
        "ulimits": {
          "nofile": {
            "soft": 16384,
            "hard": 16384
          }
        },
        "blkio_config": {
          "weight": 600
        },
        "cpus": 0.25,
        "mem_limit": 134217728,
        "mem_reservation": 33554432
      },
      "minio": {
        "init": true,
        "pids_limit": 384,
        "cpu_shares": 768,
        "ulimits": {
          "nofile": {
            "soft": 16384,
            "hard": 16384
          }
        },
        "blkio_config": {
          "weight": 600
        },
        "cpus": 1.0,
        "mem_limit": 805306368,
        "mem_reservation": 201326592
      },
      "control-center": {
        "init": true,
        "pids_limit": 384,
        "working_dir": "/app",
        "expose": [
          "8080"
        ],
        "cpu_shares": 1024,
        "ulimits": {
          "nofile": {
            "soft": 16384,
            "hard": 16384
          }
        },
        "blkio_config": {
          "weight": 700
        },
        "cpus": 1.0,
        "mem_limit": 536870912,
        "mem_reservation": 134217728
      },
      "project-router": {
        "init": true,
        "pids_limit": 192,
        "working_dir": "/app",
        "expose": [
          "8080"
        ],
        "cpu_shares": 1024,
        "ulimits": {
          "nofile": {
            "soft": 16384,
            "hard": 16384
          }
        },
        "blkio_config": {
          "weight": 700
        },
        "cpus": 0.5,
        "mem_limit": 201326592,
        "mem_reservation": 50331648
      },
      "mariadb": {
        "init": true,
        "pids_limit": 768,
        "cpu_shares": 768,
        "ulimits": {
          "nofile": {
            "soft": 16384,
            "hard": 16384
          }
        },
        "blkio_config": {
          "weight": 600
        },
        "cpus": 1.5,
        "mem_limit": 1073741824,
        "mem_reservation": 268435456
      },
      "phpmyadmin": {
        "init": true,
        "pids_limit": 256,
        "expose": [
          "80"
        ],
        "cpu_shares": 256,
        "ulimits": {
          "nofile": {
            "soft": 8192,
            "hard": 8192
          }
        },
        "blkio_config": {
          "weight": 300
        },
        "cpus": 0.25,
        "mem_limit": 268435456,
        "mem_reservation": 50331648
      },
      "phppgadmin": {
        "init": true,
        "pids_limit": 256,
        "expose": [
          "80"
        ],
        "cpu_shares": 256,
        "ulimits": {
          "nofile": {
            "soft": 8192,
            "hard": 8192
          }
        },
        "blkio_config": {
          "weight": 300
        },
        "cpus": 0.25,
        "mem_limit": 268435456,
        "mem_reservation": 50331648
      },
      "local-dns": {
        "init": true,
        "pids_limit": 64,
        "expose": [
          "53/tcp",
          "53/udp"
        ],
        "cpu_shares": 768,
        "ulimits": {
          "nofile": {
            "soft": 16384,
            "hard": 16384
          }
        },
        "blkio_config": {
          "weight": 600
        },
        "cpus": 0.1,
        "mem_limit": 67108864,
        "mem_reservation": 16777216
      },
      "prometheus": {
        "init": true,
        "pids_limit": 320,
        "cpu_shares": 512,
        "ulimits": {
          "nofile": {
            "soft": 8192,
            "hard": 8192
          }
        },
        "blkio_config": {
          "weight": 400
        },
        "cpus": 0.5,
        "mem_limit": 536870912,
        "mem_reservation": 134217728
      },
      "node-exporter": {
        "init": true,
        "pids_limit": 96,
        "cpu_shares": 512,
        "ulimits": {
          "nofile": {
            "soft": 8192,
            "hard": 8192
          }
        },
        "blkio_config": {
          "weight": 400
        },
        "cpus": 0.15,
        "mem_limit": 67108864,
        "mem_reservation": 16777216
      },
      "cadvisor": {
        "init": true,
        "pids_limit": 192,
        "cpu_shares": 512,
        "ulimits": {
          "nofile": {
            "soft": 8192,
            "hard": 8192
          }
        },
        "blkio_config": {
          "weight": 400
        },
        "cpus": 0.25,
        "mem_limit": 201326592,
        "mem_reservation": 50331648
      },
      "platform-alert-dispatcher": {
        "init": true,
        "user": "1000:1000",
        "pids_limit": 128,
        "cap_drop": [
          "ALL"
        ],
        "expose": [
          "3000"
        ],
        "cpu_shares": 512,
        "ulimits": {
          "nofile": {
            "soft": 8192,
            "hard": 8192
          }
        },
        "blkio_config": {
          "weight": 400
        },
        "cpus": 0.2,
        "mem_limit": 134217728,
        "mem_reservation": 33554432
      },
      "alertmanager": {
        "init": true,
        "pids_limit": 128,
        "cpu_shares": 512,
        "ulimits": {
          "nofile": {
            "soft": 8192,
            "hard": 8192
          }
        },
        "blkio_config": {
          "weight": 400
        },
        "cpus": 0.25,
        "mem_limit": 134217728,
        "mem_reservation": 33554432
      },
      "grafana": {
        "init": true,
        "pids_limit": 256,
        "cpu_shares": 512,
        "ulimits": {
          "nofile": {
            "soft": 8192,
            "hard": 8192
          }
        },
        "blkio_config": {
          "weight": 400
        },
        "cpus": 0.5,
        "mem_limit": 402653184,
        "mem_reservation": 100663296
      },
      "loki": {
        "init": true,
        "pids_limit": 320,
        "cpu_shares": 512,
        "ulimits": {
          "nofile": {
            "soft": 8192,
            "hard": 8192
          }
        },
        "blkio_config": {
          "weight": 400
        },
        "cpus": 0.5,
        "mem_limit": 536870912,
        "mem_reservation": 134217728
      },
      "promtail": {
        "init": true,
        "pids_limit": 192,
        "cpu_shares": 512,
        "ulimits": {
          "nofile": {
            "soft": 8192,
            "hard": 8192
          }
        },
        "blkio_config": {
          "weight": 400
        },
        "cpus": 0.25,
        "mem_limit": 201326592,
        "mem_reservation": 50331648
      },
      "waf": {
        "init": true,
        "pids_limit": 384,
        "cpu_shares": 1024,
        "ulimits": {
          "nofile": {
            "soft": 16384,
            "hard": 16384
          }
        },
        "blkio_config": {
          "weight": 700
        },
        "cpus": 1.0,
        "mem_limit": 402653184,
        "mem_reservation": 100663296
      },
      "backup-scheduler": {
        "init": true,
        "pids_limit": 256,
        "cpu_shares": 1024,
        "ulimits": {
          "nofile": {
            "soft": 16384,
            "hard": 16384
          }
        },
        "blkio_config": {
          "weight": 700
        },
        "cpus": 1.0,
        "mem_limit": 536870912,
        "mem_reservation": 134217728
      },
      "local-registry": {
        "cpu_shares": 768,
        "ulimits": {
          "nofile": {
            "soft": 16384,
            "hard": 16384
          }
        },
        "blkio_config": {
          "weight": 600
        },
        "cpus": 0.25,
        "mem_limit": 268435456,
        "mem_reservation": 67108864,
        "pids_limit": 192
      },
      "docker-socket-proxy": {
        "cpu_shares": 1024,
        "ulimits": {
          "nofile": {
            "soft": 16384,
            "hard": 16384
          }
        },
        "blkio_config": {
          "weight": 700
        },
        "init": true,
        "cpus": 0.1,
        "mem_limit": 134217728,
        "mem_reservation": 33554432,
        "pids_limit": 64,
        "expose": [
          "2375"
        ]
      }
    },
    "networkFields": {
      "enterprise_net": [
        "external",
        "name"
      ],
      "platform_edge": [
        "internal",
        "labels",
        "name"
      ],
      "platform_routing": [
        "internal",
        "labels",
        "name"
      ],
      "platform_db_admin": [
        "internal",
        "labels",
        "name"
      ],
      "platform_postgres": [
        "internal",
        "labels",
        "name"
      ],
      "platform_cache": [
        "internal",
        "labels",
        "name"
      ],
      "platform_bus": [
        "internal",
        "labels",
        "name"
      ],
      "platform_storage": [
        "internal",
        "labels",
        "name"
      ],
      "platform_observability": [
        "internal",
        "labels",
        "name"
      ],
      "platform_egress": [
        "enable_ipv6",
        "labels",
        "name"
      ],
      "platform_docker_control": [
        "driver",
        "internal",
        "name"
      ]
    },
    "volumeFields": {
      "enterprise_mariadb_data": [
        "external",
        "name"
      ],
      "enterprise_postgres_data": [
        "name"
      ],
      "enterprise_redis_data": [
        "name"
      ],
      "enterprise_keycloak_data": [
        "name"
      ],
      "enterprise_nats_data": [
        "name"
      ],
      "enterprise_minio_data": [
        "name"
      ],
      "enterprise_alertmanager_data": [
        "name"
      ],
      "enterprise_grafana_data": [
        "name"
      ],
      "enterprise_prometheus_data": [
        "name"
      ],
      "enterprise_loki_data": [
        "name"
      ],
      "backup_scheduler_logs": [
        "name"
      ],
      "enterprise_local_registry_data": [
        "external",
        "name"
      ]
    },
    "topLevelFields": [
      "configs",
      "name",
      "networks",
      "secrets",
      "services",
      "volumes"
    ]
  },
  directoryBindTargets: [
    "/app",
    "/docker-entrypoint-initdb.d",
    "/etc/coredns",
    "/etc/grafana/provisioning",
    "/etc/mysql/conf.d",
    "/etc/mysql/ssl",
    "/etc/phpmyadmin/certs",
    "/etc/prometheus/rules",
    "/infra",
    "/infra/backups",
    "/infra/reports",
    "/loki/rules",
    "/opt/keycloak/data/import",
    "/platform-postgres-init",
    "/project",
    "/var/lib/grafana/dashboards",
    "/var/lib/node-exporter/textfile",
    "/var/www/infra-docs",
    "/var/www/project-state",
    "/var/www/projects",
  ],

  secretFiles: {
    alertmanager_webhook_token: "secrets/alertmanager_webhook_token.txt",
    backup_signing_keys: "secrets/backup_signing_keys.txt",
    control_center_database_url: "secrets/control_center_database_url.txt",
    control_center_vault_keys: "secrets/control_center_vault_keys.txt",
    grafana_admin_password: "secrets/grafana_admin_password.txt",
    keycloak_admin_password: "secrets/keycloak_admin_password.txt",
    keycloak_db_password: "secrets/keycloak_db_password.txt",
    mariadb_root_password: "secrets/mariadb_root_password.txt",
    minio_root_password: "secrets/minio_root_password.txt",
    nats_password: "secrets/nats_password.txt",
    phpmyadmin_control_password: "secrets/phpmyadmin_control_password.txt",
    postgres_superuser_password: "secrets/postgres_superuser_password.txt",
    projects_gateway_signing_keys: "secrets/projects_gateway_signing_keys.txt",
    redis_password: "secrets/redis_password.txt",
    smtp_password: "secrets/smtp_password.txt",
  },
  secretFileVariables: {
    control_center_database_url: "CONTROL_CENTER_DATABASE_URL_SECRET_FILE",
    control_center_vault_keys: "CONTROL_CENTER_VAULT_KEYS_SECRET_FILE",
    mariadb_root_password: "MARIADB_ROOT_PASSWORD_SECRET_FILE",
  },
  configContentLines: {
    enterprise_traefik_routes: [
      "http:",
      "  routers:",
      "    enterprise-portal:",
      "      rule: Host(`__PORTAL_HOST__`)",
      "      entryPoints:",
      "        - web",
      "      priority: 100",
      "      middlewares:",
      "        - enterprise-edge-forwarded-https@file",
      "        - enterprise-security-headers@file",
      "        - enterprise-rate-limit@file",
      "        - enterprise-compress@file",
      "      service: enterprise-portal",
      "",
      "    enterprise-docs:",
      "      rule: Host(`__DOCS_HOST__`)",
      "      entryPoints:",
      "        - web",
      "      priority: 100",
      "      middlewares:",
      "        - enterprise-edge-forwarded-https@file",
      "        - enterprise-security-headers@file",
      "        - enterprise-rate-limit@file",
      "        - enterprise-compress@file",
      "      service: enterprise-docs",
      "",
      "    enterprise-identity:",
      "      rule: Host(`__AUTH_HOST__`)",
      "      entryPoints:",
      "        - web",
      "      priority: 200",
      "      middlewares:",
      "        - enterprise-edge-forwarded-https@file",
      "        - keycloak-security-headers@file",
      "        - enterprise-rate-limit@file",
      "        - enterprise-compress@file",
      "      service: enterprise-identity",
      "",
      "  services:",
      "    enterprise-portal:",
      "      loadBalancer:",
      "        servers:",
      "          - url: http://control-center:8080",
      "    enterprise-docs:",
      "      loadBalancer:",
      "        servers:",
      "          - url: http://control-center:8080",
      "    enterprise-identity:",
      "      loadBalancer:",
      "        servers:",
      "          - url: http://keycloak:8080",
      "",
    ],
  },
  physicalNetworkNames: {
    enterprise_net: "enterprise_net",
    platform_bus: "platform_infra_vps_bus",
    platform_cache: "platform_infra_vps_cache",
    platform_db_admin: "platform_infra_vps_db_admin",
    platform_docker_control: "platform_infra_vps_platform_docker_control",
    platform_edge: "platform_infra_vps_edge",
    platform_egress: "platform_infra_vps_egress",
    platform_observability: "platform_infra_vps_observability",
    platform_postgres: "platform_infra_vps_postgres",
    platform_routing: "platform_infra_vps_routing",
    platform_storage: "platform_infra_vps_storage",
  },
  networkLabels: {
    enterprise_net: {},
    platform_bus: { "com.platform.trust-zone": "bus" },
    platform_cache: { "com.platform.trust-zone": "cache" },
    platform_db_admin: { "com.platform.trust-zone": "db-admin" },
    platform_docker_control: {},
    platform_edge: { "com.platform.trust-zone": "edge" },
    platform_egress: { "com.platform.trust-zone": "trusted-platform-egress" },
    platform_observability: { "com.platform.trust-zone": "observability" },
    platform_postgres: { "com.platform.trust-zone": "postgres" },
    platform_routing: { "com.platform.trust-zone": "routing" },
    platform_storage: { "com.platform.trust-zone": "storage" },
  },
  serviceNetworks: {
    "alertmanager": ["platform_observability"],
    "backup-scheduler": ["platform_db_admin", "platform_docker_control", "platform_egress", "platform_storage"],
    "cadvisor": ["platform_observability"],
    "control-center": ["platform_db_admin", "platform_egress", "platform_observability", "platform_routing"],
    "docker-socket-proxy": ["platform_docker_control"],
    "grafana": ["platform_observability"],
    "keycloak": ["platform_egress", "platform_observability", "platform_postgres", "platform_routing"],
    "local-dns": ["platform_egress"],
    "local-registry": [],
    "loki": ["platform_observability"],
    "mariadb": ["platform_db_admin"],
    "minio": ["platform_storage"],
    "nats": ["platform_bus"],
    "node-exporter": ["platform_observability"],
    "phpmyadmin": ["platform_db_admin", "platform_routing"],
    "phppgadmin": ["platform_db_admin", "platform_routing"],
    "platform-alert-dispatcher": ["platform_egress", "platform_observability"],
    "postgres": ["platform_db_admin", "platform_postgres"],
    "project-router": ["platform_routing"],
    "prometheus": ["platform_observability"],
    "promtail": ["platform_observability"],
    "redis": ["platform_cache"],
    "traefik": ["platform_edge", "platform_egress", "platform_observability", "platform_routing"],
    "waf": ["platform_edge"],
  },
  serviceSecretGrants: {
    alertmanager: ["alertmanager_webhook_token"],
    "control-center": [
      "control_center_database_url",
      "control_center_vault_keys",
      "mariadb_root_password",
      "postgres_superuser_password",
      "projects_gateway_signing_keys",
    ],
    grafana: ["grafana_admin_password"],
    keycloak: ["keycloak_admin_password", "keycloak_db_password"],
    mariadb: ["mariadb_root_password"],
    minio: ["minio_root_password"],
    nats: ["nats_password"],
    "phpmyadmin": ["phpmyadmin_control_password"],
    "platform-alert-dispatcher": ["alertmanager_webhook_token", "smtp_password"],
    postgres: ["keycloak_db_password", "postgres_superuser_password"],
    redis: ["redis_password"],
  },
  serviceConfigGrants: {
    traefik: [{
      source: "enterprise_traefik_routes",
      target: "/etc/traefik/dynamic/routes.yml",
    }],
  },
  servicePortRules: {
    "docker-socket-proxy": [
      { hostIp: "127.0.0.1", protocol: "tcp", published: 2376, target: 2375 },
    ],
    "local-dns": [
      { hostIp: "192.168.1.164", protocol: "tcp", published: 53, target: 53 },
      { hostIp: "192.168.1.164", protocol: "udp", published: 53, target: 53 },
    ],
    "local-registry": [
      { hostIp: "127.0.0.1", protocol: "tcp", published: 5000, target: 5000 },
    ],
    waf: [
      { hostIp: "0.0.0.0", protocol: "tcp", published: 80, target: 8080 },
      { hostIp: "0.0.0.0", protocol: "tcp", published: 443, target: 8443 },
    ],
  },
  physicalVolumeNames: {
    backup_scheduler_logs: "platform_backup_scheduler_logs",
    enterprise_alertmanager_data: "enterprise_alertmanager_data",
    enterprise_grafana_data: "enterprise_grafana_data",
    enterprise_keycloak_data: "enterprise_keycloak_data",
    enterprise_local_registry_data: "enterprise_local_registry_data",
    enterprise_loki_data: "enterprise_loki_data",
    enterprise_mariadb_data: "enterprise_mariadb_data",
    enterprise_minio_data: "enterprise_minio_data",
    enterprise_nats_data: "enterprise_nats_data",
    enterprise_postgres_data: "enterprise_postgres_data",
    enterprise_prometheus_data: "enterprise_prometheus_data",
    enterprise_redis_data: "enterprise_redis_data",
  },
  externalVolumeNames: ["enterprise_local_registry_data", "enterprise_mariadb_data"],
  serviceImages: {
    alertmanager: "prom/alertmanager:v0.32.2@sha256:b85533a2eb45865835315810315f6951331b2dbc8c93a6cf9a51e156a006a706",
    "backup-scheduler": "platform/ops:local",
    cadvisor: "gcr.io/cadvisor/cadvisor:v0.52.1@sha256:f40e65878e25c2e78ea037f73a449527a0fb994e303dc3e34cb6b187b4b91435",
    "control-center": "platform/control-center:local",
    "docker-socket-proxy": "ghcr.io/tecnativa/docker-socket-proxy:v0.4.2@sha256:1f3a6f303320723d199d2316a3e82b2e2685d86c275d5e3deeaf182573b47476",
    grafana: "grafana/grafana:13.0.2@sha256:5dad0df181cb644a14e13617b913b261a54f7d4fd4510721dba420929f35bea2",
    keycloak: "quay.io/keycloak/keycloak:26.6.3@sha256:5fdbf2dbb5897cc34e82de49d13e23db011f9925089dbc555fc095f2c8bc1dac",
    "local-dns": "coredns/coredns:1.13.1@sha256:9b9128672209474da07c91439bf15ed704ae05ad918dd6454e5b6ae14e35fee6",
    "local-registry": "registry:3@sha256:1be55279f18a2fe1a74edf2664cac61c1bea305b7b4642dab412e7affdcb3e33",
    loki: "grafana/loki:3.7.2@sha256:191d4fdfb7264f16989f0a57f320872620a5a7c2ceeec6229212c4190ec49b86",
    mariadb: "mariadb:12.3.2@sha256:b1c7bf836e64ed9406a8984af29509f40089d55cea14b32f12c4726a1f17104b",
    minio: "quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e",
    nats: "nats:2.14-alpine@sha256:952d157e28d5394a211229bd57a7b37ff9f184e58e2c8486a08fa909fd254e32",
    "node-exporter": "prom/node-exporter:v1.10.2@sha256:3ac34ce007accad95afed72149e0d2b927b7e42fd1c866149b945b84737c62c3",
    phpmyadmin: "phpmyadmin:5.2.3@sha256:b16dc88d6e62b186dc4864adac4996fe0238587aa9f5ed507dcfc3894903a3f6",
    phppgadmin: "tozd/phppgadmin@sha256:2c146e25719c3712dd3190c2b59689f20448c2fa7b595f89be06214ddc89f1fd",
    "platform-alert-dispatcher": "platform/alert-dispatcher:local",
    postgres: "postgres:18-alpine@sha256:1b1689b20d16a014a3d195653381cf2caa75a41a92d93b255a9d6ea29fd353aa",
    "project-router": "node:26.3.1-alpine@sha256:a2dc166a387cc6ca1e62d0c8e265e49ca985d6e60abc9fe6e6c3d6ce8e63f606",
    prometheus: "prom/prometheus:v3.12.0@sha256:69f5241418838263316593f7274a304b095c40bcf22e57272865da91bd60a8ac",
    promtail: "grafana/promtail:3.6.10@sha256:2a0f5e3e160ee5d549c585f6cc4f4e1c566ff783324a424bd75bc16503fc660e",
    redis: "redis:8.6-alpine@sha256:2cc044fc5a07c9b701f8f1255a309ae9ad7856e694ac03513bf3648c01e40763",
    traefik: "traefik:v3.7.5@sha256:e4d98158c01ad752fc1071d4e9573788747230d902cdde00a772516e692d07c9",
    waf: "owasp/modsecurity-crs:4.26.0-nginx-202605200705@sha256:468c265e9b458f73f58c6c83fd0678724e383c088a0da86d828641c5f64001ed",
  },
  serviceImageVariables: {
    alertmanager: "ALERTMANAGER_IMAGE",
    "backup-scheduler": "PLATFORM_OPS_IMAGE",
    cadvisor: "CADVISOR_IMAGE",
    "control-center": "CONTROL_CENTER_IMAGE",
    "docker-socket-proxy": "DOCKER_SOCKET_PROXY_IMAGE",
    grafana: "GRAFANA_IMAGE",
    keycloak: "KEYCLOAK_IMAGE",
    "local-dns": "COREDNS_IMAGE",
    "local-registry": "REGISTRY_IMAGE",
    loki: "LOKI_IMAGE",
    mariadb: "MARIADB_IMAGE",
    minio: "MINIO_IMAGE",
    nats: "NATS_IMAGE",
    "node-exporter": "NODE_EXPORTER_IMAGE",
    phpmyadmin: "PHPMYADMIN_IMAGE",
    phppgadmin: "PHPPGADMIN_IMAGE",
    "platform-alert-dispatcher": "PLATFORM_ALERT_DISPATCHER_IMAGE",
    postgres: "POSTGRES_IMAGE",
    "project-router": "NODE_IMAGE",
    prometheus: "PROMETHEUS_IMAGE",
    promtail: "PROMTAIL_IMAGE",
    redis: "REDIS_IMAGE",
    traefik: "TRAEFIK_IMAGE",
    waf: "WAF_IMAGE",
  },
  requiredServiceControls: {
    capDropAll: ["platform-alert-dispatcher"],
    numericUsers: { "platform-alert-dispatcher": "1000:1000" },
    readOnly: [
      "backup-scheduler",
      "control-center",
      "docker-socket-proxy",
      "platform-alert-dispatcher",
      "project-router",
    ],
    securityOpt: [
      "alertmanager",
      "backup-scheduler",
      "cadvisor",
      "control-center",
      "docker-socket-proxy",
      "grafana",
      "keycloak",
      "local-dns",
      "loki",
      "mariadb",
      "minio",
      "nats",
      "node-exporter",
      "phpmyadmin",
      "phppgadmin",
      "platform-alert-dispatcher",
      "postgres",
      "project-router",
      "prometheus",
      "promtail",
      "redis",
      "traefik",
      "waf",
    ],
  },
  proxyEnvironment: {
    ALLOW_RESTARTS: "1",
    ALLOW_START: "1",
    ALLOW_STOP: "1",
    AUTH: "0",
    BUILD: "0",
    COMMIT: "0",
    CONFIGS: "0",
    CONTAINERS: "1",
    DISTRIBUTION: "0",
    EVENTS: "1",
    EXEC: "1",
    GRPC: "0",
    IMAGES: "1",
    INFO: "1",
    NETWORKS: "1",
    NODES: "0",
    PLUGINS: "0",
    POST: "1",
    SECRETS: "0",
    SERVICES: "0",
    SESSION: "0",
    SWARM: "0",
    SYSTEM: "0",
    TASKS: "0",
    VOLUMES: "1",
  },
  servicesWithDefaultLogging: [
    "alertmanager",
    "backup-scheduler",
    "cadvisor",
    "control-center",
    "grafana",
    "keycloak",
    "local-dns",
    "loki",
    "mariadb",
    "minio",
    "nats",
    "node-exporter",
    "phpmyadmin",
    "phppgadmin",
    "platform-alert-dispatcher",
    "postgres",
    "project-router",
    "prometheus",
    "promtail",
    "redis",
    "traefik",
    "waf",
  ],
  serviceHealthchecks: {
    alertmanager: {
      test: ["CMD-SHELL", "test -r /run/secrets/alertmanager_webhook_token && wget -q -O /dev/null http://127.0.0.1:9093/-/ready"],
      interval: "15s",
      timeout: "5s",
      retries: 10,
    },
    "backup-scheduler": {
      test: ["CMD-SHELL", "test -s /etc/crontabs/root && pgrep crond >/dev/null"],
      interval: "30s",
      timeout: "5s",
      retries: 5,
    },
    cadvisor: {
      test: ["CMD-SHELL", "wget -q -O /dev/null http://127.0.0.1:8080/healthz"],
      interval: "20s",
      timeout: "5s",
      retries: 10,
    },
    "control-center": {
      test: ["CMD-SHELL", "node -e \"fetch('http://127.0.0.1:8080/__health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))\""],
      interval: "15s",
      timeout: "5s",
      retries: 10,
    },
    "docker-socket-proxy": {
      test: ["CMD", "haproxy", "-c", "-f", "/usr/local/etc/haproxy/haproxy.cfg"],
      interval: "30s",
      timeout: "5s",
      retries: 5,
    },
    grafana: {
      test: ["CMD-SHELL", "wget -q -O /dev/null http://127.0.0.1:3000/api/health"],
      interval: "15s",
      timeout: "5s",
      retries: 10,
    },
    keycloak: {
      test: ["CMD-SHELL", "bash -ec 'exec 3<>/dev/tcp/127.0.0.1/9000; printf \"GET /health/ready HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n\" >&3; head -n 1 <&3 | grep -q \" 200 \"'"],
      interval: "20s",
      timeout: "5s",
      retries: 15,
      start_period: "60s",
    },
    "local-dns": {
      test: ["CMD", "/coredns", "-version"],
      interval: "30s",
      timeout: "5s",
      retries: 5,
    },
    "local-registry": {
      test: ["CMD-SHELL", "wget -q -O /dev/null http://127.0.0.1:5000/v2/"],
      interval: "20s",
      timeout: "5s",
      retries: 10,
    },
    loki: {
      test: ["CMD", "/usr/bin/loki", "-version"],
      interval: "15s",
      timeout: "5s",
      retries: 15,
    },
    mariadb: {
      test: ["CMD-SHELL", "mariadb -uroot -p\"$$(cat /run/secrets/mariadb_root_password)\" -N -e 'select 1' >/dev/null"],
      interval: "5s",
      timeout: "3s",
      retries: 30,
    },
    minio: {
      test: ["CMD-SHELL", "curl -fsS http://127.0.0.1:9000/minio/health/live >/dev/null"],
      interval: "15s",
      timeout: "5s",
      retries: 10,
    },
    nats: {
      test: ["CMD-SHELL", "wget -q -O /dev/null http://127.0.0.1:8222/healthz"],
      interval: "10s",
      timeout: "5s",
      retries: 10,
    },
    "node-exporter": {
      test: ["CMD-SHELL", "wget -q -O /dev/null http://127.0.0.1:9100/metrics"],
      interval: "20s",
      timeout: "5s",
      retries: 10,
    },
    phpmyadmin: {
      test: ["CMD-SHELL", "curl -fsS http://127.0.0.1/ >/dev/null"],
      interval: "20s",
      timeout: "5s",
      retries: 10,
    },
    phppgadmin: {
      test: ["CMD-SHELL", "php -r '$$h=@get_headers(\"http://127.0.0.1/phppgadmin/\"); exit(isset($$h[0]) && str_contains($$h[0], \" 200 \") ? 0 : 1);'"],
      interval: "20s",
      timeout: "5s",
      retries: 10,
    },
    "platform-alert-dispatcher": {
      test: ["CMD-SHELL", "node -e \"fetch('http://127.0.0.1:3000/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))\""],
      interval: "20s",
      timeout: "5s",
      retries: 10,
      start_period: "15s",
    },
    postgres: {
      test: ["CMD-SHELL", "pg_isready -U \"$${POSTGRES_USER}\" -d postgres"],
      interval: "10s",
      timeout: "5s",
      retries: 10,
    },
    "project-router": {
      test: ["CMD-SHELL", "node -e \"fetch('http://127.0.0.1:8080/__health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))\""],
      interval: "15s",
      timeout: "5s",
      retries: 10,
    },
    prometheus: {
      test: ["CMD-SHELL", "wget -q -O /dev/null http://127.0.0.1:9090/-/ready"],
      interval: "15s",
      timeout: "5s",
      retries: 10,
    },
    promtail: {
      test: ["CMD-SHELL", "bash -ec 'exec 3<>/dev/tcp/127.0.0.1/9080; printf \"GET /ready HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n\" >&3; head -n 1 <&3 | grep -q \" 200 \"'"],
      interval: "20s",
      timeout: "5s",
      retries: 10,
    },
    redis: {
      test: ["CMD-SHELL", "REDISCLI_AUTH=\"$$(cat \"$${REDIS_PASSWORD_FILE}\")\" redis-cli ping | grep PONG"],
      interval: "10s",
      timeout: "5s",
      retries: 10,
    },
    traefik: {
      test: ["CMD", "traefik", "healthcheck", "--ping"],
      interval: "15s",
      timeout: "5s",
      retries: 5,
    },
    waf: {
      test: [
        "CMD-SHELL",
        "nginx -t >/dev/null 2>&1 && { curl -ksS -o /dev/null http://127.0.0.1:8080/; code=$$?; [ $$code -eq 0 ] || [ $$code -eq 22 ]; }",
      ],
      interval: "20s",
      timeout: "5s",
      retries: 10,
      start_period: "20s",
    },
  },
  forbiddenInjectionEnvironmentKeys: [
    "BASH_ENV",
    "ENV",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "NODE_OPTIONS",
    "PYTHONPATH",
  ],
  wafFixedSecurityEnvironment: {
    BACKEND: "http://traefik:80",
    MODSEC_AUDIT_ENGINE: "RelevantOnly",
    MODSEC_RULE_ENGINE: "On",
    NGINX_X_FORWARDED_PROTO: "https",
    PROXY_SSL_VERIFY: "off",
  },
  wafProjectedSecurityEnvironment: {
    ANOMALY_INBOUND: {
      variable: "WAF_ANOMALY_INBOUND",
      fallback: "5",
      integerMinimum: 1,
      integerMaximum: 100,
    },
    ANOMALY_OUTBOUND: {
      variable: "WAF_ANOMALY_OUTBOUND",
      fallback: "4",
      integerMinimum: 1,
      integerMaximum: 100,
    },
    BLOCKING_PARANOIA: {
      variable: "WAF_BLOCKING_PARANOIA",
      fallback: "2",
      integerMinimum: 1,
      integerMaximum: 4,
    },
    DETECTION_PARANOIA: {
      variable: "WAF_DETECTION_PARANOIA",
      fallback: "2",
      integerMinimum: 1,
      integerMaximum: 4,
    },
    NGINX_ALWAYS_TLS_REDIRECT: {
      variable: "WAF_NGINX_ALWAYS_TLS_REDIRECT",
      fallback: "on",
      allowed: ["off", "on"],
    },
  },
  controlCenterFixedSecurityEnvironment: {
    CONTROL_CENTER_AUTH_MODE: "oidc-passkey",
    CONTROL_CENTER_AUTH_STORE: "postgres",
  },
  backupSchedulerBooleanEnvironment: {
    BACKUP_SCHEDULER_ENABLE_OFFSITE: {
      variable: "BACKUP_SCHEDULER_ENABLE_OFFSITE",
      fallback: "false",
    },
    BACKUP_SCHEDULER_ENABLE_RETENTION_APPLY: {
      variable: "BACKUP_SCHEDULER_ENABLE_RETENTION_APPLY",
      fallback: "false",
    },
  },
  buildDockerfiles: {
    "backup-scheduler": "docker/ops.Dockerfile",
    "control-center": "docker/control-center.Dockerfile",
    "platform-alert-dispatcher": "docker/alert-dispatcher.Dockerfile",
  },
  serviceProcessModel: {
    alertmanager: {
      command: ["--config.file=/etc/alertmanager/alertmanager.yml", "--storage.path=/alertmanager"],
      entrypoint: null,
    },
    "backup-scheduler": {
      command: null,
      entrypoint: ["sh", "/infra/scripts/backup-scheduler.sh"],
    },
    cadvisor: {
      command: ["--docker_only=true", "--store_container_labels=false", "--housekeeping_interval=30s"],
      entrypoint: null,
    },
    "control-center": { command: ["node", "/app/server.mjs"], entrypoint: null },
    "docker-socket-proxy": { command: null, entrypoint: null },
    grafana: { command: null, entrypoint: null },
    keycloak: {
      command: ['export KC_BOOTSTRAP_ADMIN_PASSWORD="$$(cat "$${KC_BOOTSTRAP_ADMIN_PASSWORD_FILE}")"; export KC_DB_PASSWORD="$$(cat "$${KC_DB_PASSWORD_FILE}")"; exec /opt/keycloak/bin/kc.sh start --http-port=8080 --import-realm'],
      entrypoint: ["/bin/sh", "-ec"],
    },
    "local-dns": { command: ["-conf", "/etc/coredns/Corefile"], entrypoint: null },
    "local-registry": { command: null, entrypoint: null },
    loki: { command: "-config.file=/etc/loki/config.yml", entrypoint: null },
    mariadb: { command: null, entrypoint: null },
    minio: {
      command: ['export MINIO_ROOT_PASSWORD="$$(cat "$${MINIO_ROOT_PASSWORD_FILE}")"; exec minio server /data --address ":9000" --console-address ":9001"'],
      entrypoint: ["/bin/sh", "-ec"],
    },
    nats: {
      command: null,
      entrypoint: [
        "/bin/sh",
        "-ec",
        'NATS_PASSWORD="$$(cat "$${NATS_PASSWORD_FILE}")"\n'
          + 'exec nats-server -c /etc/nats/nats-server.conf '
          + '--user "$$NATS_USER" --pass "$$NATS_PASSWORD"\n',
      ],
    },
    "node-exporter": {
      command: [
        "--path.rootfs=/host",
        "--collector.textfile.directory=/var/lib/node-exporter/textfile",
        "--collector.filesystem.mount-points-exclude=^/(dev|proc|sys|var/lib/docker/.+|run/docker/netns)($|/)",
        "--collector.netclass.ignored-devices=^(veth.*|br-.*|docker.*)$",
      ],
      entrypoint: null,
    },
    phpmyadmin: { command: null, entrypoint: null },
    phppgadmin: { command: null, entrypoint: null },
    "platform-alert-dispatcher": { command: null, entrypoint: null },
    postgres: { command: null, entrypoint: ["/usr/local/bin/platform-postgres-entrypoint"] },
    "project-router": { command: ["node", "/app/server.mjs"], entrypoint: null },
    prometheus: {
      command: [
        "--config.file=/etc/prometheus/prometheus.yml",
        "--storage.tsdb.path=/prometheus",
        "--storage.tsdb.retention.time=15d",
        "--web.enable-lifecycle",
      ],
      entrypoint: null,
    },
    promtail: { command: "-config.file=/etc/promtail/config.yml", entrypoint: null },
    redis: {
      command: ["sh", "-ec", 'REDIS_PASSWORD="$$(cat "$${REDIS_PASSWORD_FILE}")"\nexec redis-server --appendonly yes --requirepass "$${REDIS_PASSWORD}"\n'],
      entrypoint: null,
    },
    traefik: { command: ["--configFile=/etc/traefik/traefik.edge-http.yml"], entrypoint: null },
    waf: { command: null, entrypoint: null },
  },
  tmpfsRules: {
    "backup-scheduler": [
      "/tmp:rw,nosuid,nodev,size=256m",
      "/root:rw,nosuid,nodev,size=32m",
    ],
    "control-center": ["/tmp:rw,noexec,nosuid,nodev,size=64m"],
    "platform-alert-dispatcher": ["/tmp:rw,noexec,nosuid,nodev,size=16m"],
    "project-router": ["/tmp:rw,noexec,nosuid,nodev,size=32m"],
  },
  bindSourceRules: {
    alertmanager: {
      "/etc/alertmanager/alertmanager.yml": ["root:alertmanager/alertmanager.yml"],
    },
    "backup-scheduler": {
      "/infra": ["root:."],
      "/infra/backups": ["root:backups"],
      "/infra/reports": ["root:reports"],
      "/project": ["sibling:src"],
      "/var/www/project-state": ["root:projects-portal/state"],
    },
    "control-center": {
      "/var/www/infra-docs": ["root:."],
      "/var/www/project-state": ["root:projects-portal/state"],
      "/var/www/projects": ["sibling:src"],
    },
    grafana: {
      "/etc/grafana/provisioning": ["root:grafana/provisioning"],
      "/var/lib/grafana/dashboards": ["root:grafana/dashboards"],
    },
    keycloak: { "/opt/keycloak/data/import": ["root:keycloak/import"] },
    "local-dns": { "/etc/coredns": ["root:dns"] },
    loki: {
      "/etc/loki/config.yml": ["root:loki/config.yml"],
      "/loki/rules": ["root:loki/rules"],
    },
    mariadb: {
      "/docker-entrypoint-initdb.d": ["root:mariadb/initdb"],
      "/etc/mysql/conf.d": ["root:mariadb/conf.d"],
      "/etc/mysql/ssl": ["root:traefik/certs"],
    },
    nats: { "/etc/nats/nats-server.conf": ["root:nats/nats-server.conf"] },
    "node-exporter": {
      "/var/lib/node-exporter/textfile": ["root:projects-portal/state/node-exporter-textfile"],
    },
    phpmyadmin: {
      "/etc/apache2/conf-enabled/forwarded-proto.conf": ["root:phpmyadmin/apache-forwarded-proto.conf"],
      "/etc/phpmyadmin/certs": ["root:traefik/certs"],
      "/etc/phpmyadmin/config.user.inc.php": ["root:phpmyadmin/config.user.inc.php"],
    },
    phppgadmin: { "/etc/phppgadmin/config.inc.php": ["root:phppgadmin/config.inc.php"] },
    postgres: {
      "/platform-postgres-init": ["root:postgres/init"],
      "/usr/local/bin/platform-postgres-entrypoint": ["root:postgres/entrypoint-with-init-secrets.sh"],
    },
    "project-router": {
      "/app": ["root:project-router"],
      "/run/platform/hosted-workloads.lock.json": ["root:config/no-hosted-workloads.lock.json"],
      "/var/www/project-state": ["root:projects-portal/state"],
      "/var/www/projects": ["sibling:src"],
    },
    prometheus: {
      "/etc/prometheus/prometheus.yml": ["root:prometheus/prometheus.yml"],
      "/etc/prometheus/rules": ["root:prometheus/rules"],
    },
    promtail: { "/etc/promtail/config.yml": ["root:promtail/config.yml"] },
    traefik: {
      "/etc/traefik/dynamic/admin-routes.yml": ["root:traefik/dynamic/admin-routes.yml"],
      "/etc/traefik/dynamic/middlewares.yml": ["root:traefik/dynamic/middlewares.yml"],
      "/etc/traefik/dynamic/project-routes.yml": ["root:traefik/dynamic/project-routes.yml"],
      "/etc/traefik/traefik.edge-http.yml": ["root:traefik/traefik.edge-http.yml"],
    },
    waf: {
      "/etc/modsecurity.d/owasp-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf": [
        "root:waf/REQUEST-900-VPS-RULES-BEFORE-CRS.conf",
      ],
      "/etc/modsecurity.d/owasp-crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf": [
        "root:waf/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf",
      ],
      "/etc/nginx/conf/server.crt": ["root:traefik/certs/local-cert.pem"],
      "/etc/nginx/conf/server.key": ["root:traefik/certs/local-key.pem"],
    },
  },
  bindTargets: {
    "alertmanager": { "/etc/alertmanager/alertmanager.yml": "read-only" },
    "backup-scheduler": {
      "/infra": "read-only",
      "/infra/backups": "read-write",
      "/infra/reports": "read-write",
      "/project": "read-only",
      "/var/www/project-state": "read-write",
    },
    "control-center": {
      "/var/www/infra-docs": "read-only",
      "/var/www/project-state": "read-write",
      "/var/www/projects": "read-only",
    },
    "grafana": {
      "/etc/grafana/provisioning": "read-only",
      "/var/lib/grafana/dashboards": "read-only",
    },
    "keycloak": { "/opt/keycloak/data/import": "read-only" },
    "local-dns": { "/etc/coredns": "read-only" },
    "loki": {
      "/etc/loki/config.yml": "read-only",
      "/loki/rules": "read-only",
    },
    "mariadb": {
      "/docker-entrypoint-initdb.d": "read-only",
      "/etc/mysql/conf.d": "read-only",
      "/etc/mysql/ssl": "read-only",
    },
    "nats": { "/etc/nats/nats-server.conf": "read-only" },
    "node-exporter": { "/var/lib/node-exporter/textfile": "read-only" },
    "phpmyadmin": {
      "/etc/apache2/conf-enabled/forwarded-proto.conf": "read-only",
      "/etc/phpmyadmin/certs": "read-only",
      "/etc/phpmyadmin/config.user.inc.php": "read-only",
    },
    "phppgadmin": { "/etc/phppgadmin/config.inc.php": "read-only" },
    "postgres": {
      "/platform-postgres-init": "read-only",
      "/usr/local/bin/platform-postgres-entrypoint": "read-only",
    },
    "project-router": {
      "/app": "read-only",
      "/run/platform/hosted-workloads.lock.json": "read-only",
      "/var/www/project-state": "read-only",
      "/var/www/projects": "read-only",
    },
    "prometheus": {
      "/etc/prometheus/prometheus.yml": "read-only",
      "/etc/prometheus/rules": "read-only",
    },
    "promtail": { "/etc/promtail/config.yml": "read-only" },
    "traefik": {
      "/etc/traefik/dynamic/admin-routes.yml": "read-only",
      "/etc/traefik/dynamic/middlewares.yml": "read-only",
      "/etc/traefik/dynamic/project-routes.yml": "read-only",
      "/etc/traefik/traefik.edge-http.yml": "read-only",
    },
    "waf": {
      "/etc/modsecurity.d/owasp-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf": "read-only",
      "/etc/modsecurity.d/owasp-crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf": "read-only",
      "/etc/nginx/conf/server.crt": "read-only",
      "/etc/nginx/conf/server.key": "read-only",
    },
  },
  hostBindExceptions: [
    ["cadvisor", "/", "/rootfs", "read-only"],
    ["cadvisor", "/sys", "/sys", "read-only"],
    ["cadvisor", "/var/lib/docker", "/var/lib/docker", "read-only"],
    ["cadvisor", "/var/run", "/var/run", "read-only"],
    ["docker-socket-proxy", "/var/run/docker.sock", "/var/run/docker.sock", "read-only"],
    ["node-exporter", "/", "/host", "read-only"],
    ["promtail", "/var/lib/docker/containers", "/var/lib/docker/containers", "read-only"],
  ],
  namedVolumeTargets: {
    "alertmanager": { enterprise_alertmanager_data: "/alertmanager" },
    "backup-scheduler": { backup_scheduler_logs: "/var/log/platform" },
    "grafana": { enterprise_grafana_data: "/var/lib/grafana" },
    "keycloak": { enterprise_keycloak_data: "/opt/keycloak/data" },
    "local-registry": { enterprise_local_registry_data: "/var/lib/registry" },
    "loki": { enterprise_loki_data: "/loki" },
    "mariadb": { enterprise_mariadb_data: "/var/lib/mysql" },
    "minio": { enterprise_minio_data: "/data" },
    "nats": { enterprise_nats_data: "/data" },
    "postgres": { enterprise_postgres_data: "/var/lib/postgresql" },
    "prometheus": { enterprise_prometheus_data: "/prometheus" },
    "redis": { enterprise_redis_data: "/data" },
  },
};

const CORE_SEMANTIC_POLICY_BYTES = `${JSON.stringify(CORE_SEMANTIC_POLICY)}\n`;
export const coreSemanticPolicyDescriptor = CORE_SEMANTIC_POLICY;
export const coreSemanticPolicySha256 = crypto
  .createHash("sha256")
  .update(CORE_SEMANTIC_POLICY_BYTES)
  .digest("hex");

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function sameStructuredJson(left, right) {
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left)
      && Array.isArray(right)
      && left.length === right.length
      && left.every((value, index) => sameStructuredJson(value, right[index]));
  }
  if (plainObject(left) || plainObject(right)) {
    if (!plainObject(left) || !plainObject(right)) return false;
    const leftKeys = Object.keys(left).sort();
    const rightKeys = Object.keys(right).sort();
    return sameJson(leftKeys, rightKeys)
      && leftKeys.every((key) => sameStructuredJson(left[key], right[key]));
  }
  return left === right;
}

function sameFlatObject(left, right) {
  if (!plainObject(left) || !plainObject(right)) return false;
  const keys = Object.keys(left).sort();
  return sameJson(keys, Object.keys(right).sort())
    && keys.every((key) => left[key] === right[key]);
}

function parseDotenv(bytes) {
  const environment = new Map();
  const lines = bytes.replaceAll("\r\n", "\n").split("\n");
  for (const line of lines) {
    if (/^\s*(?:#.*)?$/.test(line)) continue;
    const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (!match || environment.has(match[1])) throw new Error("dotenv");
    let value = match[2].trim();
    if (value.startsWith("'")) {
      if (value.length < 2 || !value.endsWith("'")) throw new Error("dotenv");
      value = value.slice(1, -1);
    } else if (value.startsWith('"')) {
      if (value.length < 2 || !value.endsWith('"')) throw new Error("dotenv");
      value = JSON.parse(value);
    } else {
      value = value.replace(/\s+#.*$/, "").trim();
    }
    if (value.includes("\0") || value.includes("\n")) throw new Error("dotenv");
    environment.set(match[1], value);
  }
  return environment;
}

function envOr(environment, key, fallback) {
  const value = environment.get(key);
  return value === undefined || value === "" ? fallback : value;
}

function composeInterpolationEnd(value, offset) {
  let depth = 1;
  for (let index = offset + 2; index < value.length; index += 1) {
    if (value.startsWith("${", index)) {
      depth += 1;
      index += 1;
    } else if (value[index] === "}") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function expandComposeFallbackTemplate(value, environment, depth = 0) {
  if (typeof value !== "string" || depth > 16) return null;
  let expanded = "";
  for (let index = 0; index < value.length;) {
    if (!value.startsWith("${", index)) {
      expanded += value[index];
      index += 1;
      continue;
    }
    const end = composeInterpolationEnd(value, index);
    if (end === -1) return null;
    const expression = value.slice(index + 2, end);
    const operator = expression.indexOf(":-");
    if (operator === -1) return null;
    const variable = expression.slice(0, operator);
    const fallback = expression.slice(operator + 2);
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(variable)) return null;
    const observed = environment.get(variable);
    const projected = observed === undefined || observed === ""
      ? expandComposeFallbackTemplate(fallback, environment, depth + 1)
      : observed;
    if (typeof projected !== "string") return null;
    expanded += projected;
    index = end + 1;
  }
  return expanded;
}

function expectedServiceEnvironment(serviceName, environment) {
  const authority = CORE_SEMANTIC_POLICY.serviceEnvironmentAuthority.services[serviceName];
  if (!plainObject(authority)
      || typeof authority.present !== "boolean"
      || !plainObject(authority.entries)) {
    return { valid: false, present: false, value: null };
  }
  if (!authority.present) {
    return {
      valid: Object.keys(authority.entries).length === 0,
      present: false,
      value: null,
    };
  }
  const value = {};
  for (const [key, projection] of Object.entries(authority.entries)) {
    if (!plainObject(projection)) return { valid: false, present: true, value: null };
    if (Object.hasOwn(projection, "literal")) {
      if (!sameJson(Object.keys(projection), ["literal"])
          || typeof projection.literal !== "string") {
        return { valid: false, present: true, value: null };
      }
      value[key] = projection.literal;
      continue;
    }
    if (typeof projection.variable !== "string"
        || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(projection.variable)) {
      return { valid: false, present: true, value: null };
    }
    if (Object.hasOwn(projection, "required")) {
      if (!sameJson(Object.keys(projection).sort(), ["required", "variable"])
          || typeof projection.required !== "string") {
        return { valid: false, present: true, value: null };
      }
      const observed = environment.get(projection.variable);
      if (observed === undefined || observed === "") {
        return { valid: false, present: true, value: null };
      }
      value[key] = observed;
      continue;
    }
    if (typeof projection.fallback !== "string"
        || !sameJson(
          Object.keys(projection).sort(),
          Object.hasOwn(projection, "template")
            ? ["fallback", "template", "variable"]
            : ["fallback", "variable"],
        )) {
      return { valid: false, present: true, value: null };
    }
    const template = Object.hasOwn(projection, "template")
      ? projection.template
      : `\${${projection.variable}:-${projection.fallback}}`;
    const projected = expandComposeFallbackTemplate(template, environment);
    if (projected === null) return { valid: false, present: true, value: null };
    value[key] = projected;
  }
  return { valid: true, present: true, value };
}

function validateServiceEnvironmentAuthority(
  serviceName,
  service,
  environment,
  violations,
) {
  const expected = expectedServiceEnvironment(serviceName, environment);
  const observedPresent = Object.hasOwn(service, "environment");
  if (!expected.valid
      || observedPresent !== expected.present
      || (expected.present && !sameFlatObject(service.environment, expected.value))) {
    violations.push(`${serviceName}:environment-authority`);
  }
}

function expectedControlCenterOidcIssuer(environment) {
  const domain = envOr(environment, "DOMAIN", "localhost.com");
  const authHost = envOr(environment, "AUTH_HOST", `auth.${domain}`);
  return envOr(
    environment,
    "CONTROL_CENTER_OIDC_ISSUER",
    `https://${authHost}/realms/platform`,
  );
}

function projectedSecurityValue(environment, projection) {
  return envOr(environment, projection.variable, projection.fallback);
}

function validProjectedSecurityValue(value, projection) {
  if (projection.allowed) return projection.allowed.includes(value);
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) return false;
  const numeric = Number(value);
  return Number.isSafeInteger(numeric)
    && numeric >= projection.integerMinimum
    && numeric <= projection.integerMaximum;
}

function mountMode(readOnly) {
  return readOnly === true ? "read-only" : "read-write";
}

function hostSensitiveSource(source) {
  return source === "/"
    || source === "/dev"
    || source.startsWith("/dev/")
    || source === "/proc"
    || source.startsWith("/proc/")
    || source === "/sys"
    || source.startsWith("/sys/")
    || source === "/run"
    || source.startsWith("/run/")
    || source === "/var/run"
    || source.startsWith("/var/run/")
    || source === "/var/lib/docker"
    || source.startsWith("/var/lib/docker/");
}

function pathWithinRoot(candidate, rootDirectory) {
  return candidate === rootDirectory || candidate.startsWith(`${rootDirectory}/`);
}

function filesystemPathAuthority(
  candidate,
  anchor,
  {
    expectedType,
    fileMode,
    requireNonempty = true,
  },
) {
  try {
    if (!path.isAbsolute(candidate) || !path.isAbsolute(anchor)) return false;
    const normalizedCandidate = path.resolve(candidate);
    const normalizedAnchor = path.resolve(anchor);
    if (candidate !== normalizedCandidate
        || anchor !== normalizedAnchor
        || !pathWithinRoot(normalizedCandidate, normalizedAnchor)) {
      return false;
    }
    const relative = path.relative(normalizedAnchor, normalizedCandidate);
    if (relative === ".." || relative.startsWith(`..${path.sep}`)) return false;
    const anchorStat = fs.lstatSync(normalizedAnchor);
    if (!anchorStat.isDirectory() || anchorStat.isSymbolicLink()) return false;
    const ownerUid = anchorStat.uid;
    const components = relative === "" ? [] : relative.split(path.sep);
    let current = normalizedAnchor;
    const paths = [current];
    for (const component of components) {
      if (component === "" || component === "." || component === "..") return false;
      current = path.join(current, component);
      paths.push(current);
    }
    for (let index = 0; index < paths.length; index += 1) {
      const currentStat = fs.lstatSync(paths[index]);
      const final = index === paths.length - 1;
      const mode = currentStat.mode & 0o7777;
      if (currentStat.isSymbolicLink()
          || currentStat.uid !== ownerUid
          || (mode & 0o7000) !== 0) {
        return false;
      }
      if (!final || expectedType === "directory") {
        if (!currentStat.isDirectory()
            || (mode & 0o500) !== 0o500
            || (mode & 0o022) !== 0) {
          return false;
        }
        continue;
      }
      if (expectedType !== "file"
          || !currentStat.isFile()
          || currentStat.nlink !== 1
          || (requireNonempty && currentStat.size < 1)
          || mode !== fileMode) {
        return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}

function sensitiveOrdinarySource(source, rootDirectory) {
  if (pathWithinRoot(source, rootDirectory)) return false;
  return CORE_SEMANTIC_POLICY.sensitiveSourcePrefixes.some((prefix) =>
    source === prefix || source.startsWith(`${prefix}/`));
}

function bindTargetType(target) {
  return CORE_SEMANTIC_POLICY.directoryBindTargets.includes(target)
    ? "directory"
    : "file";
}

function bindTargetFileMode(target) {
  return target === "/usr/local/bin/platform-postgres-entrypoint" ? 0o755 : 0o644;
}

function materializeBindRule(serviceName, rule, target, rootDirectory, environment) {
  if (rule.startsWith("root:")) {
    const resolved = path.resolve(rootDirectory, rule.slice("root:".length));
    return filesystemPathAuthority(resolved, rootDirectory, {
      expectedType: bindTargetType(target),
      fileMode: bindTargetFileMode(target),
    }) ? resolved : null;
  }
  if (rule.startsWith("sibling:")) {
    const variable = serviceName === "backup-scheduler" ? "PROJECT_SOURCE_DIR" : "PHP_PROJECTS_DIR";
    const source = envOr(environment, variable, "../src");
    const resolved = path.resolve(rootDirectory, source);
    const parentWorkspace = path.resolve(rootDirectory, "..");
    if (!pathWithinRoot(resolved, parentWorkspace)
        || resolved === parentWorkspace) {
      return null;
    }
    return filesystemPathAuthority(resolved, parentWorkspace, {
      expectedType: "directory",
    }) ? resolved : null;
  }
  return rule.startsWith("exact:") ? rule.slice("exact:".length) : null;
}

function bindSourceAllowed(serviceName, source, target, rootDirectory, environment) {
  const rules = CORE_SEMANTIC_POLICY.bindSourceRules[serviceName]?.[target] ?? [];
  return rules.some((rule) =>
    source === materializeBindRule(serviceName, rule, target, rootDirectory, environment));
}

function exactHostBindAllowed(serviceName, source, target, mode) {
  return CORE_SEMANTIC_POLICY.hostBindExceptions.some((entry) =>
    sameJson(entry, [serviceName, source, target, mode]));
}

function normalizedGrant(entry) {
  if (typeof entry === "string") return { source: entry, target: entry };
  if (!plainObject(entry)
      || !sameJson(Object.keys(entry).sort(), ["source", "target"])
      || typeof entry.source !== "string"
      || typeof entry.target !== "string") {
    return null;
  }
  return { source: entry.source, target: entry.target };
}

function validateServiceGrants(serviceName, service, violations) {
  const secretEntries = service.secrets ?? [];
  if (!Array.isArray(secretEntries)) {
    violations.push(`${serviceName}:secrets-shape`);
  } else {
    const grants = secretEntries.map(normalizedGrant);
    const sources = grants.filter(Boolean).map((grant) => grant.source).sort();
    const allowed = [...(CORE_SEMANTIC_POLICY.serviceSecretGrants[serviceName] ?? [])].sort();
    if (grants.some((grant) => grant === null)
        || grants.some((grant) => grant.target !== grant.source)
        || new Set(sources).size !== sources.length
        || !sameJson(sources, allowed)) {
      violations.push(`${serviceName}:secret-grants`);
    }
  }

  const configEntries = service.configs ?? [];
  if (!Array.isArray(configEntries)) {
    violations.push(`${serviceName}:configs-shape`);
  } else {
    const grants = configEntries.map(normalizedGrant);
    const allowed = CORE_SEMANTIC_POLICY.serviceConfigGrants[serviceName] ?? [];
    const grantKeys = grants.filter(Boolean).map((grant) => JSON.stringify(grant)).sort();
    const allowedKeys = allowed.map((grant) => JSON.stringify(grant)).sort();
    if (grants.some((grant) => grant === null)
        || new Set(grantKeys).size !== grants.length
        || !sameJson(grantKeys, allowedKeys)) {
      violations.push(`${serviceName}:config-grants`);
    }
  }
}

function normalizedPort(port) {
  if (!plainObject(port)) return null;
  const allowedKeys = ["host_ip", "mode", "protocol", "published", "target"];
  if (Object.keys(port).some((field) => !allowedKeys.includes(field))) return null;
  const published = Number(port.published);
  const target = Number(port.target);
  const protocol = String(port.protocol ?? "tcp");
  const hostIp = String(port.host_ip ?? "");
  if (!Number.isInteger(published) || published < 1 || published > 65535
      || !Number.isInteger(target) || target < 1 || target > 65535
      || !["tcp", "udp"].includes(protocol)
      || (Object.hasOwn(port, "mode") && port.mode !== "ingress")) {
    return null;
  }
  return { hostIp, protocol, published, target };
}

function parsedPublishedBind(value) {
  const match = /^(?:(.+):)?([1-9][0-9]{0,4})$/.exec(value);
  if (!match) return null;
  const published = Number(match[2]);
  if (published > 65535) return null;
  return { hostIp: match[1] ?? "", published };
}

function projectedPortRules(serviceName, environment) {
  if (serviceName === "docker-socket-proxy") {
    return [{
      hostIp: "127.0.0.1",
      protocol: "tcp",
      published: Number(envOr(environment, "DOCKER_SOCKET_PROXY_PORT", "2376")),
      target: 2375,
    }];
  }
  if (serviceName === "local-dns") {
    const hostIp = envOr(environment, "LOCAL_DNS_BIND", "192.168.1.164");
    if (!/^(?!0\.0\.0\.0$)(?!::$)[A-Za-z0-9.:[\]-]+$/.test(hostIp)) return null;
    return [
      { hostIp, protocol: "tcp", published: 53, target: 53 },
      { hostIp, protocol: "udp", published: 53, target: 53 },
    ];
  }
  if (serviceName === "waf") {
    const http = parsedPublishedBind(envOr(environment, "WAF_HTTP_BIND", "0.0.0.0:80"));
    const https = parsedPublishedBind(envOr(environment, "WAF_HTTPS_BIND", "0.0.0.0:443"));
    if (!http || !https) return null;
    return [
      { ...http, protocol: "tcp", target: 8080 },
      { ...https, protocol: "tcp", target: 8443 },
    ];
  }
  return CORE_SEMANTIC_POLICY.servicePortRules[serviceName] ?? [];
}

function validateServicePorts(serviceName, service, environment, violations) {
  const ports = service.ports ?? [];
  if (!Array.isArray(ports)) {
    violations.push(`${serviceName}:ports-shape`);
    return;
  }
  const normalized = ports.map(normalizedPort);
  const allowed = projectedPortRules(serviceName, environment);
  if (allowed === null) {
    violations.push(`${serviceName}:ports-policy`);
    return;
  }
  const portKey = (port) =>
    JSON.stringify([port.hostIp, port.protocol, port.published, port.target]);
  const normalizedKeys = normalized.filter(Boolean).map(portKey).sort();
  const allowedKeys = allowed.map(portKey).sort();
  if (normalized.some((port) => port === null)
      || !sameJson(normalizedKeys, allowedKeys)) {
    violations.push(`${serviceName}:ports`);
  }
}

function validateMount(serviceName, mount, rootDirectory, environment, violations) {
  if (!plainObject(mount)) {
    violations.push(`${serviceName}:volume-syntax`);
    return;
  }
  const keys = Object.keys(mount).sort();
  const allowedKeys = mount.read_only === undefined
    ? ["source", "target", "type"]
    : ["read_only", "source", "target", "type"];
  if (!sameJson(keys, allowedKeys)
      || typeof mount.source !== "string"
      || typeof mount.target !== "string") {
    violations.push(`${serviceName}:volume-shape`);
    return;
  }
  const mode = mountMode(mount.read_only);
  if (mount.type === "bind") {
    if (!mount.source.startsWith("/") || !mount.target.startsWith("/")) {
      violations.push(`${serviceName}:bind-path`);
      return;
    }
    if (hostSensitiveSource(mount.source)) {
      if (!exactHostBindAllowed(serviceName, mount.source, mount.target, mode)) {
        violations.push(`${serviceName}:host-bind`);
      }
      return;
    }
    const requiredMode = CORE_SEMANTIC_POLICY.bindTargets[serviceName]?.[mount.target];
    if (requiredMode !== mode
        || !bindSourceAllowed(serviceName, mount.source, mount.target, rootDirectory, environment)) {
      violations.push(
        serviceName === "project-router"
          && mount.target === "/run/platform/hosted-workloads.lock.json"
          ? `${serviceName}:workload-lock-identity-changed`
          : `${serviceName}:bind-authority`,
      );
    }
    return;
  }
  if (mount.type === "volume") {
    const target = CORE_SEMANTIC_POLICY.namedVolumeTargets[serviceName]?.[mount.source];
    if (target !== mount.target || mode !== "read-write") {
      violations.push(`${serviceName}:named-volume`);
    }
    return;
  }
  if (mount.type === "tmpfs") {
    if (mount.source !== "" || !mount.target.startsWith("/")) {
      violations.push(`${serviceName}:tmpfs-volume`);
    }
    return;
  }
  violations.push(`${serviceName}:volume-type`);
}

function mountKey(type, source, target, mode) {
  return JSON.stringify([type, source, target, mode]);
}

function expectedMountKeys(serviceName, rootDirectory, environment) {
  const expected = [];
  for (const [target, mode] of Object.entries(
    CORE_SEMANTIC_POLICY.bindTargets[serviceName] ?? {},
  )) {
    const rules = CORE_SEMANTIC_POLICY.bindSourceRules[serviceName]?.[target] ?? [];
    if (rules.length !== 1) return null;
    const source = materializeBindRule(
      serviceName,
      rules[0],
      target,
      rootDirectory,
      environment,
    );
    if (source === null) return null;
    expected.push(mountKey("bind", source, target, mode));
  }
  for (const [candidateService, source, target, mode] of
    CORE_SEMANTIC_POLICY.hostBindExceptions) {
    if (candidateService === serviceName) expected.push(mountKey("bind", source, target, mode));
  }
  for (const [source, target] of Object.entries(
    CORE_SEMANTIC_POLICY.namedVolumeTargets[serviceName] ?? {},
  )) {
    expected.push(mountKey("volume", source, target, "read-write"));
  }
  return expected.sort();
}

function observedMountKeys(service) {
  if (!Object.hasOwn(service, "volumes")) return [];
  if (!Array.isArray(service.volumes)) return null;
  return service.volumes.map((mount) => {
    if (!plainObject(mount)) return null;
    return mountKey(
      String(mount.type ?? ""),
      String(mount.source ?? ""),
      String(mount.target ?? ""),
      mountMode(mount.read_only),
    );
  }).sort();
}

function validateExactAuthorityShape(config, violations) {
  const authority = CORE_SEMANTIC_POLICY.exactAuthorityShape;
  if (!plainObject(authority)
      || !sameJson(Object.keys(config).sort(), authority.topLevelFields)) {
    violations.push("document:fields");
  }
  if (config.name !== "platform_infra_vps") violations.push("document:name");

  const expectedServiceNames = Object.keys(authority.serviceFields).sort();
  const observedServiceNames = Object.keys(config.services || {}).sort();
  if (!sameJson(observedServiceNames, expectedServiceNames)) {
    violations.push("services:exact-inventory");
  }
  const declaredFieldCount = Object.values(authority.serviceFields)
    .reduce((count, fields) => count + (Array.isArray(fields) ? fields.length : 0), 0);
  if (declaredFieldCount !== 482) violations.push("policy:service-field-count");
  for (const [serviceName, service] of Object.entries(config.services || {})) {
    const expectedFields = authority.serviceFields[serviceName];
    const expectedResources = authority.serviceResources[serviceName];
    if (!Array.isArray(expectedFields)
        || !plainObject(service)) {
      violations.push(`${serviceName}:service-shape-exact`);
      continue;
    }
    const observedFields = Object.keys(service).sort();
    for (const field of new Set([...expectedFields, ...observedFields])) {
      if (expectedFields.includes(field) !== observedFields.includes(field)) {
        violations.push(`${serviceName}:${field}`);
      }
    }
    if (!plainObject(expectedResources)
        || Object.entries(expectedResources).some(([field, expected]) =>
          !sameStructuredJson(service[field], expected))) {
      violations.push(`${serviceName}:resources-exact`);
    }
  }

  for (const [kind, fieldAuthority] of [
    ["network", authority.networkFields],
    ["volume", authority.volumeFields],
  ]) {
    const collection = config[`${kind}s`] || {};
    if (!plainObject(fieldAuthority)
        || !sameJson(Object.keys(collection).sort(), Object.keys(fieldAuthority).sort())) {
      violations.push(`${kind}s:exact-inventory`);
    }
    for (const [name, definition] of Object.entries(collection)) {
      if (!Array.isArray(fieldAuthority[name])
          || !plainObject(definition)
          || !sameJson(Object.keys(definition).sort(), fieldAuthority[name])) {
        violations.push(`${kind}:${name}:fields`);
      }
    }
  }
}

function validateTopLevelAuthority(config, rootDirectory, environment, violations) {
  for (const [configName, definition] of Object.entries(config.configs || {})) {
    const hosts = [];
    const placeholders = ["__PORTAL_HOST__", "__DOCS_HOST__", "__AUTH_HOST__"];
    const normalizedContent = typeof definition?.content === "string"
      ? definition.content.replace(/rule: Host\(`([^`]+)`\)/g, (_match, host) => {
        const placeholder = placeholders[hosts.length] ?? "__EXTRA_HOST__";
        hosts.push(host);
        return `rule: Host(\`${placeholder}\`)`;
      })
      : "";
    const domain = envOr(environment, "DOMAIN", "");
    const expectedHosts = [
      envOr(environment, "CONTROL_CENTER_HOST", envOr(environment, "ADMIN_HOST", `portal.${domain}`)),
      envOr(environment, "DOCS_HOST", `docs.${domain}`),
      envOr(environment, "AUTH_HOST", `auth.${domain}`),
    ];
    const hostsValid = domain.length > 0
      && expectedHosts.every((host) => /^[a-z0-9.-]+$/.test(host))
      && sameJson(hosts, expectedHosts);
    const expectedContent = `${(CORE_SEMANTIC_POLICY.configContentLines[configName] ?? []).join("\n")}`;
    if (!plainObject(definition)
        || !sameJson(Object.keys(definition).sort(), CORE_SEMANTIC_POLICY.topLevelAuthority.configFields)
        || !hostsValid
        || normalizedContent !== expectedContent) {
      violations.push(`config:${configName}:definition`);
    }
  }
  for (const [secretName, definition] of Object.entries(config.secrets || {})) {
    if (!plainObject(definition)) {
      violations.push(`secret:${secretName}:definition`);
      continue;
    }
    const relativeDefault = CORE_SEMANTIC_POLICY.secretFiles[secretName];
    const variable = CORE_SEMANTIC_POLICY.secretFileVariables[secretName];
    const expectedFile = variable === undefined
      ? relativeDefault
      : envOr(environment, variable, relativeDefault);
    const resolvedExpectedFile = path.resolve(rootDirectory, expectedFile);
    const secretsRoot = path.resolve(rootDirectory, "secrets");
    const safeSecretPath = pathWithinRoot(resolvedExpectedFile, secretsRoot)
      && filesystemPathAuthority(resolvedExpectedFile, rootDirectory, {
        expectedType: "file",
        fileMode: secretName === "alertmanager_webhook_token" ? 0o640 : 0o600,
      });
    if (!sameJson(Object.keys(definition).sort(), ["file"])
        || relativeDefault === undefined
        || !safeSecretPath
        || definition.file !== resolvedExpectedFile) {
      violations.push(`secret:${secretName}:authority`);
    }
  }
  for (const [volumeName, definition] of Object.entries(config.volumes || {})) {
    const externalExpected = CORE_SEMANTIC_POLICY.externalVolumeNames.includes(volumeName);
    let expectedPhysicalName = CORE_SEMANTIC_POLICY.physicalVolumeNames[volumeName];
    if (volumeName === "enterprise_mariadb_data") {
      expectedPhysicalName = envOr(environment, "MARIADB_DATA_VOLUME", expectedPhysicalName);
    } else if (volumeName === "backup_scheduler_logs") {
      expectedPhysicalName = envOr(environment, "BACKUP_SCHEDULER_LOG_VOLUME", expectedPhysicalName);
    }
    const physicalNameValid = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(expectedPhysicalName)
      && (volumeName === "enterprise_mariadb_data"
        ? expectedPhysicalName.startsWith("enterprise_")
        : true)
      && (volumeName === "backup_scheduler_logs"
        ? expectedPhysicalName.startsWith("platform_")
        : true);
    if (!plainObject(definition)
        || Object.keys(definition).some((field) =>
          !CORE_SEMANTIC_POLICY.topLevelAuthority.volumeFields.includes(field))
        || !physicalNameValid
        || definition.name !== expectedPhysicalName
        || (externalExpected
          ? definition.external !== true
          : (Object.hasOwn(definition, "external") && definition.external !== false))
        || (Object.hasOwn(definition, "labels") && !plainObject(definition.labels))) {
      violations.push(`volume:${volumeName}:authority`);
    }
  }
  const physicalVolumeNames = Object.values(config.volumes || {})
    .map((definition) => definition?.name)
    .filter((name) => typeof name === "string");
  if (new Set(physicalVolumeNames).size !== physicalVolumeNames.length) {
    violations.push("volumes:physical-name-collision");
  }
  for (const [networkName, definition] of Object.entries(config.networks || {})) {
    const internalExpected = networkName !== "enterprise_net" && networkName !== "platform_egress";
    const externalExpected = networkName === "enterprise_net";
    const networkPrefix = envOr(environment, "PLATFORM_NETWORK_PREFIX", "platform_infra_vps");
    let expectedPhysicalName = CORE_SEMANTIC_POLICY.physicalNetworkNames[networkName];
    if (networkName.startsWith("platform_") && networkName !== "platform_docker_control") {
      expectedPhysicalName = `${networkPrefix}_${networkName.slice("platform_".length)}`;
    }
    if (!/^[a-z0-9][a-z0-9_-]{0,62}$/.test(networkPrefix)
        || !plainObject(definition)
        || Object.keys(definition).some((field) =>
          !CORE_SEMANTIC_POLICY.topLevelAuthority.networkFields.includes(field))
        || definition.name !== expectedPhysicalName
        || (Object.hasOwn(definition, "driver") && definition.driver !== "bridge")
        || (internalExpected
          ? definition.internal !== true
          : (Object.hasOwn(definition, "internal") && definition.internal !== false))
        || (Object.hasOwn(definition, "attachable") && definition.attachable !== false)
        || (Object.hasOwn(definition, "enable_ipv4") && definition.enable_ipv4 !== true)
        || (Object.hasOwn(definition, "enable_ipv6") && definition.enable_ipv6 !== false)
        || !sameJson(definition.labels ?? {}, CORE_SEMANTIC_POLICY.networkLabels[networkName])
        || (externalExpected
          ? definition.external !== true
          : Object.hasOwn(definition, "external"))) {
      violations.push(`network:${networkName}:authority`);
    }
  }
}

function validateCoreCapabilityCeiling(config, rootDirectory, environment) {
  const violations = [];
  if (!plainObject(config) || !plainObject(config.services)) return ["config-shape"];
  for (const kind of ["configs", "networks", "secrets", "volumes"]) {
    if (!plainObject(config[kind])) violations.push(`${kind}:shape`);
  }
  validateExactAuthorityShape(config, violations);
  validateTopLevelAuthority(config, rootDirectory, environment, violations);
  const allowedServiceFields = new Set(CORE_SEMANTIC_POLICY.allowedServiceFields);
  for (const [serviceName, service] of Object.entries(config.services)) {
    if (!plainObject(service)) {
      violations.push(`${serviceName}:service-shape`);
      continue;
    }
    const unknownFields = Object.keys(service)
      .filter((field) => !allowedServiceFields.has(field))
      .sort();
    if (unknownFields.length > 0) violations.push(`${serviceName}:service-fields`);
    if (service.container_name !== CORE_SEMANTIC_POLICY.serviceContainerNames[serviceName]) {
      violations.push(`${serviceName}:container-name`);
    }
    if (service.restart !== CORE_SEMANTIC_POLICY.serviceRestartPolicies[serviceName]) {
      violations.push(`${serviceName}:restart`);
    }
    const expectedProfiles = CORE_SEMANTIC_POLICY.serviceProfiles[serviceName];
    if (expectedProfiles === undefined) {
      if (Object.hasOwn(service, "profiles")) violations.push(`${serviceName}:profiles`);
    } else if (!sameJson(service.profiles, expectedProfiles)) {
      violations.push(`${serviceName}:profiles`);
    }
    const expectedPid = CORE_SEMANTIC_POLICY.exactExceptions.pid[serviceName];
    if (expectedPid === undefined) {
      if (Object.hasOwn(service, "pid")) violations.push(`${serviceName}:pid`);
    } else if (service.pid !== expectedPid) {
      violations.push(`${serviceName}:pid`);
    }
    const expectedNetworkMode =
      CORE_SEMANTIC_POLICY.exactExceptions.networkMode[serviceName];
    if (expectedNetworkMode === undefined) {
      if (Object.hasOwn(service, "network_mode")) {
        violations.push(`${serviceName}:network-mode`);
      }
    } else if (service.network_mode !== expectedNetworkMode) {
      violations.push(`${serviceName}:network-mode`);
    }
    const expectedDependencies = CORE_SEMANTIC_POLICY.serviceDependencies[serviceName] ?? [];
    if (expectedDependencies.length === 0) {
      if (Object.hasOwn(service, "depends_on")) {
        violations.push(`${serviceName}:depends-on`);
      }
    } else if (!plainObject(service.depends_on)
        || !sameJson(Object.keys(service.depends_on).sort(), expectedDependencies)
        || expectedDependencies.some((dependency) => {
          const definition = service.depends_on[dependency];
          return !plainObject(definition)
            || !sameJson(
              Object.keys(definition).sort(),
              ["condition", "required", "restart"],
            )
            || definition.condition !== "service_healthy"
            || definition.required !== true
            || definition.restart !== false;
        })) {
      violations.push(`${serviceName}:depends-on`);
    }
    validateServiceGrants(serviceName, service, violations);
    validateServicePorts(serviceName, service, environment, violations);
    const expectedProcess = structuredClone(CORE_SEMANTIC_POLICY.serviceProcessModel[serviceName]);
    if (serviceName === "prometheus" && expectedProcess) {
      expectedProcess.command[2] =
        `--storage.tsdb.retention.time=${envOr(environment, "PROMETHEUS_RETENTION_TIME", "15d")}`;
    }
    if (!expectedProcess
        || !sameJson(service.command ?? null, expectedProcess.command)
        || !sameJson(service.entrypoint ?? null, expectedProcess.entrypoint)) {
      violations.push(`${serviceName}:process-model`);
    }
    const imageVariable = CORE_SEMANTIC_POLICY.serviceImageVariables[serviceName];
    const expectedImage = envOr(
      environment,
      imageVariable,
      CORE_SEMANTIC_POLICY.serviceImages[serviceName],
    );
    const localImage = CORE_SEMANTIC_POLICY.serviceImages[serviceName]?.endsWith(":local")
      && expectedImage === CORE_SEMANTIC_POLICY.serviceImages[serviceName];
    if (expectedImage === undefined
        || (!localImage && !/@sha256:[a-f0-9]{64}$/.test(expectedImage))
        || service.image !== expectedImage) {
      violations.push(`${serviceName}:image`);
    }
    const expectedDockerfile = CORE_SEMANTIC_POLICY.buildDockerfiles[serviceName];
    if (expectedDockerfile === undefined) {
      if (Object.hasOwn(service, "build")) violations.push(`${serviceName}:build`);
    } else {
      const nodeImage = envOr(
        environment,
        "NODE_IMAGE",
        CORE_SEMANTIC_POLICY.serviceImages["project-router"],
      );
      if (!plainObject(service.build)
          || !sameJson(Object.keys(service.build).sort(), ["args", "context", "dockerfile"])
          || service.build.context !== rootDirectory
          || service.build.dockerfile !== expectedDockerfile
          || !sameJson(service.build.args, { NODE_IMAGE: nodeImage })) {
        violations.push(`${serviceName}:build`);
      }
    }
    validateServiceEnvironmentAuthority(serviceName, service, environment, violations);
    const serviceEnvironment = plainObject(service.environment) ? service.environment : {};
    if (serviceName === "docker-socket-proxy"
        && !sameFlatObject(serviceEnvironment, CORE_SEMANTIC_POLICY.proxyEnvironment)) {
      violations.push(`${serviceName}:environment`);
    }
    for (const key of CORE_SEMANTIC_POLICY.forbiddenInjectionEnvironmentKeys) {
      if (Object.hasOwn(serviceEnvironment, key)) {
        violations.push(`${serviceName}:environment-injection-${key}`);
      }
    }
    if (serviceName === "control-center") {
      for (const [key, value] of Object.entries(
        CORE_SEMANTIC_POLICY.controlCenterFixedSecurityEnvironment,
      )) {
        if (serviceEnvironment[key] !== value) {
          violations.push(`${serviceName}:environment-${key}`);
        }
      }
      if (serviceEnvironment.CONTROL_CENTER_OIDC_ISSUER
          !== expectedControlCenterOidcIssuer(environment)) {
        violations.push(`${serviceName}:environment-CONTROL_CENTER_OIDC_ISSUER`);
      }
    }
    if (serviceName === "waf") {
      for (const [key, value] of Object.entries(
        CORE_SEMANTIC_POLICY.wafFixedSecurityEnvironment,
      )) {
        if (serviceEnvironment[key] !== value) violations.push(`${serviceName}:environment-${key}`);
      }
      for (const [key, projection] of Object.entries(
        CORE_SEMANTIC_POLICY.wafProjectedSecurityEnvironment,
      )) {
        const expectedValue = projectedSecurityValue(environment, projection);
        if (!validProjectedSecurityValue(expectedValue, projection)
            || serviceEnvironment[key] !== expectedValue) {
          violations.push(`${serviceName}:environment-${key}`);
        }
      }
      if (Number(serviceEnvironment.DETECTION_PARANOIA)
          < Number(serviceEnvironment.BLOCKING_PARANOIA)) {
        violations.push(`${serviceName}:environment-paranoia-order`);
      }
    }
    if (serviceName === "backup-scheduler") {
      const allowedEnableKeys =
        Object.keys(CORE_SEMANTIC_POLICY.backupSchedulerBooleanEnvironment).sort();
      for (const [key, projection] of Object.entries(
        CORE_SEMANTIC_POLICY.backupSchedulerBooleanEnvironment,
      )) {
        const expectedValue = projectedSecurityValue(environment, projection);
        if (!["false", "true"].includes(expectedValue)
            || serviceEnvironment[key] !== expectedValue) {
          violations.push(`${serviceName}:environment-${key}`);
        }
      }
      const observedEnableKeys = Object.keys(serviceEnvironment)
        .filter((key) => key.startsWith("BACKUP_SCHEDULER_ENABLE_"))
        .sort();
      if (!sameJson(observedEnableKeys, allowedEnableKeys)) {
        violations.push(`${serviceName}:environment-enable-inventory`);
      }
    }
    const requiresDefaultLogging =
      CORE_SEMANTIC_POLICY.servicesWithDefaultLogging.includes(serviceName);
    if (requiresDefaultLogging) {
      if (!plainObject(service.logging)
          || !sameJson(Object.keys(service.logging).sort(), ["driver", "options"])
          || service.logging.driver !== "json-file"
          || !sameFlatObject(service.logging.options, { "max-size": "10m", "max-file": "5" })) {
        violations.push(`${serviceName}:logging`);
      }
    } else if (Object.hasOwn(service, "logging")) {
      violations.push(`${serviceName}:logging`);
    }
    const expectedHealthcheck = CORE_SEMANTIC_POLICY.serviceHealthchecks[serviceName];
    if (!sameStructuredJson(service.healthcheck, expectedHealthcheck)) {
      violations.push(`${serviceName}:healthcheck-exact`);
    }
    if (Object.hasOwn(service, "labels")
        && (!plainObject(service.labels) || Object.keys(service.labels).length !== 0)) {
      violations.push(`${serviceName}:labels`);
    }
    if (!sameJson(service.tmpfs ?? [], CORE_SEMANTIC_POLICY.tmpfsRules[serviceName] ?? [])) {
      violations.push(`${serviceName}:tmpfs`);
    }

    if (Object.hasOwn(service, "group_add")) {
      const normalized = Array.isArray(service.group_add) ? service.group_add.map(String) : [];
      const expectedGroupAdd = serviceName === "alertmanager"
        ? [envOr(environment, "ALERTMANAGER_SECRET_GID", "1000")]
        : CORE_SEMANTIC_POLICY.exactExceptions.groupAdd[serviceName];
      if (!sameJson(normalized, expectedGroupAdd)) {
        violations.push(`${serviceName}:group-add`);
      }
    }
    if (serviceName === "alertmanager"
        && (
          !/^[1-9][0-9]{0,9}$/.test(envOr(environment, "ALERTMANAGER_SECRET_GID", "1000"))
          || !sameJson(
            Array.isArray(service.group_add) ? service.group_add.map(String) : [],
            [envOr(environment, "ALERTMANAGER_SECRET_GID", "1000")],
          )
        )) {
      violations.push(`${serviceName}:required-group-add`);
    }
    if (Object.hasOwn(service, "cap_drop")
        && !sameJson(service.cap_drop, ["ALL"])) {
      violations.push(`${serviceName}:cap-drop`);
    }
    if (Object.hasOwn(service, "security_opt")
        && !sameJson(service.security_opt, ["no-new-privileges:true"])) {
      violations.push(`${serviceName}:security-opt`);
    }
    if (CORE_SEMANTIC_POLICY.requiredServiceControls.securityOpt.includes(serviceName)
        && !sameJson(service.security_opt, ["no-new-privileges:true"])) {
      violations.push(`${serviceName}:required-security-opt`);
    }
    if (CORE_SEMANTIC_POLICY.requiredServiceControls.capDropAll.includes(serviceName)
        && !sameJson(service.cap_drop, ["ALL"])) {
      violations.push(`${serviceName}:required-cap-drop`);
    }
    if (CORE_SEMANTIC_POLICY.requiredServiceControls.readOnly.includes(serviceName)
        && service.read_only !== true) {
      violations.push(`${serviceName}:required-read-only`);
    }
    const expectedUser = CORE_SEMANTIC_POLICY.requiredServiceControls.numericUsers[serviceName];
    if (expectedUser !== undefined && service.user !== expectedUser) {
      violations.push(`${serviceName}:required-user`);
    }
    if (Object.hasOwn(service, "read_only") && service.read_only !== true) {
      violations.push(`${serviceName}:read-only`);
    }
    if (Object.hasOwn(service, "user")
        && !/^[1-9][0-9]{0,9}(?::[1-9][0-9]{0,9})?$/.test(String(service.user))) {
      violations.push(`${serviceName}:user`);
    }
    if (Object.hasOwn(service, "memswap_limit")
        && Number(service.memswap_limit) !== Number(service.mem_limit)) {
      violations.push(`${serviceName}:swap`);
    }
    if (Object.hasOwn(service, "blkio_config")
        && !sameJson(Object.keys(service.blkio_config || {}).sort(), ["weight"])) {
      violations.push(`${serviceName}:blkio`);
    }
    if (Object.hasOwn(service, "ulimits")) {
      const nofile = service.ulimits?.nofile;
      const soft = Number(nofile?.soft);
      const hard = Number(nofile?.hard);
      if (!plainObject(service.ulimits)
          || !sameJson(Object.keys(service.ulimits).sort(), ["nofile"])
          || !plainObject(nofile)
          || !sameJson(Object.keys(nofile).sort(), ["hard", "soft"])
          || !Number.isInteger(soft)
          || !Number.isInteger(hard)
          || soft < 1024
          || hard < soft
          || hard > 65536) {
        violations.push(`${serviceName}:ulimits`);
      }
    }
    if (Object.hasOwn(service, "networks") && plainObject(service.networks)) {
      for (const attachment of Object.values(service.networks)) {
        if (attachment !== null
            && (!plainObject(attachment) || Object.keys(attachment).length !== 0)) {
          violations.push(`${serviceName}:network-attachment`);
          break;
        }
      }
    }
    const networkAttachments = service.networks ?? {};
    const attachedNetworks = Array.isArray(networkAttachments)
      ? networkAttachments.map(String)
      : Object.keys(networkAttachments);
    const allowedNetworks = CORE_SEMANTIC_POLICY.serviceNetworks[serviceName] ?? [];
    if ((!Array.isArray(networkAttachments) && !plainObject(networkAttachments))
        || new Set(attachedNetworks).size !== attachedNetworks.length
        || !sameJson([...attachedNetworks].sort(), allowedNetworks)) {
      violations.push(`${serviceName}:network-membership`);
    }
    if (Object.hasOwn(service, "volumes")) {
      if (!Array.isArray(service.volumes)) {
        violations.push(`${serviceName}:volumes-shape`);
      } else {
        for (const mount of service.volumes) {
          validateMount(serviceName, mount, rootDirectory, environment, violations);
        }
      }
    }
    const expectedMounts = expectedMountKeys(serviceName, rootDirectory, environment);
    const observedMounts = observedMountKeys(service);
    if (expectedMounts === null
        || observedMounts === null
        || observedMounts.some((entry) => entry === null)
        || !sameJson(observedMounts, expectedMounts)) {
      violations.push(`${serviceName}:mount-inventory`);
    }
  }
  return violations;
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function parseArguments(argv) {
  if (argv.length !== 8
      || argv[0] !== "--root"
      || argv[2] !== "--lock"
      || argv[4] !== "--config"
      || argv[6] !== "--env") {
    throw new Error("usage");
  }
  return {
    rootDirectory: fs.realpathSync.native(argv[1]),
    lockPath: argv[3],
    configPath: argv[5],
    environmentPath: argv[7],
  };
}

export function validateNoHostedCoreAuthority(lock, config, rootDirectory, environment = new Map()) {
  const binding = lock?.coreSemanticPolicy;
  if (!plainObject(binding)
      || !sameJson(Object.keys(binding).sort(), ["schema", "sha256"])
      || binding.schema !== CORE_SEMANTIC_POLICY_SCHEMA
      || binding.sha256 !== coreSemanticPolicySha256) {
    return ["policy-binding"];
  }
  const runtimeReport = evaluateRuntimeIsolation(config, {
    projectName: lock.projectName,
    protectedResourceNames: lock.protectedResourceNames,
    protectedNetworkNames: lock.protectedResourceNames?.networks,
  });
  const violations = validateCoreCapabilityCeiling(config, rootDirectory, environment);
  if (runtimeReport.status !== "passed") violations.unshift("runtime-isolation");
  return [...new Set(violations)];
}

function main() {
  try {
    const {
      rootDirectory,
      lockPath,
      configPath,
      environmentPath,
    } = parseArguments(process.argv.slice(2));
    const violations = validateNoHostedCoreAuthority(
      readJson(lockPath),
      readJson(configPath),
      rootDirectory,
      parseDotenv(fs.readFileSync(environmentPath, "utf8")),
    );
    if (violations.length > 0) {
      process.stderr.write(`no-hosted semantic authority rejected: ${violations.join(",")}\n`);
      process.exitCode = 65;
    }
  } catch {
    process.stderr.write("no-hosted semantic authority input invalid\n");
    process.exitCode = 65;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) main();
