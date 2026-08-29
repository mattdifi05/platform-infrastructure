#!/usr/bin/python3 -I
"""Fail-closed V1 LOCAL_PRIVATE exact-release reconciler.

This program is deliberately narrower than a deployment framework.  It has
four fixed operations (prepare, apply, abort and evidence), accepts no plan or
path from the caller, and never performs a project-wide Compose ``up``.
``prepare`` binds a clean github/main checkout to an immutable release model;
``apply`` consumes only that model and the controller's reconciliation marker;
``abort`` rolls back the still-reversible Docker transaction; and ``evidence``
commits the transaction and emits the controller's canonical runtime evidence.
"""

from __future__ import annotations

import base64
import binascii
import fcntl
import copy
import grp
import hashlib
import http.client
import ipaddress
import json
import os
import re
import secrets
import select
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


STATE_DIR = "/var/lib/platform-infrastructure/v1/local-private"
BOOTSTRAP_BRIDGE_RECEIPT_FILE = "/var/lib/platform-infrastructure/v1/bootstrap-bridge-receipt.json"
BOOTSTRAP_CONTROL_RECEIPT_FILE = "/var/lib/platform-infrastructure/v1/bootstrap-control-artifact-receipt.json"
INSTALL_RECEIPTS_DIR = "/var/lib/platform-infrastructure/v1/install-receipts"
PREDEPLOY_DIR = "/var/lib/platform-infrastructure/v1/predeploy/current"
AUTHORITY = f"{STATE_DIR}/exact-release-authority.json"
AUTHORITY_ARCHIVE_DIR = f"{STATE_DIR}/release-authorities"
RENDER = f"{STATE_DIR}/exact-compose-render.json"
RENDER_ENV = f"{STATE_DIR}/exact-compose.env"
SOURCE_ARCHIVE = f"{PREDEPLOY_DIR}/exact-source-archive.tar"
INSTALL_CHECKPOINT = f"{PREDEPLOY_DIR}/install-checkpoint.json"
LOCAL_CHECKPOINT = f"{PREDEPLOY_DIR}/local-private-checkpoint.json"
SCHEDULER_RECOVERY_EXPORT = f"{PREDEPLOY_DIR}/scheduler-recovery-image.tar"
RECONCILIATION = f"{STATE_DIR}/reconciliation.json"
JOURNAL = f"{STATE_DIR}/reconcile-journal.json"
RUNTIME_EVIDENCE = f"{PREDEPLOY_DIR}/runtime-inventory-evidence.json"

VALIDATION_LANE_FILE = f"{STATE_DIR}/validation-lane.json"
VALIDATION_CHECKPOINT_FILE = f"{PREDEPLOY_DIR}/local-private-checkpoint-validation.json"
VALIDATION_RUNTIME_EVIDENCE_FILE = f"{PREDEPLOY_DIR}/runtime-inventory-evidence-validation.json"
VALIDATION_LANE_SCHEMA = "platform.v1-local-private-validation-lane/v1"
VALIDATION_CHECKPOINT_SCHEMA = "platform.v1-local-private-predeploy-checkpoint-validation/v1"
VALIDATION_LANE_TTL_SECONDS = 24 * 3600
MUTATION_EVIDENCE_DIR = f"{STATE_DIR}/data-mutation-evidence"
SECRET_DIR = "/home/platform_infrastructure/platform-infrastructure/secrets"
DEPLOYMENT_REPO = "/home/platform_infrastructure/platform-infrastructure"
DEPLOYMENT_ENV = f"{DEPLOYMENT_REPO}/.env"
DATABASE_SECRET = f"{SECRET_DIR}/control_center_database_url.txt"
BOOTSTRAP_SECRET = f"{SECRET_DIR}/control_center_first_configuration_bootstrap_token.txt"
KEYCLOAK_CLIENT_SECRET = f"{SECRET_DIR}/control_center_first_configuration_keycloak_client_secret.txt"
CONFIDENTIAL_BACKUP_PASSPHRASE = f"{STATE_DIR}/confidential-backup-passphrase"
RESTIC_PASSWORD = f"{SECRET_DIR}/restic_password.txt"
RCLONE_CONFIG = f"{SECRET_DIR}/rclone/rclone.conf"
SECRET_MANAGER_STORE = f"{SECRET_DIR}/infra-secret-manager-store.json"
SECRET_MANAGER_MASTER_KEY = f"{SECRET_DIR}/infra-secret-manager-master.key"
SECRET_MANAGER_AUDIT_LOG = f"{SECRET_DIR}/infra-secret-manager-audit.log"
SECRET_PREP_STAGE = "/run/platform-v1-local-private-secret-prep"
PROJECT_SOURCE_ROOT = "/home/platform_infrastructure/src"
PROJECT_STATE_ROOT = f"{DEPLOYMENT_REPO}/projects-portal/state"
PROJECTS_PORTAL_ROOT = f"{DEPLOYMENT_REPO}/projects-portal"
TRAEFIK_ROOT = f"{DEPLOYMENT_REPO}/traefik"
CERTIFICATES_ROOT = f"{DEPLOYMENT_REPO}/traefik/certs"
LOCAL_CA_CERTIFICATE = f"{CERTIFICATES_ROOT}/ca.pem"
LOCAL_CERTIFICATE = f"{CERTIFICATES_ROOT}/local-cert.pem"
LOCAL_PRIVATE_KEY = f"{CERTIFICATES_ROOT}/local-key.pem"
BACKUP_SIGNING_KEYS = f"{SECRET_DIR}/backup_signing_keys.txt"
ROLLBACK_SPEC_DIR = f"{STATE_DIR}/rollback-specs"
ABORT_RECORD = f"{STATE_DIR}/reconciliation-abort-record.json"
ABORT_RECORD_ARCHIVE_DIR = f"{STATE_DIR}/aborted-reconciliations"
JOURNAL_ARCHIVE_DIR = f"{STATE_DIR}/reconcile-journals"
# Every mutating V1 participant acquires the shared transaction lock first;
# this reconciler then acquires only its own local lock. Controller/installer
# use the same shared-first ordering with their distinct local locks.
SHARED_LOCK = "/run/lock/platform-v1-local-private-transaction.lock"
LOCK = "/run/lock/platform-v1-local-private-reconcile.lock"
ACTIVE_RECEIPT = f"{STATE_DIR}/active-receipt.json"
STATE_FILE = f"{STATE_DIR}/state.json"

CONTROLLER = "/usr/local/libexec/platform-v1-local-private-control"
INSTALLER = "/usr/local/libexec/platform-v1-brownfield-install-consumer"
RECONCILER = "/usr/local/libexec/platform-v1-local-private-reconcile"
UNIT = "/etc/systemd/system/platform-v1-local-private-control.service"
SUDOERS = "/etc/sudoers.d/platform-v1-local-private-control"
DOCKER = "/usr/bin/docker"
GIT = "/usr/bin/git"
NODE = "/usr/bin/node"
SYSTEMCTL = "/usr/bin/systemctl"
OPENSSL = "/usr/bin/openssl"
SUPERVISOR_UNIT = "platform-v1-local-private-control.service"

TEST_ROOT_ENV = "PLATFORM_V1_RECONCILE_TEST_ROOT"
TEST_REPO_ENV = "PLATFORM_V1_RECONCILE_TEST_REPO"
TEST_DOCKER_ENV = "PLATFORM_V1_RECONCILE_TEST_DOCKER"
TEST_GIT_ENV = "PLATFORM_V1_RECONCILE_TEST_GIT"
TEST_NODE_ENV = "PLATFORM_V1_RECONCILE_TEST_NODE"
TEST_CURL_ENV = "PLATFORM_V1_RECONCILE_TEST_CURL"
TEST_SYSTEMCTL_ENV = "PLATFORM_V1_RECONCILE_TEST_SYSTEMCTL"
TEST_OPENSSL_ENV = "PLATFORM_V1_RECONCILE_TEST_OPENSSL"

SECRET_MANAGER_NEW_REQUIRED = (
    "control_center_vault_keys",
    "docker_action_backup_catalog",
    "docker_action_backup_job_execute",
    "docker_action_backup_offsite_sync",
    "docker_action_backup_prune_apply",
    "docker_action_backup_prune_plan",
    "docker_action_evidence_runtime_snapshot",
    "docker_action_restore_drill_full",
    "docker_action_runtime_intent_trust_key",
)
SECRET_MANAGER_EXISTING_PLATFORM = (
    "alertmanager_webhook_token",
    "backup_signing_keys",
    "grafana_admin_password",
    "keycloak_admin_password",
    "keycloak_db_password",
    "mariadb_root_password",
    "minio_root_password",
    "nats_password",
    "phpmyadmin_control_password",
    "postgres_superuser_password",
    "projects_gateway_signing_keys",
    "redis_password",
    "smtp_password",
)
SECRET_MANAGER_EXISTING_VAULT = (
    "app_db_password",
    "cloudflare_turnstile_secret_key",
    "database_url",
    "github_token",
    "hash_pepper_keys",
    "nats_url",
    "session_secret",
    "session_signing_keys",
)
SECRET_MANAGER_EXISTING = tuple(sorted(SECRET_MANAGER_EXISTING_PLATFORM + SECRET_MANAGER_EXISTING_VAULT))
SECRET_MANAGER_COMPLETE = tuple(sorted(SECRET_MANAGER_EXISTING + SECRET_MANAGER_NEW_REQUIRED))

AUTHORITY_SCHEMA = "platform.v1-local-private-exact-release-authority/v1"
RECONCILIATION_SCHEMA = "platform.v1-local-private-reconciliation/v1"
JOURNAL_SCHEMA = "platform.v1-local-private-reconcile-journal/v1"
RUNTIME_EVIDENCE_SCHEMA = "platform.v1-local-private-reconciliation-runtime/v1"
MUTATION_EVIDENCE_SCHEMA = "platform.v1-local-private-reconciliation-data-evidence/v1"
ROLLBACK_SPEC_SCHEMA = "platform.v1-local-private-container-rollback-spec/v1"
ABORT_RECORD_SCHEMA = "platform.v1-local-private-reconciliation-abort-record/v1"
DOCKER_SOCKET = "/var/run/docker.sock"
MAX_JSON = 4 * 1024 * 1024
MAX_AUTHORITY = 128 * 1024
MAX_ARCHIVE = 1024 * 1024 * 1024
MAX_RECOVERY_EXPORT = 4 * 1024 * 1024 * 1024
MAX_EXECUTOR_REQUEST = 32 * 1024 * 1024
MAX_EXECUTOR_RESPONSE = 96 * 1024 * 1024
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
COMMIT_RE = re.compile(r"^[a-f0-9]{40}$")
IMAGE_ID_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
DIGEST_REFERENCE_RE = re.compile(r"^[^@\s]+@sha256:[a-f0-9]{64}$")
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
RUN_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$")
EVIDENCE_LOGICAL_KEYS = (
    "anniversary", "fiplatform", "matthewdifilippo", "opstudents", "public", "stexor", "stream", "workcalendar",
    "pg-stexor", "pg-keycloak", "mariadb", "minio", "keycloak-config", "confidential",
)
RESTORE_MODE_BY_LOGICAL_KEY = {
    **{key: "SAFE_TMPFS_TYPED_ARCHIVE_EXTRACT" for key in EVIDENCE_LOGICAL_KEYS[:8]},
    "pg-stexor": "DIGEST_PINNED_NETWORK_NONE_READ_ONLY_TMPFS_POSTGRES",
    "pg-keycloak": "DIGEST_PINNED_NETWORK_NONE_READ_ONLY_TMPFS_POSTGRES",
    "mariadb": "DISPOSABLE_NETWORK_NONE_MARIADB",
    "minio": "DISPOSABLE_NETWORK_NONE_VOLUME_MINIO",
    "keycloak-config": "READ_ONLY_CONFIG_JSON_KEYCLOAK",
    "confidential": "GPG_DECRYPT_TMPFS_CONTENT_METADATA_VERIFY",
}
CHECKPOINT_EVIDENCE_PATHS = {
    "logicalBackupEvidenceSha256": f"{PREDEPLOY_DIR}/logical-backup-evidence.json",
    "offHostBackupEvidenceSha256": f"{PREDEPLOY_DIR}/offhost-backup-evidence.json",
    "restoreEvidenceSha256": f"{PREDEPLOY_DIR}/restore-evidence.json",
    "runtimeInventorySha256": RUNTIME_EVIDENCE,
    "secretsBackupEvidenceSha256": f"{PREDEPLOY_DIR}/secrets-backup-evidence.json",
}

HISTORIC_CONTAINERS = (
    "enterprise-alertmanager", "enterprise-backend", "enterprise-backup-scheduler",
    "enterprise-cadvisor", "enterprise-control-center", "enterprise-grafana",
    "enterprise-keycloak", "enterprise-local-dns", "enterprise-local-registry",
    "enterprise-loki", "enterprise-minio", "enterprise-nats", "enterprise-node-exporter",
    "enterprise-postgres", "enterprise-project-router", "enterprise-prometheus",
    "enterprise-promtail", "enterprise-redis", "enterprise-traefik", "enterprise-waf",
    "enterprise-web", "enterprise-worker-jobs", "enterprise-worker-notifications",
    "mariadb", "node-account", "node-opstudents", "node-ui", "php-anniversary",
    "php-apache", "php-fiplatform", "php-matthewdifilippo", "php-stream",
    "php-workcalendar", "phpmyadmin", "phppgadmin",
)
LEGACY_ALERT_DISPATCHER = "enterprise-alert-dispatcher"
CANONICAL_ALERT_DISPATCHER = "enterprise-platform-alert-dispatcher"
BROKER_AUTH_BOOTSTRAP = "enterprise-broker-auth-bootstrap"
CANONICAL_CONTAINERS = tuple(sorted((
    *(name for name in HISTORIC_CONTAINERS if name != "enterprise-backup-scheduler"),
    BROKER_AUTH_BOOTSTRAP,
    CANONICAL_ALERT_DISPATCHER,
)))
MANAGED_CONTAINER_BY_SERVICE = {
    "alertmanager": "enterprise-alertmanager",
    "backup-scheduler": "enterprise-backup-scheduler",
    "broker-auth-bootstrap": BROKER_AUTH_BOOTSTRAP,
    "control-center": "enterprise-control-center",
    "docker-action-activation-sidecar": "enterprise-docker-action-activation-sidecar",
    "docker-action-broker": "enterprise-docker-action-broker",
    "grafana": "enterprise-grafana",
    "keycloak": "enterprise-keycloak",
    "loki": "enterprise-loki",
    "mariadb": "mariadb",
    "minio": "enterprise-minio",
    "nats": "enterprise-nats",
    "platform-alert-dispatcher": CANONICAL_ALERT_DISPATCHER,
    "postgres": "enterprise-postgres",
    "project-router": "enterprise-project-router",
    "prometheus": "enterprise-prometheus",
    "promtail": "enterprise-promtail",
    "redis": "enterprise-redis",
    "traefik": "enterprise-traefik",
    "waf": "enterprise-waf",
}
DISABLED_SERVICES = ("backup-scheduler", "docker-action-activation-sidecar", "docker-action-broker")
ACTIVE_SERVICE_BY_CONTAINER = {
    container: service for service, container in MANAGED_CONTAINER_BY_SERVICE.items()
    if service not in DISABLED_SERVICES
}
ACTIVE_MANAGED = tuple(sorted(ACTIVE_SERVICE_BY_CONTAINER))
SERVICE_REFRESH_ORDER = (
    BROKER_AUTH_BOOTSTRAP,
    "enterprise-postgres",
    "enterprise-redis",
    "enterprise-nats",
    "enterprise-minio",
    "mariadb",
    "enterprise-keycloak",
    "enterprise-loki",
    "enterprise-promtail",
    "enterprise-prometheus",
    "enterprise-alertmanager",
    "enterprise-grafana",
    "enterprise-platform-alert-dispatcher",
    "enterprise-control-center",
    "enterprise-project-router",
    "enterprise-traefik",
    "enterprise-waf",
)
PRESERVED_LEGACY = tuple(sorted(set(CANONICAL_CONTAINERS) - set(ACTIVE_MANAGED)))
LEGACY_UNMANAGED_REASON_BY_CONTAINER = {
    "enterprise-backend": "NO_HOSTED_WORKLOAD_AUTHORITY",
    "enterprise-cadvisor": "COMPOSE_PROFILE_RAW_HOST_METRICS_DISABLED",
    "enterprise-local-dns": "COMPOSE_PROFILE_DNS_DISABLED",
    "enterprise-local-registry": "COMPOSE_PROFILE_LOCAL_RUNTIME_DISABLED",
    "enterprise-node-exporter": "COMPOSE_PROFILE_RAW_HOST_METRICS_DISABLED",
    "enterprise-web": "NO_HOSTED_WORKLOAD_AUTHORITY",
    "enterprise-worker-jobs": "NO_HOSTED_WORKLOAD_AUTHORITY",
    "enterprise-worker-notifications": "NO_HOSTED_WORKLOAD_AUTHORITY",
    "node-account": "NO_HOSTED_WORKLOAD_AUTHORITY",
    "node-opstudents": "NO_HOSTED_WORKLOAD_AUTHORITY",
    "node-ui": "NO_HOSTED_WORKLOAD_AUTHORITY",
    "php-anniversary": "NO_HOSTED_WORKLOAD_AUTHORITY",
    "php-apache": "COMPOSE_PROFILE_LEGACY_SHARED_RUNTIME_DISABLED",
    "php-fiplatform": "NO_HOSTED_WORKLOAD_AUTHORITY",
    "php-matthewdifilippo": "NO_HOSTED_WORKLOAD_AUTHORITY",
    "php-stream": "NO_HOSTED_WORKLOAD_AUTHORITY",
    "php-workcalendar": "NO_HOSTED_WORKLOAD_AUTHORITY",
    "phpmyadmin": "COMPOSE_PROFILE_ADMIN_DISABLED",
    "phppgadmin": "COMPOSE_PROFILE_ADMIN_DISABLED",
}
if tuple(sorted(LEGACY_UNMANAGED_REASON_BY_CONTAINER)) != PRESERVED_LEGACY:
    raise RuntimeError("V1 legacy-unmanaged reason inventory is not the exact preserved set.")
LEGACY_UNMANAGED = tuple({
    "containerName": name,
    "reason": LEGACY_UNMANAGED_REASON_BY_CONTAINER[name],
    "status": "LEGACY_UNMANAGED",
} for name in PRESERVED_LEGACY)
RUNTIME_IDENTITY_ENV = (
    "PLATFORM_RUNTIME_CANDIDATE_ID",
    "PLATFORM_RUNTIME_COMMIT",
    "PLATFORM_RUNTIME_TREE",
    "PLATFORM_RUNTIME_DEPLOYMENT_ID",
    "PLATFORM_RUNTIME_SOURCE_RENDER_SHA256",
    "PLATFORM_RUNTIME_WORKLOAD_LOCK_SHA256",
)
RUNTIME_IDENTITY_LABEL_BY_ENV = {
    "PLATFORM_RUNTIME_CANDIDATE_ID": "com.platform.runtime.candidate-id",
    "PLATFORM_RUNTIME_COMMIT": "com.platform.runtime.commit",
    "PLATFORM_RUNTIME_TREE": "com.platform.runtime.tree",
    "PLATFORM_RUNTIME_DEPLOYMENT_ID": "com.platform.runtime.deployment-id",
    "PLATFORM_RUNTIME_SOURCE_RENDER_SHA256": "com.platform.runtime.source-render-sha256",
    "PLATFORM_RUNTIME_WORKLOAD_LOCK_SHA256": "com.platform.runtime.workload-lock-sha256",
}
PROJECT_BY_NAME = {
    name: ("opstudents" if name == "node-opstudents" else "platform_infra_vps")
    for name in set(HISTORIC_CONTAINERS) | {LEGACY_ALERT_DISPATCHER, CANONICAL_ALERT_DISPATCHER, BROKER_AUTH_BOOTSTRAP}
}
NO_HEALTHCHECK = frozenset(("enterprise-local-dns", "enterprise-local-registry", "phpmyadmin"))

AUTHORIZED_DATA_MUTATIONS = (
    {
        "id": "control-center-database-bootstrap",
        "service": "control-center",
        "target": "/control_center/control_auth/migrations/001-004",
        "type": "SCHEMA_MIGRATION",
    },
    {
        "id": "control-center-database-runtime-secret",
        "service": "control-center",
        "target": "/run/secrets/control_center_database_url",
        "type": "BOOTSTRAP_WRITE",
    },
    {
        "id": "control-center-first-configuration-bootstrap-token",
        "service": "control-center",
        "target": "/run/secrets/control_center_first_configuration_bootstrap_token",
        "type": "BOOTSTRAP_WRITE",
    },
    {
        "id": "control-center-first-configuration-keycloak-client",
        "service": "keycloak",
        "target": "/realms/platform/clients/platform-first-configuration",
        "type": "CONFIGURATION_WRITE",
    },
)

LOCAL_IMAGE_BUILDS = (
    ("CONTROL_CENTER_IMAGE", "docker/control-center.Dockerfile", "platform/control-center"),
    ("PLATFORM_ALERT_DISPATCHER_IMAGE", "docker/alert-dispatcher.Dockerfile", "platform/alert-dispatcher"),
    ("PLATFORM_OPS_IMAGE", "docker/ops.Dockerfile", "platform/ops"),
    ("PROJECT_ROUTER_IMAGE", "docker/project-router.Dockerfile", "platform/project-router"),
    ("RESTIC_IMAGE", "docker/restic-rclone.Dockerfile", "platform/restic-rclone"),
)
DEPLOYMENT_LOCAL_IMAGE_ENV = (
    "CONTROL_CENTER_IMAGE",
    "PLATFORM_ALERT_DISPATCHER_IMAGE",
    "PLATFORM_OPS_IMAGE",
    "PROJECT_ROUTER_IMAGE",
)
BACKUP_TOOL_IMAGE_NAMES = (
    "mariadbRestore",
    "minioRestore",
    "nodeUtility",
    "postgresRestore",
    "resticRclone",
)
NODE_UTILITY_DOCKERFILES = (
    "docker/alert-dispatcher.Dockerfile",
    "docker/backup-scheduler.Dockerfile",
    "docker/control-center.Dockerfile",
    "docker/ops.Dockerfile",
    "docker/project-router.Dockerfile",
)


class Stop(Exception):
    def __init__(self, message: str, code: int = 78):
        super().__init__(message)
        self.code = code


TEST_ROOT: Optional[str] = None
OWNER_UID = os.geteuid()
OWNER_GID = os.getegid()
SECRET_UID = os.geteuid()
SECRET_GID = os.getegid()
PREVERIFIED_CONTROLLER_RECEIPT: Optional[bytes] = None
SHARED_LOCK_FD: Optional[int] = None
EXECUTOR_FD_RESERVED = False


def stop(message: str, code: int = 78) -> None:
    raise Stop(message, code)


def test_fault(boundary: str) -> None:
    if TEST_ROOT is not None and os.environ.get("PLATFORM_V1_RECONCILE_TEST_FAULT") == boundary:
        stop(f"isolated reconciliation fault at {boundary}.", 75)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def canonical_bytes(value: object) -> bytes:
    return (canonical(value) + "\n").encode("utf-8")


def duplicate_safe(pairs: List[Tuple[str, object]]) -> Dict[str, object]:
    result: Dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key}")
        result[key] = value
    return result


def parse_json(data: bytes, label: str, canonical_required: bool = False) -> Dict[str, object]:
    try:
        value = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=duplicate_safe)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        stop(f"{label} is not strict JSON: {error}.")
    if not isinstance(value, dict):
        stop(f"{label} is not one JSON object.")
    if canonical_required and data != canonical_bytes(value):
        stop(f"{label} is not canonical JSON.")
    return value


def exact_keys(value: object, keys: Iterable[str], label: str) -> Dict[str, object]:
    if not isinstance(value, dict) or set(value) != set(keys):
        stop(f"{label} fields differ from the closed V1 schema.")
    return value


def physical(logical: str) -> str:
    if TEST_ROOT is None:
        return logical
    if not logical.startswith("/"):
        stop("internal logical path is not absolute.")
    return os.path.join(TEST_ROOT, logical.removeprefix("/"))


def no_symlink_chain(pathname: str, label: str, allow_missing_leaf: bool = False) -> None:
    absolute = os.path.abspath(pathname)
    current = "/"
    parts = [part for part in absolute.split("/") if part]
    for index, part in enumerate(parts):
        current = os.path.join(current, part)
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            if allow_missing_leaf and index == len(parts) - 1:
                return
            stop(f"{label} path component is missing: {current}.")
        if stat.S_ISLNK(info.st_mode):
            stop(f"{label} traverses a symbolic link.")


def ensure_directory(logical: str, mode: int) -> str:
    pathname = physical(logical)
    parent = os.path.dirname(pathname)
    if parent and parent != pathname and not os.path.isdir(parent):
        os.makedirs(parent, mode=0o700, exist_ok=True)
    os.makedirs(pathname, mode=mode, exist_ok=True)
    no_symlink_chain(pathname, logical)
    info = os.stat(pathname, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != OWNER_UID or info.st_gid != OWNER_GID:
        stop(f"{logical} is not an authority-owned directory.")
    if stat.S_IMODE(info.st_mode) != mode:
        os.chmod(pathname, mode, follow_symlinks=False)
    return pathname


def configure_secret_anchor() -> None:
    global SECRET_UID, SECRET_GID
    anchor_logical = os.path.dirname(SECRET_DIR)
    anchor = physical(anchor_logical)
    no_symlink_chain(anchor, "LOCAL_PRIVATE deployment anchor")
    try:
        info = os.stat(anchor, follow_symlinks=False)
    except OSError as error:
        stop(f"LOCAL_PRIVATE deployment anchor is unavailable: {error}.")
    if not stat.S_ISDIR(info.st_mode) or (TEST_ROOT is None and info.st_uid == 0):
        stop("LOCAL_PRIVATE deployment anchor has an invalid owner or type.")
    if stat.S_IMODE(info.st_mode) & 0o022:
        # The historical checkout is 0775.  Root narrows only this fixed anchor
        # before using it as the deployment/secret ownership authority.
        if TEST_ROOT is None and os.geteuid() != 0:
            stop("LOCAL_PRIVATE deployment anchor is writable by group/other.")
        os.chmod(anchor, stat.S_IMODE(info.st_mode) & ~0o022, follow_symlinks=False)
        info = os.stat(anchor, follow_symlinks=False)
    if stat.S_IMODE(info.st_mode) & 0o022:
        stop("LOCAL_PRIVATE deployment anchor remains writable by group/other.")
    SECRET_UID, SECRET_GID = info.st_uid, info.st_gid
    ensure_secret_directory()


def configure_secret_identity_readonly() -> None:
    """Derive the live deployment owner for abort without chmod/create/write."""
    global SECRET_UID, SECRET_GID
    anchor = physical(DEPLOYMENT_REPO)
    no_symlink_chain(anchor, "LOCAL_PRIVATE deployment anchor")
    info = os.stat(anchor, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid == 0 or stat.S_IMODE(info.st_mode) & 0o002:
        stop("LOCAL_PRIVATE deployment anchor cannot provide a trusted abort owner.")
    env_path = physical(DEPLOYMENT_ENV)
    no_symlink_chain(env_path, "live deployment environment")
    env_info = os.stat(env_path, follow_symlinks=False)
    if (
        not stat.S_ISREG(env_info.st_mode)
        or env_info.st_uid != info.st_uid
        or env_info.st_gid != info.st_gid
        or env_info.st_nlink != 1
        or stat.S_IMODE(env_info.st_mode) not in (0o400, 0o600)
    ):
        stop("live deployment environment cannot provide a trusted abort preimage.")
    SECRET_UID, SECRET_GID = info.st_uid, info.st_gid


def ensure_secret_directory() -> str:
    pathname = physical(SECRET_DIR)
    parent = os.path.dirname(pathname)
    no_symlink_chain(parent, "parent of LOCAL_PRIVATE secret root")
    try:
        info = os.lstat(pathname)
    except FileNotFoundError:
        os.mkdir(pathname, 0o700)
        os.chown(pathname, SECRET_UID, SECRET_GID)
        os.chmod(pathname, 0o700)
        info = os.lstat(pathname)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        stop("LOCAL_PRIVATE secret root is not one real directory.")
    if info.st_uid != SECRET_UID or info.st_gid != SECRET_GID:
        if os.geteuid() != 0:
            stop("LOCAL_PRIVATE secret root ownership differs from its deployment anchor.")
        os.chown(pathname, SECRET_UID, SECRET_GID)
    if stat.S_IMODE(os.stat(pathname, follow_symlinks=False).st_mode) != 0o700:
        os.chmod(pathname, 0o700, follow_symlinks=False)
    final = os.stat(pathname, follow_symlinks=False)
    if final.st_uid != SECRET_UID or final.st_gid != SECRET_GID or stat.S_IMODE(final.st_mode) != 0o700:
        stop("LOCAL_PRIVATE secret root owner/mode reconciliation failed.")
    return pathname


def secure_secret_file(logical: str, label: str, maximum: int = 4096) -> bytes:
    pathname = physical(logical)
    no_symlink_chain(pathname, label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(pathname, flags)
    except OSError as error:
        stop(f"cannot open {label}: {error}.")
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != SECRET_UID
            or before.st_gid != SECRET_GID
            or before.st_nlink != 1
            or before.st_size > maximum
            or stat.S_IMODE(before.st_mode) != 0o600
        ):
            stop(f"{label} ownership, type, link count, size or mode is invalid.")
        data = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        if len(data) > maximum or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            stop(f"{label} changed while it was read or exceeded its boundary.")
        return data
    finally:
        os.close(fd)


def atomic_secret_bytes(logical: str, data: bytes, replace: bool = True) -> None:
    parent = ensure_secret_directory()
    pathname = physical(logical)
    if os.path.dirname(pathname) != parent or os.path.basename(pathname) not in {
        os.path.basename(DATABASE_SECRET), os.path.basename(BOOTSTRAP_SECRET), os.path.basename(KEYCLOAK_CLIENT_SECRET),
    }:
        stop("secret write escaped the closed LOCAL_PRIVATE secret set.")
    if os.path.lexists(pathname) and not replace:
        stop(f"refusing to replace preserved {logical}.")
    fd, temporary = tempfile.mkstemp(prefix=f".{os.path.basename(pathname)}.", dir=parent)
    try:
        os.fchown(fd, SECRET_UID, SECRET_GID)
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, pathname)
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        if os.path.exists(temporary):
            os.unlink(temporary)


def privileged_identity() -> Tuple[int, int]:
    return (OWNER_UID, OWNER_GID) if TEST_ROOT is not None else (0, 0)


def alert_runtime_gid() -> int:
    if TEST_ROOT is not None:
        return SECRET_GID
    try:
        return grp.getgrnam("nogroup").gr_gid
    except KeyError:
        stop("LOCAL_PRIVATE alert runtime group is unavailable.")


def read_external_regular(
    pathname: str,
    label: str,
    maximum: int,
    expected_uid: int,
    expected_gid: int,
    allowed_modes: Iterable[int],
) -> Tuple[bytes, Tuple[int, int, int, int, int, int], int]:
    no_symlink_chain(pathname, label)
    try:
        path_info = os.lstat(pathname)
    except OSError as error:
        stop(f"{label} is unavailable: {error}.")
    allowed = set(allowed_modes)
    if (
        not stat.S_ISREG(path_info.st_mode)
        or stat.S_ISLNK(path_info.st_mode)
        or path_info.st_nlink != 1
        or path_info.st_size < 1
        or path_info.st_size > maximum
    ):
        stop(f"{label} is not one bounded nonempty regular file.")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(pathname, flags)
    except OSError as error:
        stop(f"cannot open {label}: {error}.")
    try:
        before = os.fstat(fd)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_uid,
            before.st_gid,
        )
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != expected_uid
            or before.st_gid != expected_gid
            or mode not in allowed
            or (path_info.st_dev, path_info.st_ino, path_info.st_size) != identity[:3]
        ):
            stop(f"{label} ownership, identity or mode is invalid.")
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                stop(f"{label} exceeded its byte boundary.")
        after = os.fstat(fd)
        if (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_uid,
            after.st_gid,
        ) != identity:
            stop(f"{label} changed while it was read.")
        return b"".join(chunks), identity, mode
    finally:
        os.close(fd)


def external_directory_authority(logical: str, label: str, allowed_modes: Iterable[int]) -> None:
    pathname = physical(logical)
    no_symlink_chain(pathname, label)
    before = os.lstat(pathname)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(pathname, flags)
    try:
        opened = os.fstat(fd)
        mode = stat.S_IMODE(opened.st_mode)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_uid != SECRET_UID
            or opened.st_gid != SECRET_GID
            or mode not in set(allowed_modes)
            or (mode & 0o500) != 0o500
            or mode & 0o7000
        ):
            stop(f"{label} owner, type or mode is outside the LOCAL_PRIVATE path cohort.")
        target_mode = mode & ~0o022
        if target_mode != mode:
            os.fchmod(fd, target_mode)
            os.fsync(fd)
        current = os.lstat(pathname)
        final = os.fstat(fd)
        if (
            (final.st_dev, final.st_ino) != (opened.st_dev, opened.st_ino)
            or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
            or final.st_uid != SECRET_UID
            or final.st_gid != SECRET_GID
            or stat.S_IMODE(final.st_mode) != target_mode
            or target_mode & 0o022
        ):
            stop(f"{label} changed or remained writable during path preparation.")
    finally:
        os.close(fd)


def narrow_external_file_mode(
    logical: str,
    label: str,
    maximum: int,
    expected_uid: int,
    expected_gid: int,
    allowed_modes: Iterable[int],
    target_mode: int,
) -> bytes:
    pathname = physical(logical)
    data, identity, mode = read_external_regular(
        pathname, label, maximum, expected_uid, expected_gid, allowed_modes
    )
    if mode != target_mode:
        fd = os.open(pathname, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            current = os.fstat(fd)
            if (
                current.st_dev,
                current.st_ino,
                current.st_size,
                current.st_mtime_ns,
                current.st_uid,
                current.st_gid,
            ) != identity:
                stop(f"{label} changed before its bounded mode reconciliation.")
            os.fchmod(fd, target_mode)
            os.fsync(fd)
        finally:
            os.close(fd)
    final_data, final_identity, final_mode = read_external_regular(
        pathname, label, maximum, expected_uid, expected_gid, (target_mode,)
    )
    if final_data != data or final_identity != identity or final_mode != target_mode:
        stop(f"{label} bytes or identity changed during mode reconciliation.")
    return final_data


def validate_local_certificate_authority() -> None:
    descriptors = []
    try:
        for logical, label, mode in (
            (LOCAL_PRIVATE_KEY, "LOCAL_PRIVATE TLS private key", 0o640),
            (LOCAL_CERTIFICATE, "LOCAL_PRIVATE TLS certificate", 0o644),
            (LOCAL_CA_CERTIFICATE, "LOCAL_PRIVATE TLS certificate authority", 0o644),
        ):
            pathname = physical(logical)
            read_external_regular(pathname, label, 1024 * 1024, SECRET_UID, SECRET_GID, (mode,))
            descriptors.append(os.open(
                pathname,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            ))
        key_fd, certificate_fd, authority_fd = descriptors
        os.lseek(key_fd, 0, os.SEEK_SET)
        key_public = run(
            [openssl_binary(), "pkey", "-in", f"/dev/fd/{key_fd}", "-pubout"],
            "LOCAL_PRIVATE TLS key public identity",
            timeout=30,
            max_output=1024 * 1024,
            sensitive=True,
            pass_fds=tuple(descriptors),
        )
        os.lseek(certificate_fd, 0, os.SEEK_SET)
        certificate_public = run(
            [openssl_binary(), "x509", "-in", f"/dev/fd/{certificate_fd}", "-pubkey", "-noout"],
            "LOCAL_PRIVATE TLS certificate public identity",
            timeout=30,
            max_output=1024 * 1024,
            sensitive=True,
            pass_fds=tuple(descriptors),
        )
        if not key_public or key_public != certificate_public:
            stop("LOCAL_PRIVATE TLS certificate and private key do not match.")
        os.lseek(certificate_fd, 0, os.SEEK_SET)
        os.lseek(authority_fd, 0, os.SEEK_SET)
        run(
            [
                openssl_binary(), "verify", "-CAfile", f"/dev/fd/{authority_fd}",
                f"/dev/fd/{certificate_fd}",
            ],
            "LOCAL_PRIVATE TLS certificate chain",
            timeout=30,
            max_output=1024 * 1024,
            sensitive=True,
            pass_fds=tuple(descriptors),
        )
    finally:
        for fd in descriptors:
            os.close(fd)


def prepare_external_path_authority() -> None:
    configure_secret_anchor()
    directory_modes = (0o700, 0o750, 0o755, 0o770, 0o775)
    for logical, label in (
        (os.path.dirname(DEPLOYMENT_REPO), "LOCAL_PRIVATE deployment home"),
        (PROJECT_SOURCE_ROOT, "LOCAL_PRIVATE project source root"),
        (PROJECTS_PORTAL_ROOT, "LOCAL_PRIVATE projects portal root"),
        (PROJECT_STATE_ROOT, "LOCAL_PRIVATE project state root"),
        (TRAEFIK_ROOT, "LOCAL_PRIVATE Traefik root"),
        (CERTIFICATES_ROOT, "LOCAL_PRIVATE certificate root"),
    ):
        external_directory_authority(logical, label, directory_modes)
    narrow_external_file_mode(
        LOCAL_PRIVATE_KEY, "LOCAL_PRIVATE TLS private key", 1024 * 1024,
        SECRET_UID, SECRET_GID, (0o600, 0o640, 0o644), 0o640,
    )
    read_external_regular(
        physical(LOCAL_CERTIFICATE), "LOCAL_PRIVATE TLS certificate", 1024 * 1024,
        SECRET_UID, SECRET_GID, (0o644,),
    )
    read_external_regular(
        physical(LOCAL_CA_CERTIFICATE), "LOCAL_PRIVATE TLS certificate authority", 1024 * 1024,
        SECRET_UID, SECRET_GID, (0o644,),
    )
    narrow_external_file_mode(
        f"{SECRET_DIR}/alertmanager_webhook_token.txt", "Alertmanager webhook token", 4096,
        SECRET_UID, alert_runtime_gid(), (0o600, 0o640), 0o640,
    )
    validate_local_certificate_authority()


def manager_secret_metadata(name: str) -> Tuple[int, int, Tuple[int, ...]]:
    if name not in SECRET_MANAGER_COMPLETE:
        stop("secret manager metadata request escaped the closed V1 cohort.")
    if name == "alertmanager_webhook_token":
        return SECRET_UID, alert_runtime_gid(), (0o640,)
    if name == "app_db_password":
        return SECRET_UID, SECRET_GID, (0o640,)
    if name == "github_token":
        uid, gid = privileged_identity()
        return uid, gid, (0o600,)
    return SECRET_UID, SECRET_GID, (0o600,)


def manager_store_names(data: bytes, label: str) -> Tuple[Dict[str, object], Tuple[str, ...]]:
    value = parse_json(data, label)
    records = value.get("secrets")
    if value.get("manager") != "infra-secret-manager" or value.get("version") != 1 or not isinstance(records, dict):
        stop(f"{label} has an invalid encrypted-store envelope.")
    names = tuple(sorted(records))
    if any(NAME_RE.fullmatch(name) is None for name in names):
        stop(f"{label} contains a secret name outside the closed syntax.")
    return value, names


def validate_setup_secret_bytes(logical: str, data: bytes) -> None:
    label = {
        DATABASE_SECRET: "Control Center database URL",
        BOOTSTRAP_SECRET: "First Configuration bootstrap token",
        KEYCLOAK_CLIENT_SECRET: "First Configuration Keycloak client secret",
    }.get(logical)
    if label is None or not data.endswith(b"\n") or data.count(b"\n") != 1 or b"\r" in data or b"\x00" in data:
        stop("setup secret bytes differ from the closed V1 encoding.")
    try:
        value = data[:-1].decode("ascii", errors="strict")
    except UnicodeDecodeError:
        stop(f"{label} is not ASCII.")
    if logical == DATABASE_SECRET:
        parsed = urllib.parse.urlsplit(value)
        if (
            parsed.scheme not in ("postgres", "postgresql")
            or parsed.username != "control_center_runtime"
            or parsed.hostname != "postgres"
            or parsed.port != 5432
            or parsed.path != "/control_center"
            or not parsed.password
            or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", urllib.parse.unquote(parsed.password))
        ):
            stop("Control Center database URL has the wrong bounded runtime identity.")
        return
    minimum = 43 if logical == BOOTSTRAP_SECRET else 32
    if len(value) < minimum or len(value) > 1024 or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        stop(f"{label} has invalid content.")


def generate_setup_secret_bytes(logical: str) -> bytes:
    if logical == DATABASE_SECRET:
        password = secrets.token_urlsafe(36)
        encoded = urllib.parse.quote(password, safe="")
        data = f"postgresql://control_center_runtime:{encoded}@postgres:5432/control_center\n".encode("ascii")
    elif logical in (BOOTSTRAP_SECRET, KEYCLOAK_CLIENT_SECRET):
        data = (secrets.token_urlsafe(32) + "\n").encode("ascii")
    else:
        stop("setup secret generation escaped the closed V1 set.")
    validate_setup_secret_bytes(logical, data)
    return data


def fsync_directory_path(pathname: str) -> None:
    fd = os.open(pathname, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new_private_file(pathname: str, data: bytes, uid: int, gid: int, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(pathname, flags, mode)
    try:
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)


def remove_stale_secret_publish_temporary(destination: str, uid: int, gid: int, mode: int) -> None:
    temporary = os.path.join(os.path.dirname(destination), f".v1-prep-{os.path.basename(destination)}")
    if not os.path.lexists(temporary):
        return
    info = os.lstat(temporary)
    destination_info = os.lstat(destination) if os.path.lexists(destination) else None
    linked_destination = destination_info is not None and (
        info.st_dev, info.st_ino
    ) == (
        destination_info.st_dev, destination_info.st_ino
    )
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != uid
        or info.st_gid != gid
        or stat.S_IMODE(info.st_mode) != mode
        or info.st_nlink not in (1, 2)
        or (info.st_nlink == 2) != linked_destination
    ):
        stop("stale LOCAL_PRIVATE secret publication temporary is ambiguous.")
    os.unlink(temporary)
    fsync_directory_path(os.path.dirname(destination))


def publish_secret_leaf(logical: str, data: bytes) -> bool:
    pathname = physical(logical)
    parent = physical(SECRET_DIR)
    if os.path.dirname(pathname) != parent or logical not in {
        DATABASE_SECRET,
        BOOTSTRAP_SECRET,
        KEYCLOAK_CLIENT_SECRET,
        *(f"{SECRET_DIR}/{name}.txt" for name in SECRET_MANAGER_NEW_REQUIRED),
    }:
        stop("secret publication escaped the closed V1 prerequisite leaf set.")
    remove_stale_secret_publish_temporary(pathname, SECRET_UID, SECRET_GID, 0o600)
    if os.path.lexists(pathname):
        observed, _, _ = read_external_regular(
            pathname, f"existing prerequisite secret {os.path.basename(pathname)}", 4096,
            SECRET_UID, SECRET_GID, (0o600,),
        )
        if observed != data:
            stop("existing prerequisite secret differs from its staged transaction value.")
        return False
    temporary = os.path.join(parent, f".v1-prep-{os.path.basename(pathname)}")
    try:
        write_new_private_file(temporary, data, SECRET_UID, SECRET_GID, 0o600)
        try:
            os.link(temporary, pathname, follow_symlinks=False)
        except FileExistsError:
            stop("prerequisite secret appeared during atomic publication.")
        os.unlink(temporary)
        fsync_directory_path(parent)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)
    observed, _, _ = read_external_regular(
        pathname, f"published prerequisite secret {os.path.basename(pathname)}", 4096,
        SECRET_UID, SECRET_GID, (0o600,),
    )
    if observed != data:
        stop("published prerequisite secret bytes changed.")
    return True


def replace_manager_store(data: bytes) -> None:
    pathname = physical(SECRET_MANAGER_STORE)
    parent = physical(SECRET_DIR)
    uid, gid = privileged_identity()
    temporary = os.path.join(parent, ".v1-prep-infra-secret-manager-store.json")
    if os.path.lexists(temporary):
        info = os.lstat(temporary)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != uid
            or info.st_gid != gid
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            stop("stale secret-manager store temporary is ambiguous.")
        os.unlink(temporary)
        fsync_directory_path(parent)
    try:
        write_new_private_file(temporary, data, uid, gid, 0o600)
        os.replace(temporary, pathname)
        fsync_directory_path(parent)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def remove_secret_stage() -> None:
    pathname = physical(SECRET_PREP_STAGE)
    if not os.path.lexists(pathname):
        return
    uid, gid = privileged_identity()
    info = os.lstat(pathname)
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != uid
        or info.st_gid != gid
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        stop("stale LOCAL_PRIVATE secret stage is not one private root-owned directory.")
    for root, directories, files in os.walk(pathname, topdown=True, followlinks=False):
        for entry in [*directories, *files]:
            child = os.path.join(root, entry)
            child_info = os.lstat(child)
            if stat.S_ISLNK(child_info.st_mode) or child_info.st_uid != uid or child_info.st_gid != gid:
                stop("stale LOCAL_PRIVATE secret stage contains a foreign entry.")
            if stat.S_ISREG(child_info.st_mode) and child_info.st_nlink != 1:
                stop("stale LOCAL_PRIVATE secret stage contains a linked file.")
    shutil.rmtree(pathname)


def create_secret_stage() -> str:
    remove_secret_stage()
    pathname = physical(SECRET_PREP_STAGE)
    parent = os.path.dirname(pathname)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    os.mkdir(pathname, 0o700)
    uid, gid = privileged_identity()
    os.chown(pathname, uid, gid)
    os.chmod(pathname, 0o700)
    return pathname


def run_candidate_secret_manager(release: str, command: str, root: str, audit_log: str) -> None:
    manager = release_file(release, "scripts/infra-secret-manager.mjs")
    empty_environment = os.path.join(physical(SECRET_PREP_STAGE), "empty.env")
    arguments = [
        node_binary(), manager, command,
        "--secretsDir", root,
        "--store", os.path.join(root, "infra-secret-manager-store.json"),
        "--masterKey", os.path.join(root, "infra-secret-manager-master.key"),
        "--auditLog", audit_log,
        "--envFile", empty_environment,
    ]
    run(
        arguments,
        f"candidate secret manager {command}",
        timeout=180,
        max_output=1024 * 1024,
        sensitive=True,
    )


def prepare_live_prerequisite_cohort(release: str) -> Dict[str, object]:
    prepare_external_path_authority()
    privileged_uid, privileged_gid = privileged_identity()
    store_path = physical(SECRET_MANAGER_STORE)
    master_path = physical(SECRET_MANAGER_MASTER_KEY)
    audit_path = physical(SECRET_MANAGER_AUDIT_LOG)
    old_store, old_store_identity, _ = read_external_regular(
        store_path, "live secret-manager encrypted store", MAX_JSON,
        privileged_uid, privileged_gid, (0o600,),
    )
    old_store_object, old_names = manager_store_names(old_store, "live secret-manager encrypted store")
    if old_names == SECRET_MANAGER_EXISTING:
        store_state = "LEGACY_COMPLETE"
    elif old_names == SECRET_MANAGER_COMPLETE:
        store_state = "V1_COMPLETE"
    else:
        stop("live secret-manager record set is neither the exact 21-record preimage nor the exact V1 completion.")
    old_master, old_master_identity, _ = read_external_regular(
        master_path, "live secret-manager master key", 4096,
        privileged_uid, privileged_gid, (0o600,),
    )
    # PRE metadata backup copies this file.  It is not used as the audit sink
    # for simulated/live verification below, so preparation remains byte-read-
    # only with respect to historical audit evidence.
    read_external_regular(
        audit_path, "live secret-manager audit log", 64 * 1024 * 1024,
        privileged_uid, privileged_gid, (0o600, 0o640, 0o644),
    )

    existing_snapshots: Dict[str, Tuple[bytes, Tuple[int, int, int, int, int, int], int]] = {}
    for name in old_names:
        uid, gid, modes = manager_secret_metadata(name)
        existing_snapshots[name] = read_external_regular(
            physical(f"{SECRET_DIR}/{name}.txt"), f"live materialized secret {name}", 4096,
            uid, gid, modes,
        )

    setup_order = (DATABASE_SECRET, BOOTSTRAP_SECRET, KEYCLOAK_CLIENT_SECRET)
    manager_order = tuple(f"{SECRET_DIR}/{name}.txt" for name in SECRET_MANAGER_NEW_REQUIRED)
    publication_order = setup_order + manager_order
    presence = [os.path.lexists(physical(logical)) for logical in publication_order]
    prefix_length = 0
    while prefix_length < len(presence) and presence[prefix_length]:
        prefix_length += 1
    if any(presence[prefix_length:]):
        stop("prerequisite secret leaves are not one exact forward-resumable prefix.")
    if store_state == "V1_COMPLETE" and prefix_length != len(publication_order):
        stop("completed V1 secret-manager store does not have every prerequisite leaf.")

    setup_bytes: Dict[str, bytes] = {}
    for index, logical in enumerate(setup_order):
        if index < prefix_length:
            data, _, _ = read_external_regular(
                physical(logical), f"existing setup secret {os.path.basename(logical)}", 4096,
                SECRET_UID, SECRET_GID, (0o600,),
            )
            validate_setup_secret_bytes(logical, data)
            setup_bytes[logical] = data
        else:
            setup_bytes[logical] = generate_setup_secret_bytes(logical)

    stage = create_secret_stage()
    manager_stage = os.path.join(stage, "manager")
    os.mkdir(manager_stage, 0o700)
    os.chown(manager_stage, privileged_uid, privileged_gid)
    empty_environment = os.path.join(stage, "empty.env")
    write_new_private_file(empty_environment, b"\n", privileged_uid, privileged_gid, 0o600)
    target_store = old_store
    staged_manager_bytes: Dict[str, bytes] = {}
    try:
        if store_state == "LEGACY_COMPLETE":
            write_new_private_file(
                os.path.join(manager_stage, "infra-secret-manager-store.json"),
                old_store, privileged_uid, privileged_gid, 0o600,
            )
            write_new_private_file(
                os.path.join(manager_stage, "infra-secret-manager-master.key"),
                old_master, privileged_uid, privileged_gid, 0o600,
            )
            for offset, name in enumerate(SECRET_MANAGER_NEW_REQUIRED, start=len(setup_order)):
                if offset >= prefix_length:
                    continue
                logical = f"{SECRET_DIR}/{name}.txt"
                data, _, _ = read_external_regular(
                    physical(logical), f"resumable prerequisite secret {name}", 4096,
                    SECRET_UID, SECRET_GID, (0o600,),
                )
                write_new_private_file(
                    os.path.join(manager_stage, f"{name}.txt"),
                    data, privileged_uid, privileged_gid, 0o600,
                )
            stage_audit = os.path.join(stage, "candidate-manager-audit.log")
            run_candidate_secret_manager(release, "init", manager_stage, stage_audit)
            run_candidate_secret_manager(release, "verify", manager_stage, stage_audit)
            staged_master, _, _ = read_external_regular(
                os.path.join(manager_stage, "infra-secret-manager-master.key"),
                "staged secret-manager master key", 4096,
                privileged_uid, privileged_gid, (0o600,),
            )
            if staged_master != old_master:
                stop("candidate secret-manager staging changed the existing master key.")
            target_store, _, _ = read_external_regular(
                os.path.join(manager_stage, "infra-secret-manager-store.json"),
                "staged secret-manager encrypted store", MAX_JSON,
                privileged_uid, privileged_gid, (0o600,),
            )
            target_store_object, target_names = manager_store_names(
                target_store, "staged secret-manager encrypted store"
            )
            if target_names != SECRET_MANAGER_COMPLETE:
                stop("candidate secret-manager staged delta is not exactly the nine V1 records.")
            old_kms_record = old_store_object.get("kms")
            target_kms_record = target_store_object.get("kms")
            if not isinstance(old_kms_record, dict) or not isinstance(target_kms_record, dict):
                stop("candidate secret-manager KMS metadata is not one object.")
            old_kms = {key: value for key, value in old_kms_record.items() if key != "updatedAt"}
            target_kms = {key: value for key, value in target_kms_record.items() if key != "updatedAt"}
            if old_kms != target_kms:
                stop("candidate secret-manager staging changed KMS identity.")
            for name in SECRET_MANAGER_EXISTING:
                old_record = old_store_object["secrets"].get(name)
                target_record = target_store_object["secrets"].get(name)
                if not isinstance(old_record, dict) or not isinstance(target_record, dict):
                    stop("candidate secret-manager staging lost one preexisting record.")
                if target_record.get("updatedAt") != old_record.get("updatedAt"):
                    stop("candidate secret-manager staging changed preexisting record time identity.")
                expected_mode = 0o640 if name in ("alertmanager_webhook_token", "app_db_password") else 0o600
                staged_data, _, _ = read_external_regular(
                    os.path.join(manager_stage, f"{name}.txt"), f"staged materialized secret {name}", 4096,
                    privileged_uid, privileged_gid, (expected_mode,),
                )
                if staged_data != existing_snapshots[name][0]:
                    stop("candidate secret-manager staging changed preexisting raw secret bytes.")
            for name in SECRET_MANAGER_NEW_REQUIRED:
                staged_data, _, _ = read_external_regular(
                    os.path.join(manager_stage, f"{name}.txt"), f"staged new secret {name}", 4096,
                    privileged_uid, privileged_gid, (0o600,),
                )
                staged_manager_bytes[f"{SECRET_DIR}/{name}.txt"] = staged_data
        else:
            for name in SECRET_MANAGER_NEW_REQUIRED:
                logical = f"{SECRET_DIR}/{name}.txt"
                staged_manager_bytes[logical] = existing_snapshots[name][0]

        target_leaf_bytes = {**setup_bytes, **staged_manager_bytes}
        if set(target_leaf_bytes) != set(publication_order):
            stop("staged prerequisite leaf set differs from the closed V1 cohort.")
        for index, logical in enumerate(publication_order, start=1):
            publish_secret_leaf(logical, target_leaf_bytes[logical])
            test_fault(f"prerequisite-leaf-{index}")

        current_store, current_store_identity, _ = read_external_regular(
            store_path, "live secret-manager encrypted store at commit", MAX_JSON,
            privileged_uid, privileged_gid, (0o600,),
        )
        current_master, current_master_identity, _ = read_external_regular(
            master_path, "live secret-manager master key at commit", 4096,
            privileged_uid, privileged_gid, (0o600,),
        )
        if (
            current_store != old_store
            or current_store_identity != old_store_identity
            or current_master != old_master
            or current_master_identity != old_master_identity
        ):
            stop("secret-manager store or master changed before the atomic commit boundary.")
        for name, expected in existing_snapshots.items():
            uid, gid, modes = manager_secret_metadata(name)
            observed = read_external_regular(
                physical(f"{SECRET_DIR}/{name}.txt"), f"precommit materialized secret {name}", 4096,
                uid, gid, modes,
            )
            if observed != expected:
                stop("one preexisting secret changed before the store commit.")

        if store_state == "LEGACY_COMPLETE":
            replace_manager_store(target_store)
            test_fault("prerequisite-store-committed")

        live_verify_audit = os.path.join(stage, "live-verify-audit.log")
        run_candidate_secret_manager(release, "verify", physical(SECRET_DIR), live_verify_audit)
        final_store, _, _ = read_external_regular(
            store_path, "final live secret-manager encrypted store", MAX_JSON,
            privileged_uid, privileged_gid, (0o600,),
        )
        _, final_names = manager_store_names(final_store, "final live secret-manager encrypted store")
        if final_store != target_store or final_names != SECRET_MANAGER_COMPLETE:
            stop("final live secret-manager store differs from the staged V1 completion.")
        final_master, _, _ = read_external_regular(
            master_path, "final live secret-manager master key", 4096,
            privileged_uid, privileged_gid, (0o600,),
        )
        if final_master != old_master:
            stop("final live secret-manager master key changed.")
        for name in SECRET_MANAGER_COMPLETE:
            uid, gid, modes = manager_secret_metadata(name)
            final = read_external_regular(
                physical(f"{SECRET_DIR}/{name}.txt"), f"final materialized secret {name}", 4096,
                uid, gid, modes,
            )
            expected_data = existing_snapshots[name][0] if name in existing_snapshots else staged_manager_bytes[f"{SECRET_DIR}/{name}.txt"]
            if final[0] != expected_data:
                stop("final materialized secret bytes differ from the transaction cohort.")
        for logical in setup_order:
            final, _, _ = read_external_regular(
                physical(logical), f"final setup secret {os.path.basename(logical)}", 4096,
                SECRET_UID, SECRET_GID, (0o600,),
            )
            validate_setup_secret_bytes(logical, final)
            if final != setup_bytes[logical]:
                stop("final setup secret bytes differ from the transaction cohort.")
        return {
            "managerRecords": len(SECRET_MANAGER_COMPLETE),
            "publishedPrerequisiteLeaves": len(publication_order) - prefix_length,
            "resumedPrerequisiteLeaves": prefix_length,
            "status": "PASS",
            "storeState": "V1_COMPLETE",
        }
    finally:
        remove_secret_stage()


def secure_file(logical: str, label: str, maximum: int = MAX_JSON, mode: Optional[int] = None) -> bytes:
    pathname = physical(logical)
    no_symlink_chain(pathname, label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(pathname, flags)
    except OSError as error:
        stop(f"cannot open {label}: {error}.")
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != OWNER_UID
            or before.st_gid != OWNER_GID
            or before.st_nlink != 1
            or before.st_size > maximum
            or (mode is not None and stat.S_IMODE(before.st_mode) != mode)
        ):
            stop(f"{label} ownership, type, link count, size or mode is invalid.")
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                stop(f"{label} exceeds its byte boundary.")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            stop(f"{label} changed while it was read.")
        return b"".join(chunks)
    finally:
        os.close(fd)


def atomic_bytes(logical: str, data: bytes, mode: int, replace: bool = True) -> None:
    pathname = physical(logical)
    parent = os.path.dirname(pathname)
    ensure_directory("/" + os.path.relpath(parent, TEST_ROOT).replace(os.sep, "/") if TEST_ROOT else parent, 0o700)
    no_symlink_chain(parent, f"parent of {logical}")
    if os.path.lexists(pathname) and not replace:
        stop(f"refusing to replace preserved {logical}.")
    fd, temporary = tempfile.mkstemp(prefix=f".{os.path.basename(pathname)}.", dir=parent)
    try:
        os.fchmod(fd, mode)
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, pathname)
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_json(logical: str, value: object, mode: int, replace: bool = True) -> bytes:
    data = canonical_bytes(value)
    atomic_bytes(logical, data, mode, replace)
    return data


def preserve_json(logical: str, value: object, label: str) -> bytes:
    expected = canonical_bytes(value)
    if os.path.lexists(physical(logical)):
        observed = secure_file(logical, label, MAX_AUTHORITY, 0o444)
        if observed != expected:
            stop(f"{label} differs from its immutable existing bytes.")
        return observed
    atomic_bytes(logical, expected, 0o444, False)
    return secure_file(logical, label, MAX_AUTHORITY, 0o444)


def preserve_private_json(logical: str, value: object, label: str, maximum: int = MAX_JSON) -> bytes:
    expected = canonical_bytes(value)
    if len(expected) > maximum:
        stop(f"{label} exceeds its private byte boundary.")
    if os.path.lexists(physical(logical)):
        observed = secure_file(logical, label, maximum, 0o600)
        if observed != expected:
            stop(f"{label} differs from its immutable existing bytes.")
        return observed
    atomic_bytes(logical, expected, 0o600, False)
    return secure_file(logical, label, maximum, 0o600)


def command_environment(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    value = {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "DOCKER_HOST": "unix:///var/run/docker.sock",
    }
    if extra:
        value.update(extra)
    value.pop("DOCKER_CONTEXT", None)
    return value


def run_result(
    command: List[str],
    label: str,
    *,
    timeout: int = 120,
    cwd: str = "/",
    environment: Optional[Dict[str, str]] = None,
    input_bytes: Optional[bytes] = None,
    max_output: int = MAX_JSON,
    sensitive: bool = False,
    pass_fds: Tuple[int, ...] = (),
) -> subprocess.CompletedProcess:
    try:
        options = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "env": command_environment(environment),
            "cwd": cwd,
            "timeout": timeout,
            "check": False,
            "pass_fds": pass_fds,
        }
        if input_bytes is None:
            options["stdin"] = subprocess.DEVNULL
        else:
            options["input"] = input_bytes
        result = subprocess.run(command, **options)
    except (OSError, subprocess.SubprocessError) as error:
        stop(f"fixed {label} command failed: {error}.")
    if len(result.stdout) > max_output or len(result.stderr) > max_output:
        stop(f"fixed {label} output exceeded its boundary.")
    return result


def archive_producer_failure(operation: str, stderr: bytes, returncode: int) -> str:
    """Persist a bounded, root-only diagnostic for a failed producer child."""
    pathname = physical(f"{MUTATION_EVIDENCE_DIR}/{operation}-producer-failure.log")
    payload = stderr[:MAX_JSON]
    header = (
        f"returncode={returncode} stderr_bytes={len(stderr)} "
        f"captured_unix_seconds={int(time.time())}\n"
    ).encode()
    try:
        descriptor = os.open(pathname, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o400)
        try:
            offset = 0
            for chunk in (header, payload):
                view = memoryview(chunk)
                while len(view):
                    written = os.write(descriptor, view)
                    view = view[written:]
            os.fchmod(descriptor, 0o400)
        finally:
            os.close(descriptor)
    except OSError:
        return "unwritable"
    digest_line = f"sha256={digest(payload)}\n" if payload else ""
    return f"{pathname} ({digest_line.strip() or 'empty'})"


def run(
command: List[str], label: str, **kwargs: object) -> bytes:
    result = run_result(command, label, **kwargs)
    if result.returncode != 0:
        if kwargs.get("sensitive") is True:
            stop(f"fixed sensitive {label} command rejected the operation; output was suppressed.")
        detail = result.stderr.decode("utf-8", errors="replace").strip()[:512]
        stop(f"fixed {label} command rejected the operation: {detail}.")
    return result.stdout


def docker_binary() -> str:
    return os.environ.get(TEST_DOCKER_ENV, DOCKER) if TEST_ROOT else DOCKER


def git_binary() -> str:
    return os.environ.get(TEST_GIT_ENV, GIT) if TEST_ROOT else GIT


def node_binary() -> str:
    return os.environ.get(TEST_NODE_ENV, NODE) if TEST_ROOT else NODE


def curl_binary() -> str:
    return os.environ.get(TEST_CURL_ENV, "/usr/bin/curl") if TEST_ROOT else "/usr/bin/curl"


def systemctl_binary() -> str:
    return os.environ.get(TEST_SYSTEMCTL_ENV, SYSTEMCTL) if TEST_ROOT else SYSTEMCTL


def openssl_binary() -> str:
    return os.environ.get(TEST_OPENSSL_ENV, OPENSSL) if TEST_ROOT else OPENSSL


def require_maintenance_ready() -> None:
    """Prove the controller supervisor is disabled before any reconciliation write."""
    enabled = run_result(
        [systemctl_binary(), "is-enabled", SUPERVISOR_UNIT],
        "systemctl maintenance is-enabled",
        timeout=30,
        max_output=1024,
    )
    active = run_result(
        [systemctl_binary(), "is-active", SUPERVISOR_UNIT],
        "systemctl maintenance is-active",
        timeout=30,
        max_output=1024,
    )
    try:
        enabled_state = enabled.stdout.decode("utf-8", errors="strict").strip()
        active_state = active.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError:
        stop("controller supervisor returned a non-text maintenance state.")
    if not (
        enabled.returncode != 0
        and enabled_state == "disabled"
        and active.returncode != 0
        and active_state == "inactive"
    ):
        stop("controller maintenance is not ready: supervisor must be disabled and inactive.")


def docker_json(arguments: List[str], label: str, timeout: int = 45) -> object:
    output = run([docker_binary(), *arguments], f"Docker {label}", timeout=timeout)
    try:
        return json.loads(output.decode("utf-8", errors="strict"), object_pairs_hook=duplicate_safe)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        stop(f"fixed Docker {label} returned invalid JSON: {error}.")


def check_no_stdin() -> None:
    try:
        readable, _, _ = select.select([0], [], [], 0)
        if readable and os.read(0, 1):
            stop("V1 LOCAL_PRIVATE reconciler accepts no stdin.", 64)
    except (OSError, ValueError):
        stop("cannot prove empty stdin.", 64)


def configure_environment() -> None:
    global TEST_ROOT, OWNER_UID, OWNER_GID
    candidate = os.environ.get(TEST_ROOT_ENV)
    if candidate:
        if not os.path.isabs(candidate) or os.path.realpath(candidate) != candidate:
            stop("test root is not one canonical absolute path.", 64)
        info = os.stat(candidate, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            stop("test root is not one private caller-owned directory.", 64)
        TEST_ROOT = candidate
        OWNER_UID = info.st_uid
        OWNER_GID = info.st_gid
    elif os.geteuid() != 0:
        stop("V1 LOCAL_PRIVATE reconciler must run as root.", 77)
    if os.environ.get("DOCKER_HOST") not in (None, "", "unix:///var/run/docker.sock"):
        stop("caller-selected DOCKER_HOST is forbidden.", 64)
    if os.environ.get("DOCKER_CONTEXT") not in (None, "", "default"):
        stop("caller-selected DOCKER_CONTEXT is forbidden.", 64)
    if TEST_ROOT is None:
        if os.path.realpath(sys.argv[0]) != RECONCILER:
            stop("reconciler must run from its fixed installed path.", 77)
        installed = os.stat(RECONCILER, follow_symlinks=False)
        if installed.st_uid != 0 or stat.S_IMODE(installed.st_mode) != 0o555 or not stat.S_ISREG(installed.st_mode):
            stop("installed reconciler identity or mode is invalid.", 77)


def acquire_lock(logical: str, label: str) -> int:
    pathname = physical(logical)
    parent = os.path.dirname(pathname)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    fd = os.open(pathname, os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        stop(f"another V1 LOCAL_PRIVATE {label} operation is running.", 75)
    return fd


def string_list(value: object, label: str) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        stop(f"{label} is not one string sequence.")
    return list(value)


def environment_fingerprints(value: object, label: str) -> List[Dict[str, str]]:
    pairs: Dict[str, str] = {}
    if value is None:
        return []
    if isinstance(value, dict):
        iterable = [(key, "" if item is None else item) for key, item in value.items()]
    elif isinstance(value, list):
        iterable = []
        for item in value:
            if not isinstance(item, str) or "=" not in item:
                stop(f"{label} contains an invalid environment entry.")
            iterable.append(item.split("=", 1))
    else:
        stop(f"{label} is not one environment object or sequence.")
    for key, item in iterable:
        if not isinstance(key, str) or ENV_NAME_RE.fullmatch(key) is None or not isinstance(item, (str, int, float, bool)):
            stop(f"{label} contains an invalid environment name/value.")
        if key in pairs:
            stop(f"{label} contains duplicate environment name {key}.")
        pairs[key] = digest(str(item).encode())
    return [{"name": key, "valueSha256": pairs[key]} for key in sorted(pairs)]


def duration_nanoseconds(value: object, label: str) -> int:
    if isinstance(value, bool):
        stop(f"{label} duration is invalid.")
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        stop(f"{label} duration is invalid.")
    matches = list(re.finditer(r"([0-9]+)(ns|us|ms|s|m|h)", value))
    if not matches or "".join(match.group(0) for match in matches) != value:
        stop(f"{label} duration is not canonical.")
    scale = {"ns": 1, "us": 1_000, "ms": 1_000_000, "s": 1_000_000_000, "m": 60_000_000_000, "h": 3_600_000_000_000}
    rank = {"ns": 0, "us": 1, "ms": 2, "s": 3, "m": 4, "h": 5}
    units = [match.group(2) for match in matches]
    if any(rank[left] <= rank[right] for left, right in zip(units, units[1:])):
        stop(f"{label} duration is not canonical.")
    return sum(int(match.group(1)) * scale[match.group(2)] for match in matches)


def normalized_health(value: object, label: str, *, inspect: bool = False) -> Optional[Dict[str, object]]:
    if value is None:
        return None
    if not isinstance(value, dict):
        stop(f"{label} healthcheck is invalid.")
    if inspect:
        return {
            "intervalNs": int(value.get("Interval", 0)),
            "retries": int(value.get("Retries", 0)),
            "startPeriodNs": int(value.get("StartPeriod", 0)),
            "test": string_list(value.get("Test"), f"{label} healthcheck test"),
            "timeoutNs": int(value.get("Timeout", 0)),
        }
    test = ["NONE"] if value.get("disable") is True else string_list(value.get("test"), f"{label} healthcheck test")
    return {
        "intervalNs": duration_nanoseconds(value.get("interval", 0), f"{label} interval"),
        "retries": int(value.get("retries", 0)),
        "startPeriodNs": duration_nanoseconds(value.get("start_period", 0), f"{label} start period"),
        "test": test,
        "timeoutNs": duration_nanoseconds(value.get("timeout", 0), f"{label} timeout"),
    }


def resource_name(definitions: object, source: str, project: str, label: str) -> str:
    if not isinstance(definitions, dict) or source not in definitions:
        stop(f"{label} references undeclared resource {source}.")
    definition = definitions[source] or {}
    if not isinstance(definition, dict):
        stop(f"{label} resource {source} is invalid.")
    explicit = definition.get("name")
    if explicit is not None:
        if not isinstance(explicit, str) or not explicit:
            stop(f"{label} resource name is invalid.")
        return explicit
    return f"{project}_{source}"


def render_mounts(render: Dict[str, object], service: Dict[str, object], project: str, label: str) -> List[Dict[str, object]]:
    result: List[Dict[str, object]] = []
    volumes = service.get("volumes", [])
    if not isinstance(volumes, list):
        stop(f"{label} volumes are invalid.")
    for index, item in enumerate(volumes):
        if not isinstance(item, dict):
            stop(f"{label} volume {index} is not a rendered object.")
        mount_type = item.get("type", "volume")
        target = item.get("target")
        source = item.get("source", "")
        if mount_type not in ("bind", "volume", "tmpfs") or not isinstance(target, str) or not target.startswith("/") or not isinstance(source, str):
            stop(f"{label} volume {index} is invalid.")
        if mount_type == "volume":
            source = resource_name(render.get("volumes", {}), source, project, label)
        elif mount_type == "bind" and (not source.startswith("/") or os.path.normpath(source) != source):
            stop(f"{label} bind source is not one absolute canonical path.")
        result.append({"readOnly": item.get("read_only") is True, "source": source, "target": target, "type": mount_type})
    for kind, default_root in (("secrets", "/run/secrets"), ("configs", "/")):
        entries = service.get(kind, [])
        definitions = render.get(kind, {})
        if not isinstance(entries, list) or not isinstance(definitions, dict):
            stop(f"{label} {kind} are invalid.")
        for index, item in enumerate(entries):
            if isinstance(item, str):
                source_name, target = item, f"{default_root}/{item}" if kind == "secrets" else f"/{item}"
            elif isinstance(item, dict):
                source_name = item.get("source")
                target_value = item.get("target", source_name)
                target = target_value if isinstance(target_value, str) and target_value.startswith("/") else f"{default_root}/{target_value}"
            else:
                stop(f"{label} {kind} entry {index} is invalid.")
            definition = definitions.get(source_name) if isinstance(source_name, str) else None
            if kind == "configs" and isinstance(definition, dict) and "content" in definition:
                if (
                    set(definition) != {"content", "name"}
                    or not isinstance(definition.get("content"), str)
                    or not definition["content"]
                    or not isinstance(definition.get("name"), str)
                    or not definition["name"]
                    or (isinstance(item, dict) and set(item) - {"source", "target"})
                    or service.get("read_only") is True
                ):
                    stop(f"{label} inline config is not one canonical writable-layer injection.")
                # Docker Compose copies inline configs into the container after
                # create; they are not Engine mounts. Their exact bytes remain
                # bound by the canonical render used for forced recreation.
                continue
            source = definition.get("file") if isinstance(definition, dict) else None
            if not isinstance(source, str) or not source.startswith("/") or os.path.normpath(source) != source:
                stop(f"{label} {kind} source is not one absolute rendered file.")
            result.append({"readOnly": True, "source": source, "target": target, "type": "bind"})
    return sorted(result, key=lambda item: (item["target"], item["type"], item["source"], item["readOnly"]))


def render_networks(
    render: Dict[str, object], service_name: str, service: Dict[str, object], project: str, label: str
) -> Tuple[str, List[str], List[Dict[str, object]]]:
    network_mode = service.get("network_mode")
    networks = service.get("networks", {})
    if network_mode is not None:
        if not isinstance(network_mode, str) or network_mode not in ("none", "host"):
            stop(f"{label} network_mode is unsupported or invalid.")
        return network_mode, [], []
    if isinstance(networks, list):
        definitions = {name: {} for name in networks}
    elif isinstance(networks, dict):
        definitions = networks
    else:
        stop(f"{label} networks are invalid.")
    container_name = service.get("container_name")
    if container_name is not None and (not isinstance(container_name, str) or not container_name):
        stop(f"{label} container_name is invalid.")
    endpoints = []
    for name, raw in definitions.items():
        definition = {} if raw is None else raw
        if not isinstance(name, str) or not name or not isinstance(definition, dict):
            stop(f"{label} network endpoint is invalid.")
        aliases = definition.get("aliases", [])
        if aliases is None:
            aliases = []
        if not isinstance(aliases, list) or any(not isinstance(alias, str) or not alias for alias in aliases):
            stop(f"{label} network aliases are invalid.")
        expected_aliases = {service_name, *aliases}
        if container_name:
            expected_aliases.add(container_name)
        endpoints.append({
            "aliases": sorted(expected_aliases),
            "networkName": resource_name(render.get("networks", {}), name, project, label),
        })
    endpoints.sort(key=lambda item: item["networkName"])
    return "managed", [item["networkName"] for item in endpoints], endpoints


def render_ports(service: Dict[str, object], label: str) -> List[Dict[str, object]]:
    ports = service.get("ports", [])
    if not isinstance(ports, list):
        stop(f"{label} ports are invalid.")
    result = []
    for item in ports:
        if not isinstance(item, dict):
            stop(f"{label} port is not one rendered object.")
        target, published = item.get("target"), item.get("published")
        if isinstance(published, str) and published.isdigit():
            published = int(published)
        protocol, host_ip = item.get("protocol", "tcp"), item.get("host_ip", "0.0.0.0")
        if not isinstance(target, int) or not isinstance(published, int) or protocol not in ("tcp", "udp") or not isinstance(host_ip, str):
            stop(f"{label} port is invalid.")
        result.append({"containerPort": target, "hostIp": host_ip, "hostPort": published, "protocol": protocol})
    return sorted(result, key=lambda item: (item["hostIp"], item["hostPort"], item["protocol"], item["containerPort"]))


def nonnegative_integer(value: object, label: str) -> int:
    if value in (None, ""):
        return 0
    if isinstance(value, bool):
        stop(f"{label} is not a non-negative integer.")
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        stop(f"{label} is not a non-negative integer.")
    if parsed < 0 or str(value).strip() not in (str(parsed), f"{parsed}.0"):
        stop(f"{label} is not a canonical non-negative integer.")
    return parsed


def rendered_nano_cpus(value: object, label: str) -> int:
    if value in (None, ""):
        return 0
    if isinstance(value, bool):
        stop(f"{label} is not a CPU quota.")
    try:
        cpus = Decimal(str(value))
        nano = cpus * Decimal(1_000_000_000)
    except (InvalidOperation, ValueError):
        stop(f"{label} is not a CPU quota.")
    if cpus < 0 or nano != nano.to_integral_value():
        stop(f"{label} cannot be represented as exact NanoCPUs.")
    return int(nano)


def byte_size(value: str, label: str) -> int:
    match = re.fullmatch(r"([0-9]+)([kKmMgGtT])?(?:[iI]?[bB])?", value)
    if match is None:
        stop(f"{label} is not one canonical byte size.")
    exponent = {None: 0, "k": 1, "m": 2, "g": 3, "t": 4}[match.group(2).lower() if match.group(2) else None]
    return int(match.group(1)) * (1024 ** exponent)


def normalize_tmpfs_options(raw: str, label: str) -> List[str]:
    if not isinstance(raw, str):
        stop(f"{label} options are invalid.")
    options = []
    for option in filter(None, raw.split(",")):
        if option.startswith("size="):
            option = f"size={byte_size(option.removeprefix('size='), label + ' size')}"
        options.append(option)
    if len(options) != len(set(options)):
        stop(f"{label} options are duplicated.")
    return sorted(options)


def render_tmpfs(service: Dict[str, object], label: str) -> List[Dict[str, object]]:
    raw = service.get("tmpfs", [])
    if not isinstance(raw, list):
        stop(f"{label} tmpfs is invalid.")
    result = []
    for index, item in enumerate(raw):
        if not isinstance(item, str):
            stop(f"{label} tmpfs {index} is invalid.")
        target, separator, options = item.partition(":")
        if not target.startswith("/") or (separator and not options):
            stop(f"{label} tmpfs {index} target/options are invalid.")
        result.append({"options": normalize_tmpfs_options(options, f"{label} tmpfs {target}"), "target": target})
    if len({item["target"] for item in result}) != len(result):
        stop(f"{label} tmpfs targets are duplicated.")
    return sorted(result, key=lambda item: item["target"])


def inspect_tmpfs(host: Dict[str, object], label: str) -> List[Dict[str, object]]:
    raw = host.get("Tmpfs") or {}
    if not isinstance(raw, dict):
        stop(f"{label} tmpfs is invalid.")
    result = []
    for target, options in raw.items():
        if not isinstance(target, str) or not target.startswith("/") or not isinstance(options, str):
            stop(f"{label} tmpfs entry is invalid.")
        result.append({"options": normalize_tmpfs_options(options, f"{label} tmpfs {target}"), "target": target})
    return sorted(result, key=lambda item: item["target"])


def render_ulimits(service: Dict[str, object], label: str) -> List[Dict[str, object]]:
    raw = service.get("ulimits", {})
    if not isinstance(raw, dict):
        stop(f"{label} ulimits are invalid.")
    result = []
    for name, value in raw.items():
        if not isinstance(name, str) or NAME_RE.fullmatch(name) is None:
            stop(f"{label} ulimit name is invalid.")
        if isinstance(value, dict) and set(value) == {"soft", "hard"}:
            soft = nonnegative_integer(value["soft"], f"{label} {name} soft ulimit")
            hard = nonnegative_integer(value["hard"], f"{label} {name} hard ulimit")
        else:
            soft = hard = nonnegative_integer(value, f"{label} {name} ulimit")
        result.append({"hard": hard, "name": name, "soft": soft})
    return sorted(result, key=lambda item: item["name"])


def inspect_ulimits(host: Dict[str, object], label: str) -> List[Dict[str, object]]:
    raw = host.get("Ulimits") or []
    if not isinstance(raw, list):
        stop(f"{label} ulimits are invalid.")
    result = []
    for item in raw:
        if not isinstance(item, dict) or set(item) != {"Name", "Soft", "Hard"}:
            stop(f"{label} ulimit entry is invalid.")
        name = item["Name"]
        if not isinstance(name, str) or NAME_RE.fullmatch(name) is None:
            stop(f"{label} ulimit name is invalid.")
        result.append({
            "hard": nonnegative_integer(item["Hard"], f"{label} {name} hard ulimit"),
            "name": name,
            "soft": nonnegative_integer(item["Soft"], f"{label} {name} soft ulimit"),
        })
    if len({item["name"] for item in result}) != len(result):
        stop(f"{label} ulimits are duplicated.")
    return sorted(result, key=lambda item: item["name"])


def normalize_extra_hosts(raw: object, label: str, *, rendered: bool) -> List[Dict[str, str]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        stop(f"{label} extra hosts are invalid.")
    result = []
    for item in raw:
        if not isinstance(item, str):
            stop(f"{label} extra-host entry is invalid.")
        if rendered:
            host, separator, address = item.partition("=")
        else:
            host, separator, address = item.partition(":")
        if not separator or not host or not address:
            stop(f"{label} extra-host entry is malformed.")
        result.append({"address": address, "host": host})
    if len({item["host"] for item in result}) != len(result):
        stop(f"{label} extra hosts are duplicated.")
    return sorted(result, key=lambda item: (item["host"], item["address"]))


def runtime_label_subset(labels: object, label: str) -> Dict[str, str]:
    if not isinstance(labels, dict):
        stop(f"{label} labels are invalid.")
    expected = set(RUNTIME_IDENTITY_LABEL_BY_ENV.values())
    result = {name: labels[name] for name in sorted(expected) if name in labels}
    if any(not isinstance(value, str) or not value for value in result.values()):
        stop(f"{label} runtime identity label is invalid.")
    return result


def routing_label_subset(labels: object, label: str) -> Dict[str, str]:
    if not isinstance(labels, dict):
        stop(f"{label} labels are invalid.")
    result = {name: value for name, value in labels.items() if str(name).startswith("traefik.")}
    if any(not isinstance(name, str) or not name or not isinstance(value, str) for name, value in result.items()):
        stop(f"{label} routing label is invalid.")
    return {name: result[name] for name in sorted(result)}


def render_logging(service: Dict[str, object], label: str) -> Dict[str, object]:
    raw = service.get("logging")
    if raw is None:
        return {"driver": "json-file", "options": {}}
    value = exact_keys(raw, ("driver", "options"), f"{label} logging")
    driver, options = value["driver"], value["options"]
    if not isinstance(driver, str) or not driver or not isinstance(options, dict):
        stop(f"{label} logging configuration is invalid.")
    if any(not isinstance(name, str) or not name or not isinstance(option, str) for name, option in options.items()):
        stop(f"{label} logging option is invalid.")
    return {"driver": driver, "options": {name: options[name] for name in sorted(options)}}


def inspect_logging(host: Dict[str, object], label: str) -> Dict[str, object]:
    raw = host.get("LogConfig")
    if not isinstance(raw, dict) or set(raw) != {"Type", "Config"}:
        stop(f"{label} logging configuration is invalid.")
    driver, options = raw["Type"], raw["Config"]
    if not isinstance(driver, str) or not driver or not isinstance(options, dict):
        stop(f"{label} logging configuration is invalid.")
    if any(not isinstance(name, str) or not name or not isinstance(option, str) for name, option in options.items()):
        stop(f"{label} logging option is invalid.")
    return {"driver": driver, "options": {name: options[name] for name in sorted(options)}}


def render_service_semantics(render: Dict[str, object], service_name: str, image_id: str, project: str) -> Dict[str, object]:
    services = render.get("services")
    service = services.get(service_name) if isinstance(services, dict) else None
    label = f"exact render service {service_name}"
    if not isinstance(service, dict):
        stop(f"{label} is missing.")
    image_reference = service.get("image")
    if not isinstance(image_reference, str) or DIGEST_REFERENCE_RE.fullmatch(image_reference) is None:
        stop(f"{label} image reference is not digest-pinned.")
    if not isinstance(image_id, str) or IMAGE_ID_RE.fullmatch(image_id) is None:
        stop(f"{label} image ID authority is invalid.")
    network_mode, networks, network_endpoints = render_networks(render, service_name, service, project, label)
    restart = service.get("restart", "no")
    if not isinstance(restart, str):
        stop(f"{label} restart policy is invalid.")
    blkio = service.get("blkio_config", {})
    if not isinstance(blkio, dict):
        stop(f"{label} blkio configuration is invalid.")
    return {
        "blkioWeight": nonnegative_integer(blkio.get("weight"), f"{label} blkio weight"),
        "capAdd": sorted(string_list(service.get("cap_add"), f"{label} cap_add")),
        "capDrop": sorted(string_list(service.get("cap_drop"), f"{label} cap_drop")),
        "command": string_list(service.get("command"), f"{label} command"),
        "cpuShares": nonnegative_integer(service.get("cpu_shares"), f"{label} CPU shares"),
        "entrypoint": string_list(service.get("entrypoint"), f"{label} entrypoint"),
        "environment": environment_fingerprints(service.get("environment"), f"{label} environment"),
        "extraHosts": normalize_extra_hosts(service.get("extra_hosts"), label, rendered=True),
        "groupAdd": sorted(string_list(service.get("group_add"), f"{label} group_add")),
        "healthcheck": normalized_health(service.get("healthcheck"), label),
        "imageId": image_id,
        "imageReference": image_reference,
        "init": service.get("init") is True,
        "memoryBytes": nonnegative_integer(service.get("mem_limit"), f"{label} memory limit"),
        "memoryReservationBytes": nonnegative_integer(service.get("mem_reservation"), f"{label} memory reservation"),
        "logging": render_logging(service, label),
        "mounts": render_mounts(render, service, project, label),
        "nanoCpus": rendered_nano_cpus(service.get("cpus"), f"{label} CPU quota"),
        "networkMode": network_mode,
        "networkEndpoints": network_endpoints,
        "networks": networks,
        "pidMode": str(service.get("pid", "")),
        "pidsLimit": service.get("pids_limit") or 0,
        "ports": render_ports(service, label),
        "privileged": service.get("privileged") is True,
        "readOnlyRootfs": service.get("read_only") is True,
        "restartPolicy": restart,
        "routingLabels": routing_label_subset(service.get("labels", {}), label),
        "runtimeIdentityLabels": runtime_label_subset(service.get("labels", {}), label),
        "securityOpt": sorted(string_list(service.get("security_opt"), f"{label} security_opt")),
        "tmpfs": render_tmpfs(service, label),
        "ulimits": render_ulimits(service, label),
        "user": str(service.get("user", "")),
        "workingDirectory": str(service.get("working_dir", "")),
    }


def parse_env(data: bytes, label: str) -> Tuple[List[str], Dict[str, str]]:
    if b"\x00" in data or b"\r" in data:
        stop(f"{label} contains NUL or carriage-return bytes.")
    try:
        lines = data.decode("utf-8", errors="strict").split("\n")
    except UnicodeDecodeError:
        stop(f"{label} is not UTF-8.")
    if lines and lines[-1] == "":
        lines.pop()
    values: Dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        candidate = stripped.removeprefix("export ")
        if "=" not in candidate:
            stop(f"{label} contains an unsupported non-assignment line.")
        name, raw = candidate.split("=", 1)
        name = name.strip()
        if ENV_NAME_RE.fullmatch(name) is None or name in values:
            stop(f"{label} contains an invalid or duplicate variable.")
        raw = raw.strip()
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
            raw = raw[1:-1]
        values[name] = raw
    return lines, values


def read_deployment_environment(repo_root: str) -> bytes:
    pathname = os.path.join(repo_root, ".env")
    no_symlink_chain(pathname, "deployment environment")
    owner = os.stat(repo_root, follow_symlinks=False)
    if not stat.S_ISDIR(owner.st_mode) or owner.st_uid == 0 or stat.S_IMODE(owner.st_mode) & 0o022:
        stop("staging deployment checkout owner/mode is invalid.")
    fd = os.open(pathname, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != owner.st_uid or before.st_gid != owner.st_gid
            or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) not in (0o400, 0o600)
            or before.st_size > 1024 * 1024
        ):
            stop("deployment environment is not one private staging-owner file.")
        data = os.read(fd, 1024 * 1024 + 1)
        after = os.fstat(fd)
        if len(data) > 1024 * 1024 or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            stop("deployment environment changed while it was read.")
        return data
    finally:
        os.close(fd)


def materialize_environment(
    repo_root: str,
    release: str,
    local_ops_image: str,
    local_restic_image: str,
    runtime_identity: Optional[Dict[str, str]] = None,
) -> Tuple[bytes, Dict[str, str]]:
    source = os.path.join(repo_root, ".env")
    if not os.path.exists(source):
        stop("clean exact-main checkout has no deployment .env.")
    # .env is deployment-owned and may contain secrets; it is never printed or
    # embedded in authority.  Its exact bytes are bound by hash only.
    data = read_deployment_environment(repo_root)
    lines, values = parse_env(data, "deployment environment")
    ops_repository = "127.0.0.1:5000/platform/ops"
    ops_prefix = f"{ops_repository}@sha256:"
    if (
        not isinstance(local_ops_image, str)
        or DIGEST_REFERENCE_RE.fullmatch(local_ops_image) is None
        or not local_ops_image.startswith(ops_prefix)
        or values.get("PLATFORM_OPS_IMAGE") != local_ops_image
    ):
        stop("deployment environment lacks the exact immutable local ops image binding.")
    ops_sha256 = local_ops_image.removeprefix(ops_prefix)
    if SHA256_RE.fullmatch(ops_sha256) is None or ops_sha256 == "0" * 64:
        stop("deployment environment local ops image digest is not one non-zero SHA-256.")
    restic_prefix = "127.0.0.1:5000/platform/restic-rclone@sha256:"
    if (
        not isinstance(local_restic_image, str)
        or DIGEST_REFERENCE_RE.fullmatch(local_restic_image) is None
        or not local_restic_image.startswith(restic_prefix)
        or local_restic_image.removeprefix(restic_prefix) == "0" * 64
    ):
        stop("prepared Restic/rclone helper is not one immutable loopback image authority.")
    replacements = {
        "DOCKER_ACTION_ACTIVATION_INBOX": "/srv/platform/provider-activation/inbox",
        "DOCKER_ACTION_ACTIVE_RECEIPT_FILE": "/srv/platform/trust/active-receipt.json",
        "DOCKER_ACTION_ACTIVE_RECEIPT_SHA256": "0" * 64,
        "DOCKER_ACTION_COMBINED_RENDER_SHA256": "0" * 64,
        "DOCKER_ACTION_RUNTIME_INTENT_FILE": "/srv/platform/trust/runtime-intent.json",
        "DOCKER_ACTION_RUNTIME_INTENT_ID": "intent.v1-local-private-ready-but-disabled",
        "HOSTED_WORKLOAD_LOCK": "",
        "HOSTED_WORKLOAD_MODE": "no-hosted",
        "HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE": (
            f"{release}/config/no-hosted-workloads.local-private.lock.json"
        ),
        "CONTROL_CENTER_LOCAL_CA_CERT_SOURCE": LOCAL_CA_CERTIFICATE,
        # The three backup-profile services are deliberately not V1 activation
        # targets.  Bind their render-only image inputs to the already built,
        # locally published immutable ops image so Compose can render all 20
        # services without introducing a provider image/build authority.  Its
        # missing provider entrypoints also make accidental startup fail closed.
        "PLATFORM_BACKUP_SCHEDULER_IMAGE_REPOSITORY": ops_repository,
        "PLATFORM_BACKUP_SCHEDULER_IMAGE_SHA256": ops_sha256,
        "PLATFORM_COMPOSE_VARIANT": "LOCAL_PRIVATE",
        "PLATFORM_CERTS_DIR": CERTIFICATES_ROOT,
        "PLATFORM_DATA_ROOT": DEPLOYMENT_REPO,
        "PLATFORM_DOCKER_ACTION_BROKER_IMAGE_REPOSITORY": ops_repository,
        "PLATFORM_DOCKER_ACTION_BROKER_IMAGE_SHA256": ops_sha256,
        "PLATFORM_PROVIDER_ACTIVATION_SIDECAR_IMAGE_REPOSITORY": ops_repository,
        "PLATFORM_PROVIDER_ACTIVATION_SIDECAR_IMAGE_SHA256": ops_sha256,
        "PHP_PROJECTS_DIR": PROJECT_SOURCE_ROOT,
        "PROJECT_SOURCE_DIR": PROJECT_SOURCE_ROOT,
        # The helper is built from the exact release and published locally, but
        # it is not a Compose workload.  Bind it only into the immutable render
        # descriptor; do not alter the deployment-owned brownfield .env.
        "RESTIC_IMAGE": local_restic_image,
        "PLATFORM_SECRETS_ROOT": SECRET_DIR,
        "PLATFORM_STATE_DIR": PROJECT_STATE_ROOT,
        "CONTROL_CENTER_DATABASE_URL_SECRET_FILE": DATABASE_SECRET,
        "CONTROL_CENTER_FIRST_CONFIGURATION_BOOTSTRAP_TOKEN_SECRET_FILE": BOOTSTRAP_SECRET,
        "CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE": KEYCLOAK_CLIENT_SECRET,
        "V1_CONFIDENTIAL_BACKUP_PASSPHRASE_FILE": CONFIDENTIAL_BACKUP_PASSPHRASE,
        "WAF_TLS_KEY_GID": str(SECRET_GID),
    }
    if runtime_identity is not None:
        if set(runtime_identity) != set(RUNTIME_IDENTITY_ENV):
            stop("runtime identity environment is not the exact closed V1 tuple.")
        replacements.update(runtime_identity)
    output: List[str] = []
    emitted = set()
    for line in lines:
        stripped = line.strip()
        candidate = stripped.removeprefix("export ")
        name = candidate.split("=", 1)[0].strip() if "=" in candidate else ""
        if name in replacements:
            if name not in emitted:
                output.append(f"{name}={replacements[name]}")
                emitted.add(name)
            continue
        output.append(line)
    for name in sorted(set(replacements) - emitted):
        output.append(f"{name}={replacements[name]}")
    rendered = ("\n".join(output).rstrip("\n") + "\n").encode("utf-8")
    _, final_values = parse_env(rendered, "exact render environment")
    if final_values.get("PLATFORM_COMPOSE_VARIANT") != "LOCAL_PRIVATE":
        stop("exact render environment lacks the unique LOCAL_PRIVATE variant.")
    for name, expected in replacements.items():
        if final_values.get(name) != expected:
            stop(f"exact render environment does not bind {name} to its fixed V1 path.")
    present_runtime_identity = {name for name in RUNTIME_IDENTITY_ENV if name in final_values}
    if runtime_identity is None and present_runtime_identity:
        stop("source render environment unexpectedly carries a runtime identity.")
    if runtime_identity is not None and present_runtime_identity != set(RUNTIME_IDENTITY_ENV):
        stop("final render environment does not carry the complete runtime identity.")
    return rendered, final_values


def validate_confidential_passphrase_bytes(data: bytes) -> None:
    try:
        text = data.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        stop("confidential backup passphrase is not ASCII.")
    value = text.removesuffix("\n")
    if not value or "\n" in value or len(value) < 64 or len(value) > 512:
        stop("confidential backup passphrase has an invalid fixed private-file format.")


def read_passphrase_stage(pathname: str, label: str, allowed_links: Tuple[int, ...]) -> bytes:
    no_symlink_chain(pathname, label)
    fd = os.open(pathname, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode) or before.st_uid != OWNER_UID or before.st_gid != OWNER_GID
            or before.st_nlink not in allowed_links or stat.S_IMODE(before.st_mode) != 0o400
            or before.st_size > 4096
        ):
            stop(f"{label} metadata differs from the private crash-recovery contract.")
        data = os.read(fd, 4097)
        after = os.fstat(fd)
        if len(data) > 4096 or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_nlink) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink
        ):
            stop(f"{label} changed while it was read.")
        return data
    finally:
        os.close(fd)


def fsync_directory(pathname: str) -> None:
    fd = os.open(pathname, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def fsync_regular_file(pathname: str) -> None:
    fd = os.open(pathname, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def provision_confidential_backup_passphrase() -> None:
    """Crash-safely publish once, or revalidate, the root-only recovery key."""
    ensure_directory(STATE_DIR, 0o700)
    pathname = physical(CONFIDENTIAL_BACKUP_PASSPHRASE)
    temporary = pathname + ".staging"
    parent = os.path.dirname(pathname)

    if os.path.lexists(pathname):
        final_info = os.lstat(pathname)
        if os.path.lexists(temporary):
            temporary_info = os.lstat(temporary)
            if (
                (final_info.st_dev, final_info.st_ino) != (temporary_info.st_dev, temporary_info.st_ino)
                or final_info.st_nlink != 2 or temporary_info.st_nlink != 2
            ):
                stop("confidential passphrase publish residue is not the same atomic hard-link identity.")
            data = read_passphrase_stage(pathname, "published confidential backup passphrase", (2,))
            if read_passphrase_stage(temporary, "confidential passphrase publish residue", (2,)) != data:
                stop("confidential passphrase publish residue bytes differ from final.")
            validate_confidential_passphrase_bytes(data)
            os.unlink(temporary)
            fsync_directory(parent)
        data = read_passphrase_stage(pathname, "confidential backup passphrase", (1,))
        validate_confidential_passphrase_bytes(data)
        return

    data: Optional[bytes] = None
    if os.path.lexists(temporary):
        staged = read_passphrase_stage(temporary, "staged confidential backup passphrase", (1,))
        if not staged:
            # A fault immediately after O_EXCL create leaves no key bytes.  The
            # fixed name/owner/mode/link metadata was proven above, so this and
            # only this recognized incomplete staging file may be removed.
            os.unlink(temporary)
            fsync_directory(parent)
        else:
            validate_confidential_passphrase_bytes(staged)
            data = staged
    if data is None:
        data = (secrets.token_urlsafe(64) + "\n").encode("ascii")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(temporary, flags, 0o400)
        except OSError as error:
            stop(f"cannot exclusively stage the confidential backup passphrase: {error.strerror}.")
        try:
            os.fchmod(fd, 0o400)
            test_fault("PASSPHRASE_AFTER_TEMP_CREATE")
            offset = 0
            while offset < len(data):
                offset += os.write(fd, data[offset:])
            test_fault("PASSPHRASE_AFTER_TEMP_WRITE")
            os.fsync(fd)
            test_fault("PASSPHRASE_AFTER_TEMP_FSYNC")
        finally:
            os.close(fd)
    staged = read_passphrase_stage(temporary, "staged confidential backup passphrase", (1,))
    if staged != data:
        stop("staged confidential backup passphrase bytes changed before publication.")
    validate_confidential_passphrase_bytes(data)
    fsync_regular_file(temporary)
    try:
        os.link(temporary, pathname, follow_symlinks=False)
    except FileExistsError:
        stop("confidential backup passphrase appeared during atomic no-replace publication.")
    except OSError as error:
        stop(f"cannot atomically publish the confidential backup passphrase: {error.strerror}.")
    fsync_directory(parent)
    test_fault("PASSPHRASE_AFTER_PUBLISH")
    if read_passphrase_stage(pathname, "published confidential backup passphrase", (2,)) != data:
        stop("published confidential backup passphrase differs from fully synced staging bytes.")
    os.unlink(temporary)
    fsync_directory(parent)
    if read_passphrase_stage(pathname, "confidential backup passphrase", (1,)) != data:
        stop("confidential backup passphrase changed after atomic publication cleanup.")


def update_deployment_environment(repo_root: str, replacements: Dict[str, str]) -> None:
    if set(replacements) != set(DEPLOYMENT_LOCAL_IMAGE_ENV) or any(DIGEST_REFERENCE_RE.fullmatch(value) is None for value in replacements.values()):
        stop("deployment environment update differs from the four closed active local image variables.")
    pathname = os.path.join(repo_root, ".env")
    no_symlink_chain(pathname, "deployment environment")
    parent_info = os.stat(repo_root, follow_symlinks=False)
    if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid == 0 or stat.S_IMODE(parent_info.st_mode) & 0o022:
        stop("deployment checkout anchor ownership/type/mode is invalid.")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(pathname, flags)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode) or info.st_uid != parent_info.st_uid or info.st_gid != parent_info.st_gid
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) not in (0o400, 0o600)
            or info.st_size > 1024 * 1024
        ):
            stop("deployment .env is not one private deployment-owned regular file.")
        data = os.read(fd, 1024 * 1024 + 1)
        after_read = os.fstat(fd)
        if len(data) > 1024 * 1024 or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
            after_read.st_dev, after_read.st_ino, after_read.st_size, after_read.st_mtime_ns
        ):
            stop("deployment .env changed while it was read.")
    finally:
        os.close(fd)
    tracked = git_output(repo_root, ["ls-files", "--", ".env"], "deployment environment ownership")
    if tracked:
        stop("refusing to update tracked .env; deployment environment must be deployment-owned.")
    lines, _ = parse_env(data, "deployment environment")
    output: List[str] = []
    seen = set()
    for line in lines:
        stripped = line.strip()
        candidate = stripped.removeprefix("export ")
        name = candidate.split("=", 1)[0].strip() if "=" in candidate else ""
        if name in replacements:
            if name in seen:
                stop("deployment environment has duplicate image variables.")
            output.append(f"{name}={replacements[name]}")
            seen.add(name)
        else:
            output.append(line)
    for name in sorted(set(replacements) - seen):
        output.append(f"{name}={replacements[name]}")
    updated = ("\n".join(output).rstrip("\n") + "\n").encode("utf-8")
    # Preserve the deployment file's restrictive mode; never print its bytes.
    parent = os.path.dirname(pathname)
    fd, temporary = tempfile.mkstemp(prefix=".env.", dir=parent)
    try:
        os.fchmod(fd, stat.S_IMODE(info.st_mode))
        os.fchown(fd, info.st_uid, info.st_gid)
        offset = 0
        while offset < len(updated):
            offset += os.write(fd, updated[offset:])
        os.fsync(fd)
        os.close(fd)
        fd = -1
        current = os.stat(pathname, follow_symlinks=False)
        if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) != (
            info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns
        ):
            stop("deployment .env changed before its atomic replacement.")
        os.replace(temporary, pathname)
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        if os.path.exists(temporary):
            os.unlink(temporary)
    verify_fd = os.open(pathname, flags)
    try:
        verify_info = os.fstat(verify_fd)
        verify_data = os.read(verify_fd, 1024 * 1024 + 1)
    finally:
        os.close(verify_fd)
    if verify_info.st_uid != info.st_uid or verify_info.st_gid != info.st_gid or stat.S_IMODE(verify_info.st_mode) != stat.S_IMODE(info.st_mode):
        stop("updated deployment environment owner/mode changed.")
    _, values = parse_env(verify_data, "updated deployment environment")
    if any(values.get(name) != value for name, value in replacements.items()):
        stop("deployment environment image references changed during atomic update.")


def build_and_publish_local_images(repo_root: str, release: str, commit: str) -> Dict[str, str]:
    ensure_node_utility_image(release)
    replacements: Dict[str, str] = {}
    for variable, dockerfile_relative, repository in LOCAL_IMAGE_BUILDS:
        dockerfile = release_file(release, dockerfile_relative)
        tag = f"127.0.0.1:5000/{repository}:v1-{commit}"
        run(
            [
                docker_binary(), "build", "--pull=false", "--file", dockerfile,
                "--tag", tag, physical(release),
            ],
            f"immutable release image build {variable}",
            cwd=physical(release),
            timeout=1800,
        )
        run([docker_binary(), "push", tag], f"loopback registry publish {variable}", timeout=600)
        objects = docker_json(["image", "inspect", tag], f"published image {variable}")
        if not isinstance(objects, list) or len(objects) != 1 or not isinstance(objects[0], dict):
            stop(f"published {variable} image inspection has wrong cardinality.")
        image_id = objects[0].get("Id")
        repo_digests = objects[0].get("RepoDigests")
        prefix = f"127.0.0.1:5000/{repository}@sha256:"
        candidates = sorted(item for item in repo_digests if isinstance(item, str) and item.startswith(prefix)) if isinstance(repo_digests, list) else []
        if len(candidates) != 1 or IMAGE_ID_RE.fullmatch(image_id or "") is None or DIGEST_REFERENCE_RE.fullmatch(candidates[0]) is None:
            stop(f"published {variable} image lacks one exact loopback RepoDigest/image ID.")
        digest_objects = docker_json(["image", "inspect", candidates[0]], f"published digest {variable}")
        if not isinstance(digest_objects, list) or len(digest_objects) != 1 or digest_objects[0].get("Id") != image_id:
            stop(f"published {variable} RepoDigest does not resolve to its built image ID.")
        replacements[variable] = candidates[0]
    update_deployment_environment(
        repo_root,
        {name: replacements[name] for name in DEPLOYMENT_LOCAL_IMAGE_ENV},
    )
    # .env is not a source artifact.  Re-prove the checkout stayed clean after
    # updating only this deployment-owned descriptor.
    if git_output(repo_root, ["status", "--porcelain=v1", "--untracked-files=all"], "post-image clean status"):
        stop("source checkout changed while immutable local images were prepared.")
    return replacements


def git_output(repo_root: str, arguments: List[str], label: str) -> bytes:
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    return run([
        git_binary(),
        "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=/dev/null",
        "-c", f"safe.directory={repo_root}",
        "-C", repo_root,
        *arguments,
    ], f"Git {label}", cwd="/", environment=environment, timeout=120)


def clean_checkout(repo_root: str) -> Tuple[str, str]:
    top = git_output(repo_root, ["rev-parse", "--show-toplevel"], "root").decode("ascii", errors="strict").strip()
    if os.path.realpath(top) != os.path.realpath(repo_root):
        stop("prepare must run at the root of the selected exact-main checkout.")
    status = git_output(repo_root, ["status", "--porcelain=v1", "--untracked-files=all"], "clean status")
    if status:
        stop("prepare requires a completely clean checkout, including no untracked files.")
    head = git_output(repo_root, ["rev-parse", "HEAD"], "HEAD").decode("ascii", errors="strict").strip()
    github_main = git_output(repo_root, ["rev-parse", "refs/remotes/github/main"], "github/main").decode("ascii", errors="strict").strip()
    tree = git_output(repo_root, ["rev-parse", "HEAD^{tree}"], "HEAD tree").decode("ascii", errors="strict").strip()
    if COMMIT_RE.fullmatch(head) is None or COMMIT_RE.fullmatch(github_main) is None or COMMIT_RE.fullmatch(tree) is None:
        stop("Git returned a non-canonical commit/tree identity.")
    if head != github_main:
        stop("prepare requires HEAD == refs/remotes/github/main.")
    return head, tree


def install_binding() -> Dict[str, str]:
    # This checkpoint authorizes only clean source/control-plane materialization
    # so prepare can create the exact authority and run the modern PRE producer.
    # It is deliberately not backup, restore, runtime or cutover authority.
    checkpoint_bytes = secure_file(INSTALL_CHECKPOINT, "bootstrap transport checkpoint", 65536)
    checkpoint = exact_keys(parse_json(checkpoint_bytes, "bootstrap transport checkpoint"), (
        "activationAuthorized", "authoritative", "backupEvidenceAuthoritative", "bridgeSha256",
        "candidateCommit", "candidateConsumerSha256", "candidateTree", "createdAtUnixSeconds",
        "gitBundleSha256", "purpose", "schema", "sourceArchiveSha256", "sourceArchiveSizeBytes",
        "transportVerified",
    ), "bootstrap transport checkpoint")
    commit, tree, archive_sha = checkpoint["candidateCommit"], checkpoint["candidateTree"], checkpoint["sourceArchiveSha256"]
    created = checkpoint["createdAtUnixSeconds"]
    if (
        checkpoint["schema"] != "platform.v1-bootstrap-transport-checkpoint/v1"
        or checkpoint["purpose"] != "CONTROL_PLANE_STAGING_ONLY"
        or checkpoint["activationAuthorized"] is not False
        or checkpoint["authoritative"] is not False
        or checkpoint["backupEvidenceAuthoritative"] is not False
        or checkpoint["transportVerified"] is not True
        or not isinstance(commit, str) or COMMIT_RE.fullmatch(commit) is None
        or not isinstance(tree, str) or COMMIT_RE.fullmatch(tree) is None
        or not isinstance(archive_sha, str) or SHA256_RE.fullmatch(archive_sha) is None
        or archive_sha == "0" * 64
        or isinstance(created, bool) or not isinstance(created, int)
        or created > int(time.time()) + 60 or int(time.time()) - created > 900
        or isinstance(checkpoint["sourceArchiveSizeBytes"], bool)
        or not isinstance(checkpoint["sourceArchiveSizeBytes"], int)
        or checkpoint["sourceArchiveSizeBytes"] < 1024
        or checkpoint["sourceArchiveSizeBytes"] > 512 * 1024 * 1024
    ):
        stop("bootstrap transport checkpoint is not one recent non-authoritative staging-only binding.")
    for key in ("bridgeSha256", "candidateConsumerSha256", "gitBundleSha256"):
        if not isinstance(checkpoint[key], str) or SHA256_RE.fullmatch(checkpoint[key]) is None or checkpoint[key] == "0" * 64:
            stop("bootstrap transport checkpoint contains a non-canonical integrity digest.")
    # Bytes are digest-bound below; the durable mode differs across lifecycle
    # stages (0o400 while freshly staged by the bootstrap bridge, 0o444 after a
    # completed prepare republishes it), so identity checks stay mode-agnostic
    # here and lifecycle-correctness is owned by prepare's write ordering.
    source_archive = secure_file(SOURCE_ARCHIVE, "bootstrap exact source archive", MAX_ARCHIVE)
    if len(source_archive) != checkpoint["sourceArchiveSizeBytes"] or digest(source_archive) != archive_sha:
        stop("bootstrap exact source archive differs from its transport size/digest binding.")
    release = release_root(commit, archive_sha)
    receipt_logical = f"/var/lib/platform-infrastructure/v1/install-receipts/{commit}-{archive_sha}.json"
    receipt = exact_keys(parse_json(secure_file(receipt_logical, "exact install-only receipt", MAX_AUTHORITY), "exact install-only receipt", True), (
        "activationAuthorized", "authorizationSource", "backupEvidenceAuthoritative", "candidateCommit", "candidateTree",
        "dataMutation", "dockerMutation", "readyButDisabled", "releaseRoot", "schema", "sourceArchiveSha256", "status",
    ), "exact install-only receipt")
    if (
        receipt["schema"] != "platform.v1-brownfield-install-receipt/v1"
        or receipt["status"] not in ("INSTALL_ONLY_COMPLETE", "ALREADY_INSTALLED")
        or receipt["activationAuthorized"] is not False
        or receipt["backupEvidenceAuthoritative"] is not False
        or receipt["dataMutation"] is not False
        or receipt["dockerMutation"] is not False
        or receipt["authorizationSource"] != "ROOT_OPERATOR_EXPLICIT_INSTALL_ONLY"
        or receipt["candidateCommit"] != commit
        or receipt["candidateTree"] != tree
        or receipt["sourceArchiveSha256"] != archive_sha
        or receipt["releaseRoot"] != release
    ):
        stop("install-only receipt differs from the fresh checkpoint-bound candidate.")
    return {"candidateCommit": commit, "candidateTree": tree, "releaseRoot": release, "sourceArchiveSha256": archive_sha}


def stable_file_digest(logical: str, label: str, maximum: int) -> str:
    pathname = physical(logical)
    no_symlink_chain(pathname, label)
    fd = os.open(pathname, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != OWNER_UID or before.st_gid != OWNER_GID or before.st_nlink != 1 or before.st_size < 1 or before.st_size > maximum:
            stop(f"{label} ownership/type/size is invalid.")
        hasher = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                stop(f"{label} exceeded its byte boundary.")
            hasher.update(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            stop(f"{label} changed while it was hashed.")
        return hasher.hexdigest()
    finally:
        os.close(fd)


def fixed_file_identity(logical: str, label: str) -> Tuple[int, int, int, int, int]:
    pathname = physical(logical)
    no_symlink_chain(pathname, label)
    info = os.stat(pathname, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        stop(f"{label} is not one regular single-link file.")
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, stat.S_IMODE(info.st_mode))


def stable_checkpoint_evidence_snapshots() -> Tuple[Dict[str, bytes], Dict[str, Tuple[int, int, int, int, int]]]:
    snapshots: Dict[str, bytes] = {}
    identities: Dict[str, Tuple[int, int, int, int, int]] = {}
    for key, logical in CHECKPOINT_EVIDENCE_PATHS.items():
        identity = fixed_file_identity(logical, f"checkpoint {key} evidence")
        if identity[-1] & 0o022:
            stop(f"checkpoint {key} evidence is writable by group/other.")
        data = secure_file(logical, f"checkpoint {key} evidence", MAX_JSON)
        if fixed_file_identity(logical, f"checkpoint {key} evidence") != identity:
            stop(f"checkpoint {key} evidence changed around its stable snapshot.")
        snapshots[key] = data
        identities[key] = identity
    return snapshots, identities


def revalidate_checkpoint_evidence_snapshots(
    snapshots: Dict[str, bytes], identities: Dict[str, Tuple[int, int, int, int, int]]
) -> None:
    for key, logical in CHECKPOINT_EVIDENCE_PATHS.items():
        if fixed_file_identity(logical, f"checkpoint {key} evidence") != identities[key]:
            stop(f"checkpoint {key} evidence identity changed before checkpoint replacement.")
        if secure_file(logical, f"checkpoint {key} evidence", MAX_JSON) != snapshots[key]:
            stop(f"checkpoint {key} evidence bytes changed before checkpoint replacement.")


def recovery_export_identity(metadata: os.stat_result) -> Dict[str, int]:
    return {
        "ctimeNs": metadata.st_ctime_ns,
        "device": metadata.st_dev,
        "gid": metadata.st_gid,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "mtimeNs": metadata.st_mtime_ns,
        "nlink": metadata.st_nlink,
        "size": metadata.st_size,
        "uid": metadata.st_uid,
    }


def stable_recovery_export_snapshot() -> Dict[str, object]:
    pathname = physical(SCHEDULER_RECOVERY_EXPORT)
    no_symlink_chain(pathname, "scheduler recovery image export")
    fd = os.open(pathname, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode) or before.st_uid != OWNER_UID or before.st_gid != OWNER_GID
            or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size < 1024 or before.st_size > MAX_RECOVERY_EXPORT
        ):
            stop("scheduler recovery image export identity/size/permissions are unsafe.")
        hasher = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_RECOVERY_EXPORT:
                stop("scheduler recovery image export exceeded its byte boundary.")
            hasher.update(chunk)
        after = os.fstat(fd)
        if recovery_export_identity(before) != recovery_export_identity(after) or total != before.st_size:
            stop("scheduler recovery image export changed while it was hashed.")
        return {
            "identity": recovery_export_identity(before),
            "sha256": hasher.hexdigest(),
            "sizeBytes": total,
        }
    finally:
        os.close(fd)


def load_validation_lane(candidate_commit: str) -> Optional[Dict[str, object]]:
    """Return the operator validation-lane marker when present and valid.

    Absence of the file means production mode.  A present marker must be one
    root-owned 0400 canonical document bound to the current candidate and
    unexpired; anything else fails closed.
    """
    pathname = physical(VALIDATION_LANE_FILE)
    if not os.path.lexists(pathname):
        return None
    metadata = os.lstat(pathname)
    if (
        not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != OWNER_UID or metadata.st_gid != OWNER_GID
        or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o400
    ):
        stop("validation lane marker identity/mode is unsafe.")
    lane = parse_json(secure_file(VALIDATION_LANE_FILE, "validation lane marker", 4096), "validation lane marker", True)
    if set(lane.keys()) != {"schema", "candidateCommit", "createdAtUnixSeconds", "expiresAtUnixSeconds", "reason"}:
        stop("validation lane marker is not one exact closed object.")
    if (
        lane.get("schema") != VALIDATION_LANE_SCHEMA
        or lane.get("candidateCommit") != candidate_commit
        or isinstance(lane.get("createdAtUnixSeconds"), bool) or not isinstance(lane.get("createdAtUnixSeconds"), int)
        or isinstance(lane.get("expiresAtUnixSeconds"), bool) or not isinstance(lane.get("expiresAtUnixSeconds"), int)
        or not isinstance(lane.get("reason"), str) or len(lane["reason"]) < 8
        or lane["expiresAtUnixSeconds"] - lane["createdAtUnixSeconds"] > VALIDATION_LANE_TTL_SECONDS
    ):
        stop("validation lane marker fields are invalid.")
    now = int(time.time())
    if lane["createdAtUnixSeconds"] > now + 60 or now >= lane["expiresAtUnixSeconds"]:
        stop("validation lane marker is expired or future-dated.")
    return lane


def write_validation_checkpoint(authority: Dict[str, object], binding: Dict[str, object]) -> Dict[str, object]:
    """Honest non-production checkpoint: reuse references, no PASS claims."""
    lane = load_validation_lane(authority["candidateCommit"])
    require_lane = lane is not None
    if not require_lane:
        stop("validation checkpoint requested without an active validation lane.")
    recovery = existing_recovery_binding()
    now = int(time.time())
    reused = {}
    newest_evidence_mtime = 0
    for name, path in CHECKPOINT_EVIDENCE_PATHS.items():
        pathname = physical(path)
        if os.path.lexists(pathname):
            reused[name] = digest(secure_file(path, f"reused evidence {name}", MAX_JSON))
            # Real provenance: the evidence file's own mtime is the moment that
            # material was captured/written; the newest one bounds reuse age.
            newest_evidence_mtime = max(newest_evidence_mtime, int(os.stat(pathname).st_mtime))
    # True capture provenance: the prior production checkpoint records the
    # moment the producer actually completed the reused backup cycle.
    reused_capture = newest_evidence_mtime
    prior_pathname = physical(LOCAL_CHECKPOINT)
    if os.path.lexists(prior_pathname):
        prior = parse_json(secure_file(LOCAL_CHECKPOINT, "prior production checkpoint", MAX_JSON), "prior production checkpoint", True)
        prior_capture = prior.get("backupCapturedUnixSeconds")
        if isinstance(prior_capture, int) and not isinstance(prior_capture, bool) and 1700000000 < prior_capture <= now + 60:
            reused_capture = prior_capture
    checkpoint = {
        "authoritative": False,
        "backupCapturedUnixSeconds": reused_capture,
        "candidateCommit": binding["candidateCommit"],
        "candidateTree": binding["candidateTree"],
        "destructiveMutationPlanned": False,
        "generatedAtUnixSeconds": now,
        "logicalBackupEvidenceSha256": reused.get("logicalBackupEvidenceSha256", "0" * 64),
        "offHostBackupEvidenceSha256": reused.get("offHostBackupEvidenceSha256", "0" * 64),
        "restoreEvidenceSha256": reused.get("restoreEvidenceSha256", "0" * 64),
        "restoreVerified": False,
        "runtimeInventorySha256": reused.get("runtimeInventorySha256", "0" * 64),
        "runtimeRecovered": False,
        "schedulerRecoveryImageExportSha256": recovery["exportSha256"],
        "schedulerRecoveryImageId": recovery["recoveryImageId"],
        "schedulerRunningImageId": recovery["runningImageId"],
        "schema": VALIDATION_CHECKPOINT_SCHEMA,
        "secretsBackupEvidenceSha256": reused.get("secretsBackupEvidenceSha256", "0" * 64),
        "sourceArchiveSha256": binding["sourceArchiveSha256"],
        "validation": True,
    }
    payload = (json.dumps(checkpoint, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    atomic_bytes(VALIDATION_CHECKPOINT_FILE, payload, 0o400)
    written = secure_file(VALIDATION_CHECKPOINT_FILE, "validation checkpoint readback", MAX_JSON)
    if written != payload:
        stop("validation checkpoint readback differs from the written bytes.")
    return checkpoint

def validate_pre_mutation_checkpoint(
    authority: Dict[str, object], authority_bytes: bytes, reconciliation: Dict[str, object]
) -> None:
    """Reopen the exact PRE guard immediately before any mutable apply work.

    Controller begin is not the mutation boundary: a retry can occur later or
    invoke the reconciler directly.  Therefore apply independently binds the
    immutable marker to one still-fresh checkpoint, all five exact evidence
    files, and the byte-identical scheduler recovery export.
    """
    checkpoint_identity = fixed_file_identity(LOCAL_CHECKPOINT, "pre-mutation LOCAL_PRIVATE checkpoint")
    if checkpoint_identity[-1] & 0o022:
        stop("pre-mutation LOCAL_PRIVATE checkpoint is writable by group/other.")
    checkpoint_bytes = secure_file(LOCAL_CHECKPOINT, "pre-mutation LOCAL_PRIVATE checkpoint", MAX_AUTHORITY)
    if fixed_file_identity(LOCAL_CHECKPOINT, "pre-mutation LOCAL_PRIVATE checkpoint") != checkpoint_identity:
        stop("pre-mutation LOCAL_PRIVATE checkpoint changed around its stable snapshot.")
    checkpoint = exact_keys(parse_json(checkpoint_bytes, "pre-mutation LOCAL_PRIVATE checkpoint", True), (
        "authoritative", "backupCapturedUnixSeconds", "candidateCommit", "candidateTree", "destructiveMutationPlanned",
        "generatedAtUnixSeconds", "logicalBackupEvidenceSha256", "offHostBackupEvidenceSha256", "restoreEvidenceSha256",
        "restoreVerified", "runtimeInventorySha256", "runtimeRecovered", "schedulerRecoveryImageExportSha256",
        "schedulerRecoveryImageId", "schedulerRunningImageId", "schema", "secretsBackupEvidenceSha256", "sourceArchiveSha256",
    ), "pre-mutation LOCAL_PRIVATE checkpoint")
    now = int(time.time())
    captured = checkpoint["backupCapturedUnixSeconds"]
    generated = checkpoint["generatedAtUnixSeconds"]
    if (
        digest(checkpoint_bytes) != reconciliation.get("rollbackCheckpointSha256")
        or checkpoint["schema"] != "platform.v1-local-private-predeploy-checkpoint/v1"
        or checkpoint["authoritative"] is not False
        or checkpoint["destructiveMutationPlanned"] is not False
        or checkpoint["restoreVerified"] is not True
        or checkpoint["runtimeRecovered"] is not True
        or checkpoint["candidateCommit"] != authority["candidateCommit"]
        or checkpoint["candidateTree"] != authority["candidateTree"]
        or checkpoint["sourceArchiveSha256"] != authority["sourceArchiveSha256"]
        or isinstance(captured, bool) or not isinstance(captured, int)
        or isinstance(generated, bool) or not isinstance(generated, int)
        or captured > generated or generated > now + 60
        or now - captured > 3600 or now - generated > 900
    ):
        stop("pre-mutation LOCAL_PRIVATE checkpoint is stale or differs from its reconciliation/authority binding.")
    for key in CHECKPOINT_EVIDENCE_PATHS:
        if not isinstance(checkpoint[key], str) or SHA256_RE.fullmatch(checkpoint[key]) is None:
            stop(f"pre-mutation LOCAL_PRIVATE checkpoint {key} is not a canonical digest.")

    snapshots, snapshot_identities = stable_checkpoint_evidence_snapshots()
    documents = {
        key: parse_json(data, f"pre-mutation {key} evidence", True)
        for key, data in snapshots.items()
    }
    for key, data in snapshots.items():
        if digest(data) != checkpoint[key]:
            stop(f"pre-mutation {key} evidence bytes differ from the reconciliation checkpoint.")

    common_keys = {
        "artifactSetSha256", "authorityDocumentId", "authoritySha256", "backupSetSha256", "backupToolImages",
        "candidateCommit", "candidateTree", "evidencePhase", "reconciliationSha256", "runId",
        "sourceArchiveSha256", "transactionId",
    }
    extra_keys = {
        "logicalBackupEvidenceSha256": {
            "artifactCount", "artifactManifestSha256", "artifacts", "backupCompletedUnixSeconds",
            "capturedAtUnixSeconds", "checksumVerifiedCount", "freshArtifactStreamHashCount",
            "generatedAtUnixSeconds", "hmacVerifiedCount", "schema", "sourceSummarySha256", "status",
            "totalArtifactBytes",
        },
        "offHostBackupEvidenceSha256": {
            "artifactCount", "completedAtUnixSeconds", "distinctSnapshotCount", "exactPayloadReadbackCount",
            "freshExactSnapshotCount", "generatedAtUnixSeconds", "hostingerUsed", "noPrune",
            "offsiteProofSha256", "proofs", "recoveryEscrow", "repository", "repositoryProvider",
            "retentionSkipped", "schema", "sourceSummarySha256", "status",
        },
        "restoreEvidenceSha256": {
            "artifactCount", "completedAtUnixSeconds", "expectedRestoreCount", "generatedAtUnixSeconds",
            "localRestoreResultsSha256", "passedRestoreCount", "results", "schema", "sourceSummarySha256", "status",
        },
        "secretsBackupEvidenceSha256": {
            "backupCompletedUnixSeconds", "capturedAtUnixSeconds", "encryptedArtifact", "generatedAtUnixSeconds",
            "plaintextTemporaryStateAbsent", "recoveryEscrow", "schema", "secretBindingInventory", "secretRestore",
            "secretValuesRecorded", "sourceSummarySha256", "status",
        },
        "runtimeInventorySha256": {
            "capturedAtUnixSeconds", "containerCount", "containerIdentitySetSha256", "generatedAtUnixSeconds",
            "recovery", "schema", "status", "volumeCount", "volumeSetSha256",
        },
    }
    schemas = {
        "logicalBackupEvidenceSha256": "platform.v1-local-private-logical-backup-evidence/v1",
        "offHostBackupEvidenceSha256": "platform.v1-local-private-offhost-backup-evidence/v1",
        "restoreEvidenceSha256": "platform.v1-local-private-restore-evidence/v1",
        "runtimeInventorySha256": "platform.v1-local-private-runtime-inventory-evidence/v1",
        "secretsBackupEvidenceSha256": "platform.v1-local-private-secrets-backup-evidence/v1",
    }
    logical = documents["logicalBackupEvidenceSha256"]
    reference = {key: logical.get(key) for key in common_keys}
    evidence_generated = logical.get("generatedAtUnixSeconds")
    expected_common = {
        "authorityDocumentId": authority["documentId"],
        "authoritySha256": digest(authority_bytes),
        "backupToolImages": authority["backupToolImages"],
        "candidateCommit": authority["candidateCommit"],
        "candidateTree": authority["candidateTree"],
        "evidencePhase": "PRE",
        "reconciliationSha256": None,
        "sourceArchiveSha256": authority["sourceArchiveSha256"],
        "transactionId": None,
    }
    if any(reference.get(key) != value for key, value in expected_common.items()):
        stop("pre-mutation evidence authority/candidate/PRE binding is invalid.")
    if not isinstance(reference.get("runId"), str) or RUN_ID_RE.fullmatch(reference["runId"]) is None:
        stop("pre-mutation evidence run identity is invalid.")
    if (
        isinstance(evidence_generated, bool) or not isinstance(evidence_generated, int)
        or evidence_generated < captured or evidence_generated > generated
        or evidence_generated > now + 60 or now - evidence_generated > 900
    ):
        stop("pre-mutation evidence generation boundary is stale or outside its checkpoint interval.")
    for key in ("artifactSetSha256", "authoritySha256", "backupSetSha256", "sourceArchiveSha256"):
        require_evidence_sha(reference.get(key), f"pre-mutation evidence {key}")
    for key, document in documents.items():
        exact_keys(document, common_keys | extra_keys[key], f"pre-mutation {key} evidence")
        if (
            document["schema"] != schemas[key] or document["status"] != "PASS"
            or {name: document[name] for name in common_keys} != reference
            or document["generatedAtUnixSeconds"] != evidence_generated
        ):
            stop("pre-mutation evidence bundle schema/status/run binding differs.")

    for document_key, rows_key, label in (
        ("logicalBackupEvidenceSha256", "artifacts", "logical artifacts"),
        ("offHostBackupEvidenceSha256", "proofs", "off-host proofs"),
        ("restoreEvidenceSha256", "results", "restore results"),
    ):
        rows = documents[document_key][rows_key]
        if not isinstance(rows, list) or len(rows) != len(EVIDENCE_LOGICAL_KEYS):
            stop(f"pre-mutation evidence does not contain the fourteen ordered {label}.")
        logical_keys = [row.get("logicalKey") if isinstance(row, dict) else None for row in rows]
        if logical_keys != list(EVIDENCE_LOGICAL_KEYS):
            stop(f"pre-mutation evidence {label} do not have the exact ordered logical keys.")

    if (
        logical["capturedAtUnixSeconds"] != captured or logical["backupCompletedUnixSeconds"] != captured
        or documents["secretsBackupEvidenceSha256"]["capturedAtUnixSeconds"] != captured
        or documents["secretsBackupEvidenceSha256"]["backupCompletedUnixSeconds"] != captured
    ):
        stop("pre-mutation evidence backup capture boundary differs from the checkpoint.")
    for key in ("offHostBackupEvidenceSha256", "restoreEvidenceSha256"):
        completed = documents[key]["completedAtUnixSeconds"]
        if isinstance(completed, bool) or not isinstance(completed, int) or completed < captured or completed > evidence_generated:
            stop("pre-mutation evidence completion boundary is invalid.")
    validate_backup_evidence_bundle(
        authority,
        {
            key: documents[key]
            for key in (
                "logicalBackupEvidenceSha256", "offHostBackupEvidenceSha256",
                "restoreEvidenceSha256", "secretsBackupEvidenceSha256",
            )
        },
        None,
        None,
        captured,
        generated,
        "PRE",
    )
    runtime = documents["runtimeInventorySha256"]
    expected_recovery = {
        "exportSha256": checkpoint["schedulerRecoveryImageExportSha256"],
        "recoveryImageId": checkpoint["schedulerRecoveryImageId"],
        "runningImageId": checkpoint["schedulerRunningImageId"],
    }
    if (
        runtime["capturedAtUnixSeconds"] != evidence_generated
        or exact_keys(runtime["recovery"], ("exportSha256", "recoveryImageId", "runningImageId"), "pre-mutation runtime recovery") != expected_recovery
    ):
        stop("pre-mutation runtime evidence does not bind the checkpoint recovery export.")

    recovery = exact_keys(reconciliation.get("rollbackSchedulerRecovery"), (
        "archiveFormat", "configDigest", "configHash", "containerId", "exportIdentity", "exportLabels", "exportPath",
        "exportSha256", "exportSizeBytes", "imageIndexDigest", "imageIndexPath", "imageManifestDigest", "manifestConfig",
        "recoveryImageId", "recoveryTag", "runningImageId",
    ), "reconciliation rollback scheduler recovery")
    if digest(canonical(recovery).encode()) != reconciliation.get("rollbackSchedulerRecoverySha256"):
        stop("reconciliation rollback scheduler recovery digest differs.")
    recovery_labels = exact_keys(recovery["exportLabels"], (
        "com.platform.v1.local-private.candidate-commit",
        "com.platform.v1.local-private.scheduler-config-hash",
        "com.platform.v1.local-private.scheduler-container-id",
        "com.platform.v1.local-private.scheduler-running-image-id",
    ), "reconciliation rollback scheduler labels")
    for key in ("configHash", "containerId", "exportSha256"):
        require_evidence_sha(recovery[key], f"reconciliation rollback scheduler {key}")
    for key in ("configDigest", "imageIndexDigest", "imageManifestDigest", "recoveryImageId", "runningImageId"):
        if not isinstance(recovery[key], str) or IMAGE_ID_RE.fullmatch(recovery[key]) is None:
            stop("reconciliation rollback scheduler image/digest identity is invalid.")
    export_snapshot = stable_recovery_export_snapshot()
    recovery_hex = recovery["recoveryImageId"].removeprefix("sha256:")
    config_hex = recovery["configDigest"].removeprefix("sha256:")
    if (
        recovery["archiveFormat"] != "OCI_DOCKER_SAVE_V1"
        or recovery["exportPath"] != SCHEDULER_RECOVERY_EXPORT
        or recovery["exportSha256"] != checkpoint["schedulerRecoveryImageExportSha256"]
        or recovery["recoveryImageId"] != checkpoint["schedulerRecoveryImageId"]
        or recovery["runningImageId"] != checkpoint["schedulerRunningImageId"]
        or recovery["recoveryImageId"] == recovery["runningImageId"]
        or recovery["imageIndexDigest"] != recovery["recoveryImageId"]
        or recovery["imageIndexPath"] != f"blobs/sha256/{recovery_hex}"
        or recovery["manifestConfig"] != f"blobs/sha256/{config_hex}"
        or recovery["recoveryTag"] != f"platform/v1-scheduler-recovery:{authority['candidateCommit']}"
        or recovery_labels != {
            "com.platform.v1.local-private.candidate-commit": authority["candidateCommit"],
            "com.platform.v1.local-private.scheduler-config-hash": recovery["configHash"],
            "com.platform.v1.local-private.scheduler-container-id": recovery["containerId"],
            "com.platform.v1.local-private.scheduler-running-image-id": recovery["runningImageId"],
        }
        or export_snapshot != {
            "identity": recovery["exportIdentity"],
            "sha256": recovery["exportSha256"],
            "sizeBytes": recovery["exportSizeBytes"],
        }
    ):
        stop("reconciliation rollback scheduler recovery export changed or is not checkpoint-bound.")

    revalidate_checkpoint_evidence_snapshots(snapshots, snapshot_identities)
    if recovery_export_identity(os.lstat(physical(SCHEDULER_RECOVERY_EXPORT))) != export_snapshot["identity"]:
        stop("scheduler recovery image export identity changed after validation.")
    if (
        fixed_file_identity(LOCAL_CHECKPOINT, "pre-mutation LOCAL_PRIVATE checkpoint") != checkpoint_identity
        or secure_file(LOCAL_CHECKPOINT, "pre-mutation LOCAL_PRIVATE checkpoint", MAX_AUTHORITY) != checkpoint_bytes
    ):
        stop("pre-mutation LOCAL_PRIVATE checkpoint changed before apply mutation.")


def require_evidence_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        stop(f"{label} is not one canonical SHA-256 digest.")
    return value


def require_evidence_timestamp(value: object, label: str, began_at: int, now: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < began_at or value > now:
        stop(f"{label} is outside the bounded evidence interval.")
    return value


def require_evidence_count(value: object, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        stop(f"{label} is not one bounded nonnegative integer.")
    return value


def validate_evidence_restore_receipt(receipt: object, operation: str, artifact_sha256: str) -> Dict[str, object]:
    value = exact_keys(receipt, (
        "artifactSha256", "counts", "matched", "operation", "schema", "scope", "semanticComparator",
    ), f"{operation} comparator receipt")
    expected_scope = {
        "restore-test-postgres": "same-artifact-independent-double-restore",
        "restore-test-mariadb": "same-artifact-independent-double-restore",
        "restore-test-minio": "stable-live-source-before-after-to-isolated-restored-durable-tree",
        "restore-test-keycloak": "same-artifact-independent-double-extract-and-parse",
    }.get(operation)
    if (
        expected_scope is None or value["schema"] != "platform.v1.restore-evidence-receipt/v1"
        or value["operation"] != operation or value["artifactSha256"] != artifact_sha256
        or value["matched"] is not True or value["scope"] != expected_scope
    ):
        stop(f"{operation} comparator receipt is not artifact/operation/PASS bound.")
    count_names = {
        "restore-test-postgres": ("restoredTables",),
        "restore-test-mariadb": ("restoredSchemas", "restoredTables"),
        "restore-test-minio": ("bootHealthy", "restoredDurableEntries", "sourceDurableEntries"),
        "restore-test-keycloak": ("jsonCount", "realmCount"),
    }[operation]
    counts = exact_keys(value["counts"], count_names, f"{operation} comparator counts")
    for name, raw in counts.items():
        if name == "bootHealthy":
            if raw is not True:
                stop("MinIO restore comparator did not pass boot health.")
        else:
            require_evidence_count(raw, f"{operation} {name}", 1)
    semantic = value["semanticComparator"]
    if operation in ("restore-test-postgres", "restore-test-mariadb"):
        semantic = exact_keys(semantic, (
            "algorithm", "components", "engine", "firstRestore", "firstRestoreSha256", "matched", "scope",
            "secondRestore", "secondRestoreSha256", "version",
        ), f"{operation} semantic comparator")
        engine = "postgres" if operation.endswith("postgres") else "mariadb"
        fingerprint_names = (
            ("combinedSha256", "largeObjectBytes", "largeObjectRows", "largeObjectsSha256", "relationCount", "rowCount",
             "rowDataSha256", "schemaBytes", "schemaLines", "sequenceCount", "sequencesSha256", "structureSha256")
            if engine == "postgres" else
            ("combinedSha256", "relationCount", "rowCount", "rowDataSha256", "schemaBytes", "schemaCount", "schemaLines",
             "schemaSetSha256", "structureSha256")
        )
        first = exact_keys(semantic["firstRestore"], fingerprint_names, f"{operation} first fingerprint")
        second = exact_keys(semantic["secondRestore"], fingerprint_names, f"{operation} second fingerprint")
        if (
            semantic["version"] != "platform.database-restore-semantic-comparator/v1"
            or semantic["engine"] != engine or semantic["algorithm"] != "sha256"
            or semantic["scope"] != expected_scope or semantic["matched"] is not True or first != second
        ):
            stop(f"{operation} independent restore comparator is inconsistent.")
        for name, raw in first.items():
            require_evidence_sha(raw, f"{operation} {name}") if name.endswith("Sha256") else require_evidence_count(raw, f"{operation} {name}")
        require_evidence_sha(semantic["firstRestoreSha256"], f"{operation} first restore digest")
        require_evidence_sha(semantic["secondRestoreSha256"], f"{operation} second restore digest")
        if semantic["firstRestoreSha256"] != semantic["secondRestoreSha256"] or semantic["firstRestoreSha256"] != first["combinedSha256"]:
            stop(f"{operation} independent restore fingerprints differ.")
        component_names = (
            ("largeObjectsSha256", "rowDataSha256", "sequencesSha256", "structureSha256")
            if engine == "postgres" else ("rowDataSha256", "schemaSetSha256", "structureSha256")
        )
        components = exact_keys(semantic["components"], component_names, f"{operation} components")
        for name, raw in components.items():
            component = exact_keys(raw, ("firstRestore", "matched", "secondRestore"), f"{operation} {name} component")
            if component != {"firstRestore": first[name], "matched": True, "secondRestore": second[name]}:
                stop(f"{operation} component comparison is inconsistent.")
    elif operation == "restore-test-minio":
        semantic = exact_keys(semantic, (
            "algorithm", "components", "engine", "matched", "restored", "restoredMatchesSource", "restoredSha256",
            "scope", "sourceAfter", "sourceAfterSha256", "sourceBefore", "sourceBeforeSha256", "sourceStable",
            "version", "volatileExclusions",
        ), "MinIO semantic comparator")
        exclusions = [
            ".minio.sys/tmp/*", ".minio.sys/buckets/.bloomcycle.bin/xl.meta", ".minio.sys/buckets/.usage.json/xl.meta",
        ]
        tree_names = ("combinedSha256", "directoryCount", "entryCount", "excludedPaths", "fileCount", "totalFileBytes", "treeSha256")
        before = exact_keys(semantic["sourceBefore"], tree_names, "MinIO source-before fingerprint")
        after = exact_keys(semantic["sourceAfter"], tree_names, "MinIO source-after fingerprint")
        restored = exact_keys(semantic["restored"], tree_names, "MinIO restored fingerprint")
        if (
            semantic["version"] != "platform.minio-restore-tree-comparator/v1" or semantic["engine"] != "minio"
            or semantic["algorithm"] != "sha256" or semantic["scope"] != expected_scope or semantic["matched"] is not True
            or semantic["sourceStable"] is not True or semantic["restoredMatchesSource"] is not True
            or semantic["volatileExclusions"] != exclusions or before != after or before != restored
        ):
            stop("MinIO stable source/restored comparator is inconsistent.")
        for name, raw in before.items():
            if name.endswith("Sha256"):
                require_evidence_sha(raw, f"MinIO {name}")
            elif name == "excludedPaths":
                if raw != exclusions:
                    stop("MinIO fingerprint exclusions differ.")
            else:
                require_evidence_count(raw, f"MinIO {name}")
        if before["entryCount"] < 1 or before["entryCount"] != before["fileCount"] + before["directoryCount"]:
            stop("MinIO durable tree counts are invalid.")
        for name in ("sourceBeforeSha256", "sourceAfterSha256", "restoredSha256"):
            require_evidence_sha(semantic[name], f"MinIO {name}")
        if not (
            semantic["sourceBeforeSha256"] == semantic["sourceAfterSha256"] == semantic["restoredSha256"] == before["combinedSha256"]
            and counts["sourceDurableEntries"] == counts["restoredDurableEntries"] == before["entryCount"]
        ):
            stop("MinIO comparator digest/count binding is inconsistent.")
        components = exact_keys(semantic["components"], ("treeSha256",), "MinIO components")
        tree = exact_keys(components["treeSha256"], (
            "restored", "restoredMatchesSource", "sourceAfter", "sourceBefore", "sourceStable",
        ), "MinIO tree component")
        if tree != {
            "restored": before["treeSha256"], "restoredMatchesSource": True, "sourceAfter": before["treeSha256"],
            "sourceBefore": before["treeSha256"], "sourceStable": True,
        }:
            stop("MinIO tree component comparison is inconsistent.")
    else:
        semantic = exact_keys(semantic, (
            "algorithm", "components", "engine", "firstRestore", "firstRestoreSha256", "matched", "scope",
            "secondRestore", "secondRestoreSha256", "version",
        ), "Keycloak semantic comparator")
        names = (
            "archiveTreeSha256", "canonicalContentSha256", "combinedSha256", "fileCount", "jsonCount", "rawJsonSetSha256",
            "realmCount", "totalJsonBytes",
        )
        first = exact_keys(semantic["firstRestore"], names, "Keycloak first fingerprint")
        second = exact_keys(semantic["secondRestore"], names, "Keycloak second fingerprint")
        if (
            semantic["version"] != "platform.keycloak-config-restore-semantic-comparator/v1"
            or semantic["engine"] != "keycloak" or semantic["algorithm"] != "sha256"
            or semantic["scope"] != expected_scope or semantic["matched"] is not True or first != second
        ):
            stop("Keycloak independent restore comparator is inconsistent.")
        for name, raw in first.items():
            require_evidence_sha(raw, f"Keycloak {name}") if name.endswith("Sha256") else require_evidence_count(raw, f"Keycloak {name}", 1)
        for name in ("firstRestoreSha256", "secondRestoreSha256"):
            require_evidence_sha(semantic[name], f"Keycloak {name}")
        if semantic["firstRestoreSha256"] != semantic["secondRestoreSha256"] or semantic["firstRestoreSha256"] != first["combinedSha256"]:
            stop("Keycloak restore fingerprints differ.")
        component_names = ("archiveTreeSha256", "canonicalContentSha256", "rawJsonSetSha256")
        components = exact_keys(semantic["components"], component_names, "Keycloak components")
        for name, raw in components.items():
            component = exact_keys(raw, ("firstRestore", "matched", "secondRestore"), f"Keycloak {name} component")
            if component != {"firstRestore": first[name], "matched": True, "secondRestore": second[name]}:
                stop("Keycloak component comparison is inconsistent.")
        if counts["realmCount"] != first["realmCount"] or counts["jsonCount"] != first["jsonCount"]:
            stop("Keycloak comparator counts differ from its fingerprint.")
    return value


def validate_backup_evidence_bundle(
    authority: Dict[str, object],
    documents: Dict[str, Dict[str, object]],
    reconciliation_sha256: Optional[str],
    transaction_id: Optional[str],
    began_at: int,
    now: int,
    evidence_phase: str,
) -> None:
    """Validate the four exact-release PRE or POST backup documents.

    This deliberately reconstructs every cross-document digest and identity
    needed by the controller seal.  Canonical JSON alone is not backup proof:
    a substituted candidate, a false remote readback or a non-isolated restore
    must not cross the PRE mutation boundary or the POST commit boundary.
    """
    if evidence_phase not in ("PRE", "POST"):
        stop("backup evidence phase is outside the closed V1 set.")
    evidence_label = "pre-mutation" if evidence_phase == "PRE" else "post-maintenance"
    if set(documents) != {
        "logicalBackupEvidenceSha256", "offHostBackupEvidenceSha256",
        "restoreEvidenceSha256", "secretsBackupEvidenceSha256",
    }:
        stop(f"{evidence_label} backup evidence bundle cardinality differs from the closed V1 set.")
    logical = documents["logicalBackupEvidenceSha256"]
    offhost = documents["offHostBackupEvidenceSha256"]
    restore = documents["restoreEvidenceSha256"]
    secret = documents["secretsBackupEvidenceSha256"]
    ordered_documents = (logical, offhost, restore, secret)
    common_keys = {
        "artifactSetSha256", "authorityDocumentId", "authoritySha256", "backupSetSha256", "backupToolImages",
        "candidateCommit", "candidateTree", "evidencePhase", "reconciliationSha256", "runId",
        "sourceArchiveSha256", "transactionId",
    }
    extra_keys = (
        {
            "artifactCount", "artifactManifestSha256", "artifacts", "backupCompletedUnixSeconds",
            "capturedAtUnixSeconds", "checksumVerifiedCount", "freshArtifactStreamHashCount",
            "generatedAtUnixSeconds", "hmacVerifiedCount", "schema", "sourceSummarySha256", "status",
            "totalArtifactBytes",
        },
        {
            "artifactCount", "completedAtUnixSeconds", "distinctSnapshotCount", "exactPayloadReadbackCount",
            "freshExactSnapshotCount", "generatedAtUnixSeconds", "hostingerUsed", "noPrune",
            "offsiteProofSha256", "proofs", "recoveryEscrow", "repository", "repositoryProvider",
            "retentionSkipped", "schema", "sourceSummarySha256", "status",
        },
        {
            "artifactCount", "completedAtUnixSeconds", "expectedRestoreCount", "generatedAtUnixSeconds",
            "localRestoreResultsSha256", "passedRestoreCount", "results", "schema", "sourceSummarySha256", "status",
        },
        {
            "backupCompletedUnixSeconds", "capturedAtUnixSeconds", "encryptedArtifact", "generatedAtUnixSeconds",
            "plaintextTemporaryStateAbsent", "recoveryEscrow", "schema", "secretBindingInventory",
            "secretRestore", "secretValuesRecorded", "sourceSummarySha256", "status",
        },
    )
    schemas = (
        "platform.v1-local-private-logical-backup-evidence/v1",
        "platform.v1-local-private-offhost-backup-evidence/v1",
        "platform.v1-local-private-restore-evidence/v1",
        "platform.v1-local-private-secrets-backup-evidence/v1",
    )
    reference = {key: logical.get(key) for key in common_keys}
    generated_values = set()
    for index, (document, extra, schema) in enumerate(zip(ordered_documents, extra_keys, schemas)):
        exact_keys(document, common_keys | extra, f"closed {evidence_label} backup evidence {index}")
        if (
            document["schema"] != schema or document["status"] != "PASS"
            or {key: document[key] for key in common_keys} != reference
        ):
            stop(f"{evidence_label} backup evidence common binding/schema/status is inconsistent.")
        generated_values.add(require_evidence_timestamp(
            document["generatedAtUnixSeconds"], f"{evidence_label} backup evidence {index} generation", began_at, now
        ))
        for timestamp_name in ("capturedAtUnixSeconds", "completedAtUnixSeconds", "backupCompletedUnixSeconds"):
            if timestamp_name in document:
                require_evidence_timestamp(
                    document[timestamp_name], f"{evidence_label} backup evidence {index} {timestamp_name}", began_at, now
                )
    if len(generated_values) != 1:
        stop(f"{evidence_label} backup evidence documents were not generated as one bundle.")
    generated = next(iter(generated_values))
    if any(
        document.get(timestamp_name, began_at) > generated
        for document in ordered_documents
        for timestamp_name in ("capturedAtUnixSeconds", "completedAtUnixSeconds", "backupCompletedUnixSeconds")
    ):
        stop(f"{evidence_label} backup evidence completion occurs after bundle generation.")

    authority_bytes = canonical_bytes(authority)
    backup_tool_images = authority.get("backupToolImages")
    exact_keys(
        backup_tool_images,
        ("mariadbRestore", "minioRestore", "nodeUtility", "postgresRestore", "resticRclone"),
        "backup helper image authority",
    )
    for name, raw in backup_tool_images.items():
        image = exact_keys(raw, ("imageId", "imageReference"), f"{name} backup helper image authority")
        if (
            not isinstance(image["imageId"], str) or IMAGE_ID_RE.fullmatch(image["imageId"]) is None
            or not isinstance(image["imageReference"], str) or DIGEST_REFERENCE_RE.fullmatch(image["imageReference"]) is None
        ):
            stop("backup helper image authority contains a mutable or invalid identity.")
    expected_common = {
        "authorityDocumentId": authority.get("documentId"),
        "authoritySha256": digest(authority_bytes),
        "backupToolImages": backup_tool_images,
        "candidateCommit": authority.get("candidateCommit"),
        "candidateTree": authority.get("candidateTree"),
        "evidencePhase": evidence_phase,
        "reconciliationSha256": reconciliation_sha256,
        "sourceArchiveSha256": authority.get("sourceArchiveSha256"),
        "transactionId": transaction_id,
    }
    if any(reference[key] != value for key, value in expected_common.items()):
        stop(f"{evidence_label} backup evidence candidate/authority/reconciliation binding is invalid.")
    if (
        not isinstance(authority.get("documentId"), str) or SHA256_RE.fullmatch(authority["documentId"]) is None
        or not isinstance(reference["runId"], str) or RUN_ID_RE.fullmatch(reference["runId"]) is None
    ):
        stop(f"{evidence_label} backup evidence has a non-canonical run/authority identity.")
    if evidence_phase == "POST":
        if (
            not isinstance(reconciliation_sha256, str) or SHA256_RE.fullmatch(reconciliation_sha256) is None
            or not isinstance(transaction_id, str) or SHA256_RE.fullmatch(transaction_id) is None
        ):
            stop("post-maintenance backup evidence has a non-canonical reconciliation/transaction identity.")
    elif reconciliation_sha256 is not None or transaction_id is not None:
        stop("pre-mutation backup evidence unexpectedly claims a reconciliation transaction.")
    digest_keys = ["artifactSetSha256", "authoritySha256", "backupSetSha256", "sourceArchiveSha256"]
    if evidence_phase == "POST":
        digest_keys.append("reconciliationSha256")
    for key in digest_keys:
        require_evidence_sha(reference[key], f"{evidence_label} common {key}")

    artifact_keys = {
        "artifact", "artifactIndex", "checksumSidecarPath", "checksumVerified", "freshLocalRestoreVerified",
        "hmacKeyId", "hmacSidecarPath", "hmacVerified", "hostPath", "logicalKey", "sha256", "sizeBytes", "status",
    }
    artifacts = logical["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != len(EVIDENCE_LOGICAL_KEYS):
        stop("logical evidence does not contain the fourteen ordered V1 artifacts.")
    identities: List[Dict[str, object]] = []
    for index, (raw, expected_key) in enumerate(zip(artifacts, EVIDENCE_LOGICAL_KEYS), start=1):
        row = exact_keys(raw, artifact_keys, f"logical artifact {index}")
        artifact = row["artifact"]
        if (
            row["artifactIndex"] != index or row["logicalKey"] != expected_key or row["status"] != "PASS"
            or row["checksumVerified"] is not True or row["hmacVerified"] is not True
            or row["freshLocalRestoreVerified"] is not True
            or isinstance(row["sizeBytes"], bool) or not isinstance(row["sizeBytes"], int) or row["sizeBytes"] < 1
            or not isinstance(artifact, str) or not artifact or os.path.basename(artifact) != artifact
            or any(not isinstance(row[key], str) or not row[key].startswith("/") for key in (
                "checksumSidecarPath", "hmacSidecarPath", "hostPath"
            ))
            or not isinstance(row["hmacKeyId"], str) or not row["hmacKeyId"]
        ):
            stop("logical artifact row is not exact/PASS/ordered.")
        require_evidence_sha(row["sha256"], "logical artifact SHA-256")
        identities.append({key: row[key] for key in ("artifactIndex", "logicalKey", "sha256", "sizeBytes")})
    if digest(canonical_bytes(identities)) != reference["artifactSetSha256"]:
        stop("logical artifact-set digest is invalid.")
    recomputed_backup = {key: reference[key] for key in common_keys if key != "backupSetSha256"}
    if digest(canonical_bytes({**recomputed_backup, "artifacts": identities})) != reference["backupSetSha256"]:
        stop("backup-set cross-binding digest is invalid.")
    if (
        logical["artifactCount"] != 14 or logical["checksumVerifiedCount"] != 14
        or logical["hmacVerifiedCount"] != 14 or logical["freshArtifactStreamHashCount"] != 14
        or logical["totalArtifactBytes"] != sum(row["sizeBytes"] for row in artifacts)
        or digest(b"".join(canonical_bytes(item) for item in artifacts)) != logical["artifactManifestSha256"]
    ):
        stop("logical evidence aggregate/hash is invalid.")
    require_evidence_sha(logical["artifactManifestSha256"], "logical artifact manifest")
    if (
        logical["capturedAtUnixSeconds"] != logical["backupCompletedUnixSeconds"]
        or secret["capturedAtUnixSeconds"] != secret["backupCompletedUnixSeconds"]
        or secret["backupCompletedUnixSeconds"] != logical["backupCompletedUnixSeconds"]
    ):
        stop("logical/secrets backup capture boundary differs within one evidence run.")

    proof_keys = {
        "artifact", "artifactIndex", "logicalKey", "offHostLocation", "remoteChecksumSidecarByteExact",
        "remoteHmacSidecarByteExact", "remotePayloadByteExact", "sha256", "sizeBytes", "snapshotId",
        "snapshotPaths", "snapshotTag", "status",
    }
    proofs = offhost["proofs"]
    if not isinstance(proofs, list) or len(proofs) != 14:
        stop("off-host evidence does not contain fourteen ordered proof rows.")
    repository = "rclone:platform-onedrive:platform-infrastructure/restic"
    snapshot_ids = set()
    for identity, artifact_row, raw in zip(identities, artifacts, proofs):
        row = exact_keys(raw, proof_keys, "off-host proof")
        expected_paths = [
            f"/backup/{artifact_row['artifact']}", f"/backup/{artifact_row['artifact']}.sha256",
            f"/backup/{artifact_row['artifact']}.sig.json",
        ]
        if (
            any(row[key] != identity[key] for key in identity) or row["artifact"] != artifact_row["artifact"]
            or row["status"] != "PASS" or row["remotePayloadByteExact"] is not True
            or row["remoteChecksumSidecarByteExact"] is not True or row["remoteHmacSidecarByteExact"] is not True
            or not isinstance(row["snapshotId"], str) or SHA256_RE.fullmatch(row["snapshotId"]) is None
            or row["offHostLocation"] != f"{repository}#snapshot={row['snapshotId']}"
            or row["snapshotPaths"] != expected_paths
            or row["snapshotTag"] != f"local-private-v1-{reference['runId']}"
        ):
            stop("off-host location/readback/snapshot proof is invalid or substituted.")
        snapshot_ids.add(row["snapshotId"])
    if (
        len(snapshot_ids) != 14 or offhost["artifactCount"] != 14 or offhost["distinctSnapshotCount"] != 14
        or offhost["freshExactSnapshotCount"] != 14 or offhost["exactPayloadReadbackCount"] != 14
        or offhost["repository"] != repository or offhost["repositoryProvider"] != "OneDrive"
        or offhost["hostingerUsed"] is not False or offhost["noPrune"] is not True
        or offhost["retentionSkipped"] is not True
        or digest(b"".join(canonical_bytes(item) for item in proofs)) != offhost["offsiteProofSha256"]
    ):
        stop("off-host evidence aggregate/provider/hash is invalid.")
    require_evidence_sha(offhost["offsiteProofSha256"], "off-host proof set")

    restore_keys = {
        "artifact", "artifactIndex", "isolatedRestore", "logicalKey", "restoreMode", "sha256", "sizeBytes",
        "status", "verification", "verificationSha256",
    }
    results = restore["results"]
    if not isinstance(results, list) or len(results) != 14:
        stop("restore evidence does not contain fourteen ordered result rows.")
    for identity, artifact_row, raw in zip(identities, artifacts, results):
        row = exact_keys(raw, restore_keys, "isolated restore result")
        if (
            any(row[key] != identity[key] for key in identity) or row["artifact"] != artifact_row["artifact"]
            or row["isolatedRestore"] is not True or row["status"] != "PASS"
            or row["restoreMode"] != RESTORE_MODE_BY_LOGICAL_KEY[row["logicalKey"]]
        ):
            stop("isolated restore result is false, substituted or uses the wrong mode.")
        require_evidence_sha(row["verificationSha256"], "isolated restore verification")
        if digest(canonical_bytes(row["verification"])) != row["verificationSha256"]:
            stop("isolated restore verification object differs from its digest.")
        if row["logicalKey"] in EVIDENCE_LOGICAL_KEYS[:8]:
            verification = exact_keys(
                row["verification"], ("entryCount", "restoredTreeSha256", "sourceTreeSha256"),
                "application restore verification",
            )
            require_evidence_count(verification["entryCount"], "application restore entry count", 1)
            require_evidence_sha(verification["restoredTreeSha256"], "application restored tree")
            require_evidence_sha(verification["sourceTreeSha256"], "application source tree")
            if verification["restoredTreeSha256"] != verification["sourceTreeSha256"]:
                stop("application restore trees differ.")
        elif row["logicalKey"] == "confidential":
            verification = exact_keys(
                row["verification"], ("entryCount", "restoredTreeSha256", "sourceTreeSha256", "treeSha256"),
                "confidential restore verification",
            )
            require_evidence_count(verification["entryCount"], "confidential restore entry count", 1)
            for key in ("restoredTreeSha256", "sourceTreeSha256", "treeSha256"):
                require_evidence_sha(verification[key], f"confidential restore {key}")
            if not (
                verification["restoredTreeSha256"] == verification["sourceTreeSha256"] == verification["treeSha256"]
            ):
                stop("confidential restore trees differ.")
        else:
            verification = exact_keys(row["verification"], ("comparatorReceipt",), "database/config restore verification")
            operation = {
                "pg-stexor": "restore-test-postgres", "pg-keycloak": "restore-test-postgres",
                "mariadb": "restore-test-mariadb", "minio": "restore-test-minio",
                "keycloak-config": "restore-test-keycloak",
            }[row["logicalKey"]]
            validate_evidence_restore_receipt(verification["comparatorReceipt"], operation, row["sha256"])
    if (
        restore["artifactCount"] != 14 or restore["expectedRestoreCount"] != 14
        or restore["passedRestoreCount"] != 14
        or digest(b"".join(canonical_bytes(item) for item in results)) != restore["localRestoreResultsSha256"]
    ):
        stop("restore aggregate/hash is invalid.")
    require_evidence_sha(restore["localRestoreResultsSha256"], "restore result set")

    escrow_keys = {
        "certificateSha256", "certificateSha256Fingerprint", "ciphertextBase64", "ciphertextSha256",
        "ciphertextSizeBytes", "offHostLocation", "remotePayloadByteExact", "status",
    }
    escrow = exact_keys(offhost["recoveryEscrow"], escrow_keys, "off-host recovery escrow")
    if secret["recoveryEscrow"] != escrow:
        stop("secrets/off-host recovery escrow cross-binding differs.")
    try:
        if not isinstance(escrow["ciphertextBase64"], str):
            raise TypeError("ciphertext is not text")
        ciphertext = base64.b64decode(escrow["ciphertextBase64"], validate=True)
    except (binascii.Error, ValueError, TypeError):
        stop("recovery escrow ciphertext is not strict base64.")
    certificate = exact_keys(
        authority.get("recoveryEscrowCertificate"), ("path", "sha256", "sha256Fingerprint"),
        "recovery escrow certificate authority",
    )
    expected_escrow_location = f"platform-onedrive:platform-infrastructure/key-escrow/v1-local-private-recovery-{reference['runId']}.cms"
    if (
        len(ciphertext) < 256 or len(ciphertext) > 64 * 1024
        or digest(ciphertext) != escrow["ciphertextSha256"] or len(ciphertext) != escrow["ciphertextSizeBytes"]
        or escrow["certificateSha256"] != certificate["sha256"]
        or escrow["certificateSha256Fingerprint"] != certificate["sha256Fingerprint"]
        or escrow["offHostLocation"] != expected_escrow_location
        or escrow["remotePayloadByteExact"] is not True or escrow["status"] != "PASS"
    ):
        stop("recovery escrow certificate/ciphertext/readback binding is invalid.")
    require_evidence_sha(escrow["ciphertextSha256"], "recovery escrow ciphertext")

    encrypted = exact_keys(secret["encryptedArtifact"], (
        "artifact", "artifactIndex", "checksumVerified", "hmacVerified", "logicalKey", "remotePayloadByteExact",
        "sha256", "sizeBytes", "snapshotId", "status",
    ), "encrypted secret artifact")
    confidential = identities[-1]
    confidential_proof = proofs[-1]
    if (
        any(encrypted[key] != confidential[key] for key in confidential)
        or encrypted["artifact"] != artifacts[-1]["artifact"]
        or encrypted["snapshotId"] != confidential_proof["snapshotId"] or encrypted["status"] != "PASS"
        or encrypted["checksumVerified"] is not True or encrypted["hmacVerified"] is not True
        or encrypted["remotePayloadByteExact"] is not True
    ):
        stop("encrypted secret artifact does not cross-bind logical/off-host evidence.")
    secret_restore = exact_keys(secret["secretRestore"], restore_keys | {"treeSha256"}, "confidential restore result")
    if any(secret_restore[key] != results[-1][key] for key in restore_keys) or secret_restore["isolatedRestore"] is not True:
        stop("confidential restore does not cross-bind isolated restore evidence.")
    require_evidence_sha(secret_restore["treeSha256"], "confidential restore tree")
    if secret_restore["treeSha256"] != secret_restore["verification"]["treeSha256"]:
        stop("confidential restore tree does not cross-bind its verification object.")
    inventory = exact_keys(secret["secretBindingInventory"], (
        "distinctHostFiles", "mountOccurrences", "problemCount", "setSha256", "unmountedReferenceCount",
    ), "secret binding inventory")
    for key in ("distinctHostFiles", "mountOccurrences", "problemCount", "unmountedReferenceCount"):
        if isinstance(inventory[key], bool) or not isinstance(inventory[key], int) or inventory[key] < 0:
            stop("secret binding inventory counts are invalid.")
    if (
        secret["plaintextTemporaryStateAbsent"] is not True or secret["secretValuesRecorded"] is not False
        or inventory["problemCount"] != 0 or inventory["unmountedReferenceCount"] != 0
        or inventory["distinctHostFiles"] > inventory["mountOccurrences"]
    ):
        stop("secrets evidence reports plaintext residue or unresolved runtime references.")
    require_evidence_sha(inventory["setSha256"], "secret binding inventory")
    summaries = {item["sourceSummarySha256"] for item in ordered_documents}
    if len(summaries) != 1:
        stop("backup evidence source-summary cross-binding differs.")
    require_evidence_sha(next(iter(summaries)), "backup evidence source summary")


def validate_post_backup_bundle(
    authority: Dict[str, object],
    documents: Dict[str, Dict[str, object]],
    reconciliation_sha256: str,
    transaction_id: str,
    began_at: int,
    now: int,
) -> None:
    validate_backup_evidence_bundle(
        authority, documents, reconciliation_sha256, transaction_id, began_at, now, "POST"
    )


def validate_post_checkpoint_evidence(
    authority: Dict[str, object], snapshots: Dict[str, bytes], began_at: int, now: int
) -> None:
    reconciliation_bytes = secure_file(RECONCILIATION, "post-evidence reconciliation marker", MAX_JSON, 0o600)
    reconciliation = parse_json(reconciliation_bytes, "post-evidence reconciliation marker", True)
    journal_bytes = secure_file(JOURNAL, "post-evidence reconciliation journal", MAX_JSON, 0o600)
    journal = parse_json(journal_bytes, "post-evidence reconciliation journal", True)
    authority_sha = digest(canonical_bytes(authority))
    if (
        reconciliation.get("schema") != RECONCILIATION_SCHEMA or reconciliation.get("status") != "RECONCILING"
        or reconciliation.get("beganAtUnixSeconds") != began_at
        or reconciliation.get("releaseAuthorityDocumentId") != authority.get("documentId")
        or reconciliation.get("releaseAuthoritySha256") != authority_sha
        or journal.get("schema") != JOURNAL_SCHEMA or journal.get("phase") not in ("APPLIED", "COMMITTING")
        or journal.get("authorityDocumentId") != authority.get("documentId")
        or journal.get("authoritySha256") != authority_sha
        or journal.get("reconciliationSha256") != digest(reconciliation_bytes)
        or not isinstance(journal.get("transactionId"), str) or SHA256_RE.fullmatch(journal["transactionId"]) is None
    ):
        stop("post-maintenance evidence does not bind the current authority/reconciliation journal.")
    documents = {
        key: parse_json(snapshots[key], f"checkpoint {key} evidence", True)
        for key in (
            "logicalBackupEvidenceSha256", "offHostBackupEvidenceSha256", "restoreEvidenceSha256",
            "secretsBackupEvidenceSha256",
        )
    }
    validate_post_backup_bundle(
        authority, documents, digest(reconciliation_bytes), journal["transactionId"], began_at, now
    )


def refresh_local_checkpoint(
    authority: Dict[str, object], runtime_data: Optional[bytes] = None, began_at: Optional[int] = None
) -> None:
    checkpoint_bytes = secure_file(LOCAL_CHECKPOINT, "LOCAL_PRIVATE checkpoint", MAX_AUTHORITY)
    checkpoint_identity = fixed_file_identity(LOCAL_CHECKPOINT, "LOCAL_PRIVATE checkpoint")
    checkpoint = exact_keys(parse_json(checkpoint_bytes, "LOCAL_PRIVATE checkpoint", True), (
        "authoritative", "backupCapturedUnixSeconds", "candidateCommit", "candidateTree", "destructiveMutationPlanned",
        "generatedAtUnixSeconds", "logicalBackupEvidenceSha256", "offHostBackupEvidenceSha256", "restoreEvidenceSha256",
        "restoreVerified", "runtimeInventorySha256", "runtimeRecovered", "schedulerRecoveryImageExportSha256",
        "schedulerRecoveryImageId", "schedulerRunningImageId", "schema", "secretsBackupEvidenceSha256", "sourceArchiveSha256",
    ), "LOCAL_PRIVATE checkpoint")
    now = int(time.time())
    captured = checkpoint["backupCapturedUnixSeconds"]
    if (
        checkpoint["schema"] != "platform.v1-local-private-predeploy-checkpoint/v1"
        or checkpoint["authoritative"] is not False
        or checkpoint["destructiveMutationPlanned"] is not False
        or checkpoint["restoreVerified"] is not True
        or checkpoint["runtimeRecovered"] is not True
        or checkpoint["candidateCommit"] != authority["candidateCommit"]
        or checkpoint["candidateTree"] != authority["candidateTree"]
        or checkpoint["sourceArchiveSha256"] != authority["sourceArchiveSha256"]
        or isinstance(captured, bool) or not isinstance(captured, int)
        # backupCapturedUnixSeconds is recorded when the live backup phase
        # completes, mid-producer; the restore/upload/readback cycle on the
        # deployment host legitimately exceeds one hour, so the post-publish
        # guard bounds by the full measured cycle (6h) while the destructive
        # pre-mutation gate keeps its own 1h freshness at apply time.
        or captured > now + 60 or now - captured > 6 * 3600
    ):
        stop("LOCAL_PRIVATE checkpoint is not one fresh candidate-bound backup/restore guard.")
    snapshots, snapshot_identities = stable_checkpoint_evidence_snapshots()
    if runtime_data is not None and snapshots["runtimeInventorySha256"] != runtime_data:
        stop("runtime inventory bytes changed before the checkpoint refresh.")
    if began_at is not None:
        validate_post_checkpoint_evidence(authority, snapshots, began_at, now)
    for key, data in snapshots.items():
        evidence = parse_json(data, f"checkpoint {key} evidence", True)
        if began_at is not None:
            timestamps = [
                evidence[field] for field in (
                    "capturedAtUnixSeconds", "completedAtUnixSeconds", "generatedAtUnixSeconds",
                    "verifiedAtUnixSeconds", "writtenAtUnixSeconds",
                ) if field in evidence
            ]
            if (
                not timestamps
                or any(isinstance(value, bool) or not isinstance(value, int) for value in timestamps)
                or max(timestamps) < began_at
                or max(timestamps) > now
            ):
                stop(f"checkpoint {key} evidence is not one truthful post-maintenance document.")
        observed = digest(data)
        if runtime_data is None:
            if observed != checkpoint[key]:
                stop(f"LOCAL_PRIVATE checkpoint {key} differs from fixed evidence bytes.")
            if not isinstance(checkpoint[key], str) or SHA256_RE.fullmatch(checkpoint[key]) is None:
                stop(f"LOCAL_PRIVATE checkpoint {key} is not a canonical digest.")
        else:
            # The post-maintenance producer replaces all four backup/restore
            # documents, and this reconciler contributes the runtime document.
            # Bind every observed byte sequence into the one new checkpoint;
            # retaining any pre-maintenance digest would make seal ambiguous.
            checkpoint[key] = observed
    export_identity = fixed_file_identity(SCHEDULER_RECOVERY_EXPORT, "scheduler recovery image export")
    if export_identity[-1] & 0o022:
        stop("scheduler recovery image export is writable by group/other.")
    export_sha = stable_file_digest(SCHEDULER_RECOVERY_EXPORT, "scheduler recovery image export", MAX_RECOVERY_EXPORT)
    if checkpoint["schedulerRecoveryImageExportSha256"] != export_sha:
        stop("scheduler recovery export changed while the LOCAL_PRIVATE checkpoint was refreshed.")
    for key in ("schedulerRecoveryImageId", "schedulerRunningImageId"):
        if not isinstance(checkpoint[key], str) or IMAGE_ID_RE.fullmatch(checkpoint[key]) is None:
            stop("LOCAL_PRIVATE checkpoint scheduler image identity is invalid.")
    checkpoint["generatedAtUnixSeconds"] = now
    revalidate_checkpoint_evidence_snapshots(snapshots, snapshot_identities)
    if fixed_file_identity(SCHEDULER_RECOVERY_EXPORT, "scheduler recovery image export") != export_identity:
        stop("scheduler recovery export changed before checkpoint replacement.")
    if fixed_file_identity(LOCAL_CHECKPOINT, "LOCAL_PRIVATE checkpoint") != checkpoint_identity:
        stop("LOCAL_PRIVATE checkpoint changed before its atomic replacement.")
    mode = checkpoint_identity[-1]
    if mode & 0o022:
        stop("LOCAL_PRIVATE checkpoint is writable by group/other.")
    atomic_json(LOCAL_CHECKPOINT, checkpoint, mode)
    observed = secure_file(LOCAL_CHECKPOINT, "refreshed LOCAL_PRIVATE checkpoint", MAX_AUTHORITY, mode)
    if observed != canonical_bytes(checkpoint):
        stop("refreshed LOCAL_PRIVATE checkpoint bytes changed after atomic replacement.")


def git_archive(repo_root: str) -> bytes:
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    result = run_result(
        [
            git_binary(),
            "-c", "core.fsmonitor=false",
            "-c", "core.hooksPath=/dev/null",
            "-c", f"safe.directory={repo_root}",
            "-C", repo_root, "archive", "--format=tar", "HEAD",
        ],
        "Git exact source archive",
        timeout=300,
        cwd="/",
        environment=environment,
        max_output=MAX_ARCHIVE,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()[:512]
        stop(f"fixed Git archive command rejected the operation: {detail}.")
    if not result.stdout or len(result.stdout) > MAX_ARCHIVE:
        stop("Git exact source archive has an invalid size.")
    return result.stdout


def release_root(commit: str, archive_sha: str) -> str:
    return f"/srv/platform-infrastructure/releases/{commit}-{archive_sha}"


def release_file(release: str, relative: str) -> str:
    logical = f"{release}/{relative}"
    pathname = physical(logical)
    no_symlink_chain(pathname, logical)
    return pathname


def executor_authority_images(authority: Dict[str, object]) -> Tuple[set, set]:
    tools = exact_keys(
        authority.get("backupToolImages"),
        ("mariadbRestore", "minioRestore", "nodeUtility", "postgresRestore", "resticRclone"),
        "executor backup helper images",
    )
    references, identifiers = set(), set()
    for name, raw in tools.items():
        image = exact_keys(raw, ("imageId", "imageReference"), f"executor {name} image")
        if (
            not isinstance(image["imageId"], str) or IMAGE_ID_RE.fullmatch(image["imageId"]) is None
            or not isinstance(image["imageReference"], str) or DIGEST_REFERENCE_RE.fullmatch(image["imageReference"]) is None
        ):
            stop("executor helper image authority is invalid.")
        identifiers.add(image["imageId"])
        references.add(image["imageReference"])
    for raw in authority.get("serviceTargets", []):
        if not isinstance(raw, dict) or not isinstance(raw.get("semantic"), dict):
            stop("executor service target image authority is invalid.")
        image_id, reference = raw["semantic"].get("imageId"), raw["semantic"].get("imageReference")
        if not isinstance(image_id, str) or IMAGE_ID_RE.fullmatch(image_id) is None:
            stop("executor service target image ID is invalid.")
        if not isinstance(reference, str) or DIGEST_REFERENCE_RE.fullmatch(reference) is None:
            stop("executor service target image reference is mutable.")
        identifiers.add(image_id)
        references.add(reference)
    return references, identifiers


def validate_executor_request(authority: Dict[str, object], request: object, expected_id: int) -> Tuple[str, Dict[str, object]]:
    del authority  # authority is consumed by execution; request shape is fixed independently.
    value = exact_keys(request, ("action", "id", "parameters"), "typed evidence executor request")
    if isinstance(value["id"], bool) or not isinstance(value["id"], int) or value["id"] != expected_id:
        stop("evidence executor request ID is not strictly monotonic.")
    action = value["action"]
    parameter_keys = {
        "RUNTIME_INVENTORY": ("runId",),
        "VERIFY_TOOL_IMAGE": ("runId", "tool"),
        "BACKUP_APPLICATIONS": ("runId",),
        "BACKUP_POSTGRES": ("database", "runId"),
        "BACKUP_MARIADB": ("runId",),
        "BACKUP_MINIO": ("runId",),
        "BACKUP_KEYCLOAK": ("runId",),
        "BACKUP_SECRET_METADATA": ("runId",),
        "RESTORE_POSTGRES": ("logicalKey", "runId"),
        "RESTORE_MARIADB": ("runId",),
        "RESTORE_MINIO": ("runId",),
        "RESTORE_KEYCLOAK": ("runId",),
        "RESTIC_SNAPSHOTS": ("logicalKey", "runId"),
        "RESTIC_BACKUP": ("logicalKey", "runId"),
        "RESTIC_RESTORE": ("logicalKey", "runId", "snapshotId"),
        "ESCROW_UPLOAD": ("runId",),
        "ESCROW_READBACK": ("runId",),
    }
    if not isinstance(action, str) or action not in parameter_keys:
        stop("typed evidence executor action is outside the closed V1 set.")
    parameters = exact_keys(value["parameters"], parameter_keys[action], f"typed evidence executor {action} parameters")
    if not isinstance(parameters["runId"], str) or RUN_ID_RE.fullmatch(parameters["runId"]) is None:
        stop("typed evidence executor run ID is invalid.")
    if action == "VERIFY_TOOL_IMAGE" and parameters["tool"] not in {
        "mariadbRestore", "minioRestore", "nodeUtility", "postgresRestore", "resticRclone",
    }:
        stop("typed evidence executor tool selector is invalid.")
    if action == "BACKUP_POSTGRES" and parameters["database"] not in ("stexor", "keycloak"):
        stop("typed PostgreSQL backup database is outside the closed pair.")
    if "logicalKey" in parameters:
        allowed = {
            "RESTORE_POSTGRES": ("pg-stexor", "pg-keycloak"),
            "RESTIC_SNAPSHOTS": EVIDENCE_LOGICAL_KEYS,
            "RESTIC_BACKUP": EVIDENCE_LOGICAL_KEYS,
            "RESTIC_RESTORE": EVIDENCE_LOGICAL_KEYS,
        }[action]
        if parameters["logicalKey"] not in allowed:
            stop("typed evidence executor logical key is outside its action family.")
    if "snapshotId" in parameters and (
        not isinstance(parameters["snapshotId"], str) or SHA256_RE.fullmatch(parameters["snapshotId"]) is None
    ):
        stop("typed Restic restore snapshot ID is invalid.")
    return action, parameters


def executor_run_docker(arguments: List[str], label: str, timeout: int = 1800) -> subprocess.CompletedProcess:
    if any("enterprise-backup-scheduler" in item for item in arguments):
        stop("typed evidence executor never invokes the quarantined legacy scheduler.")
    return run_result(
        [docker_binary(), *arguments], f"typed evidence {label}", timeout=timeout,
        max_output=MAX_EXECUTOR_RESPONSE // 3, sensitive=True,
    )


def executor_success_output(value: object) -> Tuple[int, bytes, bytes]:
    return 0, canonical_bytes(value), b""


def executor_verify_tool(authority: Dict[str, object], tool_name: str) -> Tuple[int, bytes, bytes]:
    tool = authority["backupToolImages"][tool_name]
    result = executor_run_docker(["image", "inspect", tool["imageReference"]], f"{tool_name} image inspection", 60)
    if result.returncode != 0:
        return result.returncode, result.stdout, result.stderr
    try:
        objects = json.loads(result.stdout.decode("utf-8", errors="strict"), object_pairs_hook=duplicate_safe)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        stop(f"typed helper image inspection returned invalid JSON: {error}.")
    if not isinstance(objects, list) or len(objects) != 1 or objects[0].get("Id") != tool["imageId"]:
        stop("typed helper image digest reference differs from authority image ID.")
    return executor_success_output({
        "imageId": tool["imageId"], "imageReference": tool["imageReference"], "status": "PASS", "tool": tool_name,
    })


def executor_runtime_inventory() -> Tuple[int, bytes, bytes]:
    ids_result = executor_run_docker(["ps", "-aq", "--no-trunc"], "runtime container ID inventory", 30)
    if ids_result.returncode != 0:
        return ids_result.returncode, ids_result.stdout, ids_result.stderr
    try:
        identifiers = [item for item in ids_result.stdout.decode("ascii", errors="strict").splitlines() if item]
    except UnicodeDecodeError:
        stop("typed runtime inventory returned non-ASCII container IDs.")
    if len(identifiers) != len(set(identifiers)) or any(SHA256_RE.fullmatch(item) is None for item in identifiers):
        stop("typed runtime inventory returned invalid full container IDs.")
    containers = []
    if identifiers:
        inspect = executor_run_docker(["inspect", *sorted(identifiers)], "runtime container inspect", 60)
        if inspect.returncode != 0:
            return inspect.returncode, inspect.stdout, inspect.stderr
        try:
            containers = json.loads(inspect.stdout.decode("utf-8", errors="strict"), object_pairs_hook=duplicate_safe)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            stop(f"typed runtime container inspection returned invalid JSON: {error}.")
        if not isinstance(containers, list) or len(containers) != len(identifiers):
            stop("typed runtime container inspection cardinality differs.")
    volumes_result = executor_run_docker(["volume", "ls", "--quiet"], "runtime volume inventory", 30)
    if volumes_result.returncode != 0:
        return volumes_result.returncode, volumes_result.stdout, volumes_result.stderr
    try:
        volumes = sorted(item for item in volumes_result.stdout.decode("utf-8", errors="strict").splitlines() if item)
    except UnicodeDecodeError:
        stop("typed runtime volume inventory returned non-UTF-8 names.")
    if len(volumes) != len(set(volumes)) or any(NAME_RE.fullmatch(item) is None for item in volumes):
        stop("typed runtime volume inventory returned invalid names.")
    return executor_success_output({
        "containerIds": sorted(identifiers), "containers": containers, "status": "PASS", "volumes": volumes,
    })


def executor_workspace(run_id: str) -> str:
    return physical(f"/dev/shm/platform-v1-evidence-{run_id}-transaction")


def executor_artifact_paths(run_id: str, logical_key: str) -> Tuple[str, List[str]]:
    index = EVIDENCE_LOGICAL_KEYS.index(logical_key) + 1
    directory = os.path.join(executor_workspace(run_id), "artifact-staging", f"{index:02d}-{logical_key}")
    no_symlink_chain(directory, "typed evidence artifact staging")
    try:
        entries = sorted(os.listdir(directory))
    except OSError as error:
        stop(f"typed evidence artifact staging is unavailable: {error.strerror}.")
    if len(entries) != 3 or any(
        not os.path.isfile(os.path.join(directory, name)) or os.path.islink(os.path.join(directory, name)) for name in entries
    ):
        stop("typed evidence artifact staging is not one payload/checksum/HMAC set.")
    primary = [name for name in entries if not name.endswith(".sha256") and not name.endswith(".sig.json")]
    if len(primary) != 1 or set(entries) != {primary[0], primary[0] + ".sha256", primary[0] + ".sig.json"}:
        stop("typed evidence artifact sidecar names differ from its exact payload.")
    return directory, [primary[0], primary[0] + ".sha256", primary[0] + ".sig.json"]


def executor_service_image(authority: Dict[str, object], container_name: str) -> str:
    matches = [
        raw for raw in authority.get("serviceTargets", [])
        if isinstance(raw, dict) and raw.get("containerName") == container_name
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("semantic"), dict):
        stop(f"typed evidence executor lacks one exact {container_name} service target.")
    image_id = matches[0]["semantic"].get("imageId")
    image_reference = matches[0]["semantic"].get("imageReference")
    if (
        not isinstance(image_id, str) or IMAGE_ID_RE.fullmatch(image_id) is None
        or not isinstance(image_reference, str) or DIGEST_REFERENCE_RE.fullmatch(image_reference) is None
    ):
        stop(f"typed evidence executor {container_name} image authority is invalid.")
    return image_id


def executor_primary_artifact(run_id: str, logical_key: str) -> Tuple[str, str]:
    directory, names = executor_artifact_paths(run_id, logical_key)
    pathname = os.path.join(directory, names[0])
    try:
        metadata = os.lstat(pathname)
    except OSError as error:
        stop(f"typed evidence restore artifact is unavailable: {error.strerror}.")
    expected_uid = OWNER_UID if TEST_ROOT else 0
    if (
        not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink != 1
        or metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) != 0o400
    ):
        stop("typed evidence restore artifact is not one root-owned single-link 0400 file.")
    logical = pathname[len(TEST_ROOT):] if TEST_ROOT and pathname.startswith(TEST_ROOT) else pathname
    return pathname, digest(secure_file(logical, "typed evidence restore artifact", MAX_ARCHIVE, 0o400))


def executor_infra_environment(authority: Dict[str, object], action: str, run_id: str) -> Dict[str, str]:
    release = authority.get("releaseRoot")
    if not isinstance(release, str) or release != release_root(authority["candidateCommit"], authority["sourceArchiveSha256"]):
        stop("typed evidence infra action has a foreign exact-release root.")
    tools = exact_keys(
        authority.get("backupToolImages"),
        ("mariadbRestore", "minioRestore", "nodeUtility", "postgresRestore", "resticRclone"),
        "typed evidence backup helper images",
    )
    env_bytes = secure_file(RENDER_ENV, "typed evidence exact render environment", 1024 * 1024, 0o400)
    render_binding = exact_keys(authority.get("renderEnvironment"), ("path", "sha256"), "typed evidence render binding")
    if render_binding != {"path": RENDER_ENV, "sha256": digest(env_bytes)}:
        stop("typed evidence render environment differs from release authority.")
    _, rendered = parse_env(env_bytes, "typed evidence exact render environment")
    render_bytes = secure_file(RENDER, "typed evidence exact Compose render", MAX_JSON, 0o444)
    if authority.get("renderSha256") != digest(render_bytes):
        stop("typed evidence exact Compose render differs from release authority.")
    compose_render = parse_json(render_bytes, "typed evidence exact Compose render", True)
    services = compose_render.get("services") if isinstance(compose_render, dict) else None
    keycloak = services.get("keycloak") if isinstance(services, dict) else None
    keycloak_environment = keycloak.get("environment") if isinstance(keycloak, dict) else None
    keycloak_admin = (
        keycloak_environment.get("KC_BOOTSTRAP_ADMIN_USERNAME")
        if isinstance(keycloak_environment, dict) else None
    )
    if not isinstance(keycloak_admin, str) or re.fullmatch(r"[A-Za-z0-9._@-]{1,256}", keycloak_admin) is None:
        stop("typed evidence exact Compose render has no valid Keycloak administrator binding.")
    selected = {
        "BACKUP_SIGNING_KEYS_FILE": physical(BACKUP_SIGNING_KEYS),
        "HOME": "/nonexistent",
        "KC_BOOTSTRAP_ADMIN_USERNAME": keycloak_admin,
        "LANG": "C",
        "LC_ALL": "C",
        "MARIADB_IMAGE": tools["mariadbRestore"]["imageId"],
        "MINIO_IMAGE": executor_service_image(authority, "enterprise-minio"),
        "NODE_IMAGE": tools["nodeUtility"]["imageId"],
        "PATH": "/usr/bin:/bin",
        "PLATFORM_CLOSED_HOST_PATH_MAPPINGS": "1",
        "PLATFORM_DATA_CONTAINER_ROOT": physical(DEPLOYMENT_REPO),
        "PLATFORM_DATA_HOST_ROOT": physical(DEPLOYMENT_REPO),
        "PLATFORM_DATA_ROOT": physical(DEPLOYMENT_REPO),
        "PLATFORM_INFRA_CONTAINER_ROOT": physical(release),
        "PLATFORM_INFRA_HOST_ROOT": physical(release),
        "PLATFORM_INFRA_ROOT": physical(release),
        "PLATFORM_RELEASE_CONTAINER_ROOT": physical(release),
        "PLATFORM_RELEASE_HOST_ROOT": physical(release),
        "PLATFORM_SECRETS_CONTAINER_ROOT": physical(SECRET_DIR),
        "PLATFORM_SECRETS_HOST_ROOT": physical(SECRET_DIR),
        "PLATFORM_SECRETS_ROOT": physical(SECRET_DIR),
        "PLATFORM_STATE_CONTAINER_ROOT": physical(PROJECT_STATE_ROOT),
        "PLATFORM_STATE_HOST_ROOT": physical(PROJECT_STATE_ROOT),
        "PLATFORM_V1_EVIDENCE_ARTIFACT_ROOT": os.path.join(executor_workspace(run_id), "artifact-staging"),
        "PLATFORM_V1_EVIDENCE_AUTHORITY_SHA256": authority["documentId"],
        "PLATFORM_V1_EVIDENCE_INFRA_OPERATION": {
            "BACKUP_APPLICATIONS": "backup-applications",
            "BACKUP_POSTGRES": "backup-postgres",
            "BACKUP_MARIADB": "backup-mariadb",
            "BACKUP_MINIO": "backup-minio",
            "BACKUP_KEYCLOAK": "backup-keycloak",
            "BACKUP_SECRET_METADATA": "backup-secret-manager-metadata",
            "RESTORE_POSTGRES": "restore-test-postgres",
            "RESTORE_MARIADB": "restore-test-mariadb",
            "RESTORE_MINIO": "restore-test-minio",
            "RESTORE_KEYCLOAK": "restore-test-keycloak",
        }[action],
        "PLATFORM_V1_EVIDENCE_NETWORK_MODE": "none",
        "PLATFORM_V1_EVIDENCE_RUN_ID": run_id,
        "PLATFORM_V1_TYPED_EVIDENCE_ACTION": action,
        "POSTGRES_IMAGE": executor_service_image(authority, "enterprise-postgres"),
        "POSTGRES_OPS_SCHEMA": rendered.get("POSTGRES_OPS_SCHEMA", "ops"),
        "POSTGRES_RESTORE_TEST_IMAGE": tools["postgresRestore"]["imageId"],
        "PROJECT_SOURCE_HOST_ROOT": physical(PROJECT_SOURCE_ROOT),
        "PROJECT_SOURCE_ROOT": physical(PROJECT_SOURCE_ROOT),
        "PROJECT_STATE_ROOT": physical(PROJECT_STATE_ROOT),
    }
    if action in ("BACKUP_MARIADB", "RESTORE_MARIADB"):
        selected["MARIADB_IMAGE"] = executor_service_image(authority, "mariadb")
    return selected


def parse_executor_restore_receipt(output: bytes, operation: str, artifact_sha256: str) -> Dict[str, object]:
    try:
        lines = output.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError:
        stop(f"typed {operation} receipt output is not UTF-8.")
    prefix = "V1_EVIDENCE_RECEIPT:"
    receipts = [line[len(prefix):] for line in lines if line.startswith(prefix)]
    if len(receipts) != 1 or not lines or lines[-1] != prefix + receipts[0]:
        stop(f"typed {operation} emitted no single final comparator receipt.")
    try:
        value = json.loads(receipts[0], object_pairs_hook=duplicate_safe)
    except (json.JSONDecodeError, ValueError) as error:
        stop(f"typed {operation} comparator receipt is not strict JSON: {error}.")
    value = exact_keys(
        value, ("artifactSha256", "counts", "matched", "operation", "schema", "scope", "semanticComparator"),
        f"typed {operation} comparator receipt",
    )
    if (
        canonical_bytes(value) != (receipts[0] + "\n").encode("utf-8")
        or value["schema"] != "platform.v1.restore-evidence-receipt/v1"
        or value["operation"] != operation or value["artifactSha256"] != artifact_sha256
        or value["matched"] is not True or not isinstance(value["scope"], str) or not value["scope"]
        or not isinstance(value["counts"], dict) or not isinstance(value["semanticComparator"], dict)
    ):
        stop(f"typed {operation} comparator receipt is incomplete or cross-bound.")
    return value


def execute_typed_infra_action(
    authority: Dict[str, object], action: str, parameters: Dict[str, object]
) -> Tuple[int, bytes, bytes]:
    run_id = parameters["runId"]
    operation = {
        "BACKUP_APPLICATIONS": "backup-applications",
        "BACKUP_POSTGRES": "backup-postgres",
        "BACKUP_MARIADB": "backup-mariadb",
        "BACKUP_MINIO": "backup-minio",
        "BACKUP_KEYCLOAK": "backup-keycloak",
        "BACKUP_SECRET_METADATA": "backup-secret-manager-metadata",
        "RESTORE_POSTGRES": "restore-test-postgres",
        "RESTORE_MARIADB": "restore-test-mariadb",
        "RESTORE_MINIO": "restore-test-minio",
        "RESTORE_KEYCLOAK": "restore-test-keycloak",
    }.get(action)
    if operation is None:
        stop("typed evidence infra action is outside the fixed backup/restore set.")
    release = authority["releaseRoot"]
    infra_logical = f"{release}/scripts/infra-ops.mjs"
    infra = release_file(release, "scripts/infra-ops.mjs")
    if digest(secure_file(infra_logical, "typed evidence exact-release infra program", 32 * 1024 * 1024)) == digest(b""):
        stop("typed evidence exact-release infra program is empty.")
    arguments = [operation, "--skipEvidence", "true"]
    artifact_sha = None
    if action == "BACKUP_POSTGRES":
        arguments += ["--container", "enterprise-postgres", "--database", parameters["database"], "--user", "postgres"]
    elif action == "BACKUP_MARIADB":
        arguments += ["--container", "mariadb"]
    elif action == "BACKUP_MINIO":
        arguments += ["--container", "enterprise-minio"]
    elif action == "BACKUP_KEYCLOAK":
        arguments += ["--container", "enterprise-keycloak"]
    elif action.startswith("RESTORE_"):
        logical_key = parameters["logicalKey"] if action == "RESTORE_POSTGRES" else {
            "RESTORE_MARIADB": "mariadb", "RESTORE_MINIO": "minio", "RESTORE_KEYCLOAK": "keycloak-config",
        }[action]
        artifact, artifact_sha = executor_primary_artifact(run_id, logical_key)
        arguments += ["--backupFile", artifact, "--v1EvidenceReceipt", "true"]
        if action == "RESTORE_POSTGRES":
            database = "stexor" if logical_key == "pg-stexor" else "keycloak"
            arguments += ["--container", "enterprise-postgres", "--database", database, "--countAllUserTables", "true", "--minimumTables", "1"]
        elif action == "RESTORE_MARIADB":
            arguments += ["--container", "mariadb", "--minSchemas", "1", "--image", executor_service_image(authority, "mariadb")]
        elif action == "RESTORE_MINIO":
            arguments += [
                "--container", "enterprise-minio", "--image", executor_service_image(authority, "enterprise-minio"),
                "--utilityImage", authority["backupToolImages"]["nodeUtility"]["imageId"],
            ]
        else:
            arguments += ["--container", "enterprise-keycloak", "--minRealms", "1", "--image", authority["backupToolImages"]["nodeUtility"]["imageId"]]
    environment = executor_infra_environment(authority, action, run_id)
    result = run_result(
        [node_binary(), infra, *arguments], f"typed evidence {action}", timeout=3600, cwd=physical(release),
        environment=environment, max_output=MAX_EXECUTOR_RESPONSE // 3, sensitive=True,
    )
    if result.returncode != 0:
        return result.returncode, result.stdout, result.stderr
    if action.startswith("RESTORE_"):
        receipt = parse_executor_restore_receipt(result.stdout, operation, artifact_sha)
        return executor_success_output({"action": action, "comparatorReceipt": receipt, "status": "PASS"})
    return executor_success_output({"action": action, "status": "PASS"})


def executor_restic_base(authority: Dict[str, object], run_id: str, extra_mounts: List[str]) -> List[str]:
    workspace = executor_workspace(run_id)
    rclone_dir = os.path.join(workspace, "rclone-private")
    password_dir = os.path.join(workspace, "restic-password-private")
    for directory, label in ((rclone_dir, "rclone config"), (password_dir, "Restic password")):
        no_symlink_chain(directory, f"typed evidence {label} directory")
        if not os.path.isdir(directory) or os.path.islink(directory):
            stop(f"typed evidence {label} directory is invalid.")
    tool = authority["backupToolImages"]["resticRclone"]
    # Re-inspect immediately before every helper action.
    status, _, _ = executor_verify_tool(authority, "resticRclone")
    if status != 0:
        stop("typed evidence Restic/rclone image reinspection failed.")
    return [
        "run", "--rm", "--network", "bridge", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true", "--pids-limit", "256", "--memory", "1g", "--cpus", "1",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,mode=1777,size=128m",
        "-e", f"RESTIC_REPOSITORY={authority['evidenceProducer']['offsiteRepository']}",
        "-e", f"RESTIC_PASSWORD_FILE=/restic-password/{os.path.basename(RESTIC_PASSWORD)}",
        "-e", "RCLONE_CONFIG=/rclone-config/rclone.conf", "-v", f"{password_dir}:/restic-password:ro",
        "-v", f"{rclone_dir}:/rclone-config:rw", *extra_mounts, tool["imageId"],
    ]


def execute_typed_evidence_action(
    authority: Dict[str, object], action: str, parameters: Dict[str, object]
) -> Tuple[int, bytes, bytes]:
    if action == "RUNTIME_INVENTORY":
        return executor_runtime_inventory()
    if action == "VERIFY_TOOL_IMAGE":
        return executor_verify_tool(authority, parameters["tool"])
    if action.startswith("BACKUP_") or action.startswith("RESTORE_"):
        return execute_typed_infra_action(authority, action, parameters)
    run_id = parameters["runId"]
    if action.startswith("RESTIC_"):
        logical_key = parameters["logicalKey"]
        directory, names = executor_artifact_paths(run_id, logical_key)
        base = executor_restic_base(authority, run_id, ["-v", f"{directory}:/backup:ro"])
        tag = f"local-private-v1-{run_id}"
        if action == "RESTIC_SNAPSHOTS":
            command = ["snapshots", "--json", "--tag", tag, "--host", "platform-v1-local-private"]
        elif action == "RESTIC_BACKUP":
            command = [
                "backup", "--json", *(f"/backup/{name}" for name in names), "--tag", tag,
                "--tag", f"logical-key-{logical_key}", "--host", "platform-v1-local-private",
            ]
        else:
            readback = os.path.join(executor_workspace(run_id), f"readback-{EVIDENCE_LOGICAL_KEYS.index(logical_key) + 1:02d}")
            no_symlink_chain(readback, "typed Restic readback directory")
            if not os.path.isdir(readback) or os.path.islink(readback):
                stop("typed Restic readback directory is invalid.")
            base = executor_restic_base(authority, run_id, ["-v", f"{readback}:/restore:rw"])
            command = ["restore", "--target", "/restore", parameters["snapshotId"]]
        # RESTIC_BACKUP/RESTORE include the full OneDrive round-trip for large
        # datasets (MinIO archive alone exceeded 900s); match the 3600s budget
        # already granted to typed infra actions.
        result = executor_run_docker([*base, *command], f"{action} {logical_key}", 3600)
        return result.returncode, result.stdout, result.stderr
    workspace = executor_workspace(run_id)
    name = f"v1-local-private-recovery-{run_id}.cms"
    envelope_dir = os.path.join(workspace, "cms-recovery-envelope")
    readback_dir = os.path.join(workspace, "cms-recovery-readback")
    rclone_dir = os.path.join(workspace, "rclone-private")
    for directory in (envelope_dir, readback_dir, rclone_dir):
        no_symlink_chain(directory, "typed recovery escrow workspace")
        if not os.path.isdir(directory) or os.path.islink(directory):
            stop("typed recovery escrow workspace is invalid.")
    base = executor_restic_base(authority, run_id, [
        "-v", f"{envelope_dir}:/envelope:ro" if action == "ESCROW_UPLOAD" else f"{readback_dir}:/readback:rw",
        "--entrypoint", "/usr/local/bin/rclone",
    ])
    remote = f"{authority['evidenceProducer']['recoveryEscrowPrefix']}/{name}"
    operands = [f"/envelope/{name}", remote] if action == "ESCROW_UPLOAD" else [remote, f"/readback/{name}"]
    result = executor_run_docker([*base, "copyto", *operands, "--immutable", "--checksum"], action, 900)
    return result.returncode, result.stdout, result.stderr


def serve_evidence_executor(
    endpoint: socket.socket, authority: Dict[str, object], errors: List[BaseException], child: subprocess.Popen,
    session: Optional[Dict[str, str]] = None,
) -> None:
    try:
        if session is None:
            session = {}
        buffer = b""
        expected_id = 1
        while True:
            chunk = endpoint.recv(65536)
            if not chunk:
                if buffer:
                    stop("evidence executor client closed with a partial frame.")
                return
            buffer += chunk
            if len(buffer) > MAX_EXECUTOR_REQUEST:
                stop("evidence executor request exceeded its frame boundary.")
            while b"\n" in buffer:
                frame, buffer = buffer.split(b"\n", 1)
                if not frame:
                    stop("evidence executor received an empty frame.")
                request = parse_json(frame + b"\n", "evidence executor request", True)
                action, parameters = validate_executor_request(authority, request, expected_id)
                if "runId" not in session:
                    session["runId"] = parameters["runId"]
                elif session["runId"] != parameters["runId"]:
                    stop("evidence executor request changed run ID within one producer session.")
                expected_id += 1
                status, stdout, stderr = execute_typed_evidence_action(authority, action, parameters)
                response = {
                    "id": request["id"],
                    "status": status,
                    "stderrBase64": base64.b64encode(stderr).decode("ascii"),
                    "stdoutBase64": base64.b64encode(stdout).decode("ascii"),
                }
                response_data = canonical_bytes(response)
                if len(response_data) > MAX_EXECUTOR_RESPONSE:
                    stop("evidence executor response exceeded its frame boundary.")
                endpoint.sendall(response_data)
    except BaseException as error:
        errors.append(error)
        try:
            endpoint.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        if child.poll() is None:
            child.terminate()
    finally:
        endpoint.close()


def invoke_evidence_producer(authority: Dict[str, object], operation: str) -> Dict[str, object]:
    global EXECUTOR_FD_RESERVED
    producer = exact_keys(authority.get("evidenceProducer"), (
        "executor", "executorFlags", "forbiddenResticOperations", "hostingerAllowed", "logicalKeys",
        "offsiteRepository", "operations", "path", "recoveryEscrowPrefix", "sha256",
    ), "evidence producer invocation authority")
    if operation not in producer["operations"] or producer != evidence_producer_binding(authority["releaseRoot"]):
        stop("fixed evidence producer invocation differs from exact release authority.")
    if SHARED_LOCK_FD != 3:
        stop("fixed evidence producer requires inherited shared transaction lease FD 3.")
    if not EXECUTOR_FD_RESERVED:
        stop("fixed evidence producer requires the reconciler-owned reserved executor FD 4.")
    server_endpoint, client_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    child = None
    errors: List[BaseException] = []
    session: Dict[str, str] = {}
    thread = None
    try:
        os.dup2(client_endpoint.fileno(), 4, inheritable=True)
        client_endpoint.close()
        environment = {
            "HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin",
            "PLATFORM_V1_EVIDENCE_EXECUTOR_FD": "4", "PLATFORM_V1_EVIDENCE_SHARED_LOCK_FD": "3",
        }
        argv = [producer["executor"], *producer["executorFlags"], physical(producer["path"]), operation]
        child = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/", env=environment,
            pass_fds=(3, 4), close_fds=True,
        )
        os.close(4)
        EXECUTOR_FD_RESERVED = False
        thread = threading.Thread(
            target=serve_evidence_executor, args=(server_endpoint, authority, errors, child, session), daemon=True,
            name="v1-evidence-docker-executor",
        )
        thread.start()
        try:
            # The full PRE cycle (live backups, 14 isolated restores, OneDrive
            # upload + readback) runs ~2h on the deployment host and sits at
            # the edge of the previous budget; 4h keeps headroom for slow
            # offsite windows while remaining a hard bound.
            stdout, stderr = child.communicate(timeout=14400)
        except subprocess.TimeoutExpired:
            child.kill()
            stdout, stderr = child.communicate()
            stop("fixed sensitive exact-release evidence producer timed out; output was suppressed.")
        thread.join(timeout=10)
        if thread.is_alive():
            try:
                server_endpoint.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            thread.join(timeout=5)
        if thread.is_alive():
            stop("evidence executor did not close after its exact producer exited.")
        if errors:
            error = errors[0]
            if isinstance(error, Stop):
                raise error
            stop(f"evidence executor failed closed: {type(error).__name__}.")
        if len(stdout) > MAX_AUTHORITY or len(stderr) > MAX_AUTHORITY or child.returncode != 0:
            diagnostic = archive_producer_failure(operation, stderr, int(child.returncode))
            stop(
                f"fixed sensitive exact-release {operation} evidence producer failed; output was "
                f"suppressed. returncode={int(child.returncode)} stdout_bytes={len(stdout)} "
                f"stderr_bytes={len(stderr)} audit={diagnostic}"
            )
        receipt = parse_json(stdout, f"exact-release {operation} evidence producer receipt", True)
        if (
            receipt.get("mode") != operation or receipt.get("status") != "PASS"
            or not isinstance(receipt.get("runId"), str) or receipt.get("runId") != session.get("runId")
        ):
            stop(f"exact-release {operation} evidence producer returned a non-PASS receipt.")
        return receipt
    except OSError as error:
        stop(f"cannot start fixed exact-release evidence producer/executor: {error.strerror}.")
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait()
        try:
            client_endpoint.close()
        except OSError:
            pass
        try:
            server_endpoint.close()
        except OSError:
            pass
        try:
            os.close(4)
        except OSError:
            pass


def render_with_wrapper(release: str, environment_sha: str) -> bytes:
    wrapper_logical = f"{release}/scripts/compose-vps.sh"
    wrapper = release_file(release, "scripts/compose-vps.sh")
    if not os.path.isfile(wrapper) or os.path.islink(wrapper):
        stop("fixed release Compose wrapper is missing or not a regular file.")
    environment_bytes = secure_file(RENDER_ENV, "exact render environment", 1024 * 1024, 0o400)
    if digest(environment_bytes) != environment_sha:
        stop("exact render environment differs before Compose rendered.")
    _, environment_values = parse_env(environment_bytes, "exact render environment")
    present_runtime_identity = {name for name in RUNTIME_IDENTITY_ENV if name in environment_values}
    if present_runtime_identity and present_runtime_identity != set(RUNTIME_IDENTITY_ENV):
        stop("exact render environment carries a partial runtime identity tuple.")
    environment = {
        "COMPOSE_ENV_FILE": physical(RENDER_ENV),
        "COMPOSE_PROJECT_NAME": "platform_infra_vps",
        "PLATFORM_COMPOSE_VARIANT": "LOCAL_PRIVATE",
        "PLATFORM_V1_LOCAL_PRIVATE_RENDER": "1",
    }
    environment.update({name: environment_values[name] for name in RUNTIME_IDENTITY_ENV if name in present_runtime_identity})
    output = run([wrapper, "config", "--format", "json"], "release Compose render", cwd=physical(release), environment=environment, timeout=180)
    render = parse_json(output, "release Compose render")
    canonical_render = canonical_bytes(render)
    # Re-read the materialized descriptor after the wrapper so the render is
    # never accepted across a descriptor swap.
    if digest(secure_file(RENDER_ENV, "exact render environment", 1024 * 1024, 0o400)) != environment_sha:
        stop("exact render environment changed while Compose rendered.")
    if wrapper_logical != f"{release}/scripts/compose-vps.sh":
        stop("internal fixed wrapper binding drifted.")
    return canonical_render


def runtime_identity_environment(
    commit: str, tree: str, release: str, source_render_bytes: bytes
) -> Dict[str, str]:
    source_render = parse_json(source_render_bytes, "identity-free source Compose render", True)
    services = source_render.get("services") if isinstance(source_render, dict) else None
    if not isinstance(services, dict) or set(services) != set(MANAGED_CONTAINER_BY_SERVICE):
        stop("identity-free source render is not the exact active plus disabled V1 service set.")
    runtime_labels = set(RUNTIME_IDENTITY_LABEL_BY_ENV.values())
    for service_name, service in services.items():
        labels = service.get("labels", {}) if isinstance(service, dict) else None
        if not isinstance(labels, dict) or runtime_labels.intersection(labels):
            stop(f"identity-free source render service {service_name} already carries runtime identity labels.")
    workload_lock = secure_file(
        f"{release}/config/no-hosted-workloads.local-private.lock.json",
        "exact LOCAL_PRIVATE no-hosted workload lock",
        MAX_JSON,
    )
    source_render_sha = digest(source_render_bytes)
    workload_lock_sha = digest(workload_lock)
    seed = {
        "candidateCommit": commit,
        "candidateTree": tree,
        "sourceRenderSha256": source_render_sha,
        "workloadLockSha256": workload_lock_sha,
    }
    candidate_id = digest(canonical(seed).encode())
    return {
        "PLATFORM_RUNTIME_CANDIDATE_ID": candidate_id,
        "PLATFORM_RUNTIME_COMMIT": commit,
        "PLATFORM_RUNTIME_TREE": tree,
        "PLATFORM_RUNTIME_DEPLOYMENT_ID": f"v1-local-private:{candidate_id}",
        "PLATFORM_RUNTIME_SOURCE_RENDER_SHA256": source_render_sha,
        "PLATFORM_RUNTIME_WORKLOAD_LOCK_SHA256": workload_lock_sha,
    }


def runtime_identity_document(environment: Dict[str, str]) -> Dict[str, str]:
    if set(environment) != set(RUNTIME_IDENTITY_ENV):
        stop("runtime identity is not the exact closed V1 environment tuple.")
    return {
        "candidateId": environment["PLATFORM_RUNTIME_CANDIDATE_ID"],
        "commit": environment["PLATFORM_RUNTIME_COMMIT"],
        "deploymentId": environment["PLATFORM_RUNTIME_DEPLOYMENT_ID"],
        "sourceRenderSha256": environment["PLATFORM_RUNTIME_SOURCE_RENDER_SHA256"],
        "tree": environment["PLATFORM_RUNTIME_TREE"],
        "workloadLockSha256": environment["PLATFORM_RUNTIME_WORKLOAD_LOCK_SHA256"],
    }


def runtime_identity_labels(document: Dict[str, str]) -> Dict[str, str]:
    exact_keys(document, (
        "candidateId", "commit", "deploymentId", "sourceRenderSha256", "tree", "workloadLockSha256",
    ), "runtime identity")
    return {
        "com.platform.runtime.candidate-id": document["candidateId"],
        "com.platform.runtime.commit": document["commit"],
        "com.platform.runtime.deployment-id": document["deploymentId"],
        "com.platform.runtime.source-render-sha256": document["sourceRenderSha256"],
        "com.platform.runtime.tree": document["tree"],
        "com.platform.runtime.workload-lock-sha256": document["workloadLockSha256"],
    }


def source_render_without_runtime_identity(
    render: Dict[str, object], document: Dict[str, str]
) -> bytes:
    value = parse_json(canonical_bytes(render), "final render identity projection", True)
    services = value.get("services") if isinstance(value, dict) else None
    if not isinstance(services, dict):
        stop("final render identity projection has no services object.")
    expected_labels = runtime_identity_labels(document)
    if value.get("x-platform-runtime-labels") != expected_labels:
        stop("final render identity projection lacks exact top-level runtime identity labels.")
    value.pop("x-platform-runtime-labels")
    runtime_labels = set(RUNTIME_IDENTITY_LABEL_BY_ENV.values())
    for service in services.values():
        if not isinstance(service, dict):
            stop("final render identity projection has an invalid service.")
        labels = service.get("labels")
        if labels is None:
            continue
        if not isinstance(labels, dict):
            stop("final render identity projection has invalid labels.")
        projected = {name: label for name, label in labels.items() if name not in runtime_labels}
        if projected:
            service["labels"] = projected
        else:
            service.pop("labels", None)
    return canonical_bytes(value)


def validate_runtime_identity_document(
    document: Dict[str, str], commit: str, tree: str, release: str, render: Dict[str, object], env: Dict[str, str]
) -> None:
    exact_keys(document, (
        "candidateId", "commit", "deploymentId", "sourceRenderSha256", "tree", "workloadLockSha256",
    ), "runtime identity")
    if (
        document["commit"] != commit
        or document["tree"] != tree
        or COMMIT_RE.fullmatch(document["commit"]) is None
        or COMMIT_RE.fullmatch(document["tree"]) is None
        or SHA256_RE.fullmatch(document["sourceRenderSha256"]) is None
        or SHA256_RE.fullmatch(document["workloadLockSha256"]) is None
        or SHA256_RE.fullmatch(document["candidateId"]) is None
        or document["deploymentId"] != f"v1-local-private:{document['candidateId']}"
    ):
        stop("runtime identity tuple is invalid or differs from candidate/tree.")
    workload_lock = secure_file(
        f"{release}/config/no-hosted-workloads.local-private.lock.json",
        "exact LOCAL_PRIVATE no-hosted workload lock",
        MAX_JSON,
    )
    if document["workloadLockSha256"] != digest(workload_lock):
        stop("runtime identity workload-lock digest differs from the exact release.")
    projected_source = source_render_without_runtime_identity(render, document)
    if document["sourceRenderSha256"] != digest(projected_source):
        stop("runtime identity source-render digest differs from the identity-free projection.")
    seed = {
        "candidateCommit": commit,
        "candidateTree": tree,
        "sourceRenderSha256": document["sourceRenderSha256"],
        "workloadLockSha256": document["workloadLockSha256"],
    }
    if document["candidateId"] != digest(canonical(seed).encode()):
        stop("runtime candidate ID is not derived from candidate/tree/source-render/workload-lock.")
    expected_environment = {
        "PLATFORM_RUNTIME_CANDIDATE_ID": document["candidateId"],
        "PLATFORM_RUNTIME_COMMIT": document["commit"],
        "PLATFORM_RUNTIME_TREE": document["tree"],
        "PLATFORM_RUNTIME_DEPLOYMENT_ID": document["deploymentId"],
        "PLATFORM_RUNTIME_SOURCE_RENDER_SHA256": document["sourceRenderSha256"],
        "PLATFORM_RUNTIME_WORKLOAD_LOCK_SHA256": document["workloadLockSha256"],
    }
    if any(env.get(name) != value for name, value in expected_environment.items()):
        stop("exact render environment differs from the authority runtime identity.")
    validate_runtime_identity_render(render, document)


def validate_runtime_identity_render(render: Dict[str, object], document: Dict[str, str]) -> None:
    services = render.get("services")
    if not isinstance(services, dict) or set(services) != set(MANAGED_CONTAINER_BY_SERVICE):
        stop("final render is not the exact active plus disabled V1 service set.")
    expected = runtime_identity_labels(document)
    for service_name, service in services.items():
        labels = service.get("labels") if isinstance(service, dict) else None
        if not isinstance(labels, dict) or any(labels.get(name) != value for name, value in expected.items()):
            stop(f"final render service {service_name} lacks the exact runtime identity tuple.")


def compose_config_hashes(release: str) -> Dict[str, str]:
    output = run(
        [
            docker_binary(), "compose", "--project-name", "platform_infra_vps",
            "--project-directory", physical(release), "--file", physical(RENDER),
            "config", "--hash", "*",
        ],
        "exact render Compose config hashes",
        timeout=180,
    ).decode("ascii", errors="strict")
    hashes: Dict[str, str] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) != 2 or NAME_RE.fullmatch(parts[0]) is None or SHA256_RE.fullmatch(parts[1]) is None:
            stop("exact render Compose config-hash output is invalid.")
        service, config_hash = parts
        if service in hashes:
            stop("exact render Compose config-hash output is duplicated.")
        hashes[service] = config_hash
    if set(hashes) != set(ACTIVE_SERVICE_BY_CONTAINER.values()):
        stop("exact render Compose config hashes are not the exact active V1 service set.")
    return hashes


def image_id_for(reference: str) -> str:
    objects = docker_json(["image", "inspect", reference], f"image {reference}")
    if not isinstance(objects, list) or len(objects) != 1 or not isinstance(objects[0], dict):
        stop("immutable image inspection returned the wrong cardinality.")
    image_id = objects[0].get("Id")
    if not isinstance(image_id, str) or IMAGE_ID_RE.fullmatch(image_id) is None:
        stop("immutable image inspection returned a non-canonical image ID.")
    return image_id


def exact_release_node_utility_image(release: str) -> str:
    references = []
    for relative in NODE_UTILITY_DOCKERFILES:
        try:
            text = secure_file(
                f"{release}/{relative}",
                f"exact-release Node authority Dockerfile {relative}",
                1024 * 1024,
            ).decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            stop(f"exact-release Node authority Dockerfile {relative} is not UTF-8.")
        declarations = re.findall(r"^ARG[ \t]+NODE_IMAGE(?:[ \t]*=.*)?[ \t]*$", text, flags=re.MULTILINE)
        matches = re.findall(r"^ARG NODE_IMAGE=([^\s#]+)$", text, flags=re.MULTILINE)
        from_uses = re.findall(r"^FROM[ \t]+\$\{NODE_IMAGE\}(?:[ \t].*)?$", text, flags=re.MULTILINE)
        from_lines = re.findall(r"^FROM \$\{NODE_IMAGE\}$", text, flags=re.MULTILINE)
        if len(declarations) != 1 or len(matches) != 1 or len(from_uses) != 1 or len(from_lines) != 1:
            stop(f"exact-release Node authority Dockerfile {relative} lacks one closed NODE_IMAGE source.")
        references.append(matches[0])
    if len(set(references)) != 1:
        stop("exact-release Dockerfiles have divergent Node backup utility image authorities.")
    reference = references[0]
    if DIGEST_REFERENCE_RE.fullmatch(reference) is None or reference.endswith("@sha256:" + "0" * 64):
        stop("exact-release Dockerfiles lack one non-zero digest-pinned Node backup utility image authority.")
    return reference


def ensure_node_utility_image(release: str) -> str:
    reference = exact_release_node_utility_image(release)
    inspection = run_result(
        [docker_binary(), "image", "inspect", reference],
        "local Node backup utility image inspection",
        timeout=120,
    )
    if inspection.returncode != 0:
        run(
            [docker_binary(), "pull", reference],
            "immutable Node backup utility image pull",
            timeout=600,
        )
    image_id_for(reference)
    return reference


def backup_tool_image_references(
    release: str, render: Dict[str, object], env_values: Dict[str, str]
) -> Dict[str, str]:
    services = render.get("services")
    if not isinstance(services, dict):
        stop("canonical exact release render has no services object for backup helpers.")

    def service_image(service_name: str, helper_name: str) -> str:
        service = services.get(service_name)
        reference = service.get("image") if isinstance(service, dict) else None
        if not isinstance(reference, str):
            stop(f"canonical render omits the {helper_name} service image authority.")
        return reference

    postgres_restore = env_values.get("POSTGRES_RESTORE_TEST_IMAGE")
    if not postgres_restore:
        postgres_restore = service_image("postgres", "PostgreSQL restore")
    references = {
        "mariadbRestore": service_image("mariadb", "MariaDB restore"),
        "minioRestore": service_image("minio", "MinIO restore"),
        "nodeUtility": exact_release_node_utility_image(release),
        "postgresRestore": postgres_restore,
        "resticRclone": env_values.get("RESTIC_IMAGE", ""),
    }
    if set(references) != set(BACKUP_TOOL_IMAGE_NAMES):
        stop("backup helper image authority differs from the closed V1 set.")
    for name, reference in references.items():
        match = DIGEST_REFERENCE_RE.fullmatch(reference) if isinstance(reference, str) else None
        if match is None or reference.endswith("@sha256:" + "0" * 64):
            stop(f"canonical inputs lack one non-zero digest-pinned {name} backup helper image authority.")
    restic_prefix = "127.0.0.1:5000/platform/restic-rclone@sha256:"
    if not references["resticRclone"].startswith(restic_prefix):
        stop("Restic/rclone backup helper is not the exact locally published V1 image.")
    return references


def route_contract(render: Dict[str, object], env: Dict[str, str]) -> Tuple[List[Dict[str, object]], List[Dict[str, object]]]:
    # Preserved workloads retain enterprise_net and gain only the trust zones
    # required by their frozen configuration.  Aliases match the names already
    # consumed by exact-main managed services and monitoring configuration.
    definitions = render.get("networks", {})
    zones = {
        name: resource_name(definitions, f"platform_{name}", "platform_infra_vps", f"V1 {name} bridge")
        for name in ("routing", "db_admin", "postgres", "cache", "bus", "storage", "observability", "egress")
    }
    domain = env.get("DOMAIN", "platform-infrastructure.com").strip()
    if not re.fullmatch(r"[A-Za-z0-9.-]+", domain) or domain.startswith(".") or domain.endswith("."):
        stop("deployment DOMAIN cannot form the fixed legacy route check.")
    matrix: Dict[str, Dict[str, List[str]]] = {
        "enterprise-backend": {
            "postgres": ["backend"], "cache": ["backend"],
            "bus": ["backend"], "storage": ["backend"], "egress": ["backend"],
        },
        "enterprise-cadvisor": {"observability": ["cadvisor"]},
        "enterprise-node-exporter": {"observability": ["node-exporter"]},
        "enterprise-worker-jobs": {
            "postgres": ["worker-jobs"], "cache": ["worker-jobs"],
            "bus": ["worker-jobs"],
        },
        "enterprise-worker-notifications": {
            "postgres": ["worker-notifications"], "cache": ["worker-notifications"],
            "bus": ["worker-notifications"], "observability": ["worker-notifications"],
            "egress": ["worker-notifications"],
        },
        "node-account": {"routing": ["node-account"]},
        "node-opstudents": {"routing": ["node-opstudents"]},
        "node-ui": {"routing": ["node-ui"]},
        "php-anniversary": {"routing": ["php-anniversary"], "db_admin": ["php-anniversary"]},
        "php-fiplatform": {"routing": ["php-fiplatform"], "db_admin": ["php-fiplatform"]},
        "php-matthewdifilippo": {"routing": ["php-matthewdifilippo"]},
        "php-stream": {"routing": ["php-stream"], "db_admin": ["php-stream"]},
        "php-workcalendar": {"routing": ["php-workcalendar"], "db_admin": ["php-workcalendar"]},
        "phpmyadmin": {"routing": ["phpmyadmin"], "db_admin": ["phpmyadmin"]},
        # phppgadmin intentionally remains exited, but its frozen configuration
        # still needs the DB zone if the operator starts that preserved object.
        "phppgadmin": {"db_admin": ["phppgadmin"]},
    }
    attachments = sorted(({
        "aliases": sorted(aliases),
        "containerName": container,
        "networkName": zones[zone],
    } for container, network_map in matrix.items() for zone, aliases in network_map.items()), key=lambda item: (item["containerName"], item["networkName"]))
    route_specs = (
        ("account", "node-account", 200),
        ("anniversary", "php-anniversary", 200),
        ("fiplatform", "php-fiplatform", 200),
        ("fireport", "php-fiplatform", 200),
        ("matthewdifilippo", "php-matthewdifilippo", 200),
        ("opstudents", "node-opstudents", 200),
        ("stream", "php-stream", 303),
        ("ui", "node-ui", 200),
        ("workcalendar", "php-workcalendar", 302),
    )
    routes = sorted(({
        "containerName": container,
        "expectedStatus": status,
        "name": f"{slug}-edge-route",
        "url": f"https://{slug}.{domain}/",
    } for slug, container, status in route_specs), key=lambda item: item["name"])
    routes.append({
        "containerName": "phpmyadmin",
        "expectedStatus": 200,
        "name": "phpmyadmin-portal-route",
        "url": f"https://portal.{domain}/phpmyadmin",
    })
    routes.sort(key=lambda item: item["name"])
    return attachments, routes


def artifact_binding(logical: str, label: str, maximum: int = 2 * 1024 * 1024, mode: Optional[int] = None) -> Dict[str, str]:
    data = secure_file(logical, label, maximum, mode)
    return {"path": logical, "sha256": digest(data)}


def recovery_escrow_certificate_binding(release: str) -> Dict[str, str]:
    logical = f"{release}/config/local-private-recovery-escrow-cert.pem"
    data = secure_file(logical, "V1 recovery escrow public certificate", 256 * 1024)
    try:
        pem = data.decode("ascii", errors="strict")
        der = ssl.PEM_cert_to_DER_cert(pem)
    except (UnicodeDecodeError, ValueError, ssl.SSLError) as error:
        stop(f"V1 recovery escrow certificate is not one valid ASCII X.509 PEM: {error}.")
    if not der:
        stop("V1 recovery escrow certificate has an empty DER identity.")
    return {"path": logical, "sha256": digest(data), "sha256Fingerprint": digest(der)}


def evidence_producer_binding(release: str) -> Dict[str, object]:
    logical = f"{release}/scripts/v1-local-private-evidence-producer.py"
    data = secure_file(logical, "exact-release V1 evidence producer", 4 * 1024 * 1024)
    return {
        "executor": "/usr/bin/python3",
        "executorFlags": ["-I"],
        "forbiddenResticOperations": ["forget", "prune"],
        "hostingerAllowed": False,
        "logicalKeys": list(EVIDENCE_LOGICAL_KEYS),
        "offsiteRepository": "rclone:platform-onedrive:platform-infrastructure/restic",
        "operations": ["pre", "post"],
        "path": logical,
        "recoveryEscrowPrefix": "platform-onedrive:platform-infrastructure/key-escrow",
        "sha256": digest(data),
    }


def build_authority(
    commit: str,
    tree: str,
    archive_sha: str,
    release: str,
    env_bytes: bytes,
    render_bytes: bytes,
    env_values: Dict[str, str],
    runtime_identity_environment_values: Dict[str, str],
) -> Dict[str, object]:
    render = parse_json(render_bytes, "canonical exact release render", True)
    runtime_identity = runtime_identity_document(runtime_identity_environment_values)
    validate_runtime_identity_document(runtime_identity, commit, tree, release, render, env_values)
    services = render.get("services")
    if not isinstance(services, dict):
        stop("canonical exact release render has no services object.")
    config_hashes = compose_config_hashes(release)
    targets = []
    for container_name in ACTIVE_MANAGED:
        service_name = ACTIVE_SERVICE_BY_CONTAINER[container_name]
        service = services.get(service_name)
        if not isinstance(service, dict):
            stop(f"canonical exact release render omits active service {service_name}.")
        reference = service.get("image")
        if not isinstance(reference, str) or DIGEST_REFERENCE_RE.fullmatch(reference) is None:
            stop(f"active service {service_name} is not bound to an immutable registry digest; build/publish it before prepare.")
        image_id = image_id_for(reference)
        project = PROJECT_BY_NAME[container_name]
        targets.append({
            "configHash": config_hashes[service_name],
            "containerName": container_name,
            "project": project,
            "semantic": render_service_semantics(render, service_name, image_id, project),
            "service": service_name,
        })
    for service_name in DISABLED_SERVICES:
        if service_name not in services:
            stop(f"canonical exact release render omits disabled provider {service_name}.")
    if any(
        mount["source"] in ("/run/docker.sock", "/var/run/docker.sock")
        or mount["target"] in ("/run/docker.sock", "/var/run/docker.sock")
        for target in targets for mount in target["semantic"]["mounts"]
    ):
        stop("active exact release target grants raw Docker socket authority.")
    attachments, route_checks = route_contract(render, env_values)
    backup_tool_images = {}
    for name, reference in backup_tool_image_references(release, render, env_values).items():
        backup_tool_images[name] = {"imageId": image_id_for(reference), "imageReference": reference}
    wrapper = f"{release}/scripts/compose-vps.sh"
    artifacts = {
        "composeWrapper": artifact_binding(wrapper, "fixed release Compose wrapper"),
        "controller": artifact_binding(CONTROLLER, "installed V1 controller"),
        "installer": artifact_binding(INSTALLER, "installed V1 installer"),
        "reconciler": artifact_binding(RECONCILER, "installed V1 reconciler"),
        "sudoers": artifact_binding(SUDOERS, "installed V1 controller sudoers", 65536, 0o440),
        "unit": artifact_binding(UNIT, "installed V1 controller unit", 65536, 0o444),
    }
    now = int(time.time())
    base: Dict[str, object] = {
        "activeManagedContainerNames": list(ACTIVE_MANAGED),
        "artifacts": artifacts,
        "authorityMode": "LOCAL_PRIVATE",
        "authorizedDataMutations": [dict(item) for item in sorted(AUTHORIZED_DATA_MUTATIONS, key=lambda item: item["id"])],
        "backupToolImages": backup_tool_images,
        "candidateCommit": commit,
        "candidateTree": tree,
        "checkoutProof": {
            "clean": True,
            "githubMainCommit": commit,
            "githubMainRef": "refs/remotes/github/main",
            "headCommit": commit,
            "headTree": tree,
            "producer": "CLEAN_CHECKOUT_GITHUB_MAIN_V1",
            "status": "PASS",
            "verifiedAtUnixSeconds": now,
        },
        "controllerVerificationScope": "AUTHORITY_ARCHIVE_RELEASE_RENDER_ONLY_NOT_GITHUB",
        "disabledComposeServices": list(DISABLED_SERVICES),
        "evidenceProducer": evidence_producer_binding(release),
        "expectedContainerNames": list(CANONICAL_CONTAINERS),
        "legacyNetworkAttachments": attachments,
        "legacyRouteChecks": route_checks,
        "legacyUnmanagedContainers": [dict(item) for item in LEGACY_UNMANAGED],
        "preservedLegacyContainerNames": list(PRESERVED_LEGACY),
        "recoveryEscrowCertificate": recovery_escrow_certificate_binding(release),
        "releaseRoot": release,
        "renderEnvironment": {"path": RENDER_ENV, "sha256": digest(env_bytes)},
        "renderSha256": digest(render_bytes),
        "runtimeIdentity": runtime_identity,
        "schema": AUTHORITY_SCHEMA,
        "serviceTargets": targets,
        "sourceArchiveSha256": archive_sha,
        "status": "AUTHORIZED",
    }
    value = dict(base)
    value["documentId"] = digest(canonical(base).encode())
    return value


def read_authority(check_artifacts: bool = True, check_source_archive: bool = True) -> Tuple[Dict[str, object], bytes]:
    data = secure_file(AUTHORITY, "exact release authority", MAX_AUTHORITY, 0o444)
    value = exact_keys(parse_json(data, "exact release authority", True), (
        "activeManagedContainerNames", "artifacts", "authorityMode", "authorizedDataMutations", "backupToolImages", "candidateCommit", "candidateTree",
        "checkoutProof", "controllerVerificationScope", "disabledComposeServices", "documentId", "evidenceProducer", "expectedContainerNames",
        "legacyNetworkAttachments", "legacyRouteChecks", "legacyUnmanagedContainers", "preservedLegacyContainerNames", "releaseRoot",
        "renderEnvironment", "renderSha256", "recoveryEscrowCertificate", "runtimeIdentity", "schema", "serviceTargets",
        "sourceArchiveSha256", "status",
    ), "exact release authority")
    without = dict(value)
    document_id = without.pop("documentId", None)
    if not isinstance(document_id, str) or document_id != digest(canonical(without).encode()):
        stop("exact release authority document ID is invalid.")
    if (
        value["schema"] != AUTHORITY_SCHEMA
        or value["status"] != "AUTHORIZED"
        or value["authorityMode"] != "LOCAL_PRIVATE"
        or value["expectedContainerNames"] != list(CANONICAL_CONTAINERS)
        or value["activeManagedContainerNames"] != list(ACTIVE_MANAGED)
        or value["preservedLegacyContainerNames"] != list(PRESERVED_LEGACY)
        or value["legacyUnmanagedContainers"] != [dict(item) for item in LEGACY_UNMANAGED]
        or value["disabledComposeServices"] != list(DISABLED_SERVICES)
        or value["authorizedDataMutations"] != [dict(item) for item in sorted(AUTHORIZED_DATA_MUTATIONS, key=lambda item: item["id"])]
    ):
        stop("exact release authority closed V1 identity differs.")
    archive = secure_file(f"{AUTHORITY_ARCHIVE_DIR}/{document_id}.json", "archived exact release authority", MAX_AUTHORITY, 0o444)
    if archive != data:
        stop("current exact release authority is not byte-identical to its immutable archive copy.")
    env_binding = exact_keys(value["renderEnvironment"], ("path", "sha256"), "render environment binding")
    if env_binding["path"] != RENDER_ENV:
        stop("render environment path differs from the fixed path.")
    env_bytes = secure_file(RENDER_ENV, "exact render environment", 1024 * 1024, 0o400)
    render_bytes = secure_file(RENDER, "exact release render", MAX_JSON, 0o444)
    if check_source_archive:
        source_bytes = secure_file(SOURCE_ARCHIVE, "exact source archive", MAX_ARCHIVE, 0o444)
        if digest(env_bytes) != env_binding["sha256"] or digest(render_bytes) != value["renderSha256"] or digest(source_bytes) != value["sourceArchiveSha256"]:
            stop("exact authority environment, render or source bytes drifted.")
    else:
        if digest(env_bytes) != env_binding["sha256"] or digest(render_bytes) != value["renderSha256"]:
            stop("exact authority environment or render bytes drifted.")
    if value["releaseRoot"] != release_root(value["candidateCommit"], value["sourceArchiveSha256"]):
        stop("exact authority release root is not commit/archive-derived.")
    _, env_values = parse_env(env_bytes, "exact render environment")
    render = parse_json(render_bytes, "exact release render", True)
    validate_runtime_identity_document(
        value["runtimeIdentity"], value["candidateCommit"], value["candidateTree"], value["releaseRoot"], render, env_values
    )
    backup_tool_images = exact_keys(
        value["backupToolImages"],
        ("mariadbRestore", "minioRestore", "nodeUtility", "postgresRestore", "resticRclone"),
        "backup helper image authority",
    )
    expected_backup_references = backup_tool_image_references(value["releaseRoot"], render, env_values)
    for name, raw in backup_tool_images.items():
        backup_tool = exact_keys(raw, ("imageId", "imageReference"), f"{name} backup helper image authority")
        if (
            not isinstance(backup_tool["imageReference"], str)
            or DIGEST_REFERENCE_RE.fullmatch(backup_tool["imageReference"]) is None
            or backup_tool["imageReference"] != expected_backup_references[name]
            or not isinstance(backup_tool["imageId"], str)
            or IMAGE_ID_RE.fullmatch(backup_tool["imageId"]) is None
            or image_id_for(backup_tool["imageReference"]) != backup_tool["imageId"]
        ):
            stop(f"{name} backup helper image differs from its exact digest/config identity.")
    escrow = exact_keys(value["recoveryEscrowCertificate"], ("path", "sha256", "sha256Fingerprint"), "recovery escrow certificate authority")
    expected_escrow = recovery_escrow_certificate_binding(value["releaseRoot"])
    if escrow != expected_escrow:
        stop("recovery escrow certificate differs from exact release authority.")
    producer = exact_keys(value["evidenceProducer"], (
        "executor", "executorFlags", "forbiddenResticOperations", "hostingerAllowed", "logicalKeys",
        "offsiteRepository", "operations", "path", "recoveryEscrowPrefix", "sha256",
    ), "exact-release evidence producer authority")
    expected_producer = evidence_producer_binding(value["releaseRoot"])
    if producer != expected_producer:
        stop("exact-release evidence producer differs from authority code/operation/offsite policy.")
    if check_artifacts:
        validate_installed_artifacts_match_authority(value)
    return value, data


AUTHORITY_ARTIFACT_NAMES = ("composeWrapper", "controller", "installer", "reconciler", "sudoers", "unit")


def authority_artifact_binding(value: Dict[str, object], name: str) -> Tuple[str, int, Optional[int]]:
    logical = {
        "composeWrapper": f"{value['releaseRoot']}/scripts/compose-vps.sh",
        "controller": CONTROLLER,
        "installer": INSTALLER,
        "reconciler": RECONCILER,
        "sudoers": SUDOERS,
        "unit": UNIT,
    }[name]
    maximum = 65536 if name in ("sudoers", "unit") else 2 * 1024 * 1024
    expected_mode = 0o440 if name == "sudoers" else 0o444 if name == "unit" else None
    return logical, maximum, expected_mode


def validate_installed_artifacts_match_authority(value: Dict[str, object]) -> None:
    exact_keys(value["artifacts"], AUTHORITY_ARTIFACT_NAMES, "exact release artifacts")
    for name in AUTHORITY_ARTIFACT_NAMES:
        artifact = exact_keys(value["artifacts"].get(name) if isinstance(value["artifacts"], dict) else None, ("path", "sha256"), f"{name} artifact")
        logical, maximum, expected_mode = authority_artifact_binding(value, name)
        if artifact["path"] != logical or digest(secure_file(logical, f"{name} artifact", maximum, expected_mode)) != artifact["sha256"]:
            stop(f"{name} artifact differs from exact authority.")


def installed_artifacts_match_authority(value: Dict[str, object]) -> bool:
    """Boolean form of the installed-artifact authority loop; never stops."""
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != set(AUTHORITY_ARTIFACT_NAMES):
        return False
    for name in AUTHORITY_ARTIFACT_NAMES:
        artifact = artifacts.get(name)
        if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256"}:
            return False
        logical, maximum, expected_mode = authority_artifact_binding(value, name)
        if artifact["path"] != logical:
            return False
        try:
            installed = secure_file(logical, f"{name} artifact", maximum, expected_mode)
        except Stop:
            return False
        if digest(installed) != artifact["sha256"]:
            return False
    return True


def installed_source_archive_matches_authority(value: Dict[str, object]) -> bool:
    try:
        source_bytes = secure_file(SOURCE_ARCHIVE, "exact source archive", MAX_ARCHIVE, 0o444)
    except Stop:
        return False
    return digest(source_bytes) == value["sourceArchiveSha256"]


BOOTSTRAP_BRIDGE_RECEIPT_FIELDS = (
    "bridgeSha256", "candidateCommit", "candidateConsumerSha256", "candidateTree",
    "checkpointAfterSha256", "checkpointBeforeSha256", "controlArtifactReceiptSha256",
    "dataMutation", "dockerMutation", "documentId", "gitBundleSha256", "hostControlMutation",
    "installReceiptSha256", "legacyBroadSudoersAfterSha256", "legacyBroadSudoersBeforeSha256",
    "legacyConsumerSha256", "legacyV1SudoersSha256", "nodeRuntimeReceiptSha256",
    "releaseRoot", "schema", "sourceArchiveAfterSha256", "sourceArchiveBeforeSha256",
    "stagingEnvironmentSha256", "stagingMutation", "status",
)
BOOTSTRAP_BRIDGE_RECEIPT_FIELDS_V2 = BOOTSTRAP_BRIDGE_RECEIPT_FIELDS + ("transportSanction",)
BOOTSTRAP_CONTROL_RECEIPT_FIELDS = (
    "artifacts", "candidateCommit", "candidateTree", "dataMutation", "dockerMutation",
    "hostControlMutation", "schema", "sourceArchiveSha256", "status",
)
BOOTSTRAP_CONTROL_RECEIPT_ARTIFACT_NAMES = ("installer", "controller", "reconciler", "unit", "sudoers")
BOOTSTRAP_CONTROL_ARTIFACT_RECEIPT_SCHEMA = "platform.v1-control-artifact-install-receipt/v1"
BOOTSTRAP_BRIDGE_RECEIPT_SCHEMA = "platform.v1-brownfield-bootstrap-bridge-receipt/v1"


def latest_transport_tooling_coherence() -> str:
    """Prove the installed control tooling is exactly the latest sanctioned
    bootstrap transport's, via the bridge/control-artifact receipt chain.

    Returns the proven installed candidate commit.  Any missing, non-canonical,
    or inconsistent receipt fails closed; there is no path that accepts
    unproven installed tooling."""
    bridge_raw = secure_file(BOOTSTRAP_BRIDGE_RECEIPT_FILE, "bootstrap bridge receipt", MAX_AUTHORITY, 0o400)
    bridge = parse_json(bridge_raw, "bootstrap bridge receipt", True)
    if not isinstance(bridge, dict) or set(bridge) not in (set(BOOTSTRAP_BRIDGE_RECEIPT_FIELDS), set(BOOTSTRAP_BRIDGE_RECEIPT_FIELDS_V2)):
        stop("bootstrap bridge receipt is not one exact closed object.")
    without = dict(bridge)
    document_id = without.pop("documentId", None)
    if not isinstance(document_id, str) or document_id != digest(canonical(without).encode()):
        stop("bootstrap bridge receipt document ID is invalid.")
    if (
        bridge["schema"] != BOOTSTRAP_BRIDGE_RECEIPT_SCHEMA
        or bridge["status"] != "BOOTSTRAP_CONTROL_INSTALLED"
        or not isinstance(bridge["candidateCommit"], str) or COMMIT_RE.fullmatch(bridge["candidateCommit"]) is None
        or not isinstance(bridge["candidateTree"], str) or COMMIT_RE.fullmatch(bridge["candidateTree"]) is None
        or not isinstance(bridge["sourceArchiveAfterSha256"], str) or SHA256_RE.fullmatch(bridge["sourceArchiveAfterSha256"]) is None
    ):
        stop("bootstrap bridge receipt identity/status is invalid.")
    control_raw = secure_file(BOOTSTRAP_CONTROL_RECEIPT_FILE, "bootstrap control artifact receipt", MAX_AUTHORITY, 0o400)
    if digest(control_raw) != bridge["controlArtifactReceiptSha256"]:
        stop("bootstrap control artifact receipt differs from the bridge receipt binding.")
    control = parse_json(control_raw, "bootstrap control artifact receipt", True)
    if not isinstance(control, dict) or set(control) != set(BOOTSTRAP_CONTROL_RECEIPT_FIELDS):
        stop("bootstrap control artifact receipt is not one exact closed object.")
    if (
        control["schema"] != BOOTSTRAP_CONTROL_ARTIFACT_RECEIPT_SCHEMA
        or control["status"] != "CONTROL_ARTIFACTS_INSTALLED"
        or control["candidateCommit"] != bridge["candidateCommit"]
        or control["candidateTree"] != bridge["candidateTree"]
        or control["sourceArchiveSha256"] != bridge["sourceArchiveAfterSha256"]
        or control["dataMutation"] is not False
        or control["dockerMutation"] is not False
        or control["hostControlMutation"] is not True
    ):
        stop("bootstrap control artifact receipt differs from the bridge transport identity.")
    if not isinstance(control["artifacts"], list) or len(control["artifacts"]) != len(BOOTSTRAP_CONTROL_RECEIPT_ARTIFACT_NAMES):
        stop("bootstrap control artifact receipt inventory is invalid.")
    logical_by_name = {"installer": INSTALLER, "controller": CONTROLLER, "reconciler": RECONCILER, "unit": UNIT, "sudoers": SUDOERS}
    seen = set()
    for raw in control["artifacts"]:
        item = exact_keys(raw, ("mode", "name", "path", "sha256"), "installed control artifact")
        logical = logical_by_name.get(item["name"])
        if logical is None or item["name"] in seen or item["path"] != logical:
            stop("bootstrap control artifact receipt names an unexpected artifact.")
        seen.add(item["name"])
        maximum = 65536 if item["name"] in ("sudoers", "unit") else 2 * 1024 * 1024
        expected_mode = 0o440 if item["name"] == "sudoers" else 0o444 if item["name"] == "unit" else None
        if digest(secure_file(logical, f"installed control artifact {item['name']}", maximum, expected_mode)) != item["sha256"]:
            stop(f"installed control artifact {item['name']} differs from its sanctioned transport binding.")
    if seen != set(BOOTSTRAP_CONTROL_RECEIPT_ARTIFACT_NAMES):
        stop("bootstrap control artifact receipt inventory is incomplete.")
    return bridge["candidateCommit"]


def authority_candidate_transport_complete(value: Dict[str, object]) -> None:
    """Prove the open transaction's own candidate was completely transported:
    one immutable install receipt with a terminal install-only status must
    bind exactly the authority's candidate identity."""
    receipt_logical = f"{INSTALL_RECEIPTS_DIR}/{value['candidateCommit']}-{value['sourceArchiveSha256']}.json"
    raw = secure_file(receipt_logical, "transaction candidate install receipt", MAX_AUTHORITY, 0o444)
    receipt = parse_json(raw, "transaction candidate install receipt", True)
    if not isinstance(receipt, dict) or set(receipt) != set((
        "activationAuthorized", "authorizationSource", "backupEvidenceAuthoritative",
        "candidateCommit", "candidateTree", "dataMutation", "dockerMutation",
        "readyButDisabled", "releaseRoot", "schema", "sourceArchiveSha256", "status",
    )):
        stop("transaction candidate install receipt is not one exact closed object.")
    if (
        receipt["schema"] != "platform.v1-brownfield-install-receipt/v1"
        or receipt["status"] not in ("INSTALL_ONLY_COMPLETE", "ALREADY_INSTALLED")
        or receipt["candidateCommit"] != value["candidateCommit"]
        or receipt["candidateTree"] != value["candidateTree"]
        or receipt["sourceArchiveSha256"] != value["sourceArchiveSha256"]
        or receipt["releaseRoot"] != value["releaseRoot"]
        or receipt["authorizationSource"] != "ROOT_OPERATOR_EXPLICIT_INSTALL_ONLY"
        or receipt["backupEvidenceAuthoritative"] is not False
        or receipt["activationAuthorized"] is not False
        or receipt["dataMutation"] is not False
        or receipt["dockerMutation"] is not False
    ):
        stop("transaction candidate install receipt boundary/binding is invalid.")


def verify_superseded_transport_abort_preconditions(authority: Dict[str, object], reconciliation: Dict[str, object]) -> None:
    """Prove apply never started before admitting the zero-step stale abort.

    Every condition fails closed: the live state and receipt must be
    byte-identical to the preserved predecessor evidence, every recorded
    predecessor runtime identity must match the live capture on the closed
    controller projection, and no data-mutation evidence may exist for this
    transaction authority."""
    state_bytes = secure_file(STATE_FILE, "LOCAL_PRIVATE state", MAX_AUTHORITY, 0o600)
    receipt_bytes = secure_file(ACTIVE_RECEIPT, "LOCAL_PRIVATE active receipt", MAX_AUTHORITY, 0o444)
    if digest(state_bytes) != reconciliation["previousStateSha256"] or digest(receipt_bytes) != reconciliation["previousReceiptSha256"]:
        stop("stale abort requires the live state/receipt to equal the preserved predecessor evidence.")
    for record in reconciliation["predecessorRuntimeIdentities"]:
        if not isinstance(record, dict) or not isinstance(record.get("name"), str):
            stop("stale abort predecessor identity inventory is invalid.")
        source = inspect_one(record["name"])
        if not controller_predecessor_identity_match(record, source[1]):
            stop(f"stale abort requires predecessor container {record['name']} to match the recorded runtime identity.")
    evidence_dir = physical(MUTATION_EVIDENCE_DIR)
    if os.path.isdir(evidence_dir):
        for entry in os.listdir(evidence_dir):
            if entry.startswith(f"{authority['documentId']}-"):
                stop("stale abort requires no materialized data-mutation evidence for the transaction authority.")


def superseded_transport_abort_journal(authority: Dict[str, object], authority_bytes: bytes, reconciliation: Dict[str, object]) -> Dict[str, object]:
    """One zero-step ABORTED journal for a transaction that provably never
    entered apply: nothing was mutated, so nothing is undone."""
    marker_bytes = secure_file(RECONCILIATION, "controller reconciliation marker", MAX_JSON, 0o600)
    transaction_id = digest(authority_bytes + marker_bytes)
    now = int(time.time())
    journal = {
        "authorityDocumentId": authority["documentId"],
        "authoritySha256": digest(authority_bytes),
        "beganAtUnixSeconds": reconciliation["beganAtUnixSeconds"],
        "createdAtUnixSeconds": now,
        "dataMutationEvidence": [],
        "dataMutationStatus": {item["id"]: "PENDING" for item in authority["authorizedDataMutations"]},
        "deploymentConfigPreimage": materialize_deployment_config_preimage(transaction_id),
        "evidencePreimages": materialize_evidence_preimages(transaction_id),
        "phase": "ABORTED",
        "reconciliationSha256": digest(marker_bytes),
        "schema": JOURNAL_SCHEMA,
        "steps": [],
        "transactionId": transaction_id,
        "updatedAtUnixSeconds": now,
    }
    atomic_json(JOURNAL, journal, 0o600, False)
    return validate_journal(journal, authority, authority_bytes, reconciliation)


def prepare() -> Dict[str, object]:
    if os.path.lexists(physical(JOURNAL)) and not os.path.lexists(physical(RECONCILIATION)):
        previous_authority, previous_authority_bytes = read_authority()
        validate_authority_material(previous_authority)
        prior = parse_json(secure_file(JOURNAL, "completed reconciliation journal", MAX_JSON, 0o600), "completed reconciliation journal", True)
        if prior.get("phase") == "EVIDENCED":
            finalize_evidenced_journal(previous_authority, previous_authority_bytes)
        elif prior.get("phase") == "ABORTED":
            finalize_consumed_abort(previous_authority, previous_authority_bytes)
        else:
            stop("prepare found an unsealed reconciliation journal after controller marker removal.")
    if (
        os.path.lexists(physical(ABORT_RECORD))
        and not os.path.lexists(physical(RECONCILIATION))
        and not os.path.lexists(physical(JOURNAL))
    ):
        previous_authority, previous_authority_bytes = read_authority()
        validate_authority_material(previous_authority)
        cleanup_consumed_abort_without_current_journal(previous_authority, previous_authority_bytes)
    if os.path.lexists(physical(RECONCILIATION)) or os.path.lexists(physical(JOURNAL)):
        stop("prepare refuses to replace exact release material during an unfinished reconciliation.")
    binding = install_binding()
    staging_logical = f"/home/platform_infrastructure/.v1-release-staging/{binding['candidateCommit']}"
    repo_root = physical(staging_logical)
    selected_test_repo = os.environ.get(TEST_REPO_ENV) if TEST_ROOT else None
    if selected_test_repo is not None and selected_test_repo != repo_root:
        stop("test prepare repository differs from the fixed LOCAL_PRIVATE deployment checkout.")
    if not os.path.isabs(repo_root) or os.path.realpath(repo_root) != repo_root:
        stop("prepare repository root is not the canonical fixed deployment checkout.")
    commit, tree = clean_checkout(repo_root)
    if commit != binding["candidateCommit"] or tree != binding["candidateTree"]:
        stop("fixed staging checkout differs from the fresh install checkpoint.")
    archive_bytes = git_archive(repo_root)
    post_archive_commit, post_archive_tree = clean_checkout(repo_root)
    if (post_archive_commit, post_archive_tree) != (commit, tree):
        stop("fixed checkout identity changed while the source archive was captured.")
    archive_sha = digest(archive_bytes)
    if archive_sha != binding["sourceArchiveSha256"]:
        stop("fixed staging checkout archive differs from the installed source authority.")
    release = release_root(commit, archive_sha)
    if release != binding["releaseRoot"]:
        stop("fixed staging checkout release root differs from its install receipt.")
    release_path = physical(release)
    if not os.path.isdir(release_path) or os.path.islink(release_path):
        stop("commit/archive-derived frozen release root is not materialized.")
    installed_reconciler = secure_file(RECONCILER, "installed V1 reconciler", 2 * 1024 * 1024)
    release_reconciler = secure_file(
        f"{release}/scripts/v1-local-private-reconcile.py",
        "exact-release V1 reconciler",
        2 * 1024 * 1024,
    )
    if installed_reconciler != release_reconciler:
        stop("installed V1 reconciler differs from the immutable exact release before prerequisite preparation.")
    local_images = build_and_publish_local_images(repo_root, release, commit)
    local_ops_image = local_images["PLATFORM_OPS_IMAGE"]
    local_restic_image = local_images["RESTIC_IMAGE"]
    # Never create the recovery key until the immutable exact-release public
    # certificate has been parsed and fingerprinted successfully.
    recovery_escrow_certificate_binding(release)
    prepare_live_prerequisite_cohort(release)
    provision_confidential_backup_passphrase()
    source_env_bytes, _ = materialize_environment(
        repo_root, release, local_ops_image, local_restic_image
    )
    ensure_directory(STATE_DIR, 0o700)
    ensure_directory(PREDEPLOY_DIR, 0o700)
    ensure_directory(AUTHORITY_ARCHIVE_DIR, 0o700)
    ensure_directory(MUTATION_EVIDENCE_DIR, 0o700)
    atomic_bytes(RENDER_ENV, source_env_bytes, 0o400)
    source_render_bytes = render_with_wrapper(release, digest(source_env_bytes))
    runtime_environment = runtime_identity_environment(commit, tree, release, source_render_bytes)
    env_bytes, env_values = materialize_environment(
        repo_root, release, local_ops_image, local_restic_image, runtime_environment
    )
    atomic_bytes(RENDER_ENV, env_bytes, 0o400)
    render_bytes = render_with_wrapper(release, digest(env_bytes))
    atomic_bytes(RENDER, render_bytes, 0o444)
    atomic_bytes(SOURCE_ARCHIVE, archive_bytes, 0o444)
    authority = build_authority(
        commit, tree, archive_sha, release, env_bytes, render_bytes, env_values, runtime_environment
    )
    authority_bytes = atomic_json(AUTHORITY, authority, 0o444)
    archived = preserve_json(f"{AUTHORITY_ARCHIVE_DIR}/{authority['documentId']}.json", authority, "archived exact release authority")
    if archived != authority_bytes:
        stop("exact release authority archive copy is not byte-identical.")
    prepared_authority, _ = read_authority()
    lane = load_validation_lane(commit)
    if lane is not None:
        validation_checkpoint = write_validation_checkpoint(authority, {
            "candidateCommit": commit, "candidateTree": tree, "sourceArchiveSha256": archive_sha,
        })
        return {
            "authorityDocumentId": authority["documentId"],
            "authorityPath": AUTHORITY,
            "authoritySha256": digest(authority_bytes),
            "renderSha256": authority["renderSha256"],
            "sourceArchiveSha256": archive_sha,
            "status": "PREPARED_VALIDATION",
            "validationCheckpointPath": VALIDATION_CHECKPOINT_FILE,
            "validationCheckpointSha256": digest(json.dumps(validation_checkpoint, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")),
        }
    invoke_evidence_producer(prepared_authority, "pre")
    refresh_local_checkpoint(authority)
    return {
        "authorityDocumentId": authority["documentId"],
        "authorityPath": AUTHORITY,
        "authoritySha256": digest(authority_bytes),
        "renderSha256": authority["renderSha256"],
        "sourceArchiveSha256": archive_sha,
        "status": "PREPARED",
    }


def normalize_ports(container: Dict[str, object], name: str) -> List[Dict[str, object]]:
    settings = container.get("NetworkSettings")
    ports = settings.get("Ports") if isinstance(settings, dict) else None
    if ports is None:
        return []
    if not isinstance(ports, dict):
        stop(f"container {name} published ports are invalid.")
    result = []
    for target, bindings in ports.items():
        if bindings is None:
            continue
        match = re.fullmatch(r"([0-9]{1,5})/(tcp|udp)", str(target))
        if match is None or not isinstance(bindings, list):
            stop(f"container {name} has an invalid port binding.")
        for binding in bindings:
            if not isinstance(binding, dict) or set(binding) != {"HostIp", "HostPort"}:
                stop(f"container {name} has a non-canonical port binding.")
            try:
                host_ip = str(ipaddress.ip_address(binding["HostIp"]))
                host_port = int(binding["HostPort"])
            except (ValueError, TypeError):
                stop(f"container {name} has an invalid host port/address.")
            result.append({
                "containerPort": int(match.group(1)),
                "hostIp": host_ip,
                "hostPort": host_port,
                "protocol": match.group(2),
            })
    return sorted(result, key=lambda item: (item["hostIp"], item["hostPort"], item["protocol"], item["containerPort"]))


def inspect_network_membership(container: Dict[str, object], name: str) -> List[Dict[str, object]]:
    settings = container.get("NetworkSettings")
    networks = settings.get("Networks") if isinstance(settings, dict) else None
    if not isinstance(networks, dict):
        stop(f"container {name} network membership is invalid.")
    identifier = container.get("Id")
    short_id = identifier[:12] if isinstance(identifier, str) else ""
    result = []
    for network_name, binding in networks.items():
        if not isinstance(network_name, str) or not network_name or not isinstance(binding, dict):
            stop(f"container {name} network membership entry is invalid.")
        aliases = binding.get("Aliases") or []
        if not isinstance(aliases, list) or any(not isinstance(alias, str) or not alias for alias in aliases):
            stop(f"container {name} network aliases are invalid.")
        stable = sorted(set(alias for alias in aliases if alias != short_id))
        result.append({"aliases": stable, "networkName": network_name})
    return sorted(result, key=lambda item: item["networkName"])


def inspect_service_semantics(container: Dict[str, object], name: str) -> Dict[str, object]:
    config = container.get("Config")
    host = container.get("HostConfig")
    mounts = container.get("Mounts")
    if not isinstance(config, dict) or not isinstance(host, dict) or not isinstance(mounts, list):
        stop(f"container {name} runtime configuration is incomplete.")
    normalized_mounts = []
    for index, mount in enumerate(mounts):
        if not isinstance(mount, dict):
            stop(f"container {name} mount {index} is invalid.")
        mount_type, source, target = mount.get("Type"), mount.get("Source", ""), mount.get("Destination")
        if mount_type not in ("bind", "volume", "tmpfs") or not isinstance(source, str) or not isinstance(target, str):
            stop(f"container {name} mount {index} identity is invalid.")
        normalized_mounts.append({"readOnly": mount.get("RW") is False, "source": source, "target": target, "type": mount_type})
    restart = host.get("RestartPolicy")
    restart_name = restart.get("Name", "no") if isinstance(restart, dict) else "no"
    network_mode = host.get("NetworkMode", "")
    semantic_network_mode = network_mode if network_mode in ("none", "host") else "managed"
    health = config.get("Healthcheck")
    if isinstance(health, dict) and not health.get("Test"):
        health = None
    image_reference, image_id = config.get("Image"), container.get("Image")
    if not isinstance(image_reference, str) or not image_reference or not isinstance(image_id, str) or IMAGE_ID_RE.fullmatch(image_id) is None:
        stop(f"container {name} image declaration is invalid.")
    pids_limit = host.get("PidsLimit")
    if pids_limit in (None, 0):
        pids_limit = 0
    labels = config.get("Labels")
    network_endpoints = inspect_network_membership(container, name)
    return {
        "blkioWeight": nonnegative_integer(host.get("BlkioWeight"), f"container {name} blkio weight"),
        "capAdd": sorted(string_list(host.get("CapAdd"), f"container {name} cap-add")),
        "capDrop": sorted(string_list(host.get("CapDrop"), f"container {name} cap-drop")),
        "command": string_list(config.get("Cmd"), f"container {name} command"),
        "cpuShares": nonnegative_integer(host.get("CpuShares"), f"container {name} CPU shares"),
        "entrypoint": string_list(config.get("Entrypoint"), f"container {name} entrypoint"),
        "environment": environment_fingerprints(config.get("Env"), f"container {name} environment"),
        "extraHosts": normalize_extra_hosts(host.get("ExtraHosts"), f"container {name}", rendered=False),
        "groupAdd": sorted(string_list(host.get("GroupAdd"), f"container {name} group-add")),
        "healthcheck": normalized_health(health, f"container {name}", inspect=True),
        "imageId": image_id,
        "imageReference": image_reference,
        "init": host.get("Init") is True,
        "memoryBytes": nonnegative_integer(host.get("Memory"), f"container {name} memory limit"),
        "memoryReservationBytes": nonnegative_integer(host.get("MemoryReservation"), f"container {name} memory reservation"),
        "logging": inspect_logging(host, f"container {name}"),
        "mounts": sorted(normalized_mounts, key=lambda item: (item["target"], item["type"], item["source"], item["readOnly"])),
        "nanoCpus": nonnegative_integer(host.get("NanoCpus"), f"container {name} NanoCPUs"),
        "networkMode": semantic_network_mode,
        "networkEndpoints": network_endpoints,
        "networks": sorted(item["networkName"] for item in network_endpoints),
        "pidMode": str(host.get("PidMode") or ""),
        "pidsLimit": pids_limit,
        "ports": normalize_ports(container, name),
        "privileged": host.get("Privileged") is True,
        "readOnlyRootfs": host.get("ReadonlyRootfs") is True,
        "restartPolicy": restart_name,
        "routingLabels": routing_label_subset(labels, f"container {name}"),
        "runtimeIdentityLabels": runtime_label_subset(labels, f"container {name}"),
        "securityOpt": sorted(string_list(host.get("SecurityOpt"), f"container {name} security-opt")),
        "tmpfs": inspect_tmpfs(host, f"container {name}"),
        "ulimits": inspect_ulimits(host, f"container {name}"),
        "user": str(config.get("User", "")),
        "workingDirectory": str(config.get("WorkingDir") or ""),
    }


def runtime_configuration_digest(semantic: Dict[str, object]) -> str:
    value = dict(semantic)
    value.pop("networks", None)
    value.pop("networkMode", None)
    return digest(canonical(value).encode())


def container_identity(container: Dict[str, object]) -> Dict[str, object]:
    identifier = container.get("Id")
    name = str(container.get("Name", "")).removeprefix("/")
    config = container.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    state = container.get("State")
    if (
        not isinstance(identifier, str) or SHA256_RE.fullmatch(identifier) is None
        or not isinstance(name, str) or NAME_RE.fullmatch(name) is None
        or not isinstance(labels, dict) or not isinstance(state, dict)
    ):
        stop("Docker container inspection has an invalid identity.")
    project, service, config_hash = (
        labels.get("com.docker.compose.project"),
        labels.get("com.docker.compose.service"),
        labels.get("com.docker.compose.config-hash"),
    )
    if not isinstance(project, str) or not isinstance(service, str) or NAME_RE.fullmatch(service) is None or not isinstance(config_hash, str) or SHA256_RE.fullmatch(config_hash) is None:
        stop(f"container {name} has invalid Compose identity labels.")
    semantic = inspect_service_semantics(container, name)
    health_object = state.get("Health")
    health = health_object.get("Status") if isinstance(health_object, dict) else "none"
    exit_code = state.get("ExitCode")
    if isinstance(exit_code, bool) or not isinstance(exit_code, int):
        stop(f"container {name} has invalid exit state.")
    return {
        "configHash": config_hash,
        "containerId": identifier,
        "exitCode": exit_code,
        "health": health,
        "imageId": semantic["imageId"],
        "imageReference": semantic["imageReference"],
        "name": name,
        "networkMembership": inspect_network_membership(container, name),
        "project": project,
        "runtimeConfigSha256": runtime_configuration_digest(semantic),
        "semanticSha256": digest(canonical(semantic).encode()),
        "service": service,
        "state": state.get("Status"),
    }


def inspect_one(name: str, *, missing_ok: bool = False) -> Optional[Tuple[Dict[str, object], Dict[str, object]]]:
    result = run_result([docker_binary(), "inspect", name], f"Docker inspect {name}", timeout=30)
    if result.returncode != 0:
        if missing_ok:
            return None
        detail = result.stderr.decode("utf-8", errors="replace").strip()[:512]
        stop(f"fixed Docker inspect {name} failed: {detail}.")
    try:
        objects = json.loads(result.stdout.decode("utf-8", errors="strict"), object_pairs_hook=duplicate_safe)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        stop(f"Docker inspect {name} returned invalid JSON: {error}.")
    if not isinstance(objects, list) or len(objects) != 1 or not isinstance(objects[0], dict):
        stop(f"Docker inspect {name} returned the wrong cardinality.")
    return objects[0], container_identity(objects[0])


def inventory() -> Tuple[List[Dict[str, object]], Dict[str, Dict[str, object]]]:
    output = run([docker_binary(), "ps", "-aq", "--no-trunc"], "Docker inventory", timeout=30)
    ids = [line for line in output.decode("ascii", errors="strict").splitlines() if line]
    if len(ids) != len(set(ids)) or any(SHA256_RE.fullmatch(item) is None for item in ids):
        stop("Docker inventory contains duplicate or non-full IDs.")
    if not ids:
        return [], {}
    objects = docker_json(["inspect", *sorted(ids)], "inventory inspection", timeout=60)
    if not isinstance(objects, list) or len(objects) != len(ids):
        stop("Docker inventory inspection cardinality differs.")
    identities = []
    raw: Dict[str, Dict[str, object]] = {}
    for item in objects:
        if not isinstance(item, dict):
            stop("Docker inventory contains a non-object.")
        identity = container_identity(item)
        if identity["name"] in raw:
            stop("Docker inventory contains duplicate container names.")
        identities.append(identity)
        raw[identity["name"]] = item
    return sorted(identities, key=lambda item: item["name"]), raw


def transition_identity(record: Optional[Dict[str, object]]) -> Optional[Dict[str, object]]:
    if record is None:
        return None
    return {key: record[key] for key in (
        "configHash", "containerId", "imageId", "imageReference", "name", "runtimeConfigSha256",
    )}


def identity_matches_predecessor(actual: Dict[str, object], expected: Dict[str, object], *, name_may_differ: bool = False) -> bool:
    fields = (
        "configHash", "containerId", "exitCode", "health", "imageId", "imageReference",
        "project", "runtimeConfigSha256", "semanticSha256", "service", "state",
    )
    if not name_may_differ and actual.get("name") != expected.get("name"):
        return False
    return all(actual.get(field) == expected.get(field) for field in fields)


def target_by_name(authority: Dict[str, object]) -> Dict[str, Dict[str, object]]:
    targets = authority.get("serviceTargets")
    if not isinstance(targets, list) or len(targets) != len(ACTIVE_MANAGED):
        stop("exact release authority service target cardinality differs.")
    result = {}
    for raw in targets:
        target = exact_keys(raw, ("configHash", "containerName", "project", "semantic", "service"), "service target")
        name = target["containerName"]
        if name not in ACTIVE_MANAGED or name in result or target["service"] != ACTIVE_SERVICE_BY_CONTAINER[name] or target["project"] != PROJECT_BY_NAME[name]:
            stop("exact release authority has an invalid or duplicate service target.")
        if not isinstance(target["semantic"], dict) or not isinstance(target["configHash"], str) or SHA256_RE.fullmatch(target["configHash"]) is None:
            stop("exact release authority service target semantic is invalid.")
        result[name] = target
    if sorted(result) != list(ACTIVE_MANAGED):
        stop("exact release authority service targets are incomplete.")
    return result


def validate_authority_material(authority: Dict[str, object]) -> Dict[str, Dict[str, object]]:
    env_bytes = secure_file(RENDER_ENV, "exact render environment", 1024 * 1024, 0o400)
    _, env_values = parse_env(env_bytes, "exact render environment")
    expected_secret_bindings = {
        "PLATFORM_SECRETS_ROOT": SECRET_DIR,
        "CONTROL_CENTER_DATABASE_URL_SECRET_FILE": DATABASE_SECRET,
        "CONTROL_CENTER_FIRST_CONFIGURATION_BOOTSTRAP_TOKEN_SECRET_FILE": BOOTSTRAP_SECRET,
        "CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE": KEYCLOAK_CLIENT_SECRET,
        "V1_CONFIDENTIAL_BACKUP_PASSPHRASE_FILE": CONFIDENTIAL_BACKUP_PASSPHRASE,
    }
    if any(env_values.get(name) != pathname for name, pathname in expected_secret_bindings.items()):
        stop("exact render environment secret root/files differ from the closed LOCAL_PRIVATE deployment anchor.")
    rendered = render_with_wrapper(authority["releaseRoot"], digest(env_bytes))
    fixed_render = secure_file(RENDER, "exact release render", MAX_JSON, 0o444)
    if rendered != fixed_render or digest(rendered) != authority["renderSha256"]:
        stop("fixed release wrapper no longer renders the authority-bound semantic model.")
    render = parse_json(fixed_render, "exact release render", True)
    validate_runtime_identity_document(
        authority["runtimeIdentity"], authority["candidateCommit"], authority["candidateTree"],
        authority["releaseRoot"], render, env_values,
    )
    expected_attachments, expected_routes = route_contract(render, env_values)
    if authority["legacyNetworkAttachments"] != expected_attachments or authority["legacyRouteChecks"] != expected_routes:
        stop("exact authority legacy bridge/route contract differs from the fixed V1 compatibility map.")
    if authority["legacyUnmanagedContainers"] != [dict(item) for item in LEGACY_UNMANAGED]:
        stop("exact authority legacy-unmanaged status/reasons differ from the closed V1 inventory.")
    config_hashes = compose_config_hashes(authority["releaseRoot"])
    targets = target_by_name(authority)
    for name, target in targets.items():
        semantic = target["semantic"]
        rebuilt = render_service_semantics(render, target["service"], semantic.get("imageId"), target["project"])
        if (
            rebuilt != semantic
            or target["configHash"] != config_hashes[target["service"]]
            or image_id_for(semantic["imageReference"]) != semantic["imageId"]
        ):
            stop(f"service target {name} differs from render or local immutable image store.")
    return targets


def read_reconciliation(authority: Dict[str, object], authority_bytes: bytes) -> Dict[str, object]:
    data = secure_file(RECONCILIATION, "controller reconciliation marker", MAX_JSON, 0o600)
    value = exact_keys(parse_json(data, "controller reconciliation marker", True), (
        "activeManagedContainerNames", "beganAtUnixSeconds", "candidateCommit", "candidateTree", "controller",
        "disabledComposeServices", "expectedContainerNames", "installReceiptSha256", "plannedLegacyNetworkAttachments",
        "plannedLegacyNetworkAttachmentsSha256", "predecessorRuntimeIdentities", "predecessorRuntimeIdentitiesSha256",
        "legacyUnmanagedContainers", "preservedLegacyContainerNames", "previousReceiptDocumentId", "previousReceiptPath", "previousReceiptSha256",
        "previousStatePath", "previousStateSha256", "releaseAuthorityDocumentId", "releaseAuthoritySha256", "releaseRoot",
        "rollbackCheckpointSha256", "rollbackSchedulerRecovery", "rollbackSchedulerRecoverySha256", "runtimeIdentity", "schema",
        "sourceArchiveSha256", "status",
    ), "controller reconciliation marker")
    if (
        value["schema"] != RECONCILIATION_SCHEMA or value["status"] != "RECONCILING"
        or value["candidateCommit"] != authority["candidateCommit"] or value["candidateTree"] != authority["candidateTree"]
        or value["sourceArchiveSha256"] != authority["sourceArchiveSha256"] or value["releaseRoot"] != authority["releaseRoot"]
        or value["releaseAuthorityDocumentId"] != authority["documentId"] or value["releaseAuthoritySha256"] != digest(authority_bytes)
        or value["expectedContainerNames"] != list(CANONICAL_CONTAINERS)
        or value["activeManagedContainerNames"] != list(ACTIVE_MANAGED)
        or value["preservedLegacyContainerNames"] != list(PRESERVED_LEGACY)
        or value["legacyUnmanagedContainers"] != authority["legacyUnmanagedContainers"]
        or value["runtimeIdentity"] != authority["runtimeIdentity"]
        or value["disabledComposeServices"] != list(DISABLED_SERVICES)
    ):
        stop("controller reconciliation marker differs from exact authority/closed V1 target.")
    began = value["beganAtUnixSeconds"]
    if isinstance(began, bool) or not isinstance(began, int) or began > int(time.time()) + 60:
        stop("controller reconciliation marker timestamp is invalid.")
    predecessors = value["predecessorRuntimeIdentities"]
    if not isinstance(predecessors, list) or digest(canonical(predecessors).encode()) != value["predecessorRuntimeIdentitiesSha256"]:
        stop("controller reconciliation predecessor identities are digest-mismatched.")
    names = [item.get("name") for item in predecessors if isinstance(item, dict)]
    historic = tuple(sorted(HISTORIC_CONTAINERS))
    legacy = tuple(sorted((*HISTORIC_CONTAINERS, LEGACY_ALERT_DISPATCHER)))
    if len(names) != len(predecessors) or tuple(sorted(names)) not in (historic, legacy, CANONICAL_CONTAINERS):
        stop("controller predecessor identities are not one closed V1 form.")
    planned = value["plannedLegacyNetworkAttachments"]
    if not isinstance(planned, list) or digest(canonical(planned).encode()) != value["plannedLegacyNetworkAttachmentsSha256"]:
        stop("controller planned legacy attachments are digest-mismatched.")
    allowed = {canonical(item) for item in authority["legacyNetworkAttachments"]}
    if any(canonical(item) not in allowed for item in planned):
        stop("controller planned legacy attachment exceeds exact authority.")
    return value


def predecessor_map(reconciliation: Dict[str, object]) -> Dict[str, Dict[str, object]]:
    result = {}
    for item in reconciliation["predecessorRuntimeIdentities"]:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or item["name"] in result:
            stop("controller predecessor identity inventory is invalid or duplicated.")
        result[item["name"]] = item
    return result


CONTROLLER_RECORDED_IDENTITY_FIELDS = (
    "configHash", "containerId", "exitCode", "health", "imageId", "imageReference",
    "name", "networkMembership", "runtimeConfigSha256", "semanticSha256", "service", "state",
)
RECONCILER_COMPARABLE_IDENTITY_FIELDS = (
    "configHash", "containerId", "exitCode", "health", "imageId", "imageReference",
    "name", "networkMembership", "service", "state",
)


def controller_predecessor_identity_match(before: object, live: object) -> bool:
    """Whether one live reconciler container identity proves the controller-
    recorded predecessor identity unchanged on every implementation-independent
    field.

    The controller begin records exactly CONTROLLER_RECORDED_IDENTITY_FIELDS
    and the controller's own capture is the sole authority for the two
    semantic digest fields (runtimeConfigSha256, semanticSha256): the
    reconciler's semantic model is a different implementation whose digests
    are not comparable across modules, so the closed-set projection here
    compares the ten implementation-independent fields and the controller
    verifies the full recorded set during abort-maintenance.  The reconciler
    capture additionally carries the compose ``project`` for its own rollback
    purposes; the recorded key set must be exact, the live key set must be
    exactly the recorded set plus ``project``, and any difference on any
    comparable field fails closed."""
    fields = CONTROLLER_RECORDED_IDENTITY_FIELDS
    comparable = RECONCILER_COMPARABLE_IDENTITY_FIELDS
    if not isinstance(before, dict) or set(before) != set(fields):
        return False
    if not isinstance(live, dict) or set(live) != set(fields) | {"project"}:
        return False
    return all(before[key] == live[key] for key in comparable)


def materialize_rollback_spec(transaction_id: str, before: Optional[Dict[str, object]]) -> Tuple[Optional[str], Optional[str]]:
    if before is None:
        return None, None
    source = inspect_one(before["name"])
    if not controller_predecessor_identity_match(before, source[1]):
        stop(f"rollback source {before['name']} differs from controller predecessor evidence.")
    logical_directory = f"{ROLLBACK_SPEC_DIR}/{transaction_id}"
    ensure_directory(ROLLBACK_SPEC_DIR, 0o700)
    ensure_directory(logical_directory, 0o700)
    logical = f"{logical_directory}/{before['name']}.json"
    document = {
        "containerInspect": source[0],
        "predecessorIdentity": before,
        "schema": ROLLBACK_SPEC_SCHEMA,
        "transactionId": transaction_id,
    }
    data = preserve_private_json(logical, document, f"private rollback specification for {before['name']}")
    return logical, digest(data)


def load_rollback_spec(step: Dict[str, object], journal: Dict[str, object]) -> Dict[str, object]:
    logical, expected_sha = step.get("rollbackSpecPath"), step.get("rollbackSpecSha256")
    if not isinstance(logical, str) or not isinstance(expected_sha, str) or SHA256_RE.fullmatch(expected_sha) is None:
        stop("reconciliation step lacks its immutable private rollback specification binding.")
    expected_prefix = f"{ROLLBACK_SPEC_DIR}/{journal['transactionId']}/"
    if not logical.startswith(expected_prefix) or "/" in logical.removeprefix(expected_prefix):
        stop("private rollback specification path escaped its transaction directory.")
    data = secure_file(logical, "private rollback specification", MAX_JSON, 0o600)
    if digest(data) != expected_sha:
        stop("private rollback specification bytes differ from the journal binding.")
    value = exact_keys(parse_json(data, "private rollback specification", True), (
        "containerInspect", "predecessorIdentity", "schema", "transactionId",
    ), "private rollback specification")
    if (
        value["schema"] != ROLLBACK_SPEC_SCHEMA
        or value["transactionId"] != journal["transactionId"]
        or value["predecessorIdentity"] != step.get("before")
        or not isinstance(value["containerInspect"], dict)
        or container_identity(value["containerInspect"]) != step.get("before")
    ):
        stop("private rollback specification differs from the exact predecessor identity.")
    return value


def stable_preimage_snapshot(
    logical: str, label: str, expected_uid: Optional[int] = None, expected_gid: Optional[int] = None
) -> Tuple[bytes, int]:
    pathname = physical(logical)
    no_symlink_chain(pathname, label)
    fd = os.open(pathname, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != (OWNER_UID if expected_uid is None else expected_uid)
            or before.st_gid != (OWNER_GID if expected_gid is None else expected_gid)
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > MAX_JSON
            or mode & 0o022
        ):
            stop(f"{label} cannot be preserved as one private rollback preimage.")
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                stop(f"{label} became truncated while its preimage was captured.")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            stop(f"{label} grew while its preimage was captured.")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            stop(f"{label} changed while its preimage was captured.")
        return b"".join(chunks), mode
    finally:
        os.close(fd)


def evidence_preimage_sources() -> Tuple[str, ...]:
    # Restore the checkpoint last so a crash can never expose an old
    # checkpoint that falsely binds only a partially restored evidence set.
    evidence = tuple(sorted(set(CHECKPOINT_EVIDENCE_PATHS.values())))
    return (*evidence, LOCAL_CHECKPOINT)


def materialize_evidence_preimages(transaction_id: str) -> List[Dict[str, object]]:
    logical_directory = f"{ROLLBACK_SPEC_DIR}/{transaction_id}/evidence-preimages"
    ensure_directory(ROLLBACK_SPEC_DIR, 0o700)
    ensure_directory(f"{ROLLBACK_SPEC_DIR}/{transaction_id}", 0o700)
    ensure_directory(logical_directory, 0o700)
    entries = []
    for index, source in enumerate(evidence_preimage_sources()):
        data, mode = stable_preimage_snapshot(source, f"rollback preimage source {source}")
        preimage = f"{logical_directory}/{index:02d}.bin"
        if os.path.lexists(physical(preimage)):
            observed = secure_file(preimage, f"immutable rollback preimage {index}", MAX_JSON, 0o600)
            if observed != data:
                stop("existing rollback evidence preimage differs from current predecessor bytes.")
        else:
            atomic_bytes(preimage, data, 0o600, False)
            observed = secure_file(preimage, f"immutable rollback preimage {index}", MAX_JSON, 0o600)
        entries.append({
            "logicalPath": source,
            "mode": mode,
            "preimagePath": preimage,
            "sha256": digest(observed),
            "sizeBytes": len(observed),
        })
    # Close the capture window: every source must still be the byte/mode
    # identity from which its immutable entry was produced.
    for entry in entries:
        current, current_mode = stable_preimage_snapshot(entry["logicalPath"], "rollback preimage revalidation")
        if digest(current) != entry["sha256"] or len(current) != entry["sizeBytes"] or current_mode != entry["mode"]:
            stop("checkpoint/evidence changed while rollback preimages were materialized.")
    return entries


def validate_evidence_preimages(entries: object, transaction_id: str) -> List[Dict[str, object]]:
    if not isinstance(entries, list) or len(entries) != len(evidence_preimage_sources()):
        stop("reconciliation journal has the wrong rollback evidence-preimage cardinality.")
    expected_sources = list(evidence_preimage_sources())
    prefix = f"{ROLLBACK_SPEC_DIR}/{transaction_id}/evidence-preimages/"
    validated = []
    for index, raw in enumerate(entries):
        entry = exact_keys(raw, ("logicalPath", "mode", "preimagePath", "sha256", "sizeBytes"), f"rollback evidence preimage {index}")
        if (
            entry["logicalPath"] != expected_sources[index]
            or entry["preimagePath"] != f"{prefix}{index:02d}.bin"
            or isinstance(entry["mode"], bool)
            or not isinstance(entry["mode"], int)
            or entry["mode"] & 0o022
            or isinstance(entry["sizeBytes"], bool)
            or not isinstance(entry["sizeBytes"], int)
            or entry["sizeBytes"] < 1
            or entry["sizeBytes"] > MAX_JSON
            or not isinstance(entry["sha256"], str)
            or SHA256_RE.fullmatch(entry["sha256"]) is None
        ):
            stop("reconciliation journal contains an invalid rollback evidence preimage binding.")
        data = secure_file(entry["preimagePath"], f"rollback evidence preimage {index}", MAX_JSON, 0o600)
        if len(data) != entry["sizeBytes"] or digest(data) != entry["sha256"]:
            stop("rollback evidence preimage bytes differ from their journal binding.")
        validated.append(entry)
    return validated


def restore_evidence_preimages(journal: Dict[str, object]) -> None:
    entries = validate_evidence_preimages(journal["evidencePreimages"], journal["transactionId"])
    for entry in entries:
        data = secure_file(entry["preimagePath"], "rollback evidence preimage", MAX_JSON, 0o600)
        atomic_bytes(entry["logicalPath"], data, entry["mode"])
        observed, mode = stable_preimage_snapshot(entry["logicalPath"], "restored checkpoint/evidence preimage")
        if observed != data or mode != entry["mode"]:
            stop("restored checkpoint/evidence bytes or mode differ from the immutable preimage.")


def materialize_deployment_config_preimage(transaction_id: str) -> Dict[str, object]:
    data, mode = stable_preimage_snapshot(
        DEPLOYMENT_ENV, "live deployment environment preimage", SECRET_UID, SECRET_GID
    )
    preimage = f"{ROLLBACK_SPEC_DIR}/{transaction_id}/deployment-env.bin"
    if os.path.lexists(physical(preimage)):
        observed = secure_file(preimage, "immutable deployment environment preimage", 1024 * 1024, 0o600)
        if observed != data:
            stop("existing deployment environment preimage differs from predecessor bytes.")
    else:
        atomic_bytes(preimage, data, 0o600, False)
        observed = secure_file(preimage, "immutable deployment environment preimage", 1024 * 1024, 0o600)
    return {
        "logicalPath": DEPLOYMENT_ENV,
        "mode": mode,
        "preimagePath": preimage,
        "sha256": digest(observed),
        "sizeBytes": len(observed),
    }


def validate_deployment_config_preimage(raw: object, transaction_id: str) -> Dict[str, object]:
    entry = exact_keys(raw, ("logicalPath", "mode", "preimagePath", "sha256", "sizeBytes"), "deployment config preimage")
    if (
        entry["logicalPath"] != DEPLOYMENT_ENV
        or entry["preimagePath"] != f"{ROLLBACK_SPEC_DIR}/{transaction_id}/deployment-env.bin"
        or entry["mode"] not in (0o400, 0o600)
        or isinstance(entry["sizeBytes"], bool)
        or not isinstance(entry["sizeBytes"], int)
        or entry["sizeBytes"] < 1
        or entry["sizeBytes"] > 1024 * 1024
        or not isinstance(entry["sha256"], str)
        or SHA256_RE.fullmatch(entry["sha256"]) is None
    ):
        stop("deployment config preimage binding is invalid.")
    data = secure_file(entry["preimagePath"], "deployment config preimage", 1024 * 1024, 0o600)
    if len(data) != entry["sizeBytes"] or digest(data) != entry["sha256"]:
        stop("deployment config preimage differs from its journal binding.")
    return entry


def atomic_live_environment(data: bytes, mode: int) -> None:
    parent = physical(DEPLOYMENT_REPO)
    pathname = physical(DEPLOYMENT_ENV)
    current, current_mode = stable_preimage_snapshot(
        DEPLOYMENT_ENV, "live deployment environment", SECRET_UID, SECRET_GID
    )
    if current == data and current_mode == mode:
        return
    fd, temporary = tempfile.mkstemp(prefix=".env.v1-local-private.", dir=parent)
    try:
        os.fchown(fd, SECRET_UID, SECRET_GID)
        os.fchmod(fd, mode)
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, pathname)
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        if os.path.exists(temporary):
            os.unlink(temporary)
    observed, observed_mode = stable_preimage_snapshot(
        DEPLOYMENT_ENV, "promoted live deployment environment", SECRET_UID, SECRET_GID
    )
    if observed != data or observed_mode != mode:
        stop("promoted live deployment environment changed during atomic replacement.")


def promote_live_environment() -> None:
    data = secure_file(RENDER_ENV, "exact render environment", 1024 * 1024, 0o400)
    _, values = parse_env(data, "exact render environment")
    if values.get("PLATFORM_COMPOSE_VARIANT") != "LOCAL_PRIVATE":
        stop("refusing to promote an environment without the unique LOCAL_PRIVATE variant.")
    atomic_live_environment(data, 0o600)


def restore_deployment_config_preimage(journal: Dict[str, object]) -> None:
    entry = validate_deployment_config_preimage(journal["deploymentConfigPreimage"], journal["transactionId"])
    data = secure_file(entry["preimagePath"], "deployment config preimage", 1024 * 1024, 0o600)
    atomic_live_environment(data, entry["mode"])


def journal_document(authority: Dict[str, object], authority_bytes: bytes, reconciliation: Dict[str, object]) -> Dict[str, object]:
    marker_bytes = secure_file(RECONCILIATION, "controller reconciliation marker", MAX_JSON, 0o600)
    transaction_id = digest(authority_bytes + marker_bytes)
    evidence_preimages = materialize_evidence_preimages(transaction_id)
    deployment_config_preimage = materialize_deployment_config_preimage(transaction_id)
    previous = predecessor_map(reconciliation)
    steps = []
    for name in ACTIVE_MANAGED:
        before = previous.get(name)
        if name == CANONICAL_ALERT_DISPATCHER and before is None:
            before = previous.get(LEGACY_ALERT_DISPATCHER)
        rollback_path, rollback_sha = materialize_rollback_spec(transaction_id, before)
        steps.append({
            "after": None,
            "backupName": f"v1-rollback-{transaction_id[:12]}-{before['name']}" if before is not None else None,
            "before": before,
            "containerName": name,
            "kind": "SERVICE",
            "restoredByRecreate": False,
            "rollbackSpecPath": rollback_path,
            "rollbackSpecSha256": rollback_sha,
            "service": ACTIVE_SERVICE_BY_CONTAINER[name],
            "status": "PENDING",
        })
    scheduler = previous.get("enterprise-backup-scheduler")
    if scheduler is not None:
        rollback_path, rollback_sha = materialize_rollback_spec(transaction_id, scheduler)
        steps.append({
            "after": None,
            "backupName": f"v1-rollback-{transaction_id[:12]}-enterprise-backup-scheduler",
            "before": scheduler,
            "containerName": "enterprise-backup-scheduler",
            "kind": "REMOVE",
            "restoredByRecreate": False,
            "rollbackSpecPath": rollback_path,
            "rollbackSpecSha256": rollback_sha,
            "service": scheduler["service"],
            "status": "PENDING",
        })
    for attachment in reconciliation["plannedLegacyNetworkAttachments"]:
        steps.append({
            "attachment": attachment,
            "kind": "NETWORK_ATTACH",
            "status": "PENDING",
        })
    return {
        "authorityDocumentId": authority["documentId"],
        "authoritySha256": digest(authority_bytes),
        "beganAtUnixSeconds": reconciliation["beganAtUnixSeconds"],
        "createdAtUnixSeconds": int(time.time()),
        "dataMutationEvidence": [],
        "dataMutationStatus": {item["id"]: "PENDING" for item in authority["authorizedDataMutations"]},
        "deploymentConfigPreimage": deployment_config_preimage,
        "evidencePreimages": evidence_preimages,
        "phase": "APPLYING",
        "reconciliationSha256": digest(marker_bytes),
        "schema": JOURNAL_SCHEMA,
        "steps": steps,
        "transactionId": transaction_id,
        "updatedAtUnixSeconds": int(time.time()),
    }


def save_journal(value: Dict[str, object]) -> None:
    value["updatedAtUnixSeconds"] = int(time.time())
    atomic_json(JOURNAL, value, 0o600)


def validate_journal(value: Dict[str, object], authority: Dict[str, object], authority_bytes: bytes, reconciliation: Dict[str, object]) -> Dict[str, object]:
    exact_keys(value, (
        "authorityDocumentId", "authoritySha256", "beganAtUnixSeconds", "createdAtUnixSeconds", "dataMutationEvidence",
        "dataMutationStatus", "deploymentConfigPreimage", "evidencePreimages", "phase", "reconciliationSha256", "schema", "steps", "transactionId", "updatedAtUnixSeconds",
    ), "reconciliation journal")
    marker_bytes = secure_file(RECONCILIATION, "controller reconciliation marker", MAX_JSON, 0o600)
    if (
        value["schema"] != JOURNAL_SCHEMA
        or value["authorityDocumentId"] != authority["documentId"]
        or value["authoritySha256"] != digest(authority_bytes)
        or value["reconciliationSha256"] != digest(marker_bytes)
        or value["beganAtUnixSeconds"] != reconciliation["beganAtUnixSeconds"]
        or value["transactionId"] != digest(authority_bytes + marker_bytes)
        or value["phase"] not in ("APPLYING", "APPLIED", "COMMITTING", "EVIDENCED", "ABORTING", "ABORTED")
        or not isinstance(value["steps"], list)
        or not isinstance(value["dataMutationEvidence"], list)
        or not isinstance(value["dataMutationStatus"], dict)
    ):
        stop("reconciliation journal binding/status is invalid.")
    validate_deployment_config_preimage(value["deploymentConfigPreimage"], value["transactionId"])
    validate_evidence_preimages(value["evidencePreimages"], value["transactionId"])
    expected_mutations = {item["id"] for item in authority["authorizedDataMutations"]}
    if set(value["dataMutationStatus"]) != expected_mutations or any(
        status not in ("PENDING", "RUNNING", "APPLIED", "SKIPPED_VERIFIED") for status in value["dataMutationStatus"].values()
    ):
        stop("reconciliation journal data-mutation state is invalid.")
    evidence_ids = []
    for raw in value["dataMutationEvidence"]:
        item = exact_keys(raw, ("authorityId", "evidencePath", "evidenceSha256"), "journal data-mutation evidence")
        if item["authorityId"] not in expected_mutations or not isinstance(item["evidencePath"], str) or SHA256_RE.fullmatch(str(item["evidenceSha256"])) is None:
            stop("reconciliation journal data-mutation evidence is invalid.")
        evidence_ids.append(item["authorityId"])
    if evidence_ids != sorted(set(evidence_ids)):
        stop("reconciliation journal data-mutation evidence is duplicated or unordered.")
    for authority_id, status in value["dataMutationStatus"].items():
        if (status == "APPLIED") != (authority_id in evidence_ids):
            stop("reconciliation journal mutation status/evidence truth differs.")
    for step in value["steps"]:
        if not isinstance(step, dict) or step.get("kind") not in ("SERVICE", "REMOVE", "NETWORK_ATTACH"):
            stop("reconciliation journal contains an invalid step kind.")
        if step["kind"] in ("SERVICE", "REMOVE"):
            before = step.get("before")
            if before is None:
                if step.get("rollbackSpecPath") is not None or step.get("rollbackSpecSha256") is not None:
                    stop("new-service journal step unexpectedly has rollback specification bytes.")
            elif step.get("status") not in ("PURGED", "ABORTED"):
                load_rollback_spec(step, value)
    return value


def read_or_create_journal(authority: Dict[str, object], authority_bytes: bytes, reconciliation: Dict[str, object]) -> Dict[str, object]:
    if os.path.lexists(physical(JOURNAL)):
        value = parse_json(secure_file(JOURNAL, "reconciliation journal", MAX_JSON, 0o600), "reconciliation journal", True)
        return validate_journal(value, authority, authority_bytes, reconciliation)
    value = journal_document(authority, authority_bytes, reconciliation)
    atomic_json(JOURNAL, value, 0o600, False)
    return validate_journal(value, authority, authority_bytes, reconciliation)


def read_secret(logical: str, label: str, minimum: int = 32) -> str:
    data = secure_secret_file(logical, label, 4096)
    try:
        value = data.decode("ascii", errors="strict").removesuffix("\n")
    except UnicodeDecodeError:
        stop(f"{label} is not ASCII.")
    if len(value) < minimum or len(value) > 1024 or "\n" in value or "\r" in value or "\x00" in value:
        stop(f"{label} has invalid length or delimiters.")
    return value


def ensure_token_secret(logical: str, label: str, minimum: int = 32) -> Tuple[str, bool]:
    if os.path.lexists(physical(logical)):
        return read_secret(logical, label, minimum), False
    value = secrets.token_urlsafe(32)
    if len(value) < minimum:
        stop(f"generated {label} is unexpectedly short.")
    atomic_secret_bytes(logical, (value + "\n").encode("ascii"), False)
    return read_secret(logical, label, minimum), True


def write_mutation_evidence(
    authority: Dict[str, object],
    reconciliation: Dict[str, object],
    authority_id: str,
    details: Dict[str, object],
) -> Dict[str, str]:
    allowed = {item["id"] for item in authority["authorizedDataMutations"]}
    if authority_id not in allowed:
        stop("attempted data mutation is outside exact release authority.")
    captured = max(int(time.time()), reconciliation["beganAtUnixSeconds"])
    document = {
        "authorityId": authority_id,
        "capturedAtUnixSeconds": captured,
        "detailsSha256": digest(canonical(details).encode()),
        "schema": MUTATION_EVIDENCE_SCHEMA,
        "status": "PASS",
    }
    data = canonical_bytes(document)
    evidence_sha = digest(data)
    logical = f"{MUTATION_EVIDENCE_DIR}/{authority['documentId']}-{authority_id}-{evidence_sha}.json"
    observed = preserve_json(logical, document, f"immutable {authority_id} mutation evidence")
    if digest(observed) != evidence_sha:
        stop("immutable data-mutation evidence digest changed.")
    return {"authorityId": authority_id, "evidencePath": logical, "evidenceSha256": evidence_sha}


def set_mutation_evidence(journal: Dict[str, object], entry: Dict[str, str]) -> None:
    current = [item for item in journal["dataMutationEvidence"] if item.get("authorityId") != entry["authorityId"]]
    current.append(entry)
    journal["dataMutationEvidence"] = sorted(current, key=lambda item: item["authorityId"])
    journal["dataMutationStatus"][entry["authorityId"]] = "APPLIED"
    save_journal(journal)


def mark_mutation_skipped(journal: Dict[str, object], authority_id: str) -> None:
    if journal["dataMutationStatus"].get(authority_id) != "PENDING":
        stop("only a never-started data mutation can be marked SKIPPED_VERIFIED.")
    if any(item.get("authorityId") == authority_id for item in journal["dataMutationEvidence"]):
        stop("a verified-skipped data mutation unexpectedly has mutation evidence.")
    journal["dataMutationStatus"][authority_id] = "SKIPPED_VERIFIED"
    save_journal(journal)


def postgres_command(database: str, sql: bytes, *, query: bool = False) -> bytes:
    args = [
        docker_binary(), "exec", "-i", "--user", "postgres", "enterprise-postgres",
        "psql", "--no-psqlrc", "--set", "ON_ERROR_STOP=1", "--dbname", database,
    ]
    if query:
        args.extend(["--tuples-only", "--no-align"])
    return run(args, f"PostgreSQL {database} bounded bootstrap", timeout=120, input_bytes=sql, sensitive=True)


DATABASE_VERIFICATION_SQL = b"""
SELECT CASE WHEN
  EXISTS (SELECT 1 FROM pg_roles WHERE rolname='control_center_runtime' AND rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication)
  AND EXISTS (SELECT 1 FROM pg_database WHERE datname='control_center' AND datdba=(SELECT oid FROM pg_roles WHERE rolname='control_center_runtime'))
  AND has_schema_privilege('control_center_runtime','control_auth','USAGE')
  AND to_regclass('control_auth.oidc_transactions') IS NOT NULL
  AND to_regclass('control_auth.sessions') IS NOT NULL
  AND to_regclass('control_auth.login_throttle') IS NOT NULL
  AND to_regclass('control_auth.provider_event_tokens') IS NOT NULL
  AND to_regclass('control_auth.provider_revocations') IS NOT NULL
  AND to_regclass('control_auth.first_configuration') IS NOT NULL
  AND to_regclass('control_auth.first_configuration_sessions') IS NOT NULL
  AND has_table_privilege('control_center_runtime','control_auth.oidc_transactions','SELECT,INSERT,UPDATE,DELETE')
  AND has_table_privilege('control_center_runtime','control_auth.sessions','SELECT,INSERT,UPDATE,DELETE')
  AND has_table_privilege('control_center_runtime','control_auth.login_throttle','SELECT,INSERT,UPDATE,DELETE')
  AND has_table_privilege('control_center_runtime','control_auth.provider_event_tokens','SELECT,INSERT,UPDATE,DELETE')
  AND has_table_privilege('control_center_runtime','control_auth.provider_revocations','SELECT,INSERT,UPDATE,DELETE')
  AND has_table_privilege('control_center_runtime','control_auth.first_configuration','SELECT,INSERT,UPDATE,DELETE')
  AND has_table_privilege('control_center_runtime','control_auth.first_configuration_sessions','SELECT,INSERT,UPDATE,DELETE')
THEN 'PASS' ELSE 'FAIL' END;
"""


def runtime_database_login_ready(password: str) -> bool:
    probe = (
        "IFS= read -r PGPASSWORD; export PGPASSWORD; "
        "exec psql --no-psqlrc --set ON_ERROR_STOP=1 --host 127.0.0.1 "
        "--username control_center_runtime --dbname control_center --tuples-only --no-align"
    )
    result = run_result(
        [docker_binary(), "exec", "-i", "enterprise-postgres", "sh", "-ec", probe],
        "Control Center runtime database login verification",
        timeout=60,
        input_bytes=(password + "\nSELECT CASE WHEN current_user='control_center_runtime' THEN 'PASS' ELSE 'FAIL' END;\n").encode("ascii"),
        sensitive=True,
    )
    return result.returncode == 0 and result.stdout.decode("utf-8", errors="replace").strip() == "PASS"


def database_prerequisites_ready(password: str) -> bool:
    result = run_result(
        [
            docker_binary(), "exec", "-i", "--user", "postgres", "enterprise-postgres",
            "psql", "--no-psqlrc", "--set", "ON_ERROR_STOP=1", "--dbname", "control_center",
            "--tuples-only", "--no-align",
        ],
        "PostgreSQL bounded prerequisite verification",
        timeout=60,
        input_bytes=DATABASE_VERIFICATION_SQL,
        sensitive=True,
    )
    return (
        result.returncode == 0
        and result.stdout.decode("utf-8", errors="replace").strip() == "PASS"
        and runtime_database_login_ready(password)
    )


def database_secret() -> Tuple[str, bool]:
    if os.path.lexists(physical(DATABASE_SECRET)):
        dsn = read_secret(DATABASE_SECRET, "Control Center database URL", 40)
        parsed = urllib.parse.urlsplit(dsn)
        if (
            parsed.scheme not in ("postgres", "postgresql") or parsed.username != "control_center_runtime"
            or parsed.hostname != "postgres" or parsed.port != 5432 or parsed.path != "/control_center"
            or not parsed.password
        ):
            stop("existing Control Center database URL has the wrong bounded runtime identity.")
        return urllib.parse.unquote(parsed.password), False
    password = secrets.token_urlsafe(36)
    encoded = urllib.parse.quote(password, safe="")
    dsn = f"postgresql://control_center_runtime:{encoded}@postgres:5432/control_center"
    atomic_secret_bytes(DATABASE_SECRET, (dsn + "\n").encode("ascii"), False)
    read_secret(DATABASE_SECRET, "Control Center database URL", 40)
    return password, True


def apply_database_prerequisites(
    authority: Dict[str, object], reconciliation: Dict[str, object], journal: Dict[str, object]
) -> None:
    secret_id = "control-center-database-runtime-secret"
    migration_id = "control-center-database-bootstrap"
    secret_status = journal["dataMutationStatus"][secret_id]
    if secret_status == "PENDING" and os.path.lexists(physical(DATABASE_SECRET)):
        password, _ = database_secret()
        mark_mutation_skipped(journal, secret_id)
    elif secret_status in ("PENDING", "RUNNING"):
        journal["dataMutationStatus"][secret_id] = "RUNNING"
        save_journal(journal)
        password, created = database_secret()
        entry = write_mutation_evidence(authority, reconciliation, secret_id, {
            "created": created,
            "database": "control_center",
            "host": "postgres",
            "role": "control_center_runtime",
            "secretPath": DATABASE_SECRET,
        })
        set_mutation_evidence(journal, entry)
    else:
        password, _ = database_secret()
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", password):
        stop("Control Center runtime password is not safely representable in bounded bootstrap SQL.")
    migration_status = journal["dataMutationStatus"][migration_id]
    if migration_status in ("APPLIED", "SKIPPED_VERIFIED"):
        if not database_prerequisites_ready(password):
            stop("verified Control Center database prerequisites later drifted.")
        return
    if migration_status == "PENDING" and database_prerequisites_ready(password):
        mark_mutation_skipped(journal, migration_id)
        return
    journal["dataMutationStatus"][migration_id] = "RUNNING"
    save_journal(journal)
    role_sql = f"""
\\set ON_ERROR_STOP on
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='control_center_runtime') THEN
    CREATE ROLE control_center_runtime LOGIN PASSWORD '{password}';
  ELSE
    ALTER ROLE control_center_runtime LOGIN PASSWORD '{password}';
  END IF;
END $$;
ALTER ROLE control_center_runtime NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
SELECT 'CREATE DATABASE control_center OWNER control_center_runtime'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname='control_center')\\gexec
ALTER DATABASE control_center OWNER TO control_center_runtime;
""".encode("ascii")
    postgres_command("postgres", role_sql)
    migration_hashes = []
    for number in ("001", "002", "003", "004"):
        pathname = release_file(authority["releaseRoot"], f"control-center/migrations/{number}_{'auth_sessions' if number == '001' else 'session_security' if number == '002' else 'oidc_provider_revocation' if number == '003' else 'first_configuration'}.sql")
        data = Path(pathname).read_bytes()
        if not data or len(data) > 1024 * 1024 or b"\x00" in data:
            stop(f"Control Center migration {number} bytes are invalid.")
        migration_hashes.append({"name": os.path.basename(pathname), "sha256": digest(data)})
        postgres_command("control_center", data)
    verified = postgres_command("control_center", DATABASE_VERIFICATION_SQL, query=True).decode("utf-8", errors="strict").strip()
    if verified != "PASS" or not runtime_database_login_ready(password):
        stop("Control Center database role/migration verification did not pass.")
    entry = write_mutation_evidence(authority, reconciliation, migration_id, {
        "database": "control_center",
        "migrations": migration_hashes,
        "role": "control_center_runtime",
        "verification": "PASS",
    })
    set_mutation_evidence(journal, entry)


def apply_bootstrap_token(authority: Dict[str, object], reconciliation: Dict[str, object], journal: Dict[str, object]) -> None:
    authority_id = "control-center-first-configuration-bootstrap-token"
    status = journal["dataMutationStatus"][authority_id]
    if status in ("APPLIED", "SKIPPED_VERIFIED"):
        read_secret(BOOTSTRAP_SECRET, "First Configuration bootstrap token", 43)
        return
    if status == "PENDING" and os.path.lexists(physical(BOOTSTRAP_SECRET)):
        read_secret(BOOTSTRAP_SECRET, "First Configuration bootstrap token", 43)
        mark_mutation_skipped(journal, authority_id)
        return
    journal["dataMutationStatus"][authority_id] = "RUNNING"
    save_journal(journal)
    _, created = ensure_token_secret(BOOTSTRAP_SECRET, "First Configuration bootstrap token", 43)
    entry = write_mutation_evidence(authority, reconciliation, authority_id, {
        "created": created,
        "recovery": "ROOT_OWNED_FIXED_SECRET_FILE",
        "secretPath": BOOTSTRAP_SECRET,
    })
    set_mutation_evidence(journal, entry)


def keycloak_environment(authority: Dict[str, object], action: str) -> Dict[str, str]:
    _, values = parse_env(secure_file(RENDER_ENV, "exact render environment", 1024 * 1024, 0o400), "exact render environment")
    domain = values.get("DOMAIN", "platform-infrastructure.com")
    auth_host = values.get("AUTH_HOST", f"auth.{domain}")
    portal_host = values.get("CONTROL_CENTER_HOST", values.get("ADMIN_HOST", f"portal.{domain}"))
    identity_origin = f"https://{auth_host}"
    public_origin = values.get("CONTROL_CENTER_PUBLIC_ORIGIN", f"https://{portal_host}")
    issuer = values.get("CONTROL_CENTER_OIDC_ISSUER", f"{identity_origin}/realms/platform")
    result = {
        "CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_ID": values.get("CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_ID", "platform-first-configuration"),
        "CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE": physical(KEYCLOAK_CLIENT_SECRET),
        "CONTROL_CENTER_OIDC_CLIENT_ID": values.get("CONTROL_CENTER_OIDC_CLIENT_ID", "platform-control-center"),
        "CONTROL_CENTER_OIDC_ISSUER": issuer,
        "CONTROL_CENTER_OIDC_REDIRECT_URI": values.get("CONTROL_CENTER_OIDC_REDIRECT_URI", f"{public_origin}/auth/callback"),
        "CONTROL_CENTER_OIDC_REQUIRED_ACR": values.get("CONTROL_CENTER_OIDC_REQUIRED_ACR", "urn:platform:loa:passkey"),
        "CONTROL_CENTER_OIDC_REQUIRED_AMR": values.get("CONTROL_CENTER_OIDC_REQUIRED_AMR", "webauthn"),
        "CONTROL_CENTER_PUBLIC_ORIGIN": public_origin,
        "KEYCLOAK_CONTAINER": "enterprise-keycloak",
        "KEYCLOAK_IDENTITY_ORIGIN": identity_origin,
        "KEYCLOAK_PASSKEY_EXPECT_BINDING": "staged",
        "KEYCLOAK_PASSKEY_RP_ID": auth_host,
        "KEYCLOAK_REALM": "platform",
    }
    if action == "apply-staged":
        result.update({
            "KEYCLOAK_PASSKEY_ACTION": "apply-staged",
            "KEYCLOAK_PASSKEY_CONFIRM": "RECONCILE-PLATFORM-PASSKEY-STAGED",
        })
    elif action == "readiness":
        result.update({
            "KEYCLOAK_PASSKEY_ACTION": "readiness",
            "KEYCLOAK_PASSKEY_READINESS_PHASE": "staged",
        })
    else:
        stop("internal Keycloak prerequisite action is outside the closed staged pair.")
    return result


def keycloak_staged_ready(authority: Dict[str, object]) -> bool:
    script = release_file(authority["releaseRoot"], "scripts/keycloak-passkey-reconcile.mjs")
    result = run_result(
        [node_binary(), script],
        "Keycloak staged passkey readiness",
        cwd=physical(authority["releaseRoot"]),
        environment=keycloak_environment(authority, "readiness"),
        timeout=300,
        sensitive=True,
    )
    if result.returncode != 0:
        return False
    output = result.stdout.decode("utf-8", errors="replace").strip()
    return "readiness_phase=staged" in output and "status=ready" in output


def apply_keycloak_prerequisite(
    authority: Dict[str, object], reconciliation: Dict[str, object], journal: Dict[str, object]
) -> None:
    authority_id = "control-center-first-configuration-keycloak-client"
    status = journal["dataMutationStatus"][authority_id]
    if status in ("APPLIED", "SKIPPED_VERIFIED"):
        read_secret(KEYCLOAK_CLIENT_SECRET, "First Configuration Keycloak client secret", 32)
        if not keycloak_staged_ready(authority):
            stop("verified Keycloak staged client later drifted.")
        return
    if status == "PENDING" and os.path.lexists(physical(KEYCLOAK_CLIENT_SECRET)):
        read_secret(KEYCLOAK_CLIENT_SECRET, "First Configuration Keycloak client secret", 32)
        if keycloak_staged_ready(authority):
            mark_mutation_skipped(journal, authority_id)
            return
    journal["dataMutationStatus"][authority_id] = "RUNNING"
    save_journal(journal)
    _, created = ensure_token_secret(KEYCLOAK_CLIENT_SECRET, "First Configuration Keycloak client secret", 32)
    script = release_file(authority["releaseRoot"], "scripts/keycloak-passkey-reconcile.mjs")
    output = run([node_binary(), script], "Keycloak staged passkey reconciliation", cwd=physical(authority["releaseRoot"]), environment=keycloak_environment(authority, "apply-staged"), timeout=300, sensitive=True)
    safe_output = output.decode("utf-8", errors="strict").strip()
    if "action=apply-staged" not in safe_output or "status=ready" not in safe_output:
        stop("Keycloak staged passkey reconciliation did not return the exact ready result.")
    if not keycloak_staged_ready(authority):
        stop("Keycloak staged client did not pass post-apply readiness.")
    entry = write_mutation_evidence(authority, reconciliation, authority_id, {
        "clientId": "platform-first-configuration",
        "createdSecret": created,
        "realm": "platform",
        "stagedBrowserFlow": "browser",
        "verification": "PASS",
    })
    set_mutation_evidence(journal, entry)


def apply_data_prerequisites(
    authority: Dict[str, object], reconciliation: Dict[str, object], journal: Dict[str, object]
) -> None:
    apply_database_prerequisites(authority, reconciliation, journal)
    apply_bootstrap_token(authority, reconciliation, journal)
    apply_keycloak_prerequisite(authority, reconciliation, journal)


def backup_matches(actual: Dict[str, object], expected: Dict[str, object]) -> bool:
    return all(actual.get(key) == expected.get(key) for key in (
        "configHash", "containerId", "imageId", "imageReference", "project",
        "runtimeConfigSha256", "semanticSha256", "service",
    ))


def target_semantics(name: str, target: Dict[str, object], raw: Dict[str, object], identity: Dict[str, object]) -> bool:
    if (
        identity["name"] != name or identity["project"] != target["project"]
        or identity["service"] != target["service"] or identity["configHash"] != target["configHash"]
    ):
        return False
    return inspect_service_semantics(raw, name) == target["semantic"]


def wait_for_target(name: str, target: Dict[str, object], timeout: int = 240) -> Dict[str, object]:
    deadline = time.monotonic() + timeout
    last = "missing"
    while time.monotonic() < deadline:
        inspected = inspect_one(name, missing_ok=True)
        if inspected is None:
            last = "missing"
            time.sleep(1)
            continue
        raw, identity = inspected
        if not target_semantics(name, target, raw, identity):
            stop(f"refreshed service {name} differs semantically from exact release authority.")
        if name == BROKER_AUTH_BOOTSTRAP:
            if identity["state"] == "exited" and identity["exitCode"] == 0 and identity["health"] == "none":
                return identity
            last = f"{identity['state']}/{identity['exitCode']}"
        else:
            expected_health = "none" if target["semantic"]["healthcheck"] is None else "healthy"
            if identity["state"] == "running" and identity["health"] == expected_health:
                return identity
            last = f"{identity['state']}/{identity['health']}"
        time.sleep(2)
    stop(f"refreshed service {name} did not reach its exact healthy/completed state ({last}).")


def revalidate_render_before_mutation(authority: Dict[str, object]) -> None:
    env_bytes = secure_file(RENDER_ENV, "exact render environment", 1024 * 1024, 0o400)
    observed = render_with_wrapper(authority["releaseRoot"], digest(env_bytes))
    fixed = secure_file(RENDER, "exact release render", MAX_JSON, 0o444)
    if observed != fixed or digest(observed) != authority["renderSha256"]:
        stop("release wrapper render changed immediately before one-service mutation.")


def compose_refresh(authority: Dict[str, object], service: str) -> None:
    if service in DISABLED_SERVICES or service not in MANAGED_CONTAINER_BY_SERVICE:
        stop("one-service refresh requested an undeclared or disabled service.")
    revalidate_render_before_mutation(authority)
    command = [
        docker_binary(), "compose",
        "--project-name", "platform_infra_vps",
        "--project-directory", physical(authority["releaseRoot"]),
        "--file", physical(RENDER),
        "up", "--detach", "--no-deps", "--no-build", "--pull", "never", "--force-recreate",
        service,
    ]
    run(command, f"serial one-service Compose refresh {service}", timeout=300)


def backup_source(step: Dict[str, object], journal: Dict[str, object]) -> None:
    before = step.get("before")
    if not isinstance(before, dict):
        return
    source_name, backup_name = before["name"], step["backupName"]
    status = step["status"]
    source = inspect_one(source_name, missing_ok=True)
    backup = inspect_one(backup_name, missing_ok=True)
    if status == "RENAMING":
        if backup is not None and backup_matches(backup[1], before) and source is None:
            step["status"] = "RENAMED"
            save_journal(journal)
            status = "RENAMED"
        elif source is not None and identity_matches_predecessor(source[1], before) and backup is None:
            step["status"] = "PENDING"
            save_journal(journal)
            status = "PENDING"
        else:
            stop(f"cannot resolve interrupted container rename for {source_name}.")
    if status == "PENDING":
        if source is None or not identity_matches_predecessor(source[1], before) or backup is not None:
            stop(f"predecessor {source_name} drifted before reversible refresh.")
        step["status"] = "RENAMING"
        save_journal(journal)
        run([docker_binary(), "rename", source_name, backup_name], f"rename predecessor {source_name}", timeout=30)
        backup = inspect_one(backup_name)
        if not backup_matches(backup[1], before) or inspect_one(source_name, missing_ok=True) is not None:
            stop(f"predecessor {source_name} rename did not verify.")
        step["status"] = "RENAMED"
        save_journal(journal)
        status = "RENAMED"
    if status in ("RENAMED", "STOPPING"):
        backup = inspect_one(backup_name)
        if not backup_matches(backup[1], before):
            stop(f"renamed predecessor {source_name} identity drifted.")
        if backup[1]["state"] == "running":
            step["status"] = "STOPPING"
            save_journal(journal)
            run([docker_binary(), "stop", "--time", "30", backup_name], f"stop predecessor {source_name}", timeout=60)
        stopped = inspect_one(backup_name)
        if not backup_matches(stopped[1], before) or stopped[1]["state"] == "running":
            stop(f"predecessor backup {source_name} did not stop exactly.")
        step["status"] = "BACKED_UP"
        save_journal(journal)


def apply_service_step(
    step: Dict[str, object], target: Dict[str, object], authority: Dict[str, object], journal: Dict[str, object]
) -> None:
    name = step["containerName"]
    before = step.get("before")
    if step["status"] in ("RETAINED", "APPLIED", "PURGING", "PURGED"):
        current = wait_for_target(name, target)
        if step["status"] == "RETAINED" and (before is None or current != before):
            stop(f"retained service {name} no longer equals its predecessor identity.")
        step["after"] = current
        save_journal(journal)
        return
    current = inspect_one(name, missing_ok=True)
    if step["status"] == "PENDING" and before is not None and before["name"] == name and current is not None:
        if identity_matches_predecessor(current[1], before) and target_semantics(name, target, current[0], current[1]):
            step["after"] = current[1]
            step["status"] = "RETAINED"
            save_journal(journal)
            return
    if before is not None:
        backup_source(step, journal)
    elif step["status"] == "PENDING" and current is not None:
        stop(f"new service {name} unexpectedly exists outside predecessor evidence.")
    if step["status"] == "REFRESHING":
        current = inspect_one(name, missing_ok=True)
        if current is not None and target_semantics(name, target, current[0], current[1]):
            step["after"] = wait_for_target(name, target)
            step["status"] = "APPLIED"
            save_journal(journal)
            return
        if current is not None:
            stop(f"interrupted service refresh left non-authorized target {name}.")
    if step["status"] not in ("PENDING", "BACKED_UP", "REFRESHING"):
        stop(f"service step {name} has an invalid resume state {step['status']}.")
    step["status"] = "REFRESHING"
    save_journal(journal)
    compose_refresh(authority, step["service"])
    step["after"] = wait_for_target(name, target)
    step["status"] = "APPLIED"
    save_journal(journal)


def apply_remove_step(step: Dict[str, object], journal: Dict[str, object]) -> None:
    if step["status"] in ("BACKED_UP", "PURGING", "PURGED"):
        if step["status"] != "PURGED":
            backup = inspect_one(step["backupName"], missing_ok=True)
            if backup is None or not backup_matches(backup[1], step["before"]) or backup[1]["state"] == "running":
                stop("quarantined legacy scheduler backup identity drifted.")
        if inspect_one(step["containerName"], missing_ok=True) is not None:
            stop("legacy scheduler canonical name still exists after quarantine.")
        return
    backup_source(step, journal)
    if step["status"] != "BACKED_UP" or inspect_one(step["containerName"], missing_ok=True) is not None:
        stop("legacy scheduler was not reversibly quarantined.")


def expected_membership(before: Dict[str, object], attachments: List[Dict[str, object]]) -> List[Dict[str, object]]:
    membership = before.get("networkMembership")
    if not isinstance(membership, list):
        stop("predecessor network membership is invalid.")
    by_name = {item["networkName"]: dict(item) for item in membership if isinstance(item, dict)}
    if len(by_name) != len(membership):
        stop("predecessor network membership is duplicated.")
    for attachment in attachments:
        existing = by_name.get(attachment["networkName"])
        desired = {"aliases": attachment["aliases"], "networkName": attachment["networkName"]}
        if existing is not None and existing != desired:
            stop("existing legacy network aliases conflict with exact authority.")
        by_name[attachment["networkName"]] = desired
    return sorted(by_name.values(), key=lambda item: item["networkName"])


def apply_network_step(step: Dict[str, object], journal: Dict[str, object]) -> None:
    attachment = step["attachment"]
    current = inspect_one(attachment["containerName"])
    memberships = current[1]["networkMembership"]
    desired = {"aliases": attachment["aliases"], "networkName": attachment["networkName"]}
    present = next((item for item in memberships if item["networkName"] == attachment["networkName"]), None)
    if step["status"] == "CONNECTING":
        if present == desired:
            step["status"] = "CONNECTED"
            save_journal(journal)
            return
        if present is not None:
            stop("interrupted legacy network connect has conflicting aliases.")
        step["status"] = "PENDING"
        save_journal(journal)
    if step["status"] == "CONNECTED":
        if present != desired:
            stop("connected legacy network attachment drifted.")
        return
    if step["status"] != "PENDING" or present is not None:
        stop("legacy network attachment has an invalid pre-state.")
    step["status"] = "CONNECTING"
    save_journal(journal)
    command = [docker_binary(), "network", "connect"]
    for alias in attachment["aliases"]:
        command.extend(["--alias", alias])
    command.extend([attachment["networkName"], attachment["containerName"]])
    run(command, f"attach preserved legacy {attachment['containerName']} to {attachment['networkName']}", timeout=30)
    after = inspect_one(attachment["containerName"])[1]["networkMembership"]
    if next((item for item in after if item["networkName"] == attachment["networkName"]), None) != desired:
        stop("legacy network attachment did not verify exactly.")
    step["status"] = "CONNECTED"
    save_journal(journal)


def ensure_exact_attachment_networks(authority: Dict[str, object]) -> None:
    render = parse_json(secure_file(RENDER, "exact release render", MAX_JSON, 0o444), "exact release render", True)
    definitions = render.get("networks")
    if not isinstance(definitions, dict):
        stop("exact release render has no network definitions.")
    by_physical: Dict[str, Tuple[str, Dict[str, object]]] = {}
    for key, raw in definitions.items():
        if not isinstance(key, str) or raw is None:
            raw = {}
        if not isinstance(raw, dict):
            stop("exact release network definition is invalid.")
        name = resource_name(definitions, key, "platform_infra_vps", "exact release network")
        if name in by_physical:
            stop("exact release network resource names are duplicated.")
        by_physical[name] = (key, raw)
    needed = sorted({item["networkName"] for item in authority["legacyNetworkAttachments"]})
    for name in needed:
        binding = by_physical.get(name)
        if binding is None:
            stop("legacy attachment references a network outside the exact render.")
        key, definition = binding
        result = run_result([docker_binary(), "network", "inspect", name], f"inspect exact network {name}", timeout=30)
        if result.returncode != 0:
            if definition.get("external") is True:
                stop(f"exact external network {name} is missing.")
            command = [docker_binary(), "network", "create"]
            driver = definition.get("driver", "bridge")
            if not isinstance(driver, str) or not driver:
                stop("exact release network driver is invalid.")
            command.extend(["--driver", driver])
            if definition.get("internal") is True:
                command.append("--internal")
            if definition.get("attachable") is True:
                command.append("--attachable")
            if definition.get("enable_ipv6") is True:
                command.append("--ipv6")
            options = definition.get("driver_opts") or {}
            labels = definition.get("labels") or {}
            if not isinstance(options, dict) or not isinstance(labels, dict):
                stop("exact release network options/labels are invalid.")
            for option, value in sorted(options.items()):
                command.extend(["--opt", f"{option}={value}"])
            for label, value in sorted(labels.items()):
                command.extend(["--label", f"{label}={value}"])
            command.extend([
                "--label", f"com.docker.compose.network={key}",
                "--label", "com.docker.compose.project=platform_infra_vps",
                name,
            ])
            run(command, f"create exact network {name}", timeout=30)
            result = run_result([docker_binary(), "network", "inspect", name], f"reinspect exact network {name}", timeout=30)
        if result.returncode != 0:
            stop(f"exact network {name} is unavailable after bounded reconciliation.")
        try:
            objects = json.loads(result.stdout.decode("utf-8", errors="strict"), object_pairs_hook=duplicate_safe)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            stop(f"exact network {name} inspection is invalid: {error}.")
        if not isinstance(objects, list) or len(objects) != 1 or not isinstance(objects[0], dict):
            stop(f"exact network {name} inspection has wrong cardinality.")
        observed = objects[0]
        labels = observed.get("Labels") or {}
        expected_labels = definition.get("labels") or {}
        if (
            observed.get("Name") != name
            or observed.get("Driver") != definition.get("driver", "bridge")
            or observed.get("Internal") is not (definition.get("internal") is True)
            or observed.get("Attachable") is not (definition.get("attachable") is True)
            or observed.get("EnableIPv6") is not (definition.get("enable_ipv6") is True)
            or not isinstance(labels, dict)
            or any(str(labels.get(label)) != str(value) for label, value in expected_labels.items())
        ):
            stop(f"existing exact network {name} differs from the authority-bound render.")


def validate_preserved_legacy(
    reconciliation: Dict[str, object], authority: Dict[str, object], *, require_all_attachments: bool
) -> None:
    previous = predecessor_map(reconciliation)
    by_container: Dict[str, List[Dict[str, object]]] = {}
    for attachment in authority["legacyNetworkAttachments"]:
        by_container.setdefault(attachment["containerName"], []).append(attachment)
    for name in PRESERVED_LEGACY:
        before = previous.get(name)
        if before is None:
            stop(f"preserved legacy container {name} is absent from predecessor evidence.")
        current = inspect_one(name)
        if not identity_matches_predecessor(current[1], before):
            stop(f"preserved legacy container {name} non-network identity changed.")
        baseline = before.get("networkMembership")
        if not isinstance(baseline, list) or not any(item.get("networkName") == "enterprise_net" for item in baseline if isinstance(item, dict)):
            stop(f"preserved legacy container {name} did not retain enterprise_net in predecessor evidence.")
        if require_all_attachments:
            expected = expected_membership(before, by_container.get(name, []))
            if current[1]["networkMembership"] != expected:
                stop(f"preserved legacy container {name} final networks differ from baseline plus exact authority.")


def validate_apply_target(
    authority: Dict[str, object], reconciliation: Dict[str, object], journal: Dict[str, object], targets: Dict[str, Dict[str, object]]
) -> None:
    identities, _ = inventory()
    backup_names = {step.get("backupName") for step in journal["steps"] if step.get("backupName") and step["status"] != "PURGED"}
    visible = [item for item in identities if item["name"] not in backup_names]
    if [item["name"] for item in visible] != list(CANONICAL_CONTAINERS):
        stop("serial reconciliation visible runtime is not the closed canonical 36-container target.")
    for name, target in targets.items():
        wait_for_target(name, target)
    validate_preserved_legacy(reconciliation, authority, require_all_attachments=True)


def apply() -> Dict[str, object]:
    # This is deliberately before journal creation and every Docker/data
    # mutation.  A controller crash after writing its reconciliation marker
    # but before disabling the supervisor must remain a no-op here.
    require_maintenance_ready()
    authority, authority_bytes = read_authority()
    targets = validate_authority_material(authority)
    reconciliation = read_reconciliation(authority, authority_bytes)
    validate_pre_mutation_checkpoint(authority, authority_bytes, reconciliation)
    # Live ownership/mode narrowing and .env promotion are maintenance-only;
    # prepare remains strictly staging/state materialization.
    configure_secret_anchor()
    journal = read_or_create_journal(authority, authority_bytes, reconciliation)
    promote_live_environment()
    if journal["phase"] in ("EVIDENCED", "ABORTING", "ABORTED", "COMMITTING"):
        stop(f"apply cannot continue transaction phase {journal['phase']}.")
    if journal["phase"] == "APPLIED":
        validate_apply_target(authority, reconciliation, journal, targets)
        return {"authorityDocumentId": authority["documentId"], "status": "APPLIED", "transactionId": journal["transactionId"]}
    ensure_exact_attachment_networks(authority)
    for step in journal["steps"]:
        if step.get("kind") == "NETWORK_ATTACH":
            apply_network_step(step, journal)
    apply_data_prerequisites(authority, reconciliation, journal)
    service_steps = {step["containerName"]: step for step in journal["steps"] if step.get("kind") == "SERVICE"}
    if set(service_steps) != set(SERVICE_REFRESH_ORDER):
        stop("reconciliation journal services differ from the fixed dependency refresh order.")
    for name in SERVICE_REFRESH_ORDER:
        step = service_steps[name]
        apply_service_step(step, targets[step["containerName"]], authority, journal)
    for step in journal["steps"]:
        if step.get("kind") == "REMOVE":
            apply_remove_step(step, journal)
    if any(value not in ("APPLIED", "SKIPPED_VERIFIED") for value in journal["dataMutationStatus"].values()):
        stop("not every exact-authority data prerequisite was applied or verified already correct.")
    validate_apply_target(authority, reconciliation, journal, targets)
    journal["phase"] = "APPLIED"
    save_journal(journal)
    return {"authorityDocumentId": authority["documentId"], "status": "APPLIED", "transactionId": journal["transactionId"]}


class DockerUnixConnection(http.client.HTTPConnection):
    def __init__(self) -> None:
        super().__init__("localhost", timeout=60)

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(DOCKER_SOCKET)


def docker_engine_request(method: str, endpoint: str, body: Optional[Dict[str, object]] = None) -> Dict[str, object]:
    if TEST_ROOT is not None:
        stop("raw Docker Engine recreation is unavailable outside the isolated live rollback path.")
    payload = canonical(body).encode("utf-8") if body is not None else None
    connection = DockerUnixConnection()
    try:
        connection.request(
            method,
            endpoint,
            body=payload,
            headers={"Content-Type": "application/json", "Content-Length": str(len(payload or b""))},
        )
        response = connection.getresponse()
        data = response.read(MAX_JSON + 1)
    except (OSError, http.client.HTTPException) as error:
        stop(f"fixed Docker Engine rollback request failed without exposing its private payload: {error}.")
    finally:
        connection.close()
    if len(data) > MAX_JSON:
        stop("fixed Docker Engine rollback response exceeded its boundary.")
    if response.status < 200 or response.status >= 300:
        stop(f"fixed Docker Engine rollback request was rejected with status {response.status}; response was suppressed.")
    if not data:
        return {}
    return parse_json(data, "Docker Engine rollback response")


def rollback_create_payload(raw: Dict[str, object], before: Dict[str, object]) -> Tuple[Dict[str, object], str, List[Dict[str, object]]]:
    config = raw.get("Config")
    host = raw.get("HostConfig")
    network_settings = raw.get("NetworkSettings")
    networks = network_settings.get("Networks") if isinstance(network_settings, dict) else None
    if not isinstance(config, dict) or not isinstance(host, dict) or not isinstance(networks, dict) or not networks:
        stop("private rollback specification lacks Docker create configuration.")
    if config.get("Image") != before["imageReference"] or raw.get("Image") != before["imageId"]:
        stop("private rollback image binding differs from predecessor identity.")
    memberships = before.get("networkMembership")
    if not isinstance(memberships, list) or not memberships:
        stop("private rollback predecessor has no exact network membership.")
    membership_by_name = {item.get("networkName"): item for item in memberships if isinstance(item, dict)}
    if set(membership_by_name) != set(networks):
        stop("private rollback network membership differs from Docker inspect.")
    primary = host.get("NetworkMode")
    if primary not in networks:
        primary = sorted(networks)[0]
    primary_raw = networks[primary]
    if not isinstance(primary_raw, dict):
        stop("private rollback primary network endpoint is invalid.")
    endpoint = {
        "Aliases": membership_by_name[primary]["aliases"],
        "DriverOpts": primary_raw.get("DriverOpts"),
        "IPAMConfig": primary_raw.get("IPAMConfig"),
        "Links": primary_raw.get("Links"),
    }
    endpoint = {key: value for key, value in endpoint.items() if value not in (None, [], {})}
    create_host = copy.deepcopy(host)
    create_host["NetworkMode"] = primary
    create_config = copy.deepcopy(config)
    create_config["Image"] = before["imageReference"]
    create_config["HostConfig"] = create_host
    create_config["NetworkingConfig"] = {"EndpointsConfig": {primary: endpoint}}
    additional = []
    for name in sorted(networks):
        if name == primary:
            continue
        raw_endpoint = networks[name]
        if not isinstance(raw_endpoint, dict):
            stop("private rollback additional network endpoint is invalid.")
        ipam = raw_endpoint.get("IPAMConfig") or {}
        if not isinstance(ipam, dict):
            stop("private rollback additional network IPAM is invalid.")
        additional.append({
            **dict(membership_by_name[name]),
            "ipv4Address": ipam.get("IPv4Address") or "",
            "ipv6Address": ipam.get("IPv6Address") or "",
        })
    return create_config, primary, additional


def recreate_predecessor(step: Dict[str, object], journal: Dict[str, object]) -> None:
    spec = load_rollback_spec(step, journal)
    before = step["before"]
    if image_id_for(before["imageReference"]) != before["imageId"]:
        stop("rollback predecessor image reference no longer resolves to its exact local image ID.")
    payload, _, additional = rollback_create_payload(spec["containerInspect"], before)
    response = docker_engine_request(
        "POST",
        f"/containers/create?name={urllib.parse.quote(before['name'], safe='')}",
        payload,
    )
    identifier = response.get("Id")
    if not isinstance(identifier, str) or SHA256_RE.fullmatch(identifier) is None:
        stop("Docker Engine rollback recreation did not return one full container ID.")
    for membership in additional:
        command = [docker_binary(), "network", "connect"]
        if membership["ipv4Address"]:
            command.extend(["--ip", membership["ipv4Address"]])
        if membership["ipv6Address"]:
            command.extend(["--ip6", membership["ipv6Address"]])
        for alias in membership["aliases"]:
            command.extend(["--alias", alias])
        command.extend([membership["networkName"], before["name"]])
        run(command, f"restore predecessor network {membership['networkName']}", timeout=30, sensitive=True)
    # A recreated stopped/exited predecessor must execute once to recover its
    # exact terminal state; all managed one-shots in the V1 form are idempotent.
    run([docker_binary(), "start", before["name"]], f"restart recreated predecessor {before['name']}", timeout=60, sensitive=True)
    step["restoredByRecreate"] = True
    save_journal(journal)


def recreated_identity_matches(actual: Dict[str, object], expected: Dict[str, object]) -> bool:
    fields = (
        "configHash", "exitCode", "health", "imageId", "imageReference", "networkMembership",
        "project", "runtimeConfigSha256", "semanticSha256", "service", "state",
    )
    return actual.get("name") == expected.get("name") and all(actual.get(field) == expected.get(field) for field in fields)


def restore_predecessor_step(step: Dict[str, object], journal: Dict[str, object]) -> None:
    before = step.get("before")
    target_name = step.get("containerName")
    backup_name = step.get("backupName")
    if step.get("status") in ("PENDING", "RETAINED", "ABORTED"):
        if step.get("status") in ("PENDING", "RETAINED") and isinstance(before, dict):
            source = inspect_one(before["name"], missing_ok=True)
            if source is None or (
                not identity_matches_predecessor(source[1], before)
                and not recreated_identity_matches(source[1], before)
            ):
                stop(f"unmutated predecessor {before['name']} drifted during abort.")
        step["status"] = "ABORTED"
        save_journal(journal)
        return
    if step.get("status") in ("PURGING", "PURGED"):
        stop("abort cannot reverse a predecessor backup already committed by evidence.")
    step["status"] = "ABORTING"
    save_journal(journal)
    current = inspect_one(target_name, missing_ok=True)
    if current is not None and (before is None or current[1]["containerId"] != before["containerId"]):
        run([docker_binary(), "rm", "--force", target_name], f"remove target {target_name} during abort", timeout=60)
        if inspect_one(target_name, missing_ok=True) is not None:
            stop(f"target {target_name} remained after abort removal.")
    if before is not None:
        backup = inspect_one(backup_name, missing_ok=True)
        original = inspect_one(before["name"], missing_ok=True)
        if backup is None:
            if original is None:
                recreate_predecessor(step, journal)
                original = inspect_one(before["name"])
            elif not identity_matches_predecessor(original[1], before) and not recreated_identity_matches(original[1], before):
                stop(f"abort cannot locate or recreate exact predecessor {before['name']}.")
        else:
            if not backup_matches(backup[1], before) or original is not None:
                stop(f"abort predecessor backup {before['name']} has an ambiguous identity.")
            run([docker_binary(), "rename", backup_name, before["name"]], f"restore predecessor name {before['name']}", timeout=30)
            restored = inspect_one(before["name"])
            if not backup_matches(restored[1], before):
                stop(f"restored predecessor {before['name']} static identity differs.")
        restored = inspect_one(before["name"])
        if before["state"] == "running" and restored[1]["state"] != "running":
            run([docker_binary(), "start", before["name"]], f"restart predecessor {before['name']}", timeout=60)
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            restored = inspect_one(before["name"])
            if identity_matches_predecessor(restored[1], before) or recreated_identity_matches(restored[1], before):
                break
            if not backup_matches(restored[1], before) and not step.get("restoredByRecreate"):
                stop(f"restored predecessor {before['name']} configuration identity drifted.")
            time.sleep(2)
        else:
            stop(f"restored predecessor {before['name']} did not recover its prior runtime state.")
    step["status"] = "ABORTED"
    save_journal(journal)


def disconnect_network_step(step: Dict[str, object], journal: Dict[str, object]) -> None:
    if step.get("status") in ("PENDING", "ABORTED"):
        step["status"] = "ABORTED"
        save_journal(journal)
        return
    if step.get("status") not in ("CONNECTING", "CONNECTED", "DISCONNECTING"):
        stop("network step has an invalid abort state.")
    attachment = step["attachment"]
    current = inspect_one(attachment["containerName"])
    present = next((item for item in current[1]["networkMembership"] if item["networkName"] == attachment["networkName"]), None)
    desired = {"aliases": attachment["aliases"], "networkName": attachment["networkName"]}
    if present is not None and present != desired:
        stop("abort refuses to disconnect a network attachment with non-authorized aliases.")
    if present is not None:
        step["status"] = "DISCONNECTING"
        save_journal(journal)
        run(
            [docker_binary(), "network", "disconnect", attachment["networkName"], attachment["containerName"]],
            f"disconnect transaction-added network from {attachment['containerName']}",
            timeout=30,
        )
    after = inspect_one(attachment["containerName"])[1]["networkMembership"]
    if any(item["networkName"] == attachment["networkName"] for item in after):
        stop("transaction-added network remained after abort disconnect.")
    step["status"] = "ABORTED"
    save_journal(journal)


def validated_residual_mutations(journal: Dict[str, object]) -> List[Dict[str, str]]:
    if any(status == "RUNNING" for status in journal["dataMutationStatus"].values()):
        stop("abort cannot truthfully classify an interrupted data mutation; resume apply verification first.")
    residual = sorted(journal["dataMutationEvidence"], key=lambda item: item["authorityId"])
    for item in residual:
        data = secure_file(item["evidencePath"], f"residual mutation evidence {item['authorityId']}", MAX_JSON, 0o444)
        if digest(data) != item["evidenceSha256"]:
            stop("residual mutation evidence differs from its reconciliation journal binding.")
    return residual


def validate_abort_residual_entries(raw: object, authority: Dict[str, object]) -> List[Dict[str, str]]:
    if not isinstance(raw, list):
        stop("reconciliation abort record residual mutations are not one list.")
    allowed = {item["id"] for item in authority["authorizedDataMutations"]}
    result = []
    for index, item_raw in enumerate(raw):
        item = exact_keys(item_raw, ("authorityId", "evidencePath", "evidenceSha256"), f"abort residual mutation {index}")
        prefix = f"{MUTATION_EVIDENCE_DIR}/{authority['documentId']}-{item['authorityId']}-"
        if (
            item["authorityId"] not in allowed
            or not isinstance(item["evidencePath"], str)
            or not item["evidencePath"].startswith(prefix)
            or not item["evidencePath"].endswith(f"-{item['evidenceSha256']}.json")
            or not isinstance(item["evidenceSha256"], str)
            or SHA256_RE.fullmatch(item["evidenceSha256"]) is None
        ):
            stop("reconciliation abort record has an invalid residual mutation binding.")
        evidence = secure_file(item["evidencePath"], f"abort residual mutation {item['authorityId']}", MAX_JSON, 0o444)
        if digest(evidence) != item["evidenceSha256"]:
            stop("reconciliation abort residual mutation evidence bytes changed.")
        result.append(item)
    if result != sorted(result, key=lambda item: item["authorityId"]) or len({item["authorityId"] for item in result}) != len(result):
        stop("reconciliation abort residual mutations are not uniquely sorted.")
    return result


def materialize_abort_record(authority: Dict[str, object], authority_bytes: bytes, journal: Dict[str, object]) -> Tuple[Dict[str, object], bytes, str]:
    journal_bytes = secure_file(JOURNAL, "aborted reconciliation journal", MAX_JSON, 0o600)
    if os.path.lexists(physical(ABORT_RECORD)):
        return validate_abort_record(authority, authority_bytes, journal_bytes)
    residual = validated_residual_mutations(journal)
    record = {
        "authorityDocumentId": authority["documentId"],
        "authoritySha256": digest(authority_bytes),
        "completedAtUnixSeconds": int(time.time()),
        "journalSha256": digest(journal_bytes),
        "residualDataMutations": residual,
        "residualDataMutationsSha256": digest(canonical(residual).encode()),
        "schema": ABORT_RECORD_SCHEMA,
        "status": "ABORTED_WITH_RESIDUAL_DATA_MUTATIONS" if residual else "ABORTED_NO_DATA_MUTATION",
        "transactionId": journal["transactionId"],
    }
    data = canonical_bytes(record)
    record_sha = digest(data)
    archive = f"{ABORT_RECORD_ARCHIVE_DIR}/{journal['transactionId']}-{record_sha}.json"
    if os.path.lexists(physical(ABORT_RECORD)):
        current = secure_file(ABORT_RECORD, "current reconciliation abort record", MAX_JSON, 0o444)
        if current != data:
            stop("current reconciliation abort record differs from the immutable transaction result.")
    else:
        atomic_bytes(ABORT_RECORD, data, 0o444, False)
    if os.path.lexists(physical(archive)):
        archived = secure_file(archive, "immutable reconciliation abort record", MAX_JSON, 0o444)
        if archived != data:
            stop("archived reconciliation abort record differs from the fixed current record.")
    else:
        ensure_directory(ABORT_RECORD_ARCHIVE_DIR, 0o700)
        atomic_bytes(archive, data, 0o444, False)
    if secure_file(ABORT_RECORD, "current reconciliation abort record", MAX_JSON, 0o444) != secure_file(
        archive, "immutable reconciliation abort record", MAX_JSON, 0o444
    ):
        stop("current and immutable reconciliation abort record bytes differ.")
    return record, data, archive


def validate_abort_record(authority: Dict[str, object], authority_bytes: bytes, journal_bytes: bytes) -> Tuple[Dict[str, object], bytes, str]:
    data = secure_file(ABORT_RECORD, "current reconciliation abort record", MAX_JSON, 0o444)
    record = exact_keys(parse_json(data, "current reconciliation abort record", True), (
        "authorityDocumentId", "authoritySha256", "completedAtUnixSeconds", "journalSha256",
        "residualDataMutations", "residualDataMutationsSha256", "schema", "status", "transactionId",
    ), "current reconciliation abort record")
    journal_value = parse_json(journal_bytes, "aborted reconciliation journal binding", True)
    journal_began = journal_value.get("beganAtUnixSeconds")
    residual = validate_abort_residual_entries(record["residualDataMutations"], authority)
    if (
        record["schema"] != ABORT_RECORD_SCHEMA
        or record["authorityDocumentId"] != authority["documentId"]
        or record["authoritySha256"] != digest(authority_bytes)
        or record["journalSha256"] != digest(journal_bytes)
        or record["transactionId"] != journal_value.get("transactionId")
        or isinstance(record["completedAtUnixSeconds"], bool)
        or not isinstance(record["completedAtUnixSeconds"], int)
        or isinstance(journal_began, bool)
        or not isinstance(journal_began, int)
        or record["completedAtUnixSeconds"] < journal_began
        or record["completedAtUnixSeconds"] > int(time.time()) + 60
        or not isinstance(record["transactionId"], str)
        or SHA256_RE.fullmatch(record["transactionId"]) is None
        or record["residualDataMutationsSha256"] != digest(canonical(residual).encode())
        or record["status"] != ("ABORTED_WITH_RESIDUAL_DATA_MUTATIONS" if residual else "ABORTED_NO_DATA_MUTATION")
    ):
        stop("current reconciliation abort record is not authority/journal/mutation bound.")
    record_sha = digest(data)
    archive = f"{ABORT_RECORD_ARCHIVE_DIR}/{record['transactionId']}-{record_sha}.json"
    if secure_file(archive, "immutable reconciliation abort record", MAX_JSON, 0o444) != data:
        stop("immutable reconciliation abort record differs from current exact bytes.")
    return record, data, archive


def controller_verified_abort_binding(record: Dict[str, object], record_data: bytes, archive: str) -> Dict[str, object]:
    if PREVERIFIED_CONTROLLER_RECEIPT is None:
        stop("second abort requires one fixed controller verify before the shared transaction lock.")
    current = secure_file(ACTIVE_RECEIPT, "controller post-abort active receipt", MAX_AUTHORITY, 0o444)
    if current != PREVERIFIED_CONTROLLER_RECEIPT:
        stop("controller ACTIVE receipt changed between fixed verify and abort finalization.")
    receipt = parse_json(current, "controller post-abort active receipt", True)
    expected = {**record, "recordPath": archive, "recordSha256": digest(record_data)}
    if (
        receipt.get("schema") != "platform.v1-local-private-control-receipt/v1"
        or receipt.get("status") != "ACTIVE"
        or receipt.get("abortedAuthorizedReconciliation") != expected
    ):
        stop("controller ACTIVE receipt does not bind the exact consumed reconciliation abort record.")
    return receipt


def preverified_active_receipt() -> Dict[str, object]:
    if PREVERIFIED_CONTROLLER_RECEIPT is None:
        stop("transaction finalization requires one fixed controller verify before the shared lock.")
    current = secure_file(ACTIVE_RECEIPT, "controller post-transaction active receipt", MAX_AUTHORITY, 0o444)
    if current != PREVERIFIED_CONTROLLER_RECEIPT:
        stop("controller ACTIVE receipt changed between fixed verify and transaction finalization.")
    receipt = parse_json(current, "controller post-transaction active receipt", True)
    if receipt.get("schema") != "platform.v1-local-private-control-receipt/v1" or receipt.get("status") != "ACTIVE":
        stop("controller post-transaction receipt is not ACTIVE V1 LOCAL_PRIVATE.")
    return receipt


def archive_journal_bytes(journal: Dict[str, object], journal_bytes: bytes) -> str:
    journal_sha = digest(journal_bytes)
    archive = f"{JOURNAL_ARCHIVE_DIR}/{journal['transactionId']}-{journal_sha}.json"
    ensure_directory(JOURNAL_ARCHIVE_DIR, 0o700)
    if os.path.lexists(physical(archive)):
        if secure_file(archive, "immutable reconciliation journal", MAX_JSON, 0o444) != journal_bytes:
            stop("immutable reconciliation journal differs from current exact bytes.")
    else:
        atomic_bytes(archive, journal_bytes, 0o444, False)
    return archive


def cleanup_transaction_preimages(journal: Dict[str, object]) -> None:
    bound = [journal.get("deploymentConfigPreimage"), *(journal.get("evidencePreimages") or [])]
    for raw in bound:
        if not isinstance(raw, dict):
            stop("transaction preimage cleanup found an invalid journal binding.")
        logical = raw.get("preimagePath")
        expected_sha = raw.get("sha256")
        if not isinstance(logical, str) or not isinstance(expected_sha, str) or SHA256_RE.fullmatch(expected_sha) is None:
            stop("transaction preimage cleanup binding is invalid.")
        if os.path.lexists(physical(logical)):
            data = secure_file(logical, "transaction private preimage cleanup", MAX_JSON, 0o600)
            if digest(data) != expected_sha:
                stop("transaction private preimage changed before cleanup.")
            os.unlink(physical(logical))
    root = physical(f"{ROLLBACK_SPEC_DIR}/{journal['transactionId']}")
    for candidate in (os.path.join(root, "evidence-preimages"), root):
        try:
            os.rmdir(candidate)
        except FileNotFoundError:
            pass
        except OSError as error:
            if error.errno not in (39, 66):  # ENOTEMPTY on Linux/macOS
                stop(f"transaction private preimage directory cleanup failed: {error}.")


def finalize_evidenced_journal(authority: Dict[str, object], authority_bytes: bytes) -> Dict[str, object]:
    journal_bytes = secure_file(JOURNAL, "evidenced reconciliation journal", MAX_JSON, 0o600)
    journal = exact_keys(parse_json(journal_bytes, "evidenced reconciliation journal", True), (
        "authorityDocumentId", "authoritySha256", "beganAtUnixSeconds", "createdAtUnixSeconds", "dataMutationEvidence",
        "dataMutationStatus", "deploymentConfigPreimage", "evidencePreimages", "phase", "reconciliationSha256", "schema", "steps", "transactionId", "updatedAtUnixSeconds",
    ), "evidenced reconciliation journal")
    if (
        journal["schema"] != JOURNAL_SCHEMA
        or journal["phase"] != "EVIDENCED"
        or journal["authorityDocumentId"] != authority["documentId"]
        or journal["authoritySha256"] != digest(authority_bytes)
    ):
        stop("only one authority-bound EVIDENCED journal can be finalized after seal.")
    receipt = preverified_active_receipt()
    external = receipt.get("externalAuthorizedReconciliation")
    runtime_data = secure_file(RUNTIME_EVIDENCE, "sealed runtime reconciliation evidence", MAX_JSON, 0o444)
    checkpoint_data = secure_file(LOCAL_CHECKPOINT, "sealed LOCAL_PRIVATE checkpoint", MAX_AUTHORITY)
    if (
        not isinstance(external, dict)
        or external.get("status") != "SEALED"
        or external.get("releaseAuthorityDocumentId") != authority["documentId"]
        or external.get("releaseAuthoritySha256") != digest(authority_bytes)
        or external.get("runtimeEvidenceSha256") != digest(runtime_data)
        or external.get("dataMutations") != journal["dataMutationEvidence"]
        or receipt.get("checkpointSha256") != digest(checkpoint_data)
    ):
        stop("controller ACTIVE receipt does not bind this exact evidenced reconciliation/checkpoint.")
    archive = archive_journal_bytes(journal, journal_bytes)
    cleanup_transaction_preimages(journal)
    if secure_file(JOURNAL, "evidenced reconciliation journal", MAX_JSON, 0o600) != journal_bytes:
        stop("evidenced reconciliation journal changed before final removal.")
    os.unlink(physical(JOURNAL))
    return {
        "authorityDocumentId": authority["documentId"],
        "journalArchivePath": archive,
        "status": "EVIDENCED_FINALIZED",
        "transactionId": journal["transactionId"],
    }


def preverify_consumed_abort_before_shared_lock(operation: str) -> None:
    global PREVERIFIED_CONTROLLER_RECEIPT
    if operation not in ("abort", "prepare") or os.path.lexists(physical(RECONCILIATION)):
        return
    if operation == "prepare" and not os.path.lexists(physical(ABORT_RECORD)) and not os.path.lexists(physical(JOURNAL)):
        return
    if operation == "abort" and not os.path.lexists(physical(JOURNAL)) and not os.path.lexists(physical(ABORT_RECORD)):
        return
    output = run([CONTROLLER, "verify"], "controller post-abort verification", timeout=120, max_output=MAX_AUTHORITY)
    # Controller stdout must itself be the canonical ACTIVE receipt that it
    # wrote; after the shared lock is acquired finalization reopens and compares
    # the fixed file byte-for-byte before removing any current transaction file.
    parse_json(output, "preverified controller post-abort receipt", True)
    PREVERIFIED_CONTROLLER_RECEIPT = output


def finalize_consumed_abort(authority: Dict[str, object], authority_bytes: bytes) -> Dict[str, object]:
    journal_bytes = secure_file(JOURNAL, "aborted reconciliation journal", MAX_JSON, 0o600)
    journal = exact_keys(parse_json(journal_bytes, "aborted reconciliation journal", True), (
        "authorityDocumentId", "authoritySha256", "beganAtUnixSeconds", "createdAtUnixSeconds", "dataMutationEvidence",
        "dataMutationStatus", "deploymentConfigPreimage", "evidencePreimages", "phase", "reconciliationSha256", "schema", "steps", "transactionId", "updatedAtUnixSeconds",
    ), "aborted reconciliation journal")
    if (
        journal["schema"] != JOURNAL_SCHEMA
        or journal["phase"] != "ABORTED"
        or journal["authorityDocumentId"] != authority["documentId"]
        or journal["authoritySha256"] != digest(authority_bytes)
        or not isinstance(journal["transactionId"], str)
        or SHA256_RE.fullmatch(journal["transactionId"]) is None
    ):
        stop("only one authority-bound ABORTED journal can be finalized.")
    record, record_data, record_archive = validate_abort_record(authority, authority_bytes, journal_bytes)
    if record["transactionId"] != journal["transactionId"]:
        stop("controller abort record transaction differs from the current journal.")
    controller_verified_abort_binding(record, record_data, record_archive)
    journal_sha = digest(journal_bytes)
    journal_archive = f"{JOURNAL_ARCHIVE_DIR}/{journal['transactionId']}-{journal_sha}.json"
    ensure_directory(JOURNAL_ARCHIVE_DIR, 0o700)
    if os.path.lexists(physical(journal_archive)):
        if secure_file(journal_archive, "immutable aborted reconciliation journal", MAX_JSON, 0o444) != journal_bytes:
            stop("immutable aborted journal differs from current exact bytes.")
    else:
        atomic_bytes(journal_archive, journal_bytes, 0o444, False)
    # Current journal is the retry blocker and is removed only after controller
    # verify proved its exact abort record was consumed into ACTIVE state.
    if secure_file(JOURNAL, "aborted reconciliation journal", MAX_JSON, 0o600) != journal_bytes:
        stop("aborted reconciliation journal changed before finalization.")
    os.unlink(physical(JOURNAL))
    if os.path.lexists(physical(ABORT_RECORD)):
        if secure_file(ABORT_RECORD, "consumed current abort record", MAX_JSON, 0o444) != record_data:
            stop("current abort record changed before cleanup.")
        os.unlink(physical(ABORT_RECORD))
    return {
        "authorityDocumentId": authority["documentId"],
        "journalArchivePath": journal_archive,
        "recordArchivePath": record_archive,
        "status": "ABORT_FINALIZED",
        "transactionId": journal["transactionId"],
    }


def cleanup_consumed_abort_without_current_journal(authority: Dict[str, object], authority_bytes: bytes) -> Dict[str, object]:
    record_data = secure_file(ABORT_RECORD, "orphaned consumed abort record", MAX_JSON, 0o444)
    record = exact_keys(parse_json(record_data, "orphaned consumed abort record", True), (
        "authorityDocumentId", "authoritySha256", "completedAtUnixSeconds", "journalSha256",
        "residualDataMutations", "residualDataMutationsSha256", "schema", "status", "transactionId",
    ), "orphaned consumed abort record")
    if (
        record["schema"] != ABORT_RECORD_SCHEMA
        or record["authorityDocumentId"] != authority["documentId"]
        or record["authoritySha256"] != digest(authority_bytes)
        or not isinstance(record["journalSha256"], str)
        or SHA256_RE.fullmatch(record["journalSha256"]) is None
        or not isinstance(record["transactionId"], str)
        or SHA256_RE.fullmatch(record["transactionId"]) is None
    ):
        stop("orphaned consumed abort record is not authority-bound.")
    journal_archive = f"{JOURNAL_ARCHIVE_DIR}/{record['transactionId']}-{record['journalSha256']}.json"
    archived_journal = secure_file(journal_archive, "immutable aborted reconciliation journal", MAX_JSON, 0o444)
    if digest(archived_journal) != record["journalSha256"]:
        stop("orphaned abort record differs from its immutable journal archive.")
    record_archive = f"{ABORT_RECORD_ARCHIVE_DIR}/{record['transactionId']}-{digest(record_data)}.json"
    if secure_file(record_archive, "immutable reconciliation abort record", MAX_JSON, 0o444) != record_data:
        stop("orphaned current abort record differs from its immutable archive.")
    controller_verified_abort_binding(record, record_data, record_archive)
    os.unlink(physical(ABORT_RECORD))
    return {
        "authorityDocumentId": authority["documentId"],
        "journalArchivePath": journal_archive,
        "recordArchivePath": record_archive,
        "status": "ABORT_FINALIZED",
        "transactionId": record["transactionId"],
    }


def abort() -> Dict[str, object]:
    """Undo reversible Docker/network steps before controller abort-maintenance.

    Authorized database/bootstrap/Keycloak prerequisites are additive and are
    intentionally not presented as a complete data rollback.  After this
    succeeds, the fixed operator sequence is controller ``abort-maintenance``
    followed by controller ``verify``.
    """
    authority, authority_bytes = read_authority(check_artifacts=False, check_source_archive=False)
    validate_authority_material(authority)
    marker_exists = os.path.lexists(physical(RECONCILIATION))
    journal_exists = os.path.lexists(physical(JOURNAL))
    if journal_exists and not marker_exists:
        return finalize_consumed_abort(authority, authority_bytes)
    if not journal_exists and os.path.lexists(physical(ABORT_RECORD)):
        return cleanup_consumed_abort_without_current_journal(authority, authority_bytes)
    if not marker_exists:
        return {"authorityDocumentId": authority["documentId"], "status": "ABORTED", "transactionId": None}
    strict_tooling = installed_artifacts_match_authority(authority) and installed_source_archive_matches_authority(authority)
    if not strict_tooling:
        # The open transaction belongs to a superseded exact release: a newer
        # sanctioned bootstrap transport is installed (proven by the receipt
        # chain below), so the transaction's begin-era tooling is gone and its
        # rollback plan cannot be executed.  Because apply provably never
        # started (every precondition fails closed), the honest closure is one
        # zero-step ABORTED journal plus its record; the fixed operator
        # sequence stays controller ``abort-maintenance`` then ``verify``.
        coherent_candidate = latest_transport_tooling_coherence()
        if coherent_candidate == authority["candidateCommit"]:
            stop("superseding-transport abort requires a different installed candidate.")
        authority_candidate_transport_complete(authority)
        reconciliation = read_reconciliation(authority, authority_bytes)
        verify_superseded_transport_abort_preconditions(authority, reconciliation)
        configure_secret_identity_readonly()
        journal = superseded_transport_abort_journal(authority, authority_bytes, reconciliation)
        record, data, archive = materialize_abort_record(authority, authority_bytes, journal)
        return {
            "abortRecordPath": archive,
            "abortRecordSha256": digest(data),
            "authorityDocumentId": authority["documentId"],
            "status": record["status"],
            "transactionId": journal["transactionId"],
        }
    reconciliation = read_reconciliation(authority, authority_bytes)
    configure_secret_identity_readonly()
    journal = read_or_create_journal(authority, authority_bytes, reconciliation)
    if journal["phase"] == "EVIDENCED" or journal["phase"] == "COMMITTING":
        stop("abort is closed after the evidence commit point; use receipt-bound recovery artifacts.")
    if journal["phase"] == "ABORTED":
        restore_deployment_config_preimage(journal)
        restore_evidence_preimages(journal)
        record, data, archive = materialize_abort_record(authority, authority_bytes, journal)
        return {
            "abortRecordPath": archive,
            "abortRecordSha256": digest(data),
            "authorityDocumentId": authority["documentId"],
            "status": record["status"],
            "transactionId": journal["transactionId"],
        }
    journal["phase"] = "ABORTING"
    save_journal(journal)
    for step in reversed(journal["steps"]):
        if step.get("kind") == "NETWORK_ATTACH":
            disconnect_network_step(step, journal)
        elif step.get("kind") in ("SERVICE", "REMOVE"):
            restore_predecessor_step(step, journal)
        else:
            stop("reconciliation journal contains an unknown step kind.")
    expected = predecessor_map(reconciliation)
    identities, _ = inventory()
    if {item["name"] for item in identities} != set(expected):
        stop("aborted Docker inventory does not equal the exact predecessor closed form.")
    current = {item["name"]: item for item in identities}
    recreated_names = {
        step["before"]["name"] for step in journal["steps"]
        if step.get("restoredByRecreate") is True and isinstance(step.get("before"), dict)
    }
    for name, before in expected.items():
        matched = recreated_identity_matches(current[name], before) if name in recreated_names else identity_matches_predecessor(current[name], before)
        if not matched:
            stop(f"aborted predecessor {name} does not equal frozen identity.")
    # Evidence refresh may already have atomically replaced any subset of the
    # five documents/checkpoint before it failed.  Restore the immutable
    # predecessor bytes and modes before controller abort-maintenance can
    # reopen the prior receipt.
    restore_deployment_config_preimage(journal)
    restore_evidence_preimages(journal)
    journal["phase"] = "ABORTED"
    save_journal(journal)
    record, data, archive = materialize_abort_record(authority, authority_bytes, journal)
    return {
        "abortRecordPath": archive,
        "abortRecordSha256": digest(data),
        "authorityDocumentId": authority["documentId"],
        "status": record["status"],
        "transactionId": journal["transactionId"],
    }


def purge_predecessor_backups(journal: Dict[str, object]) -> None:
    journal["phase"] = "COMMITTING"
    save_journal(journal)
    test_fault("AFTER_COMMITTING")
    for step in journal["steps"]:
        backup_name = step.get("backupName")
        if not backup_name:
            continue
        if step["status"] == "PURGED":
            if inspect_one(backup_name, missing_ok=True) is not None:
                stop("purged predecessor backup unexpectedly reappeared.")
            continue
        rollback_path = step.get("rollbackSpecPath")
        if step.get("kind") == "SERVICE" and inspect_one(backup_name, missing_ok=True) is None:
            if step["status"] not in ("RETAINED", "APPLIED", "PURGING"):
                stop("Compose-discovered predecessor vanished outside one completed/retained service refresh.")
            if isinstance(rollback_path, str) and os.path.lexists(physical(rollback_path)):
                load_rollback_spec(step, journal)
                os.unlink(physical(rollback_path))
            step["status"] = "PURGED"
            save_journal(journal)
            test_fault(f"AFTER_PURGE_{step['containerName']}")
            continue
        if step["status"] == "PURGING":
            backup = inspect_one(backup_name, missing_ok=True)
            if backup is None:
                step["status"] = "PURGED"
                save_journal(journal)
                test_fault(f"AFTER_PURGE_{step['containerName']}")
                continue
        if step["status"] not in ("APPLIED", "BACKED_UP", "PURGING"):
            stop("evidence commit found an incomplete predecessor backup step.")
        backup = inspect_one(backup_name, missing_ok=True)
        if backup is None or not backup_matches(backup[1], step["before"]):
            stop("predecessor backup identity drifted before evidence commit.")
        step["status"] = "PURGING"
        save_journal(journal)
        run([docker_binary(), "rm", "--force", backup_name], f"commit predecessor backup removal {backup_name}", timeout=60)
        if inspect_one(backup_name, missing_ok=True) is not None:
            stop("predecessor backup remained after evidence commit removal.")
        if isinstance(rollback_path, str) and os.path.lexists(physical(rollback_path)):
            load_rollback_spec(step, journal)
            os.unlink(physical(rollback_path))
        step["status"] = "PURGED"
        save_journal(journal)
        test_fault(f"AFTER_PURGE_{step['containerName']}")


def route_checks(authority: Dict[str, object], reconciliation: Dict[str, object]) -> List[Dict[str, object]]:
    _, env = parse_env(secure_file(RENDER_ENV, "exact render environment", 1024 * 1024, 0o400), "exact render environment")
    ca_source = env.get("CONTROL_CENTER_LOCAL_CA_CERT_SOURCE")
    if not ca_source:
        stop("exact environment omits the local CA source needed for route proof.")
    if not os.path.isabs(ca_source):
        ca_source = os.path.join(authority["releaseRoot"], ca_source.removeprefix("./"))
    ca_path = physical(ca_source) if TEST_ROOT and ca_source.startswith("/") else ca_source
    if TEST_ROOT is None:
        no_symlink_chain(ca_path, "local route-check CA")
    results = []
    for declared in authority["legacyRouteChecks"]:
        parsed = urllib.parse.urlsplit(declared["url"])
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            stop("fixed legacy edge route check is not one credential-free HTTPS URL.")
        port = parsed.port or 443
        output = run(
            [
                curl_binary(), "--silent", "--show-error", "--max-time", "20", "--connect-timeout", "5",
                "--cacert", ca_path, "--resolve", f"{parsed.hostname}:{port}:127.0.0.1",
                "--output", "-", "--write-out", "\n%{http_code}", declared["url"],
            ],
            f"legacy edge route check {declared['name']}",
            timeout=30,
        )
        body, separator, status_raw = output.rpartition(b"\n")
        if not separator or not re.fullmatch(rb"[0-9]{3}", status_raw):
            stop(f"legacy route check {declared['name']} returned malformed status evidence.")
        observed = int(status_raw)
        if observed != declared["expectedStatus"]:
            stop(f"legacy route check {declared['name']} returned {observed}, expected {declared['expectedStatus']}.")
        results.append({
            "checkedAtUnixSeconds": max(int(time.time()), reconciliation["beganAtUnixSeconds"]),
            "containerName": declared["containerName"],
            "expectedStatus": declared["expectedStatus"],
            "name": declared["name"],
            "observedStatus": observed,
            "responseSha256": digest(body),
            "status": "PASS",
            "url": declared["url"],
        })
    return sorted(results, key=lambda item: item["name"])


def legacy_network_evidence(
    authority: Dict[str, object], reconciliation: Dict[str, object], current: Dict[str, Dict[str, object]]
) -> Tuple[List[Dict[str, object]], List[Dict[str, object]]]:
    previous = predecessor_map(reconciliation)
    additions = []
    memberships = []
    by_container: Dict[str, List[Dict[str, object]]] = {}
    for attachment in authority["legacyNetworkAttachments"]:
        by_container.setdefault(attachment["containerName"], []).append(attachment)
    for name in PRESERVED_LEGACY:
        before = previous[name]
        after = current[name]
        expected = expected_membership(before, by_container.get(name, []))
        if after["networkMembership"] != expected:
            stop(f"legacy network evidence for {name} differs from exact baseline plus additions.")
        baseline_names = {item["networkName"] for item in before["networkMembership"]}
        additions.extend(
            dict(item) for item in by_container.get(name, []) if item["networkName"] not in baseline_names
        )
        memberships.append({"containerName": name, "networks": after["networkMembership"]})
    return (
        sorted(additions, key=lambda item: (item["containerName"], item["networkName"])),
        sorted(memberships, key=lambda item: item["containerName"]),
    )


def service_transitions(reconciliation: Dict[str, object], current: Dict[str, Dict[str, object]]) -> List[Dict[str, object]]:
    previous = predecessor_map(reconciliation)
    transitions = []
    for name in CANONICAL_CONTAINERS:
        current_record = current[name]
        previous_record = previous.get(name)
        if name == CANONICAL_ALERT_DISPATCHER and previous_record is None:
            previous_record = previous.get(LEGACY_ALERT_DISPATCHER)
        current_id = transition_identity(current_record)
        previous_id = transition_identity(previous_record)
        status = (
            "CREATED" if previous_id is None
            else "REPLACED" if previous_id["name"] != current_id["name"]
            else "RETAINED" if previous_id == current_id
            else "RECREATED"
        )
        transitions.append({"current": current_id, "previous": previous_id, "service": current_record["service"], "status": status})
    scheduler = previous.get("enterprise-backup-scheduler")
    if scheduler is not None:
        transitions.append({"current": None, "previous": transition_identity(scheduler), "service": scheduler["service"], "status": "REMOVED"})
    return sorted(transitions, key=lambda item: (item["current"] or item["previous"])["name"])


def stable_canonical_inventory(journal: Dict[str, object]) -> Tuple[List[Dict[str, object]], Dict[str, Dict[str, object]]]:
    first, first_raw = inventory()
    second, second_raw = inventory()
    if first != second:
        stop("canonical Docker runtime changed while evidence was captured.")
    backup_steps = {
        step["backupName"]: step for step in journal["steps"]
        if isinstance(step.get("backupName"), str) and step.get("status") != "PURGED"
    }
    for backup_name, step in backup_steps.items():
        backup = next((item for item in first if item["name"] == backup_name), None)
        if backup is not None and (
            not isinstance(step.get("before"), dict)
            or not backup_matches(backup, step["before"])
            or backup["state"] == "running"
        ):
            stop("reversible predecessor backup drifted before evidence commit.")
    unexpected = {item["name"] for item in first} - set(CANONICAL_CONTAINERS) - set(backup_steps)
    if unexpected:
        stop("evidence inventory contains a container outside canonical target and its bounded rollback set.")
    first = [item for item in first if item["name"] in CANONICAL_CONTAINERS]
    first_raw = {name: item for name, item in first_raw.items() if name in CANONICAL_CONTAINERS}
    if [item["name"] for item in first] != list(CANONICAL_CONTAINERS):
        stop("evidence Docker runtime is not exactly the canonical 36-container form.")
    # Require the same immutable image IDs to remain locally inspectable.
    image_ids = sorted({item["imageId"] for item in first})
    images = docker_json(["image", "inspect", *image_ids], "canonical local image availability", timeout=60)
    if not isinstance(images, list) or {item.get("Id") for item in images if isinstance(item, dict)} != set(image_ids):
        stop("one canonical runtime image is unavailable from the local image store.")
    for identity in first:
        name = identity["name"]
        if name == "phppgadmin":
            if identity["state"] != "exited":
                stop("phppgadmin did not retain its declared exited state.")
        elif name == BROKER_AUTH_BOOTSTRAP:
            if identity["state"] != "exited" or identity["exitCode"] != 0 or identity["health"] != "none":
                stop("broker auth bootstrap is not completed exit-0.")
        else:
            expected_health = "none" if name in NO_HEALTHCHECK else "healthy"
            if identity["state"] != "running" or identity["health"] != expected_health:
                stop(f"canonical container {name} is not healthy/running.")
        mounts = first_raw[name].get("Mounts")
        if not isinstance(mounts, list):
            stop(f"canonical container {name} has invalid mounts.")
        if any(
            isinstance(mount, dict) and (
                mount.get("Source") in ("/run/docker.sock", "/var/run/docker.sock")
                or mount.get("Destination") in ("/run/docker.sock", "/var/run/docker.sock")
            ) for mount in mounts
        ):
            stop("canonical runtime still grants raw Docker socket authority.")
    return first, first_raw


def evidence() -> Dict[str, object]:
    # Keep the same pre-write gate as apply.  Evidence writes and predecessor
    # purge are forbidden if maintenance was only marked but not made ready.
    require_maintenance_ready()
    authority, authority_bytes = read_authority()
    targets = validate_authority_material(authority)
    reconciliation = read_reconciliation(authority, authority_bytes)
    journal = read_or_create_journal(authority, authority_bytes, reconciliation)
    if journal["phase"] not in ("APPLIED", "COMMITTING", "EVIDENCED"):
        stop("runtime evidence requires a completely applied reconciliation transaction.")
    if journal["phase"] == "EVIDENCED":
        existing = secure_file(RUNTIME_EVIDENCE, "runtime reconciliation evidence", MAX_JSON, 0o444)
        value = parse_json(existing, "runtime reconciliation evidence", True)
        return {"evidencePath": RUNTIME_EVIDENCE, "evidenceSha256": digest(existing), "status": value.get("status", "PASS")}
    validate_apply_target(authority, reconciliation, journal, targets)
    lane = load_validation_lane(authority["candidateCommit"])
    # Route proof is intentionally obtained before the irreversible commit.
    # A failure therefore leaves every predecessor backup available to abort.
    route_checks(authority, reconciliation)
    # The exact-release producer refreshes logical/off-host/isolated-restore/
    # secrets proof under this same inherited shared transaction lease. It
    # cannot select paths, retention actions or a different release.
    if journal["phase"] == "APPLIED" and lane is None:
        invoke_evidence_producer(authority, "post")
    identities, _ = stable_canonical_inventory(journal)
    current = {item["name"]: item for item in identities}
    for name, target in targets.items():
        inspected = inspect_one(name)
        if not target_semantics(name, target, inspected[0], inspected[1]):
            stop(f"evidence target {name} differs from exact authority.")
    validate_preserved_legacy(reconciliation, authority, require_all_attachments=True)
    additions, memberships = legacy_network_evidence(authority, reconciliation, current)
    transitions = service_transitions(reconciliation, current)
    checks = route_checks(authority, reconciliation)
    if lane is not None:
        runtime_document = {
            "capturedAtUnixSeconds": int(time.time()),
            "containers": [
                {"containerId": item.get("containerId", ""), "name": item.get("name", ""), "state": item.get("state", "")}
                for item in identities
            ],
            "candidateCommit": authority["candidateCommit"],
            "schema": "platform.v1-local-private-reconciliation-runtime-validation/v1",
            "validation": True,
        }
        payload = (canonical(runtime_document) + "\n").encode("utf-8")
        atomic_bytes(VALIDATION_RUNTIME_EVIDENCE_FILE, payload, 0o444)
        written = secure_file(VALIDATION_RUNTIME_EVIDENCE_FILE, "validation runtime evidence", MAX_JSON)
        if digest(written) != digest(payload) or written != payload:
            stop("validation runtime evidence readback differs from the written bytes.")
        return {
            "evidencePath": VALIDATION_RUNTIME_EVIDENCE_FILE,
            "evidenceSha256": digest(payload),
            "status": "VALIDATION",
        }
    identities, _ = stable_canonical_inventory(journal)
    current = {item["name"]: item for item in identities}
    for name, target in targets.items():
        inspected = inspect_one(name)
        if not target_semantics(name, target, inspected[0], inspected[1]):
            stop(f"evidence target {name} differs from exact authority.")
    validate_preserved_legacy(reconciliation, authority, require_all_attachments=True)
    additions, memberships = legacy_network_evidence(authority, reconciliation, current)
    transitions = service_transitions(reconciliation, current)
    checks = route_checks(authority, reconciliation)
    data_mutations = sorted(journal["dataMutationEvidence"], key=lambda item: item["authorityId"])
    expected_mutations = {item["id"] for item in authority["authorizedDataMutations"]}
    if not {item.get("authorityId") for item in data_mutations}.issubset(expected_mutations):
        stop("runtime evidence contains a data mutation outside exact release authority.")
    evidence_identities = [{
        **{key: item[key] for key in (
            "configHash", "containerId", "exitCode", "health", "imageId", "imageReference", "name",
            "networkMembership", "project", "runtimeConfigSha256", "semanticSha256", "service", "state",
        )},
        "imageAvailability": "LOCAL_IMAGE_STORE",
    } for item in identities]
    # Preserve controller field order semantically through canonical JSON.
    evidence_identities = [{key: item[key] for key in (
        "configHash", "containerId", "exitCode", "health", "imageAvailability", "imageId", "imageReference", "name",
        "networkMembership", "project", "runtimeConfigSha256", "semanticSha256", "service", "state",
    )} for item in evidence_identities]
    document = {
        "activeManagedContainerNames": list(ACTIVE_MANAGED),
        "candidateCommit": authority["candidateCommit"],
        "candidateTree": authority["candidateTree"],
        "capturedAtUnixSeconds": max(int(time.time()), reconciliation["beganAtUnixSeconds"]),
        "containerIdentities": evidence_identities,
        "containerIdentitiesSha256": digest(canonical(evidence_identities).encode()),
        "dataMutations": data_mutations,
        "dataMutationsSha256": digest(canonical(data_mutations).encode()),
        "expectedContainerNames": list(CANONICAL_CONTAINERS),
        "legacyNetworkAttachments": additions,
        "legacyNetworkAttachmentsSha256": digest(canonical(additions).encode()),
        "legacyNetworkMemberships": memberships,
        "legacyNetworkMembershipsSha256": digest(canonical(memberships).encode()),
        "legacyRouteChecks": checks,
        "legacyRouteChecksSha256": digest(canonical(checks).encode()),
        "legacyUnmanagedContainers": [dict(item) for item in LEGACY_UNMANAGED],
        "preservedLegacyContainerNames": list(PRESERVED_LEGACY),
        "releaseAuthorityDocumentId": authority["documentId"],
        "releaseAuthoritySha256": digest(authority_bytes),
        "runtimeIdentity": authority["runtimeIdentity"],
        "schema": RUNTIME_EVIDENCE_SCHEMA,
        "serviceTransitions": transitions,
        "serviceTransitionsSha256": digest(canonical(transitions).encode()),
        "sourceArchiveSha256": authority["sourceArchiveSha256"],
        "status": "PASS",
    }
    data = atomic_json(RUNTIME_EVIDENCE, document, 0o444)
    # Full post-maintenance evidence and its checkpoint are proven while every
    # predecessor is still recoverable.  Missing/stale evidence therefore
    # leaves phase APPLIED and abort available.
    refresh_local_checkpoint(authority, data, reconciliation["beganAtUnixSeconds"])
    purge_predecessor_backups(journal)
    journal["phase"] = "EVIDENCED"
    save_journal(journal)
    return {"evidencePath": RUNTIME_EVIDENCE, "evidenceSha256": digest(data), "status": "PASS"}


def main() -> None:
    global EXECUTOR_FD_RESERVED, SHARED_LOCK_FD
    if len(sys.argv) != 2 or sys.argv[1] not in ("prepare", "apply", "abort", "evidence"):
        stop("usage: v1-local-private-reconcile prepare|apply|abort|evidence", 64)
    check_no_stdin()
    operation = sys.argv[1]
    configure_environment()
    # The controller verify used to prove abort consumption must run before we
    # take the shared lock (the controller takes that same lock). Its exact
    # receipt bytes are revalidated under both locks during finalization.
    preverify_consumed_abort_before_shared_lock(operation)
    shared_lock_fd = acquire_lock(SHARED_LOCK, "shared transaction")
    if shared_lock_fd != 3:
        os.dup2(shared_lock_fd, 3, inheritable=True)
        os.close(shared_lock_fd)
    else:
        os.set_inheritable(shared_lock_fd, True)
    SHARED_LOCK_FD = 3
    reservation = os.open("/dev/null", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    if reservation != 4:
        os.dup2(reservation, 4, inheritable=False)
        os.close(reservation)
    else:
        os.set_inheritable(reservation, False)
    EXECUTOR_FD_RESERVED = True
    try:
        local_lock_fd = acquire_lock(LOCK, "reconciliation")
        try:
            result = {
                "prepare": prepare,
                "apply": apply,
                "abort": abort,
                "evidence": evidence,
            }[operation]()
            sys.stdout.write(canonical(result) + "\n")
        finally:
            os.close(local_lock_fd)
    finally:
        EXECUTOR_FD_RESERVED = False
        try:
            os.close(4)
        except OSError:
            pass
        SHARED_LOCK_FD = None
        os.close(3)


if __name__ == "__main__":
    try:
        main()
    except Stop as error:
        sys.stderr.write(f"STOP: {error}\n")
        raise SystemExit(error.code)
