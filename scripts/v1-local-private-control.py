#!/usr/bin/python3 -I
"""Root-only V1 LOCAL_PRIVATE brownfield control and reconciliation seal.

The controller verifies the historical and reconciled closed V1 forms.  It
never mutates a Docker object; a separately installed, authority-bound V1
reconciler performs and journals the serial per-service transaction.  This
controller only freezes rollback evidence, controls its own supervisor, and
seals exact post-maintenance evidence.
"""

from __future__ import annotations

import fcntl
import hashlib
import ipaddress
import json
import os
import re
import secrets
import select
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import time
import urllib.parse
from decimal import Decimal, InvalidOperation
from typing import Dict, Iterable, List, Optional, Tuple


CANDIDATE_COMMIT = ""
CANDIDATE_TREE = ""
SOURCE_ARCHIVE_SHA256 = ""
RELEASE_ROOT = ""
INSTALL_RECEIPT = ""
EXACT_RELEASE_AUTHORITY = "/var/lib/platform-infrastructure/v1/local-private/exact-release-authority.json"
EXACT_RELEASE_RENDER = "/var/lib/platform-infrastructure/v1/local-private/exact-compose-render.json"
EXACT_RELEASE_ENV = "/var/lib/platform-infrastructure/v1/local-private/exact-compose.env"
SOURCE_ARCHIVE = "/var/lib/platform-infrastructure/v1/predeploy/current/exact-source-archive.tar"
CHECKPOINT = "/var/lib/platform-infrastructure/v1/predeploy/current/local-private-checkpoint.json"
SCHEDULER_RECOVERY_EXPORT = "/var/lib/platform-infrastructure/v1/predeploy/current/scheduler-recovery-image.tar"
SCHEDULER_RECOVERY_TAG = ""
EVIDENCE_PATHS = {
    "logicalBackupEvidenceSha256": "/var/lib/platform-infrastructure/v1/predeploy/current/logical-backup-evidence.json",
    "offHostBackupEvidenceSha256": "/var/lib/platform-infrastructure/v1/predeploy/current/offhost-backup-evidence.json",
    "restoreEvidenceSha256": "/var/lib/platform-infrastructure/v1/predeploy/current/restore-evidence.json",
    "runtimeInventorySha256": "/var/lib/platform-infrastructure/v1/predeploy/current/runtime-inventory-evidence.json",
    "secretsBackupEvidenceSha256": "/var/lib/platform-infrastructure/v1/predeploy/current/secrets-backup-evidence.json",
}
STATE_DIR = "/var/lib/platform-infrastructure/v1/local-private"
AUTHORITY_ARCHIVE_DIR = f"{STATE_DIR}/release-authorities"
STATE_FILE = f"{STATE_DIR}/state.json"
RECEIPT_FILE = f"{STATE_DIR}/active-receipt.json"
RECONCILIATION_FILE = f"{STATE_DIR}/reconciliation.json"
RECONCILE_JOURNAL_FILE = f"{STATE_DIR}/reconcile-journal.json"
ABORT_RECORD_FILE = f"{STATE_DIR}/reconciliation-abort-record.json"
ABORT_RECORD_ARCHIVE_DIR = f"{STATE_DIR}/aborted-reconciliations"
LOCK_FILE = "/run/lock/platform-v1-local-private-control.lock"
TRANSACTION_LOCK_FILE = "/run/lock/platform-v1-local-private-transaction.lock"
CONTROLLER_PATH = "/usr/local/libexec/platform-v1-local-private-control"
UNIT_PATH = "/etc/systemd/system/platform-v1-local-private-control.service"
SUDOERS_PATH = "/etc/sudoers.d/platform-v1-local-private-control"
UNIT_NAME = "platform-v1-local-private-control.service"
DOCKER = "/usr/bin/docker"
SYSTEMCTL = "/usr/bin/systemctl"
TEST_ROOT_ENV = "PLATFORM_V1_LOCAL_PRIVATE_TEST_ROOT"
TEST_DOCKER_ENV = "PLATFORM_V1_LOCAL_PRIVATE_TEST_DOCKER"
TEST_SYSTEMCTL_ENV = "PLATFORM_V1_LOCAL_PRIVATE_TEST_SYSTEMCTL"
RECOVERY_LABELS = {
    "candidateCommit": "com.platform.v1.local-private.candidate-commit",
    "configHash": "com.platform.v1.local-private.scheduler-config-hash",
    "containerId": "com.platform.v1.local-private.scheduler-container-id",
    "runningImageId": "com.platform.v1.local-private.scheduler-running-image-id",
}

RECEIPT_SCHEMA = "platform.v1-local-private-control-receipt/v1"
STATE_SCHEMA = "platform.v1-local-private-control-state/v1"
RECONCILIATION_SCHEMA = "platform.v1-local-private-reconciliation/v1"
ABORT_RECORD_SCHEMA = "platform.v1-local-private-reconciliation-abort-record/v1"
MAX_JSON = 128 * 1024
MAX_DOCKER_JSON = 4 * 1024 * 1024
MAX_RECOVERY_EXPORT_BYTES = 4 * 1024 * 1024 * 1024
MAX_RECOVERY_CONFIG_BYTES = 16 * 1024 * 1024
MAX_CHECKPOINT_AGE = 900
# backupCapturedUnixSeconds is stamped mid-producer (backup phase); the
# restore/upload/readback cycle legitimately exceeds 1h on the deployment
# host, so the activate-side bound matches the measured 6h cycle while
# generatedAtUnixSeconds keeps the tight 900s publish-freshness anchor.
MAX_BACKUP_AGE = 6 * 3600

VALIDATION_LANE_FILE = f"{STATE_DIR}/validation-lane.json"
VALIDATION_CHECKPOINT_FILE = "/var/lib/platform-infrastructure/v1/predeploy/current/local-private-checkpoint-validation.json"
CHECKPOINT_EVIDENCE_PATHS = {
    "logicalBackupEvidenceSha256": "/var/lib/platform-infrastructure/v1/predeploy/current/logical-backup-evidence.json",
    "offHostBackupEvidenceSha256": "/var/lib/platform-infrastructure/v1/predeploy/current/offhost-backup-evidence.json",
    "restoreEvidenceSha256": "/var/lib/platform-infrastructure/v1/predeploy/current/restore-evidence.json",
    "runtimeInventorySha256": "/var/lib/platform-infrastructure/v1/predeploy/current/runtime-inventory-evidence.json",
    "secretsBackupEvidenceSha256": "/var/lib/platform-infrastructure/v1/predeploy/current/secrets-backup-evidence.json",
}
VALIDATION_LANE_SCHEMA = "platform.v1-local-private-validation-lane/v1"
VALIDATION_CHECKPOINT_SCHEMA = "platform.v1-local-private-predeploy-checkpoint-validation/v1"
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
ID_RE = re.compile(r"^[a-f0-9]{64}$")
SERVICE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")

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
LEGACY_CONTAINERS = tuple(sorted((*HISTORIC_CONTAINERS, LEGACY_ALERT_DISPATCHER)))
CANONICAL_CONTAINERS = tuple(sorted((
    *(name for name in HISTORIC_CONTAINERS if name != "enterprise-backup-scheduler"),
    BROKER_AUTH_BOOTSTRAP,
    CANONICAL_ALERT_DISPATCHER,
)))
CLOSED_CONTAINER_SEQUENCES = frozenset((
    tuple(sorted(HISTORIC_CONTAINERS)),
    LEGACY_CONTAINERS,
    CANONICAL_CONTAINERS,
))
EXPECTED_NAMES = frozenset(HISTORIC_CONTAINERS)
CANONICAL_EXPECTED_NAMES = frozenset(CANONICAL_CONTAINERS)
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
DISABLED_MANAGED_SERVICES = ("backup-scheduler", "docker-action-activation-sidecar", "docker-action-broker")
BACKUP_TOOL_IMAGE_KEYS = (
    "mariadbRestore", "minioRestore", "nodeUtility", "postgresRestore", "resticRclone",
)
EVIDENCE_LOGICAL_KEYS = (
    "anniversary", "fiplatform", "matthewdifilippo", "opstudents", "public",
    "stexor", "stream", "workcalendar", "pg-stexor", "pg-keycloak", "mariadb",
    "minio", "keycloak-config", "confidential",
)
ACTIVE_MANAGED_CONTAINERS = frozenset(
    container for service, container in MANAGED_CONTAINER_BY_SERVICE.items()
    if service not in DISABLED_MANAGED_SERVICES
)
PRESERVED_LEGACY_CONTAINERS = frozenset(CANONICAL_EXPECTED_NAMES - ACTIVE_MANAGED_CONTAINERS)
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
LEGACY_UNMANAGED_CONTAINERS = tuple({
    "containerName": name,
    "reason": LEGACY_UNMANAGED_REASON_BY_CONTAINER[name],
    "status": "LEGACY_UNMANAGED",
} for name in sorted(PRESERVED_LEGACY_CONTAINERS))
RUNTIME_IDENTITY_LABELS = (
    "com.platform.runtime.candidate-id", "com.platform.runtime.commit",
    "com.platform.runtime.deployment-id", "com.platform.runtime.source-render-sha256",
    "com.platform.runtime.tree", "com.platform.runtime.workload-lock-sha256",
)
NO_HEALTHCHECK = frozenset(("enterprise-local-dns", "enterprise-local-registry", "phpmyadmin"))
HISTORIC_EXITED = "phppgadmin"
CANONICAL_COMPLETED = BROKER_AUTH_BOOTSTRAP
PROJECT_BY_NAME = {
    name: ("opstudents" if name == "node-opstudents" else "platform_infra_vps")
    for name in set(HISTORIC_CONTAINERS) | {LEGACY_ALERT_DISPATCHER, CANONICAL_ALERT_DISPATCHER, BROKER_AUTH_BOOTSTRAP}
}
EXACT_SERVICE_BY_NAME = {
    BROKER_AUTH_BOOTSTRAP: "broker-auth-bootstrap",
    CANONICAL_ALERT_DISPATCHER: "platform-alert-dispatcher",
    LEGACY_ALERT_DISPATCHER: "alert-dispatcher",
}
READY_BUT_DISABLED = (
    "PROVIDER_ADMISSION", "DNS_PUBLICATION", "DAST", "SIGSTORE_PROMOTION",
    "PROVIDER_DOCKER_ACTION_ACTIVATION_SIDECAR", "PROVIDER_DOCKER_ACTION_BROKER",
    "PROVIDER_SOCKETLESS_BACKUP_SCHEDULER",
)
PROVIDER_COMPONENTS = (
    {"name": "PROVIDER_DOCKER_ACTION_ACTIVATION_SIDECAR", "status": "READY_BUT_DISABLED"},
    {"name": "PROVIDER_DOCKER_ACTION_BROKER", "status": "READY_BUT_DISABLED"},
    {"name": "PROVIDER_SOCKETLESS_BACKUP_SCHEDULER", "status": "READY_BUT_DISABLED"},
)
EXTERNAL_DEPENDENCIES = (
    {"name": "HOSTINGER", "status": "NOT_REQUIRED"},
    {"name": "CLOUDFLARE", "status": "NOT_REQUIRED"},
    {"name": "PUBLIC_DNS", "status": "READY_BUT_DISABLED"},
    {"name": "EXTERNAL_DAST", "status": "READY_BUT_DISABLED"},
    {"name": "SIGSTORE_PROMOTION", "status": "READY_BUT_DISABLED"},
    {"name": "PUBLIC_PROVIDER", "status": "READY_BUT_DISABLED"},
)


class Stop(Exception):
    def __init__(self, message: str, code: int = 78):
        super().__init__(message)
        self.code = code


TEST_ROOT: Optional[str] = None
OWNER_UID = os.geteuid()
OWNER_GID = os.getegid()
EXACT_AUTHORITY: Optional[Dict[str, object]] = None
EXACT_AUTHORITY_SHA256 = ""


def stop(message: str, code: int = 78) -> None:
    raise Stop(message, code)


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def exact_keys(value: object, keys: Iterable[str], label: str) -> Dict[str, object]:
    if not isinstance(value, dict) or set(value) != set(keys):
        stop(f"{label} is not one exact closed object.")
    return value


def duplicate_safe(pairs: List[Tuple[str, object]]) -> Dict[str, object]:
    result: Dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            stop(f"JSON contains duplicate member {key!r}.")
        result[key] = value
    return result


def parse_json(data: bytes, label: str, require_canonical: bool = False) -> Dict[str, object]:
    try:
        text = data.decode("utf-8", errors="strict")
        value = json.loads(text, object_pairs_hook=duplicate_safe)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        stop(f"{label} is not strict JSON: {error}.")
    if not isinstance(value, dict):
        stop(f"{label} must be one JSON object.")
    if require_canonical and text != canonical(value) + "\n":
        stop(f"{label} is not canonical JSON.")
    return value


def mode(metadata: os.stat_result) -> int:
    return stat.S_IMODE(metadata.st_mode)


def physical(pathname: str) -> str:
    if not pathname.startswith("/") or os.path.normpath(pathname) != pathname:
        stop("internal path is not canonical.")
    if TEST_ROOT is None:
        return pathname
    result = os.path.join(TEST_ROOT, pathname[1:])
    if os.path.commonpath((TEST_ROOT, result)) != TEST_ROOT:
        stop("test path escaped the private root.")
    return result


def no_symlink_chain(pathname: str, label: str, final_required: bool = True) -> None:
    current = "/"
    parts = [part for part in pathname.split("/") if part]
    for index, part in enumerate(parts):
        current = os.path.join(current, part)
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            if final_required or index != len(parts) - 1:
                stop(f"{label} is missing.")
            return
        if stat.S_ISLNK(metadata.st_mode):
            stop(f"{label} traverses a symbolic link.")
        if index != len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            stop(f"{label} has a non-directory ancestor.")


def secure_file(logical: str, label: str, maximum: int = MAX_JSON, exact_mode: Optional[int] = None) -> bytes:
    pathname = physical(logical)
    no_symlink_chain(pathname, label)
    fd = os.open(pathname, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != OWNER_UID:
            stop(f"{label} identity is unsafe.")
        if mode(before) & 0o022 or (exact_mode is not None and mode(before) != exact_mode):
            stop(f"{label} permissions are unsafe.")
        if before.st_size < 2 or before.st_size > maximum:
            stop(f"{label} size is outside its boundary.")
        data = b""
        while len(data) <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not chunk:
                break
            data += chunk
        after = os.fstat(fd)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode, value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if len(data) > maximum or identity(before) != identity(after) or len(data) != before.st_size:
            stop(f"{label} changed while read.")
        return data
    finally:
        os.close(fd)


def stream_snapshot(logical: str, label: str) -> Dict[str, object]:
    pathname = physical(logical)
    no_symlink_chain(pathname, label)
    fd = os.open(pathname, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != OWNER_UID or mode(before) & 0o022:
            stop(f"{label} identity or permissions are unsafe.")
        if before.st_size < 1024 or before.st_size > MAX_RECOVERY_EXPORT_BYTES:
            stop(f"{label} size is outside its fixed boundary.")
        hasher = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_RECOVERY_EXPORT_BYTES:
                stop(f"{label} exceeds its fixed byte boundary.")
            hasher.update(chunk)
        after = os.fstat(fd)
        identity = lambda value: {
            "ctimeNs": value.st_ctime_ns,
            "device": value.st_dev,
            "gid": value.st_gid,
            "inode": value.st_ino,
            "mode": mode(value),
            "mtimeNs": value.st_mtime_ns,
            "nlink": value.st_nlink,
            "size": value.st_size,
            "uid": value.st_uid,
        }
        if identity(before) != identity(after) or size != before.st_size:
            stop(f"{label} changed while being stream-hashed.")
        return {"identity": identity(before), "sha256": hasher.hexdigest(), "sizeBytes": size}
    finally:
        os.close(fd)


def revalidate_stream_snapshot(snapshot: Dict[str, object], label: str) -> None:
    current = stream_snapshot(SCHEDULER_RECOVERY_EXPORT, label)
    if current != snapshot:
        stop(f"{label} bytes or filesystem identity changed after validation.")


def safe_tar_name(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value or any(part in ("", ".", "..") for part in value.split("/")):
        stop(f"{label} path is unsafe.")
    if len(value.encode("utf-8")) > 4096:
        stop(f"{label} path exceeds its boundary.")
    return value


def parse_recovery_export(
    snapshot: Dict[str, object],
    recovery_image_id: str,
    expected_tag: Optional[str] = None,
    expected_commit: Optional[str] = None,
) -> Dict[str, object]:
    expected_tag = expected_tag or SCHEDULER_RECOVERY_TAG
    expected_commit = expected_commit or CANDIDATE_COMMIT
    pathname = physical(SCHEDULER_RECOVERY_EXPORT)
    no_symlink_chain(pathname, "scheduler recovery image export")
    fd = os.open(pathname, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        if snapshot.get("identity") != {
            "ctimeNs": before.st_ctime_ns, "device": before.st_dev, "gid": before.st_gid,
            "inode": before.st_ino, "mode": mode(before), "mtimeNs": before.st_mtime_ns,
            "nlink": before.st_nlink, "size": before.st_size, "uid": before.st_uid,
        }:
            stop("scheduler recovery image export changed before manifest parsing.")
        stream = os.fdopen(os.dup(fd), "rb", closefd=True)
        try:
            archive = tarfile.open(fileobj=stream, mode="r:")
            try:
                members = archive.getmembers()
                if not members or len(members) > 100_000:
                    stop("scheduler recovery export entry count is invalid.")
                by_name = {}
                for member in members:
                    name = safe_tar_name(member.name.rstrip("/"), "scheduler recovery export member")
                    if name in by_name:
                        stop("scheduler recovery export contains duplicate members.")
                    if not member.isfile() and not member.isdir():
                        stop("scheduler recovery export contains a forbidden member type.")
                    by_name[name] = member
                def member_bytes(name: str, maximum: int, label: str) -> bytes:
                    member = by_name.get(name)
                    if member is None or not member.isfile() or member.size < 2 or member.size > maximum:
                        stop(f"{label} is missing or invalid.")
                    source = archive.extractfile(member)
                    if source is None:
                        stop(f"{label} cannot be read.")
                    data = source.read(maximum + 1)
                    if len(data) != member.size:
                        stop(f"{label} bytes are truncated or oversized.")
                    return data

                def json_object(data: bytes, label: str) -> Dict[str, object]:
                    try:
                        value = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=duplicate_safe)
                    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
                        stop(f"{label} is invalid JSON: {error}.")
                    if not isinstance(value, dict):
                        stop(f"{label} must be one JSON object.")
                    return value

                def descriptor_blob(descriptor: object, expected_media: set, label: str) -> Tuple[Dict[str, object], bytes, str]:
                    descriptor_value = exact_keys(descriptor, ("annotations", "digest", "mediaType", "size"), label)
                    digest_value = descriptor_value["digest"]
                    size_value = descriptor_value["size"]
                    if descriptor_value["mediaType"] not in expected_media or not isinstance(digest_value, str) or re.fullmatch(r"sha256:[a-f0-9]{64}", digest_value) is None or isinstance(size_value, bool) or not isinstance(size_value, int) or size_value < 2 or size_value > MAX_RECOVERY_CONFIG_BYTES:
                        stop(f"{label} media/digest/size is invalid.")
                    blob_name = f"blobs/sha256/{digest_value.removeprefix('sha256:')}"
                    blob = member_bytes(blob_name, MAX_RECOVERY_CONFIG_BYTES, f"{label} blob")
                    if len(blob) != size_value or digest(blob) != digest_value.removeprefix("sha256:"):
                        stop(f"{label} blob digest/size differs.")
                    return descriptor_value, blob, blob_name

                def verify_layer_blob(descriptor: object, index: int) -> str:
                    label = f"scheduler recovery OCI layer descriptor {index}"
                    if not isinstance(descriptor, dict) or set(descriptor) not in (
                        {"digest", "mediaType", "size"},
                        {"annotations", "digest", "mediaType", "size"},
                    ):
                        stop(f"{label} is not closed.")
                    digest_value = descriptor["digest"]
                    size_value = descriptor["size"]
                    allowed_media = {
                        "application/vnd.oci.image.layer.v1.tar",
                        "application/vnd.oci.image.layer.v1.tar+gzip",
                        "application/vnd.oci.image.layer.v1.tar+zstd",
                        "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    }
                    if (
                        descriptor["mediaType"] not in allowed_media
                        or not isinstance(digest_value, str)
                        or re.fullmatch(r"sha256:[a-f0-9]{64}", digest_value) is None
                        or isinstance(size_value, bool)
                        or not isinstance(size_value, int)
                        or size_value < 1
                        or size_value > MAX_RECOVERY_EXPORT_BYTES
                    ):
                        stop(f"{label} media/digest/size is invalid.")
                    blob_name = f"blobs/sha256/{digest_value.removeprefix('sha256:')}"
                    member = by_name.get(blob_name)
                    if member is None or not member.isfile() or member.size != size_value:
                        stop(f"{label} blob is missing or has a different size.")
                    source = archive.extractfile(member)
                    if source is None:
                        stop(f"{label} blob cannot be read.")
                    hasher = hashlib.sha256()
                    observed = 0
                    try:
                        while True:
                            chunk = source.read(1024 * 1024)
                            if not chunk:
                                break
                            observed += len(chunk)
                            if observed > size_value:
                                stop(f"{label} blob exceeds its declared size.")
                            hasher.update(chunk)
                    finally:
                        source.close()
                    if observed != size_value or hasher.hexdigest() != digest_value.removeprefix("sha256:"):
                        stop(f"{label} blob digest/size differs.")
                    return blob_name

                layout_bytes = member_bytes("oci-layout", 1024, "scheduler recovery OCI layout")
                layout = json_object(layout_bytes, "scheduler recovery OCI layout")
                if (
                    layout != {"imageLayoutVersion": "1.0.0"}
                    or layout_bytes != canonical(layout).encode("utf-8")
                ):
                    stop("scheduler recovery OCI layout is not the exact canonical 1.0.0 object.")

                root_index = json_object(member_bytes("index.json", 1024 * 1024, "scheduler recovery OCI index.json"), "scheduler recovery OCI index.json")
                if (
                    set(root_index) not in ({"manifests", "schemaVersion"}, {"manifests", "mediaType", "schemaVersion"})
                    or root_index.get("schemaVersion") != 2
                    or root_index.get("mediaType", "application/vnd.oci.image.index.v1+json") != "application/vnd.oci.image.index.v1+json"
                    or not isinstance(root_index.get("manifests"), list)
                    or len(root_index["manifests"]) != 1
                ):
                    stop("scheduler recovery OCI root index must contain exactly one image descriptor.")
                root_descriptor, image_index_bytes, image_index_path = descriptor_blob(
                    root_index["manifests"][0],
                    {"application/vnd.oci.image.index.v1+json"},
                    "scheduler recovery OCI image-index descriptor",
                )
                if root_descriptor["digest"] != recovery_image_id:
                    stop("scheduler recovery OCI image-index digest is not the inspected recovery image ID.")
                annotations = root_descriptor["annotations"]
                if not isinstance(annotations, dict) or set(annotations) != {
                    "io.containerd.image.name", "org.opencontainers.image.ref.name",
                }:
                    stop("scheduler recovery OCI image-index annotations are missing.")

                image_index = json_object(image_index_bytes, "scheduler recovery OCI image index")
                if set(image_index) - {"annotations", "manifests", "mediaType", "schemaVersion"} or image_index.get("schemaVersion") != 2 or image_index.get("mediaType") != "application/vnd.oci.image.index.v1+json" or not isinstance(image_index.get("manifests"), list) or len(image_index["manifests"]) != 1:
                    stop("scheduler recovery OCI image index schema/media is invalid.")
                platform_descriptors = []
                for candidate in image_index["manifests"]:
                    if not isinstance(candidate, dict) or set(candidate) - {"annotations", "digest", "mediaType", "platform", "size"}:
                        stop("scheduler recovery OCI platform descriptor is not closed.")
                    platform = candidate.get("platform")
                    if isinstance(platform, dict) and platform.get("os") == "linux" and platform.get("architecture") == "amd64":
                        platform_descriptors.append(candidate)
                if len(platform_descriptors) != 1:
                    stop("scheduler recovery OCI index must contain exactly one linux/amd64 image manifest.")
                manifest_descriptor = dict(platform_descriptors[0])
                manifest_descriptor.setdefault("annotations", {})
                manifest_descriptor.pop("platform", None)
                manifest_descriptor, manifest_bytes, _ = descriptor_blob(
                    manifest_descriptor,
                    {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"},
                    "scheduler recovery OCI image-manifest descriptor",
                )
                image_manifest = json_object(manifest_bytes, "scheduler recovery OCI image manifest")
                if set(image_manifest) - {"annotations", "artifactType", "config", "layers", "mediaType", "schemaVersion", "subject"} or image_manifest.get("schemaVersion") != 2 or image_manifest.get("mediaType") not in {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"} or not isinstance(image_manifest.get("layers"), list) or not 1 <= len(image_manifest["layers"]) <= 1024:
                    stop("scheduler recovery OCI image manifest schema/media/layers are invalid.")
                layer_paths = [
                    verify_layer_blob(layer_descriptor, index)
                    for index, layer_descriptor in enumerate(image_manifest["layers"])
                ]
                config_descriptor = image_manifest.get("config")
                if not isinstance(config_descriptor, dict) or set(config_descriptor) - {"annotations", "digest", "mediaType", "size"}:
                    stop("scheduler recovery OCI config descriptor is not closed.")
                config_descriptor = dict(config_descriptor)
                config_descriptor.setdefault("annotations", {})
                config_descriptor, config_bytes, config_name = descriptor_blob(
                    config_descriptor,
                    {"application/vnd.oci.image.config.v1+json", "application/vnd.docker.container.image.v1+json"},
                    "scheduler recovery OCI config descriptor",
                )
                image_config = json_object(config_bytes, "scheduler recovery OCI config")
                if image_config.get("architecture") != "amd64" or image_config.get("os") != "linux":
                    stop("scheduler recovery OCI config platform is not linux/amd64.")
                config_section = image_config.get("config")
                export_labels = config_section.get("Labels") if isinstance(config_section, dict) else None
                if not isinstance(export_labels, dict):
                    stop("scheduler recovery OCI config labels are missing.")
                ref_name = annotations.get("org.opencontainers.image.ref.name")
                containerd_name = annotations.get("io.containerd.image.name")
                if ref_name not in (expected_tag, expected_commit) or containerd_name not in (expected_tag, f"docker.io/{expected_tag}"):
                    stop("scheduler recovery OCI index annotations are not bound to the fixed recovery tag.")
                manifest_bytes = member_bytes("manifest.json", 1024 * 1024, "scheduler recovery Docker manifest.json")
                try:
                    docker_manifest = json.loads(manifest_bytes.decode("utf-8", errors="strict"), object_pairs_hook=duplicate_safe)
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
                    stop(f"scheduler recovery Docker manifest.json is invalid JSON: {error}.")
                if (
                    not isinstance(docker_manifest, list)
                    or len(docker_manifest) != 1
                    or not isinstance(docker_manifest[0], dict)
                    or set(docker_manifest[0]) != {"Config", "Layers", "RepoTags"}
                    or docker_manifest[0]["Config"] != config_name
                    or docker_manifest[0]["Layers"] != layer_paths
                    or docker_manifest[0]["RepoTags"] != [expected_tag]
                ):
                    stop("scheduler recovery Docker manifest.json is not the exact OCI-bound singleton image.")
                export_result = {
                    "archiveFormat": "OCI_DOCKER_SAVE_V1",
                    "configDigest": config_descriptor["digest"],
                    "exportLabels": {key: export_labels.get(key) for key in RECOVERY_LABELS.values()},
                    "imageIndexDigest": root_descriptor["digest"],
                    "imageIndexPath": image_index_path,
                    "imageManifestDigest": manifest_descriptor["digest"],
                    "manifestConfig": config_name,
                    "recoveryTag": expected_tag,
                }
            finally:
                archive.close()
        finally:
            stream.close()
        after = os.fstat(fd)
        if before.st_dev != after.st_dev or before.st_ino != after.st_ino or before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns or before.st_ctime_ns != after.st_ctime_ns:
            stop("scheduler recovery export changed while its manifest was parsed.")
        return export_result
    except (tarfile.TarError, OSError) as error:
        stop(f"scheduler recovery export is not one valid Docker-save tar: {error}.")
    finally:
        os.close(fd)


def validate_bound_recovery_export(recovery: object, full_hash: bool) -> None:
    expected_keys = {
        "archiveFormat", "configDigest", "configHash", "containerId", "exportIdentity",
        "exportLabels", "exportPath", "exportSha256", "exportSizeBytes",
        "imageIndexDigest", "imageIndexPath", "imageManifestDigest", "manifestConfig",
        "recoveryImageId", "recoveryTag", "runningImageId",
    }
    if not isinstance(recovery, dict) or set(recovery) != expected_keys:
        stop("receipt-bound scheduler recovery export is not one exact object.")
    if recovery["exportPath"] != SCHEDULER_RECOVERY_EXPORT:
        stop("receipt-bound scheduler recovery export path is not fixed.")
    for key in ("configHash", "containerId", "exportSha256"):
        sha256_value(recovery[key], f"scheduler recovery {key}")
    digest_fields = ("configDigest", "imageIndexDigest", "imageManifestDigest", "recoveryImageId", "runningImageId")
    if any(not isinstance(recovery[key], str) or re.fullmatch(r"sha256:[a-f0-9]{64}", recovery[key]) is None for key in digest_fields):
        stop("receipt-bound scheduler OCI/image digests are invalid.")
    recovery_hex = recovery["recoveryImageId"].removeprefix("sha256:")
    config_hex = recovery["configDigest"].removeprefix("sha256:")
    recovery_candidate = recovery["exportLabels"].get(RECOVERY_LABELS["candidateCommit"]) if isinstance(recovery.get("exportLabels"), dict) else None
    if not isinstance(recovery_candidate, str) or re.fullmatch(r"[a-f0-9]{40}", recovery_candidate) is None:
        stop("receipt-bound scheduler recovery candidate is invalid.")
    expected_tag = f"platform/v1-scheduler-recovery:{recovery_candidate}"
    expected_labels = {
        RECOVERY_LABELS["candidateCommit"]: recovery_candidate,
        RECOVERY_LABELS["configHash"]: recovery["configHash"],
        RECOVERY_LABELS["containerId"]: recovery["containerId"],
        RECOVERY_LABELS["runningImageId"]: recovery["runningImageId"],
    }
    if (
        recovery["archiveFormat"] != "OCI_DOCKER_SAVE_V1"
        or recovery["imageIndexDigest"] != recovery["recoveryImageId"]
        or recovery["imageIndexPath"] != f"blobs/sha256/{recovery_hex}"
        or recovery["manifestConfig"] != f"blobs/sha256/{config_hex}"
        or recovery["recoveryTag"] != expected_tag
        or recovery["exportLabels"] != expected_labels
        or isinstance(recovery["exportSizeBytes"], bool)
        or not isinstance(recovery["exportSizeBytes"], int)
        or not 1024 <= recovery["exportSizeBytes"] <= MAX_RECOVERY_EXPORT_BYTES
    ):
        stop("receipt-bound scheduler OCI export metadata is invalid.")
    if full_hash:
        snapshot = stream_snapshot(SCHEDULER_RECOVERY_EXPORT, "receipt-bound scheduler recovery image export")
        parsed = parse_recovery_export(snapshot, recovery["recoveryImageId"], expected_tag, recovery_candidate)
        metadata_keys = expected_keys - {
            "configHash", "containerId", "exportIdentity", "exportPath", "exportSha256",
            "exportSizeBytes", "recoveryImageId", "runningImageId",
        }
        if (
            snapshot["identity"] != recovery["exportIdentity"]
            or snapshot["sha256"] != recovery["exportSha256"]
            or snapshot["sizeBytes"] != recovery["exportSizeBytes"]
            or any(parsed[key] != recovery[key] for key in metadata_keys)
        ):
            stop("receipt-bound scheduler recovery image export changed.")
        return
    pathname = physical(SCHEDULER_RECOVERY_EXPORT)
    no_symlink_chain(pathname, "receipt-bound scheduler recovery image export")
    metadata = os.lstat(pathname)
    identity = {
        "ctimeNs": metadata.st_ctime_ns, "device": metadata.st_dev, "gid": metadata.st_gid,
        "inode": metadata.st_ino, "mode": mode(metadata), "mtimeNs": metadata.st_mtime_ns,
        "nlink": metadata.st_nlink, "size": metadata.st_size, "uid": metadata.st_uid,
    }
    if identity != recovery["exportIdentity"]:
        stop("receipt-bound scheduler recovery image export identity changed.")


def secure_directory(logical: str, label: str, exact_mode: Optional[int] = None) -> None:
    pathname = physical(logical)
    no_symlink_chain(pathname, label)
    metadata = os.lstat(pathname)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != OWNER_UID:
        stop(f"{label} identity is unsafe.")
    if mode(metadata) & 0o022 or (exact_mode is not None and mode(metadata) != exact_mode):
        stop(f"{label} permissions are unsafe.")


def ensure_private_directory(logical: str) -> None:
    pathname = physical(logical)
    try:
        metadata = os.lstat(pathname)
    except FileNotFoundError:
        parent = os.path.dirname(pathname)
        no_symlink_chain(parent, "state parent")
        parent_metadata = os.lstat(parent)
        if not stat.S_ISDIR(parent_metadata.st_mode) or parent_metadata.st_uid != OWNER_UID or mode(parent_metadata) & 0o022:
            stop("state parent is unsafe.")
        os.mkdir(pathname, 0o700)
        os.chown(pathname, OWNER_UID, OWNER_GID)
        metadata = os.lstat(pathname)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != OWNER_UID or mode(metadata) != 0o700:
        stop("LOCAL_PRIVATE state directory is unsafe.")


def atomic_write(logical: str, value: Dict[str, object], target_mode: int, replace: bool) -> None:
    pathname = physical(logical)
    parent = os.path.dirname(pathname)
    secure_directory(STATE_DIR, "LOCAL_PRIVATE state directory", 0o700)
    temporary = os.path.join(parent, f".tmp-{os.getpid()}-{secrets.token_hex(12)}")
    data = (canonical(value) + "\n").encode()
    if len(data) > MAX_JSON:
        stop("LOCAL_PRIVATE document exceeds 128 KiB.")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, data)
        os.fchown(fd, OWNER_UID, OWNER_GID)
        os.fchmod(fd, target_mode)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        if replace:
            os.replace(temporary, pathname)
        else:
            try:
                os.link(temporary, pathname, follow_symlinks=False)
            except FileExistsError:
                stop("LOCAL_PRIVATE receipt already exists.")
            os.unlink(temporary)
        dirfd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def canonical_bytes(value: Dict[str, object]) -> bytes:
    return (canonical(value) + "\n").encode()


def preserve_immutable_document(logical: str, value: Dict[str, object], label: str) -> bytes:
    expected = canonical_bytes(value)
    if os.path.lexists(physical(logical)):
        observed = secure_file(logical, label, exact_mode=0o444)
        if observed != expected:
            stop(f"{label} differs from the preserved rollback evidence.")
        return observed
    atomic_write(logical, value, 0o444, False)
    observed = secure_file(logical, label, exact_mode=0o444)
    if observed != expected:
        stop(f"{label} changed while it was preserved.")
    return observed


def remove_exact_document(logical: str, value: Dict[str, object], label: str) -> None:
    expected = canonical_bytes(value)
    if secure_file(logical, label, exact_mode=0o600) != expected:
        stop(f"{label} changed before transaction completion.")
    pathname = physical(logical)
    os.unlink(pathname)
    dirfd = os.open(os.path.dirname(pathname), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dirfd)
    finally:
        os.close(dirfd)


def initialize() -> None:
    global TEST_ROOT, OWNER_UID, OWNER_GID, DOCKER, SYSTEMCTL
    candidate = os.environ.get(TEST_ROOT_ENV)
    if candidate is not None:
        if os.geteuid() == 0:
            stop("non-root test seam is forbidden for effective UID 0.", 77)
        candidate = os.path.realpath(candidate)
        metadata = os.lstat(candidate)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != os.geteuid() or mode(metadata) != 0o700:
            stop("test root must be a private caller-owned directory.", 77)
        TEST_ROOT = candidate
        for env_name, target_name in ((TEST_DOCKER_ENV, "DOCKER"), (TEST_SYSTEMCTL_ENV, "SYSTEMCTL")):
            value = os.environ.get(env_name)
            if not value or os.path.commonpath((candidate, os.path.realpath(value))) != candidate:
                stop(f"{env_name} must stay inside the private test root.", 77)
            if target_name == "DOCKER":
                DOCKER = value
            else:
                SYSTEMCTL = value
    elif os.geteuid() != 0:
        stop("production LOCAL_PRIVATE control requires effective UID 0.", 77)
    OWNER_UID = os.geteuid()
    OWNER_GID = os.getegid()
    if os.environ.get("DOCKER_CONTEXT") or (os.environ.get("DOCKER_HOST") and os.environ.get("DOCKER_HOST") != "unix:///var/run/docker.sock"):
        stop("caller-controlled Docker routing is forbidden.", 77)
    expected_controller = physical(CONTROLLER_PATH)
    if os.path.realpath(sys.argv[0]) != expected_controller:
        stop("controller must run from its fixed installed path.", 77)
    secure_file(CONTROLLER_PATH, "installed LOCAL_PRIVATE controller", 1024 * 1024, 0o555)
    secure_file(UNIT_PATH, "installed LOCAL_PRIVATE systemd unit", 65536, 0o444)


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
        if not isinstance(key, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) is None or not isinstance(item, (str, int, float, bool)):
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
        test = value.get("Test")
        return {
            "intervalNs": int(value.get("Interval", 0)),
            "retries": int(value.get("Retries", 0)),
            "startPeriodNs": int(value.get("StartPeriod", 0)),
            "test": string_list(test, f"{label} healthcheck test"),
            "timeoutNs": int(value.get("Timeout", 0)),
        }
    if value.get("disable") is True:
        test = ["NONE"]
    else:
        test = string_list(value.get("test"), f"{label} healthcheck test")
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
    definition = definitions[source]
    if definition is None:
        definition = {}
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
        target = item.get("target")
        published = item.get("published")
        protocol = item.get("protocol", "tcp")
        host_ip = item.get("host_ip", "0.0.0.0")
        if isinstance(published, str) and published.isdigit():
            published = int(published)
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
    for item in raw:
        if not isinstance(item, str):
            stop(f"{label} tmpfs entry is invalid.")
        target, separator, options = item.partition(":")
        if not target.startswith("/") or (separator and not options):
            stop(f"{label} tmpfs target/options are invalid.")
        result.append({"options": normalize_tmpfs_options(options, f"{label} tmpfs {target}"), "target": target})
    if len({item["target"] for item in result}) != len(result):
        stop(f"{label} tmpfs targets are duplicated.")
    return sorted(result, key=lambda item: item["target"])


def render_ulimits(service: Dict[str, object], label: str) -> List[Dict[str, object]]:
    raw = service.get("ulimits", {})
    if not isinstance(raw, dict):
        stop(f"{label} ulimits are invalid.")
    result = []
    for name, value in raw.items():
        if not isinstance(name, str) or SERVICE_RE.fullmatch(name) is None:
            stop(f"{label} ulimit name is invalid.")
        if isinstance(value, dict) and set(value) == {"soft", "hard"}:
            soft = nonnegative_integer(value["soft"], f"{label} {name} soft ulimit")
            hard = nonnegative_integer(value["hard"], f"{label} {name} hard ulimit")
        else:
            soft = hard = nonnegative_integer(value, f"{label} {name} ulimit")
        result.append({"hard": hard, "name": name, "soft": soft})
    return sorted(result, key=lambda item: item["name"])


def normalize_extra_hosts(raw: object, label: str) -> List[Dict[str, str]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        stop(f"{label} extra hosts are invalid.")
    result = []
    for item in raw:
        if not isinstance(item, str):
            stop(f"{label} extra-host entry is invalid.")
        host, separator, address = item.partition("=")
        if not separator or not host or not address:
            stop(f"{label} extra-host entry is malformed.")
        result.append({"address": address, "host": host})
    if len({item["host"] for item in result}) != len(result):
        stop(f"{label} extra hosts are duplicated.")
    return sorted(result, key=lambda item: (item["host"], item["address"]))


def runtime_label_subset(labels: object, label: str) -> Dict[str, str]:
    if not isinstance(labels, dict):
        stop(f"{label} labels are invalid.")
    result = {name: labels[name] for name in RUNTIME_IDENTITY_LABELS if name in labels}
    if set(result) != set(RUNTIME_IDENTITY_LABELS) or any(not isinstance(value, str) or not value for value in result.values()):
        stop(f"{label} runtime identity labels are incomplete or invalid.")
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


def render_service_semantics(render: Dict[str, object], service_name: str, image_id: str, project: str) -> Dict[str, object]:
    services = render.get("services")
    service = services.get(service_name) if isinstance(services, dict) else None
    label = f"exact render service {service_name}"
    if not isinstance(service, dict):
        stop(f"{label} is missing.")
    image_reference = service.get("image")
    if not isinstance(image_reference, str) or re.fullmatch(r"[^@\s]+@sha256:[a-f0-9]{64}", image_reference) is None:
        stop(f"{label} image reference is not digest-pinned.")
    if not isinstance(image_id, str) or re.fullmatch(r"sha256:[a-f0-9]{64}", image_id) is None:
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
        "extraHosts": normalize_extra_hosts(service.get("extra_hosts"), label),
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


def authority_without_document_id(value: Dict[str, object]) -> Dict[str, object]:
    result = dict(value)
    result.pop("documentId", None)
    return result


def validate_runtime_identity(
    value: object, render: Dict[str, object], environment_lines: List[str], commit: str, tree: str, release_root: str
) -> Dict[str, str]:
    identity = exact_keys(value, (
        "candidateId", "commit", "deploymentId", "sourceRenderSha256", "tree", "workloadLockSha256",
    ), "V1 runtime identity")
    for key in ("candidateId", "sourceRenderSha256", "workloadLockSha256"):
        sha256_value(identity[key], f"V1 runtime identity {key}")
    if (
        identity["commit"] != commit or identity["tree"] != tree
        or not isinstance(identity["commit"], str) or re.fullmatch(r"[a-f0-9]{40}", identity["commit"]) is None
        or not isinstance(identity["tree"], str) or re.fullmatch(r"[a-f0-9]{40}", identity["tree"]) is None
        or identity["deploymentId"] != f"v1-local-private:{identity['candidateId']}"
    ):
        stop("V1 runtime identity candidate/tree/deployment binding is invalid.")
    workload_lock = secure_file(
        f"{release_root}/config/no-hosted-workloads.local-private.lock.json",
        "V1 exact no-hosted workload lock",
        MAX_JSON,
    )
    if identity["workloadLockSha256"] != digest(workload_lock):
        stop("V1 runtime identity workload-lock digest differs from the exact release.")
    seed = {
        "candidateCommit": commit,
        "candidateTree": tree,
        "sourceRenderSha256": identity["sourceRenderSha256"],
        "workloadLockSha256": identity["workloadLockSha256"],
    }
    if identity["candidateId"] != digest(canonical(seed).encode()):
        stop("V1 runtime candidate ID is not derived from the closed source tuple.")
    expected_labels = {
        "com.platform.runtime.candidate-id": identity["candidateId"],
        "com.platform.runtime.commit": identity["commit"],
        "com.platform.runtime.deployment-id": identity["deploymentId"],
        "com.platform.runtime.source-render-sha256": identity["sourceRenderSha256"],
        "com.platform.runtime.tree": identity["tree"],
        "com.platform.runtime.workload-lock-sha256": identity["workloadLockSha256"],
    }
    services = render.get("services")
    if not isinstance(services, dict) or set(services) != set(MANAGED_CONTAINER_BY_SERVICE):
        stop("V1 final render is not the exact active plus disabled service set.")
    source_render = parse_json(canonical_bytes(render), "V1 final render source projection", True)
    if source_render.get("x-platform-runtime-labels") != expected_labels:
        stop("V1 final render lacks exact top-level runtime identity labels.")
    source_render.pop("x-platform-runtime-labels")
    for service_name, service in services.items():
        labels = service.get("labels") if isinstance(service, dict) else None
        if not isinstance(labels, dict) or any(labels.get(name) != label for name, label in expected_labels.items()):
            stop(f"V1 final render service {service_name} lacks exact runtime identity labels.")
        projected = source_render["services"][service_name]
        remaining = {name: label for name, label in projected["labels"].items() if name not in expected_labels}
        if remaining:
            projected["labels"] = remaining
        else:
            projected.pop("labels", None)
    if digest(canonical_bytes(source_render)) != identity["sourceRenderSha256"]:
        stop("V1 runtime identity source-render digest differs from the label-free projection.")
    environment = {}
    runtime_names = {
        "PLATFORM_RUNTIME_CANDIDATE_ID": identity["candidateId"],
        "PLATFORM_RUNTIME_COMMIT": identity["commit"],
        "PLATFORM_RUNTIME_TREE": identity["tree"],
        "PLATFORM_RUNTIME_DEPLOYMENT_ID": identity["deploymentId"],
        "PLATFORM_RUNTIME_SOURCE_RENDER_SHA256": identity["sourceRenderSha256"],
        "PLATFORM_RUNTIME_WORKLOAD_LOCK_SHA256": identity["workloadLockSha256"],
    }
    for line in environment_lines:
        name, separator, raw = line.partition("=")
        if separator and name in runtime_names:
            if name in environment:
                stop("V1 runtime identity environment variable is duplicated.")
            environment[name] = raw
    if environment != runtime_names:
        stop("V1 exact render environment lacks the authority runtime identity tuple.")
    return identity


def validate_backup_tool_images(value: object, label: str) -> Dict[str, object]:
    images = exact_keys(value, BACKUP_TOOL_IMAGE_KEYS, label)
    for name in BACKUP_TOOL_IMAGE_KEYS:
        image = exact_keys(images[name], ("imageId", "imageReference"), f"{label} {name}")
        if (
            not isinstance(image["imageId"], str)
            or re.fullmatch(r"sha256:[a-f0-9]{64}", image["imageId"]) is None
            or not isinstance(image["imageReference"], str)
            or re.fullmatch(r"[^@\s]+@sha256:[a-f0-9]{64}", image["imageReference"]) is None
        ):
            stop(f"{label} {name} is not immutable.")
    return images


def validate_evidence_producer(value: object, release_root: str, label: str) -> Dict[str, object]:
    producer = exact_keys(value, (
        "executor", "executorFlags", "forbiddenResticOperations", "hostingerAllowed",
        "logicalKeys", "offsiteRepository", "operations", "path",
        "recoveryEscrowPrefix", "sha256",
    ), label)
    if (
        producer["executor"] != "/usr/bin/python3"
        or producer["executorFlags"] != ["-I"]
        or producer["forbiddenResticOperations"] != ["forget", "prune"]
        or producer["hostingerAllowed"] is not False
        or producer["logicalKeys"] != list(EVIDENCE_LOGICAL_KEYS)
        or producer["offsiteRepository"] != "rclone:platform-onedrive:platform-infrastructure/restic"
        or producer["operations"] != ["pre", "post"]
        or producer["path"] != f"{release_root}/scripts/v1-local-private-evidence-producer.py"
        or producer["recoveryEscrowPrefix"] != "platform-onedrive:platform-infrastructure/key-escrow"
    ):
        stop(f"{label} closed execution/storage contract is invalid.")
    sha256_value(producer["sha256"], f"{label} source")
    return producer


def validate_archived_authority(value: Dict[str, object], label: str) -> Dict[str, object]:
    exact_keys(value, (
        "activeManagedContainerNames", "artifacts", "authorityMode", "authorizedDataMutations", "backupToolImages", "candidateCommit", "candidateTree",
        "checkoutProof", "controllerVerificationScope", "disabledComposeServices", "documentId", "evidenceProducer", "expectedContainerNames",
        "legacyNetworkAttachments", "legacyRouteChecks", "legacyUnmanagedContainers", "preservedLegacyContainerNames", "releaseRoot",
        "renderEnvironment", "renderSha256", "recoveryEscrowCertificate", "runtimeIdentity", "schema", "serviceTargets",
        "sourceArchiveSha256", "status",
    ), label)
    document_id = value.get("documentId")
    if not isinstance(document_id, str) or document_id != digest(canonical(authority_without_document_id(value)).encode()):
        stop(f"{label} document ID is invalid.")
    if (
        value.get("schema") != "platform.v1-local-private-exact-release-authority/v1"
        or value.get("status") != "AUTHORIZED"
        or value.get("authorityMode") != "LOCAL_PRIVATE"
        or value.get("expectedContainerNames") != list(CANONICAL_CONTAINERS)
        or value.get("activeManagedContainerNames") != sorted(ACTIVE_MANAGED_CONTAINERS)
        or value.get("preservedLegacyContainerNames") != sorted(PRESERVED_LEGACY_CONTAINERS)
        or value.get("legacyUnmanagedContainers") != [dict(item) for item in LEGACY_UNMANAGED_CONTAINERS]
        or value.get("disabledComposeServices") != list(DISABLED_MANAGED_SERVICES)
        or not isinstance(value.get("authorizedDataMutations"), list)
        or not isinstance(value.get("legacyNetworkAttachments"), list)
        or not isinstance(value.get("legacyRouteChecks"), list)
    ):
        stop(f"{label} closed V1 scope/status is invalid.")
    document_binding(value, label)
    runtime_identity = exact_keys(value["runtimeIdentity"], (
        "candidateId", "commit", "deploymentId", "sourceRenderSha256", "tree", "workloadLockSha256",
    ), f"{label} runtime identity")
    if (
        runtime_identity["commit"] != value["candidateCommit"]
        or runtime_identity["tree"] != value["candidateTree"]
        or runtime_identity["deploymentId"] != f"v1-local-private:{runtime_identity['candidateId']}"
    ):
        stop(f"{label} runtime identity differs from its candidate/tree.")
    for key in ("candidateId", "sourceRenderSha256", "workloadLockSha256"):
        sha256_value(runtime_identity[key], f"{label} runtime identity {key}")
    validate_backup_tool_images(value["backupToolImages"], f"{label} backup tool images")
    validate_evidence_producer(value["evidenceProducer"], value["releaseRoot"], f"{label} evidence producer")
    certificate = exact_keys(value["recoveryEscrowCertificate"], ("path", "sha256", "sha256Fingerprint"), f"{label} recovery escrow certificate")
    if certificate["path"] != f"{value['releaseRoot']}/config/local-private-recovery-escrow-cert.pem":
        stop(f"{label} recovery escrow certificate path is invalid.")
    sha256_value(certificate["sha256"], f"{label} recovery escrow certificate bytes")
    sha256_value(certificate["sha256Fingerprint"], f"{label} recovery escrow certificate fingerprint")
    return value


def authority_for_external(value: Dict[str, object]) -> Dict[str, object]:
    document_id = value.get("releaseAuthorityDocumentId")
    authority_sha = value.get("releaseAuthoritySha256")
    sha256_value(document_id, "external reconciliation authority document")
    sha256_value(authority_sha, "external reconciliation authority bytes")
    if EXACT_AUTHORITY is not None and document_id == EXACT_AUTHORITY.get("documentId") and authority_sha == EXACT_AUTHORITY_SHA256:
        return EXACT_AUTHORITY
    pathname = f"{AUTHORITY_ARCHIVE_DIR}/{document_id}.json"
    data = secure_file(pathname, "archived V1 exact release authority", exact_mode=0o444)
    if digest(data) != authority_sha:
        stop("archived V1 exact release authority bytes differ from the receipt binding.")
    return validate_archived_authority(parse_json(data, "archived V1 exact release authority", True), "archived V1 exact release authority")


def validate_authority_network_attachments(value: object, render: Dict[str, object]) -> List[Dict[str, object]]:
    if not isinstance(value, list):
        stop("V1 exact legacy network attachments are not one sequence.")
    definitions = render.get("networks")
    if not isinstance(definitions, dict):
        stop("V1 exact render has no closed network definitions.")
    rendered_names = set()
    for key in definitions:
        rendered_names.add(resource_name(definitions, key, "platform_infra_vps", "V1 exact render network"))
    result = []
    seen = set()
    for index, raw in enumerate(value):
        item = exact_keys(raw, ("aliases", "containerName", "networkName"), f"V1 exact legacy network attachment {index}")
        container_name = item["containerName"]
        network_name = item["networkName"]
        aliases = item["aliases"]
        if (
            container_name not in PRESERVED_LEGACY_CONTAINERS
            or not isinstance(network_name, str)
            or network_name not in rendered_names
            or network_name == "enterprise_net"
            or not isinstance(aliases, list)
            or any(not isinstance(alias, str) or not alias or len(alias) > 128 for alias in aliases)
            or aliases != sorted(set(aliases))
            or (container_name, network_name) in seen
        ):
            stop("V1 exact legacy network attachment is invalid, duplicated, or outside the rendered networks.")
        seen.add((container_name, network_name))
        result.append({"aliases": aliases, "containerName": container_name, "networkName": network_name})
    if result != sorted(result, key=lambda item: (item["containerName"], item["networkName"])):
        stop("V1 exact legacy network attachments are not canonically ordered.")
    return result


def validate_authorized_data_mutations(value: object) -> List[Dict[str, str]]:
    if not isinstance(value, list):
        stop("V1 exact authorized data mutations are not one sequence.")
    result = []
    seen = set()
    allowed_types = {"BOOTSTRAP_WRITE", "SCHEMA_MIGRATION", "CONFIGURATION_WRITE"}
    for index, raw in enumerate(value):
        item = exact_keys(raw, ("id", "service", "target", "type"), f"V1 exact authorized data mutation {index}")
        if (
            not isinstance(item["id"], str)
            or SERVICE_RE.fullmatch(item["id"]) is None
            or item["id"] in seen
            or item["service"] not in MANAGED_CONTAINER_BY_SERVICE
            or item["service"] in DISABLED_MANAGED_SERVICES
            or not isinstance(item["target"], str)
            or not item["target"].startswith("/")
            or os.path.normpath(item["target"]) != item["target"]
            or item["type"] not in allowed_types
        ):
            stop("V1 exact authorized data mutation is invalid or duplicated.")
        seen.add(item["id"])
        result.append(dict(item))
    if result != sorted(result, key=lambda item: item["id"]):
        stop("V1 exact authorized data mutations are not canonically ordered.")
    return result


def validate_authority_route_checks(value: object, attachments: List[Dict[str, object]]) -> List[Dict[str, object]]:
    if not isinstance(value, list) or not value:
        stop("V1 exact legacy route checks are missing.")
    result = []
    seen = set()
    routed_containers = {item["containerName"] for item in attachments if str(item["networkName"]).endswith("_routing")}
    for index, raw in enumerate(value):
        item = exact_keys(raw, ("containerName", "expectedStatus", "name", "url"), f"V1 exact legacy route check {index}")
        parsed = urllib.parse.urlsplit(item["url"]) if isinstance(item["url"], str) else None
        if (
            item["containerName"] not in PRESERVED_LEGACY_CONTAINERS
            or not isinstance(item["name"], str)
            or SERVICE_RE.fullmatch(item["name"]) is None
            or item["name"] in seen
            or isinstance(item["expectedStatus"], bool)
            or not isinstance(item["expectedStatus"], int)
            or not 200 <= item["expectedStatus"] <= 399
            or parsed is None
            or parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            stop("V1 exact legacy route check is invalid or duplicated.")
        seen.add(item["name"])
        result.append(dict(item))
    if result != sorted(result, key=lambda item: item["name"]):
        stop("V1 exact legacy route checks are not canonically ordered.")
    if not routed_containers.issubset({item["containerName"] for item in result}):
        stop("V1 exact legacy route checks omit one routed legacy attachment.")
    return result


def configure_exact_release_authority() -> Dict[str, object]:
    global EXACT_AUTHORITY, CANDIDATE_COMMIT, CANDIDATE_TREE, SOURCE_ARCHIVE_SHA256
    global RELEASE_ROOT, INSTALL_RECEIPT, SCHEDULER_RECOVERY_TAG, EXACT_AUTHORITY_SHA256
    data = secure_file(EXACT_RELEASE_AUTHORITY, "V1 exact release authority", exact_mode=0o444)
    value = exact_keys(parse_json(data, "V1 exact release authority", True), (
        "activeManagedContainerNames", "artifacts", "authorityMode", "authorizedDataMutations", "backupToolImages", "candidateCommit", "candidateTree",
        "checkoutProof", "controllerVerificationScope", "disabledComposeServices", "documentId", "evidenceProducer",
        "expectedContainerNames", "legacyNetworkAttachments", "legacyRouteChecks", "legacyUnmanagedContainers", "preservedLegacyContainerNames",
        "recoveryEscrowCertificate", "releaseRoot", "renderEnvironment", "renderSha256", "runtimeIdentity", "schema",
        "serviceTargets", "sourceArchiveSha256", "status",
    ), "V1 exact release authority")
    document_id = value["documentId"]
    if not isinstance(document_id, str) or document_id != digest(canonical(authority_without_document_id(value)).encode()):
        stop("V1 exact release authority document ID is invalid.")
    archived_bytes = secure_file(f"{AUTHORITY_ARCHIVE_DIR}/{document_id}.json", "archived current V1 exact release authority", exact_mode=0o444)
    if archived_bytes != data:
        stop("current V1 exact release authority is not byte-identical to its immutable archive copy.")
    binding = document_binding(value, "V1 exact release authority")
    proof = exact_keys(value["checkoutProof"], (
        "clean", "githubMainCommit", "githubMainRef", "headCommit", "headTree", "producer", "status", "verifiedAtUnixSeconds",
    ), "V1 exact release authority checkout proof")
    if (
        value["schema"] != "platform.v1-local-private-exact-release-authority/v1"
        or value["status"] != "AUTHORIZED"
        or value["authorityMode"] != "LOCAL_PRIVATE"
        or value["controllerVerificationScope"] != "AUTHORITY_ARCHIVE_RELEASE_RENDER_ONLY_NOT_GITHUB"
        or proof["clean"] is not True
        or proof["status"] != "PASS"
        or proof["producer"] != "CLEAN_CHECKOUT_GITHUB_MAIN_V1"
        or proof["githubMainRef"] != "refs/remotes/github/main"
        or proof["headCommit"] != binding["candidateCommit"]
        or proof["githubMainCommit"] != binding["candidateCommit"]
        or proof["headTree"] != binding["candidateTree"]
        or isinstance(proof["verifiedAtUnixSeconds"], bool)
        or not isinstance(proof["verifiedAtUnixSeconds"], int)
        or value["expectedContainerNames"] != list(CANONICAL_CONTAINERS)
        or value["activeManagedContainerNames"] != sorted(ACTIVE_MANAGED_CONTAINERS)
        or value["preservedLegacyContainerNames"] != sorted(PRESERVED_LEGACY_CONTAINERS)
        or value["legacyUnmanagedContainers"] != [dict(item) for item in LEGACY_UNMANAGED_CONTAINERS]
        or value["disabledComposeServices"] != list(DISABLED_MANAGED_SERVICES)
    ):
        stop("V1 exact release authority main proof/scope/target is invalid.")
    render_bytes = secure_file(EXACT_RELEASE_RENDER, "V1 exact LOCAL_PRIVATE Compose render", MAX_DOCKER_JSON, 0o444)
    if digest(render_bytes) != value["renderSha256"]:
        stop("V1 exact release authority render digest differs from the immutable render bytes.")
    render = parse_json(render_bytes, "V1 exact LOCAL_PRIVATE Compose render", True)
    environment_binding = exact_keys(value["renderEnvironment"], ("path", "sha256"), "V1 exact render environment")
    if environment_binding["path"] != EXACT_RELEASE_ENV:
        stop("V1 exact render environment path is invalid.")
    sha256_value(environment_binding["sha256"], "V1 exact render environment")
    environment_bytes = secure_file(EXACT_RELEASE_ENV, "V1 exact LOCAL_PRIVATE Compose environment", 1024 * 1024, 0o400)
    if digest(environment_bytes) != environment_binding["sha256"]:
        stop("V1 exact render environment bytes differ from release authority.")
    try:
        environment_lines = environment_bytes.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError:
        stop("V1 exact render environment is not UTF-8.")
    variant_lines = [line for line in environment_lines if line.startswith("PLATFORM_COMPOSE_VARIANT=")]
    if variant_lines != ["PLATFORM_COMPOSE_VARIANT=LOCAL_PRIVATE"]:
        stop("V1 exact render environment does not contain the one descriptor-bound LOCAL_PRIVATE variant.")
    validate_runtime_identity(
        value["runtimeIdentity"], render, environment_lines,
        binding["candidateCommit"], binding["candidateTree"], binding["releaseRoot"],
    )
    validate_backup_tool_images(value["backupToolImages"], "V1 backup tool images")
    evidence_producer = validate_evidence_producer(value["evidenceProducer"], binding["releaseRoot"], "V1 evidence producer")
    certificate = exact_keys(value["recoveryEscrowCertificate"], ("path", "sha256", "sha256Fingerprint"), "V1 recovery escrow certificate")
    expected_certificate_path = f"{binding['releaseRoot']}/config/local-private-recovery-escrow-cert.pem"
    if certificate["path"] != expected_certificate_path:
        stop("V1 recovery escrow certificate path is invalid.")
    sha256_value(certificate["sha256"], "V1 recovery escrow certificate bytes")
    sha256_value(certificate["sha256Fingerprint"], "V1 recovery escrow certificate fingerprint")
    certificate_bytes = secure_file(expected_certificate_path, "V1 recovery escrow certificate", 65536, 0o444)
    if digest(certificate_bytes) != certificate["sha256"]:
        stop("V1 recovery escrow certificate PEM bytes differ from release authority.")
    producer_bytes = secure_file(evidence_producer["path"], "V1 evidence producer source", 2 * 1024 * 1024, 0o444)
    if digest(producer_bytes) != evidence_producer["sha256"]:
        stop("V1 evidence producer source bytes differ from release authority.")
    try:
        certificate_text = certificate_bytes.decode("ascii", errors="strict")
        if certificate_text.count("-----BEGIN CERTIFICATE-----") != 1 or certificate_text.count("-----END CERTIFICATE-----") != 1:
            raise ValueError("certificate PEM cardinality differs")
        certificate_der = ssl.PEM_cert_to_DER_cert(certificate_text)
    except (UnicodeDecodeError, ValueError) as error:
        stop(f"V1 recovery escrow certificate is not one exact X.509 PEM: {error}.")
    if digest(certificate_der) != certificate["sha256Fingerprint"]:
        stop("V1 recovery escrow certificate DER fingerprint differs from release authority.")
    attachments = validate_authority_network_attachments(value["legacyNetworkAttachments"], render)
    if not attachments:
        stop("V1 exact LOCAL_PRIVATE authority has no required legacy network bridge attachments.")
    validate_authority_route_checks(value["legacyRouteChecks"], attachments)
    validate_authorized_data_mutations(value["authorizedDataMutations"])
    archive_snapshot = stream_snapshot(SOURCE_ARCHIVE, "V1 exact source archive")
    if archive_snapshot["sha256"] != binding["sourceArchiveSha256"]:
        stop("V1 exact release authority archive digest differs from the immutable archive bytes.")
    artifacts = exact_keys(value["artifacts"], ("composeWrapper", "controller", "installer", "reconciler", "sudoers", "unit"), "V1 exact release artifacts")
    expected_artifact_paths = {
        "composeWrapper": f"{binding['releaseRoot']}/scripts/compose-vps.sh",
        "controller": CONTROLLER_PATH,
        "installer": "/usr/local/libexec/platform-v1-brownfield-install-consumer",
        "reconciler": "/usr/local/libexec/platform-v1-local-private-reconcile",
        "sudoers": SUDOERS_PATH,
        "unit": UNIT_PATH,
    }
    for name, expected_path in expected_artifact_paths.items():
        artifact = exact_keys(artifacts[name], ("path", "sha256"), f"V1 exact {name} artifact")
        if artifact["path"] != expected_path:
            stop(f"V1 exact {name} artifact path is invalid.")
        sha256_value(artifact["sha256"], f"V1 exact {name} artifact")
        maximum = 2 * 1024 * 1024 if name in ("composeWrapper", "controller", "installer", "reconciler") else 65536
        expected_mode = 0o440 if name == "sudoers" else 0o444 if name == "unit" else None
        if digest(secure_file(expected_path, f"installed V1 exact {name} artifact", maximum, expected_mode)) != artifact["sha256"]:
            stop(f"installed V1 exact {name} artifact differs from the release authority.")
    targets = value["serviceTargets"]
    if not isinstance(targets, list) or not targets:
        stop("V1 exact release authority has no service targets.")
    rebuilt = []
    target_names = set()
    target_services = set()
    for index, target in enumerate(targets):
        target = exact_keys(target, ("configHash", "containerName", "project", "semantic", "service"), f"V1 exact service target {index}")
        service_name = target["service"]
        container_name = target["containerName"]
        if (
            not isinstance(service_name, str) or SERVICE_RE.fullmatch(service_name) is None or service_name in target_services
            or not isinstance(container_name, str) or container_name not in CANONICAL_EXPECTED_NAMES or container_name in target_names
            or MANAGED_CONTAINER_BY_SERVICE.get(service_name) != container_name
            or target["project"] != PROJECT_BY_NAME[container_name]
            or not isinstance(target["semantic"], dict)
            or not isinstance(target["configHash"], str) or SHA256_RE.fullmatch(target["configHash"]) is None
        ):
            stop("V1 exact service target identity is invalid or duplicated.")
        rebuilt.append({
            "configHash": target["configHash"],
            "containerName": container_name,
            "project": target["project"],
            "semantic": render_service_semantics(render, service_name, target["semantic"].get("imageId"), target["project"]),
            "service": service_name,
        })
        target_names.add(container_name)
        target_services.add(service_name)
    if rebuilt != targets:
        stop("V1 exact service targets differ semantically from the immutable LOCAL_PRIVATE render.")
    services = render.get("services")
    if not isinstance(services, dict) or any(name not in services for name in value["disabledComposeServices"]):
        stop("V1 exact render omits a declared READY_BUT_DISABLED provider service.")
    scheduler = services["backup-scheduler"]
    if not isinstance(scheduler, dict) or any(
        isinstance(item, dict) and item.get("source") in ("/run/docker.sock", "/var/run/docker.sock")
        for item in scheduler.get("volumes", []) if isinstance(scheduler.get("volumes", []), list)
    ):
        stop("V1 exact disabled scheduler render implicitly retains raw Docker authority.")
    if target_names != ACTIVE_MANAGED_CONTAINERS or "enterprise-backup-scheduler" in target_names:
        stop("V1 exact target must quarantine the legacy scheduler while its socketless providers are disabled.")
    if any(
        mount["source"] in ("/run/docker.sock", "/var/run/docker.sock")
        or mount["target"] in ("/run/docker.sock", "/var/run/docker.sock")
        for target in targets for mount in target["semantic"]["mounts"]
    ):
        stop("V1 exact active managed target grants undeclared raw Docker authority.")
    CANDIDATE_COMMIT = binding["candidateCommit"]
    CANDIDATE_TREE = binding["candidateTree"]
    SOURCE_ARCHIVE_SHA256 = binding["sourceArchiveSha256"]
    RELEASE_ROOT = binding["releaseRoot"]
    INSTALL_RECEIPT = f"/var/lib/platform-infrastructure/v1/install-receipts/{CANDIDATE_COMMIT}-{SOURCE_ARCHIVE_SHA256}.json"
    SCHEDULER_RECOVERY_TAG = f"platform/v1-scheduler-recovery:{CANDIDATE_COMMIT}"
    EXACT_AUTHORITY = value
    EXACT_AUTHORITY_SHA256 = digest(data)
    validate_release_and_install()
    return value


def check_no_stdin() -> None:
    try:
        readable, _, _ = select.select([0], [], [], 0)
        if readable and os.read(0, 1):
            stop("LOCAL_PRIVATE control accepts no stdin.", 64)
    except (OSError, ValueError):
        stop("cannot prove empty stdin.", 64)


def sha256_value(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value) or value == "0" * 64:
        stop(f"{label} is not one non-placeholder SHA-256 digest.")
    return value


def validate_fixed_evidence_files(checkpoint: Dict[str, object]) -> Dict[str, bytes]:
    snapshots: Dict[str, bytes] = {}
    for digest_field, pathname in EVIDENCE_PATHS.items():
        label = digest_field.removesuffix("Sha256")
        data = secure_file(pathname, f"fixed {label} file")
        parse_json(data, f"fixed {label} file", True)
        if digest(data) != checkpoint[digest_field]:
            stop(f"fixed {label} file bytes differ from the fresh checkpoint.")
        snapshots[pathname] = data
    return snapshots


def assert_checkpoint_bytes_still_fresh(data: bytes) -> None:
    checkpoint = parse_json(data, "fresh PRE-DEPLOY checkpoint")
    captured = checkpoint.get("backupCapturedUnixSeconds")
    generated = checkpoint.get("generatedAtUnixSeconds")
    now = int(time.time())
    if (
        isinstance(captured, bool) or not isinstance(captured, int)
        or isinstance(generated, bool) or not isinstance(generated, int)
        or captured > generated or generated > now + 60
        or now - captured > MAX_BACKUP_AGE or now - generated > MAX_CHECKPOINT_AGE
    ):
        stop("PRE-DEPLOY checkpoint became stale before activation mutation.")


def document_binding(value: Dict[str, object], label: str) -> Dict[str, str]:
    commit = value.get("candidateCommit")
    tree = value.get("candidateTree")
    archive = value.get("sourceArchiveSha256")
    release_root = value.get("releaseRoot")
    if (
        not isinstance(commit, str) or re.fullmatch(r"[a-f0-9]{40}", commit) is None
        or not isinstance(tree, str) or re.fullmatch(r"[a-f0-9]{40}", tree) is None
        or not isinstance(archive, str) or SHA256_RE.fullmatch(archive) is None
        or release_root != f"/srv/platform-infrastructure/releases/{commit}-{archive}"
    ):
        stop(f"{label} candidate/release binding is invalid.")
    return {
        "candidateCommit": commit,
        "candidateTree": tree,
        "sourceArchiveSha256": archive,
        "releaseRoot": release_root,
    }


def validate_release_and_install(binding: Optional[Dict[str, object]] = None) -> str:
    selected = document_binding(binding or {
        "candidateCommit": CANDIDATE_COMMIT,
        "candidateTree": CANDIDATE_TREE,
        "sourceArchiveSha256": SOURCE_ARCHIVE_SHA256,
        "releaseRoot": RELEASE_ROOT,
    }, "selected V1 release")
    release_root = selected["releaseRoot"]
    install_receipt = f"/var/lib/platform-infrastructure/v1/install-receipts/{selected['candidateCommit']}-{selected['sourceArchiveSha256']}.json"
    secure_directory(release_root, "frozen V1 release", 0o555)
    data = secure_file(install_receipt, "V1 install receipt")
    value = exact_keys(parse_json(data, "V1 install receipt", True), (
        "activationAuthorized", "authorizationSource", "backupEvidenceAuthoritative",
        "candidateCommit", "candidateTree", "dataMutation", "dockerMutation",
        "readyButDisabled", "releaseRoot", "schema", "sourceArchiveSha256", "status",
    ), "V1 install receipt")
    if value["schema"] != "platform.v1-brownfield-install-receipt/v1" or value["status"] not in ("INSTALL_ONLY_COMPLETE", "ALREADY_INSTALLED"):
        stop("V1 install receipt status/schema is invalid.")
    if any(value[key] != selected[key] for key in selected):
        stop("V1 install receipt candidate binding differs.")
    if value["activationAuthorized"] is not False or value["dockerMutation"] is not False or value["dataMutation"] is not False or value["backupEvidenceAuthoritative"] is not False:
        stop("V1 install receipt exceeds install-only authority.")
    if value["authorizationSource"] != "ROOT_OPERATOR_EXPLICIT_INSTALL_ONLY":
        stop("V1 install receipt authorization source is invalid.")
    return digest(data)


def load_validation_lane(candidate_commit: str) -> Optional[Dict[str, object]]:
    """Return the operator validation-lane marker when present and valid.

    Absence means production mode.  A present marker must be one root-owned
    0400 canonical document bound to the current candidate and unexpired;
    anything else fails closed.
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
        or lane["expiresAtUnixSeconds"] - lane["createdAtUnixSeconds"] > 24 * 3600
    ):
        stop("validation lane marker fields are invalid.")
    now = int(time.time())
    if lane["createdAtUnixSeconds"] > now + 60 or now >= lane["expiresAtUnixSeconds"]:
        stop("validation lane marker is expired or future-dated.")
    return lane


def validate_validation_checkpoint(lane: Dict[str, object]) -> Tuple[str, bytes, Dict[str, object], Dict[str, object]]:
    """Validation-lane checkpoint: recovery pair is production-grade, the
    evidence digests are reused references verified by readback, and the
    non-production booleans are mandatory."""
    data = secure_file(VALIDATION_CHECKPOINT_FILE, "validation PRE-DEPLOY checkpoint")
    value = exact_keys(parse_json(data, "validation PRE-DEPLOY checkpoint"), (
        "authoritative", "backupCapturedUnixSeconds", "candidateCommit", "candidateTree",
        "destructiveMutationPlanned", "generatedAtUnixSeconds", "logicalBackupEvidenceSha256",
        "offHostBackupEvidenceSha256", "restoreEvidenceSha256", "restoreVerified",
        "runtimeInventorySha256", "runtimeRecovered", "schedulerRecoveryImageExportSha256",
        "schedulerRecoveryImageId", "schedulerRunningImageId", "schema",
        "secretsBackupEvidenceSha256", "sourceArchiveSha256", "validation",
    ), "validation PRE-DEPLOY checkpoint")
    if (
        value["schema"] != VALIDATION_CHECKPOINT_SCHEMA or value["validation"] is not True
        or value["authoritative"] is not False or value["destructiveMutationPlanned"] is not False
        or value["restoreVerified"] is not False or value["runtimeRecovered"] is not False
        or value["candidateCommit"] != CANDIDATE_COMMIT or value["candidateTree"] != CANDIDATE_TREE
        or value["sourceArchiveSha256"] != SOURCE_ARCHIVE_SHA256
    ):
        stop("validation PRE-DEPLOY checkpoint is not one explicit non-production candidate-bound document.")
    for key in ("logicalBackupEvidenceSha256", "offHostBackupEvidenceSha256", "restoreEvidenceSha256", "runtimeInventorySha256", "schedulerRecoveryImageExportSha256", "secretsBackupEvidenceSha256"):
        sha256_value(value[key], key)
    # Reused-evidence readback: every referenced evidence file must still exist
    # with the exact recorded digest (absent files are only tolerated when the
    # recorded digest is the explicit zero placeholder).
    for key, logical in CHECKPOINT_EVIDENCE_PATHS.items():
        recorded = value[key]
        pathname = physical(logical)
        if not os.path.lexists(pathname):
            if recorded != "0" * 64:
                stop(f"validation reuse reference {key} points at missing evidence.")
            continue
        observed = digest(secure_file(logical, f"validation reused {key}", MAX_JSON))
        if observed != recorded:
            stop(f"validation reused evidence {key} differs from its recorded digest.")
    running_image_id = value["schedulerRunningImageId"]
    recovery_image_id = value["schedulerRecoveryImageId"]
    if any(not isinstance(item, str) or re.fullmatch(r"sha256:[a-f0-9]{64}", item) is None for item in (running_image_id, recovery_image_id)) or running_image_id == recovery_image_id:
        stop("validation scheduler running/recovery image IDs are invalid or not distinct.")
    now = int(time.time())
    if value["generatedAtUnixSeconds"] > now + 60 or now - value["generatedAtUnixSeconds"] > MAX_CHECKPOINT_AGE:
        stop("validation PRE-DEPLOY checkpoint is stale or future-dated.")
    if value["backupCapturedUnixSeconds"] > now + 60 or now - value["backupCapturedUnixSeconds"] > MAX_BACKUP_AGE:
        stop("validation reused backup reference is stale or future-dated.")
    export_snapshot = stream_snapshot(SCHEDULER_RECOVERY_EXPORT, "scheduler recovery image export")
    if export_snapshot["sha256"] != value["schedulerRecoveryImageExportSha256"]:
        stop("scheduler recovery image export bytes differ from the validation checkpoint.")
    export_metadata = parse_recovery_export(export_snapshot, recovery_image_id)
    recovery: Dict[str, object] = {
        "exportIdentity": export_snapshot["identity"],
        "exportPath": SCHEDULER_RECOVERY_EXPORT,
        "exportSha256": value["schedulerRecoveryImageExportSha256"],
        "exportSizeBytes": export_snapshot["sizeBytes"],
        "recoveryImageId": recovery_image_id,
        "runningImageId": running_image_id,
        **export_metadata,
    }
    recovery["configHash"] = export_metadata["exportLabels"][RECOVERY_LABELS["configHash"]]
    recovery["containerId"] = export_metadata["exportLabels"][RECOVERY_LABELS["containerId"]]
    return digest(data), data, recovery, export_snapshot


def validate_checkpoint() -> Tuple[str, bytes, Dict[str, object], Dict[str, object], Dict[str, bytes]]:
    lane = load_validation_lane(CANDIDATE_COMMIT)
    if lane is not None:
        validation_sha, validation_bytes, validation_recovery, validation_export = validate_validation_checkpoint(lane)
        return validation_sha, validation_bytes, validation_recovery, validation_export, {}
    data = secure_file(CHECKPOINT, "fresh PRE-DEPLOY checkpoint")
    value = exact_keys(parse_json(data, "fresh PRE-DEPLOY checkpoint"), (
        "authoritative", "backupCapturedUnixSeconds", "candidateCommit", "candidateTree",
        "destructiveMutationPlanned", "generatedAtUnixSeconds", "logicalBackupEvidenceSha256",
        "offHostBackupEvidenceSha256", "restoreEvidenceSha256", "restoreVerified",
        "runtimeInventorySha256", "runtimeRecovered", "schedulerRecoveryImageExportSha256",
        "schedulerRecoveryImageId", "schedulerRunningImageId", "schema",
        "secretsBackupEvidenceSha256", "sourceArchiveSha256",
    ), "fresh PRE-DEPLOY checkpoint")
    if value["schema"] != "platform.v1-local-private-predeploy-checkpoint/v1":
        stop("fresh PRE-DEPLOY checkpoint schema is invalid.")
    if value["authoritative"] is not False or value["destructiveMutationPlanned"] is not False or value["restoreVerified"] is not True or value["runtimeRecovered"] is not True:
        stop("fresh PRE-DEPLOY checkpoint is incomplete.")
    if value["candidateCommit"] != CANDIDATE_COMMIT or value["candidateTree"] != CANDIDATE_TREE or value["sourceArchiveSha256"] != SOURCE_ARCHIVE_SHA256:
        stop("fresh PRE-DEPLOY checkpoint candidate binding differs.")
    for key in ("logicalBackupEvidenceSha256", "offHostBackupEvidenceSha256", "restoreEvidenceSha256", "runtimeInventorySha256", "schedulerRecoveryImageExportSha256", "secretsBackupEvidenceSha256"):
        sha256_value(value[key], key)
    evidence_snapshots = validate_fixed_evidence_files(value)
    running_image_id = value["schedulerRunningImageId"]
    recovery_image_id = value["schedulerRecoveryImageId"]
    if any(not isinstance(item, str) or re.fullmatch(r"sha256:[a-f0-9]{64}", item) is None for item in (running_image_id, recovery_image_id)) or running_image_id == recovery_image_id:
        stop("scheduler running/recovery image IDs are invalid or not distinct.")
    timestamps = [value[key] for key in ("backupCapturedUnixSeconds", "generatedAtUnixSeconds")]
    if any(isinstance(item, bool) or not isinstance(item, int) or item < 1700000000 for item in timestamps):
        stop("PRE-DEPLOY checkpoint timestamps are invalid.")
    now = int(time.time())
    if timestamps != sorted(timestamps) or timestamps[-1] > now + 60 or now - timestamps[0] > MAX_BACKUP_AGE or now - timestamps[1] > MAX_CHECKPOINT_AGE:
        stop("PRE-DEPLOY checkpoint is stale, future-dated, or unordered.")
    export_snapshot = stream_snapshot(SCHEDULER_RECOVERY_EXPORT, "scheduler recovery image export")
    if export_snapshot["sha256"] != value["schedulerRecoveryImageExportSha256"]:
        stop("scheduler recovery image export bytes differ from the fresh checkpoint.")
    export_metadata = parse_recovery_export(export_snapshot, recovery_image_id)
    for key, label in (("configHash", RECOVERY_LABELS["configHash"]), ("containerId", RECOVERY_LABELS["containerId"])):
        value_sha = export_metadata["exportLabels"].get(label)
        if key == "configHash":
            if not isinstance(value_sha, str) or SHA256_RE.fullmatch(value_sha) is None:
                stop("scheduler recovery export config-hash label is missing or invalid.")
        else:
            if not isinstance(value_sha, str) or ID_RE.fullmatch(value_sha) is None:
                stop("scheduler recovery export container-id label is missing or invalid.")
    recovery: Dict[str, object] = {
        "exportIdentity": export_snapshot["identity"],
        "exportPath": SCHEDULER_RECOVERY_EXPORT,
        "exportSha256": value["schedulerRecoveryImageExportSha256"],
        "exportSizeBytes": export_snapshot["sizeBytes"],
        "recoveryImageId": recovery_image_id,
        "runningImageId": running_image_id,
        **export_metadata,
    }
    # Single centralized promotion of the live scheduler identity: every
    # consumer (begin first path, begin retry, reconciliation apply) must see
    # the exact same closed 16-key recovery object.
    recovery["configHash"] = export_metadata["exportLabels"][RECOVERY_LABELS["configHash"]]
    recovery["containerId"] = export_metadata["exportLabels"][RECOVERY_LABELS["containerId"]]
    return digest(data), data, recovery, export_snapshot, evidence_snapshots


def command_environment() -> Dict[str, str]:
    return {"HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin", "DOCKER_HOST": "unix:///var/run/docker.sock"}


def run_result(command: List[str], label: str, timeout: int = 45) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=command_environment(), cwd="/", timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        stop(f"fixed {label} command failed: {error}.")
    if len(result.stdout) > MAX_DOCKER_JSON or len(result.stderr) > MAX_DOCKER_JSON:
        stop(f"fixed {label} output exceeded its boundary.")
    return result


def run(command: List[str], label: str, timeout: int = 45) -> bytes:
    result = run_result(command, label, timeout)
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip()[:512]
        stop(f"fixed {label} command rejected the operation: {detail}.")
    return result.stdout


def docker_json(arguments: List[str], label: str) -> object:
    output = run([DOCKER, *arguments], f"Docker {label}", 30)
    try:
        return json.loads(output.decode("utf-8", errors="strict"), object_pairs_hook=duplicate_safe)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        stop(f"fixed Docker {label} returned invalid JSON: {error}.")


def normalize_ports(container: Dict[str, object], name: str) -> List[Dict[str, object]]:
    network = container.get("NetworkSettings")
    ports = network.get("Ports") if isinstance(network, dict) else None
    if ports is None:
        return []
    if not isinstance(ports, dict):
        stop(f"container {name} has invalid published-port state.")
    result: List[Dict[str, object]] = []
    for target, bindings in ports.items():
        if bindings is None:
            continue
        match = re.fullmatch(r"([0-9]{1,5})/(tcp|udp)", str(target))
        if match is None or not isinstance(bindings, list):
            stop(f"container {name} has invalid port binding.")
        container_port = int(match.group(1))
        for binding in bindings:
            if not isinstance(binding, dict) or set(binding) != {"HostIp", "HostPort"}:
                stop(f"container {name} has non-canonical port binding.")
            try:
                host_port = int(binding["HostPort"])
                host_ip = str(ipaddress.ip_address(binding["HostIp"]))
            except (ValueError, TypeError):
                stop(f"container {name} has invalid host port/address.")
            if not 1 <= container_port <= 65535 or not 1 <= host_port <= 65535:
                stop(f"container {name} port is out of range.")
            result.append({"containerName": name, "containerPort": container_port, "hostIp": host_ip, "hostPort": host_port, "protocol": match.group(2)})
    return sorted(result, key=lambda item: (item["containerName"], item["hostIp"], item["hostPort"], item["protocol"], item["containerPort"]))


def validate_port_policy(ports: List[Dict[str, object]]) -> None:
    expected_waf = {("0.0.0.0", 80, 8080, "tcp"), ("0.0.0.0", 443, 8443, "tcp")}
    observed_waf = {(item["hostIp"], item["hostPort"], item["containerPort"], item["protocol"]) for item in ports if item["containerName"] == "enterprise-waf"}
    if observed_waf != expected_waf:
        stop("enterprise-waf published ports differ from the fixed 80/443 edge policy.")
    dns = [item for item in ports if item["containerName"] == "enterprise-local-dns"]
    if len(dns) != 2 or {item["protocol"] for item in dns} != {"tcp", "udp"} or any(item["hostPort"] != 53 or item["containerPort"] != 53 for item in dns):
        stop("enterprise-local-dns must publish exactly LAN TCP/UDP 53.")
    dns_ips = {item["hostIp"] for item in dns}
    if len(dns_ips) != 1:
        stop("enterprise-local-dns bindings must share one LAN address.")
    dns_ip = ipaddress.ip_address(next(iter(dns_ips)))
    if not dns_ip.is_private or dns_ip.is_loopback or dns_ip.is_link_local or dns_ip.is_unspecified or dns_ip.is_multicast:
        stop("enterprise-local-dns is not bound to one private LAN address.")
    registry = [item for item in ports if item["containerName"] == "enterprise-local-registry"]
    if len(registry) != 1 or registry[0]["hostPort"] != 5000 or registry[0]["containerPort"] != 5000 or registry[0]["protocol"] != "tcp" or not ipaddress.ip_address(registry[0]["hostIp"]).is_loopback:
        stop("enterprise-local-registry must publish only loopback TCP 5000.")
    if any(item["containerName"] not in {"enterprise-waf", "enterprise-local-dns", "enterprise-local-registry"} for item in ports):
        stop("a non-edge container publishes a host port.")


def closed_expected_names(expected_names: Iterable[str]) -> frozenset[str]:
    result = frozenset(expected_names)
    if tuple(sorted(result)) not in CLOSED_CONTAINER_SEQUENCES:
        stop("requested Docker container set is not one declared V1 identity.")
    return result


def inspect_network_membership(container: Dict[str, object], name: str) -> List[Dict[str, object]]:
    network_settings = container.get("NetworkSettings")
    networks = network_settings.get("Networks") if isinstance(network_settings, dict) else None
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
        # Docker injects the current short container ID as an ephemeral alias;
        # it is not part of the declared network contract.
        stable_aliases = sorted(set(alias for alias in aliases if alias != short_id))
        result.append({"aliases": stable_aliases, "networkName": network_name})
    return sorted(result, key=lambda item: item["networkName"])


def inspect_service_semantics(container: Dict[str, object], name: str) -> Dict[str, object]:
    config = container.get("Config")
    host = container.get("HostConfig")
    if not isinstance(config, dict) or not isinstance(host, dict):
        stop(f"container {name} runtime configuration is incomplete.")
    mounts = container.get("Mounts")
    if not isinstance(mounts, list):
        stop(f"container {name} mount inventory is invalid.")
    normalized_mounts = []
    for index, mount in enumerate(mounts):
        if not isinstance(mount, dict):
            stop(f"container {name} mount {index} is invalid.")
        mount_type = mount.get("Type")
        source = mount.get("Source", "")
        target = mount.get("Destination")
        if mount_type not in ("bind", "volume", "tmpfs") or not isinstance(source, str) or not isinstance(target, str):
            stop(f"container {name} mount {index} identity is invalid.")
        normalized_mounts.append({"readOnly": mount.get("RW") is False, "source": source, "target": target, "type": mount_type})
    restart = host.get("RestartPolicy")
    restart_name = restart.get("Name", "no") if isinstance(restart, dict) else "no"
    network_mode = host.get("NetworkMode", "")
    if network_mode in ("none", "host"):
        semantic_network_mode = network_mode
    else:
        semantic_network_mode = "managed"
    health = config.get("Healthcheck")
    if isinstance(health, dict) and not health.get("Test"):
        health = None
    ports = [
        {key: port[key] for key in ("containerPort", "hostIp", "hostPort", "protocol")}
        for port in normalize_ports(container, name)
    ]
    networks = [item["networkName"] for item in inspect_network_membership(container, name)]
    image_reference = config.get("Image")
    image_id = container.get("Image")
    if not isinstance(image_reference, str) or not image_reference or not isinstance(image_id, str):
        stop(f"container {name} image declaration is invalid.")
    pids_limit = host.get("PidsLimit")
    if pids_limit in (None, 0):
        pids_limit = 0
    return {
        "capAdd": sorted(string_list(host.get("CapAdd"), f"container {name} cap-add")),
        "capDrop": sorted(string_list(host.get("CapDrop"), f"container {name} cap-drop")),
        "command": string_list(config.get("Cmd"), f"container {name} command"),
        "entrypoint": string_list(config.get("Entrypoint"), f"container {name} entrypoint"),
        "environment": environment_fingerprints(config.get("Env"), f"container {name} environment"),
        "healthcheck": normalized_health(health, f"container {name}", inspect=True),
        "imageId": image_id,
        "imageReference": image_reference,
        "init": host.get("Init") is True,
        "mounts": sorted(normalized_mounts, key=lambda item: (item["target"], item["type"], item["source"], item["readOnly"])),
        "networkMode": semantic_network_mode,
        "networks": sorted(networks),
        "pidsLimit": pids_limit,
        "ports": sorted(ports, key=lambda item: (item["hostIp"], item["hostPort"], item["protocol"], item["containerPort"])),
        "privileged": host.get("Privileged") is True,
        "readOnlyRootfs": host.get("ReadonlyRootfs") is True,
        "restartPolicy": restart_name,
        "securityOpt": sorted(string_list(host.get("SecurityOpt"), f"container {name} security-opt")),
        "user": str(config.get("User", "")),
    }


def runtime_configuration_digest(semantic: Dict[str, object]) -> str:
    # Network membership is authorized and evidenced independently because
    # legacy bridge attachments are allowed without recreating a container.
    value = dict(semantic)
    value.pop("networks", None)
    value.pop("networkMode", None)
    return digest(canonical(value).encode())


def observation_names(observation: object, label: str) -> frozenset[str]:
    if not isinstance(observation, dict) or not isinstance(observation.get("containers"), list):
        stop(f"{label} has no closed container inventory.")
    names = []
    for record in observation["containers"]:
        if not isinstance(record, dict) or not isinstance(record.get("name"), str):
            stop(f"{label} contains an invalid container record.")
        names.append(record["name"])
    if len(names) != len(set(names)):
        stop(f"{label} contains duplicate container names.")
    return closed_expected_names(names)


def observe(
    scheduler_recovery: Dict[str, str],
    expected_names: Iterable[str] = EXPECTED_NAMES,
    enforce_current_authority: bool = True,
) -> Dict[str, object]:
    expected = closed_expected_names(expected_names)
    reconciled_profile = expected == CANONICAL_EXPECTED_NAMES
    expected_count = len(expected)
    info = docker_json(["info", "--format", "{{json .}}"], "daemon identity")
    if not isinstance(info, dict):
        stop("Docker daemon identity is invalid.")
    daemon = {}
    for source, target in (("ID", "id"), ("Name", "name"), ("ServerVersion", "serverVersion"), ("DockerRootDir", "dockerRootDir")):
        value = info.get(source)
        if not isinstance(value, str) or not value or len(value) > 512:
            stop(f"Docker daemon {source} is invalid.")
        daemon[target] = value
    ids_output = run([DOCKER, "ps", "-aq", "--no-trunc"], "Docker container inventory", 30).decode("ascii", errors="strict")
    ids = [line for line in ids_output.splitlines() if line]
    if len(ids) != expected_count or len(set(ids)) != expected_count or any(ID_RE.fullmatch(item) is None for item in ids):
        stop(f"Docker inventory is not exactly {expected_count} unique full container IDs.")
    inspected = docker_json(["inspect", *sorted(ids)], "container inspection")
    if not isinstance(inspected, list) or len(inspected) != expected_count:
        stop(f"Docker inspection did not return exactly {expected_count} containers.")
    records: List[Dict[str, object]] = []
    ports: List[Dict[str, object]] = []
    raw_owners: List[Dict[str, object]] = []
    image_ids = set()
    names = set()
    for container in inspected:
        if not isinstance(container, dict):
            stop("Docker returned a non-object container inspection.")
        identifier = container.get("Id")
        name = str(container.get("Name", "")).removeprefix("/")
        if not isinstance(identifier, str) or ID_RE.fullmatch(identifier) is None or name not in expected or name in names:
            stop("Docker container ID/name inventory differs from the closed allowlist.")
        names.add(name)
        config = container.get("Config")
        state = container.get("State")
        if not isinstance(config, dict) or not isinstance(state, dict) or not isinstance(config.get("Labels"), dict):
            stop(f"container {name} inspection is incomplete.")
        labels = config["Labels"]
        project = labels.get("com.docker.compose.project")
        service = labels.get("com.docker.compose.service")
        config_hash = labels.get("com.docker.compose.config-hash")
        if (
            project != PROJECT_BY_NAME[name]
            or not isinstance(service, str)
            or SERVICE_RE.fullmatch(service) is None
            or (name in EXACT_SERVICE_BY_NAME and service != EXACT_SERVICE_BY_NAME[name])
            or not isinstance(config_hash, str)
            or SHA256_RE.fullmatch(config_hash) is None
        ):
            stop(f"container {name} Compose identity/config hash is invalid.")
        image_id = container.get("Image")
        if not isinstance(image_id, str) or re.fullmatch(r"sha256:[a-f0-9]{64}", image_id) is None:
            stop(f"container {name} image ID is not immutable.")
        image_ids.add(image_id)
        runtime_state = state.get("Status")
        health_object = state.get("Health")
        health = health_object.get("Status") if isinstance(health_object, dict) else "none"
        if name == HISTORIC_EXITED:
            if runtime_state != "exited":
                stop("phppgadmin must remain the declared exited historical admin container.")
        elif name == CANONICAL_COMPLETED:
            if runtime_state != "exited" or state.get("ExitCode") != 0 or health != "none":
                stop("enterprise-broker-auth-bootstrap must be one completed exit-0 exact-main one-shot.")
        else:
            if runtime_state != "running":
                stop(f"container {name} is not running.")
            if name in NO_HEALTHCHECK:
                if health != "none":
                    stop(f"container {name} unexpectedly has a healthcheck.")
            elif health != "healthy":
                stop(f"container {name} is not healthy.")
        exit_code = state.get("ExitCode")
        if isinstance(exit_code, bool) or not isinstance(exit_code, int):
            stop(f"container {name} exit state is invalid.")
        record = {"configHash": config_hash, "containerId": identifier, "exitCode": exit_code, "health": health, "imageId": image_id, "name": name, "project": project, "service": service, "state": runtime_state}
        if reconciled_profile:
            semantic = inspect_service_semantics(container, name)
            membership = inspect_network_membership(container, name)
            record.update({
                "imageReference": semantic["imageReference"],
                "networkMembership": membership,
                "runtimeConfigSha256": runtime_configuration_digest(semantic),
                "semanticSha256": digest(canonical(semantic).encode()),
            })
            if enforce_current_authority and name in ACTIVE_MANAGED_CONTAINERS:
                if EXACT_AUTHORITY is None:
                    stop("V1 exact managed runtime has no release authority.")
                target = next((item for item in EXACT_AUTHORITY["serviceTargets"] if item["containerName"] == name), None)
                if target is None or target["service"] != service or semantic != target["semantic"]:
                    stop(f"container {name} runtime semantics differ from the exact release render/image authority.")
        records.append(record)
        ports.extend(normalize_ports(container, name))
        mounts = container.get("Mounts")
        if not isinstance(mounts, list):
            stop(f"container {name} mount inventory is invalid.")
        for mount in mounts:
            if not isinstance(mount, dict):
                stop(f"container {name} mount entry is invalid.")
            destination = mount.get("Destination")
            source = mount.get("Source")
            if destination in ("/var/run/docker.sock", "/run/docker.sock") or source in ("/var/run/docker.sock", "/run/docker.sock"):
                if destination not in ("/var/run/docker.sock", "/run/docker.sock") or source not in ("/var/run/docker.sock", "/run/docker.sock"):
                    stop(f"container {name} has an ambiguous Docker socket mount.")
                raw_owners.append({"containerId": identifier, "name": name, "readOnly": mount.get("RW") is False, "source": source, "status": "PASS", "target": destination})
    if names != expected:
        stop("Docker container-name allowlist is incomplete or contains extras.")
    if reconciled_profile:
        if raw_owners:
            stop("reconciled V1 runtime must have no raw Docker socket container authority.")
    elif len(raw_owners) != 1 or raw_owners[0]["name"] != "enterprise-backup-scheduler" or raw_owners[0]["readOnly"] is not False:
        stop("raw Docker socket container authority is not the one receipt-bound RW legacy scheduler.")
    validate_port_policy(ports)
    scheduler_record = next((item for item in records if item["name"] == "enterprise-backup-scheduler"), None)
    scheduler_image = scheduler_record["imageId"] if scheduler_record is not None else scheduler_recovery.get("runningImageId")
    recovery_base_keys = {
        "archiveFormat", "configDigest", "exportIdentity", "exportLabels", "exportPath",
        "exportSha256", "exportSizeBytes", "imageIndexDigest", "imageIndexPath",
        "imageManifestDigest", "manifestConfig", "recoveryImageId", "recoveryTag",
        "runningImageId",
    }
    if not isinstance(scheduler_recovery, dict) or not recovery_base_keys.issubset(scheduler_recovery) or set(scheduler_recovery) - recovery_base_keys - {"configHash", "containerId"}:
        stop("scheduler recovery binding is not one closed object.")
    if scheduler_recovery.get("runningImageId") != scheduler_image or scheduler_recovery.get("exportPath") != SCHEDULER_RECOVERY_EXPORT:
        stop("scheduler recovery artifact is not bound to its declared predecessor image.")
    recovery_image = scheduler_recovery["recoveryImageId"]
    if recovery_image == scheduler_image:
        stop("scheduler recovery image must be distinct from the running image ID.")
    local_images = image_ids - ({scheduler_image} if scheduler_record is not None else set())
    image_objects = docker_json(["image", "inspect", *sorted(local_images)], "immutable image inspection")
    if not isinstance(image_objects, list) or {item.get("Id") for item in image_objects if isinstance(item, dict)} != local_images:
        stop("one or more required immutable local Docker image IDs are unavailable.")
    scheduler_result = run_result([DOCKER, "image", "inspect", scheduler_image], "Docker scheduler image inspection", 30)
    if scheduler_result.returncode == 0:
        try:
            scheduler_objects = json.loads(scheduler_result.stdout.decode("utf-8", errors="strict"), object_pairs_hook=duplicate_safe)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            stop("scheduler image inspection returned invalid JSON.")
        if not isinstance(scheduler_objects, list) or {item.get("Id") for item in scheduler_objects if isinstance(item, dict)} != {scheduler_image}:
            stop("scheduler immutable image inspection differs from the running container.")
        scheduler_availability = "LOCAL_IMAGE_STORE_AND_RECOVERY_EXPORT_BOUND"
    else:
        missing_detail = scheduler_result.stderr.decode("utf-8", errors="strict").strip()
        expected_missing = {
            f"Error response from daemon: No such image: {scheduler_image}",
            f"Error: No such image: {scheduler_image}",
        }
        if scheduler_result.stdout not in (b"", b"[]\n") or missing_detail not in expected_missing:
            stop("scheduler image inspection failed for a reason other than the one exact missing image ID.")
        sha256_value(scheduler_recovery.get("exportSha256"), "scheduler recovery export")
        scheduler_availability = "RECOVERY_IMAGE_EXPORT_BOUND"
    recovery_objects = docker_json(["image", "inspect", recovery_image], "scheduler recovery image inspection")
    if not isinstance(recovery_objects, list) or {item.get("Id") for item in recovery_objects if isinstance(item, dict)} != {recovery_image}:
        stop("scheduler recovery image ID is unavailable from the local image store.")
    recovery_object = recovery_objects[0]
    recovery_config = recovery_object.get("Config") if isinstance(recovery_object, dict) else None
    recovery_labels = recovery_config.get("Labels") if isinstance(recovery_config, dict) else None
    recovery_tags = recovery_object.get("RepoTags") if isinstance(recovery_object, dict) else None
    recovery_config_hash = scheduler_record["configHash"] if scheduler_record is not None else scheduler_recovery.get("exportLabels", {}).get(RECOVERY_LABELS["configHash"])
    recovery_container_id = scheduler_record["containerId"] if scheduler_record is not None else scheduler_recovery.get("exportLabels", {}).get(RECOVERY_LABELS["containerId"])
    if not isinstance(recovery_config_hash, str) or SHA256_RE.fullmatch(recovery_config_hash) is None or not isinstance(recovery_container_id, str) or ID_RE.fullmatch(recovery_container_id) is None:
        stop("scheduler recovery artifact predecessor identity is invalid.")
    recovery_candidate = scheduler_recovery.get("exportLabels", {}).get(RECOVERY_LABELS["candidateCommit"])
    recovery_tag = scheduler_recovery.get("recoveryTag")
    if not isinstance(recovery_candidate, str) or re.fullmatch(r"[a-f0-9]{40}", recovery_candidate) is None or recovery_tag != f"platform/v1-scheduler-recovery:{recovery_candidate}":
        stop("scheduler recovery artifact release binding is invalid.")
    expected_labels = {
        RECOVERY_LABELS["candidateCommit"]: recovery_candidate,
        RECOVERY_LABELS["configHash"]: recovery_config_hash,
        RECOVERY_LABELS["containerId"]: recovery_container_id,
        RECOVERY_LABELS["runningImageId"]: scheduler_image,
    }
    if recovery_tags != [recovery_tag]:
        stop("scheduler recovery image is not bound to the one fixed local tag.")
    if (
        scheduler_recovery.get("exportLabels") != expected_labels
        or not isinstance(recovery_labels, dict)
        or any(recovery_labels.get(key) != value for key, value in expected_labels.items())
    ):
        stop("scheduler recovery image labels are not bound to candidate and live scheduler identity.")
    bound_recovery = {key: scheduler_recovery[key] for key in recovery_base_keys}
    bound_recovery["configHash"] = recovery_config_hash
    bound_recovery["containerId"] = recovery_container_id
    for record in records:
        record["imageAvailability"] = scheduler_availability if record["name"] == "enterprise-backup-scheduler" else "LOCAL_IMAGE_STORE"
    records.sort(key=lambda item: item["name"])
    raw_authority = raw_owners[0] if not reconciled_profile else {"mode": "NONE", "owners": [], "status": "PASS"}
    return {"containers": records, "daemon": daemon, "publishedPorts": ports, "rawDockerAuthority": raw_authority, "schedulerRecovery": bound_recovery}


def stable_observation(
    scheduler_recovery: Dict[str, str],
    expected_names: Iterable[str] = EXPECTED_NAMES,
    enforce_current_authority: bool = True,
) -> Dict[str, object]:
    expected = closed_expected_names(expected_names)
    first = observe(scheduler_recovery, expected, enforce_current_authority)
    second = observe(scheduler_recovery, expected, enforce_current_authority)
    if canonical(first) != canonical(second):
        stop("Docker runtime changed during LOCAL_PRIVATE adoption.")
    return first


def capture_runtime_identities(expected_names: Iterable[str]) -> List[Dict[str, object]]:
    expected = closed_expected_names(expected_names)
    ids_output = run([DOCKER, "ps", "-aq", "--no-trunc"], "Docker semantic identity inventory", 30).decode("ascii", errors="strict")
    ids = [line for line in ids_output.splitlines() if line]
    if len(ids) != len(expected) or len(set(ids)) != len(expected) or any(ID_RE.fullmatch(item) is None for item in ids):
        stop("Docker semantic identity inventory is not one closed V1 set.")
    inspected = docker_json(["inspect", *sorted(ids)], "Docker semantic identity inspection")
    if not isinstance(inspected, list) or len(inspected) != len(expected):
        stop("Docker semantic identity inspection cardinality differs.")
    result = []
    for container in inspected:
        if not isinstance(container, dict):
            stop("Docker semantic identity contains one invalid object.")
        name = str(container.get("Name", "")).removeprefix("/")
        identifier = container.get("Id")
        config = container.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        if name not in expected or not isinstance(identifier, str) or ID_RE.fullmatch(identifier) is None or not isinstance(labels, dict):
            stop("Docker semantic identity differs from the closed V1 names/IDs.")
        config_hash = labels.get("com.docker.compose.config-hash")
        service = labels.get("com.docker.compose.service")
        image_id = container.get("Image")
        if not isinstance(config_hash, str) or SHA256_RE.fullmatch(config_hash) is None or not isinstance(service, str) or SERVICE_RE.fullmatch(service) is None or not isinstance(image_id, str) or re.fullmatch(r"sha256:[a-f0-9]{64}", image_id) is None:
            stop(f"container {name} semantic Compose/image identity is invalid.")
        semantic = inspect_service_semantics(container, name)
        state = container.get("State")
        if not isinstance(state, dict) or not isinstance(state.get("ExitCode"), int):
            stop(f"container {name} semantic runtime state is invalid.")
        health_object = state.get("Health")
        health = health_object.get("Status") if isinstance(health_object, dict) else "none"
        result.append({
            "configHash": config_hash,
            "containerId": identifier,
            "imageId": image_id,
            "imageReference": semantic["imageReference"],
            "name": name,
            "networkMembership": inspect_network_membership(container, name),
            "exitCode": state["ExitCode"],
            "health": health,
            "runtimeConfigSha256": runtime_configuration_digest(semantic),
            "semanticSha256": digest(canonical(semantic).encode()),
            "service": service,
            "state": state.get("Status"),
        })
    result.sort(key=lambda item: item["name"])
    if [item["name"] for item in result] != sorted(expected):
        stop("Docker semantic identity names are incomplete or duplicated.")
    return result


def stable_runtime_identities(expected_names: Iterable[str]) -> List[Dict[str, object]]:
    first = capture_runtime_identities(expected_names)
    second = capture_runtime_identities(expected_names)
    if first != second:
        stop("Docker semantic identities changed while establishing reconciliation rollback evidence.")
    return first


def validate_predecessor_runtime_snapshot(
    observation: Dict[str, object],
    identities: List[Dict[str, object]],
) -> None:
    frozen = {item["name"]: item for item in observation["containers"]}
    current = {item["name"]: item for item in identities}
    if set(frozen) != set(current):
        stop("predecessor semantic runtime names differ from its frozen state.")
    base_fields = ("configHash", "containerId", "exitCode", "health", "imageId", "name", "service", "state")
    for name, record in frozen.items():
        actual = current[name]
        if any(record.get(field) != actual.get(field) for field in base_fields):
            stop(f"predecessor container {name} drifted from its frozen runtime identity.")
        for field in ("imageReference", "networkMembership", "runtimeConfigSha256", "semanticSha256"):
            if field in record and record[field] != actual.get(field):
                stop(f"predecessor container {name} drifted from its reconciled semantic identity.")


def validate_legacy_network_target(
    predecessor_identities: List[Dict[str, object]],
    observation: Dict[str, object],
) -> Tuple[List[Dict[str, object]], List[Dict[str, object]]]:
    if EXACT_AUTHORITY is None:
        stop("legacy network target has no exact release authority.")
    previous = {item["name"]: item for item in predecessor_identities}
    current = {item["name"]: item for item in observation["containers"]}
    authority = EXACT_AUTHORITY["legacyNetworkAttachments"]
    additions = []
    final_memberships = []
    by_container: Dict[str, List[Dict[str, object]]] = {}
    for attachment in authority:
        by_container.setdefault(attachment["containerName"], []).append({
            "aliases": attachment["aliases"],
            "networkName": attachment["networkName"],
        })
    for name in sorted(PRESERVED_LEGACY_CONTAINERS):
        before = previous.get(name)
        after = current.get(name)
        if before is None or after is None:
            stop("preserved legacy runtime is missing from predecessor or target evidence.")
        for field in ("configHash", "containerId", "imageId", "imageReference", "name", "runtimeConfigSha256", "service"):
            if after.get(field) != before.get(field):
                stop(f"preserved legacy container {name} was recreated or its non-network configuration changed.")
        baseline = before.get("networkMembership")
        target = after.get("networkMembership")
        if not isinstance(baseline, list) or not isinstance(target, list):
            stop(f"preserved legacy container {name} network evidence is invalid.")
        expected_by_name = {item["networkName"]: item for item in baseline}
        if len(expected_by_name) != len(baseline) or "enterprise_net" not in expected_by_name:
            stop(f"preserved legacy container {name} predecessor networks are duplicated or omit enterprise_net.")
        for attachment in by_container.get(name, []):
            existing = expected_by_name.get(attachment["networkName"])
            if existing is None:
                expected_by_name[attachment["networkName"]] = attachment
                additions.append({"aliases": attachment["aliases"], "containerName": name, "networkName": attachment["networkName"]})
            elif existing != attachment:
                stop(f"preserved legacy container {name} already has an authority network with conflicting aliases.")
        expected_membership = sorted(expected_by_name.values(), key=lambda item: item["networkName"])
        if target != expected_membership:
            stop(f"preserved legacy container {name} final network membership/aliases differ from baseline plus the exact authority.")
        final_memberships.append({"containerName": name, "networks": target})
    return additions, final_memberships


def reconciliation_container_identities(observation: Dict[str, object]) -> List[Dict[str, object]]:
    fields = (
        "configHash", "containerId", "exitCode", "health", "imageAvailability",
        "imageId", "imageReference", "name", "networkMembership", "project",
        "runtimeConfigSha256", "semanticSha256", "service", "state",
    )
    return [{key: record[key] for key in fields} for record in observation["containers"]]


def transition_identity(record: Dict[str, object]) -> Dict[str, object]:
    return {key: record[key] for key in (
        "configHash", "containerId", "imageId", "imageReference", "name", "runtimeConfigSha256",
    )}


def reconciliation_service_transitions(
    previous_identities: List[Dict[str, object]],
    current_observation: Dict[str, object],
) -> List[Dict[str, object]]:
    previous = {record["name"]: record for record in previous_identities}
    transitions = []
    for current_record in current_observation["containers"]:
        name = current_record["name"]
        previous_record = previous.get(name)
        if name == CANONICAL_ALERT_DISPATCHER and previous_record is None:
            previous_record = previous.get(LEGACY_ALERT_DISPATCHER)
        current_identity = transition_identity(current_record)
        previous_identity = transition_identity(previous_record) if previous_record is not None else None
        if previous_identity is None:
            status = "CREATED"
        elif previous_identity["name"] != current_identity["name"]:
            status = "REPLACED"
        elif previous_identity == current_identity:
            status = "RETAINED"
        else:
            status = "RECREATED"
        transitions.append({
            "current": current_identity,
            "previous": previous_identity,
            "service": current_record["service"],
            "status": status,
        })
    scheduler = previous.get("enterprise-backup-scheduler")
    if scheduler is not None:
        transitions.append({
            "current": None,
            "previous": transition_identity(scheduler),
            "service": scheduler["service"],
            "status": "REMOVED",
        })
    return sorted(transitions, key=lambda item: (item["current"] or item["previous"])["name"])


def validate_data_mutation_evidence(
    value: object,
    authority: Optional[Dict[str, object]] = None,
    began_at: Optional[int] = None,
) -> List[Dict[str, str]]:
    authority = authority or EXACT_AUTHORITY
    if authority is None or not isinstance(value, list):
        stop("reconciliation data-mutation evidence is invalid.")
    allowed = {item["id"] for item in authority["authorizedDataMutations"] if isinstance(item, dict) and isinstance(item.get("id"), str)}
    result = []
    seen = set()
    for index, raw in enumerate(value):
        item = exact_keys(raw, ("authorityId", "evidencePath", "evidenceSha256"), f"reconciliation data mutation {index}")
        if item["authorityId"] not in allowed or item["authorityId"] in seen:
            stop("reconciliation data mutation is duplicated or outside release authority.")
        sha256_value(item["evidenceSha256"], "reconciliation data mutation evidence")
        expected_path = (
            f"{STATE_DIR}/data-mutation-evidence/"
            f"{authority['documentId']}-{item['authorityId']}-{item['evidenceSha256']}.json"
        )
        if item["evidencePath"] != expected_path:
            stop("reconciliation data mutation evidence path is not fixed.")
        evidence_bytes = secure_file(expected_path, "reconciliation data mutation evidence", exact_mode=0o444)
        if digest(evidence_bytes) != item["evidenceSha256"]:
            stop("reconciliation data mutation evidence bytes differ from their digest.")
        evidence = exact_keys(parse_json(evidence_bytes, "reconciliation data mutation evidence", True), (
            "authorityId", "capturedAtUnixSeconds", "detailsSha256", "schema", "status",
        ), "reconciliation data mutation evidence")
        captured = evidence["capturedAtUnixSeconds"]
        if (
            evidence["schema"] != "platform.v1-local-private-reconciliation-data-evidence/v1"
            or evidence["status"] != "PASS"
            or evidence["authorityId"] != item["authorityId"]
            or isinstance(captured, bool)
            or not isinstance(captured, int)
            or (began_at is not None and captured < began_at)
            or captured > int(time.time()) + 60
        ):
            stop("reconciliation data mutation evidence identity/time is invalid.")
        sha256_value(evidence["detailsSha256"], "reconciliation data mutation details")
        seen.add(item["authorityId"])
        result.append(dict(item))
    if result != sorted(result, key=lambda item: item["authorityId"]):
        stop("reconciliation data mutations are not canonically ordered.")
    return result


def validate_actual_legacy_attachments(value: object, authority: Optional[Dict[str, object]] = None) -> List[Dict[str, object]]:
    authority = authority or EXACT_AUTHORITY
    if authority is None or not isinstance(value, list):
        stop("reconciliation legacy network attachments are invalid.")
    allowed = {canonical(item) for item in authority["legacyNetworkAttachments"]}
    result = []
    seen = set()
    for index, raw in enumerate(value):
        item = exact_keys(raw, ("aliases", "containerName", "networkName"), f"reconciliation legacy network attachment {index}")
        encoded = canonical(item)
        if encoded not in allowed or encoded in seen:
            stop("reconciliation legacy network attachment is duplicated or outside release authority.")
        seen.add(encoded)
        result.append(dict(item))
    if result != sorted(result, key=lambda item: (item["containerName"], item["networkName"])):
        stop("reconciliation legacy network attachments are not canonically ordered.")
    return result


def external_reconciliation_document(
    reconciliation: Dict[str, object],
    runtime_evidence_sha: str,
    transitions: List[Dict[str, object]],
    legacy_network_attachments: List[Dict[str, object]],
    data_mutations: List[Dict[str, str]],
) -> Dict[str, object]:
    container_recreate = any(item["status"] in ("CREATED", "REMOVED", "REPLACED", "RECREATED") for item in transitions)
    external_docker_mutation = container_recreate or bool(legacy_network_attachments)
    return {
        "authority": "ROOT_OPERATOR_EXPLICIT_V1_RECONCILIATION",
        "beganAtUnixSeconds": reconciliation["beganAtUnixSeconds"],
        "containerRecreate": container_recreate,
        "controllerDockerMutation": False,
        "dataMutation": bool(data_mutations),
        "dataMutations": data_mutations,
        "dataMutationsSha256": digest(canonical(data_mutations).encode()),
        "externalDockerMutation": external_docker_mutation,
        "legacyNetworkAttachments": legacy_network_attachments,
        "legacyNetworkAttachmentsSha256": digest(canonical(legacy_network_attachments).encode()),
        "legacyUnmanagedContainers": reconciliation["legacyUnmanagedContainers"],
        "previousReceiptDocumentId": reconciliation["previousReceiptDocumentId"],
        "releaseAuthorityDocumentId": reconciliation["releaseAuthorityDocumentId"],
        "releaseAuthoritySha256": reconciliation["releaseAuthoritySha256"],
        "runtimeEvidenceSha256": runtime_evidence_sha,
        "runtimeIdentity": reconciliation["runtimeIdentity"],
        "serviceTransitions": transitions,
        "serviceTransitionsSha256": digest(canonical(transitions).encode()),
        "status": "SEALED",
    }


def validate_external_reconciliation(value: object, observation: Dict[str, object]) -> Dict[str, object]:
    external = exact_keys(value, (
        "authority", "beganAtUnixSeconds", "containerRecreate", "controllerDockerMutation",
        "dataMutation", "dataMutations", "dataMutationsSha256", "externalDockerMutation",
        "legacyNetworkAttachments", "legacyNetworkAttachmentsSha256", "legacyUnmanagedContainers", "previousReceiptDocumentId",
        "releaseAuthorityDocumentId", "releaseAuthoritySha256", "runtimeEvidenceSha256", "runtimeIdentity",
        "serviceTransitions", "serviceTransitionsSha256", "status",
    ), "external authorized reconciliation")
    bound_authority = authority_for_external(external)
    if (
        external["authority"] != "ROOT_OPERATOR_EXPLICIT_V1_RECONCILIATION"
        or external["status"] != "SEALED"
        or external["controllerDockerMutation"] is not False
        or isinstance(external["beganAtUnixSeconds"], bool)
        or not isinstance(external["beganAtUnixSeconds"], int)
        or external["releaseAuthorityDocumentId"] != bound_authority["documentId"]
        or external["legacyUnmanagedContainers"] != bound_authority["legacyUnmanagedContainers"]
        or external["runtimeIdentity"] != bound_authority["runtimeIdentity"]
    ):
        stop("external authorized reconciliation authority/mutation truth is invalid.")
    for key in ("previousReceiptDocumentId", "releaseAuthorityDocumentId", "releaseAuthoritySha256", "runtimeEvidenceSha256", "serviceTransitionsSha256", "dataMutationsSha256", "legacyNetworkAttachmentsSha256"):
        sha256_value(external[key], f"external reconciliation {key}")
    data_mutations = validate_data_mutation_evidence(external["dataMutations"], bound_authority, external["beganAtUnixSeconds"])
    attachments = validate_actual_legacy_attachments(external["legacyNetworkAttachments"], bound_authority)
    if external["dataMutationsSha256"] != digest(canonical(data_mutations).encode()) or external["legacyNetworkAttachmentsSha256"] != digest(canonical(attachments).encode()):
        stop("external reconciliation data/network evidence digest differs.")
    transitions = external["serviceTransitions"]
    if not isinstance(transitions, list) or len(transitions) not in (len(CANONICAL_CONTAINERS), len(CANONICAL_CONTAINERS) + 1):
        stop("external reconciliation service transitions have invalid cardinality.")
    current_records = {record["name"]: record for record in observation["containers"]}
    current_names = []
    removed_names = []
    for index, transition in enumerate(transitions):
        transition = exact_keys(transition, ("current", "previous", "service", "status"), f"external reconciliation transition {index}")
        current = transition["current"]
        if current is not None:
            current = exact_keys(current, ("configHash", "containerId", "imageId", "imageReference", "name", "runtimeConfigSha256"), f"external reconciliation current identity {index}")
            expected_record = current_records.get(current["name"])
            if expected_record is None or current != transition_identity(expected_record) or transition["service"] != expected_record["service"]:
                stop("external reconciliation current service identity differs from the ACTIVE observation.")
            current_names.append(current["name"])
        previous = transition["previous"]
        if previous is not None:
            previous = exact_keys(previous, ("configHash", "containerId", "imageId", "imageReference", "name", "runtimeConfigSha256"), f"external reconciliation previous identity {index}")
            for key in ("configHash", "containerId", "runtimeConfigSha256"):
                sha256_value(previous[key], f"external reconciliation previous {key}")
            if not isinstance(previous["imageId"], str) or re.fullmatch(r"sha256:[a-f0-9]{64}", previous["imageId"]) is None or not isinstance(previous["imageReference"], str) or not previous["imageReference"]:
                stop("external reconciliation previous image ID is invalid.")
            allowed_previous_name = {current["name"]} if current is not None else {"enterprise-backup-scheduler"}
            if current is not None and current["name"] == CANONICAL_ALERT_DISPATCHER:
                allowed_previous_name.add(LEGACY_ALERT_DISPATCHER)
            if previous["name"] not in allowed_previous_name:
                stop("external reconciliation previous service name is not a declared predecessor.")
        expected_status = (
            "REMOVED" if current is None and previous is not None
            else "CREATED" if previous is None
            else "REPLACED" if previous["name"] != current["name"]
            else "RETAINED" if previous == current
            else "RECREATED"
        )
        if transition["status"] != expected_status:
            stop("external reconciliation service transition status is false.")
        if expected_status == "REMOVED":
            removed_names.append(previous["name"])
        if current is not None and current["name"] in PRESERVED_LEGACY_CONTAINERS and expected_status != "RETAINED":
            stop("external reconciliation recreated or changed one preserved legacy workload.")
    container_recreate = any(item["status"] in ("CREATED", "REMOVED", "REPLACED", "RECREATED") for item in transitions)
    docker_mutation = container_recreate or bool(attachments)
    if (
        sorted(current_names) != list(CANONICAL_CONTAINERS)
        or removed_names not in ([], ["enterprise-backup-scheduler"])
        or external["serviceTransitionsSha256"] != digest(canonical(transitions).encode())
        or external["containerRecreate"] is not container_recreate
        or external["externalDockerMutation"] is not docker_mutation
        or external["dataMutation"] is not bool(data_mutations)
    ):
        stop("external reconciliation transitions/mutation truth are not one closed canonical V1 sequence.")
    return external


def validate_reconciliation_runtime_evidence(
    reconciliation: Dict[str, object],
    checkpoint_sha: str,
    checkpoint_bytes: bytes,
    evidence_snapshots: Dict[str, bytes],
    observation: Dict[str, object],
) -> Dict[str, object]:
    checkpoint = parse_json(checkpoint_bytes, "fresh PRE-DEPLOY checkpoint")
    previous_state, _ = validate_reconciliation_rollback(reconciliation)
    generated = checkpoint.get("generatedAtUnixSeconds")
    if (
        isinstance(generated, bool)
        or not isinstance(generated, int)
        or generated < reconciliation["beganAtUnixSeconds"]
        or checkpoint_sha == previous_state["checkpointSha256"]
    ):
        stop("reconciliation seal checkpoint is not a new post-maintenance checkpoint.")
    timestamp_fields = (
        "capturedAtUnixSeconds", "completedAtUnixSeconds", "generatedAtUnixSeconds",
        "verifiedAtUnixSeconds", "writtenAtUnixSeconds",
    )
    now = int(time.time())
    for pathname, evidence_bytes in evidence_snapshots.items():
        evidence = parse_json(evidence_bytes, f"post-maintenance evidence {pathname}", True)
        timestamps = [evidence.get(key) for key in timestamp_fields if key in evidence]
        if (
            not timestamps
            or any(isinstance(item, bool) or not isinstance(item, int) for item in timestamps)
            or max(timestamps) < reconciliation["beganAtUnixSeconds"]
            or max(timestamps) > generated
            or now - max(timestamps) > MAX_BACKUP_AGE
        ):
            stop("every reconciliation evidence document must be fresh and generated after maintenance began.")
    runtime_path = EVIDENCE_PATHS["runtimeInventorySha256"]
    data = evidence_snapshots.get(runtime_path)
    if data is None:
        stop("reconciliation runtime identity evidence is missing.")
    value = exact_keys(parse_json(data, "reconciliation runtime identity evidence", True), (
        "activeManagedContainerNames", "candidateCommit", "candidateTree", "capturedAtUnixSeconds",
        "containerIdentities", "containerIdentitiesSha256", "dataMutations", "dataMutationsSha256",
        "expectedContainerNames", "legacyNetworkAttachments", "legacyNetworkAttachmentsSha256",
        "legacyNetworkMemberships", "legacyNetworkMembershipsSha256", "legacyRouteChecks", "legacyRouteChecksSha256",
        "legacyUnmanagedContainers", "preservedLegacyContainerNames", "releaseAuthorityDocumentId", "releaseAuthoritySha256",
        "runtimeIdentity", "schema", "serviceTransitions",
        "serviceTransitionsSha256", "sourceArchiveSha256", "status",
    ), "reconciliation runtime identity evidence")
    captured = value["capturedAtUnixSeconds"]
    identities = reconciliation_container_identities(observation)
    transitions = reconciliation_service_transitions(reconciliation["predecessorRuntimeIdentities"], observation)
    attachments, memberships = validate_legacy_network_target(reconciliation["predecessorRuntimeIdentities"], observation)
    data_mutations = validate_data_mutation_evidence(value["dataMutations"], began_at=reconciliation["beganAtUnixSeconds"])
    if EXACT_AUTHORITY is None or not isinstance(value["legacyRouteChecks"], list):
        stop("reconciliation legacy route checks are missing.")
    route_checks = []
    route_authority = {item["name"]: item for item in EXACT_AUTHORITY["legacyRouteChecks"]}
    for index, raw in enumerate(value["legacyRouteChecks"]):
        item = exact_keys(raw, (
            "checkedAtUnixSeconds", "containerName", "expectedStatus", "name", "observedStatus", "responseSha256", "status", "url",
        ), f"reconciliation legacy route check {index}")
        declared = route_authority.get(item["name"])
        checked = item["checkedAtUnixSeconds"]
        if (
            declared is None
            or {key: item[key] for key in ("containerName", "expectedStatus", "name", "url")} != declared
            or item["status"] != "PASS"
            or item["observedStatus"] != item["expectedStatus"]
            or isinstance(checked, bool)
            or not isinstance(checked, int)
            or checked < reconciliation["beganAtUnixSeconds"]
            or checked > generated
        ):
            stop("reconciliation legacy route check is not one fresh exact PASS result.")
        sha256_value(item["responseSha256"], "reconciliation legacy route response")
        route_checks.append(dict(item))
    if [item["name"] for item in route_checks] != sorted(route_authority) or value["legacyRouteChecksSha256"] != digest(canonical(route_checks).encode()):
        stop("reconciliation legacy route checks are incomplete, unordered, or digest-mismatched.")
    if (
        value["schema"] != "platform.v1-local-private-reconciliation-runtime/v1"
        or value["status"] != "PASS"
        or value["candidateCommit"] != CANDIDATE_COMMIT
        or value["candidateTree"] != CANDIDATE_TREE
        or value["sourceArchiveSha256"] != SOURCE_ARCHIVE_SHA256
        or value["releaseAuthorityDocumentId"] != reconciliation["releaseAuthorityDocumentId"]
        or value["releaseAuthoritySha256"] != reconciliation["releaseAuthoritySha256"]
        or value["expectedContainerNames"] != list(CANONICAL_CONTAINERS)
        or value["activeManagedContainerNames"] != sorted(ACTIVE_MANAGED_CONTAINERS)
        or value["preservedLegacyContainerNames"] != sorted(PRESERVED_LEGACY_CONTAINERS)
        or value["legacyUnmanagedContainers"] != [dict(item) for item in LEGACY_UNMANAGED_CONTAINERS]
        or EXACT_AUTHORITY is None
        or value["runtimeIdentity"] != EXACT_AUTHORITY["runtimeIdentity"]
        or value["containerIdentities"] != identities
        or value["containerIdentitiesSha256"] != digest(canonical(identities).encode())
        or value["serviceTransitions"] != transitions
        or value["serviceTransitionsSha256"] != digest(canonical(transitions).encode())
        or value["legacyNetworkAttachments"] != attachments
        or value["legacyNetworkAttachmentsSha256"] != digest(canonical(attachments).encode())
        or value["legacyNetworkMemberships"] != memberships
        or value["legacyNetworkMembershipsSha256"] != digest(canonical(memberships).encode())
        or value["legacyRouteChecks"] != route_checks
        or value["dataMutations"] != data_mutations
        or value["dataMutationsSha256"] != digest(canonical(data_mutations).encode())
        or isinstance(captured, bool)
        or not isinstance(captured, int)
        or captured < reconciliation["beganAtUnixSeconds"]
        or captured > generated
        or int(time.time()) - captured > MAX_CHECKPOINT_AGE
    ):
        stop("reconciliation runtime identity evidence is not exact, post-maintenance, and target-bound.")
    external = external_reconciliation_document(reconciliation, digest(data), transitions, attachments, data_mutations)
    return validate_external_reconciliation(external, observation)


def controller_identity() -> Dict[str, object]:
    controller = secure_file(CONTROLLER_PATH, "installed LOCAL_PRIVATE controller", 1024 * 1024, 0o555)
    unit = secure_file(UNIT_PATH, "installed LOCAL_PRIVATE systemd unit", 65536, 0o444)
    sudoers = secure_file(SUDOERS_PATH, "installed LOCAL_PRIVATE sudoers policy", 65536, 0o440)
    return {
        "installedPath": CONTROLLER_PATH,
        "sha256": digest(controller),
        "sudoersPath": SUDOERS_PATH,
        "sudoersSha256": digest(sudoers),
        "unitPath": UNIT_PATH,
        "unitSha256": digest(unit),
    }


def state_document(
    status: str,
    observation: Dict[str, object],
    install_sha: str,
    checkpoint_sha: str,
    created: int,
    external_reconciliation: Optional[Dict[str, object]] = None,
    aborted_reconciliation: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    result = {
        "candidateCommit": CANDIDATE_COMMIT,
        "candidateTree": CANDIDATE_TREE,
        "checkpointSha256": checkpoint_sha,
        "controller": controller_identity(),
        "createdAtUnixSeconds": created,
        "installReceiptSha256": install_sha,
        "observation": observation,
        "releaseRoot": RELEASE_ROOT,
        "schema": STATE_SCHEMA,
        "sourceArchiveSha256": SOURCE_ARCHIVE_SHA256,
        "status": status,
    }
    if external_reconciliation is not None:
        result["externalAuthorizedReconciliation"] = validate_external_reconciliation(external_reconciliation, observation)
    if aborted_reconciliation is not None:
        result["abortedAuthorizedReconciliation"] = validate_aborted_reconciliation_binding(aborted_reconciliation)
    return result


def validate_state(value: Dict[str, object], allow_activating: bool) -> Dict[str, object]:
    base_keys = ("candidateCommit", "candidateTree", "checkpointSha256", "controller", "createdAtUnixSeconds", "installReceiptSha256", "observation", "releaseRoot", "schema", "sourceArchiveSha256", "status")
    if not isinstance(value, dict) or value.get("schema") != STATE_SCHEMA:
        stop("LOCAL_PRIVATE state schema is invalid.")
    optional = []
    if "externalAuthorizedReconciliation" in value:
        optional.append("externalAuthorizedReconciliation")
        validate_external_reconciliation(value["externalAuthorizedReconciliation"], value["observation"])
    if "abortedAuthorizedReconciliation" in value:
        optional.append("abortedAuthorizedReconciliation")
        validate_aborted_reconciliation_binding(value["abortedAuthorizedReconciliation"])
    exact_keys(value, (*base_keys, *optional), "LOCAL_PRIVATE state")
    allowed = ("ACTIVATING", "ACTIVE") if allow_activating else ("ACTIVE",)
    document_binding(value, "LOCAL_PRIVATE state")
    if value["status"] not in allowed:
        stop("LOCAL_PRIVATE state binding/status is invalid.")
    sha256_value(value["checkpointSha256"], "state checkpoint")
    sha256_value(value["installReceiptSha256"], "state install receipt")
    if not isinstance(value["createdAtUnixSeconds"], int):
        stop("LOCAL_PRIVATE state timestamp is invalid.")
    return value


def read_state(allow_activating: bool = False) -> Dict[str, object]:
    return validate_state(parse_json(secure_file(STATE_FILE, "LOCAL_PRIVATE state", exact_mode=0o600), "LOCAL_PRIVATE state", True), allow_activating)


def rollback_paths(document_id: str) -> Tuple[str, str]:
    if not SHA256_RE.fullmatch(document_id):
        stop("rollback receipt document ID is invalid.")
    return (
        f"{STATE_DIR}/rollback-{document_id}-state.json",
        f"{STATE_DIR}/rollback-{document_id}-receipt.json",
    )


def planned_legacy_network_attachments(predecessor_identities: List[Dict[str, object]]) -> List[Dict[str, object]]:
    if EXACT_AUTHORITY is None:
        stop("legacy network attachment plan has no exact release authority.")
    previous = {item["name"]: item for item in predecessor_identities}
    result = []
    for attachment in EXACT_AUTHORITY["legacyNetworkAttachments"]:
        identity = previous.get(attachment["containerName"])
        if identity is None:
            stop("legacy network attachment authority names one missing predecessor container.")
        membership = identity.get("networkMembership")
        if not isinstance(membership, list):
            stop("legacy predecessor network membership is invalid.")
        existing = next((item for item in membership if item.get("networkName") == attachment["networkName"]), None)
        expected = {"aliases": attachment["aliases"], "networkName": attachment["networkName"]}
        if existing is None:
            result.append(dict(attachment))
        elif existing != expected:
            stop("legacy predecessor already has an exact target network with conflicting aliases.")
    return result


def reconciliation_document(
    state: Dict[str, object],
    receipt: Dict[str, object],
    install_sha: str,
    began_at: int,
    predecessor_identities: List[Dict[str, object]],
    rollback_scheduler_recovery: Dict[str, object],
    rollback_checkpoint_sha256: str,
) -> Dict[str, object]:
    if EXACT_AUTHORITY is None:
        stop("reconciliation cannot begin without one exact V1 release authority.")
    state_path, receipt_path = rollback_paths(receipt["documentId"])
    planned_attachments = planned_legacy_network_attachments(predecessor_identities)
    return {
        "activeManagedContainerNames": sorted(ACTIVE_MANAGED_CONTAINERS),
        "beganAtUnixSeconds": began_at,
        "candidateCommit": CANDIDATE_COMMIT,
        "candidateTree": CANDIDATE_TREE,
        "controller": controller_identity(),
        "disabledComposeServices": list(DISABLED_MANAGED_SERVICES),
        "expectedContainerNames": list(CANONICAL_CONTAINERS),
        "installReceiptSha256": install_sha,
        "legacyUnmanagedContainers": [dict(item) for item in LEGACY_UNMANAGED_CONTAINERS],
        "plannedLegacyNetworkAttachments": planned_attachments,
        "plannedLegacyNetworkAttachmentsSha256": digest(canonical(planned_attachments).encode()),
        "predecessorRuntimeIdentities": predecessor_identities,
        "predecessorRuntimeIdentitiesSha256": digest(canonical(predecessor_identities).encode()),
        "preservedLegacyContainerNames": sorted(PRESERVED_LEGACY_CONTAINERS),
        "previousReceiptDocumentId": receipt["documentId"],
        "previousReceiptPath": receipt_path,
        "previousReceiptSha256": digest(canonical_bytes(receipt)),
        "previousStatePath": state_path,
        "previousStateSha256": digest(canonical_bytes(state)),
        "releaseAuthorityDocumentId": EXACT_AUTHORITY["documentId"],
        "releaseAuthoritySha256": EXACT_AUTHORITY_SHA256,
        "releaseRoot": RELEASE_ROOT,
        "rollbackCheckpointSha256": rollback_checkpoint_sha256,
        "rollbackSchedulerRecovery": rollback_scheduler_recovery,
        "rollbackSchedulerRecoverySha256": digest(canonical(rollback_scheduler_recovery).encode()),
        "runtimeIdentity": EXACT_AUTHORITY["runtimeIdentity"],
        "schema": RECONCILIATION_SCHEMA,
        "sourceArchiveSha256": SOURCE_ARCHIVE_SHA256,
        "status": "RECONCILING",
    }


def validate_reconciliation(value: Dict[str, object]) -> Dict[str, object]:
    exact_keys(value, (
        "activeManagedContainerNames", "beganAtUnixSeconds", "candidateCommit", "candidateTree", "controller",
        "disabledComposeServices", "expectedContainerNames", "installReceiptSha256",
        "legacyUnmanagedContainers",
        "plannedLegacyNetworkAttachments", "plannedLegacyNetworkAttachmentsSha256",
        "predecessorRuntimeIdentities", "predecessorRuntimeIdentitiesSha256", "preservedLegacyContainerNames",
        "previousReceiptDocumentId", "previousReceiptPath", "previousReceiptSha256",
        "previousStatePath", "previousStateSha256", "releaseAuthorityDocumentId", "releaseAuthoritySha256", "releaseRoot", "runtimeIdentity", "schema",
        "rollbackCheckpointSha256", "rollbackSchedulerRecovery", "rollbackSchedulerRecoverySha256", "sourceArchiveSha256", "status",
    ), "LOCAL_PRIVATE reconciliation")
    if (
        value["schema"] != RECONCILIATION_SCHEMA
        or value["status"] != "RECONCILING"
        or value["candidateCommit"] != CANDIDATE_COMMIT
        or value["candidateTree"] != CANDIDATE_TREE
        or value["sourceArchiveSha256"] != SOURCE_ARCHIVE_SHA256
        or value["releaseRoot"] != RELEASE_ROOT
        or value["expectedContainerNames"] != list(CANONICAL_CONTAINERS)
        or value["activeManagedContainerNames"] != sorted(ACTIVE_MANAGED_CONTAINERS)
        or value["preservedLegacyContainerNames"] != sorted(PRESERVED_LEGACY_CONTAINERS)
        or value["legacyUnmanagedContainers"] != [dict(item) for item in LEGACY_UNMANAGED_CONTAINERS]
        or value["disabledComposeServices"] != list(DISABLED_MANAGED_SERVICES)
        or EXACT_AUTHORITY is None
        or value["releaseAuthorityDocumentId"] != EXACT_AUTHORITY["documentId"]
        or value["releaseAuthoritySha256"] != EXACT_AUTHORITY_SHA256
        or value["runtimeIdentity"] != EXACT_AUTHORITY["runtimeIdentity"]
    ):
        stop("LOCAL_PRIVATE reconciliation binding/status is invalid.")
    if isinstance(value["beganAtUnixSeconds"], bool) or not isinstance(value["beganAtUnixSeconds"], int):
        stop("LOCAL_PRIVATE reconciliation timestamp is invalid.")
    for key in ("installReceiptSha256", "plannedLegacyNetworkAttachmentsSha256", "predecessorRuntimeIdentitiesSha256", "previousReceiptDocumentId", "previousReceiptSha256", "previousStateSha256", "releaseAuthorityDocumentId", "releaseAuthoritySha256", "rollbackCheckpointSha256", "rollbackSchedulerRecoverySha256"):
        sha256_value(value[key], f"reconciliation {key}")
    if value["rollbackSchedulerRecoverySha256"] != digest(canonical(value["rollbackSchedulerRecovery"]).encode()):
        stop("LOCAL_PRIVATE reconciliation rollback scheduler recovery digest differs.")
    validate_bound_recovery_export(value["rollbackSchedulerRecovery"], True)
    predecessor_identities = value["predecessorRuntimeIdentities"]
    if not isinstance(predecessor_identities, list) or value["predecessorRuntimeIdentitiesSha256"] != digest(canonical(predecessor_identities).encode()):
        stop("LOCAL_PRIVATE reconciliation predecessor runtime identities are invalid.")
    identity_names = [item.get("name") for item in predecessor_identities if isinstance(item, dict)]
    if len(identity_names) != len(predecessor_identities) or tuple(sorted(identity_names)) not in CLOSED_CONTAINER_SEQUENCES:
        stop("LOCAL_PRIVATE reconciliation predecessor semantic inventory is not one closed V1 profile.")
    planned = validate_actual_legacy_attachments(value["plannedLegacyNetworkAttachments"])
    if value["plannedLegacyNetworkAttachmentsSha256"] != digest(canonical(planned).encode()):
        stop("LOCAL_PRIVATE reconciliation planned legacy network attachment digest differs.")
    expected_state_path, expected_receipt_path = rollback_paths(value["previousReceiptDocumentId"])
    if value["previousStatePath"] != expected_state_path or value["previousReceiptPath"] != expected_receipt_path:
        stop("LOCAL_PRIVATE reconciliation rollback paths are not fixed.")
    if value["controller"] != controller_identity():
        stop("LOCAL_PRIVATE reconciliation controller identity drifted.")
    return value


def read_reconciliation() -> Dict[str, object]:
    return validate_reconciliation(parse_json(
        secure_file(RECONCILIATION_FILE, "LOCAL_PRIVATE reconciliation", exact_mode=0o600),
        "LOCAL_PRIVATE reconciliation",
        True,
    ))


ABORT_RECORD_FIELDS = (
    "authorityDocumentId", "authoritySha256", "completedAtUnixSeconds", "journalSha256",
    "residualDataMutations", "residualDataMutationsSha256", "schema", "status", "transactionId",
)


def validate_aborted_reconciliation_binding(value: object) -> Dict[str, object]:
    binding = exact_keys(value, (*ABORT_RECORD_FIELDS, "recordPath", "recordSha256"), "aborted authorized reconciliation")
    for key in ("authorityDocumentId", "authoritySha256", "journalSha256", "residualDataMutationsSha256", "recordSha256", "transactionId"):
        sha256_value(binding[key], f"aborted reconciliation {key}")
    completed = binding["completedAtUnixSeconds"]
    residual = binding["residualDataMutations"]
    if (
        binding["schema"] != ABORT_RECORD_SCHEMA
        or isinstance(completed, bool)
        or not isinstance(completed, int)
        or completed < 1700000000
        or completed > int(time.time()) + 60
        or not isinstance(residual, list)
        or binding["residualDataMutationsSha256"] != digest(canonical(residual).encode())
        or binding["status"] != ("ABORTED_WITH_RESIDUAL_DATA_MUTATIONS" if residual else "ABORTED_NO_DATA_MUTATION")
    ):
        stop("aborted reconciliation status/timestamp/mutation binding is invalid.")
    authority = authority_for_external({
        "releaseAuthorityDocumentId": binding["authorityDocumentId"],
        "releaseAuthoritySha256": binding["authoritySha256"],
    })
    allowed = {}
    for raw in authority["authorizedDataMutations"]:
        item = exact_keys(raw, ("id", "service", "target", "type"), "aborted reconciliation authorized data mutation")
        identifier = item["id"]
        if not isinstance(identifier, str) or SERVICE_RE.fullmatch(identifier) is None or identifier in allowed:
            stop("aborted reconciliation authority contains an invalid or duplicate data mutation ID.")
        allowed[identifier] = item
    normalized = []
    seen = set()
    for index, raw in enumerate(residual):
        item = exact_keys(raw, ("authorityId", "evidencePath", "evidenceSha256"), f"aborted residual data mutation {index}")
        authority_id = item["authorityId"]
        evidence_sha = sha256_value(item["evidenceSha256"], f"aborted residual data mutation {index} evidence")
        expected_path = f"{STATE_DIR}/data-mutation-evidence/{binding['authorityDocumentId']}-{authority_id}-{evidence_sha}.json"
        if authority_id not in allowed or authority_id in seen or item["evidencePath"] != expected_path:
            stop("aborted residual data mutation exceeds its exact release authority or fixed evidence path.")
        evidence = secure_file(expected_path, f"aborted residual data mutation {authority_id} evidence", MAX_JSON, 0o444)
        parse_json(evidence, f"aborted residual data mutation {authority_id} evidence", True)
        if digest(evidence) != evidence_sha:
            stop("aborted residual data mutation evidence bytes differ from the receipt binding.")
        seen.add(authority_id)
        normalized.append(item)
    if normalized != sorted(normalized, key=lambda item: item["authorityId"]):
        stop("aborted residual data mutations are not one sorted closed sequence.")
    record = {key: binding[key] for key in ABORT_RECORD_FIELDS}
    record_bytes = canonical_bytes(record)
    if digest(record_bytes) != binding["recordSha256"]:
        stop("aborted reconciliation record digest is invalid.")
    expected_record_path = f"{ABORT_RECORD_ARCHIVE_DIR}/{binding['transactionId']}-{binding['recordSha256']}.json"
    if binding["recordPath"] != expected_record_path:
        stop("aborted reconciliation immutable record path is invalid.")
    if secure_file(expected_record_path, "immutable reconciliation abort record", MAX_JSON, 0o444) != record_bytes:
        stop("immutable reconciliation abort record bytes differ from the ACTIVE binding.")
    return binding


def consume_current_abort_record(reconciliation: Dict[str, object]) -> Dict[str, object]:
    record_bytes = secure_file(ABORT_RECORD_FILE, "current reconciliation abort record", MAX_JSON, 0o444)
    record = exact_keys(parse_json(record_bytes, "current reconciliation abort record", True), ABORT_RECORD_FIELDS, "current reconciliation abort record")
    marker_bytes = secure_file(RECONCILIATION_FILE, "LOCAL_PRIVATE reconciliation", MAX_JSON, 0o600)
    authority_bytes = secure_file(EXACT_RELEASE_AUTHORITY, "V1 exact release authority", MAX_JSON, 0o444)
    journal_bytes = secure_file(RECONCILE_JOURNAL_FILE, "aborted reconciliation journal", MAX_JSON, 0o600)
    parse_json(journal_bytes, "aborted reconciliation journal", True)
    record_sha = digest(record_bytes)
    binding = {
        **record,
        "recordPath": f"{ABORT_RECORD_ARCHIVE_DIR}/{record['transactionId']}-{record_sha}.json",
        "recordSha256": record_sha,
    }
    binding = validate_aborted_reconciliation_binding(binding)
    if (
        record["authorityDocumentId"] != reconciliation["releaseAuthorityDocumentId"]
        or record["authoritySha256"] != reconciliation["releaseAuthoritySha256"]
        or record["authoritySha256"] != digest(authority_bytes)
        or record["journalSha256"] != digest(journal_bytes)
        or record["transactionId"] != digest(authority_bytes + marker_bytes)
        or record["completedAtUnixSeconds"] < reconciliation["beganAtUnixSeconds"]
        or secure_file(ABORT_RECORD_FILE, "current reconciliation abort record", MAX_JSON, 0o444) != record_bytes
    ):
        stop("current reconciliation abort record is not bound to the exact authority, marker, journal, and maintenance window.")
    return binding


def validate_reconciliation_rollback(reconciliation: Dict[str, object]) -> Tuple[Dict[str, object], Dict[str, object]]:
    state_bytes = secure_file(reconciliation["previousStatePath"], "immutable rollback state", exact_mode=0o444)
    receipt_bytes = secure_file(reconciliation["previousReceiptPath"], "immutable rollback receipt", exact_mode=0o444)
    if digest(state_bytes) != reconciliation["previousStateSha256"] or digest(receipt_bytes) != reconciliation["previousReceiptSha256"]:
        stop("immutable rollback state/receipt digest differs from the reconciliation marker.")
    state = validate_state(parse_json(state_bytes, "immutable rollback state", True), False)
    receipt = validate_receipt_document(parse_json(receipt_bytes, "immutable rollback receipt", True))
    if receipt["documentId"] != reconciliation["previousReceiptDocumentId"]:
        stop("immutable rollback receipt document ID differs from the reconciliation marker.")
    if receipt_from_state(state, receipt.get("activatedAtUnixSeconds")) != receipt:
        stop("immutable rollback receipt differs from its preserved state.")
    observation_names(state["observation"], "immutable rollback state")
    return state, receipt


def local_artifact_trust(observation: Dict[str, object]) -> Dict[str, object]:
    subjects = [{key: item[key] for key in ("configHash", "containerId", "imageAvailability", "imageId", "name")} for item in observation["containers"]]
    recovery = observation["schedulerRecovery"]
    return {
        "mode": "LOCAL_DOCKER_IMMUTABLE_IMAGE_ID",
        "schedulerRecovery": {
            "archiveFormat": recovery["archiveFormat"],
            "configDigest": recovery["configDigest"],
            "configHash": recovery["configHash"],
            "containerName": "enterprise-backup-scheduler",
            "containerId": recovery["containerId"],
            "exportLabels": recovery["exportLabels"],
            "exportPath": recovery["exportPath"],
            "exportSha256": recovery["exportSha256"],
            "exportSizeBytes": recovery["exportSizeBytes"],
            "imageIndexDigest": recovery["imageIndexDigest"],
            "imageIndexPath": recovery["imageIndexPath"],
            "imageManifestDigest": recovery["imageManifestDigest"],
            "manifestConfig": recovery["manifestConfig"],
            "recoveryImageId": recovery["recoveryImageId"],
            "recoveryTag": recovery["recoveryTag"],
            "runningImageId": recovery["runningImageId"],
            "status": "RECOVERY_IMAGE_EXPORT_BOUND",
        },
        "status": "PASS",
        "subjects": subjects,
    }


def with_document_id(value: Dict[str, object]) -> Dict[str, object]:
    result = dict(value)
    result["documentId"] = digest(canonical(value).encode())
    return result


def receipt_from_state(state: Dict[str, object], activated_at: int) -> Dict[str, object]:
    observation = state["observation"]
    containers = observation["containers"]
    expected_names = observation_names(observation, "receipt state observation")
    container_count = len(expected_names)
    running_count = sum(1 for item in containers if item.get("state") == "running")
    exited_count = sum(1 for item in containers if item.get("state") == "exited")
    external = state.get("externalAuthorizedReconciliation")
    aborted = state.get("abortedAuthorizedReconciliation")
    is_external_reconciliation = external is not None
    if is_external_reconciliation:
        external = validate_external_reconciliation(external, observation)
    if aborted is not None:
        aborted = validate_aborted_reconciliation_binding(aborted)
    residual_data_mutation = aborted is not None and bool(aborted["residualDataMutations"])
    base = {
        "activatedAtUnixSeconds": activated_at,
        "authorityMode": "LOCAL_PRIVATE",
        "candidateCommit": state["candidateCommit"],
        "candidateTree": state["candidateTree"],
        "checkpointSha256": state["checkpointSha256"],
        "containerRecreate": external["containerRecreate"] if is_external_reconciliation else False,
        "controller": state["controller"],
        "dataMutation": (external["dataMutation"] if is_external_reconciliation else False) or residual_data_mutation,
        "dockerMutation": external["externalDockerMutation"] if is_external_reconciliation else False,
        "dockerControlPlane": {
            "mode": "LOCAL_ROOT_SYSTEMD_SUPERVISOR",
            "providerBrokerStatus": "READY_BUT_DISABLED",
            "service": UNIT_NAME,
            "status": "ACTIVE",
        },
        "externalDependencies": list(EXTERNAL_DEPENDENCIES),
        "hostControlMutation": True,
        "installReceiptSha256": state["installReceiptSha256"],
        "localArtifactTrust": local_artifact_trust(observation),
        "mutationModel": (
            "ABORTED_EXTERNAL_AUTHORIZED_RECONCILIATION"
            if aborted is not None
            else "EXTERNAL_AUTHORIZED_RECONCILIATION" if is_external_reconciliation else "ADDITIVE_ADOPTION"
        ),
        "mutationPerformed": True,
        "networkIsolation": {"policy": "EDGE_PUBLISHED_PORT_ALLOWLIST", "publishedPorts": observation["publishedPorts"], "status": "PASS"},
        "providerComponents": list(PROVIDER_COMPONENTS),
        "readyButDisabled": list(READY_BUT_DISABLED),
        "releaseRoot": state["releaseRoot"],
        "runtime": {"containerCount": container_count, "containers": containers, "daemon": observation["daemon"], "exitedCount": exited_count, "rawDockerAuthority": observation["rawDockerAuthority"], "runningCount": running_count},
        "schema": RECEIPT_SCHEMA,
        "sourceArchiveSha256": state["sourceArchiveSha256"],
        "status": "ACTIVE",
        "supervisor": {"active": True, "enabled": True, "service": UNIT_NAME, "status": "ACTIVE", "type": "ROOT_SYSTEMD_NOTIFY"},
    }
    if is_external_reconciliation:
        base["externalAuthorizedReconciliation"] = external
    if aborted is not None:
        base["abortedAuthorizedReconciliation"] = aborted
    return with_document_id(base)


def validate_receipt_document(receipt: Dict[str, object]) -> Dict[str, object]:
    document_id = receipt.get("documentId")
    without = dict(receipt)
    without.pop("documentId", None)
    if not isinstance(document_id, str) or document_id != digest(canonical(without).encode()):
        stop("LOCAL_PRIVATE receipt document ID is invalid.")
    if receipt.get("schema") != RECEIPT_SCHEMA or receipt.get("status") != "ACTIVE" or receipt.get("authorityMode") != "LOCAL_PRIVATE":
        stop("LOCAL_PRIVATE receipt status/schema is invalid.")
    return receipt


def systemctl(arguments: List[str], label: str) -> str:
    return run([SYSTEMCTL, *arguments], f"systemctl {label}", 60).decode("utf-8", errors="strict").strip()


def ensure_supervisor_active() -> None:
    systemctl(["daemon-reload"], "daemon-reload")
    systemctl(["enable", "--now", UNIT_NAME], "enable --now")
    if systemctl(["is-enabled", UNIT_NAME], "is-enabled") != "enabled":
        stop("LOCAL_PRIVATE supervisor is not enabled.")
    if systemctl(["is-active", UNIT_NAME], "is-active") != "active":
        stop("LOCAL_PRIVATE supervisor is not active.")


def supervisor_is_enabled_and_active() -> bool:
    enabled = run_result([SYSTEMCTL, "is-enabled", UNIT_NAME], "systemctl is-enabled", 30)
    active = run_result([SYSTEMCTL, "is-active", UNIT_NAME], "systemctl is-active", 30)
    return (
        enabled.returncode == 0
        and enabled.stdout.decode("utf-8", errors="strict").strip() == "enabled"
        and active.returncode == 0
        and active.stdout.decode("utf-8", errors="strict").strip() == "active"
    )


def supervisor_is_disabled_and_inactive() -> bool:
    enabled = run_result([SYSTEMCTL, "is-enabled", UNIT_NAME], "systemctl is-enabled", 30)
    active = run_result([SYSTEMCTL, "is-active", UNIT_NAME], "systemctl is-active", 30)
    return (
        enabled.returncode != 0
        and enabled.stdout.decode("utf-8", errors="strict").strip() == "disabled"
        and active.returncode != 0
        and active.stdout.decode("utf-8", errors="strict").strip() == "inactive"
    )


def disable_supervisor() -> None:
    systemctl(["disable", "--now", UNIT_NAME], "disable --now")
    if not supervisor_is_disabled_and_inactive():
        stop("LOCAL_PRIVATE supervisor is not disabled and inactive.")


def acquire_lock() -> int:
    pathname = physical(LOCK_FILE)
    no_symlink_chain(os.path.dirname(pathname), "LOCAL_PRIVATE lock parent")
    fd = os.open(pathname, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    metadata = os.fstat(fd)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_uid != OWNER_UID or mode(metadata) != 0o600:
        os.close(fd)
        stop("LOCAL_PRIVATE lock identity is unsafe.")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        stop("another LOCAL_PRIVATE control transaction is active.", 75)
    return fd


def acquire_transaction_lock() -> int:
    """Serialize every authority/runtime maintenance mutation across V1 tools.

    This lock is deliberately acquired before the controller-local lock.  The
    reconciler and the control-artifact installer use the same ordering, so a
    prepare cannot publish a new authority while begin-maintenance is binding
    the previous one, and abort/seal cannot overlap a Docker mutation.
    """
    pathname = physical(TRANSACTION_LOCK_FILE)
    no_symlink_chain(os.path.dirname(pathname), "LOCAL_PRIVATE transaction lock parent")
    fd = os.open(pathname, os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
    metadata = os.fstat(fd)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_uid != OWNER_UID or mode(metadata) != 0o600:
        os.close(fd)
        stop("LOCAL_PRIVATE transaction lock identity is unsafe.")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        stop("another V1 LOCAL_PRIVATE maintenance transaction is active.", 75)
    return fd


def validate_predecessor_controller(value: object) -> None:
    legacy_fields = {"installedPath", "sha256", "unitPath", "unitSha256"}
    current_fields = legacy_fields | {"sudoersPath", "sudoersSha256"}
    if not isinstance(value, dict) or set(value) not in (legacy_fields, current_fields):
        stop("predecessor controller identity is not one closed historical/current V1 form.")
    controller = value
    if controller["installedPath"] != CONTROLLER_PATH or controller["unitPath"] != UNIT_PATH:
        stop("predecessor controller installed paths are invalid.")
    sha256_value(controller["sha256"], "predecessor controller")
    sha256_value(controller["unitSha256"], "predecessor controller unit")
    if set(controller) == current_fields:
        if controller["sudoersPath"] != SUDOERS_PATH:
            stop("predecessor controller sudoers path is invalid.")
        sha256_value(controller["sudoersSha256"], "predecessor controller sudoers")


def active_baseline_for_reconciliation() -> Tuple[str, Dict[str, object], Dict[str, object]]:
    state = read_state(False)
    predecessor_install_sha = validate_release_and_install(state)
    if state["installReceiptSha256"] != predecessor_install_sha:
        stop("LOCAL_PRIVATE predecessor state install evidence drifted.")
    validate_predecessor_controller(state["controller"])
    expected_names = observation_names(state["observation"], "LOCAL_PRIVATE predecessor state")
    if tuple(sorted(expected_names)) not in (tuple(sorted(HISTORIC_CONTAINERS)), LEGACY_CONTAINERS, CANONICAL_CONTAINERS):
        stop("LOCAL_PRIVATE reconciliation predecessor is not one declared V1 baseline.")
    receipt = validate_receipt_document(parse_json(
        secure_file(RECEIPT_FILE, "LOCAL_PRIVATE active receipt", exact_mode=0o444),
        "LOCAL_PRIVATE active receipt",
        True,
    ))
    if receipt_from_state(state, receipt.get("activatedAtUnixSeconds")) != receipt:
        stop("LOCAL_PRIVATE predecessor receipt differs from its root state.")
    validate_predecessor_runtime_snapshot(state["observation"], stable_runtime_identities(expected_names))
    if not supervisor_is_enabled_and_active():
        stop("LOCAL_PRIVATE predecessor supervisor is not enabled and active.")
    target_install_sha = validate_release_and_install()
    return target_install_sha, state, receipt


def reconciliation_status() -> Dict[str, object]:
    reconciliation = read_reconciliation()
    if validate_release_and_install() != reconciliation["installReceiptSha256"]:
        stop("LOCAL_PRIVATE reconciliation install evidence drifted.")
    previous_state, previous_receipt = validate_reconciliation_rollback(reconciliation)
    state_bytes = secure_file(STATE_FILE, "LOCAL_PRIVATE state", exact_mode=0o600)
    receipt_bytes = secure_file(RECEIPT_FILE, "LOCAL_PRIVATE active receipt", exact_mode=0o444)
    if digest(state_bytes) == reconciliation["previousStateSha256"]:
        if digest(receipt_bytes) != reconciliation["previousReceiptSha256"]:
            stop("LOCAL_PRIVATE reconciliation retained state but lost its predecessor receipt.")
        if parse_json(state_bytes, "LOCAL_PRIVATE state", True) != previous_state or parse_json(receipt_bytes, "LOCAL_PRIVATE active receipt", True) != previous_receipt:
            stop("LOCAL_PRIVATE predecessor bytes differ from immutable rollback evidence.")
        return reconciliation
    state = validate_state(parse_json(state_bytes, "LOCAL_PRIVATE state", True), True)
    state_names = observation_names(state["observation"], "LOCAL_PRIVATE reconciliation intermediate state")
    if "externalAuthorizedReconciliation" not in state and tuple(sorted(state_names)) in (tuple(sorted(HISTORIC_CONTAINERS)), LEGACY_CONTAINERS):
        if (
            state["controller"] != reconciliation["controller"]
            or state["installReceiptSha256"] != reconciliation["installReceiptSha256"]
            or state["checkpointSha256"] != reconciliation["rollbackCheckpointSha256"]
        ):
            stop("LOCAL_PRIVATE abort rebaseline is not transaction-bound.")
        receipt = validate_receipt_document(parse_json(receipt_bytes, "LOCAL_PRIVATE active receipt", True))
        if digest(receipt_bytes) != reconciliation["previousReceiptSha256"] and receipt_from_state(state, receipt.get("activatedAtUnixSeconds")) != receipt:
            stop("LOCAL_PRIVATE abort rebaseline receipt differs from state.")
        return reconciliation
    if state.get("schema") != STATE_SCHEMA or "externalAuthorizedReconciliation" not in state:
        stop("LOCAL_PRIVATE reconciliation target state is not the closed reconciled V1 form.")
    if state["controller"] != reconciliation["controller"] or state["installReceiptSha256"] != reconciliation["installReceiptSha256"]:
        stop("LOCAL_PRIVATE reconciliation target state binding drifted.")
    if observation_names(state["observation"], "LOCAL_PRIVATE reconciliation target state") != CANONICAL_EXPECTED_NAMES:
        stop("LOCAL_PRIVATE reconciliation target state is not the canonical exact-main set.")
    validate_reconciliation_target_binding(state, reconciliation, previous_state)
    receipt = validate_receipt_document(parse_json(receipt_bytes, "LOCAL_PRIVATE active receipt", True))
    if receipt != previous_receipt and receipt_from_state(state, receipt.get("activatedAtUnixSeconds")) != receipt:
        stop("LOCAL_PRIVATE reconciliation receipt is neither predecessor nor target evidence.")
    return reconciliation


def reconciliation_retains_predecessor_state(reconciliation: Dict[str, object]) -> bool:
    return digest(secure_file(STATE_FILE, "LOCAL_PRIVATE state", exact_mode=0o600)) == reconciliation["previousStateSha256"]


def validate_reconciliation_target_binding(
    state: Dict[str, object],
    reconciliation: Dict[str, object],
    previous_state: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    if state.get("schema") != STATE_SCHEMA or "externalAuthorizedReconciliation" not in state:
        stop("LOCAL_PRIVATE reconciliation target state is not the closed reconciled V1 form.")
    if previous_state is None:
        previous_state, _ = validate_reconciliation_rollback(reconciliation)
    external = validate_external_reconciliation(state["externalAuthorizedReconciliation"], state["observation"])
    expected_transitions = reconciliation_service_transitions(reconciliation["predecessorRuntimeIdentities"], state["observation"])
    expected_attachments, _ = validate_legacy_network_target(reconciliation["predecessorRuntimeIdentities"], state["observation"])
    expected_external = external_reconciliation_document(
        reconciliation,
        external["runtimeEvidenceSha256"],
        expected_transitions,
        expected_attachments,
        external["dataMutations"],
    )
    if (
        external != expected_external
        or state["checkpointSha256"] == previous_state["checkpointSha256"]
        or state["createdAtUnixSeconds"] < reconciliation["beganAtUnixSeconds"]
    ):
        stop("LOCAL_PRIVATE reconciliation target state is not bound to its predecessor, fresh checkpoint, and exact service transitions.")
    return external


def begin_maintenance() -> Dict[str, object]:
    ensure_private_directory(STATE_DIR)
    if os.path.lexists(physical(RECONCILIATION_FILE)):
        reconciliation = reconciliation_status()
        if not reconciliation_retains_predecessor_state(reconciliation):
            stop("LOCAL_PRIVATE seal has started; resume seal instead of reopening maintenance.")
        if digest(secure_file(RECEIPT_FILE, "LOCAL_PRIVATE active receipt", exact_mode=0o444)) != reconciliation["previousReceiptSha256"]:
            stop("LOCAL_PRIVATE seal receipt transition has started; resume seal.")
        checkpoint_sha, _, rollback_recovery, _, _ = validate_checkpoint()
        if (
            checkpoint_sha != reconciliation["rollbackCheckpointSha256"]
            or rollback_recovery != reconciliation["rollbackSchedulerRecovery"]
        ):
            stop("LOCAL_PRIVATE maintenance retry no longer has its exact fresh PRE checkpoint/recovery evidence.")
        disable_supervisor()
        return reconciliation
    install_sha, state, receipt = active_baseline_for_reconciliation()
    predecessor_identities = stable_runtime_identities(observation_names(state["observation"], "LOCAL_PRIVATE predecessor state"))
    rollback_checkpoint_sha, _, rollback_recovery, _, _ = validate_checkpoint()
    # Promote the live scheduler identity into top-level binding keys: the
    # reconciliation retry/seal validators require the closed 16-key recovery
    # object while the export parser yields the 14-key archive-derived set.
    rollback_recovery = {
        **rollback_recovery,
        "configHash": rollback_recovery["exportLabels"][RECOVERY_LABELS["configHash"]],
        "containerId": rollback_recovery["exportLabels"][RECOVERY_LABELS["containerId"]],
    }
    scheduler = next((item for item in predecessor_identities if item["name"] == "enterprise-backup-scheduler"), None)
    if scheduler is not None and (
        rollback_recovery["runningImageId"] != scheduler["imageId"]
        or rollback_recovery["exportLabels"].get(RECOVERY_LABELS["configHash"]) != scheduler["configHash"]
        or rollback_recovery["exportLabels"].get(RECOVERY_LABELS["containerId"]) != scheduler["containerId"]
    ):
        stop("fresh rollback recovery artifact is not bound to the live predecessor scheduler.")
    reconciliation = reconciliation_document(state, receipt, install_sha, int(time.time()), predecessor_identities, rollback_recovery, rollback_checkpoint_sha)
    preserve_immutable_document(reconciliation["previousStatePath"], state, "immutable rollback state")
    preserve_immutable_document(reconciliation["previousReceiptPath"], receipt, "immutable rollback receipt")
    atomic_write(RECONCILIATION_FILE, reconciliation, 0o600, False)
    disable_supervisor()
    return reconciliation


def test_abort_fault(boundary: str) -> None:
    if TEST_ROOT is not None and os.environ.get("PLATFORM_V1_LOCAL_PRIVATE_TEST_ABORT_FAULT") == boundary:
        os._exit(86)


def abort_maintenance() -> Dict[str, object]:
    if not os.path.lexists(physical(RECONCILIATION_FILE)):
        return verify_active()
    reconciliation = read_reconciliation()
    aborted_reconciliation = consume_current_abort_record(reconciliation)
    previous_state, previous_receipt = validate_reconciliation_rollback(reconciliation)
    previous_names = observation_names(previous_state["observation"], "LOCAL_PRIVATE abort predecessor")
    current_identities = stable_runtime_identities(previous_names)
    if current_identities != reconciliation["predecessorRuntimeIdentities"]:
        stop("abort requires external per-service rollback and removal of only transaction-added legacy network attachments before controller rebaseline.")
    if not supervisor_is_disabled_and_inactive():
        disable_supervisor()
    if previous_names == CANONICAL_EXPECTED_NAMES:
        abort_state = state_document(
            "ACTIVE",
            previous_state["observation"],
            previous_state["installReceiptSha256"],
            previous_state["checkpointSha256"],
            int(time.time()),
            previous_state.get("externalAuthorizedReconciliation"),
            aborted_reconciliation,
        )
        atomic_write(STATE_FILE, abort_state, 0o600, True)
        test_abort_fault("AFTER_STATE_REBASELINE")
        abort_receipt = receipt_from_state(abort_state, int(time.time()))
        atomic_write(RECEIPT_FILE, abort_receipt, 0o444, True)
        test_abort_fault("AFTER_RECEIPT_REBASELINE")
        ensure_supervisor_active()
        test_abort_fault("AFTER_SUPERVISOR_ACTIVATION")
        if canonical(stable_observation(previous_state["observation"]["schedulerRecovery"], previous_names, False)) != canonical(previous_state["observation"]):
            stop("reconciled predecessor changed before abort transaction closure.")
        test_abort_fault("BEFORE_MARKER_REMOVAL")
        remove_exact_document(RECONCILIATION_FILE, reconciliation, "LOCAL_PRIVATE reconciliation")
        return verify_active()
    if tuple(sorted(previous_names)) not in (tuple(sorted(HISTORIC_CONTAINERS)), LEGACY_CONTAINERS):
        stop("abort predecessor is not one closed V1 profile.")
    observation = stable_observation(reconciliation["rollbackSchedulerRecovery"], previous_names, False)
    validate_predecessor_runtime_snapshot(previous_state["observation"], current_identities)
    abort_state = state_document(
        "ACTIVE",
        observation,
        reconciliation["installReceiptSha256"],
        reconciliation["rollbackCheckpointSha256"],
        int(time.time()),
        None,
        aborted_reconciliation,
    )
    atomic_write(STATE_FILE, abort_state, 0o600, True)
    test_abort_fault("AFTER_STATE_REBASELINE")
    abort_receipt = receipt_from_state(abort_state, int(time.time()))
    atomic_write(RECEIPT_FILE, abort_receipt, 0o444, True)
    test_abort_fault("AFTER_RECEIPT_REBASELINE")
    ensure_supervisor_active()
    test_abort_fault("AFTER_SUPERVISOR_ACTIVATION")
    if canonical(stable_observation(observation["schedulerRecovery"], previous_names, False)) != canonical(observation):
        stop("abort runtime changed before transaction closure.")
    test_abort_fault("BEFORE_MARKER_REMOVAL")
    remove_exact_document(RECONCILIATION_FILE, reconciliation, "LOCAL_PRIVATE reconciliation")
    return verify_active()


def active_profile_names(state: Dict[str, object], label: str) -> frozenset[str]:
    names = observation_names(state["observation"], label)
    if state["schema"] == STATE_SCHEMA and "externalAuthorizedReconciliation" not in state and names == EXPECTED_NAMES:
        return names
    if state["schema"] == STATE_SCHEMA and "externalAuthorizedReconciliation" in state and names == CANONICAL_EXPECTED_NAMES:
        return names
    stop("LOCAL_PRIVATE ACTIVE profile is neither the historical V1 receipt nor the canonical reconciled V1 receipt.")


def verify_active() -> Dict[str, object]:
    state = read_state(False)
    install_sha = validate_release_and_install(state)
    if state["installReceiptSha256"] != install_sha:
        stop("LOCAL_PRIVATE state install evidence drifted.")
    validate_predecessor_controller(state["controller"])
    validate_bound_recovery_export(state["observation"]["schedulerRecovery"], True)
    receipt = validate_receipt_document(parse_json(secure_file(RECEIPT_FILE, "LOCAL_PRIVATE active receipt", exact_mode=0o444), "LOCAL_PRIVATE active receipt", True))
    expected = receipt_from_state(state, receipt.get("activatedAtUnixSeconds"))
    if receipt != expected:
        stop("LOCAL_PRIVATE receipt differs from its root state.")
    expected_names = active_profile_names(state, "LOCAL_PRIVATE active state")
    external = state.get("externalAuthorizedReconciliation")
    enforce_current = external is None or external.get("releaseAuthorityDocumentId") == (EXACT_AUTHORITY or {}).get("documentId")
    if canonical(stable_observation(state["observation"]["schedulerRecovery"], expected_names, enforce_current)) != canonical(state["observation"]):
        stop("LOCAL_PRIVATE live runtime drifted from the frozen receipt.")
    if systemctl(["is-enabled", UNIT_NAME], "is-enabled") != "enabled" or systemctl(["is-active", UNIT_NAME], "is-active") != "active":
        stop("LOCAL_PRIVATE supervisor is not enabled and active.")
    return receipt


def verify() -> Dict[str, object]:
    if os.path.lexists(physical(RECONCILIATION_FILE)):
        return reconciliation_status()
    return verify_active()


def activate() -> Dict[str, object]:
    install_sha = validate_release_and_install()
    ensure_private_directory(STATE_DIR)
    if os.path.lexists(physical(RECONCILIATION_FILE)):
        reconciliation_status()
        stop("LOCAL_PRIVATE reconciliation is in progress; use seal.")
    if os.path.lexists(physical(RECEIPT_FILE)):
        ensure_supervisor_active()
        return verify_active()
    existing_state = None
    if os.path.lexists(physical(STATE_FILE)):
        existing_state = read_state(True)
        if existing_state["installReceiptSha256"] != install_sha or existing_state["controller"] != controller_identity():
            stop("existing LOCAL_PRIVATE activation state has evidence/controller drift.")
        validate_bound_recovery_export(existing_state["observation"]["schedulerRecovery"], True)
        existing_names = observation_names(existing_state["observation"], "existing LOCAL_PRIVATE activation state")
        if canonical(stable_observation(existing_state["observation"]["schedulerRecovery"], existing_names)) != canonical(existing_state["observation"]):
            stop("existing LOCAL_PRIVATE activation state has runtime drift.")
        # Crash-safe completion: Type=notify already reached READY, so the
        # first host mutation happened under the checkpoint stored in state.
        # Finalizing state/receipt is additive evidence, not a new Docker or
        # application mutation, and does not require rewriting stale evidence.
        if existing_state["status"] == "ACTIVE" and not supervisor_is_enabled_and_active():
            # Crash after ACTIVE state but before the immutable receipt: restart
            # only this already-adopted host supervisor from the unchanged
            # baseline, then finish the receipt.  No state refresh occurs.
            ensure_supervisor_active()
        if supervisor_is_enabled_and_active():
            active_state = state_document("ACTIVE", existing_state["observation"], install_sha, existing_state["checkpointSha256"], existing_state["createdAtUnixSeconds"])
            atomic_write(STATE_FILE, active_state, 0o600, True)
            receipt = receipt_from_state(active_state, int(time.time()))
            atomic_write(RECEIPT_FILE, receipt, 0o444, False)
            return verify_active()
    checkpoint_sha, checkpoint_bytes, scheduler_recovery, export_snapshot, evidence_snapshots = validate_checkpoint()
    observation = stable_observation(scheduler_recovery)
    now = int(time.time())
    if existing_state is not None and canonical(existing_state["observation"]) != canonical(observation):
        stop("ACTIVATING state may refresh only its checkpoint at identical runtime identity.")
    state = state_document("ACTIVATING", observation, install_sha, checkpoint_sha, now)
    atomic_write(STATE_FILE, state, 0o600, True)
    # Revalidate the last-responsible-moment backup checkpoint immediately
    # before the first host mutation (systemd enable/start).
    if secure_file(CHECKPOINT, "fresh PRE-DEPLOY checkpoint") != checkpoint_bytes:
        stop("PRE-DEPLOY checkpoint changed before activation mutation.")
    assert_checkpoint_bytes_still_fresh(checkpoint_bytes)
    for pathname, expected_bytes in evidence_snapshots.items():
        if secure_file(pathname, "fixed PRE-DEPLOY evidence file") != expected_bytes:
            stop("one fixed PRE-DEPLOY evidence file changed before activation mutation.")
    revalidate_stream_snapshot(export_snapshot, "scheduler recovery image export")
    if validate_release_and_install() != install_sha:
        stop("V1 install receipt changed before activation mutation.")
    ensure_supervisor_active()
    active_state = state_document("ACTIVE", observation, install_sha, checkpoint_sha, state["createdAtUnixSeconds"])
    atomic_write(STATE_FILE, active_state, 0o600, True)
    receipt = receipt_from_state(active_state, int(time.time()))
    atomic_write(RECEIPT_FILE, receipt, 0o444, False)
    return verify_active()


def revalidate_fresh_inputs(
    checkpoint_bytes: bytes,
    export_snapshot: Dict[str, object],
    evidence_snapshots: Dict[str, bytes],
    install_sha: str,
) -> None:
    if secure_file(CHECKPOINT, "fresh PRE-DEPLOY checkpoint") != checkpoint_bytes:
        stop("PRE-DEPLOY checkpoint changed before reconciliation seal mutation.")
    assert_checkpoint_bytes_still_fresh(checkpoint_bytes)
    for pathname, expected_bytes in evidence_snapshots.items():
        if secure_file(pathname, "fixed PRE-DEPLOY evidence file") != expected_bytes:
            stop("one fixed PRE-DEPLOY evidence file changed before reconciliation seal mutation.")
    revalidate_stream_snapshot(export_snapshot, "scheduler recovery image export")
    if validate_release_and_install() != install_sha:
        stop("V1 install receipt changed before reconciliation seal mutation.")


def validate_target_state(state: Dict[str, object], reconciliation: Dict[str, object]) -> Dict[str, object]:
    validate_reconciliation_target_binding(state, reconciliation)
    if state["controller"] != reconciliation["controller"] or state["installReceiptSha256"] != reconciliation["installReceiptSha256"]:
        stop("LOCAL_PRIVATE reconciliation target state binding drifted.")
    if observation_names(state["observation"], "LOCAL_PRIVATE reconciliation target state") != CANONICAL_EXPECTED_NAMES:
        stop("LOCAL_PRIVATE reconciliation target is not the declared canonical exact-main set.")
    validate_bound_recovery_export(state["observation"]["schedulerRecovery"], True)
    if canonical(stable_observation(state["observation"]["schedulerRecovery"], CANONICAL_EXPECTED_NAMES)) != canonical(state["observation"]):
        stop("LOCAL_PRIVATE reconciliation target runtime is not stable at its exact healthy identity.")
    return state


def receipt_matches_state(receipt: Dict[str, object], state: Dict[str, object]) -> bool:
    return receipt_from_state(state, receipt.get("activatedAtUnixSeconds")) == receipt


def finalize_reconciliation(reconciliation: Dict[str, object], state: Dict[str, object]) -> Dict[str, object]:
    state = validate_target_state(state, reconciliation)
    if not supervisor_is_enabled_and_active():
        ensure_supervisor_active()
    active_state = state_document(
        "ACTIVE",
        state["observation"],
        state["installReceiptSha256"],
        state["checkpointSha256"],
        state["createdAtUnixSeconds"],
        state["externalAuthorizedReconciliation"],
    )
    current_receipt = validate_receipt_document(parse_json(
        secure_file(RECEIPT_FILE, "LOCAL_PRIVATE active receipt", exact_mode=0o444),
        "LOCAL_PRIVATE active receipt",
        True,
    ))
    if receipt_matches_state(current_receipt, active_state):
        receipt = current_receipt
    else:
        if digest(canonical_bytes(current_receipt)) != reconciliation["previousReceiptSha256"]:
            stop("LOCAL_PRIVATE reconciliation active receipt is neither predecessor nor canonical target.")
        receipt = receipt_from_state(active_state, int(time.time()))
        atomic_write(RECEIPT_FILE, receipt, 0o444, True)
    # Receipt first, ACTIVE state second: the supervisor remains in its
    # receipt-free ACTIVATING path until matching immutable evidence exists.
    if state["status"] != "ACTIVE":
        atomic_write(STATE_FILE, active_state, 0o600, True)
    # Keep the persistent RECONCILING marker until the new state, receipt,
    # exact runtime and supervisor have all passed the ordinary ACTIVE gate.
    verify_active()
    remove_exact_document(RECONCILIATION_FILE, reconciliation, "LOCAL_PRIVATE reconciliation")
    return verify_active()


def seal_with_fresh_evidence(
    reconciliation: Dict[str, object],
    install_sha: str,
    existing_target: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    if not supervisor_is_disabled_and_inactive():
        stop("LOCAL_PRIVATE reconciliation seal requires its supervisor disabled and inactive.")
    checkpoint_sha, checkpoint_bytes, scheduler_recovery, export_snapshot, evidence_snapshots = validate_checkpoint()
    observation = stable_observation(scheduler_recovery, CANONICAL_EXPECTED_NAMES)
    external_reconciliation = validate_reconciliation_runtime_evidence(
        reconciliation,
        checkpoint_sha,
        checkpoint_bytes,
        evidence_snapshots,
        observation,
    )
    if existing_target is not None and canonical(existing_target["observation"]) != canonical(observation):
        stop("LOCAL_PRIVATE interrupted seal may refresh evidence only at identical canonical runtime identity.")
    state = state_document(
        "ACTIVATING",
        observation,
        install_sha,
        checkpoint_sha,
        int(time.time()),
        external_reconciliation,
    )
    atomic_write(STATE_FILE, state, 0o600, True)
    revalidate_fresh_inputs(checkpoint_bytes, export_snapshot, evidence_snapshots, install_sha)
    ensure_supervisor_active()
    return finalize_reconciliation(reconciliation, state)


def seal() -> Dict[str, object]:
    if load_validation_lane(CANDIDATE_COMMIT) is not None:
        stop("validation lane forbids the production seal; run the full production chain.")
    reconciliation = reconciliation_status()
    install_sha = validate_release_and_install()
    if install_sha != reconciliation["installReceiptSha256"]:
        stop("LOCAL_PRIVATE reconciliation install evidence drifted before seal.")
    state_bytes = secure_file(STATE_FILE, "LOCAL_PRIVATE state", exact_mode=0o600)
    if digest(state_bytes) == reconciliation["previousStateSha256"]:
        if not supervisor_is_disabled_and_inactive():
            stop("LOCAL_PRIVATE maintenance has not completed supervisor disablement.")
        return seal_with_fresh_evidence(reconciliation, install_sha)
    state = validate_target_state(
        validate_state(parse_json(state_bytes, "LOCAL_PRIVATE state", True), True),
        reconciliation,
    )
    current_receipt = validate_receipt_document(parse_json(
        secure_file(RECEIPT_FILE, "LOCAL_PRIVATE active receipt", exact_mode=0o444),
        "LOCAL_PRIVATE active receipt",
        True,
    ))
    target_receipt_exists = receipt_matches_state(current_receipt, state)
    predecessor_receipt_exists = digest(canonical_bytes(current_receipt)) == reconciliation["previousReceiptSha256"]
    if not target_receipt_exists and not predecessor_receipt_exists:
        stop("LOCAL_PRIVATE interrupted seal receipt is not transaction-bound.")
    if state["status"] == "ACTIVE":
        if not target_receipt_exists:
            stop("LOCAL_PRIVATE ACTIVE target has no matching target receipt.")
        return finalize_reconciliation(reconciliation, state)
    if supervisor_is_enabled_and_active() or target_receipt_exists:
        return finalize_reconciliation(reconciliation, state)
    if not supervisor_is_disabled_and_inactive():
        disable_supervisor()
    return seal_with_fresh_evidence(reconciliation, install_sha, state)


def notify(message: str) -> None:
    address = os.environ.get("NOTIFY_SOCKET")
    if TEST_ROOT is None and not address:
        stop("systemd notify socket is unavailable.")
    if not address:
        return
    if address.startswith("@"):
        address = "\0" + address[1:]
    client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        client.sendto(message.encode(), address)
    finally:
        client.close()


def wait_for_expected_runtime(expected: Dict[str, object], enforce_current_authority: bool, timeout_seconds: int = 90) -> None:
    expected_names = observation_names(expected, "supervisor expected runtime")
    deadline = time.monotonic() + timeout_seconds
    last_error = "runtime has not reached the frozen healthy identity"
    while True:
        try:
            current = stable_observation(expected["schedulerRecovery"], expected_names, enforce_current_authority)
            if canonical(current) == canonical(expected):
                return
            last_error = "runtime identity differs from the frozen activation state"
        except Stop as error:
            last_error = str(error)
        if time.monotonic() >= deadline:
            stop(f"bounded supervisor startup wait expired: {last_error}.")
        notify(f"STATUS=Waiting for V1 LOCAL_PRIVATE runtime: {last_error[:240]}")
        time.sleep(3)


def supervise() -> None:
    state = read_state(True)
    install_sha = validate_release_and_install(state)
    if os.path.lexists(physical(RECONCILIATION_FILE)) and state["status"] == "ACTIVE":
        reconciliation = reconciliation_status()
        if reconciliation_retains_predecessor_state(reconciliation):
            return
    if state["installReceiptSha256"] != install_sha:
        stop("LOCAL_PRIVATE supervisor startup verification failed.")
    validate_predecessor_controller(state["controller"])
    if state["status"] == "ACTIVE":
        active_profile_names(state, "LOCAL_PRIVATE supervisor state")
    validate_bound_recovery_export(state["observation"]["schedulerRecovery"], True)
    external = state.get("externalAuthorizedReconciliation")
    enforce_current = external is None or external.get("releaseAuthorityDocumentId") == (EXACT_AUTHORITY or {}).get("documentId")
    wait_for_expected_runtime(state["observation"], enforce_current)
    notify("READY=1\nSTATUS=V1 LOCAL_PRIVATE runtime verified")
    interval = 10.0
    watchdog = os.environ.get("WATCHDOG_USEC")
    if watchdog and watchdog.isdigit():
        interval = max(1.0, min(10.0, int(watchdog) / 3_000_000))
    while True:
        time.sleep(interval)
        state = read_state(True)
        if os.path.lexists(physical(RECONCILIATION_FILE)) and state["status"] == "ACTIVE":
            reconciliation = reconciliation_status()
            if reconciliation_retains_predecessor_state(reconciliation):
                notify("STOPPING=1\nSTATUS=V1 LOCAL_PRIVATE reconciliation maintenance")
                return
        if state["status"] == "ACTIVE":
            active_profile_names(state, "LOCAL_PRIVATE supervisor state")
            receipt = validate_receipt_document(parse_json(secure_file(RECEIPT_FILE, "LOCAL_PRIVATE active receipt", exact_mode=0o444), "LOCAL_PRIVATE active receipt", True))
            if receipt_from_state(state, receipt.get("activatedAtUnixSeconds")) != receipt:
                stop("LOCAL_PRIVATE supervisor receipt verification failed.")
        expected_names = observation_names(state["observation"], "LOCAL_PRIVATE supervisor state")
        external = state.get("externalAuthorizedReconciliation")
        enforce_current = external is None or external.get("releaseAuthorityDocumentId") == (EXACT_AUTHORITY or {}).get("documentId")
        if canonical(observe(state["observation"]["schedulerRecovery"], expected_names, enforce_current)) != canonical(state["observation"]):
            stop("LOCAL_PRIVATE supervisor detected runtime drift.")
        validate_bound_recovery_export(state["observation"]["schedulerRecovery"], False)
        notify("WATCHDOG=1\nSTATUS=V1 LOCAL_PRIVATE runtime verified")


def main(arguments: List[str]) -> int:
    if len(arguments) != 1 or arguments[0] not in ("abort-maintenance", "activate", "begin-maintenance", "seal", "verify", "supervise"):
        sys.stderr.write("platform-v1-local-private-control: usage: platform-v1-local-private-control abort-maintenance|activate|begin-maintenance|seal|verify|supervise\n")
        return 64
    try:
        check_no_stdin()
        initialize()
        if arguments[0] == "supervise":
            configure_exact_release_authority()
            supervise()
            return 0
        transaction_lock: Optional[int] = None
        try:
            if arguments[0] in ("abort-maintenance", "activate", "begin-maintenance", "seal"):
                transaction_lock = acquire_transaction_lock()
            lock = acquire_lock()
            try:
                # Authority bytes are opened only after the shared transaction
                # lease.  Reading them before the lease would permit prepare to
                # swap the authority between this read and begin-maintenance.
                configure_exact_release_authority()
                if arguments[0] == "activate":
                    receipt = activate()
                elif arguments[0] == "abort-maintenance":
                    receipt = abort_maintenance()
                elif arguments[0] == "begin-maintenance":
                    receipt = begin_maintenance()
                elif arguments[0] == "seal":
                    receipt = seal()
                else:
                    receipt = verify()
            finally:
                os.close(lock)
        finally:
            if transaction_lock is not None:
                os.close(transaction_lock)
        sys.stdout.write(canonical(receipt) + "\n")
        return 0
    except Stop as error:
        sys.stderr.write(f"platform-v1-local-private-control: STOP: {error}\n")
        return error.code
    except BrokenPipeError:
        return 74
    except BaseException as error:
        sys.stderr.write(f"platform-v1-local-private-control: STOP: unexpected bounded failure: {error}\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
