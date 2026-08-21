#!/usr/bin/python3 -I
"""Root-only, additive V1 LOCAL_PRIVATE brownfield control supervisor.

The controller adopts one closed live-runtime identity.  It never creates,
starts, stops, removes, updates, or recreates a Docker object.  Its only host
mutation is enabling and starting its own fixed systemd supervisor unit.
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
import stat
import subprocess
import sys
import tarfile
import time
from typing import Dict, Iterable, List, Optional, Tuple


CANDIDATE_COMMIT = "832bf2baec47055342af7e7f73425444381b91e0"
CANDIDATE_TREE = "91cee2380809cb0691b9ac47cafa2a673d434caa"
SOURCE_ARCHIVE_SHA256 = "6eabff5f3fdbb4b129519d23a2dd9864f65477c5f0e1ecb58e1b8a9a79af3007"
RELEASE_ROOT = f"/srv/platform-infrastructure/releases/{CANDIDATE_COMMIT}-{SOURCE_ARCHIVE_SHA256}"
INSTALL_RECEIPT = f"/var/lib/platform-infrastructure/v1/install-receipts/{CANDIDATE_COMMIT}-{SOURCE_ARCHIVE_SHA256}.json"
CHECKPOINT = "/var/lib/platform-infrastructure/v1/predeploy/current/local-private-checkpoint.json"
SCHEDULER_RECOVERY_EXPORT = "/var/lib/platform-infrastructure/v1/predeploy/current/scheduler-recovery-image.tar"
SCHEDULER_RECOVERY_TAG = f"platform/v1-scheduler-recovery:{CANDIDATE_COMMIT}"
EVIDENCE_PATHS = {
    "logicalBackupEvidenceSha256": "/var/lib/platform-infrastructure/v1/predeploy/current/logical-backup-evidence.json",
    "offHostBackupEvidenceSha256": "/var/lib/platform-infrastructure/v1/predeploy/current/offhost-backup-evidence.json",
    "restoreEvidenceSha256": "/var/lib/platform-infrastructure/v1/predeploy/current/restore-evidence.json",
    "runtimeInventorySha256": "/var/lib/platform-infrastructure/v1/predeploy/current/runtime-inventory-evidence.json",
    "secretsBackupEvidenceSha256": "/var/lib/platform-infrastructure/v1/predeploy/current/secrets-backup-evidence.json",
}
STATE_DIR = "/var/lib/platform-infrastructure/v1/local-private"
STATE_FILE = f"{STATE_DIR}/state.json"
RECEIPT_FILE = f"{STATE_DIR}/active-receipt.json"
LOCK_FILE = "/run/lock/platform-v1-local-private-control.lock"
CONTROLLER_PATH = "/usr/local/libexec/platform-v1-local-private-control"
UNIT_PATH = "/etc/systemd/system/platform-v1-local-private-control.service"
UNIT_NAME = "platform-v1-local-private-control.service"
UNIT_SHA256 = "d4f481a4f6a8b5c39a11834eb4680e1cfb02872be0baa378da8cb05259c9aa6e"
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
MAX_JSON = 128 * 1024
MAX_DOCKER_JSON = 4 * 1024 * 1024
MAX_RECOVERY_EXPORT_BYTES = 4 * 1024 * 1024 * 1024
MAX_RECOVERY_CONFIG_BYTES = 16 * 1024 * 1024
MAX_CHECKPOINT_AGE = 900
MAX_BACKUP_AGE = 3600
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
ID_RE = re.compile(r"^[a-f0-9]{64}$")
SERVICE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")

CONTAINERS = (
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
EXPECTED_NAMES = frozenset(CONTAINERS)
NO_HEALTHCHECK = frozenset(("enterprise-local-dns", "enterprise-local-registry", "phpmyadmin"))
EXITED_ONLY = "phppgadmin"
PROJECT_BY_NAME = {name: ("opstudents" if name == "node-opstudents" else "platform_infra_vps") for name in CONTAINERS}
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


def parse_recovery_export(snapshot: Dict[str, object], recovery_image_id: str) -> Dict[str, object]:
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
                expected_tag = SCHEDULER_RECOVERY_TAG
                ref_name = annotations.get("org.opencontainers.image.ref.name")
                containerd_name = annotations.get("io.containerd.image.name")
                if ref_name not in (expected_tag, CANDIDATE_COMMIT) or containerd_name not in (expected_tag, f"docker.io/{expected_tag}"):
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
    expected_labels = {
        RECOVERY_LABELS["candidateCommit"]: CANDIDATE_COMMIT,
        RECOVERY_LABELS["configHash"]: recovery["configHash"],
        RECOVERY_LABELS["containerId"]: recovery["containerId"],
        RECOVERY_LABELS["runningImageId"]: recovery["runningImageId"],
    }
    if (
        recovery["archiveFormat"] != "OCI_DOCKER_SAVE_V1"
        or recovery["imageIndexDigest"] != recovery["recoveryImageId"]
        or recovery["imageIndexPath"] != f"blobs/sha256/{recovery_hex}"
        or recovery["manifestConfig"] != f"blobs/sha256/{config_hex}"
        or recovery["recoveryTag"] != SCHEDULER_RECOVERY_TAG
        or recovery["exportLabels"] != expected_labels
        or isinstance(recovery["exportSizeBytes"], bool)
        or not isinstance(recovery["exportSizeBytes"], int)
        or not 1024 <= recovery["exportSizeBytes"] <= MAX_RECOVERY_EXPORT_BYTES
    ):
        stop("receipt-bound scheduler OCI export metadata is invalid.")
    if full_hash:
        snapshot = stream_snapshot(SCHEDULER_RECOVERY_EXPORT, "receipt-bound scheduler recovery image export")
        parsed = parse_recovery_export(snapshot, recovery["recoveryImageId"])
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
    unit = secure_file(UNIT_PATH, "installed LOCAL_PRIVATE systemd unit", 65536, 0o444)
    if digest(unit) != UNIT_SHA256:
        stop("installed LOCAL_PRIVATE systemd unit differs from the pinned bytes.")


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


def validate_release_and_install() -> str:
    secure_directory(RELEASE_ROOT, "frozen V1 release", 0o555)
    data = secure_file(INSTALL_RECEIPT, "V1 install receipt")
    value = exact_keys(parse_json(data, "V1 install receipt", True), (
        "activationAuthorized", "authorizationSource", "backupEvidenceAuthoritative",
        "candidateCommit", "candidateTree", "dataMutation", "dockerMutation",
        "readyButDisabled", "releaseRoot", "schema", "sourceArchiveSha256", "status",
    ), "V1 install receipt")
    if value["schema"] != "platform.v1-brownfield-install-receipt/v1" or value["status"] not in ("INSTALL_ONLY_COMPLETE", "ALREADY_INSTALLED"):
        stop("V1 install receipt status/schema is invalid.")
    if value["candidateCommit"] != CANDIDATE_COMMIT or value["candidateTree"] != CANDIDATE_TREE or value["sourceArchiveSha256"] != SOURCE_ARCHIVE_SHA256 or value["releaseRoot"] != RELEASE_ROOT:
        stop("V1 install receipt candidate binding differs.")
    if value["activationAuthorized"] is not False or value["dockerMutation"] is not False or value["dataMutation"] is not False or value["backupEvidenceAuthoritative"] is not False:
        stop("V1 install receipt exceeds install-only authority.")
    if value["authorizationSource"] != "ROOT_OPERATOR_EXPLICIT_INSTALL_ONLY":
        stop("V1 install receipt authorization source is invalid.")
    return digest(data)


def validate_checkpoint() -> Tuple[str, bytes, Dict[str, object], Dict[str, object], Dict[str, bytes]]:
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
    recovery: Dict[str, object] = {
        "exportIdentity": export_snapshot["identity"],
        "exportPath": SCHEDULER_RECOVERY_EXPORT,
        "exportSha256": value["schedulerRecoveryImageExportSha256"],
        "exportSizeBytes": export_snapshot["sizeBytes"],
        "recoveryImageId": recovery_image_id,
        "runningImageId": running_image_id,
        **export_metadata,
    }
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


def observe(scheduler_recovery: Dict[str, str]) -> Dict[str, object]:
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
    if len(ids) != 35 or len(set(ids)) != 35 or any(ID_RE.fullmatch(item) is None for item in ids):
        stop("Docker inventory is not exactly 35 unique full container IDs.")
    inspected = docker_json(["inspect", *sorted(ids)], "container inspection")
    if not isinstance(inspected, list) or len(inspected) != 35:
        stop("Docker inspection did not return exactly 35 containers.")
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
        if not isinstance(identifier, str) or ID_RE.fullmatch(identifier) is None or name not in EXPECTED_NAMES or name in names:
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
        if project != PROJECT_BY_NAME[name] or not isinstance(service, str) or SERVICE_RE.fullmatch(service) is None or not isinstance(config_hash, str) or SHA256_RE.fullmatch(config_hash) is None:
            stop(f"container {name} Compose identity/config hash is invalid.")
        image_id = container.get("Image")
        if not isinstance(image_id, str) or re.fullmatch(r"sha256:[a-f0-9]{64}", image_id) is None:
            stop(f"container {name} image ID is not immutable.")
        image_ids.add(image_id)
        runtime_state = state.get("Status")
        health_object = state.get("Health")
        health = health_object.get("Status") if isinstance(health_object, dict) else "none"
        if name == EXITED_ONLY:
            if runtime_state != "exited":
                stop("phppgadmin is the only allowed exited container and must remain exited.")
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
        records.append({"configHash": config_hash, "containerId": identifier, "exitCode": exit_code, "health": health, "imageId": image_id, "name": name, "project": project, "service": service, "state": runtime_state})
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
    if names != EXPECTED_NAMES:
        stop("Docker container-name allowlist is incomplete or contains extras.")
    if len(raw_owners) != 1 or raw_owners[0]["name"] != "enterprise-backup-scheduler" or raw_owners[0]["readOnly"] is not False:
        stop("raw Docker socket container authority is not the one receipt-bound RW legacy scheduler.")
    validate_port_policy(ports)
    scheduler_record = next(item for item in records if item["name"] == "enterprise-backup-scheduler")
    scheduler_image = scheduler_record["imageId"]
    recovery_base_keys = {
        "archiveFormat", "configDigest", "exportIdentity", "exportLabels", "exportPath",
        "exportSha256", "exportSizeBytes", "imageIndexDigest", "imageIndexPath",
        "imageManifestDigest", "manifestConfig", "recoveryImageId", "recoveryTag",
        "runningImageId",
    }
    if not isinstance(scheduler_recovery, dict) or not recovery_base_keys.issubset(scheduler_recovery) or set(scheduler_recovery) - recovery_base_keys - {"configHash", "containerId"}:
        stop("scheduler recovery binding is not one closed object.")
    if scheduler_recovery.get("runningImageId") != scheduler_image or scheduler_recovery.get("exportPath") != SCHEDULER_RECOVERY_EXPORT:
        stop("scheduler running image ID is not bound to the live scheduler.")
    recovery_image = scheduler_recovery["recoveryImageId"]
    if recovery_image == scheduler_image:
        stop("scheduler recovery image must be distinct from the missing running image ID.")
    local_images = image_ids - {scheduler_image}
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
        stop("scheduler running image unexpectedly exists; the fixed missing-image recovery model no longer matches live state.")
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
    expected_labels = {
        RECOVERY_LABELS["candidateCommit"]: CANDIDATE_COMMIT,
        RECOVERY_LABELS["configHash"]: scheduler_record["configHash"],
        RECOVERY_LABELS["containerId"]: scheduler_record["containerId"],
        RECOVERY_LABELS["runningImageId"]: scheduler_image,
    }
    if recovery_tags != [SCHEDULER_RECOVERY_TAG]:
        stop("scheduler recovery image is not bound to the one fixed local tag.")
    if (
        scheduler_recovery.get("exportLabels") != expected_labels
        or not isinstance(recovery_labels, dict)
        or any(recovery_labels.get(key) != value for key, value in expected_labels.items())
    ):
        stop("scheduler recovery image labels are not bound to candidate and live scheduler identity.")
    bound_recovery = {key: scheduler_recovery[key] for key in recovery_base_keys}
    bound_recovery["configHash"] = scheduler_record["configHash"]
    bound_recovery["containerId"] = scheduler_record["containerId"]
    for record in records:
        record["imageAvailability"] = scheduler_availability if record["name"] == "enterprise-backup-scheduler" else "LOCAL_IMAGE_STORE"
    records.sort(key=lambda item: item["name"])
    return {"containers": records, "daemon": daemon, "publishedPorts": ports, "rawDockerAuthority": raw_owners[0], "schedulerRecovery": bound_recovery}


def stable_observation(scheduler_recovery: Dict[str, str]) -> Dict[str, object]:
    first = observe(scheduler_recovery)
    second = observe(scheduler_recovery)
    if canonical(first) != canonical(second):
        stop("Docker runtime changed during LOCAL_PRIVATE adoption.")
    return first


def controller_identity() -> Dict[str, object]:
    controller = secure_file(CONTROLLER_PATH, "installed LOCAL_PRIVATE controller", 1024 * 1024, 0o555)
    unit = secure_file(UNIT_PATH, "installed LOCAL_PRIVATE systemd unit", 65536, 0o444)
    return {"installedPath": CONTROLLER_PATH, "sha256": digest(controller), "unitPath": UNIT_PATH, "unitSha256": digest(unit)}


def state_document(status: str, observation: Dict[str, object], install_sha: str, checkpoint_sha: str, created: int) -> Dict[str, object]:
    return {"candidateCommit": CANDIDATE_COMMIT, "candidateTree": CANDIDATE_TREE, "checkpointSha256": checkpoint_sha, "controller": controller_identity(), "createdAtUnixSeconds": created, "installReceiptSha256": install_sha, "observation": observation, "releaseRoot": RELEASE_ROOT, "schema": STATE_SCHEMA, "sourceArchiveSha256": SOURCE_ARCHIVE_SHA256, "status": status}


def validate_state(value: Dict[str, object], allow_activating: bool) -> Dict[str, object]:
    exact_keys(value, ("candidateCommit", "candidateTree", "checkpointSha256", "controller", "createdAtUnixSeconds", "installReceiptSha256", "observation", "releaseRoot", "schema", "sourceArchiveSha256", "status"), "LOCAL_PRIVATE state")
    allowed = ("ACTIVATING", "ACTIVE") if allow_activating else ("ACTIVE",)
    if value["schema"] != STATE_SCHEMA or value["status"] not in allowed or value["candidateCommit"] != CANDIDATE_COMMIT or value["candidateTree"] != CANDIDATE_TREE or value["sourceArchiveSha256"] != SOURCE_ARCHIVE_SHA256 or value["releaseRoot"] != RELEASE_ROOT:
        stop("LOCAL_PRIVATE state binding/status is invalid.")
    sha256_value(value["checkpointSha256"], "state checkpoint")
    sha256_value(value["installReceiptSha256"], "state install receipt")
    if not isinstance(value["createdAtUnixSeconds"], int):
        stop("LOCAL_PRIVATE state timestamp is invalid.")
    return value


def read_state(allow_activating: bool = False) -> Dict[str, object]:
    return validate_state(parse_json(secure_file(STATE_FILE, "LOCAL_PRIVATE state", exact_mode=0o600), "LOCAL_PRIVATE state", True), allow_activating)


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
    base = {
        "activatedAtUnixSeconds": activated_at,
        "authorityMode": "LOCAL_PRIVATE",
        "candidateCommit": CANDIDATE_COMMIT,
        "candidateTree": CANDIDATE_TREE,
        "checkpointSha256": state["checkpointSha256"],
        "containerRecreate": False,
        "controller": state["controller"],
        "dataMutation": False,
        "dockerMutation": False,
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
        "mutationModel": "ADDITIVE_ADOPTION",
        "mutationPerformed": True,
        "networkIsolation": {"policy": "EDGE_PUBLISHED_PORT_ALLOWLIST", "publishedPorts": observation["publishedPorts"], "status": "PASS"},
        "providerComponents": list(PROVIDER_COMPONENTS),
        "readyButDisabled": list(READY_BUT_DISABLED),
        "releaseRoot": RELEASE_ROOT,
        "runtime": {"containerCount": 35, "containers": containers, "daemon": observation["daemon"], "exitedCount": 1, "rawDockerAuthority": observation["rawDockerAuthority"], "runningCount": 34},
        "schema": RECEIPT_SCHEMA,
        "sourceArchiveSha256": SOURCE_ARCHIVE_SHA256,
        "status": "ACTIVE",
        "supervisor": {"active": True, "enabled": True, "service": UNIT_NAME, "status": "ACTIVE", "type": "ROOT_SYSTEMD_NOTIFY"},
    }
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


def verify_active() -> Dict[str, object]:
    install_sha = validate_release_and_install()
    state = read_state(False)
    if state["installReceiptSha256"] != install_sha or state["controller"] != controller_identity():
        stop("LOCAL_PRIVATE state evidence/controller identity drifted.")
    validate_bound_recovery_export(state["observation"]["schedulerRecovery"], True)
    receipt = validate_receipt_document(parse_json(secure_file(RECEIPT_FILE, "LOCAL_PRIVATE active receipt", exact_mode=0o444), "LOCAL_PRIVATE active receipt", True))
    expected = receipt_from_state(state, receipt.get("activatedAtUnixSeconds"))
    if receipt != expected:
        stop("LOCAL_PRIVATE receipt differs from its root state.")
    if canonical(stable_observation(state["observation"]["schedulerRecovery"])) != canonical(state["observation"]):
        stop("LOCAL_PRIVATE live runtime drifted from the frozen receipt.")
    if systemctl(["is-enabled", UNIT_NAME], "is-enabled") != "enabled" or systemctl(["is-active", UNIT_NAME], "is-active") != "active":
        stop("LOCAL_PRIVATE supervisor is not enabled and active.")
    return receipt


def activate() -> Dict[str, object]:
    install_sha = validate_release_and_install()
    ensure_private_directory(STATE_DIR)
    if os.path.lexists(physical(RECEIPT_FILE)):
        ensure_supervisor_active()
        return verify_active()
    existing_state = None
    if os.path.lexists(physical(STATE_FILE)):
        existing_state = read_state(True)
        if existing_state["installReceiptSha256"] != install_sha or existing_state["controller"] != controller_identity():
            stop("existing LOCAL_PRIVATE activation state has evidence/controller drift.")
        validate_bound_recovery_export(existing_state["observation"]["schedulerRecovery"], True)
        if canonical(stable_observation(existing_state["observation"]["schedulerRecovery"])) != canonical(existing_state["observation"]):
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


def wait_for_expected_runtime(expected: Dict[str, object], timeout_seconds: int = 90) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error = "runtime has not reached the frozen healthy identity"
    while True:
        try:
            current = stable_observation(expected["schedulerRecovery"])
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
    install_sha = validate_release_and_install()
    state = read_state(True)
    if state["installReceiptSha256"] != install_sha or state["controller"] != controller_identity():
        stop("LOCAL_PRIVATE supervisor startup verification failed.")
    validate_bound_recovery_export(state["observation"]["schedulerRecovery"], True)
    wait_for_expected_runtime(state["observation"])
    notify("READY=1\nSTATUS=V1 LOCAL_PRIVATE runtime verified")
    interval = 10.0
    watchdog = os.environ.get("WATCHDOG_USEC")
    if watchdog and watchdog.isdigit():
        interval = max(1.0, min(10.0, int(watchdog) / 3_000_000))
    while True:
        time.sleep(interval)
        state = read_state(True)
        if state["status"] == "ACTIVE":
            receipt = validate_receipt_document(parse_json(secure_file(RECEIPT_FILE, "LOCAL_PRIVATE active receipt", exact_mode=0o444), "LOCAL_PRIVATE active receipt", True))
            if receipt_from_state(state, receipt.get("activatedAtUnixSeconds")) != receipt:
                stop("LOCAL_PRIVATE supervisor receipt verification failed.")
        if canonical(observe(state["observation"]["schedulerRecovery"])) != canonical(state["observation"]):
            stop("LOCAL_PRIVATE supervisor detected runtime drift.")
        validate_bound_recovery_export(state["observation"]["schedulerRecovery"], False)
        notify("WATCHDOG=1\nSTATUS=V1 LOCAL_PRIVATE runtime verified")


def main(arguments: List[str]) -> int:
    if len(arguments) != 1 or arguments[0] not in ("activate", "verify", "supervise"):
        sys.stderr.write("platform-v1-local-private-control: usage: platform-v1-local-private-control activate|verify|supervise\n")
        return 64
    try:
        check_no_stdin()
        initialize()
        if arguments[0] == "supervise":
            supervise()
            return 0
        lock = acquire_lock()
        try:
            receipt = activate() if arguments[0] == "activate" else verify_active()
        finally:
            os.close(lock)
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
