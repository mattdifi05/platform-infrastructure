#!/usr/bin/python3 -I
"""Produce the existing V1 LOCAL_PRIVATE backup evidence bundle.

The entrypoint is intentionally closed: ``pre`` captures the rollback gate
before maintenance and ``post`` captures the seal gate after reconciliation
``apply``.  It accepts no caller supplied path, repository, image, tag or
command.  The exact release, live data roots, OneDrive Restic repository and
evidence destinations are all fixed and independently rebound before use.

This is not a retention tool.  It never invokes Restic forget, prune or any
Hostinger endpoint.  Every run uploads fourteen new snapshots and restores
each snapshot into a root-only tmpfs directory for byte-exact readback.
"""

from __future__ import annotations

import base64
import configparser
import fcntl
import fnmatch
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import select
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


STATE_DIR = "/var/lib/platform-infrastructure/v1/local-private"
PREDEPLOY_DIR = "/var/lib/platform-infrastructure/v1/predeploy/current"
AUTHORITY = f"{STATE_DIR}/exact-release-authority.json"
RECONCILIATION = f"{STATE_DIR}/reconciliation.json"
JOURNAL = f"{STATE_DIR}/reconcile-journal.json"
SOURCE_ARCHIVE = f"{PREDEPLOY_DIR}/exact-source-archive.tar"
INSTALL_CHECKPOINT = f"{PREDEPLOY_DIR}/install-checkpoint.json"
LOCAL_CHECKPOINT = f"{PREDEPLOY_DIR}/local-private-checkpoint.json"
SCHEDULER_RECOVERY_EXPORT = f"{PREDEPLOY_DIR}/scheduler-recovery-image.tar"
LOGICAL_EVIDENCE = f"{PREDEPLOY_DIR}/logical-backup-evidence.json"
OFFHOST_EVIDENCE = f"{PREDEPLOY_DIR}/offhost-backup-evidence.json"
RESTORE_EVIDENCE = f"{PREDEPLOY_DIR}/restore-evidence.json"
RUNTIME_EVIDENCE = f"{PREDEPLOY_DIR}/runtime-inventory-evidence.json"
SECRETS_EVIDENCE = f"{PREDEPLOY_DIR}/secrets-backup-evidence.json"
EVIDENCE_PREIMAGES = f"{STATE_DIR}/evidence-preimages"
ROLLBACK_SPEC_DIR = f"{STATE_DIR}/rollback-specs"
LOCK = "/run/lock/platform-v1-local-private-evidence.lock"
SHARED_LOCK = "/run/lock/platform-v1-local-private-transaction.lock"
SHARED_LOCK_FD_ENV = "PLATFORM_V1_EVIDENCE_SHARED_LOCK_FD"
EXECUTOR_FD_ENV = "PLATFORM_V1_EVIDENCE_EXECUTOR_FD"
EXECUTOR_FD = 4
MAX_EXECUTOR_FRAME = 96 * 1024 * 1024

LIVE_ROOT = "/home/platform_infrastructure/platform-infrastructure"
PROJECT_SOURCE_ROOT = "/home/platform_infrastructure/src"
SECRETS_ROOT = f"{LIVE_ROOT}/secrets"
PROJECT_STATE_ROOT = f"{LIVE_ROOT}/projects-portal/state"
LIVE_ENV = f"{LIVE_ROOT}/.env"
RENDER_ENV = f"{STATE_DIR}/exact-compose.env"
BACKUPS_ROOT = f"{LIVE_ROOT}/backups"
REPORTS_ROOT = f"{LIVE_ROOT}/reports/local-private-predeploy"
BACKUP_SIGNING_KEYS = f"{SECRETS_ROOT}/backup_signing_keys.txt"
RESTIC_PASSWORD = f"{SECRETS_ROOT}/restic_password.txt"
RCLONE_CONFIG = f"{SECRETS_ROOT}/rclone/rclone.conf"
CONFIDENTIAL_PASSPHRASE = f"{STATE_DIR}/confidential-backup-passphrase"
CONFIDENTIAL_PASSPHRASE_ENV = "V1_CONFIDENTIAL_BACKUP_PASSPHRASE_FILE"

GIT = "/usr/bin/git"
GPG = "/usr/bin/gpg"
OPENSSL = "/usr/bin/openssl"
PYTHON = "/usr/bin/python3"

RECOVERY_CERT_RELATIVE = "config/local-private-recovery-escrow-cert.pem"
ESCROW_REMOTE_PREFIX = "platform-onedrive:platform-infrastructure/key-escrow"

ONEDRIVE_REPOSITORY = "rclone:platform-onedrive:platform-infrastructure/restic"
ONEDRIVE_REMOTE = "platform-onedrive"
RESTIC_HOSTNAME = "platform-v1-local-private"
RESTIC_FORBIDDEN_OPERATIONS = frozenset(("forget", "prune"))

APP_SLUGS = (
    "anniversary", "fiplatform", "matthewdifilippo", "opstudents",
    "public", "stexor", "stream", "workcalendar",
)
LOGICAL_KEYS = (*APP_SLUGS, "pg-stexor", "pg-keycloak", "mariadb", "minio", "keycloak-config", "confidential")
APPLICATION_EXCLUDE_EXACT = frozenset((
    ".git", ".hg", ".svn", ".env", "node_modules", "vendor", ".next", ".nuxt", "dist", "build",
    "coverage", ".cache", ".turbo", ".parcel-cache", "backups", ".codex-backups",
))
APPLICATION_EXCLUDE_GLOBS = (".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.dump", "*.sql", "*.sqlite", "*.sqlite3")
APPLICATION_EXCLUDE_PATHS = ("storage/logs", "var/cache", "var/log")

EVIDENCE_FILES = {
    "logicalBackupEvidenceSha256": LOGICAL_EVIDENCE,
    "offHostBackupEvidenceSha256": OFFHOST_EVIDENCE,
    "restoreEvidenceSha256": RESTORE_EVIDENCE,
    "runtimeInventorySha256": RUNTIME_EVIDENCE,
    "secretsBackupEvidenceSha256": SECRETS_EVIDENCE,
}

SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
COMMIT_RE = re.compile(r"^[a-f0-9]{40}$")
IMAGE_ID_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
SNAPSHOT_ID_RE = re.compile(r"^[a-f0-9]{64}$")
KEY_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
RUN_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$")
TRANSACTION_ID_RE = re.compile(r"^[a-f0-9]{64}$")
MAX_JSON = 16 * 1024 * 1024
MAX_COMMAND_OUTPUT = 32 * 1024 * 1024
MAX_ARCHIVE = 2 * 1024 * 1024 * 1024
MAX_RECOVERY_EXPORT = 4 * 1024 * 1024 * 1024

TEST_ROOT = os.environ.get("PLATFORM_V1_EVIDENCE_TEST_ROOT")


class Stop(RuntimeError):
    def __init__(self, message: str, code: int = 78) -> None:
        super().__init__(message)
        self.code = code


def stop(message: str, code: int = 78) -> None:
    raise Stop(message, code)


def physical(logical: str) -> str:
    if TEST_ROOT and logical.startswith("/"):
        return os.path.join(TEST_ROOT, logical.lstrip("/"))
    return logical


def binary(logical: str, test_name: str) -> str:
    if TEST_ROOT:
        selected = os.environ.get(test_name)
        if selected:
            return selected
    return logical


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def canonical_bytes(value: object) -> bytes:
    return f"{canonical(value)}\n".encode("utf-8")


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_file(logical: str, maximum: int = MAX_ARCHIVE, *, allow_empty: bool = False) -> str:
    pathname = logical if TEST_ROOT and logical.startswith(f"{TEST_ROOT}/") else physical(logical)
    try:
        fd = os.open(pathname, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        stop(f"cannot open fixed file {logical}: {error.strerror}.")
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or (before.st_size < 1 and not allow_empty) or before.st_size > maximum:
            stop(f"fixed file identity is invalid: {logical}.")
        result = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                stop(f"fixed file exceeded its boundary: {logical}.")
            result.update(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            stop(f"fixed file changed while hashed: {logical}.")
        return result.hexdigest()
    finally:
        os.close(fd)


def duplicate_safe(pairs: Sequence[Tuple[str, object]]) -> Dict[str, object]:
    result: Dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key}")
        result[key] = value
    return result


def read_bytes(
    logical: str, label: str, maximum: int = MAX_JSON, *, allow_missing: bool = False,
    owner_uids: Optional[Iterable[int]] = None, exact_modes: Optional[Iterable[int]] = None,
) -> Optional[bytes]:
    pathname = physical(logical)
    try:
        fd = os.open(pathname, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        if allow_missing:
            return None
        stop(f"{label} is missing.")
    except OSError as error:
        stop(f"cannot open {label}: {error.strerror}.")
    try:
        before = os.fstat(fd)
        expected_uid = os.geteuid() if TEST_ROOT else 0
        accepted_uids = {expected_uid} if owner_uids is None else set(owner_uids)
        accepted_modes = None if exact_modes is None else set(exact_modes)
        observed_mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size < 1
            or before.st_size > maximum or before.st_uid not in accepted_uids or observed_mode & 0o022
            or (accepted_modes is not None and observed_mode not in accepted_modes)
        ):
            stop(f"{label} has unsafe ownership, mode, link count or size.")
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                stop(f"{label} exceeded its byte boundary.")
            chunks.append(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            stop(f"{label} changed while read.")
        return b"".join(chunks)
    finally:
        os.close(fd)


def fixed_data_owner_uids() -> Tuple[int, ...]:
    pathname = physical(LIVE_ROOT)
    try:
        metadata = os.lstat(pathname)
    except OSError as error:
        stop(f"cannot inspect the fixed live root: {error.strerror}.")
    expected_root = os.geteuid() if TEST_ROOT else 0
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o022:
        stop("fixed live root ownership boundary is unsafe.")
    return tuple(sorted({expected_root, metadata.st_uid}))


def read_fixed_data_file(logical: str, label: str, maximum: int) -> bytes:
    data = read_bytes(logical, label, maximum, owner_uids=fixed_data_owner_uids())
    assert data is not None
    return data


def read_confidential_passphrase() -> bytes:
    expected_root = os.geteuid() if TEST_ROOT else 0
    data = read_bytes(
        CONFIDENTIAL_PASSPHRASE, "dedicated confidential-backup passphrase", 4096,
        owner_uids=(expected_root,), exact_modes=(0o400, 0o600),
    )
    assert data is not None
    if len(data.rstrip(b"\n")) < 64 or b"\x00" in data or len(data.splitlines()) != 1:
        stop("dedicated confidential-backup passphrase is not one high-entropy-length value.")
    return data


def read_json(logical: str, label: str, maximum: int = MAX_JSON, *, canonical_required: bool = True) -> Tuple[Dict[str, object], bytes]:
    data = read_bytes(logical, label, maximum)
    assert data is not None
    try:
        value = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=duplicate_safe)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        stop(f"{label} is not strict JSON: {error}.")
    if not isinstance(value, dict):
        stop(f"{label} is not one JSON object.")
    if canonical_required and canonical_bytes(value) != data:
        stop(f"{label} is not canonical JSON.")
    return value, data


def exact_keys(value: object, expected: Iterable[str], label: str) -> Dict[str, object]:
    if not isinstance(value, dict) or set(value) != set(expected):
        stop(f"{label} has missing or unexpected fields.")
    return value


def require_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None or value == "0" * 64:
        stop(f"{label} is not one non-placeholder SHA-256.")
    return value


def require_commit(value: object, label: str) -> str:
    if not isinstance(value, str) or COMMIT_RE.fullmatch(value) is None:
        stop(f"{label} is not one Git object ID.")
    return value


def write_atomic(logical: str, data: bytes, mode: int = 0o400) -> None:
    pathname = physical(logical)
    parent = os.path.dirname(pathname)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    if os.path.islink(parent):
        stop(f"fixed output parent is a symlink: {logical}.")
    temporary = os.path.join(parent, f".{os.path.basename(pathname)}.v1-evidence-{os.getpid()}-{secrets.token_hex(8)}")
    fd = -1
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
        os.write(fd, data)
        os.fsync(fd)
        os.fchmod(fd, mode)
        if not TEST_ROOT:
            os.fchown(fd, 0, 0)
        os.close(fd)
        fd = -1
        os.replace(temporary, pathname)
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    observed = read_bytes(logical, f"published {logical}", max(MAX_JSON, len(data) + 1))
    if observed != data:
        stop(f"published bytes changed: {logical}.")


def write_canonical(logical: str, value: object, mode: int = 0o400) -> bytes:
    data = canonical_bytes(value)
    write_atomic(logical, data, mode)
    return data


def command_environment(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    value = {"HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
    if extra:
        value.update(extra)
    return value


def run(
    arguments: Sequence[str], label: str, *, timeout: int = 300, environment: Optional[Dict[str, str]] = None,
    input_bytes: Optional[bytes] = None, maximum_output: int = MAX_COMMAND_OUTPUT, pass_fds: Sequence[int] = (),
) -> bytes:
    try:
        result = subprocess.run(
            list(arguments), stdin=None if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/", env=environment or command_environment(),
            input=input_bytes, timeout=timeout, check=False, pass_fds=tuple(pass_fds),
        )
    except (OSError, subprocess.SubprocessError) as error:
        stop(f"fixed {label} command failed without exposing private output: {error}.")
    if len(result.stdout) > maximum_output or len(result.stderr) > maximum_output:
        stop(f"fixed {label} output exceeded its boundary.")
    if result.returncode != 0:
        stop(f"fixed {label} command returned exit {result.returncode}; output was suppressed.")
    return result.stdout


def typed_executor(action: str, parameters: Dict[str, object], label: str) -> bytes:
    status, stdout, _ = executor_request(action, parameters)
    if status != 0:
        stop(f"fixed admitted {label} returned exit {status}; output was suppressed.")
    return stdout


def typed_executor_json(action: str, parameters: Dict[str, object], label: str) -> object:
    output = typed_executor(action, parameters, label)
    try:
        value = json.loads(output.decode("utf-8", errors="strict"), object_pairs_hook=duplicate_safe)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        stop(f"fixed admitted {label} returned invalid JSON: {error}.")
    if canonical_bytes(value) != output:
        stop(f"fixed admitted {label} returned noncanonical JSON.")
    return value


def check_no_stdin() -> None:
    try:
        readable, _, _ = select.select([0], [], [], 0)
        if readable and os.read(0, 1):
            stop("V1 evidence producer accepts no stdin.", 64)
    except (OSError, ValueError):
        stop("cannot prove empty stdin.", 64)


def acquire_lock(logical: str, label: str) -> int:
    pathname = physical(logical)
    os.makedirs(os.path.dirname(pathname), mode=0o755, exist_ok=True)
    if os.path.islink(pathname) or os.path.islink(os.path.dirname(pathname)):
        stop(f"{label} lock identity is unsafe.")
    fd = os.open(pathname, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        metadata = os.fstat(fd)
        expected_uid = os.geteuid() if TEST_ROOT else 0
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) != 0o600:
            stop(f"{label} lock identity is unsafe.")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        stop(f"another {label} transaction is running.", 75)
    except BaseException:
        os.close(fd)
        raise
    return fd


def validate_inherited_shared_lease() -> int:
    raw = os.environ.get(SHARED_LOCK_FD_ENV)
    if raw != "3":
        stop("evidence producer requires the fixed reconciler shared-lock lease FD 3.", 77)
    fd = 3
    pathname = physical(SHARED_LOCK)
    try:
        inherited = os.fstat(fd)
        target = os.lstat(pathname)
    except OSError as error:
        stop(f"cannot validate inherited shared-lock lease: {error.strerror}.", 77)
    expected_uid = os.geteuid() if TEST_ROOT else 0
    identity = lambda value: (value.st_dev, value.st_ino)
    if (
        identity(inherited) != identity(target) or not stat.S_ISREG(inherited.st_mode)
        or inherited.st_nlink != 1 or inherited.st_uid != expected_uid or stat.S_IMODE(inherited.st_mode) != 0o600
        or stat.S_IMODE(target.st_mode) != 0o600
    ):
        stop("inherited shared-lock lease identity is unsafe.", 77)
    probe = os.open(pathname, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            fcntl.flock(probe, fcntl.LOCK_UN)
            stop("inherited shared-lock lease was not already held by the reconciler.", 77)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            stop("shared lock is held by a different open-file-description.", 77)
    finally:
        os.close(probe)
    return fd


_executor_request_id = 0


def validate_executor_capability() -> int:
    if os.environ.get(EXECUTOR_FD_ENV) != str(EXECUTOR_FD):
        stop("evidence producer requires the fixed reconciler executor capability FD 4.", 77)
    try:
        metadata = os.fstat(EXECUTOR_FD)
    except OSError as error:
        stop(f"cannot inspect reconciler executor capability: {error.strerror}.", 77)
    if not stat.S_ISSOCK(metadata.st_mode):
        stop("reconciler executor capability is not one inherited Unix socket.", 77)
    if not TEST_ROOT:
        try:
            probe = socket.fromfd(EXECUTOR_FD, socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                credentials = probe.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            finally:
                probe.close()
            _, uid, gid = struct.unpack("3i", credentials)
        except (AttributeError, OSError, struct.error) as error:
            stop(f"cannot prove reconciler executor peer credentials: {error}.", 77)
        if uid != 0 or gid != 0:
            stop("reconciler executor peer is not root-owned.", 77)
    return EXECUTOR_FD


def executor_request(action: str, parameters: Dict[str, object]) -> Tuple[int, bytes, bytes]:
    global _executor_request_id
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
    if action not in parameter_keys:
        stop("internal executor action is outside the closed typed V1 allowlist.")
    value = exact_keys(parameters, parameter_keys[action], f"{action} executor parameters")
    run_id = value.get("runId")
    if not isinstance(run_id, str) or RUN_ID_RE.fullmatch(run_id) is None:
        stop(f"{action} executor run ID is invalid.")
    if "logicalKey" in value and value["logicalKey"] not in LOGICAL_KEYS:
        stop(f"{action} executor logical family is invalid.")
    if "database" in value and value["database"] not in ("stexor", "keycloak"):
        stop("PostgreSQL executor database is outside the closed pair.")
    if "tool" in value and value["tool"] not in ("mariadbRestore", "minioRestore", "nodeUtility", "postgresRestore", "resticRclone"):
        stop("backup helper executor tool is outside the closed authority set.")
    if "snapshotId" in value and (not isinstance(value["snapshotId"], str) or SNAPSHOT_ID_RE.fullmatch(value["snapshotId"]) is None):
        stop("Restic executor snapshot ID is invalid.")
    validate_executor_capability()
    _executor_request_id += 1
    request = canonical_bytes({"action": action, "id": _executor_request_id, "parameters": value})
    if len(request) > 4 * 1024 * 1024:
        stop("executor request exceeded its fixed boundary.")
    offset = 0
    while offset < len(request):
        try:
            offset += os.write(EXECUTOR_FD, request[offset:])
        except OSError as error:
            stop(f"reconciler executor request failed: {error.strerror}.")
    chunks = []
    total = 0
    newline_at = -1
    while True:
        try:
            chunk = os.read(EXECUTOR_FD, min(1024 * 1024, MAX_EXECUTOR_FRAME + 1 - total))
        except OSError as error:
            stop(f"reconciler executor response failed: {error.strerror}.")
        if not chunk:
            stop("reconciler executor closed before one response.")
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_EXECUTOR_FRAME:
            stop("reconciler executor response exceeded its fixed boundary.")
        joined = b"".join(chunks)
        newline_at = joined.find(b"\n")
        if newline_at >= 0:
            break
    data = b"".join(chunks)
    if newline_at != len(data) - 1:
        stop("reconciler executor response contained trailing or multiple frames.")
    try:
        response = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=duplicate_safe)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        stop(f"reconciler executor response is not strict JSON: {error}.")
    response = exact_keys(response, ("id", "status", "stderrBase64", "stdoutBase64"), "reconciler executor response")
    if canonical_bytes(response) != data or response["id"] != _executor_request_id:
        stop("reconciler executor response is noncanonical or belongs to another request.")
    status = response["status"]
    if isinstance(status, bool) or not isinstance(status, int) or status < 0 or status > 255:
        stop("reconciler executor response status is invalid.")
    try:
        stdout = base64.b64decode(response["stdoutBase64"], validate=True)
        stderr = base64.b64decode(response["stderrBase64"], validate=True)
    except (TypeError, ValueError):
        stop("reconciler executor response payload is not strict base64.")
    if len(stdout) > MAX_COMMAND_OUTPUT or len(stderr) > MAX_COMMAND_OUTPUT:
        stop("reconciler executor response output exceeded its boundary.")
    return status, stdout, stderr


def recover_stale_private_temp_roots() -> int:
    parent = physical("/dev/shm")
    os.makedirs(parent, mode=0o1777, exist_ok=True)
    pattern = re.compile(r"^platform-v1-evidence-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}-[A-Za-z0-9_-]+$")
    expected_uid = os.geteuid() if TEST_ROOT else 0
    removed = 0
    for name in sorted(os.listdir(parent)):
        if not name.startswith("platform-v1-evidence-"):
            continue
        pathname = os.path.join(parent, name)
        metadata = os.lstat(pathname)
        if (
            pattern.fullmatch(name) is None or not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            stop("stale V1 evidence tmpfs root has unsafe identity and was not removed.")
        for current, directories, files in os.walk(pathname, topdown=True, followlinks=False):
            for child in [*directories, *files]:
                child_path = os.path.join(current, child)
                child_metadata = os.lstat(child_path)
                if child_metadata.st_uid != expected_uid:
                    stop("stale V1 evidence tmpfs tree contains a foreign-owned entry.")
        shutil.rmtree(pathname)
        removed += 1
    if any(name.startswith("platform-v1-evidence-") for name in os.listdir(parent)):
        stop("stale V1 evidence tmpfs root remained after startup recovery.")
    return removed


def parse_env(logical: str) -> Dict[str, str]:
    data = read_fixed_data_file(logical, "fixed deployment environment", 1024 * 1024)
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        stop("fixed deployment environment is not UTF-8.")
    result: Dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            stop("fixed deployment environment contains a non-assignment.")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) is None or key in result:
            stop("fixed deployment environment contains a duplicate or invalid key.")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        result[key] = value
    if result.get(CONFIDENTIAL_PASSPHRASE_ENV) != CONFIDENTIAL_PASSPHRASE:
        stop("fixed deployment environment does not bind the dedicated confidential-backup passphrase path.")
    return result


def stable_git_archive_sha(repo_root: str) -> Tuple[str, str, str]:
    git = binary(GIT, "PLATFORM_V1_EVIDENCE_TEST_GIT")
    environment = command_environment({"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0"})
    def git_out(args: Sequence[str], label: str) -> str:
        return run([git, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", f"safe.directory={repo_root}", "-C", repo_root, *args], f"Git {label}", timeout=120, environment=environment).decode("ascii", errors="strict").strip()
    head = git_out(["rev-parse", "HEAD"], "HEAD")
    tree = git_out(["rev-parse", "HEAD^{tree}"], "tree")
    github_main = git_out(["rev-parse", "refs/remotes/github/main"], "github/main")
    status = git_out(["status", "--porcelain=v1", "--untracked-files=all"], "status")
    if head != github_main or status or COMMIT_RE.fullmatch(head) is None or COMMIT_RE.fullmatch(tree) is None:
        stop("fixed staging checkout is not clean exact github/main.")
    archive = run([git, "-c", "core.hooksPath=/dev/null", "-C", repo_root, "archive", "--format=tar", "HEAD"], "Git exact archive", timeout=180, environment=environment, maximum_output=MAX_ARCHIVE)
    return head, tree, digest_bytes(archive)


def validate_archive_member(script_logical: str) -> None:
    archive_path = physical(SOURCE_ARCHIVE)
    script_path = physical(script_logical)
    expected_name = "scripts/v1-local-private-evidence-producer.py"
    try:
        with tarfile.open(archive_path, "r:") as archive:
            matches = [member for member in archive.getmembers() if member.name == expected_name]
            if len(matches) != 1 or not matches[0].isfile() or matches[0].issym() or matches[0].islnk():
                stop("exact source archive does not contain one regular evidence producer.")
            extracted = archive.extractfile(matches[0])
            if extracted is None:
                stop("cannot read exact source archive evidence producer.")
            archived = extracted.read(4 * 1024 * 1024 + 1)
            if len(archived) > 4 * 1024 * 1024:
                stop("archived evidence producer exceeds its boundary.")
    except (OSError, tarfile.TarError) as error:
        stop(f"cannot inspect exact source archive producer: {error}.")
    with open(script_path, "rb") as current:
        current_bytes = current.read(4 * 1024 * 1024 + 1)
    if archived != current_bytes:
        stop("running evidence producer differs from the exact source archive.")


def load_binding(operation: str) -> Dict[str, object]:
    install, _ = read_json(INSTALL_CHECKPOINT, "fresh install checkpoint")
    commit = require_commit(install.get("candidateCommit"), "install candidateCommit")
    tree = require_commit(install.get("candidateTree"), "install candidateTree")
    archive_sha = require_sha(install.get("sourceArchiveSha256"), "install sourceArchiveSha256")
    if digest_file(SOURCE_ARCHIVE) != archive_sha:
        stop("exact source archive differs from the install checkpoint.")
    authority, authority_bytes = read_json(AUTHORITY, "exact release authority")
    if authority.get("schema") != "platform.v1-local-private-exact-release-authority/v1" or authority.get("status") != "AUTHORIZED":
        stop("exact release authority status/schema is invalid.")
    if (authority.get("candidateCommit"), authority.get("candidateTree"), authority.get("sourceArchiveSha256")) != (commit, tree, archive_sha):
        stop("exact release authority differs from the install checkpoint.")
    code_root = authority.get("releaseRoot")
    if code_root != f"/srv/platform-infrastructure/releases/{commit}-{archive_sha}":
        stop("exact release authority root is not commit/archive-derived.")
    script_logical = f"{code_root}/scripts/v1-local-private-evidence-producer.py"
    validate_archive_member(script_logical)
    producer_authority = exact_keys(
        authority.get("evidenceProducer"), (
            "executor", "executorFlags", "forbiddenResticOperations", "hostingerAllowed", "logicalKeys", "offsiteRepository",
            "operations", "path", "recoveryEscrowPrefix", "sha256",
        ), "evidence producer authority",
    )
    producer_bytes = read_bytes(script_logical, "authority-bound evidence producer", 4 * 1024 * 1024)
    assert producer_bytes is not None
    if producer_authority != {
        "executor": PYTHON, "executorFlags": ["-I"], "forbiddenResticOperations": ["forget", "prune"],
        "hostingerAllowed": False, "logicalKeys": list(LOGICAL_KEYS), "offsiteRepository": ONEDRIVE_REPOSITORY,
        "operations": ["pre", "post"], "path": script_logical, "recoveryEscrowPrefix": ESCROW_REMOTE_PREFIX,
        "sha256": digest_bytes(producer_bytes),
    }:
        stop("evidence producer authority differs from the closed V1 executable/operation/off-site contract.")
    certificate = exact_keys(
        authority.get("recoveryEscrowCertificate"), ("path", "sha256", "sha256Fingerprint"),
        "recovery escrow certificate authority",
    )
    certificate_path = f"{code_root}/{RECOVERY_CERT_RELATIVE}"
    certificate_bytes = read_bytes(certificate_path, "authority-bound recovery escrow certificate", 256 * 1024)
    assert certificate_bytes is not None
    if certificate["path"] != certificate_path or digest_bytes(certificate_bytes) != certificate["sha256"]:
        stop("recovery escrow certificate path/bytes differ from exact authority.")
    certificate_der = run(
        [binary(OPENSSL, "PLATFORM_V1_EVIDENCE_TEST_OPENSSL"), "x509", "-in", physical(certificate_path), "-outform", "DER"],
        "recovery escrow certificate DER", timeout=30, maximum_output=256 * 1024,
    )
    certificate_text = run(
        [binary(OPENSSL, "PLATFORM_V1_EVIDENCE_TEST_OPENSSL"), "x509", "-in", physical(certificate_path), "-noout", "-text"],
        "recovery escrow certificate inspection", timeout=30, maximum_output=512 * 1024,
    )
    if digest_bytes(certificate_der) != certificate["sha256Fingerprint"] or b"Public-Key: (4096 bit)" not in certificate_text:
        stop("recovery escrow certificate fingerprint/key size differs from exact authority.")
    backup_tools = exact_keys(
        authority.get("backupToolImages"), ("mariadbRestore", "minioRestore", "nodeUtility", "postgresRestore", "resticRclone"),
        "backup tool images authority",
    )
    for name, raw in backup_tools.items():
        tool = exact_keys(raw, ("imageId", "imageReference"), f"{name} backup tool image authority")
        if (
            IMAGE_ID_RE.fullmatch(str(tool["imageId"])) is None or not isinstance(tool["imageReference"], str)
            or "@sha256:" not in tool["imageReference"]
        ):
            stop("backup tool image authority identity/reference is not digest-pinned.")
    if operation == "pre":
        if os.path.lexists(physical(RECONCILIATION)) or os.path.lexists(physical(JOURNAL)):
            stop("pre evidence must be the final gate before begin/apply, without a reconciliation transaction.")
        began = int(time.time())
        transaction_id = None
        evidence_preimages = None
        reconciliation_sha = None
    else:
        reconciliation, reconciliation_bytes = read_json(RECONCILIATION, "LOCAL_PRIVATE reconciliation")
        journal, _ = read_json(JOURNAL, "LOCAL_PRIVATE reconciliation journal")
        began = reconciliation.get("beganAtUnixSeconds")
        transaction_id = journal.get("transactionId")
        if (
            not isinstance(began, int) or isinstance(began, bool) or began < 1700000000
            or journal.get("phase") != "APPLIED" or TRANSACTION_ID_RE.fullmatch(str(transaction_id or "")) is None
            or journal.get("authorityDocumentId") not in (None, authority.get("documentId"))
        ):
            stop("post evidence requires one completely applied, transaction-bound reconciliation.")
        if digest_bytes(authority_bytes) != reconciliation.get("releaseAuthoritySha256"):
            stop("reconciliation differs from the exact release authority bytes.")
        evidence_preimages = journal.get("evidencePreimages")
        reconciliation_sha = digest_bytes(reconciliation_bytes)
    if os.path.realpath(physical(script_logical)) != os.path.realpath(sys.argv[0]):
        stop("evidence producer was not invoked from the fixed exact-main path.")
    return {
        "archiveSha256": archive_sha,
        "beganAtUnixSeconds": began,
        "candidateCommit": commit,
        "candidateTree": tree,
        "codeRoot": code_root,
        "scriptPath": script_logical,
        "transactionId": transaction_id,
        "evidencePreimages": evidence_preimages,
        "evidencePreimagesSha256": digest_bytes(canonical_bytes(evidence_preimages)) if evidence_preimages is not None else None,
        "authorityDocumentId": authority.get("documentId"),
        "authoritySha256": digest_bytes(authority_bytes),
        "recoveryEscrowCertificate": certificate,
        "reconciliationSha256": reconciliation_sha,
        "backupToolImages": backup_tools,
        "operation": operation,
    }


def revalidate_post_transaction(binding: Dict[str, object]) -> None:
    if binding.get("transactionId") is None:
        return
    authority, authority_bytes = read_json(AUTHORITY, "revalidated exact release authority")
    reconciliation, reconciliation_bytes = read_json(RECONCILIATION, "revalidated LOCAL_PRIVATE reconciliation")
    journal, _ = read_json(JOURNAL, "revalidated LOCAL_PRIVATE reconciliation journal")
    if (
        digest_bytes(authority_bytes) != binding["authoritySha256"]
        or authority.get("documentId") != binding["authorityDocumentId"]
        or digest_bytes(reconciliation_bytes) != binding["reconciliationSha256"]
        or reconciliation.get("releaseAuthoritySha256") != binding["authoritySha256"]
        or journal.get("transactionId") != binding["transactionId"]
        or journal.get("phase") != "APPLIED"
        or digest_bytes(canonical_bytes(journal.get("evidencePreimages"))) != binding["evidencePreimagesSha256"]
    ):
        stop("post reconciliation/authority/rollback binding changed during evidence production.")


def docker_inventory(run_id: str) -> Dict[str, object]:
    receipt = exact_keys(
        typed_executor_json("RUNTIME_INVENTORY", {"runId": run_id}, "runtime inventory"),
        ("containerIds", "containers", "status", "volumes"), "runtime inventory executor result",
    )
    if receipt["status"] != "PASS":
        stop("runtime inventory executor returned a non-PASS receipt.")
    identifiers = receipt["containerIds"]
    if not isinstance(identifiers, list) or any(not isinstance(item, str) for item in identifiers):
        stop("Docker container ID inventory is not one string list.")
    if len(identifiers) != len(set(identifiers)) or any(SHA256_RE.fullmatch(item) is None for item in identifiers):
        stop("Docker container ID inventory is invalid.")
    if identifiers != sorted(identifiers):
        stop("Docker container ID inventory is not in canonical order.")
    objects = receipt["containers"]
    if not isinstance(objects, list) or len(objects) != len(identifiers):
        stop("Docker container inventory cardinality differs.")
    containers = []
    secret_mounts = []
    secret_references = []
    for expected_identifier, raw in zip(identifiers, objects):
        if not isinstance(raw, dict):
            stop("Docker inventory contains a non-object.")
        name = str(raw.get("Name", "")).lstrip("/")
        identifier = str(raw.get("Id", ""))
        image = str(raw.get("Image", ""))
        state = raw.get("State") if isinstance(raw.get("State"), dict) else {}
        restart = raw.get("RestartCount")
        if not name or identifier != expected_identifier or SHA256_RE.fullmatch(identifier) is None or IMAGE_ID_RE.fullmatch(image) is None or not isinstance(restart, int):
            stop("Docker container identity is invalid.")
        containers.append({"containerId": identifier, "imageId": image, "name": name, "restartCount": restart, "state": state.get("Status")})
        config = raw.get("Config") if isinstance(raw.get("Config"), dict) else {}
        for config_field in ("Env", "Cmd", "Entrypoint"):
            values = config.get(config_field)
            if isinstance(values, str):
                values = [values]
            if not isinstance(values, list):
                continue
            for value in values:
                if not isinstance(value, str):
                    continue
                for destination in sorted(set(re.findall(r"/run/secrets/[A-Za-z0-9._-]+", value))):
                    secret_references.append({"containerName": name, "destination": destination})
        mounts = raw.get("Mounts") if isinstance(raw.get("Mounts"), list) else []
        for mount in mounts:
            if not isinstance(mount, dict) or not str(mount.get("Destination", "")).startswith("/run/secrets/"):
                continue
            source = str(mount.get("Source", ""))
            destination = str(mount.get("Destination", ""))
            if not source.startswith(f"{SECRETS_ROOT}/") or mount.get("RW") is not False:
                stop("runtime secret mount escapes the fixed read-only secret root.")
            source_path = physical(source)
            metadata = os.lstat(source_path)
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                stop("runtime secret mount source is not one regular file.")
            secret_mounts.append({"containerName": name, "destination": destination, "source": source})
    containers.sort(key=lambda item: item["name"])
    secret_mounts.sort(key=lambda item: (item["containerName"], item["destination"], item["source"]))
    secret_references = sorted(
        {canonical(item): item for item in secret_references}.values(), key=lambda item: (item["containerName"], item["destination"])
    )
    mounted = {(item["containerName"], item["destination"]) for item in secret_mounts}
    unmounted_references = [item for item in secret_references if (item["containerName"], item["destination"]) not in mounted]
    volumes = receipt["volumes"]
    if not isinstance(volumes, list) or any(not isinstance(item, str) or not item for item in volumes):
        stop("Docker volume inventory is not one nonempty string list.")
    if len(volumes) != len(set(volumes)) or volumes != sorted(volumes):
        stop("Docker volume inventory is duplicated.")
    return {
        "containers": containers, "secretMounts": secret_mounts, "secretReferences": secret_references,
        "unmountedSecretReferences": unmounted_references, "volumes": volumes,
    }


def assert_scheduler_absent_post(inventory: Dict[str, object]) -> None:
    names = {item["name"] for item in inventory["containers"]}
    if "enterprise-backup-scheduler" in names:
        stop("post evidence forbids the legacy scheduler canonical container.")


def payload_files() -> List[str]:
    root = physical(BACKUPS_ROOT)
    patterns = (
        "applications/**/*.tar.gz", "postgres/*.dump", "mariadb/*.sql.gz",
        "minio/*.tar.gz", "keycloak/*.tar.gz", "secret-manager/*.tar.gz", "secret-manager-real/*.tar.gpg",
    )
    result = []
    for pattern in patterns:
        result.extend(str(item) for item in Path(root).glob(pattern) if item.is_file() and not item.is_symlink())
    return sorted(set(result))


def run_infra(
    binding: Dict[str, object], run_id: str, operation: str, *, database: Optional[str] = None,
    logical_key: Optional[str] = None,
) -> Dict[str, object]:
    del binding
    action_by_operation = {
        "backup-applications": "BACKUP_APPLICATIONS", "backup-postgres": "BACKUP_POSTGRES",
        "backup-mariadb": "BACKUP_MARIADB", "backup-minio": "BACKUP_MINIO",
        "backup-keycloak": "BACKUP_KEYCLOAK", "backup-secret-manager-metadata": "BACKUP_SECRET_METADATA",
        "restore-test-postgres": "RESTORE_POSTGRES", "restore-test-mariadb": "RESTORE_MARIADB",
        "restore-test-minio": "RESTORE_MINIO", "restore-test-keycloak": "RESTORE_KEYCLOAK",
    }
    action = action_by_operation.get(operation)
    if action is None:
        stop("internal infra operation is outside the fixed producer allowlist.")
    parameters: Dict[str, object] = {"runId": run_id}
    if action == "BACKUP_POSTGRES":
        parameters["database"] = database
    elif action == "RESTORE_POSTGRES":
        parameters["logicalKey"] = logical_key
    result = typed_executor_json(action, parameters, f"{operation} workflow")
    if operation.startswith("restore-test-"):
        value = exact_keys(result, ("action", "comparatorReceipt", "status"), f"{operation} executor result")
    else:
        value = exact_keys(result, ("action", "status"), f"{operation} executor result")
    if value["action"] != action or value["status"] != "PASS":
        stop(f"{operation} executor returned a non-PASS or cross-action result.")
    return value


def find_new(before: Iterable[str], predicate, expected: int, label: str) -> List[str]:
    old = set(before)
    new = [path for path in payload_files() if path not in old and predicate(path)]
    if len(new) != expected:
        stop(f"{label} produced {len(new)} payloads, expected {expected}.")
    return sorted(new)


def parse_versioned_keys() -> List[Tuple[str, bytes]]:
    data = read_fixed_data_file(BACKUP_SIGNING_KEYS, "backup signing keyring", 65536)
    try:
        value = data.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError:
        stop("backup signing keyring is not UTF-8.")
    result = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        key_id, separator, secret_value = item.partition("=")
        if not separator or KEY_ID_RE.fullmatch(key_id.strip()) is None or len(secret_value.strip()) < 48:
            stop("backup signing keyring contains an invalid key.")
        result.append((key_id.strip(), secret_value.strip().encode("utf-8")))
    if not result and len(value) >= 48:
        result.append(("legacy", value.encode("utf-8")))
    if not result or len({item[0] for item in result}) != len(result):
        stop("backup signing keyring is empty or duplicated.")
    return result


def read_regular_path(pathname: str, label: str, maximum: int) -> bytes:
    try:
        fd = os.open(pathname, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        stop(f"cannot open {label}: {error.strerror}.")
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size < 1 or before.st_size > maximum
            or stat.S_IMODE(before.st_mode) & 0o022
        ):
            stop(f"{label} identity/mode/size is invalid.")
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                stop(f"{label} became truncated while read.")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            stop(f"{label} grew while read.")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            stop(f"{label} changed while read.")
        return b"".join(chunks)
    finally:
        os.close(fd)


def signature_message(name: str, sha256: str) -> bytes:
    return f"platform-postgres-backup-v1\n{name}\n{sha256}\n".encode("utf-8")


def verify_artifact(pathname: str, *, require_backup_root: bool = True) -> Dict[str, object]:
    logical = pathname[len(TEST_ROOT):] if TEST_ROOT and pathname.startswith(TEST_ROOT) else pathname
    if require_backup_root and not logical.startswith(f"{BACKUPS_ROOT}/"):
        stop("backup payload escaped the fixed backup root.")
    metadata = os.lstat(pathname)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size < 1:
        stop("backup payload is not one non-empty regular file.")
    sha = digest_file(logical)
    checksum_path = f"{pathname}.sha256"
    signature_path = f"{pathname}.sig.json"
    try:
        checksum_raw = read_regular_path(checksum_path, "backup checksum sidecar", 4096)
        checksum = checksum_raw.decode("utf-8", errors="strict").strip().split()[0]
        sidecar_raw = read_regular_path(signature_path, "backup HMAC sidecar", 65536)
        sidecar = json.loads(sidecar_raw.decode("utf-8", errors="strict"), object_pairs_hook=duplicate_safe)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, IndexError) as error:
        stop(f"backup sidecar is unreadable or invalid: {error}.")
    expected_fields = {"algorithm", "artifact", "keyId", "sha256", "signature", "signedAt", "version"}
    if (
        checksum != sha or not isinstance(sidecar, dict) or set(sidecar) != expected_fields
        or sidecar.get("version") != 1 or sidecar.get("algorithm") != "HMAC-SHA256"
        or sidecar.get("artifact") != os.path.basename(pathname) or sidecar.get("sha256") != sha
        or KEY_ID_RE.fullmatch(str(sidecar.get("keyId", ""))) is None
    ):
        stop("backup checksum or HMAC metadata differs from the payload.")
    try:
        supplied = str(sidecar["signature"]).encode("ascii")
    except UnicodeEncodeError:
        stop("backup HMAC signature is not ASCII.")
    keys = dict(parse_versioned_keys())
    secret_value = keys.get(str(sidecar["keyId"]))
    valid = secret_value is not None and hmac.compare_digest(
        base64.urlsafe_b64encode(hmac.new(secret_value, signature_message(os.path.basename(pathname), sha), hashlib.sha256).digest()).rstrip(b"="),
        supplied,
    )
    if not valid:
        stop("backup HMAC verification failed.")
    return {
        "checksumPath": checksum_path, "checksumSha256": digest_bytes(checksum_raw),
        "hmacKeyId": sidecar["keyId"],
        "hmacPath": signature_path, "hmacSha256": digest_bytes(sidecar_raw),
        "path": pathname,
        "sha256": sha,
        "sizeBytes": metadata.st_size,
    }


def snapshot_regular_file(source: str, destination: str, maximum: int) -> Tuple[str, int]:
    try:
        source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        stop(f"cannot snapshot verified artifact input: {error.strerror}.")
    destination_fd = -1
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size < 1 or before.st_size > maximum:
            stop("verified artifact input identity changed before transaction snapshot.")
        os.makedirs(os.path.dirname(destination), mode=0o700, exist_ok=True)
        destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
        hasher = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                stop("verified artifact input exceeded its transaction snapshot boundary.")
            hasher.update(chunk)
            offset = 0
            while offset < len(chunk):
                offset += os.write(destination_fd, chunk[offset:])
        os.fsync(destination_fd)
        os.fchmod(destination_fd, 0o400)
        after = os.fstat(source_fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            stop("verified artifact input changed while transaction-snapshotted.")
        return hasher.hexdigest(), total
    finally:
        os.close(source_fd)
        if destination_fd >= 0:
            os.close(destination_fd)


def snapshot_artifact_record(
    verified: Dict[str, object], index: int, logical_key: str, logical_path: str, temp_root: str,
) -> Dict[str, object]:
    root = os.path.join(temp_root, "artifact-staging", f"{index:02d}-{logical_key}")
    mappings = (
        ("path", "sha256", MAX_ARCHIVE), ("checksumPath", "checksumSha256", 4096), ("hmacPath", "hmacSha256", 65536),
    )
    staged = {}
    for path_key, digest_key, maximum in mappings:
        source = str(verified[path_key])
        destination = os.path.join(root, os.path.basename(source))
        observed_sha, _ = snapshot_regular_file(source, destination, maximum)
        if observed_sha != verified[digest_key]:
            stop("transaction artifact snapshot differs from the verified payload/sidecar identity.")
        staged[path_key] = destination
    observed = verify_artifact(staged["path"], require_backup_root=False)
    if observed["sha256"] != verified["sha256"] or observed["hmacKeyId"] != verified["hmacKeyId"]:
        stop("root-owned transaction artifact set failed independent checksum/HMAC revalidation.")
    return {
        **observed, "logicalChecksumPath": str(verified["checksumPath"]), "logicalHmacPath": str(verified["hmacPath"]),
        "logicalPath": logical_path,
    }


def sign_artifact(pathname: str) -> Dict[str, object]:
    sha = digest_file(pathname[len(TEST_ROOT):] if TEST_ROOT and pathname.startswith(TEST_ROOT) else pathname)
    name = os.path.basename(pathname)
    key_id, secret_value = parse_versioned_keys()[0]
    signature = base64.urlsafe_b64encode(hmac.new(secret_value, signature_message(name, sha), hashlib.sha256).digest()).rstrip(b"=").decode("ascii")
    checksum = f"{sha}  {name}\n".encode("ascii")
    document = {
        "algorithm": "HMAC-SHA256", "artifact": name, "keyId": key_id, "sha256": sha,
        "signature": signature, "signedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "version": 1,
    }
    checksum_logical = (f"{pathname}.sha256")[len(TEST_ROOT):] if TEST_ROOT and pathname.startswith(TEST_ROOT) else f"{pathname}.sha256"
    signature_logical = (f"{pathname}.sig.json")[len(TEST_ROOT):] if TEST_ROOT and pathname.startswith(TEST_ROOT) else f"{pathname}.sig.json"
    write_atomic(checksum_logical, checksum, 0o600)
    write_atomic(signature_logical, canonical_bytes(document), 0o600)
    return verify_artifact(pathname)


def overlay_sources() -> List[Tuple[str, str]]:
    root = Path(physical(PROJECT_SOURCE_ROOT))
    selected: List[Tuple[str, str]] = []
    recursive = (
        "anniversary/private/database", "stream/private/database", "workcalendar/database",
    )
    exact = (
        "fiplatform/private/.env", "fiplatform/private/cache/app_cache.sqlite",
        "stream/private/.env", "stream/private/.env.example",
    )
    for relative in recursive:
        directory = root / relative
        if not directory.is_dir() or directory.is_symlink():
            stop(f"required recovery overlay directory is missing: {relative}.")
        for file_path in sorted(directory.rglob("*")):
            if file_path.is_symlink() or (file_path.exists() and not file_path.is_file()):
                stop("recovery overlay contains a link or non-regular entry.")
            if file_path.is_file():
                selected.append((str(file_path), str(file_path.relative_to(root))))
    for relative in exact:
        file_path = root / relative
        if not file_path.is_file() or file_path.is_symlink():
            stop(f"required recovery overlay file is missing: {relative}.")
        selected.append((str(file_path), relative))
    matthew = root / "matthewdifilippo"
    for file_path in sorted(matthew.glob(".env*")) + sorted((matthew / "build").glob("**/.env*")):
        if file_path.is_symlink() or not file_path.is_file():
            stop("matthewdifilippo recovery overlay contains an unsafe entry.")
        selected.append((str(file_path), str(file_path.relative_to(root))))
    if not any(relative == "matthewdifilippo/.env" for _, relative in selected):
        stop("matthewdifilippo recovery overlay omits its active environment.")
    deduplicated = {relative: source for source, relative in selected}
    if len(deduplicated) != len(selected):
        stop("recovery overlay source set is duplicated.")
    return [(deduplicated[key], key) for key in sorted(deduplicated)]


def copy_regular(source: str, destination: str) -> Dict[str, object]:
    metadata = os.lstat(source)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink != 1:
        stop("confidential backup source is not one regular non-linked file.")
    os.makedirs(os.path.dirname(destination), mode=0o700, exist_ok=True)
    shutil.copyfile(source, destination, follow_symlinks=False)
    os.chmod(destination, stat.S_IMODE(metadata.st_mode))
    if not TEST_ROOT:
        os.chown(destination, metadata.st_uid, metadata.st_gid)
    os.utime(destination, ns=(metadata.st_atime_ns, metadata.st_mtime_ns), follow_symlinks=False)
    return {
        "gid": metadata.st_gid, "mode": stat.S_IMODE(metadata.st_mode), "sha256": digest_file(
            destination[len(TEST_ROOT):] if TEST_ROOT and destination.startswith(TEST_ROOT) else destination,
            max(1, metadata.st_size + 1), allow_empty=True,
        ), "sizeBytes": metadata.st_size, "uid": metadata.st_uid,
    }


def build_confidential_artifact(
    run_id: str, temp_root: str, secret_metadata: Dict[str, object],
) -> Tuple[Dict[str, object], Dict[str, Dict[str, object]]]:
    stage = os.path.join(temp_root, "confidential-stage")
    os.makedirs(stage, mode=0o700)
    manifest: Dict[str, Dict[str, object]] = {}
    secret_root = Path(physical(SECRETS_ROOT))
    for source in sorted(secret_root.rglob("*")):
        if source.is_symlink() or (source.exists() and not source.is_file() and not source.is_dir()):
            stop("fixed secret root contains a link or non-regular entry.")
        if source.is_file():
            relative = f"secret-files/{source.relative_to(secret_root)}"
            manifest[relative] = copy_regular(str(source), os.path.join(stage, relative))
    for source, relative_source in overlay_sources():
        relative = f"recovery-overlay/{relative_source}"
        manifest[relative] = copy_regular(source, os.path.join(stage, relative))
    state_root = Path(physical(PROJECT_STATE_ROOT))
    required_state = {"projects.json", "databases.json", "secret-vault.json", "operations.jsonl", "audit.jsonl"}
    if not state_root.is_dir() or state_root.is_symlink() or not required_state.issubset({item.name for item in state_root.iterdir()}):
        stop("curated Control Center state root is missing required files.")
    for source in sorted(state_root.rglob("*")):
        relative_source = source.relative_to(state_root)
        parts = relative_source.parts
        if "backup-jobs" in parts or any(
            fnmatch.fnmatchcase(part, "*.tmp") or fnmatch.fnmatchcase(part, "*.tmp-*") or fnmatch.fnmatchcase(part, "*.codex-*")
            for part in parts
        ):
            continue
        if source.is_symlink() or (source.exists() and not source.is_file() and not source.is_dir()):
            stop("curated Control Center state contains a link or special entry.")
        if source.is_file():
            relative = f"platform-state/control-center/{relative_source.as_posix()}"
            manifest[relative] = copy_regular(str(source), os.path.join(stage, relative))
    for key in ("path", "checksumPath", "hmacPath"):
        source = str(secret_metadata[key])
        relative = f"platform-metadata/secret-manager/{os.path.basename(source)}"
        manifest[relative] = copy_regular(source, os.path.join(stage, relative))
    if not manifest:
        stop("confidential recovery overlay is empty.")
    output_directory = physical(f"{BACKUPS_ROOT}/secret-manager-real")
    os.makedirs(output_directory, mode=0o700, exist_ok=True)
    final = os.path.join(output_directory, f"actual-secrets-recovery-overlay-{run_id}.tar.gpg")
    staging = f"{final}.staging-{os.getpid()}-{secrets.token_hex(8)}"
    tar_process = subprocess.Popen(
        ["/usr/bin/tar", "-cf", "-", "-C", stage, "secret-files", "recovery-overlay", "platform-state", "platform-metadata"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=command_environment(), cwd="/",
    )
    try:
        assert tar_process.stdout is not None
        gpg_result = subprocess.run(
            [binary(GPG, "PLATFORM_V1_EVIDENCE_TEST_GPG"), "--batch", "--yes", "--quiet", "--pinentry-mode", "loopback",
             "--passphrase-file", physical(CONFIDENTIAL_PASSPHRASE), "--symmetric", "--cipher-algo", "AES256", "--output", staging],
            stdin=tar_process.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=command_environment(), cwd="/", timeout=300, check=False,
        )
        tar_process.stdout.close()
        tar_stderr = tar_process.stderr.read(MAX_COMMAND_OUTPUT + 1) if tar_process.stderr is not None else b""
        tar_status = tar_process.wait(timeout=60)
        if tar_status != 0 or gpg_result.returncode != 0 or len(tar_stderr) > MAX_COMMAND_OUTPUT or len(gpg_result.stderr) > MAX_COMMAND_OUTPUT:
            stop("confidential backup encryption failed; output was suppressed.")
        os.chmod(staging, 0o600)
        os.replace(staging, final)
    finally:
        if tar_process.poll() is None:
            tar_process.kill()
            tar_process.wait()
        try:
            os.unlink(staging)
        except FileNotFoundError:
            pass
    return sign_artifact(final), manifest


def safe_member_name(name: str) -> str:
    normalized = name.removeprefix("./")
    if not normalized or normalized.startswith("/") or "\\" in normalized or "\x00" in normalized or ".." in normalized.split("/"):
        stop("restore archive contains an unsafe path.")
    return normalized.rstrip("/")


def application_path_excluded(relative: str) -> bool:
    parts = tuple(part for part in relative.split("/") if part)
    if any(part in APPLICATION_EXCLUDE_EXACT for part in parts):
        return True
    if any(fnmatch.fnmatchcase(part, pattern) for part in parts for pattern in APPLICATION_EXCLUDE_GLOBS):
        return True
    return any(relative == prefix or relative.startswith(f"{prefix}/") for prefix in APPLICATION_EXCLUDE_PATHS)


def capture_application_source(slug: str) -> Dict[str, object]:
    root = os.path.join(physical(PROJECT_SOURCE_ROOT), slug)
    if not os.path.isdir(root) or os.path.islink(root):
        stop(f"fixed application source is not one directory: {slug}.")
    rows = []
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        relative_parent = os.path.relpath(current, root)
        relative_parent = "" if relative_parent == "." else relative_parent.replace(os.sep, "/")
        kept_directories = []
        for name in sorted(directories):
            relative = f"{relative_parent}/{name}".lstrip("/")
            if application_path_excluded(relative):
                continue
            pathname = os.path.join(current, name)
            metadata = os.lstat(pathname)
            if stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(pathname)
                resolved = os.path.realpath(pathname)
                if os.path.isabs(target) or os.path.commonpath((root, resolved)) != root:
                    stop("application source contains an escaping symbolic link.")
                rows.append({"mode": stat.S_IMODE(metadata.st_mode), "path": relative, "target": target, "type": "symlink"})
            elif stat.S_ISDIR(metadata.st_mode):
                kept_directories.append(name)
                rows.append({"mode": stat.S_IMODE(metadata.st_mode), "path": relative, "type": "directory"})
            else:
                stop("application source contains a special directory entry.")
        directories[:] = kept_directories
        for name in sorted(files):
            relative = f"{relative_parent}/{name}".lstrip("/")
            if application_path_excluded(relative):
                continue
            pathname = os.path.join(current, name)
            metadata = os.lstat(pathname)
            if stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(pathname)
                resolved = os.path.realpath(pathname)
                if os.path.isabs(target) or os.path.commonpath((root, resolved)) != root:
                    stop("application source contains an escaping symbolic link.")
                rows.append({"mode": stat.S_IMODE(metadata.st_mode), "path": relative, "target": target, "type": "symlink"})
            elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                rows.append({
                    "mode": stat.S_IMODE(metadata.st_mode), "path": relative, "sha256": digest_file(
                        pathname[len(TEST_ROOT):] if TEST_ROOT and pathname.startswith(TEST_ROOT) else pathname,
                        max(1, metadata.st_size + 1), allow_empty=True,
                    ), "sizeBytes": metadata.st_size, "type": "file",
                })
            else:
                stop("application source contains a special or hard-linked file.")
    rows.sort(key=lambda item: (item["path"], item["type"]))
    if not any(item["type"] == "file" for item in rows):
        stop(f"application source has no selected regular files: {slug}.")
    return {"entryCount": len(rows), "rows": rows, "treeSha256": digest_bytes(canonical_bytes(rows))}


def restore_application(record: Dict[str, object], expected: Dict[str, object], temp_root: str) -> Dict[str, object]:
    slug = str(record["logicalKey"])
    target = os.path.join(temp_root, f"restore-app-{slug}")
    os.makedirs(target, mode=0o700)
    rows = []
    deferred_links = []
    try:
        with tarfile.open(record["path"], "r:gz") as archive:
            for member in archive.getmembers():
                name = safe_member_name(member.name)
                if name != slug and not name.startswith(f"{slug}/"):
                    stop("application restore archive contains a foreign project path.")
                relative = name[len(slug):].lstrip("/")
                if not relative:
                    continue
                if application_path_excluded(relative):
                    stop("application restore archive contains an excluded path.")
                if member.islnk() or not (member.isdir() or member.isfile() or member.issym()):
                    stop("application restore archive contains a link or special entry.")
                destination = os.path.join(target, name)
                if member.isdir():
                    os.makedirs(destination, mode=member.mode & 0o777)
                    rows.append({"mode": member.mode & 0o7777, "path": relative, "type": "directory"})
                    continue
                if member.issym():
                    link_target = member.linkname
                    resolved = os.path.realpath(os.path.join(os.path.dirname(destination), link_target))
                    project_target = os.path.join(target, slug)
                    if os.path.isabs(link_target) or os.path.commonpath((project_target, resolved)) != project_target:
                        stop("application restore archive contains an escaping symbolic link.")
                    deferred_links.append((destination, link_target))
                    rows.append({"mode": member.mode & 0o7777, "path": relative, "target": link_target, "type": "symlink"})
                    continue
                source = archive.extractfile(member)
                if source is None:
                    stop("application restore archive member is unreadable.")
                os.makedirs(os.path.dirname(destination), mode=0o700, exist_ok=True)
                with open(destination, "xb") as output:
                    hasher = hashlib.sha256()
                    size = 0
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        output.write(chunk)
                        hasher.update(chunk)
                        size += len(chunk)
                os.chmod(destination, member.mode & 0o777)
                rows.append({
                    "mode": member.mode & 0o7777, "path": relative, "sha256": hasher.hexdigest(),
                    "sizeBytes": size, "type": "file",
                })
            for destination, link_target in deferred_links:
                os.symlink(link_target, destination)
    except (OSError, tarfile.TarError) as error:
        stop(f"application restore failed: {error}.")
    rows.sort(key=lambda item: (item["path"], item["type"]))
    if rows != expected["rows"]:
        stop("application isolated restore tree differs from the captured source tree.")
    if not any(item["type"] == "file" for item in rows):
        stop("application restore produced no regular files.")
    return {
        "entryCount": len(rows), "restoreMode": "SAFE_TMPFS_TYPED_ARCHIVE_EXTRACT",
        "restoredTreeSha256": digest_bytes(canonical_bytes(rows)), "sourceTreeSha256": expected["treeSha256"],
    }


def restore_confidential(record: Dict[str, object], expected: Dict[str, Dict[str, object]], temp_root: str) -> Dict[str, object]:
    plain_tar = os.path.join(temp_root, "confidential-readback.tar")
    output = run(
        [binary(GPG, "PLATFORM_V1_EVIDENCE_TEST_GPG"), "--batch", "--quiet", "--pinentry-mode", "loopback",
         "--passphrase-file", physical(CONFIDENTIAL_PASSPHRASE), "--decrypt", record["path"]],
        "confidential backup decrypt", timeout=300, maximum_output=MAX_ARCHIVE,
    )
    with open(plain_tar, "xb") as handle:
        handle.write(output)
        handle.flush()
        os.fsync(handle.fileno())
    observed: Dict[str, Dict[str, object]] = {}
    try:
        with tarfile.open(plain_tar, "r:") as archive:
            for member in archive.getmembers():
                name = safe_member_name(member.name)
                if member.isdir():
                    continue
                if member.issym() or member.islnk() or not member.isfile() or name in observed:
                    stop("confidential restore contains a link, special or duplicate entry.")
                source = archive.extractfile(member)
                if source is None:
                    stop("confidential restore member is unreadable.")
                hasher = hashlib.sha256()
                size = 0
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    hasher.update(chunk)
                observed[name] = {"gid": member.gid, "mode": member.mode & 0o7777, "sha256": hasher.hexdigest(), "sizeBytes": size, "uid": member.uid}
    except (OSError, tarfile.TarError) as error:
        stop(f"confidential restore archive is invalid: {error}.")
    if observed != expected:
        stop("confidential restore content/metadata differs from its source snapshot.")
    tree_sha = digest_bytes(canonical_bytes(observed))
    return {
        "entryCount": len(observed), "restoreMode": "GPG_DECRYPT_TMPFS_CONTENT_METADATA_VERIFY",
        "restoredTreeSha256": tree_sha, "sourceTreeSha256": digest_bytes(canonical_bytes(expected)),
        "treeSha256": tree_sha,
    }


def require_nonnegative_integer(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        stop(f"{label} is not one bounded nonnegative integer.")
    return value


def validate_restore_receipt(receipt: object, operation: str, artifact_sha256: str) -> Dict[str, object]:
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
    counts_by_operation = {
        "restore-test-postgres": ("restoredTables",),
        "restore-test-mariadb": ("restoredSchemas", "restoredTables"),
        "restore-test-minio": ("bootHealthy", "restoredDurableEntries", "sourceDurableEntries"),
        "restore-test-keycloak": ("jsonCount", "realmCount"),
    }
    counts = exact_keys(value["counts"], counts_by_operation[operation], f"{operation} comparator counts")
    for name, raw in counts.items():
        if name == "bootHealthy":
            if raw is not True:
                stop("MinIO restored artifact did not pass its boot health receipt.")
        else:
            require_nonnegative_integer(raw, f"{operation} {name}", minimum=1)
    semantic = value["semanticComparator"]
    if operation in ("restore-test-postgres", "restore-test-mariadb"):
        semantic = exact_keys(semantic, (
            "algorithm", "components", "engine", "firstRestore", "firstRestoreSha256", "matched", "scope",
            "secondRestore", "secondRestoreSha256", "version",
        ), f"{operation} semantic comparator")
        engine = "postgres" if operation.endswith("postgres") else "mariadb"
        if (
            semantic["version"] != "platform.database-restore-semantic-comparator/v1"
            or semantic["engine"] != engine or semantic["algorithm"] != "sha256"
            or semantic["scope"] != expected_scope or semantic["matched"] is not True
            or semantic["firstRestore"] != semantic["secondRestore"]
        ):
            stop(f"{operation} independent restore comparator is inconsistent.")
        for name in ("firstRestoreSha256", "secondRestoreSha256"):
            require_sha(semantic[name], f"{operation} {name}")
        if semantic["firstRestoreSha256"] != semantic["secondRestoreSha256"]:
            stop(f"{operation} independent restore fingerprints differ.")
        fingerprint_keys = (
            ("combinedSha256", "largeObjectBytes", "largeObjectRows", "largeObjectsSha256", "relationCount", "rowCount",
             "rowDataSha256", "schemaBytes", "schemaLines", "sequenceCount", "sequencesSha256", "structureSha256")
            if engine == "postgres" else
            ("combinedSha256", "relationCount", "rowCount", "rowDataSha256", "schemaBytes", "schemaCount", "schemaLines",
             "schemaSetSha256", "structureSha256")
        )
        first = exact_keys(semantic["firstRestore"], fingerprint_keys, f"{operation} first fingerprint")
        second = exact_keys(semantic["secondRestore"], fingerprint_keys, f"{operation} second fingerprint")
        for name, raw in first.items():
            if name.endswith("Sha256"):
                require_sha(raw, f"{operation} {name}")
            else:
                require_nonnegative_integer(raw, f"{operation} {name}")
        if first != second or first["combinedSha256"] != semantic["firstRestoreSha256"]:
            stop(f"{operation} comparator fingerprints do not cross-bind their receipt.")
        component_names = (
            ("largeObjectsSha256", "rowDataSha256", "sequencesSha256", "structureSha256")
            if engine == "postgres" else ("rowDataSha256", "schemaSetSha256", "structureSha256")
        )
        components = exact_keys(semantic["components"], component_names, f"{operation} component comparison")
        for name, raw in components.items():
            component = exact_keys(raw, ("firstRestore", "matched", "secondRestore"), f"{operation} {name} comparison")
            if component != {"firstRestore": first[name], "matched": True, "secondRestore": second[name]}:
                stop(f"{operation} component comparison is inconsistent.")
    elif operation == "restore-test-minio":
        semantic = exact_keys(semantic, (
            "algorithm", "components", "engine", "matched", "restored", "restoredMatchesSource", "restoredSha256",
            "scope", "sourceAfter", "sourceAfterSha256", "sourceBefore", "sourceBeforeSha256", "sourceStable",
            "version", "volatileExclusions",
        ), "MinIO semantic comparator")
        exclusions = [
            ".minio.sys/tmp/*", ".minio.sys/buckets/.bloomcycle.bin/xl.meta",
            ".minio.sys/buckets/.usage.json/xl.meta",
        ]
        if (
            semantic["version"] != "platform.minio-restore-tree-comparator/v1" or semantic["engine"] != "minio"
            or semantic["algorithm"] != "sha256" or semantic["scope"] != expected_scope
            or semantic["matched"] is not True or semantic["sourceStable"] is not True
            or semantic["restoredMatchesSource"] is not True or semantic["volatileExclusions"] != exclusions
            or semantic["sourceBefore"] != semantic["sourceAfter"] or semantic["sourceBefore"] != semantic["restored"]
        ):
            stop("MinIO stable live-source/restored comparator is inconsistent.")
        tree_keys = ("combinedSha256", "directoryCount", "entryCount", "excludedPaths", "fileCount", "totalFileBytes", "treeSha256")
        source = exact_keys(semantic["sourceBefore"], tree_keys, "MinIO source-before fingerprint")
        exact_keys(semantic["sourceAfter"], tree_keys, "MinIO source-after fingerprint")
        exact_keys(semantic["restored"], tree_keys, "MinIO restored fingerprint")
        for name, raw in source.items():
            if name.endswith("Sha256"):
                require_sha(raw, f"MinIO {name}")
            elif name == "excludedPaths":
                if raw != exclusions:
                    stop("MinIO fingerprint exclusions differ from the exact historical set.")
            else:
                require_nonnegative_integer(raw, f"MinIO {name}")
        if source["entryCount"] < 1 or source["entryCount"] != source["fileCount"] + source["directoryCount"]:
            stop("MinIO durable tree counts are invalid.")
        for name in ("sourceBeforeSha256", "sourceAfterSha256", "restoredSha256"):
            require_sha(semantic[name], f"MinIO {name}")
        if not (
            semantic["sourceBeforeSha256"] == semantic["sourceAfterSha256"] == semantic["restoredSha256"] == source["combinedSha256"]
            and counts["sourceDurableEntries"] == counts["restoredDurableEntries"] == source["entryCount"]
        ):
            stop("MinIO durable-tree comparator does not cross-bind its counts/digests.")
        components = exact_keys(semantic["components"], ("treeSha256",), "MinIO component comparison")
        tree = exact_keys(components["treeSha256"], (
            "restored", "restoredMatchesSource", "sourceAfter", "sourceBefore", "sourceStable",
        ), "MinIO tree comparison")
        if tree != {
            "restored": source["treeSha256"], "restoredMatchesSource": True, "sourceAfter": source["treeSha256"],
            "sourceBefore": source["treeSha256"], "sourceStable": True,
        }:
            stop("MinIO tree component comparison is inconsistent.")
    else:
        semantic = exact_keys(semantic, (
            "algorithm", "components", "engine", "firstRestore", "firstRestoreSha256", "matched", "scope",
            "secondRestore", "secondRestoreSha256", "version",
        ), "Keycloak semantic comparator")
        if (
            semantic["version"] != "platform.keycloak-config-restore-semantic-comparator/v1"
            or semantic["engine"] != "keycloak" or semantic["algorithm"] != "sha256"
            or semantic["scope"] != expected_scope or semantic["matched"] is not True
            or semantic["firstRestore"] != semantic["secondRestore"]
        ):
            stop("Keycloak independent extract comparator is inconsistent.")
        fingerprint_keys = (
            "archiveTreeSha256", "canonicalContentSha256", "combinedSha256", "fileCount", "jsonCount", "rawJsonSetSha256",
            "realmCount", "totalJsonBytes",
        )
        first = exact_keys(semantic["firstRestore"], fingerprint_keys, "Keycloak first fingerprint")
        second = exact_keys(semantic["secondRestore"], fingerprint_keys, "Keycloak second fingerprint")
        for name, raw in first.items():
            if name.endswith("Sha256"):
                require_sha(raw, f"Keycloak {name}")
            else:
                require_nonnegative_integer(raw, f"Keycloak {name}", minimum=1)
        for name in ("firstRestoreSha256", "secondRestoreSha256"):
            require_sha(semantic[name], f"Keycloak {name}")
        if not (
            first == second
            and semantic["firstRestoreSha256"] == semantic["secondRestoreSha256"] == first["combinedSha256"]
        ):
            stop("Keycloak comparator fingerprints do not cross-bind their receipt.")
        component_names = ("archiveTreeSha256", "canonicalContentSha256", "rawJsonSetSha256")
        components = exact_keys(semantic["components"], component_names, "Keycloak component comparison")
        for name, raw in components.items():
            component = exact_keys(raw, ("firstRestore", "matched", "secondRestore"), f"Keycloak {name} comparison")
            if component != {"firstRestore": first[name], "matched": True, "secondRestore": second[name]}:
                stop("Keycloak component comparison is inconsistent.")
        if counts["realmCount"] != first["realmCount"] or counts["jsonCount"] != first["jsonCount"]:
            stop("Keycloak comparator counts do not cross-bind their receipt.")
    return value


def run_typed_restore(
    binding: Dict[str, object], run_id: str, record: Dict[str, object],
) -> Dict[str, object]:
    key = record["logicalKey"]
    if key in ("pg-stexor", "pg-keycloak"):
        result = run_infra(binding, run_id, "restore-test-postgres", logical_key=str(key))
        return {
            "comparatorReceipt": validate_restore_receipt(
                result["comparatorReceipt"], "restore-test-postgres", str(record["sha256"]),
            ),
            "restoreMode": "DIGEST_PINNED_NETWORK_NONE_READ_ONLY_TMPFS_POSTGRES",
        }
    if key == "mariadb":
        result = run_infra(binding, run_id, "restore-test-mariadb")
        return {
            "comparatorReceipt": validate_restore_receipt(
                result["comparatorReceipt"], "restore-test-mariadb", str(record["sha256"]),
            ),
            "restoreMode": "DISPOSABLE_NETWORK_NONE_MARIADB",
        }
    if key == "minio":
        result = run_infra(binding, run_id, "restore-test-minio")
        return {
            "comparatorReceipt": validate_restore_receipt(
                result["comparatorReceipt"], "restore-test-minio", str(record["sha256"]),
            ),
            "restoreMode": "DISPOSABLE_NETWORK_NONE_VOLUME_MINIO",
        }
    if key == "keycloak-config":
        result = run_infra(binding, run_id, "restore-test-keycloak")
        return {
            "comparatorReceipt": validate_restore_receipt(
                result["comparatorReceipt"], "restore-test-keycloak", str(record["sha256"]),
            ),
            "restoreMode": "READ_ONLY_CONFIG_JSON_KEYCLOAK",
        }
    stop("typed restore received an unknown family.")


def create_artifact_records(
    binding: Dict[str, object], run_id: str, temp_root: str,
) -> Tuple[List[Dict[str, object]], Dict[str, Dict[str, object]], Dict[str, Dict[str, object]]]:
    for tool_name in ("mariadbRestore", "minioRestore", "nodeUtility", "postgresRestore", "resticRclone"):
        assert_backup_tool_image(binding, run_id, tool_name)
    application_manifests = {slug: capture_application_source(slug) for slug in APP_SLUGS}
    before = payload_files()
    run_infra(binding, run_id, "backup-applications")
    applications = find_new(before, lambda path: "/applications/" in path and path.endswith(".tar.gz"), 8, "application backup")
    by_slug = {Path(path).parent.name: path for path in applications}
    if tuple(sorted(by_slug)) != tuple(sorted(APP_SLUGS)):
        stop("application backup family set differs from the exact eight applications.")
    before = payload_files()
    run_infra(binding, run_id, "backup-postgres", database="stexor")
    stexor = find_new(before, lambda path: "/postgres/" in path and Path(path).name.startswith("stexor-") and path.endswith(".dump"), 1, "stexor PostgreSQL backup")[0]
    before = payload_files()
    run_infra(binding, run_id, "backup-postgres", database="keycloak")
    keycloak_db = find_new(before, lambda path: "/postgres/" in path and Path(path).name.startswith("keycloak-") and path.endswith(".dump"), 1, "keycloak PostgreSQL backup")[0]
    before = payload_files()
    run_infra(binding, run_id, "backup-mariadb")
    mariadb = find_new(before, lambda path: "/mariadb/" in path and Path(path).name.startswith("mariadb-all-") and path.endswith(".sql.gz"), 1, "MariaDB backup")[0]
    before = payload_files()
    run_infra(binding, run_id, "backup-minio")
    minio = find_new(before, lambda path: "/minio/" in path and Path(path).name.startswith("minio-data-") and path.endswith(".tar.gz"), 1, "MinIO backup")[0]
    before = payload_files()
    run_infra(binding, run_id, "backup-keycloak")
    keycloak_config = find_new(before, lambda path: "/keycloak/" in path and Path(path).name.startswith("keycloak-config-") and path.endswith(".tar.gz"), 1, "Keycloak config backup")[0]
    before = payload_files()
    run_infra(binding, run_id, "backup-secret-manager-metadata")
    metadata_path = find_new(
        before, lambda path: "/secret-manager/" in path and Path(path).name.startswith("secret-manager-metadata-") and path.endswith(".tar.gz"),
        1, "Secret Manager metadata backup",
    )[0]
    secret_metadata = verify_artifact(metadata_path)
    confidential, confidential_manifest = build_confidential_artifact(run_id, temp_root, secret_metadata)
    for key in ("path", "checksumPath", "hmacPath"):
        os.unlink(str(secret_metadata[key]))
    paths = [by_slug[slug] for slug in APP_SLUGS] + [stexor, keycloak_db, mariadb, minio, keycloak_config, confidential["path"]]
    records = []
    for index, (key, path) in enumerate(zip(LOGICAL_KEYS, paths), start=1):
        verified = confidential if key == "confidential" else verify_artifact(path)
        logical_path = path[len(TEST_ROOT):] if TEST_ROOT and path.startswith(TEST_ROOT) else path
        staged = snapshot_artifact_record(verified, index, key, logical_path, temp_root)
        records.append({**staged, "artifactIndex": index, "logicalKey": key})
    if len(records) != 14 or [item["logicalKey"] for item in records] != list(LOGICAL_KEYS):
        stop("fresh artifact record set is not exactly fourteen ordered families.")
    return records, confidential_manifest, application_manifests


def run_local_restores(
    binding: Dict[str, object], run_id: str, records: List[Dict[str, object]], confidential_manifest: Dict[str, Dict[str, object]],
    application_manifests: Dict[str, Dict[str, object]], temp_root: str,
) -> List[Dict[str, object]]:
    results = []
    for record in records:
        key = record["logicalKey"]
        if key in APP_SLUGS:
            details = restore_application(record, application_manifests[str(key)], temp_root)
        elif key == "confidential":
            details = restore_confidential(record, confidential_manifest, temp_root)
        else:
            details = run_typed_restore(binding, run_id, record)
        results.append({
            "artifactIndex": record["artifactIndex"], "freshArtifact": os.path.basename(record["path"]),
            "freshLocalRestoreVerified": True, "freshSha256": record["sha256"], "logicalKey": key,
            "schemaVersion": 1, "status": "PASS", **details,
        })
    if len(results) != 14:
        stop("local restore result set is incomplete.")
    return results


def validate_onedrive_config() -> None:
    data = read_fixed_data_file(RCLONE_CONFIG, "OneDrive rclone configuration", 1024 * 1024)
    parser = configparser.RawConfigParser(strict=True, interpolation=None)
    try:
        parser.read_string(data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, configparser.Error) as error:
        stop(f"OneDrive rclone configuration is invalid: {error}.")
    if parser.sections() != [ONEDRIVE_REMOTE] or parser.get(ONEDRIVE_REMOTE, "type", fallback="").strip().lower() != "onedrive":
        stop("rclone configuration is not the single fixed OneDrive remote.")


def assert_backup_tool_image(binding: Dict[str, object], run_id: str, name: str = "resticRclone") -> str:
    tools = exact_keys(
        binding.get("backupToolImages"), ("mariadbRestore", "minioRestore", "nodeUtility", "postgresRestore", "resticRclone"),
        "backup tool images binding",
    )
    tool = exact_keys(tools.get(name), ("imageId", "imageReference"), f"{name} backup tool image binding")
    observed = exact_keys(
        typed_executor_json(
            "VERIFY_TOOL_IMAGE", {"runId": run_id, "tool": name}, f"{name} authority backup tool image",
        ),
        ("imageId", "imageReference", "status", "tool"), f"{name} image verification result",
    )
    if (
        observed != {**tool, "status": "PASS", "tool": name}
        or IMAGE_ID_RE.fullmatch(str(tool["imageId"])) is None
    ):
        stop("backup tool digest reference was retargeted or differs from exact authority.")
    return str(tool["imageId"])


def parse_snapshot_summary(output: bytes) -> str:
    for line in reversed(output.decode("utf-8", errors="replace").splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        candidate = value.get("snapshot_id") if isinstance(value, dict) and value.get("message_type") == "summary" else None
        if isinstance(candidate, str) and SNAPSHOT_ID_RE.fullmatch(candidate):
            return candidate
    stop("Restic backup returned no full snapshot receipt.")


def list_snapshots(run_id: str, logical_key: str) -> List[Dict[str, object]]:
    output = typed_executor(
        "RESTIC_SNAPSHOTS", {"logicalKey": logical_key, "runId": run_id},
        f"snapshot list for {logical_key}",
    )
    try:
        value = json.loads(output.decode("utf-8", errors="strict"), object_pairs_hook=duplicate_safe)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        stop(f"Restic snapshot list is invalid: {error}.")
    if not isinstance(value, list):
        stop("Restic snapshot list is not an array.")
    return value


def cms_recovery_escrow(
    binding: Dict[str, object], run_id: str, temp_root: str,
    restic_password: bytes, confidential_passphrase: bytes,
) -> Dict[str, object]:
    try:
        restic_value = restic_password.decode("ascii", errors="strict").removesuffix("\n")
        confidential_value = confidential_passphrase.decode("ascii", errors="strict").removesuffix("\n")
    except UnicodeDecodeError:
        stop("recovery bootstrap credentials are not ASCII.")
    if not restic_value or not confidential_value or "\n" in restic_value or "\n" in confidential_value:
        stop("recovery bootstrap credentials contain invalid delimiters.")
    bootstrap = canonical_bytes({
        "authorityDocumentId": binding["authorityDocumentId"], "candidateCommit": binding["candidateCommit"],
        "candidateTree": binding["candidateTree"], "certificateSha256Fingerprint": binding["recoveryEscrowCertificate"]["sha256Fingerprint"],
        "confidentialPassphrase": confidential_value, "phase": str(binding.get("operation", "")).upper(),
        "reconciliationSha256": binding["reconciliationSha256"], "resticPassword": restic_value,
        "resticRepository": ONEDRIVE_REPOSITORY, "runId": run_id,
        "schema": "platform.v1-local-private-recovery-bootstrap/v1", "sourceArchiveSha256": binding["archiveSha256"],
        "transactionId": binding["transactionId"],
    })
    envelope_dir = os.path.join(temp_root, "cms-recovery-envelope")
    readback_dir = os.path.join(temp_root, "cms-recovery-readback")
    os.makedirs(envelope_dir, mode=0o700)
    os.makedirs(readback_dir, mode=0o700)
    name = f"v1-local-private-recovery-{run_id}.cms"
    envelope = os.path.join(envelope_dir, name)
    certificate = physical(str(binding["recoveryEscrowCertificate"]["path"]))
    run(
        [binary(OPENSSL, "PLATFORM_V1_EVIDENCE_TEST_OPENSSL"), "cms", "-encrypt", "-binary", "-outform", "DER",
         "-aes256", "-out", envelope, certificate],
        "CMS recovery escrow encryption", timeout=60, input_bytes=bootstrap, maximum_output=1024 * 1024,
    )
    try:
        envelope_bytes = Path(envelope).read_bytes()
    except OSError as error:
        stop(f"CMS recovery escrow envelope is unreadable: {error.strerror}.")
    if len(envelope_bytes) < 256 or len(envelope_bytes) > 64 * 1024:
        stop("CMS recovery escrow envelope size is invalid.")
    remote_object = f"{ESCROW_REMOTE_PREFIX}/{name}"
    typed_executor("ESCROW_UPLOAD", {"runId": run_id}, "CMS recovery escrow upload")
    typed_executor("ESCROW_READBACK", {"runId": run_id}, "CMS recovery escrow readback")
    readback = Path(readback_dir, name).read_bytes()
    if readback != envelope_bytes:
        stop("direct OneDrive CMS recovery escrow readback is not byte-exact.")
    result = {
        "certificateSha256": binding["recoveryEscrowCertificate"]["sha256"],
        "certificateSha256Fingerprint": binding["recoveryEscrowCertificate"]["sha256Fingerprint"],
        "ciphertextBase64": base64.b64encode(envelope_bytes).decode("ascii"),
        "ciphertextSha256": digest_bytes(envelope_bytes), "ciphertextSizeBytes": len(envelope_bytes),
        "offHostLocation": remote_object, "remotePayloadByteExact": True, "status": "PASS",
    }
    shutil.rmtree(envelope_dir)
    shutil.rmtree(readback_dir)
    if os.path.lexists(envelope_dir) or os.path.lexists(readback_dir):
        stop("CMS recovery escrow temporary state remained after verified readback.")
    return result


def upload_and_readback(
    binding: Dict[str, object], records: List[Dict[str, object]], run_id: str, temp_root: str,
) -> Tuple[List[Dict[str, object]], Dict[str, object]]:
    validate_onedrive_config()
    assert_backup_tool_image(binding, run_id)
    rclone_dir = os.path.join(temp_root, "rclone-private")
    password_dir = os.path.join(temp_root, "restic-password-private")
    os.makedirs(rclone_dir, mode=0o700)
    os.makedirs(password_dir, mode=0o700)
    shutil.copyfile(physical(RCLONE_CONFIG), os.path.join(rclone_dir, "rclone.conf"), follow_symlinks=False)
    os.chmod(os.path.join(rclone_dir, "rclone.conf"), 0o600)
    restic_password = read_fixed_data_file(RESTIC_PASSWORD, "Restic repository password", 4096)
    restic_password_copy = os.path.join(password_dir, os.path.basename(RESTIC_PASSWORD))
    with open(restic_password_copy, "xb") as handle:
        handle.write(restic_password)
    os.chmod(restic_password_copy, 0o400)
    confidential_passphrase = read_confidential_passphrase()
    escrow = cms_recovery_escrow(
        binding, run_id, temp_root, restic_password, confidential_passphrase,
    )
    tag = f"local-private-v1-{run_id}"
    if list_snapshots(run_id, str(records[0]["logicalKey"])):
        stop("fresh Restic tag already has snapshots.")
    proofs = []
    for record in records:
        directory = os.path.dirname(record["path"])
        names = [os.path.basename(record["path"]), os.path.basename(record["checksumPath"]), os.path.basename(record["hmacPath"])]
        output = typed_executor(
            "RESTIC_BACKUP", {"logicalKey": record["logicalKey"], "runId": run_id},
            f"fresh upload {record['logicalKey']}",
        )
        snapshot_id = parse_snapshot_summary(output)
        readback = os.path.join(temp_root, f"readback-{record['artifactIndex']:02d}")
        os.makedirs(readback, mode=0o700)
        snapshot_rows = list_snapshots(run_id, str(record["logicalKey"]))
        snapshot = [item for item in snapshot_rows if isinstance(item, dict) and item.get("id") == snapshot_id]
        expected_paths = [f"/backup/{name}" for name in names]
        if (
            len(snapshot) != 1 or snapshot[0].get("hostname") != RESTIC_HOSTNAME
            or set(snapshot[0].get("tags") or []) != {tag, f"logical-key-{record['logicalKey']}"}
            or not isinstance(snapshot[0].get("paths"), list) or len(snapshot[0]["paths"]) != 3
            or set(snapshot[0]["paths"]) != set(expected_paths)
        ):
            stop("Restic snapshot metadata differs from its exact full-ID/tag/host/path contract.")
        typed_executor(
            "RESTIC_RESTORE",
            {"logicalKey": record["logicalKey"], "runId": run_id, "snapshotId": snapshot_id},
            f"readback {record['logicalKey']}",
        )
        restored = os.path.join(readback, "backup")
        if sorted(os.listdir(readback)) != ["backup"] or sorted(os.listdir(restored)) != sorted(names):
            stop("OneDrive Restic readback contains a path outside the exact three-file artifact set.")
        for local, name in zip((record["path"], record["checksumPath"], record["hmacPath"]), names):
            remote = os.path.join(restored, name)
            if not os.path.isfile(remote) or os.path.islink(remote) or digest_file(remote, MAX_ARCHIVE) != digest_file(
                local[len(TEST_ROOT):] if TEST_ROOT and local.startswith(TEST_ROOT) else local, MAX_ARCHIVE
            ):
                stop("OneDrive Restic readback differs byte-for-byte from its local artifact set.")
        shutil.rmtree(readback)
        record.update({"offsiteSnapshotId": snapshot_id, "offsiteSnapshotTag": tag})
        proofs.append({
            "artifact": os.path.basename(record["path"]), "artifactIndex": record["artifactIndex"],
            "logicalKey": record["logicalKey"], "offHostLocation": f"{ONEDRIVE_REPOSITORY}#snapshot={snapshot_id}",
            "remoteChecksumSidecarByteExact": True,
            "remoteHmacSidecarByteExact": True, "remotePayloadByteExact": True, "retentionSkipped": True,
            "sha256": record["sha256"], "sizeBytes": record["sizeBytes"], "snapshotId": snapshot_id,
            "snapshotPaths": expected_paths, "snapshotTag": tag, "status": "PASS",
        })
    snapshots = list_snapshots(run_id, str(records[0]["logicalKey"]))
    ids = {item.get("id") for item in snapshots if isinstance(item, dict)}
    expected = {item["snapshotId"] for item in proofs}
    if len(proofs) != 14 or len(expected) != 14 or len(snapshots) != 14 or ids != expected:
        stop("fresh OneDrive snapshot count/set differs from fourteen exact data artifacts.")
    shutil.rmtree(rclone_dir)
    shutil.rmtree(password_dir)
    if any(os.path.lexists(path) for path in (rclone_dir, password_dir)):
        stop("private rclone/password temporary state remained after upload/readback.")
    return proofs, escrow


def validate_transaction_preimages(binding: Dict[str, object]) -> Dict[str, object]:
    transaction_id = str(binding.get("transactionId") or "")
    raw_entries = binding.get("evidencePreimages")
    sources = sorted((LOGICAL_EVIDENCE, OFFHOST_EVIDENCE, RESTORE_EVIDENCE, RUNTIME_EVIDENCE, SECRETS_EVIDENCE)) + [LOCAL_CHECKPOINT]
    if TRANSACTION_ID_RE.fullmatch(transaction_id) is None or not isinstance(raw_entries, list) or len(raw_entries) != len(sources):
        stop("post evidence has no complete transaction-bound rollback preimage set.")
    validated = []
    for index, (raw, source) in enumerate(zip(raw_entries, sources)):
        entry = exact_keys(raw, ("logicalPath", "mode", "preimagePath", "sha256", "sizeBytes"), f"rollback evidence preimage {index}")
        expected_path = f"{ROLLBACK_SPEC_DIR}/{transaction_id}/evidence-preimages/{index:02d}.bin"
        mode = entry["mode"]
        size = entry["sizeBytes"]
        if (
            entry["logicalPath"] != source or entry["preimagePath"] != expected_path
            or isinstance(mode, bool) or not isinstance(mode, int) or mode & 0o022
            or isinstance(size, bool) or not isinstance(size, int) or size < 1 or size > MAX_JSON
            or not isinstance(entry["sha256"], str) or SHA256_RE.fullmatch(entry["sha256"]) is None
        ):
            stop("rollback evidence preimage binding is invalid.")
        preimage = read_bytes(expected_path, f"rollback evidence preimage {index}", MAX_JSON, exact_modes=(0o600,))
        current = read_bytes(source, f"rollback evidence source {index}", MAX_JSON)
        assert preimage is not None and current is not None
        if len(preimage) != size or digest_bytes(preimage) != entry["sha256"] or current != preimage:
            stop("rollback evidence preimage differs from its immutable source binding before publication.")
        validated.append({"logicalPath": source, "mode": mode, "sha256": entry["sha256"], "sizeBytes": size})
    manifest = {
        "files": validated, "schema": "platform.v1-local-private-evidence-preimage/v1",
        "status": "PRESERVED", "transactionId": transaction_id,
    }
    return {"manifestSha256": digest_bytes(canonical_bytes(manifest)), "transactionId": transaction_id}


def existing_recovery_binding() -> Dict[str, object]:
    checkpoint, _ = read_json(LOCAL_CHECKPOINT, "existing LOCAL_PRIVATE checkpoint")
    export_sha = digest_file(SCHEDULER_RECOVERY_EXPORT, MAX_RECOVERY_EXPORT)
    running = checkpoint.get("schedulerRunningImageId")
    recovery = checkpoint.get("schedulerRecoveryImageId")
    if (
        checkpoint.get("schedulerRecoveryImageExportSha256") != export_sha
        or IMAGE_ID_RE.fullmatch(str(running or "")) is None or IMAGE_ID_RE.fullmatch(str(recovery or "")) is None
        or running == recovery
    ):
        stop("historical scheduler recovery export/checkpoint binding is invalid.")
    return {"exportSha256": export_sha, "recoveryImageId": recovery, "runningImageId": running}


def runtime_evidence(
    run_id: str, captured: int, inventory: Dict[str, object], recovery: Dict[str, object], common: Dict[str, object],
) -> Dict[str, object]:
    containers = inventory["containers"]
    volumes = inventory["volumes"]
    return {
        **common,
        "capturedAtUnixSeconds": captured,
        "containerCount": len(containers),
        "containerIdentitySetSha256": digest_bytes(canonical_bytes(containers)),
        "generatedAtUnixSeconds": captured,
        "recovery": {
            "exportSha256": recovery["exportSha256"], "recoveryImageId": recovery["recoveryImageId"],
            "runningImageId": recovery["runningImageId"],
        },
        "runId": run_id,
        "schema": "platform.v1-local-private-runtime-inventory-evidence/v1",
        "status": "PASS",
        "volumeCount": len(volumes),
        "volumeSetSha256": digest_bytes(canonical_bytes(volumes)),
    }


def evidence_common(binding: Dict[str, object], run_id: str, records: List[Dict[str, object]]) -> Tuple[Dict[str, object], List[Dict[str, object]]]:
    identities = [{
        "artifactIndex": item["artifactIndex"], "logicalKey": item["logicalKey"],
        "sha256": item["sha256"], "sizeBytes": item["sizeBytes"],
    } for item in records]
    artifact_set_sha = digest_bytes(canonical_bytes(identities))
    common = {
        "artifactSetSha256": artifact_set_sha, "authorityDocumentId": binding["authorityDocumentId"],
        "authoritySha256": binding["authoritySha256"], "backupToolImages": binding["backupToolImages"],
        "candidateCommit": binding["candidateCommit"], "candidateTree": binding["candidateTree"],
        "evidencePhase": str(binding["operation"]).upper(), "reconciliationSha256": binding["reconciliationSha256"],
        "runId": run_id, "sourceArchiveSha256": binding["archiveSha256"], "transactionId": binding["transactionId"],
    }
    common["backupSetSha256"] = digest_bytes(canonical_bytes({**common, "artifacts": identities}))
    return common, identities


def validate_backup_evidence_documents(
    documents: Sequence[Dict[str, object]], binding: Dict[str, object], now: int,
) -> None:
    if len(documents) != 4:
        stop("backup evidence bundle cardinality is invalid.")
    logical, offhost, restore, secret = documents
    common_keys = {
        "artifactSetSha256", "authorityDocumentId", "authoritySha256", "backupSetSha256", "backupToolImages",
        "candidateCommit", "candidateTree", "evidencePhase", "reconciliationSha256", "runId",
        "sourceArchiveSha256", "transactionId",
    }
    extra_keys = (
        {
            "artifactCount", "artifactManifestSha256", "artifacts", "backupCompletedUnixSeconds", "capturedAtUnixSeconds",
            "checksumVerifiedCount", "freshArtifactStreamHashCount", "generatedAtUnixSeconds", "hmacVerifiedCount", "schema",
            "sourceSummarySha256", "status", "totalArtifactBytes",
        },
        {
            "artifactCount", "completedAtUnixSeconds", "distinctSnapshotCount", "exactPayloadReadbackCount",
            "freshExactSnapshotCount", "generatedAtUnixSeconds", "hostingerUsed", "noPrune", "offsiteProofSha256", "proofs",
            "recoveryEscrow", "repository", "repositoryProvider", "retentionSkipped", "schema", "sourceSummarySha256", "status",
        },
        {
            "artifactCount", "completedAtUnixSeconds", "expectedRestoreCount", "generatedAtUnixSeconds",
            "localRestoreResultsSha256", "passedRestoreCount", "results", "schema", "sourceSummarySha256", "status",
        },
        {
            "backupCompletedUnixSeconds", "capturedAtUnixSeconds", "encryptedArtifact", "generatedAtUnixSeconds",
            "plaintextTemporaryStateAbsent", "recoveryEscrow", "schema", "secretBindingInventory", "secretRestore",
            "secretValuesRecorded", "sourceSummarySha256", "status",
        },
    )
    schemas = (
        "platform.v1-local-private-logical-backup-evidence/v1",
        "platform.v1-local-private-offhost-backup-evidence/v1",
        "platform.v1-local-private-restore-evidence/v1",
        "platform.v1-local-private-secrets-backup-evidence/v1",
    )
    reference = {key: logical.get(key) for key in common_keys}
    for index, (document, extra, schema) in enumerate(zip(documents, extra_keys, schemas)):
        exact_keys(document, common_keys | extra, f"closed backup evidence {index}")
        if document["schema"] != schema or document["status"] != "PASS" or {key: document[key] for key in common_keys} != reference:
            stop("backup evidence common binding/schema/status is inconsistent.")
        timestamp_names = ("generatedAtUnixSeconds", "capturedAtUnixSeconds", "completedAtUnixSeconds", "backupCompletedUnixSeconds")
        timestamps = [document[key] for key in timestamp_names if key in document]
        if not timestamps or any(isinstance(value, bool) or not isinstance(value, int) or value > now for value in timestamps):
            stop("backup evidence timestamps are invalid.")
    expected_common = {
        "authorityDocumentId": binding["authorityDocumentId"], "authoritySha256": binding["authoritySha256"],
        "backupToolImages": binding["backupToolImages"], "candidateCommit": binding["candidateCommit"],
        "candidateTree": binding["candidateTree"], "evidencePhase": str(binding["operation"]).upper(),
        "reconciliationSha256": binding["reconciliationSha256"], "sourceArchiveSha256": binding["archiveSha256"],
        "transactionId": binding["transactionId"],
    }
    if any(reference[key] != value for key, value in expected_common.items()) or RUN_ID_RE.fullmatch(str(reference["runId"])) is None:
        stop("backup evidence candidate/authority/reconciliation/run binding is invalid.")
    if binding["operation"] == "post" and (
        not isinstance(reference["reconciliationSha256"], str) or SHA256_RE.fullmatch(reference["reconciliationSha256"]) is None
        or TRANSACTION_ID_RE.fullmatch(str(reference["transactionId"])) is None
    ):
        stop("post backup evidence lacks reconciliation/transaction binding.")
    if binding["operation"] == "pre" and (reference["reconciliationSha256"] is not None or reference["transactionId"] is not None):
        stop("pre backup evidence unexpectedly claims a reconciliation transaction.")
    artifact_keys = {
        "artifact", "artifactIndex", "checksumSidecarPath", "checksumVerified", "freshLocalRestoreVerified", "hmacKeyId",
        "hmacSidecarPath", "hmacVerified", "hostPath", "logicalKey", "sha256", "sizeBytes", "status",
    }
    artifacts = logical["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != 14:
        stop("logical evidence does not contain fourteen artifact rows.")
    identities = []
    for index, (raw, expected_key) in enumerate(zip(artifacts, LOGICAL_KEYS), start=1):
        row = exact_keys(raw, artifact_keys, f"logical artifact {index}")
        if (
            row["artifactIndex"] != index or row["logicalKey"] != expected_key or row["status"] != "PASS"
            or row["checksumVerified"] is not True or row["hmacVerified"] is not True or row["freshLocalRestoreVerified"] is not True
            or not isinstance(row["sizeBytes"], int) or isinstance(row["sizeBytes"], bool) or row["sizeBytes"] < 1
        ):
            stop("logical artifact row is not exact/PASS/ordered.")
        require_sha(row["sha256"], "logical artifact sha256")
        identities.append({key: row[key] for key in ("artifactIndex", "logicalKey", "sha256", "sizeBytes")})
    if digest_bytes(canonical_bytes(identities)) != reference["artifactSetSha256"]:
        stop("logical artifact-set digest is invalid.")
    recomputed_backup = {key: reference[key] for key in common_keys if key != "backupSetSha256"}
    if digest_bytes(canonical_bytes({**recomputed_backup, "artifacts": identities})) != reference["backupSetSha256"]:
        stop("backup-set cross-binding digest is invalid.")
    if (
        logical["artifactCount"] != 14 or logical["checksumVerifiedCount"] != 14 or logical["hmacVerifiedCount"] != 14
        or logical["freshArtifactStreamHashCount"] != 14
        or digest_bytes(b"".join(canonical_bytes(item) for item in artifacts)) != logical["artifactManifestSha256"]
    ):
        stop("logical evidence aggregate/hash is invalid.")
    proof_keys = {
        "artifact", "artifactIndex", "logicalKey", "offHostLocation", "remoteChecksumSidecarByteExact",
        "remoteHmacSidecarByteExact", "remotePayloadByteExact", "sha256", "sizeBytes", "snapshotId",
        "snapshotPaths", "snapshotTag", "status",
    }
    proofs = offhost["proofs"]
    if not isinstance(proofs, list) or len(proofs) != 14:
        stop("off-host evidence does not contain fourteen proof rows.")
    snapshot_ids = set()
    for identity, raw in zip(identities, proofs):
        row = exact_keys(raw, proof_keys, "off-host proof")
        if any(row[key] != identity[key] for key in identity) or row["artifact"] != artifacts[identity["artifactIndex"] - 1]["artifact"]:
            stop("off-host proof is substituted from another artifact/run.")
        if (
            row["status"] != "PASS" or row["remotePayloadByteExact"] is not True
            or row["remoteChecksumSidecarByteExact"] is not True or row["remoteHmacSidecarByteExact"] is not True
            or SNAPSHOT_ID_RE.fullmatch(str(row["snapshotId"])) is None
            or row["offHostLocation"] != f"{ONEDRIVE_REPOSITORY}#snapshot={row['snapshotId']}"
            or not isinstance(row["snapshotPaths"], list) or len(row["snapshotPaths"]) != 3 or len(set(row["snapshotPaths"])) != 3
        ):
            stop("off-host location/readback/snapshot proof is invalid.")
        snapshot_ids.add(row["snapshotId"])
    if (
        len(snapshot_ids) != 14 or offhost["artifactCount"] != 14 or offhost["distinctSnapshotCount"] != 14
        or offhost["freshExactSnapshotCount"] != 14 or offhost["exactPayloadReadbackCount"] != 14
        or offhost["repository"] != ONEDRIVE_REPOSITORY or offhost["repositoryProvider"] != "OneDrive"
        or offhost["hostingerUsed"] is not False or offhost["noPrune"] is not True or offhost["retentionSkipped"] is not True
        or digest_bytes(b"".join(canonical_bytes(item) for item in proofs)) != offhost["offsiteProofSha256"]
    ):
        stop("off-host evidence aggregate/provider/hash is invalid.")
    restore_keys = {
        "artifact", "artifactIndex", "isolatedRestore", "logicalKey", "restoreMode", "sha256", "sizeBytes", "status",
        "verification", "verificationSha256",
    }
    results = restore["results"]
    modes = {
        **{key: "SAFE_TMPFS_TYPED_ARCHIVE_EXTRACT" for key in APP_SLUGS},
        "pg-stexor": "DIGEST_PINNED_NETWORK_NONE_READ_ONLY_TMPFS_POSTGRES",
        "pg-keycloak": "DIGEST_PINNED_NETWORK_NONE_READ_ONLY_TMPFS_POSTGRES", "mariadb": "DISPOSABLE_NETWORK_NONE_MARIADB",
        "minio": "DISPOSABLE_NETWORK_NONE_VOLUME_MINIO", "keycloak-config": "READ_ONLY_CONFIG_JSON_KEYCLOAK",
        "confidential": "GPG_DECRYPT_TMPFS_CONTENT_METADATA_VERIFY",
    }
    if not isinstance(results, list) or len(results) != 14:
        stop("restore evidence does not contain fourteen result rows.")
    for identity, artifact, raw in zip(identities, artifacts, results):
        row = exact_keys(raw, restore_keys, "isolated restore result")
        if (
            any(row[key] != identity[key] for key in identity) or row["artifact"] != artifact["artifact"]
            or row["isolatedRestore"] is not True or row["status"] != "PASS" or row["restoreMode"] != modes[row["logicalKey"]]
        ):
            stop("isolated restore result is false, substituted or uses the wrong mode.")
        require_sha(row["verificationSha256"], "restore verification digest")
        if digest_bytes(canonical_bytes(row["verification"])) != row["verificationSha256"]:
            stop("isolated restore verification object does not match its digest.")
        if row["logicalKey"] in APP_SLUGS:
            verification = exact_keys(
                row["verification"], ("entryCount", "restoredTreeSha256", "sourceTreeSha256"),
                "application restore verification",
            )
            require_nonnegative_integer(verification["entryCount"], "application restore entry count", minimum=1)
            for name in ("restoredTreeSha256", "sourceTreeSha256"):
                require_sha(verification[name], f"application restore {name}")
            if verification["restoredTreeSha256"] != verification["sourceTreeSha256"]:
                stop("application restore verification trees differ.")
        elif row["logicalKey"] == "confidential":
            verification = exact_keys(
                row["verification"], ("entryCount", "restoredTreeSha256", "sourceTreeSha256", "treeSha256"),
                "confidential restore verification",
            )
            require_nonnegative_integer(verification["entryCount"], "confidential restore entry count", minimum=1)
            for name in ("restoredTreeSha256", "sourceTreeSha256", "treeSha256"):
                require_sha(verification[name], f"confidential restore {name}")
            if not (
                verification["restoredTreeSha256"] == verification["sourceTreeSha256"] == verification["treeSha256"]
            ):
                stop("confidential restore verification trees differ.")
        else:
            verification = exact_keys(row["verification"], ("comparatorReceipt",), "database/config restore verification")
            operation = {
                "pg-stexor": "restore-test-postgres", "pg-keycloak": "restore-test-postgres",
                "mariadb": "restore-test-mariadb", "minio": "restore-test-minio",
                "keycloak-config": "restore-test-keycloak",
            }[row["logicalKey"]]
            validate_restore_receipt(verification["comparatorReceipt"], operation, str(row["sha256"]))
    if (
        restore["artifactCount"] != 14 or restore["expectedRestoreCount"] != 14 or restore["passedRestoreCount"] != 14
        or digest_bytes(b"".join(canonical_bytes(item) for item in results)) != restore["localRestoreResultsSha256"]
    ):
        stop("restore aggregate/hash is invalid.")
    escrow_keys = {
        "certificateSha256", "certificateSha256Fingerprint", "ciphertextBase64", "ciphertextSha256", "ciphertextSizeBytes",
        "offHostLocation", "remotePayloadByteExact", "status",
    }
    escrow = exact_keys(offhost["recoveryEscrow"], escrow_keys, "off-host recovery escrow")
    if secret["recoveryEscrow"] != escrow:
        stop("secrets/off-host recovery escrow cross-binding differs.")
    try:
        ciphertext = base64.b64decode(escrow["ciphertextBase64"], validate=True)
    except (ValueError, TypeError):
        stop("recovery escrow ciphertext is not strict base64.")
    if (
        digest_bytes(ciphertext) != escrow["ciphertextSha256"] or len(ciphertext) != escrow["ciphertextSizeBytes"]
        or escrow["certificateSha256"] != binding["recoveryEscrowCertificate"]["sha256"]
        or escrow["certificateSha256Fingerprint"] != binding["recoveryEscrowCertificate"]["sha256Fingerprint"]
        or not str(escrow["offHostLocation"]).startswith(f"{ESCROW_REMOTE_PREFIX}/")
        or escrow["remotePayloadByteExact"] is not True or escrow["status"] != "PASS"
    ):
        stop("recovery escrow certificate/ciphertext/readback binding is invalid.")
    encrypted = exact_keys(secret["encryptedArtifact"], (
        "artifact", "artifactIndex", "checksumVerified", "hmacVerified", "logicalKey", "remotePayloadByteExact",
        "sha256", "sizeBytes", "snapshotId", "status",
    ), "encrypted secret artifact")
    confidential = identities[-1]
    confidential_proof = proofs[-1]
    if (
        any(encrypted[key] != confidential[key] for key in confidential) or encrypted["artifact"] != artifacts[-1]["artifact"]
        or encrypted["snapshotId"] != confidential_proof["snapshotId"] or encrypted["status"] != "PASS"
        or encrypted["checksumVerified"] is not True or encrypted["hmacVerified"] is not True or encrypted["remotePayloadByteExact"] is not True
    ):
        stop("encrypted secret artifact does not cross-bind logical/off-host evidence.")
    secret_restore = exact_keys(secret["secretRestore"], restore_keys | {"treeSha256"}, "confidential restore result")
    if any(secret_restore[key] != results[-1][key] for key in restore_keys) or secret_restore["isolatedRestore"] is not True:
        stop("confidential restore does not cross-bind isolated restore evidence.")
    require_sha(secret_restore["treeSha256"], "confidential restore tree")
    if secret_restore["treeSha256"] != secret_restore["verification"]["treeSha256"]:
        stop("confidential restore tree does not cross-bind its closed verification object.")
    inventory = exact_keys(secret["secretBindingInventory"], (
        "distinctHostFiles", "mountOccurrences", "problemCount", "setSha256", "unmountedReferenceCount",
    ), "secret binding inventory")
    if (
        secret["plaintextTemporaryStateAbsent"] is not True or secret["secretValuesRecorded"] is not False
        or inventory["problemCount"] != 0 or inventory["unmountedReferenceCount"] != 0
    ):
        stop("secrets evidence reports plaintext residue or unresolved runtime references.")
    summaries = {item["sourceSummarySha256"] for item in documents}
    if len(summaries) != 1 or any(SHA256_RE.fullmatch(str(value)) is None for value in summaries):
        stop("backup evidence source-summary cross-binding differs.")


def publish_evidence(
    operation: str, binding: Dict[str, object], run_id: str, records: List[Dict[str, object]], restores: List[Dict[str, object]],
    offsite: List[Dict[str, object]], recovery_escrow: Dict[str, object], inventory_before: Dict[str, object],
    inventory_after: Dict[str, object], backup_completed: int, restore_completed: int, offsite_completed: int,
    recovery: Dict[str, object], preimage: Optional[Dict[str, object]],
) -> Dict[str, object]:
    generated = int(time.time())
    if min(backup_completed, restore_completed, offsite_completed, generated) < int(binding["beganAtUnixSeconds"]):
        stop("evidence timestamps precede the selected V1 gate boundary.")
    common, identities = evidence_common(binding, run_id, records)
    artifact_rows = [{
        "artifact": os.path.basename(item["path"]), "artifactIndex": item["artifactIndex"],
        "checksumSidecarPath": item["logicalChecksumPath"], "checksumVerified": True,
        "freshLocalRestoreVerified": True, "hmacKeyId": item["hmacKeyId"], "hmacSidecarPath": item["logicalHmacPath"],
        "hmacVerified": True, "hostPath": item["logicalPath"], "logicalKey": item["logicalKey"],
        "sha256": item["sha256"], "sizeBytes": item["sizeBytes"], "status": "PASS",
    } for item in records]
    restore_by_key = {item["logicalKey"]: item for item in restores}
    restore_rows = []
    for record in records:
        raw = restore_by_key[record["logicalKey"]]
        details = {key: value for key, value in raw.items() if key not in (
            "artifactIndex", "freshArtifact", "freshLocalRestoreVerified", "freshSha256", "logicalKey", "schemaVersion", "status",
        )}
        verification = {key: value for key, value in details.items() if key != "restoreMode"}
        restore_rows.append({
            "artifact": os.path.basename(record["path"]), "artifactIndex": record["artifactIndex"], "isolatedRestore": True,
            "logicalKey": record["logicalKey"], "restoreMode": details["restoreMode"], "sha256": record["sha256"],
            "sizeBytes": record["sizeBytes"], "status": "PASS", "verification": verification,
            "verificationSha256": digest_bytes(canonical_bytes(verification)),
        })
    proof_by_key = {item["logicalKey"]: item for item in offsite}
    proof_rows = [{key: proof_by_key[record["logicalKey"]][key] for key in (
        "artifact", "artifactIndex", "logicalKey", "offHostLocation", "remoteChecksumSidecarByteExact",
        "remoteHmacSidecarByteExact", "remotePayloadByteExact", "sha256", "sizeBytes", "snapshotId",
        "snapshotPaths", "snapshotTag", "status",
    )} for record in records]
    summary = {
        **common, "artifactCount": 14, "backupCompletedUnixSeconds": backup_completed,
        "cleanup": {"plaintextTmpfsAbsent": True, "privateRcloneConfigAbsent": True, "temporaryHelpersAbsent": True},
        "generatedAtUnixSeconds": generated, "localRestorePassedCount": 14, "offsiteExactReadbackCount": 14,
        "schema": "platform.v1-local-private-evidence-summary/v1", "status": "PASS",
    }
    report_root = f"{REPORTS_ROOT}/{run_id}"
    artifact_manifest = b"".join(canonical_bytes(item) for item in artifact_rows)
    restore_jsonl = b"".join(canonical_bytes(item) for item in restore_rows)
    offsite_jsonl = b"".join(canonical_bytes(item) for item in proof_rows)
    write_atomic(f"{report_root}/artifact-manifest.jsonl", artifact_manifest, 0o400)
    write_atomic(f"{report_root}/local-restore-results.jsonl", restore_jsonl, 0o400)
    write_atomic(f"{report_root}/offsite-proof.jsonl", offsite_jsonl, 0o400)
    summary_bytes = write_canonical(f"{report_root}/summary.json", summary, 0o400)
    summary_sha = digest_bytes(summary_bytes)
    logical = {
        **common, "artifactCount": 14, "artifactManifestSha256": digest_bytes(artifact_manifest), "artifacts": artifact_rows,
        "backupCompletedUnixSeconds": backup_completed, "capturedAtUnixSeconds": backup_completed,
        "checksumVerifiedCount": 14, "freshArtifactStreamHashCount": 14, "generatedAtUnixSeconds": generated,
        "hmacVerifiedCount": 14, "schema": "platform.v1-local-private-logical-backup-evidence/v1",
        "sourceSummarySha256": summary_sha, "status": "PASS", "totalArtifactBytes": sum(item["sizeBytes"] for item in records),
    }
    offhost = {
        **common, "artifactCount": 14, "completedAtUnixSeconds": offsite_completed, "distinctSnapshotCount": 14,
        "exactPayloadReadbackCount": 14, "freshExactSnapshotCount": 14, "generatedAtUnixSeconds": generated,
        "hostingerUsed": False, "noPrune": True, "offsiteProofSha256": digest_bytes(offsite_jsonl), "proofs": proof_rows,
        "recoveryEscrow": recovery_escrow, "repository": ONEDRIVE_REPOSITORY, "repositoryProvider": "OneDrive",
        "retentionSkipped": True, "schema": "platform.v1-local-private-offhost-backup-evidence/v1",
        "sourceSummarySha256": summary_sha, "status": "PASS",
    }
    restore = {
        **common, "artifactCount": 14, "completedAtUnixSeconds": restore_completed, "expectedRestoreCount": 14,
        "generatedAtUnixSeconds": generated, "localRestoreResultsSha256": digest_bytes(restore_jsonl),
        "passedRestoreCount": 14, "results": restore_rows, "schema": "platform.v1-local-private-restore-evidence/v1",
        "sourceSummarySha256": summary_sha, "status": "PASS",
    }
    secret_record = next(item for item in records if item["logicalKey"] == "confidential")
    secret_proof = next(item for item in proof_rows if item["logicalKey"] == "confidential")
    raw_secret_restore = restore_by_key["confidential"]
    secret_restore_row = next(item for item in restore_rows if item["logicalKey"] == "confidential")
    unmounted = inventory_after["unmountedSecretReferences"]
    if unmounted:
        stop("runtime secret references exist without corresponding read-only mounts.")
    mount_rows = inventory_after["secretMounts"]
    secret_evidence = {
        **common, "backupCompletedUnixSeconds": backup_completed, "capturedAtUnixSeconds": backup_completed,
        "encryptedArtifact": {
            "artifact": os.path.basename(secret_record["path"]), "artifactIndex": secret_record["artifactIndex"],
            "checksumVerified": True, "hmacVerified": True, "logicalKey": "confidential", "remotePayloadByteExact": True,
            "sha256": secret_record["sha256"], "sizeBytes": secret_record["sizeBytes"],
            "snapshotId": secret_proof["snapshotId"], "status": "PASS",
        },
        "generatedAtUnixSeconds": generated, "plaintextTemporaryStateAbsent": True, "recoveryEscrow": recovery_escrow,
        "schema": "platform.v1-local-private-secrets-backup-evidence/v1",
        "secretBindingInventory": {
            "distinctHostFiles": len({item["source"] for item in mount_rows}), "mountOccurrences": len(mount_rows),
            "problemCount": len(unmounted), "setSha256": digest_bytes(canonical_bytes({"mounts": mount_rows, "unmounted": unmounted})),
            "unmountedReferenceCount": len(unmounted),
        },
        "secretRestore": {
            **secret_restore_row, "treeSha256": raw_secret_restore["treeSha256"],
        },
        "secretValuesRecorded": False, "sourceSummarySha256": summary_sha, "status": "PASS",
    }
    documents = (logical, offhost, restore, secret_evidence)
    validate_backup_evidence_documents(documents, binding, generated)
    logical_bytes, offhost_bytes, restore_bytes, secrets_bytes = (canonical_bytes(item) for item in documents)
    if operation == "post" and preimage is None:
        stop("post evidence cannot publish without immutable transaction preimages.")
    write_atomic(LOGICAL_EVIDENCE, logical_bytes, 0o400)
    write_atomic(OFFHOST_EVIDENCE, offhost_bytes, 0o400)
    write_atomic(RESTORE_EVIDENCE, restore_bytes, 0o400)
    write_atomic(SECRETS_EVIDENCE, secrets_bytes, 0o400)
    checkpoint_bytes = None
    if operation == "pre":
        runtime_bytes = canonical_bytes(runtime_evidence(run_id, generated, inventory_after, recovery, common))
        write_atomic(RUNTIME_EVIDENCE, runtime_bytes, 0o400)
        checkpoint = {
            "authoritative": False, "backupCapturedUnixSeconds": backup_completed,
            "candidateCommit": binding["candidateCommit"], "candidateTree": binding["candidateTree"],
            "destructiveMutationPlanned": False, "generatedAtUnixSeconds": generated,
            "logicalBackupEvidenceSha256": digest_bytes(logical_bytes), "offHostBackupEvidenceSha256": digest_bytes(offhost_bytes),
            "restoreEvidenceSha256": digest_bytes(restore_bytes), "restoreVerified": True,
            "runtimeInventorySha256": digest_bytes(runtime_bytes), "runtimeRecovered": True,
            "schedulerRecoveryImageExportSha256": recovery["exportSha256"], "schedulerRecoveryImageId": recovery["recoveryImageId"],
            "schedulerRunningImageId": recovery["runningImageId"], "schema": "platform.v1-local-private-predeploy-checkpoint/v1",
            "secretsBackupEvidenceSha256": digest_bytes(secrets_bytes), "sourceArchiveSha256": binding["archiveSha256"],
        }
        checkpoint_bytes = canonical_bytes(checkpoint)
        write_atomic(LOCAL_CHECKPOINT, checkpoint_bytes, 0o400)
    return {
        "artifactCount": 14, "backupSetSha256": common["backupSetSha256"], "backupToolImages": binding["backupToolImages"],
        "checkpointSha256": digest_bytes(checkpoint_bytes) if checkpoint_bytes is not None else None,
        "evidence": {
            "logicalBackupEvidenceSha256": digest_bytes(logical_bytes), "offHostBackupEvidenceSha256": digest_bytes(offhost_bytes),
            "restoreEvidenceSha256": digest_bytes(restore_bytes), "secretsBackupEvidenceSha256": digest_bytes(secrets_bytes),
        },
        "mode": operation, "offsiteProvider": "OneDrive", "preimage": preimage, "recoveryEscrow": recovery_escrow,
        "restoreCount": 14, "runId": run_id, "schema": "platform.v1-local-private-evidence-producer-receipt/v1",
        "snapshotCount": 14, "status": "PASS",
    }


def ensure_runtime_unchanged(before: Dict[str, object], after: Dict[str, object], operation: str) -> None:
    if before != after:
        stop("live container identity/restart/state or volume set changed during evidence production.")
    if operation == "post":
        assert_scheduler_absent_post(after)


def produce(operation: str) -> Dict[str, object]:
    binding = load_binding(operation)
    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}"
    if RUN_ID_RE.fullmatch(run_id) is None:
        stop("internal run ID is invalid.")
    before = docker_inventory(run_id)
    if operation == "post":
        assert_scheduler_absent_post(before)
    recovery = existing_recovery_binding()
    temporary_parent = physical("/dev/shm")
    os.makedirs(temporary_parent, mode=0o1777, exist_ok=True)
    temp_root = os.path.join(temporary_parent, f"platform-v1-evidence-{run_id}-transaction")
    try:
        os.mkdir(temp_root, mode=0o700)
    except OSError as error:
        stop(f"cannot create the exact private evidence workspace: {error.strerror}.")
    preimage = None
    try:
        if operation == "post":
            preimage = validate_transaction_preimages(binding)
            revalidate_post_transaction(binding)
        records, confidential_manifest, application_manifests = create_artifact_records(binding, run_id, temp_root)
        backup_completed = int(time.time())
        revalidate_post_transaction(binding)
        restores = run_local_restores(binding, run_id, records, confidential_manifest, application_manifests, temp_root)
        restore_completed = int(time.time())
        revalidate_post_transaction(binding)
        offsite, recovery_escrow = upload_and_readback(binding, records, run_id, temp_root)
        offsite_completed = int(time.time())
        revalidate_post_transaction(binding)
        after = docker_inventory(run_id)
        ensure_runtime_unchanged(before, after, operation)
        receipt = publish_evidence(
            operation, binding, run_id, records, restores, offsite, recovery_escrow, before, after,
            backup_completed, restore_completed, offsite_completed, recovery, preimage,
        )
        revalidate_post_transaction(binding)
        return receipt
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)
        if os.path.lexists(temp_root):
            stop("temporary plaintext/rclone/readback state remained after evidence production.")


def main(arguments: Sequence[str]) -> int:
    if len(arguments) != 1 or arguments[0] not in ("pre", "post"):
        sys.stderr.write("v1-local-private-evidence-producer: usage: v1-local-private-evidence-producer pre|post\n")
        return 64
    try:
        check_no_stdin()
        if not TEST_ROOT and os.geteuid() != 0:
            stop("V1 evidence producer requires root.", 77)
        test_owned_transaction_lock = None
        if TEST_ROOT and SHARED_LOCK_FD_ENV not in os.environ:
            test_owned_transaction_lock = acquire_lock(SHARED_LOCK, "V1 LOCAL_PRIVATE")
        else:
            validate_inherited_shared_lease()
        try:
            producer_lock = acquire_lock(LOCK, "V1 evidence producer")
            try:
                recover_stale_private_temp_roots()
                receipt = produce(arguments[0])
            finally:
                os.close(producer_lock)
        finally:
            if test_owned_transaction_lock is not None:
                os.close(test_owned_transaction_lock)
        data = canonical_bytes(receipt)
        if len(data) > 128 * 1024:
            stop("V1 evidence producer receipt exceeds 128 KiB.")
        sys.stdout.buffer.write(data)
        return 0
    except Stop as error:
        sys.stderr.write(f"v1-local-private-evidence-producer: STOP: {error}\n")
        return error.code
    except BrokenPipeError:
        return 74
    except BaseException as error:
        sys.stderr.write(f"v1-local-private-evidence-producer: STOP: unexpected bounded failure: {error}\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
