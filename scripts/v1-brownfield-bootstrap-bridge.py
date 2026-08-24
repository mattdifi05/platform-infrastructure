#!/usr/bin/python3 -I
"""V1 bridge from the observed historical or exact prior control set to exact-main.

The initial live historical consumer accepts only its frozen candidate.  This
bridge therefore enters through the separately observed legacy NOPASSWD grant;
later candidates additionally require one complete exact prior receipt,
release, and installed-control chain.  It accepts one closed, hash-bound frame,
preserves every replaced predeploy input, invokes the uploaded exact-main
consumer with empty stdin, and emits a canonical receipt.  It has no Docker,
service, provider, data, or activation authority.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import time
from typing import Dict, Iterable, List, Optional, Tuple


SCHEMA = "platform.v1-brownfield-bootstrap-bridge-receipt/v1"
ENVELOPE_SCHEMA = "platform.v1-brownfield-bootstrap-result/v1"
FRAME_SCHEMA = "platform.v1-brownfield-bootstrap-frame/v1"
TRANSPORT_CHECKPOINT_SCHEMA = "platform.v1-bootstrap-transport-checkpoint/v1"
JOURNAL_SCHEMA = "platform.v1-brownfield-bootstrap-transaction/v1"
TEST_ROOT_ENV = "PLATFORM_V1_BOOTSTRAP_TEST_ROOT"
TEST_CRASH_ENV = "PLATFORM_V1_BOOTSTRAP_TEST_CRASH_AFTER"
TEST_LEGACY_CONSUMER_SHA_ENV = "PLATFORM_V1_BOOTSTRAP_TEST_LEGACY_CONSUMER_SHA256"
LOCK = "/run/lock/platform-v1-brownfield-bootstrap.lock"
TRANSACTION = "/var/lib/platform-infrastructure/v1/bootstrap-transaction"
SOURCE_ARCHIVE = "/var/lib/platform-infrastructure/v1/predeploy/current/exact-source-archive.tar"
INSTALL_CHECKPOINT = "/var/lib/platform-infrastructure/v1/predeploy/current/install-checkpoint.json"
BRIDGE_RECEIPT = "/var/lib/platform-infrastructure/v1/bootstrap-bridge-receipt.json"
CONTROL_RECEIPT = "/var/lib/platform-infrastructure/v1/bootstrap-control-artifact-receipt.json"
NODE_RUNTIME_RECEIPT = "/var/lib/platform-infrastructure/v1/local-private/node-runtime-prerequisite-receipt.json"
INSTALLED_CONSUMER = "/usr/local/libexec/platform-v1-brownfield-install-consumer"
V1_SUDOERS = "/etc/sudoers.d/platform-v1-local-private-control"
LEGACY_BROAD_SUDOERS = "/etc/sudoers.d/platform_infrastructure"
CONTROLLER = "/usr/local/libexec/platform-v1-local-private-control"
RECONCILER = "/usr/local/libexec/platform-v1-local-private-reconcile"
UNIT = "/etc/systemd/system/platform-v1-local-private-control.service"
UPLOAD_BRIDGE = "/home/platform_infrastructure/.v1-bootstrap-upload/v1-brownfield-bootstrap-bridge.py"
STAGING_PARENT = "/home/platform_infrastructure/.v1-release-staging"
LIVE_ENV = "/home/platform_infrastructure/platform-infrastructure/.env"
RELEASES_PARENT = "/srv/platform-infrastructure/releases"
RECEIPTS_PARENT = "/var/lib/platform-infrastructure/v1/install-receipts"
PYTHON = "/usr/bin/python3"
GIT = "/usr/bin/git"
MAX_MANIFEST = 16 * 1024
MAX_CONSUMER = 2 * 1024 * 1024
MAX_BRIDGE = 2 * 1024 * 1024
MAX_CHECKPOINT = 128 * 1024
MAX_ENV = 1024 * 1024
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_BUNDLE = 1024 * 1024 * 1024
MAX_RECEIPT = 128 * 1024
MAX_CONTROL_ARTIFACT = 4 * 1024 * 1024
SHA256 = re.compile(r"^[a-f0-9]{64}$")
GIT_OBJECT = re.compile(r"^[a-f0-9]{40}$")
LEGACY_CONSUMER_SHA256 = "9902e8c83f12cee7d16ee97b660cde12444da479acbe85f9efa4c613d82f76a9"
LEGACY_CONSUMER_SIZE = 44825
LEGACY_V1_SUDOERS = (
    b"Defaults:platform_infrastructure env_reset\n"
    b"Defaults:platform_infrastructure secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
    b"platform_infrastructure ALL=(root) NOPASSWD: /usr/local/libexec/platform-v1-local-private-control activate\n"
)
LEGACY_BROAD_SUDOERS_BYTES = b"platform_infrastructure ALL=(ALL) NOPASSWD:ALL\n"
FRAME_PARTS: Tuple[Tuple[str, int], ...] = (
    ("bridge", MAX_BRIDGE),
    ("consumer", MAX_CONSUMER),
    ("checkpoint", MAX_CHECKPOINT),
    ("gitBundle", MAX_BUNDLE),
    ("sourceArchive", MAX_ARCHIVE),
)
CONTROL_ARTIFACT_PATHS: Tuple[str, ...] = (
    INSTALLED_CONSUMER,
    CONTROLLER,
    RECONCILER,
    UNIT,
    V1_SUDOERS,
)
CONTROL_ARTIFACT_SPECS: Tuple[Tuple[str, str, str, int, int, int], ...] = (
    ("installer", "scripts/v1-brownfield-install-consumer.py", INSTALLED_CONSUMER, 0o555, 0o555, MAX_CONSUMER),
    ("controller", "scripts/v1-local-private-control.py", CONTROLLER, 0o444, 0o555, MAX_CONTROL_ARTIFACT),
    ("reconciler", "scripts/v1-local-private-reconcile.py", RECONCILER, 0o444, 0o555, MAX_CONTROL_ARTIFACT),
    ("unit", "systemd/platform-v1-local-private-control.service", UNIT, 0o444, 0o444, 64 * 1024),
    ("sudoers", "sudoers/platform-v1-local-private-control", V1_SUDOERS, 0o444, 0o440, 64 * 1024),
)
INSTALL_READY_BUT_DISABLED = (
    "PROVIDER_ADMISSION",
    "DNS_PUBLICATION",
    "DAST",
    "SIGSTORE_PROMOTION",
    "DOCKER_CONTROL_PLANE",
)
BRIDGE_RECEIPT_FIELDS = (
    "bridgeSha256", "candidateCommit", "candidateConsumerSha256", "candidateTree",
    "checkpointAfterSha256", "checkpointBeforeSha256", "controlArtifactReceiptSha256",
    "dataMutation", "dockerMutation", "documentId", "gitBundleSha256", "hostControlMutation",
    "installReceiptSha256", "legacyBroadSudoersAfterSha256", "legacyBroadSudoersBeforeSha256",
    "legacyConsumerSha256", "legacyV1SudoersSha256", "nodeRuntimeReceiptSha256",
    "releaseRoot", "schema", "sourceArchiveAfterSha256", "sourceArchiveBeforeSha256",
    "stagingEnvironmentSha256", "stagingMutation", "status",
)
CONTROL_RECEIPT_FIELDS = (
    "artifacts", "candidateCommit", "candidateTree", "dataMutation", "dockerMutation",
    "hostControlMutation", "schema", "sourceArchiveSha256", "status",
)
INSTALL_RECEIPT_FIELDS = (
    "activationAuthorized", "authorizationSource", "backupEvidenceAuthoritative",
    "candidateCommit", "candidateTree", "dataMutation", "dockerMutation",
    "readyButDisabled", "releaseRoot", "schema", "sourceArchiveSha256", "status",
)


class BridgeStop(Exception):
    def __init__(self, message: str, code: int = 78):
        super().__init__(message)
        self.code = code


TEST_ROOT: Optional[str] = None


def stop(message: str, code: int = 78) -> None:
    raise BridgeStop(message, code)


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def exact_keys(value: object, keys: Iterable[str], label: str) -> Dict[str, object]:
    if not isinstance(value, dict) or set(value) != set(keys):
        stop(f"{label} is not one exact closed object.")
    return value


def sha(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None or value == "0" * 64:
        stop(f"{label} is not one non-placeholder SHA-256.")
    return value


def physical(logical: str) -> str:
    if not logical.startswith("/") or os.path.normpath(logical) != logical:
        stop("fixed logical path is invalid.")
    if TEST_ROOT is None:
        return logical
    value = os.path.join(TEST_ROOT, logical[1:])
    if os.path.commonpath((TEST_ROOT, value)) != TEST_ROOT:
        stop("test path escaped its fixed root.")
    return value


def initialize_test_root() -> Optional[str]:
    raw = os.environ.get(TEST_ROOT_ENV)
    if raw is None:
        return None
    if os.geteuid() == 0:
        stop("test-root seam is forbidden to root.", 77)
    value = os.path.realpath(raw)
    metadata = os.lstat(value)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
        stop("test root identity/mode is invalid.", 77)
    return value


def owner_uid() -> int:
    return os.geteuid() if TEST_ROOT is not None else pwd.getpwnam("platform_infrastructure").pw_uid


def owner_gid() -> int:
    return os.getegid() if TEST_ROOT is not None else pwd.getpwnam("platform_infrastructure").pw_gid


def ensure_directory(logical: str, mode: int, uid: int, gid: Optional[int] = None) -> None:
    pathname = physical(logical)
    selected_gid = uid if gid is None else gid
    os.makedirs(pathname, mode=mode, exist_ok=True)
    metadata = os.lstat(pathname)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        stop(f"fixed directory {logical} has an unsafe type.")
    if TEST_ROOT is None:
        os.chown(pathname, uid, selected_gid)
    os.chmod(pathname, mode)


def snapshot(logical: str, label: str, maximum: int, *, uid: Optional[int] = None, modes: Tuple[int, ...] = ()) -> bytes:
    pathname = physical(logical)
    before = os.lstat(pathname)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        stop(f"{label} is not one regular non-linked file.")
    if before.st_size < 1 or before.st_size > maximum:
        stop(f"{label} size is invalid.")
    if uid is not None and before.st_uid != uid:
        stop(f"{label} owner is invalid.")
    if modes and stat.S_IMODE(before.st_mode) not in modes:
        stop(f"{label} mode is invalid.")
    descriptor = os.open(pathname, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        opened = os.fstat(descriptor)
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
    finally:
        os.close(descriptor)
    after = os.lstat(pathname)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_uid, item.st_gid, item.st_mode, item.st_nlink, item.st_size, item.st_mtime_ns)
    if identity(before) != identity(opened) or identity(opened) != identity(after) or len(data) != before.st_size:
        stop(f"{label} changed during stable capture.")
    return bytes(data)


def parse_canonical_object(raw: bytes, fields: Iterable[str], label: str) -> Dict[str, object]:
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        stop(f"{label} is not strict JSON.")
    if canonical(value) != raw:
        stop(f"{label} is not canonical JSON.")
    return exact_keys(value, fields, label)


def validate_document_id(value: Dict[str, object], label: str) -> None:
    without_id = dict(value)
    document_id = without_id.pop("documentId", None)
    sha(document_id, f"{label} documentId")
    if document_id != digest(canonical(without_id)[:-1]):
        stop(f"{label} document ID is invalid.")


def validate_prior_install_receipt(prior: Dict[str, object], owner: int) -> None:
    commit = prior["candidateCommit"]
    archive_sha = prior["sourceArchiveAfterSha256"]
    logical = f"{RECEIPTS_PARENT}/{commit}-{archive_sha}.json"
    raw = snapshot(logical, "prior exact install-only receipt", MAX_RECEIPT, uid=owner, modes=(0o444,))
    value = parse_canonical_object(raw, INSTALL_RECEIPT_FIELDS, "prior exact install-only receipt")
    if (
        value["schema"] != "platform.v1-brownfield-install-receipt/v1"
        or value["status"] not in ("INSTALL_ONLY_COMPLETE", "ALREADY_INSTALLED")
        or value["candidateCommit"] != commit
        or value["candidateTree"] != prior["candidateTree"]
        or value["sourceArchiveSha256"] != archive_sha
        or value["releaseRoot"] != prior["releaseRoot"]
        or value["authorizationSource"] != "ROOT_OPERATOR_EXPLICIT_INSTALL_ONLY"
        or value["backupEvidenceAuthoritative"] is not False
        or value["activationAuthorized"] is not False
        or value["dataMutation"] is not False
        or value["dockerMutation"] is not False
        or value["readyButDisabled"] != list(INSTALL_READY_BUT_DISABLED)
    ):
        stop("prior exact install-only receipt boundary/binding is invalid.")
    # An idempotent install returns ALREADY_INSTALLED while deliberately leaving
    # the first immutable receipt untouched.  The bridge binds that exact output,
    # so accept only the durable bytes or that one deterministic status rendering.
    accepted = {digest(raw)}
    if value["status"] == "INSTALL_ONLY_COMPLETE":
        accepted.add(digest(canonical({**value, "status": "ALREADY_INSTALLED"})))
    if prior["installReceiptSha256"] not in accepted:
        stop("prior bootstrap/install receipt digest chain is invalid.")


def validate_prior_control_chain(
    entries: List[Dict[str, object]],
    expected_legacy_consumer_sha: str,
    owner: int,
) -> Tuple[str, str, str]:
    prior_raw = snapshot(
        BRIDGE_RECEIPT,
        "prior bootstrap bridge receipt",
        MAX_RECEIPT,
        uid=owner,
        modes=(0o400,),
    )
    prior = parse_canonical_object(prior_raw, BRIDGE_RECEIPT_FIELDS, "prior bootstrap bridge receipt")
    validate_document_id(prior, "prior bootstrap bridge receipt")
    commit = prior["candidateCommit"]
    tree = prior["candidateTree"]
    archive_sha = prior["sourceArchiveAfterSha256"]
    if (
        prior["schema"] != SCHEMA
        or prior["status"] != "BOOTSTRAP_CONTROL_INSTALLED"
        or not isinstance(commit, str)
        or GIT_OBJECT.fullmatch(commit) is None
        or not isinstance(tree, str)
        or GIT_OBJECT.fullmatch(tree) is None
    ):
        stop("prior bootstrap bridge receipt identity/status is invalid.")
    for field in (
        "bridgeSha256", "candidateConsumerSha256", "checkpointAfterSha256",
        "controlArtifactReceiptSha256", "gitBundleSha256",
        "installReceiptSha256", "legacyBroadSudoersAfterSha256",
        "legacyBroadSudoersBeforeSha256", "legacyConsumerSha256",
        "legacyV1SudoersSha256", "nodeRuntimeReceiptSha256", "sourceArchiveAfterSha256",
        "stagingEnvironmentSha256",
    ):
        sha(prior[field], f"prior bootstrap bridge receipt {field}")
    for field in ("checkpointBeforeSha256", "sourceArchiveBeforeSha256"):
        if prior[field] is not None:
            sha(prior[field], f"prior bootstrap bridge receipt {field}")
    release = f"{RELEASES_PARENT}/{commit}-{archive_sha}"
    if (
        prior["releaseRoot"] != release
        or prior["dataMutation"] is not False
        or prior["dockerMutation"] is not False
        or not isinstance(prior["hostControlMutation"], bool)
        or not isinstance(prior["stagingMutation"], bool)
        or prior["legacyConsumerSha256"] != expected_legacy_consumer_sha
        or prior["legacyV1SudoersSha256"] != digest(LEGACY_V1_SUDOERS)
        or prior["legacyBroadSudoersBeforeSha256"] != digest(LEGACY_BROAD_SUDOERS_BYTES)
        or prior["legacyBroadSudoersAfterSha256"] != digest(LEGACY_BROAD_SUDOERS_BYTES)
    ):
        stop("prior bootstrap bridge receipt boundary/history is invalid.")
    if (
        entries[0]["sha256"] != archive_sha
        or entries[1]["sha256"] != prior["checkpointAfterSha256"]
        or entries[2]["sha256"] != digest(prior_raw)
    ):
        stop("current bootstrap transport preimage differs from the prior exact receipt.")

    control_raw = snapshot(
        CONTROL_RECEIPT,
        "prior bootstrap control receipt",
        MAX_RECEIPT,
        uid=owner,
        modes=(0o400,),
    )
    control = parse_canonical_object(control_raw, CONTROL_RECEIPT_FIELDS, "prior bootstrap control receipt")
    if (
        entries[3]["sha256"] != digest(control_raw)
        or prior["controlArtifactReceiptSha256"] != digest(control_raw)
        or control["schema"] != "platform.v1-control-artifact-install-receipt/v1"
        or control["status"] not in ("CONTROL_ARTIFACTS_INSTALLED", "ALREADY_INSTALLED")
        or control["candidateCommit"] != commit
        or control["candidateTree"] != tree
        or control["sourceArchiveSha256"] != archive_sha
        or control["dataMutation"] is not False
        or control["dockerMutation"] is not False
        or control["hostControlMutation"] is not (control["status"] == "CONTROL_ARTIFACTS_INSTALLED")
        or prior["hostControlMutation"] is not control["hostControlMutation"]
        or not isinstance(control["artifacts"], list)
        or len(control["artifacts"]) != len(CONTROL_ARTIFACT_SPECS)
    ):
        stop("prior bootstrap/control receipt chain is invalid.")

    for index, (raw, spec) in enumerate(zip(control["artifacts"], CONTROL_ARTIFACT_SPECS)):
        name, source, target, source_mode, target_mode, maximum = spec
        artifact = exact_keys(raw, ("mode", "name", "path", "sha256"), f"prior control artifact {index}")
        artifact_sha = sha(artifact["sha256"], f"prior control artifact {index}")
        if (
            artifact["name"] != name
            or artifact["path"] != target
            or artifact["mode"] != f"{target_mode:04o}"
            or entries[index + 4]["sha256"] != artifact_sha
            or entries[index + 4]["mode"] != target_mode
        ):
            stop("prior control artifact identity/preimage is invalid.")
        installed = snapshot(
            target,
            f"current installed V1 {name} artifact",
            maximum,
            uid=owner,
            modes=(target_mode,),
        )
        frozen = snapshot(
            f"{release}/{source}",
            f"prior frozen V1 {name} artifact",
            maximum,
            uid=owner,
            modes=(source_mode,),
        )
        if digest(installed) != artifact_sha or digest(frozen) != artifact_sha:
            stop("current/frozen V1 control artifact differs from the prior exact receipt.")

    bridge_source = snapshot(
        f"{release}/scripts/v1-brownfield-bootstrap-bridge.py",
        "prior frozen V1 bootstrap bridge",
        MAX_BRIDGE,
        uid=owner,
        modes=(0o444,),
    )
    installer_sha = control["artifacts"][0]["sha256"]
    if digest(bridge_source) != prior["bridgeSha256"] or installer_sha != prior["candidateConsumerSha256"]:
        stop("prior release does not contain its receipt-bound bridge/consumer bytes.")
    validate_prior_install_receipt(prior, owner)
    return (
        prior["legacyConsumerSha256"],
        prior["legacyV1SudoersSha256"],
        prior["legacyBroadSudoersBeforeSha256"],
    )


def fsync_dir(pathname: str) -> None:
    descriptor = os.open(pathname, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write(logical: str, data: bytes, mode: int, suffix: str) -> None:
    pathname = physical(logical)
    parent = os.path.dirname(pathname)
    temporary = os.path.join(parent, f".v1-bootstrap-{suffix}.tmp")
    try:
        metadata = os.lstat(temporary)
        if stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            stop("bootstrap temporary path has an unsafe type.")
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        if TEST_ROOT is None:
            os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, pathname)
    fsync_dir(parent)


def write_private_file(pathname: str, data: bytes, mode: int, uid: int, gid: int) -> None:
    parent = os.path.dirname(pathname)
    temporary = os.path.join(parent, ".v1-bootstrap-private.tmp")
    if os.path.lexists(temporary):
        metadata = os.lstat(temporary)
        if stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            stop("bootstrap private staging path has an unsafe type.")
        os.unlink(temporary)
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        if TEST_ROOT is None:
            os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, pathname)
    fsync_dir(parent)


def remove_tree(pathname: str) -> None:
    metadata = os.lstat(pathname)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        stop("bootstrap rollback tree has an unsafe type.")
    if TEST_ROOT is not None:
        # Production rollback runs as root.  The non-root test seam still has
        # to model removal of the consumer's deliberately read-only release
        # directories without weakening any production path.
        for root, directories, _files in os.walk(pathname, topdown=False, followlinks=False):
            for directory in directories:
                candidate = os.path.join(root, directory)
                if not os.path.islink(candidate):
                    os.chmod(candidate, 0o700)
            os.chmod(root, 0o700)
    shutil.rmtree(pathname)
    fsync_dir(os.path.dirname(pathname))


def read_manifest() -> Dict[str, object]:
    header = sys.stdin.buffer.read(8)
    if len(header) != 8 or re.fullmatch(rb"[0-9a-f]{8}", header) is None:
        stop("bootstrap frame manifest header is invalid.", 65)
    length = int(header, 16)
    if length < 2 or length > MAX_MANIFEST:
        stop("bootstrap frame manifest length is invalid.", 65)
    raw = sys.stdin.buffer.read(length)
    if len(raw) != length:
        stop("bootstrap frame manifest is truncated.", 65)
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        stop("bootstrap frame manifest is not strict JSON.", 65)
    if canonical(value)[:-1] != raw:
        stop("bootstrap frame manifest is not canonical JSON.", 65)
    value = exact_keys(value, (
        "bridgeSha256", "candidateCommit", "candidateTree", "checkpointSha256",
        "consumerSha256", "gitBundleSha256", "lengths", "schema",
        "sourceArchiveSha256",
    ), "bootstrap frame manifest")
    if value["schema"] != FRAME_SCHEMA:
        stop("bootstrap frame manifest schema is invalid.", 65)
    if not isinstance(value["candidateCommit"], str) or GIT_OBJECT.fullmatch(value["candidateCommit"]) is None:
        stop("bootstrap candidate commit is invalid.", 65)
    if not isinstance(value["candidateTree"], str) or GIT_OBJECT.fullmatch(value["candidateTree"]) is None:
        stop("bootstrap candidate tree is invalid.", 65)
    lengths = exact_keys(value["lengths"], [name for name, _ in FRAME_PARTS], "bootstrap frame lengths")
    for name, maximum in FRAME_PARTS:
        if isinstance(lengths[name], bool) or not isinstance(lengths[name], int) or not 1 <= lengths[name] <= maximum:
            stop(f"bootstrap {name} length is invalid.", 65)
        sha(value[f"{name}Sha256"] if name != "sourceArchive" else value["sourceArchiveSha256"], f"bootstrap {name}")
    return value


def read_part(name: str, length: int, expected: str, destination: str) -> bytes:
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    hasher = hashlib.sha256()
    captured = bytearray() if length <= MAX_CHECKPOINT or name in ("bridge", "consumer") else None
    try:
        remaining = length
        while remaining:
            chunk = sys.stdin.buffer.read(min(1024 * 1024, remaining))
            if not chunk:
                stop(f"bootstrap {name} body is truncated.", 65)
            hasher.update(chunk)
            if captured is not None:
                captured.extend(chunk)
            offset = 0
            while offset < len(chunk):
                offset += os.write(descriptor, chunk[offset:])
            remaining -= len(chunk)
        if TEST_ROOT is None:
            os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o500 if name in ("bridge", "consumer") else 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if hasher.hexdigest() != expected:
        stop(f"bootstrap {name} body digest is invalid.", 65)
    return bytes(captured or b"")


def validate_checkpoint(raw: bytes, manifest: Dict[str, object]) -> None:
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        stop("bootstrap checkpoint is not strict JSON.", 65)
    if canonical(value) != raw:
        stop("bootstrap checkpoint is not canonical JSON.", 65)
    value = exact_keys(value, (
        "activationAuthorized", "authoritative", "backupEvidenceAuthoritative",
        "bridgeSha256", "candidateCommit", "candidateConsumerSha256",
        "candidateTree", "createdAtUnixSeconds", "gitBundleSha256", "purpose",
        "schema", "sourceArchiveSha256", "sourceArchiveSizeBytes",
        "transportVerified",
    ), "bootstrap transport checkpoint")
    if (
        value["candidateCommit"] != manifest["candidateCommit"]
        or value["candidateTree"] != manifest["candidateTree"]
        or value["sourceArchiveSha256"] != manifest["sourceArchiveSha256"]
        or value["bridgeSha256"] != manifest["bridgeSha256"]
        or value["candidateConsumerSha256"] != manifest["consumerSha256"]
        or value["gitBundleSha256"] != manifest["gitBundleSha256"]
        or value["sourceArchiveSizeBytes"] != manifest["lengths"]["sourceArchive"]
        or value["schema"] != TRANSPORT_CHECKPOINT_SCHEMA
        or value["purpose"] != "CONTROL_PLANE_STAGING_ONLY"
        or value["authoritative"] is not False
        or value["activationAuthorized"] is not False
        or value["backupEvidenceAuthoritative"] is not False
        or value["transportVerified"] is not True
    ):
        stop("bootstrap transport checkpoint scope/candidate binding is invalid.", 65)
    for key in ("bridgeSha256", "candidateConsumerSha256", "gitBundleSha256"):
        sha(value[key], f"bootstrap transport checkpoint {key}")
    timestamp = value["createdAtUnixSeconds"]
    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        stop("bootstrap transport checkpoint timestamp is invalid.", 65)
    now = int(time.time())
    if timestamp > now + 60 or now - timestamp > 900:
        stop("bootstrap transport checkpoint is stale.", 65)


def run(command: List[str], label: str, *, env: Optional[Dict[str, str]] = None, timeout: int = 300) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/", env=env, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        stop(f"{label} failed: {error}.")
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace")[:512].strip()
        stop(f"{label} rejected the fixed input: {detail}.")
    return result


def git_run(arguments: List[str], label: str, *, repository: Optional[str] = None) -> subprocess.CompletedProcess[bytes]:
    command = [
        GIT,
        "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=/dev/null",
        "-c", "core.untrackedCache=false",
    ]
    if repository is not None:
        command.extend(("-c", f"safe.directory={repository}"))
    command.extend(arguments)
    return run(
        command,
        label,
        env={
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "HOME": "/nonexistent",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        },
    )


def validate_or_create_staging(manifest: Dict[str, object], bundle: str, journal: Dict[str, object]) -> str:
    commit = manifest["candidateCommit"]
    tree = manifest["candidateTree"]
    logical = f"{STAGING_PARENT}/{commit}"
    pathname = physical(logical)
    uid = owner_uid()
    gid = owner_gid()
    live_environment = snapshot(
        LIVE_ENV,
        "live deployment environment",
        MAX_ENV,
        uid=uid,
        modes=(0o400, 0o600),
    )
    if not os.path.lexists(pathname):
        temporary = physical(f"{STAGING_PARENT}/.bootstrap-{commit}")
        if os.path.lexists(temporary):
            remove_tree(temporary)
        git_run(["clone", "--no-checkout", "--", bundle, temporary], "bootstrap Git clone")
        git_run(["-C", temporary, "checkout", "--detach", commit], "bootstrap Git checkout", repository=temporary)
        tracked_environment = git_run(
            ["-C", temporary, "ls-files", "--", ".env"],
            "bootstrap deployment environment ownership",
            repository=temporary,
        ).stdout
        if tracked_environment:
            stop("bootstrap refuses a source-tracked deployment environment.")
        git_run(
            ["-C", temporary, "update-ref", "refs/remotes/github/main", commit, "0" * 40],
            "bootstrap exact github/main ref creation",
            repository=temporary,
        )
        if TEST_ROOT is None:
            for root, directories, files in os.walk(temporary):
                os.chown(root, uid, gid)
                for entry in directories + files:
                    os.chown(os.path.join(root, entry), uid, gid, follow_symlinks=False)
        write_private_file(os.path.join(temporary, ".env"), live_environment, 0o600, uid, gid)
        os.rename(temporary, pathname)
        fsync_dir(os.path.dirname(pathname))
        journal["stagingCreated"] = True
        write_journal(journal)
        crash_point()
    head = git_run(["-C", pathname, "rev-parse", "--verify", "HEAD^{commit}"], "bootstrap staging commit", repository=pathname).stdout.decode().strip()
    actual_tree = git_run(["-C", pathname, "rev-parse", "--verify", "HEAD^{tree}"], "bootstrap staging tree", repository=pathname).stdout.decode().strip()
    github_main = git_run(
        ["-C", pathname, "rev-parse", "--verify", "refs/remotes/github/main^{commit}"],
        "bootstrap staging github/main ref",
        repository=pathname,
    ).stdout.decode().strip()
    dirty = git_run(["-C", pathname, "status", "--porcelain=v1", "--untracked-files=all"], "bootstrap staging cleanliness", repository=pathname).stdout
    if head != commit or actual_tree != tree or github_main != commit or dirty:
        stop("bootstrap staging checkout identity is invalid.")
    if git_run(["-C", pathname, "ls-files", "--", ".env"], "bootstrap staging environment ownership", repository=pathname).stdout:
        stop("bootstrap staging deployment environment is source-tracked.")
    staged_environment = snapshot(
        f"{logical}/.env",
        "staging deployment environment",
        MAX_ENV,
        uid=uid,
        modes=(0o600,),
    )
    if staged_environment != live_environment:
        stop("staging deployment environment differs from the stable live preimage.")
    if snapshot(
        LIVE_ENV,
        "live deployment environment",
        MAX_ENV,
        uid=uid,
        modes=(0o400, 0o600),
    ) != live_environment:
        stop("live deployment environment changed during bootstrap capture.")
    return digest(live_environment)


def journal_path() -> str:
    return f"{TRANSACTION}/journal.json"


def write_journal(value: Dict[str, object]) -> None:
    atomic_write(journal_path(), canonical(value), 0o600, "journal")


def snapshot_limit(logical: str) -> int:
    if logical == SOURCE_ARCHIVE:
        return MAX_ARCHIVE
    if logical == INSTALL_CHECKPOINT:
        return MAX_CHECKPOINT
    if logical in CONTROL_ARTIFACT_PATHS:
        return MAX_CONTROL_ARTIFACT
    return MAX_RECEIPT


def backup_entry(logical: str, index: int) -> Dict[str, object]:
    pathname = physical(logical)
    if not os.path.lexists(pathname):
        return {"existed": False, "mode": None, "path": logical, "preimage": None, "sha256": None}
    raw = snapshot(logical, f"bootstrap preimage {logical}", snapshot_limit(logical))
    preimage = f"{TRANSACTION}/preimage-{index}.bin"
    atomic_write(preimage, raw, 0o600, f"preimage-{index}")
    return {"existed": True, "mode": stat.S_IMODE(os.lstat(pathname).st_mode), "path": logical, "preimage": preimage, "sha256": digest(raw)}


def restore_entry(entry: Dict[str, object], index: int) -> None:
    logical = entry["path"]
    pathname = physical(logical)
    if entry["existed"]:
        raw = snapshot(entry["preimage"], f"bootstrap transaction preimage {index}", snapshot_limit(logical), modes=(0o600,))
        if digest(raw) != entry["sha256"]:
            stop("bootstrap transaction preimage digest changed.")
        atomic_write(logical, raw, entry["mode"], f"rollback-{index}")
    elif os.path.lexists(pathname):
        metadata = os.lstat(pathname)
        if stat.S_ISDIR(metadata.st_mode):
            stop("bootstrap rollback target has unsafe directory type.")
        os.unlink(pathname)
        fsync_dir(os.path.dirname(pathname))


def committed_receipts_match(journal: Dict[str, object]) -> bool:
    try:
        bridge_raw = snapshot(
            BRIDGE_RECEIPT,
            "committed bootstrap bridge receipt",
            MAX_RECEIPT,
            modes=(0o400,),
        )
        control_raw = snapshot(
            CONTROL_RECEIPT,
            "committed bootstrap control receipt",
            MAX_RECEIPT,
            modes=(0o400,),
        )
        node_runtime_raw = snapshot(
            NODE_RUNTIME_RECEIPT,
            "committed Node runtime prerequisite receipt",
            MAX_RECEIPT,
            modes=(0o444,),
        )
        install_raw = snapshot(
            journal["installReceiptPath"],
            "committed install-only receipt",
            MAX_RECEIPT,
            modes=(0o444,),
        )
        bridge = json.loads(bridge_raw.decode("utf-8", errors="strict"))
        control = json.loads(control_raw.decode("utf-8", errors="strict"))
        node_runtime = json.loads(node_runtime_raw.decode("utf-8", errors="strict"))
        install = json.loads(install_raw.decode("utf-8", errors="strict"))
    except (BridgeStop, OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    if (
        canonical(bridge) != bridge_raw
        or canonical(control) != control_raw
        or canonical(node_runtime) != node_runtime_raw
        or canonical(install) != install_raw
    ):
        return False
    return (
        bridge.get("schema") == SCHEMA
        and bridge.get("status") == "BOOTSTRAP_CONTROL_INSTALLED"
        and bridge.get("candidateCommit") == journal["candidateCommit"]
        and bridge.get("candidateTree") == journal["candidateTree"]
        and bridge.get("sourceArchiveAfterSha256") == journal["sourceArchiveSha256"]
        and bridge.get("controlArtifactReceiptSha256") == digest(control_raw)
        and bridge.get("installReceiptSha256") == digest(install_raw)
        and bridge.get("nodeRuntimeReceiptSha256") == digest(node_runtime_raw)
        and install.get("schema") == "platform.v1-brownfield-install-receipt/v1"
        and install.get("status") in ("INSTALL_ONLY_COMPLETE", "ALREADY_INSTALLED")
        and install.get("candidateCommit") == journal["candidateCommit"]
        and install.get("candidateTree") == journal["candidateTree"]
        and install.get("sourceArchiveSha256") == journal["sourceArchiveSha256"]
        and install.get("dataMutation") is False
        and install.get("dockerMutation") is False
        and control.get("schema") == "platform.v1-control-artifact-install-receipt/v1"
        and control.get("candidateCommit") == journal["candidateCommit"]
        and control.get("candidateTree") == journal["candidateTree"]
        and control.get("sourceArchiveSha256") == journal["sourceArchiveSha256"]
        and control.get("dataMutation") is False
        and control.get("dockerMutation") is False
        and node_runtime.get("schema") == "platform.v1-node-runtime-prerequisite-receipt/v1"
        and node_runtime.get("status") == "NODE_RUNTIME_READY"
        and node_runtime.get("candidateCommit") == journal["candidateCommit"]
        and node_runtime.get("candidateTree") == journal["candidateTree"]
        and node_runtime.get("sourceArchiveSha256") == journal["sourceArchiveSha256"]
        and node_runtime.get("dataMutation") is False
        and node_runtime.get("dockerMutation") is False
        and node_runtime.get("workloadMutation") is False
    )


def read_journal() -> Dict[str, object]:
    raw = snapshot(journal_path(), "bootstrap transaction journal", MAX_RECEIPT, modes=(0o600,))
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        stop("bootstrap transaction journal is invalid.")
    if canonical(value) != raw:
        stop("bootstrap transaction journal is not canonical.")
    value = exact_keys(value, (
        "candidateCommit", "candidateTree", "controlAttempted", "entries", "installReceiptExisted",
        "installReceiptPath", "releaseExisted", "releasePath", "schema",
        "sourceArchiveSha256", "stagingCreated", "stagingPath", "status",
    ), "bootstrap transaction journal")
    if value["schema"] != JOURNAL_SCHEMA or value["status"] not in ("INSTALLING", "COMMITTED"):
        stop("bootstrap transaction journal status is invalid.")
    if not isinstance(value["controlAttempted"], bool):
        stop("bootstrap transaction control-attempt state is invalid.")
    return value


def cleanup_transaction() -> None:
    pathname = physical(TRANSACTION)
    if os.path.lexists(pathname):
        remove_tree(pathname)


def recover_transaction() -> None:
    pathname = physical(TRANSACTION)
    if not os.path.lexists(pathname):
        return
    journal = read_journal()
    if journal["status"] == "COMMITTED" or committed_receipts_match(journal):
        cleanup_transaction()
        return
    for index, entry in reversed(list(enumerate(journal["entries"]))):
        restore_entry(entry, index)
    if journal["controlAttempted"]:
        systemctl = "/usr/bin/systemctl"
        if TEST_ROOT is not None:
            systemctl = os.environ.get("PLATFORM_V1_INSTALL_CONSUMER_TEST_SYSTEMCTL", "")
            if not systemctl.startswith(TEST_ROOT + os.sep):
                stop("bootstrap rollback systemctl test seam is invalid.", 77)
        run([systemctl, "daemon-reload"], "bootstrap control-artifact rollback daemon-reload")
    release = physical(journal["releasePath"])
    if not journal["releaseExisted"] and os.path.lexists(release):
        remove_tree(release)
    install_receipt = physical(journal["installReceiptPath"])
    if not journal["installReceiptExisted"] and os.path.lexists(install_receipt):
        metadata = os.lstat(install_receipt)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            stop("bootstrap install receipt rollback type is invalid.")
        os.unlink(install_receipt)
        fsync_dir(os.path.dirname(install_receipt))
    staging = physical(journal["stagingPath"])
    if journal["stagingCreated"] and os.path.lexists(staging):
        remove_tree(staging)
    cleanup_transaction()


_crash_counter = 0


def crash_point() -> None:
    global _crash_counter
    raw = os.environ.get(TEST_CRASH_ENV)
    if raw is None:
        return
    if TEST_ROOT is None or re.fullmatch(r"[1-9][0-9]?", raw) is None:
        stop("bootstrap crash seam is invalid.", 77)
    _crash_counter += 1
    if _crash_counter == int(raw):
        os._exit(87)


def acquire_lock() -> int:
    pathname = physical(LOCK)
    os.makedirs(os.path.dirname(pathname), mode=0o755, exist_ok=True)
    descriptor = os.open(pathname, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    return descriptor


def main_apply() -> Dict[str, object]:
    if TEST_ROOT is None and os.geteuid() != 0:
        stop("production bootstrap bridge requires effective UID 0.", 77)
    uid = owner_uid()
    gid = owner_gid()
    bridge_before = snapshot(UPLOAD_BRIDGE, "uploaded bootstrap bridge", MAX_BRIDGE, uid=uid, modes=(0o500, 0o700))
    manifest = read_manifest()
    if digest(bridge_before) != manifest["bridgeSha256"]:
        stop("uploaded bootstrap bridge differs from frame authority.", 65)
    lock = acquire_lock()
    try:
        ensure_directory("/var/lib/platform-infrastructure/v1", 0o700, 0)
        ensure_directory("/var/lib/platform-infrastructure/v1/predeploy", 0o700, 0)
        ensure_directory("/var/lib/platform-infrastructure/v1/predeploy/current", 0o700, 0)
        ensure_directory("/var/lib/platform-infrastructure/v1/install-receipts", 0o755, 0)
        ensure_directory("/srv", 0o755, 0)
        ensure_directory("/srv/platform-infrastructure", 0o755, 0)
        ensure_directory(RELEASES_PARENT, 0o755, 0)
        ensure_directory(STAGING_PARENT, 0o700, uid, gid)
        recover_transaction()

        legacy_consumer = snapshot(INSTALLED_CONSUMER, "historical installed consumer", MAX_CONSUMER, uid=0 if TEST_ROOT is None else uid, modes=(0o555,))
        legacy_v1_sudoers = snapshot(V1_SUDOERS, "historical V1 sudoers", 64 * 1024, uid=0 if TEST_ROOT is None else uid, modes=(0o440,))
        broad_sudoers = snapshot(LEGACY_BROAD_SUDOERS, "legacy broad sudo bridge", 64 * 1024, uid=0 if TEST_ROOT is None else uid, modes=(0o440,))
        expected_legacy_consumer_sha = LEGACY_CONSUMER_SHA256
        expected_legacy_consumer_size = LEGACY_CONSUMER_SIZE
        if TEST_ROOT is not None:
            expected_legacy_consumer_sha = sha(
                os.environ.get(TEST_LEGACY_CONSUMER_SHA_ENV),
                "test historical consumer",
            )
            expected_legacy_consumer_size = len(legacy_consumer)
        historical_precondition = (
            len(legacy_consumer) == expected_legacy_consumer_size
            and digest(legacy_consumer) == expected_legacy_consumer_sha
            and legacy_v1_sudoers == LEGACY_V1_SUDOERS
        )
        if broad_sudoers != LEGACY_BROAD_SUDOERS_BYTES:
            stop("legacy broad sudo bootstrap precondition is not exact.")

        commit = manifest["candidateCommit"]
        archive_sha = manifest["sourceArchiveSha256"]
        release = f"{RELEASES_PARENT}/{commit}-{archive_sha}"
        install_receipt = f"{RECEIPTS_PARENT}/{commit}-{archive_sha}.json"
        staging = f"{STAGING_PARENT}/{commit}"
        ensure_directory(TRANSACTION, 0o700, 0)
        entries = [
            backup_entry(SOURCE_ARCHIVE, 0),
            backup_entry(INSTALL_CHECKPOINT, 1),
            backup_entry(BRIDGE_RECEIPT, 2),
            backup_entry(CONTROL_RECEIPT, 3),
            *[
                backup_entry(logical, index)
                for index, logical in enumerate(CONTROL_ARTIFACT_PATHS, start=4)
            ],
        ]
        journal: Dict[str, object] = {
            "candidateCommit": commit,
            "candidateTree": manifest["candidateTree"],
            "controlAttempted": False,
            "entries": entries,
            "installReceiptExisted": os.path.lexists(physical(install_receipt)),
            "installReceiptPath": install_receipt,
            "releaseExisted": os.path.lexists(physical(release)),
            "releasePath": release,
            "schema": JOURNAL_SCHEMA,
            "sourceArchiveSha256": archive_sha,
            "stagingCreated": False,
            "stagingPath": staging,
            "status": "INSTALLING",
        }
        write_journal(journal)
        crash_point()

        part_paths: Dict[str, str] = {}
        captured: Dict[str, bytes] = {}
        for name, _maximum in FRAME_PARTS:
            target = physical(f"{TRANSACTION}/{name}.bin")
            expected = manifest[f"{name}Sha256"] if name != "sourceArchive" else archive_sha
            captured[name] = read_part(name, manifest["lengths"][name], expected, target)
            part_paths[name] = target
            crash_point()
        if sys.stdin.buffer.read(1):
            stop("bootstrap frame has trailing bytes.", 65)
        if captured["bridge"] != bridge_before:
            stop("stable bridge frame differs from executed bridge.", 65)
        validate_checkpoint(captured["checkpoint"], manifest)

        if historical_precondition:
            legacy_consumer_sha256 = digest(legacy_consumer)
            legacy_v1_sudoers_sha256 = digest(legacy_v1_sudoers)
            legacy_broad_before_sha256 = digest(broad_sudoers)
        else:
            (
                legacy_consumer_sha256,
                legacy_v1_sudoers_sha256,
                legacy_broad_before_sha256,
            ) = validate_prior_control_chain(entries, expected_legacy_consumer_sha, 0 if TEST_ROOT is None else uid)

        atomic_write(SOURCE_ARCHIVE, snapshot(f"{TRANSACTION}/sourceArchive.bin", "staged source archive", MAX_ARCHIVE, modes=(0o400,)), 0o400, "archive")
        crash_point()
        atomic_write(INSTALL_CHECKPOINT, captured["checkpoint"], 0o400, "checkpoint")
        crash_point()
        staging_environment_sha256 = validate_or_create_staging(
            manifest,
            part_paths["gitBundle"],
            journal,
        )

        child_env = {
            "HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin",
            "PYTHONHASHSEED": "0",
        }
        if TEST_ROOT is not None:
            child_env["PLATFORM_V1_INSTALL_CONSUMER_TEST_ROOT"] = TEST_ROOT
            for name in (
                "PLATFORM_V1_INSTALL_CONSUMER_TEST_VISUDO",
                "PLATFORM_V1_INSTALL_CONSUMER_TEST_SYSTEMD_ANALYZE",
                "PLATFORM_V1_INSTALL_CONSUMER_TEST_SYSTEMCTL",
            ):
                if name in os.environ:
                    child_env[name] = os.environ[name]
        result = run(
            [PYTHON, "-I", part_paths["consumer"], "bootstrap-install"],
            "exact-main transport-only bootstrap consumer",
            env=child_env,
            timeout=900,
        )
        if len(result.stdout) < 2 or len(result.stdout) > MAX_RECEIPT:
            stop("exact-main bootstrap consumer receipt size is invalid.")
        try:
            install_value = json.loads(result.stdout.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            stop("exact-main bootstrap consumer receipt is invalid.")
        if canonical(install_value) != result.stdout:
            stop("exact-main bootstrap consumer receipt is not canonical.")
        if (
            install_value.get("schema") != "platform.v1-brownfield-install-receipt/v1"
            or install_value.get("status") not in ("INSTALL_ONLY_COMPLETE", "ALREADY_INSTALLED")
            or install_value.get("candidateCommit") != commit
            or install_value.get("candidateTree") != manifest["candidateTree"]
            or install_value.get("sourceArchiveSha256") != archive_sha
            or install_value.get("releaseRoot") != release
            or install_value.get("dataMutation") is not False
            or install_value.get("dockerMutation") is not False
        ):
            stop("exact-main bootstrap consumer receipt binding is invalid.")
        crash_point()

        release_consumer = physical(f"{release}/scripts/v1-brownfield-install-consumer.py")
        journal["controlAttempted"] = True
        write_journal(journal)
        crash_point()
        control_result = run(
            [PYTHON, "-I", release_consumer, "install-control-artifacts"],
            "exact-main control artifact consumer",
            env=child_env,
            timeout=900,
        )
        if len(control_result.stdout) < 2 or len(control_result.stdout) > MAX_RECEIPT:
            stop("exact-main control artifact receipt size is invalid.")
        try:
            control_value = json.loads(control_result.stdout.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            stop("exact-main control artifact receipt is invalid.")
        if canonical(control_value) != control_result.stdout:
            stop("exact-main control artifact receipt is not canonical.")
        if (
            set(control_value) != {
                "artifacts", "candidateCommit", "candidateTree", "dataMutation",
                "dockerMutation", "hostControlMutation", "schema",
                "sourceArchiveSha256", "status",
            }
            or control_value["schema"] != "platform.v1-control-artifact-install-receipt/v1"
            or control_value["status"] not in ("CONTROL_ARTIFACTS_INSTALLED", "ALREADY_INSTALLED")
            or control_value["candidateCommit"] != commit
            or control_value["candidateTree"] != manifest["candidateTree"]
            or control_value["sourceArchiveSha256"] != archive_sha
            or control_value["dataMutation"] is not False
            or control_value["dockerMutation"] is not False
            or control_value["hostControlMutation"] is not (
                control_value["status"] == "CONTROL_ARTIFACTS_INSTALLED"
            )
            or not isinstance(control_value["artifacts"], list)
            or len(control_value["artifacts"]) != 5
        ):
            stop("exact-main control artifact receipt binding is invalid.")
        broad_sudoers_after = snapshot(
            LEGACY_BROAD_SUDOERS,
            "legacy broad sudo bridge after bootstrap",
            64 * 1024,
            uid=0 if TEST_ROOT is None else uid,
            modes=(0o440,),
        )
        if broad_sudoers_after != broad_sudoers:
            stop("legacy broad sudo bridge changed during the bounded bootstrap.")
        crash_point()

        node_environment = dict(child_env)
        if TEST_ROOT is not None:
            node_environment["PLATFORM_V1_NODE_RUNTIME_TEST_ROOT"] = TEST_ROOT
            for name in (
                "PLATFORM_V1_NODE_RUNTIME_TEST_APT_CACHE",
                "PLATFORM_V1_NODE_RUNTIME_TEST_APT_GET",
                "PLATFORM_V1_NODE_RUNTIME_TEST_DPKG_QUERY",
                "PLATFORM_V1_NODE_RUNTIME_TEST_NODE",
            ):
                if name in os.environ:
                    node_environment[name] = os.environ[name]
        node_helper_logical = f"{release}/scripts/v1-node-runtime-prerequisite.py"
        node_helper = physical(node_helper_logical)
        node_result = run(
            [PYTHON, "-I", node_helper, "apply"],
            "exact-release Node runtime prerequisite",
            env=node_environment,
            timeout=1200,
        )
        if len(node_result.stdout) < 2 or len(node_result.stdout) > MAX_RECEIPT:
            stop("exact-release Node runtime prerequisite receipt size is invalid.")
        try:
            node_value = json.loads(node_result.stdout.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            stop("exact-release Node runtime prerequisite receipt is invalid.")
        node_fields = {
            "activationAuthorized", "binaryPath", "binarySha256", "candidateCommit", "candidateTree",
            "dataMutation", "dockerMutation", "documentId", "helperSha256", "hostControlMutation",
            "packageArchitecture", "packageName", "packageSource", "packageVersion", "receiptPath",
            "releaseRoot", "runtimeVersion", "schema", "sourceArchiveSha256", "status", "workloadMutation",
        }
        node_without_id = dict(node_value)
        node_document_id = node_without_id.pop("documentId", None)
        if (
            canonical(node_value) != node_result.stdout
            or set(node_value) != node_fields
            or node_document_id != digest(json.dumps(node_without_id, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode())
            or node_value["schema"] != "platform.v1-node-runtime-prerequisite-receipt/v1"
            or node_value["status"] != "NODE_RUNTIME_READY"
            or node_value["candidateCommit"] != commit
            or node_value["candidateTree"] != manifest["candidateTree"]
            or node_value["sourceArchiveSha256"] != archive_sha
            or node_value["releaseRoot"] != release
            or node_value["receiptPath"] != NODE_RUNTIME_RECEIPT
            or node_value["activationAuthorized"] is not False
            or node_value["dataMutation"] is not False
            or node_value["dockerMutation"] is not False
            or node_value["workloadMutation"] is not False
            or not isinstance(node_value["hostControlMutation"], bool)
            or node_value["helperSha256"] != digest(snapshot(
                node_helper_logical,
                "exact-release Node runtime prerequisite helper",
                MAX_CONTROL_ARTIFACT,
                modes=(0o444, 0o555),
            ))
        ):
            stop("exact-release Node runtime prerequisite receipt binding is invalid.")
        if snapshot(
            NODE_RUNTIME_RECEIPT,
            "durable Node runtime prerequisite receipt",
            MAX_RECEIPT,
            modes=(0o444,),
        ) != node_result.stdout:
            stop("durable Node runtime prerequisite receipt differs from helper output.")
        crash_point()

        before_archive = entries[0]["sha256"]
        before_checkpoint = entries[1]["sha256"]
        receipt_base = {
            "bridgeSha256": manifest["bridgeSha256"],
            "candidateCommit": commit,
            "candidateConsumerSha256": manifest["consumerSha256"],
            "candidateTree": manifest["candidateTree"],
            "checkpointAfterSha256": manifest["checkpointSha256"],
            "checkpointBeforeSha256": before_checkpoint,
            "controlArtifactReceiptSha256": digest(control_result.stdout),
            "dataMutation": False,
            "dockerMutation": False,
            "gitBundleSha256": manifest["gitBundleSha256"],
            "hostControlMutation": control_value["hostControlMutation"],
            "installReceiptSha256": digest(result.stdout),
            "legacyBroadSudoersAfterSha256": digest(broad_sudoers_after),
            "legacyBroadSudoersBeforeSha256": legacy_broad_before_sha256,
            "legacyConsumerSha256": legacy_consumer_sha256,
            "legacyV1SudoersSha256": legacy_v1_sudoers_sha256,
            "nodeRuntimeReceiptSha256": digest(node_result.stdout),
            "releaseRoot": release,
            "schema": SCHEMA,
            "sourceArchiveAfterSha256": archive_sha,
            "sourceArchiveBeforeSha256": before_archive,
            "stagingEnvironmentSha256": staging_environment_sha256,
            "stagingMutation": journal["stagingCreated"],
            "status": "BOOTSTRAP_CONTROL_INSTALLED",
        }
        receipt = {**receipt_base, "documentId": digest(json.dumps(receipt_base, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode())}
        receipt_bytes = canonical(receipt)
        atomic_write(CONTROL_RECEIPT, control_result.stdout, 0o400, "control-receipt")
        atomic_write(BRIDGE_RECEIPT, receipt_bytes, 0o400, "receipt")
        crash_point()
        # Both consumers and the prerequisite helper have committed; install,
        # control, Node-runtime, and bootstrap receipts are durable.  This is a
        # forward commit point: recovery accepts only the exact bound receipt
        # set and never treats it as backup/cutover authority.
        journal["status"] = "COMMITTED"
        write_journal(journal)
        crash_point()
        cleanup_transaction()
        if snapshot(UPLOAD_BRIDGE, "uploaded bootstrap bridge", MAX_BRIDGE, uid=uid, modes=(0o500, 0o700)) != bridge_before:
            stop("uploaded bootstrap bridge changed during transaction.")
        return {
            "bootstrap": receipt,
            "controlArtifacts": control_value,
            "nodeRuntime": node_value,
            "schema": ENVELOPE_SCHEMA,
        }
    except BaseException:
        try:
            recover_transaction()
        except BaseException:
            pass
        raise
    finally:
        os.close(lock)


def main(argv: List[str]) -> int:
    if argv != ["apply"]:
        sys.stderr.write("v1-brownfield-bootstrap-bridge: usage: v1-brownfield-bootstrap-bridge apply\n")
        return 64
    try:
        global TEST_ROOT
        TEST_ROOT = initialize_test_root()
        receipt = main_apply()
        sys.stdout.buffer.write(canonical(receipt))
    except BridgeStop as error:
        sys.stderr.write(f"v1-brownfield-bootstrap-bridge: STOP: {error}\n")
        return error.code
    except BrokenPipeError:
        return 74
    except BaseException as error:
        sys.stderr.write(f"v1-brownfield-bootstrap-bridge: STOP: unexpected bounded failure: {error}\n")
        return 78
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
