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

import base64
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
TEST_CONTROLLER_VERIFY_ENV = "PLATFORM_V1_BOOTSTRAP_TEST_CONTROLLER_VERIFY"
LOCK = "/run/lock/platform-v1-brownfield-bootstrap.lock"
TRANSACTION_LOCK = "/run/lock/platform-v1-local-private-transaction.lock"
TRANSACTION = "/var/lib/platform-infrastructure/v1/bootstrap-transaction"
SOURCE_ARCHIVE = "/var/lib/platform-infrastructure/v1/predeploy/current/exact-source-archive.tar"
INSTALL_CHECKPOINT = "/var/lib/platform-infrastructure/v1/predeploy/current/install-checkpoint.json"
BRIDGE_RECEIPT = "/var/lib/platform-infrastructure/v1/bootstrap-bridge-receipt.json"
CONTROL_RECEIPT = "/var/lib/platform-infrastructure/v1/bootstrap-control-artifact-receipt.json"
NODE_RUNTIME_RECEIPT = "/var/lib/platform-infrastructure/v1/local-private/node-runtime-prerequisite-receipt.json"
EXACT_RELEASE_AUTHORITY = "/var/lib/platform-infrastructure/v1/local-private/exact-release-authority.json"
AUTHORITY_ARCHIVE_DIR = "/var/lib/platform-infrastructure/v1/local-private/release-authorities"
ACTIVE_STATE = "/var/lib/platform-infrastructure/v1/local-private/state.json"
ACTIVE_RECEIPT = "/var/lib/platform-infrastructure/v1/local-private/active-receipt.json"
OPEN_RECONCILIATION = "/var/lib/platform-infrastructure/v1/local-private/reconciliation.json"
OPEN_RECONCILE_JOURNAL = "/var/lib/platform-infrastructure/v1/local-private/reconcile-journal.json"
OPEN_ABORT_RECORD = "/var/lib/platform-infrastructure/v1/local-private/reconciliation-abort-record.json"
INSTALLED_CONSUMER = "/usr/local/libexec/platform-v1-brownfield-install-consumer"
V1_SUDOERS = "/etc/sudoers.d/platform-v1-local-private-control"
LEGACY_BROAD_SUDOERS = "/etc/sudoers.d/platform_infrastructure"
CONTROLLER = "/usr/local/libexec/platform-v1-local-private-control"
RECONCILER = "/usr/local/libexec/platform-v1-local-private-reconcile"
UNIT = "/etc/systemd/system/platform-v1-local-private-control.service"
UPLOAD_BRIDGE = "/home/platform_infrastructure/.v1-bootstrap-upload/v1-brownfield-bootstrap-bridge.py"
STAGING_PARENT = "/home/platform_infrastructure/.v1-release-staging"
DEFAULT_LIVE_ENV = "/home/platform_infrastructure/platform-infrastructure/.env"
GREENFIELD_LIVE_ENV_ROOT = "/home/platform_infrastructure/greenfield-live/"
LIVE_ENV_ENV = "PLATFORM_V1_LIVE_ENV"
LIVE_ENV_REQUIRE_ENV = "PLATFORM_V1_REQUIRE_GREENFIELD_PREIMAGE"
LIVE_ENV_PROVENANCE_ENV = "PLATFORM_V1_LIVE_ENV_PROVENANCE"
# Backward-compatible default: the frozen brownfield rollback authority.  This
# file is NEVER mutated by a greenfield install and is only ever compared
# against when no greenfield preimage override is supplied.
LIVE_ENV = DEFAULT_LIVE_ENV
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
MAX_SANCTION = 64 * 1024
SANCTION_SCHEMA = "platform.v1-transport-checkpoint-sanction/v1"
SANCTION_REASON = "TRANSPORT_CHECKPOINT_REGENERATED_NO_PRIOR_BYTES"
SUCCESSOR_SANCTION_SCHEMA = "platform.v1-transport-successor-sanction/v2"
SUCCESSOR_SANCTION_REASON = "TRANSPORT_CHECKPOINT_REGENERATED_WITH_EXACT_GREENFIELD_PREIMAGE_REUSE"
SANCTION_EMPTY_SHA256 = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
SANCTION_TRUST_CERT_RELPATH = "config/local-private-recovery-escrow-cert.pem"
SANCTION_TRUST_CERT_SHA256 = "358dcd60560f0976f6b27db0972cc996d336516a529c48bf4236dcf22e0c55a2"
PRODUCTION_OPENSSL = "/usr/bin/openssl"
FRAME_PARTS: Tuple[Tuple[str, int], ...] = (
    ("bridge", MAX_BRIDGE),
    ("consumer", MAX_CONSUMER),
    ("checkpoint", MAX_CHECKPOINT),
    ("sanction", MAX_SANCTION),
    ("gitBundle", MAX_BUNDLE),
    ("sourceArchive", MAX_ARCHIVE),
)
SUCCESSOR_SANCTION_FIELDS = (
    "candidateCommit", "candidateTree", "checkpointSha256", "createdAtUnixSeconds",
    "greenfieldPreimagePath", "greenfieldPreimageSha256", "greenfieldProvenancePath",
    "greenfieldProvenanceReleaseCommit", "greenfieldProvenanceSha256",
    "priorCandidateCommit", "priorCandidateTree", "priorCheckpointAfterSha256",
    "priorReceiptDocumentId", "priorStagingEnvironmentSha256", "reasonCode", "schema",
    "runtimeActiveReceiptSha256", "runtimeAuthorityDocumentId", "runtimeAuthoritySha256",
    "runtimeCandidateCommit", "runtimeCandidateTree", "runtimeSourceArchiveSha256",
    "signatureBase64", "sourceArchiveSha256",
)
SUCCESSOR_SANCTION_SUMMARY_FIELDS = SUCCESSOR_SANCTION_FIELDS + (
    "present", "sanctionDigest", "signerCertSha256",
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
BRIDGE_RECEIPT_FIELDS_V2 = BRIDGE_RECEIPT_FIELDS + ("transportSanction",)
CONTROL_RECEIPT_FIELDS = (
    "artifacts", "candidateCommit", "candidateTree", "dataMutation", "dockerMutation",
    "hostControlMutation", "schema", "sourceArchiveSha256", "status",
)
EXACT_AUTHORITY_FIELDS = (
    "activeManagedContainerNames", "artifacts", "authorityMode", "authorizedDataMutations",
    "backupToolImages", "candidateCommit", "candidateTree", "checkoutProof",
    "controllerVerificationScope", "disabledComposeServices", "documentId", "evidenceProducer",
    "expectedContainerNames", "legacyNetworkAttachments", "legacyRouteChecks",
    "legacyUnmanagedContainers", "preservedLegacyContainerNames", "recoveryEscrowCertificate",
    "releaseRoot", "renderEnvironment", "renderSha256", "runtimeIdentity", "schema",
    "serviceTargets", "sourceArchiveSha256", "status",
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


def resolve_sanction_openssl() -> str:
    if TEST_ROOT is not None:
        override = os.environ.get("PLATFORM_V1_BOOTSTRAP_TEST_SANCTION_OPENSSL")
        if override:
            return override
    return PRODUCTION_OPENSSL


def resolve_sanction_trust_cert_sha() -> str:
    if TEST_ROOT is not None:
        override = os.environ.get("PLATFORM_V1_BOOTSTRAP_TEST_SANCTION_CERT_SHA256")
        if override:
            return override
    return SANCTION_TRUST_CERT_SHA256


def evaluate_transport_sanction(
    raw: bytes,
    manifest: Dict[str, object],
    prior: Dict[str, object],
    owner: int,
    successor: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    if digest(raw) == SANCTION_EMPTY_SHA256:
        if successor is None:
            stop("current bootstrap transport preimage differs from the prior exact receipt.")
        stop("successor greenfield continuity requires an operator-signed transport sanction.")
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        stop("bootstrap transport sanction is not strict JSON.")
    if canonical(value) != raw or not isinstance(value, dict):
        stop("bootstrap transport sanction is not canonical JSON.")
    fields = (
        "checkpointSha256", "createdAtUnixSeconds", "priorCheckpointAfterSha256",
        "priorReceiptDocumentId", "reasonCode", "schema", "signatureBase64",
    ) if successor is None else SUCCESSOR_SANCTION_FIELDS
    value = exact_keys(value, fields, "bootstrap transport sanction")
    timestamp = value["createdAtUnixSeconds"]
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or not isinstance(value["reasonCode"], str):
        stop("bootstrap transport sanction fields are invalid.")
    now = int(time.time())
    if timestamp > now + 60 or now - timestamp > 900:
        stop("bootstrap transport sanction is stale.")
    core = {key: item for key, item in value.items() if key != "signatureBase64"}
    core_bytes = canonical(core)
    signature = value["signatureBase64"]
    if not isinstance(signature, str) or len(signature) > MAX_SANCTION // 2:
        stop("bootstrap transport sanction signature is invalid.")
    try:
        signature_der = base64.b64decode(signature.encode("ascii"), validate=True)
    except (TypeError, ValueError):
        stop("bootstrap transport sanction signature encoding is invalid.")
    if successor is None:
        if (
            value["schema"] != SANCTION_SCHEMA
            or value["reasonCode"] != SANCTION_REASON
            or sha(value["checkpointSha256"], "transport sanction checkpoint digest") != manifest["checkpointSha256"]
            or sha(value["priorCheckpointAfterSha256"], "transport sanction prior checkpoint digest") != prior["checkpointAfterSha256"]
            or value["priorReceiptDocumentId"] != prior["documentId"]
        ):
            stop("bootstrap transport sanction binding is invalid.")
    else:
        for field in (
            "checkpointSha256", "greenfieldPreimageSha256", "greenfieldProvenanceSha256",
            "priorCheckpointAfterSha256", "priorReceiptDocumentId", "priorStagingEnvironmentSha256",
            "runtimeActiveReceiptSha256", "runtimeAuthorityDocumentId", "runtimeAuthoritySha256",
            "runtimeSourceArchiveSha256", "sourceArchiveSha256",
        ):
            sha(value[field], f"successor sanction {field}")
        for field in (
            "candidateCommit", "candidateTree", "greenfieldProvenanceReleaseCommit",
            "priorCandidateCommit", "priorCandidateTree", "runtimeCandidateCommit", "runtimeCandidateTree",
        ):
            if not isinstance(value[field], str) or GIT_OBJECT.fullmatch(value[field]) is None or value[field] == "0" * 40:
                stop(f"successor sanction {field} is invalid.")
        for field in ("greenfieldPreimagePath", "greenfieldProvenancePath"):
            pathname = value[field]
            if (
                not isinstance(pathname, str) or pathname == DEFAULT_LIVE_ENV
                or not pathname.startswith(GREENFIELD_LIVE_ENV_ROOT)
                or pathname != os.path.normpath(pathname)
            ):
                stop(f"successor sanction {field} is invalid.")
        expected = {
            "candidateCommit": manifest["candidateCommit"],
            "candidateTree": manifest["candidateTree"],
            "checkpointSha256": manifest["checkpointSha256"],
            "priorCandidateCommit": prior["candidateCommit"],
            "priorCandidateTree": prior["candidateTree"],
            "priorCheckpointAfterSha256": prior["checkpointAfterSha256"],
            "priorReceiptDocumentId": prior["documentId"],
            "priorStagingEnvironmentSha256": prior["stagingEnvironmentSha256"],
            "reasonCode": SUCCESSOR_SANCTION_REASON,
            "schema": SUCCESSOR_SANCTION_SCHEMA,
            "sourceArchiveSha256": manifest["sourceArchiveSha256"],
            **successor,
        }
        if any(value[field] != expected[field] for field in expected):
            stop("successor transport sanction binding is invalid.")
        if value["greenfieldPreimageSha256"] != value["priorStagingEnvironmentSha256"]:
            stop("successor transport sanction preimage/staging binding is invalid.")
    release = prior["releaseRoot"]
    if not isinstance(release, str) or not os.path.isabs(release):
        stop("bootstrap transport sanction trust anchor path is invalid.")
    cert_bytes = snapshot(
        f"{release}/{SANCTION_TRUST_CERT_RELPATH}",
        "pinned V1 recovery escrow certificate",
        MAX_RECEIPT,
        uid=owner,
        modes=(0o444, 0o644),
    )
    cert_sha = resolve_sanction_trust_cert_sha()
    if digest(cert_bytes) != cert_sha:
        stop("bootstrap transport sanction trust anchor differs from the pinned certificate.")
    openssl_bin = resolve_sanction_openssl()
    core_path = physical(f"{TRANSACTION}/.sanction-core.tmp")
    signature_path = physical(f"{TRANSACTION}/.sanction-signature.der")
    for pathname in (core_path, signature_path):
        try:
            os.unlink(pathname)
        except FileNotFoundError:
            pass
    result_code = 78
    try:
        descriptor = os.open(core_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            offset = 0
            while offset < len(core_bytes):
                offset += os.write(descriptor, core_bytes[offset:])
        finally:
            os.close(descriptor)
        descriptor = os.open(signature_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            offset = 0
            while offset < len(signature_der):
                offset += os.write(descriptor, signature_der[offset:])
        finally:
            os.close(descriptor)
        verify = subprocess.run(
            [
                openssl_bin, "cms", "-verify", "-binary", "-inform", "DER",
                "-in", signature_path, "-content", core_path, "-CAfile",
                physical(f"{release}/{SANCTION_TRUST_CERT_RELPATH}"),
                "-purpose", "any", "-no_check_time",
            ],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd="/", timeout=30, check=False,
        )
        result_code = verify.returncode
    except (OSError, subprocess.SubprocessError):
        stop("bootstrap transport sanction verification failed.")
    finally:
        for pathname in (core_path, signature_path):
            try:
                os.unlink(pathname)
            except OSError:
                pass
    if result_code != 0:
        stop("bootstrap transport sanction signature rejected.")
    if successor is None:
        return {
            "present": True,
            "reasonCode": SANCTION_REASON,
            "sanctionDigest": digest(raw),
            "signerCertSha256": cert_sha,
        }
    return {
        **value,
        "present": True,
        "sanctionDigest": digest(raw),
        "signerCertSha256": cert_sha,
    }


def validate_prior_transport_sanction(prior: Dict[str, object]) -> None:
    if "transportSanction" not in prior:
        return
    value = prior["transportSanction"]
    if isinstance(value, dict) and set(value) == {"present"} and value["present"] is False:
        return
    if isinstance(value, dict) and set(value) == {
        "present", "reasonCode", "sanctionDigest", "signerCertSha256",
    }:
        if (
            value["present"] is not True
            or value["reasonCode"] != SANCTION_REASON
            or sha(value["sanctionDigest"], "prior transport sanction digest") != value["sanctionDigest"]
            or sha(value["signerCertSha256"], "prior transport sanction signer") != value["signerCertSha256"]
        ):
            stop("prior transport sanction summary is invalid.")
        return
    value = exact_keys(value, SUCCESSOR_SANCTION_SUMMARY_FIELDS, "prior successor sanction summary")
    if value["present"] is not True:
        stop("prior successor sanction presence is invalid.")
    signed = {field: value[field] for field in SUCCESSOR_SANCTION_FIELDS}
    signed_raw = canonical(signed)
    if (
        value["schema"] != SUCCESSOR_SANCTION_SCHEMA
        or value["reasonCode"] != SUCCESSOR_SANCTION_REASON
        or digest(signed_raw) != value["sanctionDigest"]
        or value["signerCertSha256"] != resolve_sanction_trust_cert_sha()
        or value["candidateCommit"] != prior["candidateCommit"]
        or value["candidateTree"] != prior["candidateTree"]
        or value["checkpointSha256"] != prior["checkpointAfterSha256"]
        or value["sourceArchiveSha256"] != prior["sourceArchiveAfterSha256"]
        or value["greenfieldPreimageSha256"] != prior["stagingEnvironmentSha256"]
        or value["greenfieldPreimageSha256"] != value["priorStagingEnvironmentSha256"]
    ):
        stop("prior successor sanction summary binding is invalid.")
    for field in (
        "checkpointSha256", "greenfieldPreimageSha256", "greenfieldProvenanceSha256",
        "priorCheckpointAfterSha256", "priorReceiptDocumentId", "priorStagingEnvironmentSha256",
        "runtimeActiveReceiptSha256", "runtimeAuthorityDocumentId", "runtimeAuthoritySha256",
        "runtimeSourceArchiveSha256", "sanctionDigest", "signerCertSha256",
        "sourceArchiveSha256",
    ):
        sha(value[field], f"prior successor sanction {field}")
    for field in (
        "candidateCommit", "candidateTree", "greenfieldProvenanceReleaseCommit",
        "priorCandidateCommit", "priorCandidateTree", "runtimeCandidateCommit", "runtimeCandidateTree",
    ):
        if not isinstance(value[field], str) or GIT_OBJECT.fullmatch(value[field]) is None or value[field] == "0" * 40:
            stop(f"prior successor sanction {field} is invalid.")
    for field in ("greenfieldPreimagePath", "greenfieldProvenancePath"):
        pathname = value[field]
        if (
            not isinstance(pathname, str) or pathname == DEFAULT_LIVE_ENV
            or not pathname.startswith(GREENFIELD_LIVE_ENV_ROOT)
            or pathname != os.path.normpath(pathname)
        ):
            stop(f"prior successor sanction {field} is invalid.")
    signature = value["signatureBase64"]
    if not isinstance(signature, str) or len(signature) > MAX_SANCTION // 2:
        stop("prior successor sanction signature is invalid.")
    try:
        base64.b64decode(signature.encode("ascii"), validate=True)
    except (TypeError, ValueError):
        stop("prior successor sanction signature encoding is invalid.")


def no_open_runtime_transaction() -> None:
    for logical in (OPEN_RECONCILIATION, OPEN_RECONCILE_JOURNAL, OPEN_ABORT_RECORD):
        if os.path.lexists(physical(logical)):
            stop("successor transport requires a fully closed V1 reconciliation state.")


def controller_verify_command() -> List[str]:
    if TEST_ROOT is None:
        return [CONTROLLER, "verify"]
    helper = os.environ.get(TEST_CONTROLLER_VERIFY_ENV)
    if not helper or not helper.startswith(TEST_ROOT + os.sep) or os.path.realpath(helper) != helper:
        stop("successor controller verify test seam is invalid.", 77)
    metadata = os.lstat(helper)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
        stop("successor controller verify test helper is invalid.", 77)
    return [helper, physical(ACTIVE_RECEIPT)]


def validate_transitional_runtime_authority(
    owner: int,
    prior_artifact_mismatches: Tuple[str, ...],
    prior_source_archive_mismatch: bool,
    transaction_lease: Dict[str, Optional[int]],
) -> Dict[str, object]:
    if prior_artifact_mismatches not in ((), ("reconciler",)):
        stop("successor transport installed artifact divergence is not the reconciler-only transition.")
    no_open_runtime_transaction()
    authority_raw = snapshot(
        EXACT_RELEASE_AUTHORITY, "current exact release authority", MAX_RECEIPT,
        uid=owner, modes=(0o444,),
    )
    authority = parse_canonical_object(authority_raw, EXACT_AUTHORITY_FIELDS, "current exact release authority")
    validate_document_id(authority, "current exact release authority")
    candidate_commit = authority["candidateCommit"]
    candidate_tree = authority["candidateTree"]
    source_sha = authority["sourceArchiveSha256"]
    if (
        authority["schema"] != "platform.v1-local-private-exact-release-authority/v1"
        or authority["status"] != "AUTHORIZED"
        or authority["authorityMode"] != "LOCAL_PRIVATE"
        or not isinstance(candidate_commit, str) or GIT_OBJECT.fullmatch(candidate_commit) is None
        or not isinstance(candidate_tree, str) or GIT_OBJECT.fullmatch(candidate_tree) is None
        or sha(source_sha, "runtime authority source archive") != source_sha
        or authority["releaseRoot"] != f"{RELEASES_PARENT}/{candidate_commit}-{source_sha}"
    ):
        stop("successor runtime authority identity/status is invalid.")
    archived_raw = snapshot(
        f"{AUTHORITY_ARCHIVE_DIR}/{authority['documentId']}.json",
        "archived current exact release authority", MAX_RECEIPT, uid=owner, modes=(0o444,),
    )
    if archived_raw != authority_raw:
        stop("current exact release authority differs from its immutable archive.")
    source_raw = snapshot(
        SOURCE_ARCHIVE, "runtime authority source archive", MAX_ARCHIVE,
        uid=owner, modes=(0o400, 0o444),
    )
    if digest(source_raw) != source_sha:
        stop("current source archive differs from the exact runtime authority.")
    artifacts = exact_keys(
        authority["artifacts"],
        ("composeWrapper", "controller", "installer", "reconciler", "sudoers", "unit"),
        "current exact release authority artifacts",
    )
    installed_snapshots: Dict[str, Tuple[bytes, int]] = {}
    for name, _source, target, _source_mode, target_mode, maximum in CONTROL_ARTIFACT_SPECS:
        artifact = exact_keys(artifacts[name], ("path", "sha256"), f"runtime authority {name} artifact")
        if artifact["path"] != target or sha(artifact["sha256"], f"runtime authority {name} artifact") != artifact["sha256"]:
            stop("runtime authority control artifact binding is invalid.")
        installed = snapshot(target, f"runtime authority installed {name}", maximum, uid=owner, modes=(target_mode,))
        if digest(installed) != artifact["sha256"]:
            stop("installed control artifact differs from the exact runtime authority.")
        installed_snapshots[target] = (installed, target_mode)
    compose = exact_keys(artifacts["composeWrapper"], ("path", "sha256"), "runtime authority compose wrapper")
    if compose["path"] != f"{authority['releaseRoot']}/scripts/compose-vps.sh":
        stop("runtime authority compose wrapper path is invalid.")
    sha(compose["sha256"], "runtime authority compose wrapper")
    state_raw = snapshot(ACTIVE_STATE, "current ACTIVE state", MAX_RECEIPT, uid=owner, modes=(0o600,))
    state = json.loads(state_raw.decode("utf-8", errors="strict"))
    if canonical(state) != state_raw or not isinstance(state, dict) or state.get("schema") != "platform.v1-local-private-control-state/v1" or state.get("status") != "ACTIVE":
        stop("successor runtime state is not one canonical ACTIVE state.")
    receipt_raw = snapshot(ACTIVE_RECEIPT, "current ACTIVE receipt", MAX_RECEIPT, uid=owner, modes=(0o444,))
    receipt = json.loads(receipt_raw.decode("utf-8", errors="strict"))
    if canonical(receipt) != receipt_raw or not isinstance(receipt, dict) or receipt.get("schema") != "platform.v1-local-private-control-receipt/v1" or receipt.get("status") != "ACTIVE":
        stop("successor runtime receipt is not one canonical ACTIVE receipt.")
    # The installed controller's verify command takes this same shared lock.
    # Hand it the exclusion lease, then reacquire and byte-revalidate the full
    # proof before trusting its output or authorizing any target publication.
    # No unleased observation can therefore survive into the signed gate.
    descriptor = transaction_lease.get("descriptor")
    if not isinstance(descriptor, int):
        stop("successor transaction lease is unavailable.")
    transaction_lease["descriptor"] = None
    os.close(descriptor)
    verified = run(
        controller_verify_command(), "installed authority-bound controller verify",
        env={"HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        timeout=180,
    )
    transaction_lease["descriptor"] = acquire_transaction_lock()
    if verified.stdout != receipt_raw:
        stop("controller verify output differs from the current ACTIVE receipt.")
    no_open_runtime_transaction()
    if (
        snapshot(EXACT_RELEASE_AUTHORITY, "stable current exact release authority", MAX_RECEIPT, uid=owner, modes=(0o444,)) != authority_raw
        or snapshot(
            f"{AUTHORITY_ARCHIVE_DIR}/{authority['documentId']}.json",
            "stable archived exact release authority", MAX_RECEIPT,
            uid=owner, modes=(0o444,),
        ) != archived_raw
        or snapshot(
            SOURCE_ARCHIVE, "stable runtime authority source archive", MAX_ARCHIVE,
            uid=owner, modes=(0o400, 0o444),
        ) != source_raw
        or snapshot(ACTIVE_STATE, "stable current ACTIVE state", MAX_RECEIPT, uid=owner, modes=(0o600,)) != state_raw
        or snapshot(ACTIVE_RECEIPT, "stable current ACTIVE receipt", MAX_RECEIPT, uid=owner, modes=(0o444,)) != receipt_raw
        or any(
            snapshot(
                target, "stable runtime authority artifact", len(data) + 1,
                uid=owner, modes=(mode,),
            ) != data
            for target, (data, mode) in installed_snapshots.items()
        )
    ):
        stop("successor runtime authority changed during controller verification.")
    if prior_artifact_mismatches == () and prior_source_archive_mismatch is False:
        # Ordinary exact-prior successor continuity is permitted, but it is
        # still bound to and signed over the fully verified active authority.
        pass
    return {
        "runtimeActiveReceiptSha256": digest(receipt_raw),
        "runtimeAuthorityDocumentId": authority["documentId"],
        "runtimeAuthoritySha256": digest(authority_raw),
        "runtimeCandidateCommit": candidate_commit,
        "runtimeCandidateTree": candidate_tree,
        "runtimeSourceArchiveSha256": source_sha,
    }


def validate_prior_control_chain(
    entries: List[Dict[str, object]],
    expected_legacy_consumer_sha: str,
    owner: int,
) -> Tuple[str, str, str, Dict[str, object], bool, Tuple[str, ...], bool]:
    prior_raw = snapshot(
        BRIDGE_RECEIPT,
        "prior bootstrap bridge receipt",
        MAX_RECEIPT,
        uid=owner,
        modes=(0o400,),
    )
    try:
        parsed = json.loads(prior_raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        stop("prior bootstrap bridge receipt is not strict JSON.")
    if isinstance(parsed, dict) and set(parsed) == set(BRIDGE_RECEIPT_FIELDS_V2):
        prior_fields = BRIDGE_RECEIPT_FIELDS_V2
    elif isinstance(parsed, dict) and set(parsed) == set(BRIDGE_RECEIPT_FIELDS):
        prior_fields = BRIDGE_RECEIPT_FIELDS
    else:
        stop("prior bootstrap bridge receipt is not one exact closed object.")
    prior = parse_canonical_object(prior_raw, prior_fields, "prior bootstrap bridge receipt")
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
    validate_prior_transport_sanction(prior)
    checkpoint_mismatch = entries[1]["sha256"] != prior["checkpointAfterSha256"]
    source_archive_mismatch = entries[0]["sha256"] != archive_sha
    if entries[2]["sha256"] != digest(prior_raw):
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

    artifact_mismatches: List[str] = []
    for index, (raw, spec) in enumerate(zip(control["artifacts"], CONTROL_ARTIFACT_SPECS)):
        name, source, target, source_mode, target_mode, maximum = spec
        artifact = exact_keys(raw, ("mode", "name", "path", "sha256"), f"prior control artifact {index}")
        artifact_sha = sha(artifact["sha256"], f"prior control artifact {index}")
        if (
            artifact["name"] != name
            or artifact["path"] != target
            or artifact["mode"] != f"{target_mode:04o}"
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
        if entries[index + 4]["sha256"] != digest(installed):
            stop("installed V1 control artifact changed after transaction capture.")
        if digest(frozen) != artifact_sha:
            stop("current/frozen V1 control artifact differs from the prior exact receipt.")
        if digest(installed) != artifact_sha:
            if name != "reconciler":
                stop("installed V1 control artifact divergence is not the reconciler-only transition.")
            artifact_mismatches.append(name)

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
        prior,
        checkpoint_mismatch,
        tuple(artifact_mismatches),
        source_archive_mismatch,
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
        "consumerSha256", "gitBundleSha256", "lengths", "sanctionSha256", "schema",
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


def resolve_live_env(
    manifest: Dict[str, object],
    prior: Optional[Dict[str, object]],
    sanction_raw: bytes,
    checkpoint_mismatch: bool,
    prior_artifact_mismatches: Tuple[str, ...],
    prior_source_archive_mismatch: bool,
    environment_owner: int,
    authority_owner: int,
    transaction_lease: Dict[str, Optional[int]],
) -> Dict[str, object]:
    """Capture the live preimage and authorize only exact successor continuity.

    Default (no override) is the frozen brownfield rollback authority.  A
    greenfield LOCAL_PRIVATE install supplies an explicit GREENFIELD preimage
    that is cryptographically bound to the candidate release through a
    provenance manifest.  The greenfield preimage must never equal, and must
    never accidentally consume, the brownfield live environment.  Every
    misconfiguration FAILS CLOSED.
    """
    override = os.environ.get(LIVE_ENV_ENV)
    require_greenfield = os.environ.get(LIVE_ENV_REQUIRE_ENV) == "1"
    sanction_summary: Dict[str, object] = {"present": False}
    if not override:
        if require_greenfield:
            stop("greenfield install requires an explicit GREENFIELD preimage (PLATFORM_V1_LIVE_ENV).", 65)
        if prior_artifact_mismatches or prior_source_archive_mismatch:
            stop("prior control/source divergence requires signed greenfield successor continuity.")
        if checkpoint_mismatch:
            if prior is None:
                stop("checkpoint divergence has no prior receipt authority.")
            sanction_summary = evaluate_transport_sanction(sanction_raw, manifest, prior, authority_owner)
        live = snapshot(DEFAULT_LIVE_ENV, "live deployment environment", MAX_ENV, uid=environment_owner, modes=(0o400, 0o600))
        return {
            "bytes": live, "path": DEFAULT_LIVE_ENV, "priorStagingBytes": None,
            "priorStagingPath": None, "provenanceBytes": None, "provenancePath": None,
            "transportSanction": sanction_summary,
        }
    if override == DEFAULT_LIVE_ENV:
        stop("greenfield preimage must not equal the brownfield live environment.", 65)
    if not override.startswith(GREENFIELD_LIVE_ENV_ROOT) or override != os.path.normpath(override):
        stop("greenfield preimage must live under the greenfield authority.", 65)
    provenance_path = os.environ.get(LIVE_ENV_PROVENANCE_ENV)
    if not provenance_path or not provenance_path.startswith(GREENFIELD_LIVE_ENV_ROOT) or provenance_path != os.path.normpath(provenance_path):
        stop("greenfield preimage provenance is missing or outside the greenfield authority.", 65)
    prov_raw = snapshot(
        provenance_path, "greenfield preimage provenance", MAX_RECEIPT,
        uid=environment_owner, modes=(0o400, 0o600),
    )
    prov = parse_canonical_object(prov_raw, (
        "schema", "generatedAtUnixSeconds", "releaseCommit", "greenfieldEnvSha256",
        "renderEnvSha256", "preimagePath", "preimageSha256", "imageIdentities",
    ), "greenfield preimage provenance")
    if (
        prov["schema"] != "platform.v1-greenfield-preimage/v1"
        or isinstance(prov["generatedAtUnixSeconds"], bool)
        or not isinstance(prov["generatedAtUnixSeconds"], int)
        or prov["generatedAtUnixSeconds"] <= 0
    ):
        stop("greenfield preimage provenance schema is invalid.", 65)
    if not isinstance(prov["releaseCommit"], str) or not GIT_OBJECT.fullmatch(prov["releaseCommit"]):
        stop("greenfield preimage provenance release commit is invalid.", 65)
    if prov["preimagePath"] != override:
        stop("greenfield preimage provenance path does not match the live env path.", 65)
    sha(prov["greenfieldEnvSha256"], "greenfield source environment digest")
    sha(prov["renderEnvSha256"], "greenfield render environment digest")
    sha(prov["preimageSha256"], "greenfield preimage provenance digest")
    live = snapshot(override, "greenfield preimage", MAX_ENV, uid=environment_owner, modes=(0o400, 0o600))
    live_sha = digest(live)
    if prov["preimageSha256"] != live_sha:
        stop("greenfield preimage digest does not match the provenance.", 65)
    identities = prov.get("imageIdentities")
    if not isinstance(identities, dict):
        stop("greenfield preimage image identities are invalid.", 65)
    for key in ("PLATFORM_OPS_IMAGE", "CONTROL_CENTER_IMAGE", "PROJECT_ROUTER_IMAGE", "PLATFORM_ALERT_DISPATCHER_IMAGE"):
        value = identities.get(key)
        if not isinstance(value, str) or "@sha256:" not in value:
            stop(f"greenfield preimage missing image identity {key}.", 65)
        sha(value.split("@sha256:", 1)[1], f"greenfield preimage {key} digest")
    prior_staging_path: Optional[str] = None
    prior_staging_bytes: Optional[bytes] = None
    if prov["releaseCommit"] == manifest["candidateCommit"]:
        if prior_artifact_mismatches or prior_source_archive_mismatch:
            stop("prior control/source divergence is not authorized by direct candidate provenance.")
        if checkpoint_mismatch:
            if prior is None:
                stop("checkpoint divergence has no prior receipt authority.")
            sanction_summary = evaluate_transport_sanction(sanction_raw, manifest, prior, authority_owner)
    else:
        if prior is None:
            stop("greenfield preimage provenance successor continuity has no exact prior receipt.", 65)
        prior_staging_path = f"{STAGING_PARENT}/{prior['candidateCommit']}/.env"
        prior_staging_bytes = snapshot(
            prior_staging_path, "prior receipt-bound staging environment", MAX_ENV,
            uid=environment_owner, modes=(0o600,),
        )
        if digest(prior_staging_bytes) != prior["stagingEnvironmentSha256"] or prior_staging_bytes != live:
            stop("greenfield successor preimage differs from the prior receipt-bound staging environment.")
        prior_summary = prior.get("transportSanction")
        prior_continuity = (
            isinstance(prior_summary, dict)
            and set(prior_summary) == set(SUCCESSOR_SANCTION_SUMMARY_FIELDS)
            and prior_summary.get("schema") == SUCCESSOR_SANCTION_SCHEMA
            and prior_summary.get("greenfieldPreimagePath") == override
            and prior_summary.get("greenfieldPreimageSha256") == live_sha
            and prior_summary.get("greenfieldProvenancePath") == provenance_path
            and prior_summary.get("greenfieldProvenanceSha256") == digest(prov_raw)
            and prior_summary.get("greenfieldProvenanceReleaseCommit") == prov["releaseCommit"]
        )
        if not prior_continuity and prov["releaseCommit"] != prior["candidateCommit"]:
            stop("greenfield provenance is not the prior candidate or its signed continuity chain.")
        same_exact_successor = (
            prior_continuity
            and prior["candidateCommit"] == manifest["candidateCommit"]
            and prior["candidateTree"] == manifest["candidateTree"]
            and not prior_artifact_mismatches
            and not prior_source_archive_mismatch
        )
        if (
            same_exact_successor
            and prior_summary["checkpointSha256"] == manifest["checkpointSha256"]
        ):
            # Exact-frame crash/replay retains the original signed receipt.
            sanction_summary = dict(prior_summary)
        elif same_exact_successor:
            # A fresh invocation normally regenerates only the non-authoritative
            # checkpoint timestamp.  It needs a fresh signature; the original
            # authority/runtime proof remains immutably chained through the
            # prior v2 receipt and the exact installed/source/release checks.
            no_open_runtime_transaction()
            successor = {
                "greenfieldPreimagePath": override,
                "greenfieldPreimageSha256": live_sha,
                "greenfieldProvenancePath": provenance_path,
                "greenfieldProvenanceReleaseCommit": prov["releaseCommit"],
                "greenfieldProvenanceSha256": digest(prov_raw),
                **{
                    field: prior_summary[field]
                    for field in (
                        "runtimeActiveReceiptSha256", "runtimeAuthorityDocumentId",
                        "runtimeAuthoritySha256", "runtimeCandidateCommit",
                        "runtimeCandidateTree", "runtimeSourceArchiveSha256",
                    )
                },
            }
            sanction_summary = evaluate_transport_sanction(
                sanction_raw, manifest, prior, authority_owner, successor,
            )
        else:
            runtime = validate_transitional_runtime_authority(
                authority_owner, prior_artifact_mismatches, prior_source_archive_mismatch,
                transaction_lease,
            )
            successor = {
                "greenfieldPreimagePath": override,
                "greenfieldPreimageSha256": live_sha,
                "greenfieldProvenancePath": provenance_path,
                "greenfieldProvenanceReleaseCommit": prov["releaseCommit"],
                "greenfieldProvenanceSha256": digest(prov_raw),
                **runtime,
            }
            sanction_summary = evaluate_transport_sanction(
                sanction_raw, manifest, prior, authority_owner, successor,
            )
    return {
        "bytes": live, "path": override, "priorStagingBytes": prior_staging_bytes,
        "priorStagingPath": prior_staging_path, "provenanceBytes": prov_raw,
        "provenancePath": provenance_path, "transportSanction": sanction_summary,
    }


def validate_or_create_staging(
    manifest: Dict[str, object], bundle: str, journal: Dict[str, object],
    live_context: Dict[str, object],
) -> str:
    commit = manifest["candidateCommit"]
    tree = manifest["candidateTree"]
    logical = f"{STAGING_PARENT}/{commit}"
    pathname = physical(logical)
    uid = owner_uid()
    gid = owner_gid()
    live_env_path = live_context["path"]
    live_environment = live_context["bytes"]
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
        live_env_path,
        "live deployment environment",
        MAX_ENV,
        uid=uid,
        modes=(0o400, 0o600),
    ) != live_environment:
        stop("live deployment environment changed during bootstrap capture.")
    provenance_path = live_context["provenancePath"]
    if provenance_path is not None and snapshot(
        provenance_path, "greenfield preimage provenance", MAX_RECEIPT,
        uid=uid, modes=(0o400, 0o600),
    ) != live_context["provenanceBytes"]:
        stop("greenfield preimage provenance changed during bootstrap capture.")
    prior_staging_path = live_context["priorStagingPath"]
    if prior_staging_path is not None and snapshot(
        prior_staging_path, "prior receipt-bound staging environment", MAX_ENV,
        uid=uid, modes=(0o600,),
    ) != live_context["priorStagingBytes"]:
        stop("prior receipt-bound staging environment changed during bootstrap capture.")
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
    if not isinstance(bridge, dict) or set(bridge) not in (
        set(BRIDGE_RECEIPT_FIELDS), set(BRIDGE_RECEIPT_FIELDS_V2),
    ):
        return False
    try:
        validate_document_id(bridge, "committed bootstrap bridge receipt")
        validate_prior_transport_sanction(bridge)
    except BridgeStop:
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
    if value["schema"] != JOURNAL_SCHEMA or value["status"] not in ("VALIDATING", "INSTALLING", "COMMITTED"):
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
    if journal["status"] == "VALIDATING":
        # No authority-bearing target is touched until the signed/predecessor
        # gate promotes this journal durably to INSTALLING.
        cleanup_transaction()
        return
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


def acquire_transaction_lock() -> int:
    """Join the controller/reconciler/install maintenance exclusion domain.

    The bridge holds this lock only while it proves the predecessor/runtime
    state and publishes the exact target source, checkpoint, and staging
    environment.  It must be released before invoking the control-artifact
    consumer, which independently reacquires the same lock in the common
    transaction-before-installer order.
    """
    pathname = physical(TRANSACTION_LOCK)
    descriptor = os.open(
        pathname,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    metadata = os.fstat(descriptor)
    expected_owner = os.geteuid() if TEST_ROOT is not None else 0
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != expected_owner
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        os.close(descriptor)
        stop("LOCAL_PRIVATE transaction lock identity is unsafe.")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(descriptor)
        stop("another V1 LOCAL_PRIVATE maintenance transaction is active.", 75)
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
            "status": "VALIDATING",
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

        # This lock closes the runtime-proof/publication TOCTOU against every
        # controller, reconciler, and control-artifact maintenance operation.
        # It is released before either consumer is invoked: the control
        # consumer later reacquires it itself, preventing lock recursion.
        transaction_lease: Dict[str, Optional[int]] = {
            "descriptor": acquire_transaction_lock(),
        }
        try:
            prior: Optional[Dict[str, object]] = None
            checkpoint_mismatch = False
            prior_artifact_mismatches: Tuple[str, ...] = ()
            prior_source_archive_mismatch = False
            if historical_precondition:
                legacy_consumer_sha256 = digest(legacy_consumer)
                legacy_v1_sudoers_sha256 = digest(legacy_v1_sudoers)
                legacy_broad_before_sha256 = digest(broad_sudoers)
            else:
                (
                    legacy_consumer_sha256,
                    legacy_v1_sudoers_sha256,
                    legacy_broad_before_sha256,
                    prior,
                    checkpoint_mismatch,
                    prior_artifact_mismatches,
                    prior_source_archive_mismatch,
                ) = validate_prior_control_chain(
                    entries,
                    expected_legacy_consumer_sha,
                    0 if TEST_ROOT is None else uid,
                )

            # The signed successor gate is deliberately complete before either
            # authority-bearing predeploy target is replaced.
            live_context = resolve_live_env(
                manifest, prior, captured["sanction"], checkpoint_mismatch,
                prior_artifact_mismatches, prior_source_archive_mismatch,
                uid,
                0 if TEST_ROOT is None else uid,
                transaction_lease,
            )
            sanction_summary = live_context["transportSanction"]
            # This durable promotion is the publication intent.  Recovery may
            # restore the captured preimages from this point onward; before it,
            # a failed signature or lock acquisition only discards scratch.
            journal["status"] = "INSTALLING"
            write_journal(journal)
            atomic_write(SOURCE_ARCHIVE, snapshot(f"{TRANSACTION}/sourceArchive.bin", "staged source archive", MAX_ARCHIVE, modes=(0o400,)), 0o400, "archive")
            crash_point()
            atomic_write(INSTALL_CHECKPOINT, captured["checkpoint"], 0o400, "checkpoint")
            crash_point()
            staging_environment_sha256 = validate_or_create_staging(
                manifest,
                part_paths["gitBundle"],
                journal,
                live_context,
            )
        finally:
            descriptor = transaction_lease["descriptor"]
            if descriptor is not None:
                os.close(descriptor)

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
            "transportSanction": sanction_summary,
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
