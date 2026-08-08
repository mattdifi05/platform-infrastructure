#!/usr/bin/env python3
"""Fixed-action supervisor for the global platform activation transaction."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import pwd
import re
import select
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time


VERSION = "platform-activation-broker/v1"
GLOBAL_STATE_DIRECTORY = "/srv/platform-infrastructure/platform-activation"
RELEASE_STATE_STORE = "/srv/platform-infrastructure/release-states"
FIXED_FIREWALL_HELPER = "/usr/local/libexec/platform-workload-egress-firewall"
FIXED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
HEX64 = re.compile(r"^[a-f0-9]{64}$")
GIT_OBJECT = re.compile(r"^([a-f0-9]{40}|[a-f0-9]{64})$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
RELEASE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,254}$")
SERVICE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
PINNED_IMAGE = re.compile(
    r"^[a-z0-9.-]+(?::[0-9]+)?(?:/[a-z0-9._-]+)+@sha256:[a-f0-9]{64}$"
)
CONTEXT_KEYS = {
    "schema", "repository", "commitSha", "treeSha", "sourceArchiveSha256",
    "releaseId", "releaseRoot", "stateId", "stateRoot", "environmentFile",
    "environmentSha256", "projectName", "decisionId", "provider", "receipts",
    "dastChainSha256", "runtimeIntentSha256", "subjects", "hostedLockSha256",
    "noHosted", "sourceRenderSha256", "combinedRenderSha256",
    "persistentVolumes",
}
JOURNAL_KEYS = {
    "version", "state", "transactionId", "phase", "detail", "projectName",
    "daemonId", "releaseContextSha256", "releaseContextPath", "repository",
    "commitSha", "treeSha", "sourceArchiveSha256", "releaseId", "stateId",
    "decisionId", "runtimeIntentSha256", "targetState", "actualState",
    "lockPath", "previousLockPath", "activeReceiptSha256",
    "recoveredTransactionId",
}
ACTIVE_KEYS = {
    "version", "state", "projectName", "daemonId", "releaseContextSha256",
    "releaseContextPath", "repository", "commitSha", "treeSha",
    "sourceArchiveSha256", "releaseId", "stateId", "decisionId",
    "runtimeIntentSha256", "lockPath", "lockSha256", "coreRenderSha256",
    "combinedRenderSha256", "modelSha256", "serviceNames",
    "containerReceipts", "networkReceipts", "volumeReceipts",
}
PHASE_TRANSITIONS = {
    "intent": {"core-validated"},
    "core-validated": {"quiesced"},
    "quiesced": {"creating"},
    "creating": {"created"},
    "created": {"firewall-active", "firewall-inactive"},
    "firewall-active": {"runtime-verified"},
    "firewall-inactive": {"runtime-verified"},
    "runtime-verified": {"postdeploy-verified"},
    "postdeploy-verified": set(),
}


class BrokerError(Exception):
    pass


def fail(message: str) -> "NoReturn":
    print(message, file=sys.stderr)
    raise SystemExit(1)


def production() -> bool:
    return sys.platform.startswith("linux")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def stable_bytes(document: dict) -> bytes:
    return (json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n").encode()


def exact_keys(document: object, expected: set[str]) -> bool:
    return isinstance(document, dict) and set(document) == expected


def safe_regular(pathname: str, owner: int, mode: int) -> os.stat_result:
    try:
        details = os.lstat(pathname)
    except OSError as error:
        raise BrokerError(f"Protected file is unavailable: {pathname}: {error.strerror}.") from error
    if (
        not stat.S_ISREG(details.st_mode)
        or stat.S_ISLNK(details.st_mode)
        or details.st_nlink != 1
        or details.st_uid != owner
        or stat.S_IMODE(details.st_mode) != mode
    ):
        raise BrokerError(f"Protected file ownership or mode is invalid: {pathname}.")
    return details


def safe_directory(pathname: str, owner: int, mode: int, group: int | None = None) -> os.stat_result:
    try:
        details = os.lstat(pathname)
    except OSError as error:
        raise BrokerError(f"Protected directory is unavailable: {pathname}: {error.strerror}.") from error
    if (
        not stat.S_ISDIR(details.st_mode)
        or stat.S_ISLNK(details.st_mode)
        or os.path.realpath(pathname) != pathname
        or details.st_uid != owner
        or (group is not None and details.st_gid != group)
        or stat.S_IMODE(details.st_mode) != mode
    ):
        raise BrokerError(f"Protected directory ownership or mode is invalid: {pathname}.")
    return details


def caller_identity() -> tuple[int, int]:
    if production():
        if os.geteuid() != 0:
            raise BrokerError("Platform activation supervisor must execute as root.")
        try:
            uid = int(os.environ["SUDO_UID"], 10)
            gid = int(os.environ["SUDO_GID"], 10)
        except (KeyError, ValueError) as error:
            raise BrokerError("Platform activation supervisor requires sudo caller identity.") from error
        if uid <= 0 or gid < 0:
            raise BrokerError("Platform activation supervisor refuses an invalid deployment caller.")
        return uid, gid
    return os.getuid(), os.getgid()


def validate_parent_chain(candidate: str, owner: int) -> None:
    current = os.path.abspath(candidate)
    chain: list[str] = []
    while current != "/":
        chain.append(current)
        current = os.path.dirname(current)
    allowed_owners = {owner} if production() else {0, owner}
    for pathname in reversed(chain):
        details = os.lstat(pathname)
        if stat.S_ISLNK(details.st_mode) or details.st_uid not in allowed_owners or (details.st_mode & 0o022) != 0:
            raise BrokerError(f"Immutable release path component is unsafe: {pathname}.")


def secure_gate(script: str) -> str:
    candidate = os.path.abspath(script)
    owner = 0 if production() else os.getuid()
    if production() and not candidate.startswith("/srv/platform-infrastructure/releases/"):
        raise BrokerError("Activation gate is outside the immutable release store.")
    validate_parent_chain(candidate, owner)
    details = os.lstat(candidate)
    if (
        not stat.S_ISREG(details.st_mode)
        or stat.S_ISLNK(details.st_mode)
        or details.st_nlink != 1
        or details.st_uid != owner
        or (details.st_mode & 0o022) != 0
        or not candidate.endswith("/scripts/hosted-workload-activation-gate.sh")
    ):
        raise BrokerError("Activation gate is not an immutable release script.")
    return candidate


def coordinator(directory_argument: str, uid: int, gid: int, create: bool) -> str:
    directory = os.path.abspath(directory_argument)
    if production() and directory != GLOBAL_STATE_DIRECTORY:
        raise BrokerError("Activation state path is not the fixed global coordinator.")
    expected_owner = 0 if production() else uid
    expected_mode = 0o750 if production() else 0o700
    if create:
        try:
            os.mkdir(directory, expected_mode)
        except FileExistsError:
            pass
        if production():
            os.chown(directory, 0, gid)
            os.chmod(directory, expected_mode)
    safe_directory(directory, expected_owner, expected_mode, gid)
    return directory


def acquire_lock(directory: str, uid: int, gid: int) -> tuple[int, os.stat_result]:
    target = os.path.join(directory, "activation.lock")
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    expected_owner = 0 if production() else uid
    expected_mode = 0o640 if production() else 0o600
    try:
        descriptor = os.open(target, flags | os.O_CREAT | os.O_EXCL, expected_mode)
        if production():
            os.fchown(descriptor, 0, gid)
        os.fsync(descriptor)
        directory_descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as error:
        if error.errno != errno.EEXIST:
            raise BrokerError(f"Activation mutex could not be created safely: {error.strerror}.") from error
        try:
            descriptor = os.open(target, flags)
        except OSError as open_error:
            raise BrokerError(
                f"Activation mutex could not be opened safely: {open_error.strerror}."
            ) from open_error
    opened = os.fstat(descriptor)
    named = safe_regular(target, expected_owner, expected_mode)
    if opened.st_dev != named.st_dev or opened.st_ino != named.st_ino:
        raise BrokerError("Activation mutex descriptor/path identity mismatch.")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        raise BrokerError("Another platform activation transaction holds the global mutex.") from error
    os.set_inheritable(descriptor, False)
    return descriptor, opened


def stable_read_file(pathname: str, owner: int, mode: int, optional: bool = False) -> bytes | None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(pathname, flags)
    except OSError as error:
        if optional and error.errno == errno.ENOENT:
            return None
        raise BrokerError(f"Protected object cannot be opened: {pathname}.") from error
    try:
        before = os.fstat(descriptor)
        named = safe_regular(pathname, owner, mode)
        if before.st_dev != named.st_dev or before.st_ino != named.st_ino:
            raise BrokerError(f"Protected object descriptor/path mismatch: {pathname}.")
        raw = os.read(descriptor, 16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise BrokerError(f"Protected object is too large: {pathname}.")
        after = os.fstat(descriptor)
        for field in ["st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"]:
            if getattr(before, field) != getattr(after, field):
                raise BrokerError(f"Protected object changed while being read: {pathname}.")
        return raw
    finally:
        os.close(descriptor)


def atomic_write(directory: str, name: str, document: dict, uid: int, gid: int) -> None:
    expected_mode = 0o640 if production() else 0o600
    target = os.path.join(directory, name)
    payload = stable_bytes(document)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{name}.", suffix=".tmp", dir=directory)
    try:
        os.fchmod(descriptor, expected_mode)
        if production():
            os.fchown(descriptor, 0, gid)
        os.write(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, target)
        directory_descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def validate_context(document: object, path_value: str) -> dict:
    if not exact_keys(document, CONTEXT_KEYS):
        raise BrokerError("Trusted release context has an open or incomplete schema.")
    assert isinstance(document, dict)
    sha_fields = [
        "sourceArchiveSha256", "environmentSha256", "dastChainSha256",
        "runtimeIntentSha256", "sourceRenderSha256", "combinedRenderSha256",
    ]
    if (
        document["schema"] != "platform-trusted-release-context/v3"
        or document["projectName"] != "platform_infra_vps"
        or not isinstance(document["noHosted"], bool)
        or not all(isinstance(document[key], str) and HEX64.fullmatch(document[key]) for key in sha_fields)
        or document["sourceRenderSha256"] == document["combinedRenderSha256"]
        or (
            document["hostedLockSha256"] is not None
            if document["noHosted"]
            else not isinstance(document["hostedLockSha256"], str)
            or not HEX64.fullmatch(document["hostedLockSha256"])
        )
        or not isinstance(document["commitSha"], str) or not GIT_OBJECT.fullmatch(document["commitSha"])
        or not isinstance(document["treeSha"], str) or not GIT_OBJECT.fullmatch(document["treeSha"])
        or not isinstance(document["releaseId"], str) or not RELEASE_IDENTIFIER.fullmatch(document["releaseId"])
        or not isinstance(document["stateId"], str) or not RELEASE_IDENTIFIER.fullmatch(document["stateId"])
        or not isinstance(document["decisionId"], str) or not IDENTIFIER.fullmatch(document["decisionId"])
        or not isinstance(document["subjects"], list) or not document["subjects"]
    ):
        raise BrokerError("Trusted release context identity is invalid.")
    if (
        not exact_keys(document["provider"], {"metadataSha256", "runId", "attempt", "challenge"})
        or not isinstance(document["provider"]["metadataSha256"], str)
        or not HEX64.fullmatch(document["provider"]["metadataSha256"])
        or not isinstance(document["provider"]["runId"], str)
        or not IDENTIFIER.fullmatch(document["provider"]["runId"])
        or not isinstance(document["provider"]["attempt"], int)
        or isinstance(document["provider"]["attempt"], bool)
        or document["provider"]["attempt"] < 1
        or not isinstance(document["provider"]["challenge"], str)
        or not HEX64.fullmatch(document["provider"]["challenge"])
    ):
        raise BrokerError("Trusted release context provider admission is invalid.")
    receipt_keys = {
        "artifactSha256", "deploymentSha256", "dastProviderSha256",
        "dastAuthorizationSha256",
    }
    if (
        not exact_keys(document["receipts"], receipt_keys)
        or not all(
            isinstance(document["receipts"][key], str)
            and HEX64.fullmatch(document["receipts"][key])
            for key in receipt_keys
        )
    ):
        raise BrokerError("Trusted release context receipt admission is invalid.")
    expected_context_path = os.path.join(document["stateRoot"], "trusted-release-context.json")
    if expected_context_path != path_value or os.path.basename(document["stateRoot"]) != document["stateId"]:
        raise BrokerError("Trusted release context path/state identity mismatch.")
    subjects = document["subjects"]
    if subjects != sorted(subjects, key=lambda value: value.get("serviceName", "")):
        raise BrokerError("Trusted release subjects are not sorted.")
    seen: set[str] = set()
    for subject in subjects:
        if (
            not exact_keys(subject, {"serviceName", "imageReference", "imageId"})
            or not isinstance(subject["serviceName"], str) or not SERVICE.fullmatch(subject["serviceName"])
            or subject["serviceName"] in seen
            or not isinstance(subject["imageReference"], str)
            or not PINNED_IMAGE.fullmatch(subject["imageReference"])
            or not isinstance(subject["imageId"], str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", subject["imageId"])
        ):
            raise BrokerError("Trusted release subject map is invalid.")
        seen.add(subject["serviceName"])
    scheduler = [item for item in subjects if item["serviceName"] == "backup-scheduler"]
    if (
        len(scheduler) != 1
        or not re.fullmatch(
            r"[a-z0-9.-]+(?::[0-9]+)?(?:/[a-z0-9._-]+)*/platform-infrastructure-backup-scheduler@sha256:[a-f0-9]{64}",
            scheduler[0]["imageReference"],
        )
    ):
        raise BrokerError("Trusted release context must bind the dedicated backup scheduler image.")
    volumes = document["persistentVolumes"]
    if not isinstance(volumes, list) or len(volumes) != 1:
        raise BrokerError("Trusted release context must bind one exact persistent volume.")
    volume = volumes[0]
    if (
        not exact_keys(
            volume,
            {"name", "createdAt", "driver", "scope", "options", "labels", "mountpoint", "owner"},
        )
        or volume["name"] != "enterprise_local_registry_data"
        or volume["driver"] != "local"
        or volume["scope"] != "local"
        or not isinstance(volume["createdAt"], str)
        or not volume["createdAt"]
        or not exact_keys(volume["options"], set())
        or not exact_keys(
            volume["labels"],
            {"platform.infrastructure.managed", "platform.infrastructure.purpose"},
        )
        or volume["labels"]["platform.infrastructure.managed"] != "true"
        or volume["labels"]["platform.infrastructure.purpose"] != "local-registry"
        or not isinstance(volume["mountpoint"], str)
        or not volume["mountpoint"].startswith("/")
        or "//" in volume["mountpoint"]
        or ".." in volume["mountpoint"].split("/")
        or not volume["mountpoint"].endswith("/enterprise_local_registry_data/_data")
        or not exact_keys(volume["owner"], {"uid", "gid", "mode"})
        or volume["owner"]["uid"] != 0
        or volume["owner"]["gid"] != 0
        or not isinstance(volume["owner"]["mode"], str)
        or not re.fullmatch(r"0[0-7]{3}", volume["owner"]["mode"])
        or int(volume["owner"]["mode"], 8) & 0o022
    ):
        raise BrokerError("Trusted release context persistent volume identity is invalid.")
    return document


def load_context(path_value: str) -> tuple[dict, str]:
    candidate = os.path.abspath(path_value)
    owner = 0 if production() else os.getuid()
    if production() and not candidate.startswith(f"{RELEASE_STATE_STORE}/"):
        raise BrokerError("Trusted release context is outside the release-state store.")
    raw = stable_read_file(candidate, owner, 0o640)
    assert raw is not None
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BrokerError("Trusted release context JSON is invalid.") from error
    return validate_context(document, candidate), sha256_bytes(raw)


def journal_for_context(
    context: dict,
    context_path: str,
    context_sha: str,
    transaction_id: str,
    daemon_id: str,
    target_state: str,
    lock_path: str | None,
    previous_lock_path: str | None,
    detail: str,
) -> dict:
    return {
        "version": 2,
        "state": "pending",
        "transactionId": transaction_id,
        "phase": "intent",
        "detail": detail,
        "projectName": "platform_infra_vps",
        "daemonId": daemon_id,
        "releaseContextSha256": context_sha,
        "releaseContextPath": context_path,
        "repository": context["repository"],
        "commitSha": context["commitSha"],
        "treeSha": context["treeSha"],
        "sourceArchiveSha256": context["sourceArchiveSha256"],
        "releaseId": context["releaseId"],
        "stateId": context["stateId"],
        "decisionId": context["decisionId"],
        "runtimeIntentSha256": context["runtimeIntentSha256"],
        "targetState": target_state,
        "actualState": None,
        "lockPath": lock_path,
        "previousLockPath": previous_lock_path,
        "activeReceiptSha256": None,
        "recoveredTransactionId": None,
    }


def validate_journal(document: object) -> dict:
    if not exact_keys(document, JOURNAL_KEYS):
        raise BrokerError("Activation journal schema is not exact.")
    assert isinstance(document, dict)
    if (
        document["version"] != 2
        or document["state"] not in {"pending", "complete"}
        or not isinstance(document["transactionId"], str) or not HEX64.fullmatch(document["transactionId"])
        or document["projectName"] != "platform_infra_vps"
        or not isinstance(document["releaseContextSha256"], str) or not HEX64.fullmatch(document["releaseContextSha256"])
        or document["targetState"] not in {"hosted", "no-hosted"}
        or document["actualState"] not in {None, "hosted", "no-hosted", "stopped"}
    ):
        raise BrokerError("Activation journal identity is invalid.")
    return document


def validate_receipt_list(value: object, name: str) -> list:
    if not isinstance(value, list):
        raise BrokerError(f"Active {name} receipts must be an array.")
    return value


def validate_active(document: object) -> dict:
    if not exact_keys(document, ACTIVE_KEYS):
        raise BrokerError("Active receipt schema is not exact.")
    assert isinstance(document, dict)
    if (
        document["version"] != 2
        or document["state"] not in {"hosted", "no-hosted", "stopped"}
        or document["projectName"] != "platform_infra_vps"
        or not isinstance(document["releaseContextSha256"], str) or not HEX64.fullmatch(document["releaseContextSha256"])
        or not isinstance(document["serviceNames"], list)
        or document["serviceNames"] != sorted(set(document["serviceNames"]))
    ):
        raise BrokerError("Active receipt identity is invalid.")
    validate_receipt_list(document["containerReceipts"], "container")
    validate_receipt_list(document["networkReceipts"], "network")
    validate_receipt_list(document["volumeReceipts"], "volume")
    return document


def read_json_state(directory: str, name: str, uid: int, optional: bool = True) -> dict | None:
    owner = 0 if production() else uid
    raw = stable_read_file(os.path.join(directory, name), owner, 0o640 if production() else 0o600, optional)
    if raw is None:
        return None
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BrokerError(f"Activation {name} JSON is invalid.") from error
    return validate_journal(document) if name == "journal.json" else validate_active(document)


def validate_state_pair(journal: dict | None, active: dict | None) -> None:
    if journal and journal["state"] == "complete":
        if not active:
            raise BrokerError("Complete activation journal has no active receipt.")
        receipt_sha = sha256_bytes(stable_bytes(active))
        if journal["activeReceiptSha256"] != receipt_sha or journal["actualState"] != active["state"]:
            raise BrokerError("Complete activation journal and active receipt are inconsistent.")
    if active:
        context, context_sha = load_context(active["releaseContextPath"])
        for key in [
            "repository", "commitSha", "treeSha", "sourceArchiveSha256",
            "releaseId", "stateId", "decisionId", "runtimeIntentSha256",
        ]:
            if active[key] != context[key]:
                raise BrokerError("Active receipt release provenance does not match retained context.")
        if active["releaseContextSha256"] != context_sha:
            raise BrokerError("Active receipt release-context digest is invalid.")


def parse_request_line(raw: bytes, token: str) -> tuple[str, list, str]:
    try:
        request = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BrokerError("Broker request is not valid JSON.") from error
    if not exact_keys(request, {"token", "action", "arguments", "stdin"}):
        raise BrokerError("Broker request schema is not exact.")
    if request["token"] != token or not isinstance(request["action"], str) or not isinstance(request["arguments"], list) or not isinstance(request["stdin"], str):
        raise BrokerError("Broker request authentication is invalid.")
    if any(not isinstance(value, str) for value in request["arguments"]):
        raise BrokerError("Broker request arguments must be strings.")
    return request["action"], request["arguments"], request["stdin"]


def context_matches_journal(context: dict, context_path: str, context_sha: str, journal: dict) -> None:
    if journal["releaseContextPath"] != context_path or journal["releaseContextSha256"] != context_sha:
        raise BrokerError("Transaction context does not match the pending journal.")
    for key in [
        "repository", "commitSha", "treeSha", "sourceArchiveSha256",
        "releaseId", "stateId", "decisionId", "runtimeIntentSha256",
    ]:
        if journal[key] != context[key]:
            raise BrokerError("Transaction context provenance differs from pending journal.")


def receipt_from_commit(
    context: dict,
    context_path: str,
    context_sha: str,
    daemon_id: str,
    actual_state: str,
    lock_path: str | None,
    model_sha: str | None,
    service_names: list[str],
    receipts: dict,
) -> dict:
    if actual_state == "hosted":
        if context["noHosted"]:
            raise BrokerError("Hosted commit conflicts with no-hosted release intent.")
        lock_sha = context["hostedLockSha256"]
        core_sha = context["sourceRenderSha256"]
        combined_sha = context["combinedRenderSha256"]
        expected_names = [item["serviceName"] for item in context["subjects"]]
        if service_names != expected_names:
            raise BrokerError("Hosted active service set differs from trusted subjects.")
    elif actual_state == "no-hosted":
        no_hosted_path = os.path.join(context["releaseRoot"], "config", "no-hosted-workloads.lock.json")
        raw = stable_read_file(no_hosted_path, 0 if production() else os.getuid(), 0o644)
        assert raw is not None
        lock_sha = sha256_bytes(raw)
        core_sha = context["sourceRenderSha256"]
        combined_sha = context["combinedRenderSha256"] if context["noHosted"] else core_sha
        subject_names = {item["serviceName"] for item in context["subjects"]}
        if not service_names or any(name not in subject_names for name in service_names):
            raise BrokerError("No-hosted service set is not a trusted core subject subset.")
    elif actual_state == "stopped":
        lock_sha = context["hostedLockSha256"]
        core_sha = context["sourceRenderSha256"]
        combined_sha = context["combinedRenderSha256"]
        if service_names or any(receipts.get(key) for key in ["containerReceipts", "networkReceipts", "volumeReceipts"]):
            raise BrokerError("Stopped receipt cannot claim active services or Engine resources.")
        model_sha = None
    else:
        raise BrokerError("Unsupported committed activation state.")
    if model_sha is not None and (not isinstance(model_sha, str) or not HEX64.fullmatch(model_sha)):
        raise BrokerError("Committed runtime model digest is invalid.")
    return {
        "version": 2,
        "state": actual_state,
        "projectName": "platform_infra_vps",
        "daemonId": daemon_id,
        "releaseContextSha256": context_sha,
        "releaseContextPath": context_path,
        "repository": context["repository"],
        "commitSha": context["commitSha"],
        "treeSha": context["treeSha"],
        "sourceArchiveSha256": context["sourceArchiveSha256"],
        "releaseId": context["releaseId"],
        "stateId": context["stateId"],
        "decisionId": context["decisionId"],
        "runtimeIntentSha256": context["runtimeIntentSha256"],
        "lockPath": lock_path,
        "lockSha256": lock_sha,
        "coreRenderSha256": core_sha,
        "combinedRenderSha256": combined_sha,
        "modelSha256": model_sha,
        "serviceNames": service_names,
        "containerReceipts": validate_receipt_list(receipts.get("containerReceipts"), "container"),
        "networkReceipts": validate_receipt_list(receipts.get("networkReceipts"), "network"),
        "volumeReceipts": validate_receipt_list(receipts.get("volumeReceipts"), "volume"),
    }


def commit_pair(directory: str, uid: int, gid: int, journal: dict, active: dict, detail: str) -> dict:
    validate_active(active)
    receipt_sha = sha256_bytes(stable_bytes(active))
    complete = {
        **journal,
        "state": "complete",
        "phase": "complete",
        "detail": detail,
        "actualState": active["state"],
        "activeReceiptSha256": receipt_sha,
    }
    validate_journal(complete)
    atomic_write(directory, "active.json", active, uid, gid)
    atomic_write(directory, "journal.json", complete, uid, gid)
    return {"journal": complete, "active": active}


def run_firewall(
    mode: str,
    lock_path: str,
    project_name: str,
    daemon_id: str,
    helper_path: str,
) -> dict:
    if project_name != "platform_infra_vps":
        raise BrokerError("Firewall request project is not canonical.")
    helper = FIXED_FIREWALL_HELPER if production() else helper_path
    owner = 0 if production() else os.getuid()
    safe_regular(helper, owner, stat.S_IMODE(os.lstat(helper).st_mode))
    if os.lstat(helper).st_mode & 0o022:
        raise BrokerError("Privileged firewall helper is writable.")
    common = ["--project-name", project_name, "--expected-daemon-id", daemon_id]
    if mode == "preflight":
        arguments = ["--privilege-preflight", "--lock", lock_path, *common]
    elif mode == "apply":
        arguments = ["--apply", "--lock", lock_path, *common, "--confirm", "APPLY-WORKLOAD-EGRESS-FIREWALL"]
    elif mode == "verify":
        arguments = ["--verify", "--lock", lock_path, *common]
    elif mode == "deactivate":
        arguments = ["--rollback", *common, "--confirm", "ROLLBACK-WORKLOAD-EGRESS-FIREWALL"]
    else:
        raise BrokerError("Unsupported firewall broker action.")
    environment = {
        "PATH": FIXED_PATH,
        "DOCKER_HOST": "unix:///var/run/docker.sock",
        "HOSTED_WORKLOAD_ALLOW_RESOLVED": "0",
        "LANG": "C.UTF-8",
    }
    result = subprocess.run(
        ["/bin/sh", helper, *arguments],
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=600,
        check=False,
    )
    return {"status": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def dispatch(
    action: str,
    arguments: list[str],
    stdin_value: str,
    directory: str,
    uid: int,
    gid: int,
    local_firewall_helper: str,
) -> object:
    journal = read_json_state(directory, "journal.json", uid)
    active = read_json_state(directory, "active.json", uid)
    validate_state_pair(journal, active)
    if action == "ping":
        if arguments:
            raise BrokerError("Ping takes no arguments.")
        return {"version": VERSION, "coordinator": directory, "supervisorPid": os.getpid()}
    if action == "snapshot":
        if arguments:
            raise BrokerError("Snapshot takes no arguments.")
        return {"journal": journal, "active": active}
    if action == "begin":
        if len(arguments) != 8:
            raise BrokerError("Begin requires transaction/context/daemon/target/lock/previous/detail.")
        transaction_id, context_path, daemon_id, target_state, lock_path, previous_lock_path, detail, expected_previous_sha = arguments
        if not HEX64.fullmatch(transaction_id) or target_state not in {"hosted", "no-hosted"}:
            raise BrokerError("Begin transaction identity is invalid.")
        if journal and journal["state"] == "pending":
            raise BrokerError("A pending transaction must be recovered before begin.")
        context, context_sha = load_context(context_path)
        if context["noHosted"] != (target_state == "no-hosted"):
            raise BrokerError("Begin target differs from trusted release intent.")
        current_previous_sha = active["releaseContextSha256"] if active else ""
        if expected_previous_sha != current_previous_sha:
            raise BrokerError("Begin active-receipt compare-and-swap failed.")
        created = journal_for_context(
            context,
            context_path,
            context_sha,
            transaction_id,
            daemon_id,
            target_state,
            lock_path or None,
            previous_lock_path or None,
            detail,
        )
        atomic_write(directory, "journal.json", created, uid, gid)
        return created
    if action == "advance":
        if len(arguments) != 4:
            raise BrokerError("Advance requires transaction/from/to/detail.")
        transaction_id, previous_phase, next_phase, detail = arguments
        if not journal or journal["state"] != "pending" or journal["transactionId"] != transaction_id or journal["phase"] != previous_phase:
            raise BrokerError("Advance compare-and-swap failed.")
        if next_phase not in PHASE_TRANSITIONS.get(previous_phase, set()):
            raise BrokerError("Activation journal phase transition is forbidden.")
        updated = {**journal, "phase": next_phase, "detail": detail}
        atomic_write(directory, "journal.json", updated, uid, gid)
        return updated
    if action == "commit":
        if len(arguments) != 8:
            raise BrokerError("Commit requires transaction/from/context/daemon/state/lock/model/detail.")
        transaction_id, previous_phase, context_path, daemon_id, actual_state, lock_path, model_sha, detail = arguments
        if not journal or journal["state"] != "pending" or journal["transactionId"] != transaction_id or journal["phase"] != previous_phase:
            raise BrokerError("Commit compare-and-swap failed.")
        context, context_sha = load_context(context_path)
        context_matches_journal(context, context_path, context_sha, journal)
        try:
            evidence = json.loads(stdin_value)
        except json.JSONDecodeError as error:
            raise BrokerError("Commit Engine evidence JSON is invalid.") from error
        if not exact_keys(evidence, {"serviceNames", "containerReceipts", "networkReceipts", "volumeReceipts"}):
            raise BrokerError("Commit Engine evidence schema is not exact.")
        service_names = evidence["serviceNames"]
        if not isinstance(service_names, list) or service_names != sorted(set(service_names)) or any(not isinstance(name, str) or not SERVICE.fullmatch(name) for name in service_names):
            raise BrokerError("Commit service set is invalid.")
        receipt = receipt_from_commit(
            context,
            context_path,
            context_sha,
            daemon_id,
            actual_state,
            lock_path or None,
            model_sha or None,
            service_names,
            evidence,
        )
        return commit_pair(directory, uid, gid, journal, receipt, detail)
    if action == "recover-stop":
        if len(arguments) != 5:
            raise BrokerError("Recover-stop requires transaction/from/context/daemon/detail.")
        transaction_id, previous_phase, retained_path, daemon_id, detail = arguments
        if not journal or journal["state"] != "pending" or journal["transactionId"] != transaction_id or journal["phase"] != previous_phase:
            raise BrokerError("Recovery compare-and-swap failed.")
        expected_path = os.path.join(os.path.dirname(os.path.dirname(journal["releaseContextPath"])), journal["stateId"], "trusted-release-context.json")
        if retained_path != expected_path:
            raise BrokerError("Recovery retained context path is not journal-derived.")
        context, context_sha = load_context(retained_path)
        context_matches_journal(context, retained_path, context_sha, journal)
        receipt = receipt_from_commit(
            context,
            retained_path,
            context_sha,
            daemon_id,
            "stopped",
            journal["lockPath"],
            None,
            [],
            {"containerReceipts": [], "networkReceipts": [], "volumeReceipts": []},
        )
        return commit_pair(directory, uid, gid, journal, receipt, detail)
    if action == "firewall":
        if len(arguments) != 4:
            raise BrokerError("Firewall requires mode/lock/project/daemon.")
        return run_firewall(*arguments, local_firewall_helper)
    raise BrokerError("Unsupported broker action.")


def sanitize_environment(uid: int, broker_fd: int, token: str, supervisor_pid: int) -> dict[str, str]:
    if not production():
        environment = os.environ.copy()
        environment.update(
            {
                "PLATFORM_ACTIVATION_BROKER_FD": str(broker_fd),
                "PLATFORM_ACTIVATION_BROKER_TOKEN": token,
                "PLATFORM_ACTIVATION_SUPERVISOR_PID": str(supervisor_pid),
            }
        )
        return environment
    account = pwd.getpwuid(uid)
    environment = {
        "PATH": FIXED_PATH,
        "HOME": account.pw_dir,
        "USER": account.pw_name,
        "LOGNAME": account.pw_name,
        "SHELL": "/bin/bash",
        "LANG": "C.UTF-8",
        "TMPDIR": "/tmp",
        "PLATFORM_ACTIVATION_BROKER_FD": str(broker_fd),
        "PLATFORM_ACTIVATION_BROKER_TOKEN": token,
        "PLATFORM_ACTIVATION_SUPERVISOR_PID": str(supervisor_pid),
    }
    for key, value in os.environ.items():
        if (
            key.startswith("DEPLOY_")
            or key in {
                "HOSTED_ACTIVATION_TIMEOUT_SECONDS",
                "HOSTED_VERIFY_TIMEOUT_SECONDS",
                "HOSTED_STOP_TIMEOUT_SECONDS",
                "TZ",
            }
            or key.startswith("LC_")
        ):
            environment[key] = value
    return environment


def send_response(channel: socket.socket, response: dict) -> None:
    channel.sendall(stable_bytes(response))


def supervise(directory_argument: str, script_argument: str, arguments: list[str]) -> int:
    uid, gid = caller_identity()
    directory = coordinator(directory_argument, uid, gid, True)
    script = secure_gate(script_argument)
    lock_descriptor, _ = acquire_lock(directory, uid, gid)
    parent_channel, child_channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    token = os.urandom(32).hex()
    child_pid = os.fork()
    if child_pid == 0:
        try:
            parent_channel.close()
            os.close(lock_descriptor)
            child_channel.set_inheritable(True)
            environment = sanitize_environment(uid, child_channel.fileno(), token, os.getppid())
            if production():
                os.setgroups([])
                os.setgid(gid)
                os.setuid(uid)
            os.execve("/bin/bash", ["/bin/bash", script, *arguments], environment)
        except BaseException as error:
            print(f"Activation supervisor child failed: {error}", file=sys.stderr)
            os._exit(126)
    child_channel.close()
    parent_channel.setblocking(False)
    buffer = b""
    exit_status: int | None = None

    def forward_signal(signal_number: int, _frame: object) -> None:
        try:
            os.kill(child_pid, signal_number)
        except ProcessLookupError:
            pass

    for signal_number in [signal.SIGHUP, signal.SIGINT, signal.SIGTERM]:
        signal.signal(signal_number, forward_signal)
    local_firewall_helper = os.path.join(os.path.dirname(script), "workload-egress-firewall.sh")
    try:
        while exit_status is None:
            waited, status = os.waitpid(child_pid, os.WNOHANG)
            if waited == child_pid:
                exit_status = os.waitstatus_to_exitcode(status)
                break
            readable, _, _ = select.select([parent_channel], [], [], 0.2)
            if not readable:
                continue
            try:
                chunk = parent_channel.recv(65536)
            except BlockingIOError:
                continue
            if not chunk:
                continue
            buffer += chunk
            if len(buffer) > 20 * 1024 * 1024:
                raise BrokerError("Broker request buffer exceeded the hard limit.")
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                if not line:
                    continue
                try:
                    action, request_arguments, stdin_value = parse_request_line(line, token)
                    result = dispatch(
                        action,
                        request_arguments,
                        stdin_value,
                        directory,
                        uid,
                        gid,
                        local_firewall_helper,
                    )
                    send_response(parent_channel, {"ok": True, "result": result})
                except (BrokerError, OSError, subprocess.SubprocessError) as error:
                    send_response(parent_channel, {"ok": False, "error": str(error)})
        return exit_status
    finally:
        parent_channel.close()
        os.close(lock_descriptor)
        if exit_status is None:
            try:
                os.kill(child_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(child_pid, 0)
            except ChildProcessError:
                pass


def verify_peer(channel: socket.socket) -> None:
    if not production():
        return
    try:
        credentials = channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        peer_pid = int.from_bytes(credentials[0:4], sys.byteorder)
        peer_uid = int.from_bytes(credentials[4:8], sys.byteorder)
    except OSError as error:
        raise BrokerError("Broker peer credentials are unavailable.") from error
    if peer_pid <= 0 or peer_uid != 0:
        raise BrokerError("Broker peer is not the privileged supervisor.")


def client(fd_text: str, token: str, action: str, arguments: list[str]) -> int:
    try:
        descriptor = int(fd_text, 10)
    except ValueError as error:
        raise BrokerError("Broker client descriptor is invalid.") from error
    channel = socket.socket(fileno=os.dup(descriptor))
    verify_peer(channel)
    stdin_value = sys.stdin.read()
    request = {
        "token": token,
        "action": action,
        "arguments": arguments,
        "stdin": stdin_value,
    }
    channel.sendall(stable_bytes(request))
    buffer = b""
    while b"\n" not in buffer:
        chunk = channel.recv(65536)
        if not chunk:
            raise BrokerError("Broker supervisor closed the authenticated session.")
        buffer += chunk
        if len(buffer) > 20 * 1024 * 1024:
            raise BrokerError("Broker response exceeded the hard limit.")
    line, _ = buffer.split(b"\n", 1)
    response = json.loads(line)
    if not response.get("ok"):
        raise BrokerError(str(response.get("error", "Broker request failed.")))
    result = response.get("result")
    if (
        not production()
        and action == "commit"
        and os.environ.get("HOSTED_TEST_LOSE_COMMIT_ACK") == "1"
    ):
        raise BrokerError("Injected loss of the durable commit acknowledgement.")
    if action == "firewall":
        if result.get("stdout"):
            sys.stdout.write(result["stdout"])
        if result.get("stderr"):
            sys.stderr.write(result["stderr"])
        return int(result["status"])
    if result is not None:
        sys.stdout.write(json.dumps(result, separators=(",", ":"), sort_keys=True) + "\n")
    return 0


def main() -> None:
    try:
        if len(sys.argv) >= 5 and sys.argv[1] == "supervise":
            raise SystemExit(supervise(sys.argv[2], sys.argv[3], sys.argv[4:]))
        if len(sys.argv) >= 5 and sys.argv[1] == "client":
            raise SystemExit(client(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:]))
        if len(sys.argv) == 2 and sys.argv[1] == "version":
            print(VERSION)
            return
        fail("Usage: platform-activation-broker supervise STATE_DIR GATE [ARG...] | client FD TOKEN ACTION [ARG...] | version")
    except BrokerError as error:
        fail(str(error))


if __name__ == "__main__":
    main()
