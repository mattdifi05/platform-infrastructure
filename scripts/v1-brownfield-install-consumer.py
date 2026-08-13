#!/usr/bin/python3 -I
"""Authoritative, candidate-specific V1 install-only root consumer.

This program has one deliberately small authority: materialize one exact
source archive into one content-addressed release directory after an explicit
root-operator invocation.
It does not run candidate code and has no Docker, provider, network, backup,
restore, service-management, database, or activation capability.

Production inputs and outputs are constants.  The only test seam maps those
absolute paths below a private directory and is rejected when effective UID is
zero.  Test pins are consequently incapable of changing a production target.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import io
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tarfile
import time
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Dict, Iterable, List, Optional, Tuple


CANDIDATE_COMMIT = "832bf2baec47055342af7e7f73425444381b91e0"
CANDIDATE_TREE = "91cee2380809cb0691b9ac47cafa2a673d434caa"
SOURCE_ARCHIVE_SHA256 = "6eabff5f3fdbb4b129519d23a2dd9864f65477c5f0e1ecb58e1b8a9a79af3007"

STAGING_CHECKOUT = (
    "/home/platform_infrastructure/.v1-release-staging/"
    + CANDIDATE_COMMIT
)
SOURCE_ARCHIVE = (
    "/var/lib/platform-infrastructure/v1/predeploy/current/"
    "exact-source-archive.tar"
)
INSTALL_CHECKPOINT = (
    "/var/lib/platform-infrastructure/v1/predeploy/current/"
    "install-checkpoint.json"
)
FINAL_RELEASE = (
    "/srv/platform-infrastructure/releases/"
    + CANDIDATE_COMMIT
    + "-"
    + SOURCE_ARCHIVE_SHA256
)
INSTALL_RECEIPT = (
    "/var/lib/platform-infrastructure/v1/install-receipts/"
    + CANDIDATE_COMMIT
    + "-"
    + SOURCE_ARCHIVE_SHA256
    + ".json"
)
LOCK_PATH = "/run/lock/platform-v1-brownfield-install.lock"

RECEIPT_SCHEMA = "platform.v1-brownfield-install-receipt/v1"
TEST_ROOT_ENV = "PLATFORM_V1_INSTALL_CONSUMER_TEST_ROOT"
TEST_PINS = (
    "/var/lib/platform-infrastructure/v1/predeploy/current/"
    ".install-consumer-test-pins.json"
)
READY_BUT_DISABLED = [
    "PROVIDER_ADMISSION",
    "DNS_PUBLICATION",
    "DAST",
    "SIGSTORE_PROMOTION",
    "DOCKER_CONTROL_PLANE",
]

GIT = "/usr/bin/git"
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_EXPANDED_BYTES = 1024 * 1024 * 1024
MAX_ENTRY_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 100_000
MAX_EVIDENCE_BYTES = 64 * 1024
MAX_RECEIPT_BYTES = 128 * 1024
MAX_CHECKPOINT_AGE_SECONDS = 900
MAX_CLOCK_SKEW_SECONDS = 60
SHA256 = re.compile(r"^[a-f0-9]{64}$")
GIT_OBJECT = re.compile(r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")


class InstallStop(Exception):
    def __init__(self, message: str, code: int = 78):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Pins:
    commit: str
    tree: str
    archive_sha256: str
    fault_after_writes: Optional[int] = None


@dataclass(frozen=True)
class Snapshot:
    logical_path: str
    physical_path: str
    data: bytes
    identity: Tuple[int, int, int, int, int, int, int, int, int]


@dataclass(frozen=True)
class ArchiveEntry:
    path: str
    kind: str
    mode: int
    size: int
    sha256: Optional[str] = None
    data: Optional[bytes] = None
    link_target: Optional[str] = None


@dataclass(frozen=True)
class ArchivePlan:
    entries: Dict[str, ArchiveEntry]


def stop(message: str, code: int = 78) -> None:
    raise InstallStop(message, code)


def exact_keys(value: object, keys: Iterable[str], label: str) -> Dict[str, object]:
    if not isinstance(value, dict) or set(value.keys()) != set(keys):
        stop(f"{label} is not one exact closed object.")
    return value


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def exact_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        stop(f"{label} is not one lowercase SHA-256 digest.")
    if value == "0" * 64:
        stop(f"{label} may not be the all-zero placeholder digest.")
    return value


def mode_bits(value: os.stat_result) -> int:
    return stat.S_IMODE(value.st_mode)


def stat_identity(value: os.stat_result) -> Tuple[int, int, int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_gid,
        mode_bits(value),
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def ensure_canonical_absolute(pathname: str, label: str) -> str:
    if (
        not isinstance(pathname, str)
        or not pathname.startswith("/")
        or os.path.normpath(pathname) != pathname
        or any(character in pathname for character in "\x00\r\n\t")
    ):
        stop(f"{label} is not one canonical absolute path.")
    return pathname


def initialize_test_root() -> Optional[str]:
    candidate = os.environ.get(TEST_ROOT_ENV)
    if candidate is None:
        return None

    if os.geteuid() == 0:
        stop("the non-root test seam is forbidden for effective UID 0.", 77)
    ensure_canonical_absolute(candidate, TEST_ROOT_ENV)
    try:
        metadata = os.lstat(candidate)
    except OSError as error:
        stop(f"test root is unavailable: {error}.", 77)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        stop("test root must be one real directory.", 77)
    if os.path.realpath(candidate) != candidate:
        stop("test root must be a canonical physical path.", 77)
    if metadata.st_uid != os.geteuid() or mode_bits(metadata) != 0o700:
        stop("test root must be owned by the caller with exact mode 0700.", 77)
    return candidate


TEST_ROOT: Optional[str] = None
OUTPUT_UID = os.geteuid()
OUTPUT_GID = os.getegid()


def physical(logical_path: str) -> str:
    ensure_canonical_absolute(logical_path, "fixed logical path")
    if TEST_ROOT is None:
        return logical_path
    result = os.path.join(TEST_ROOT, logical_path[1:])
    if os.path.commonpath([TEST_ROOT, result]) != TEST_ROOT:
        stop("test path escaped its private root.")
    return result


def assert_no_symlink_chain(pathname: str, label: str, require_final: bool = True) -> None:
    pathname = ensure_canonical_absolute(pathname, label)
    current = "/"
    components = [component for component in pathname.split("/") if component]
    for index, component in enumerate(components):
        current = os.path.join(current, component)
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            if require_final or index != len(components) - 1:
                stop(f"{label} is missing: {current}.")
            return
        except OSError as error:
            stop(f"cannot inspect {label}: {error}.")
        if stat.S_ISLNK(metadata.st_mode):
            stop(f"{label} traverses a symbolic link: {current}.")
        if index != len(components) - 1 and not stat.S_ISDIR(metadata.st_mode):
            stop(f"{label} has a non-directory ancestor: {current}.")


def assert_secure_directory(
    pathname: str,
    label: str,
    owner_uid: int,
    forbid_group_other_write: bool = True,
) -> os.stat_result:
    assert_no_symlink_chain(pathname, label)
    metadata = os.lstat(pathname)
    if not stat.S_ISDIR(metadata.st_mode):
        stop(f"{label} is not a directory.")
    if metadata.st_uid != owner_uid:
        stop(f"{label} has the wrong owner.")
    if forbid_group_other_write and mode_bits(metadata) & 0o022:
        stop(f"{label} is writable by group or other.")
    return metadata


def read_descriptor(fd: int, maximum: int, label: str) -> bytes:
    chunks: List[bytes] = []
    size = 0
    while True:
        chunk = os.read(fd, min(1024 * 1024, maximum + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > maximum:
            stop(f"{label} exceeds its fixed byte boundary.")
    return b"".join(chunks)


def snapshot_regular_file(
    logical_path: str,
    label: str,
    minimum: int,
    maximum: int,
    owner_uid: int,
) -> Snapshot:
    pathname = physical(logical_path)
    assert_no_symlink_chain(pathname, label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(pathname, flags)
    except OSError as error:
        stop(f"cannot open {label}: {error}.")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            stop(f"{label} must be one singly linked regular file.")
        if before.st_uid != owner_uid or mode_bits(before) & 0o022:
            stop(f"{label} owner or write permissions are unsafe.")
        if before.st_size < minimum or before.st_size > maximum:
            stop(f"{label} size is outside its fixed boundary.")
        data = read_descriptor(descriptor, maximum, label)
        after = os.fstat(descriptor)
        if stat_identity(before) != stat_identity(after) or len(data) != before.st_size:
            stop(f"{label} changed while being snapshotted.")
        return Snapshot(
            logical_path=logical_path,
            physical_path=pathname,
            data=data,
            identity=stat_identity(before),
        )
    finally:
        os.close(descriptor)


def revalidate_snapshot(snapshot: Snapshot, label: str, owner_uid: int) -> None:
    current = snapshot_regular_file(
        snapshot.logical_path,
        label,
        1,
        max(len(snapshot.data), 1),
        owner_uid,
    )
    if current.identity != snapshot.identity or current.data != snapshot.data:
        stop(f"{label} changed after validation.")


def json_no_duplicates(pairs: List[Tuple[str, object]]) -> Dict[str, object]:
    result: Dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            stop(f"JSON contains duplicate member {key!r}.")
        result[key] = value
    return result


def parse_json(snapshot: Snapshot, label: str) -> Dict[str, object]:
    try:
        text = snapshot.data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        stop(f"{label} is not strict UTF-8 JSON.")
    if text.startswith("\ufeff"):
        stop(f"{label} may not contain a UTF-8 BOM.")
    try:
        value = json.loads(text, object_pairs_hook=json_no_duplicates)
    except (json.JSONDecodeError, ValueError) as error:
        stop(f"{label} is not valid closed JSON: {error}.")
    if not isinstance(value, dict):
        stop(f"{label} must contain one JSON object.")
    return value


def exact_unix_seconds(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1_700_000_000:
        stop(f"{label} is not one bounded Unix timestamp.")
    return value


def validate_install_checkpoint(pins: Pins) -> Snapshot:
    """Validate a fresh safety checkpoint without treating it as authority.

    The explicit root invocation remains the sole install-only authority.  This
    root-owned document is only a last-responsible-moment preservation guard:
    it binds the real raw/off-host equality and restore/runtime evidence that
    the operator produced immediately before invoking this additive consumer.
    """

    snapshot = snapshot_regular_file(
        INSTALL_CHECKPOINT,
        "fresh PRE-DEPLOY install checkpoint",
        2,
        MAX_EVIDENCE_BYTES,
        OUTPUT_UID,
    )
    checkpoint = exact_keys(
        parse_json(snapshot, "fresh PRE-DEPLOY install checkpoint"),
        [
            "archiveListingSha256",
            "authoritative",
            "backupCapturedUnixSeconds",
            "backupVerifiedUnixSeconds",
            "candidateCommit",
            "candidateTree",
            "logicalEvidenceSha256",
            "offHostRawArchiveSha256",
            "rawArchiveSha256",
            "restoreEvidenceSha256",
            "restoreVerified",
            "runtimeInventorySha256",
            "runtimeRecovered",
            "runtimeVerifiedUnixSeconds",
            "sourceArchiveSha256",
        ],
        "fresh PRE-DEPLOY install checkpoint",
    )
    if checkpoint["authoritative"] is not False:
        stop("PRE-DEPLOY checkpoint must remain a non-authoritative safety precondition.")
    if checkpoint["restoreVerified"] is not True or checkpoint["runtimeRecovered"] is not True:
        stop("PRE-DEPLOY restore/runtime verification is incomplete.")
    if (
        checkpoint["candidateCommit"] != pins.commit
        or checkpoint["candidateTree"] != pins.tree
        or checkpoint["sourceArchiveSha256"] != pins.archive_sha256
    ):
        stop("PRE-DEPLOY checkpoint is bound to a different candidate.")
    raw_sha256 = exact_sha256(checkpoint["rawArchiveSha256"], "raw archive")
    off_host_sha256 = exact_sha256(
        checkpoint["offHostRawArchiveSha256"],
        "off-host raw archive",
    )
    if raw_sha256 != off_host_sha256:
        stop("PRE-DEPLOY raw and off-host archive digests differ.")
    for name in (
        "archiveListingSha256",
        "logicalEvidenceSha256",
        "restoreEvidenceSha256",
        "runtimeInventorySha256",
    ):
        exact_sha256(checkpoint[name], name)
    captured = exact_unix_seconds(
        checkpoint["backupCapturedUnixSeconds"],
        "backup capture time",
    )
    verified = exact_unix_seconds(
        checkpoint["backupVerifiedUnixSeconds"],
        "backup verification time",
    )
    runtime_verified = exact_unix_seconds(
        checkpoint["runtimeVerifiedUnixSeconds"],
        "runtime verification time",
    )
    now = int(time.time())
    if not captured <= verified <= runtime_verified <= now + MAX_CLOCK_SKEW_SECONDS:
        stop("PRE-DEPLOY checkpoint timestamps are unordered or in the future.")
    if (
        now - captured > MAX_CHECKPOINT_AGE_SECONDS
        or now - verified > MAX_CHECKPOINT_AGE_SECONDS
        or now - runtime_verified > MAX_CHECKPOINT_AGE_SECONDS
    ):
        stop("PRE-DEPLOY backup/runtime verification is stale.")
    return snapshot


def load_pins() -> Pins:
    if TEST_ROOT is None:
        return Pins(CANDIDATE_COMMIT, CANDIDATE_TREE, SOURCE_ARCHIVE_SHA256)
    pins_snapshot = snapshot_regular_file(
        TEST_PINS,
        "non-root test pins",
        2,
        MAX_EVIDENCE_BYTES,
        OUTPUT_UID,
    )
    value = exact_keys(
        parse_json(pins_snapshot, "non-root test pins"),
        ["candidateCommit", "candidateTree", "faultAfterWrites", "sourceArchiveSha256"],
        "non-root test pins",
    )
    commit = value["candidateCommit"]
    tree = value["candidateTree"]
    archive_sha256 = value["sourceArchiveSha256"]
    fault = value["faultAfterWrites"]
    if not isinstance(commit, str) or GIT_OBJECT.fullmatch(commit) is None:
        stop("non-root test commit pin is invalid.")
    if not isinstance(tree, str) or GIT_OBJECT.fullmatch(tree) is None:
        stop("non-root test tree pin is invalid.")
    exact_sha256(archive_sha256, "non-root test archive pin")
    if fault is not None and (
        isinstance(fault, bool) or not isinstance(fault, int) or fault < 0 or fault > 100_000
    ):
        stop("non-root test fault injection is invalid.")
    return Pins(commit, tree, archive_sha256, fault)


def fixed_git_environment() -> Dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "XDG_CONFIG_HOME": "/nonexistent",
    }


def run_git(staging: str, arguments: List[str], label: str) -> bytes:
    command = [
        GIT,
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.untrackedCache=false",
        "-c",
        f"safe.directory={staging}",
        "-C",
        staging,
        *arguments,
    ]
    try:
        result = subprocess.run(
            command,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=fixed_git_environment(),
            cwd="/",
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        stop(f"fixed Git {label} failed: {error}.")
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()[:512]
        stop(f"fixed Git {label} rejected the staging checkout: {detail}.")
    return result.stdout


def validate_staging_checkout(pins: Pins) -> Tuple[int, int, int, int, int]:
    staging = physical(STAGING_CHECKOUT)
    home = physical("/home/platform_infrastructure")
    home_metadata = assert_secure_directory(
        home, "staging account home", os.lstat(home).st_uid
    )
    staging_parent = physical("/home/platform_infrastructure/.v1-release-staging")
    assert_secure_directory(
        staging_parent, "staging parent", home_metadata.st_uid
    )
    metadata = assert_secure_directory(
        staging, "exact staging checkout", home_metadata.st_uid
    )
    top_level = run_git(staging, ["rev-parse", "--show-toplevel"], "top-level check")
    try:
        rendered_top_level = top_level.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError:
        stop("fixed Git returned a non-UTF-8 top-level path.")
    if rendered_top_level != staging:
        stop("staging checkout is not the exact fixed Git top level.")
    head = run_git(staging, ["rev-parse", "--verify", "HEAD^{commit}"], "HEAD check")
    tree = run_git(staging, ["rev-parse", "--verify", "HEAD^{tree}"], "tree check")
    if head.decode("ascii", errors="strict").strip() != pins.commit:
        stop("staging checkout HEAD differs from the pinned V1 candidate.")
    if tree.decode("ascii", errors="strict").strip() != pins.tree:
        stop("staging checkout tree differs from the pinned V1 candidate tree.")
    index = run_git(staging, ["ls-files", "--stage", "-z"], "index check")
    for record in index.split(b"\0"):
        if record.startswith(b"160000 "):
            stop("staging checkout contains a gitlink/submodule.")
    dirty = run_git(
        staging,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"],
        "cleanliness check",
    )
    if dirty:
        stop("staging checkout is dirty or contains untracked files.")
    after = os.lstat(staging)
    if (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        mode_bits(metadata),
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_uid,
        after.st_gid,
        mode_bits(after),
    ):
        stop("staging checkout identity changed during validation.")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        mode_bits(metadata),
    )


def safe_archive_path(raw_name: str) -> str:
    if (
        not isinstance(raw_name, str)
        or not raw_name
        or raw_name.startswith("/")
        or "\\" in raw_name
        or any(ord(character) < 32 or ord(character) == 127 for character in raw_name)
    ):
        stop("source archive contains an unsafe pathname.")
    name = raw_name[:-1] if raw_name.endswith("/") else raw_name
    path_value = PurePosixPath(name)
    parts = path_value.parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        stop("source archive pathname is not canonical.")
    if any(len(part.encode("utf-8")) > 255 for part in parts) or len(name.encode("utf-8")) > 4096:
        stop("source archive pathname exceeds the fixed boundary.")
    if parts[0] == ".git":
        stop("source archive may not materialize Git administrative state.")
    if str(path_value) != name:
        stop("source archive pathname is not normalized.")
    return name


def safe_link_target(entry_path: str, target: str) -> str:
    if (
        not isinstance(target, str)
        or not target
        or target.startswith("/")
        or "\\" in target
        or any(ord(character) < 32 or ord(character) == 127 for character in target)
    ):
        stop(f"source archive symlink {entry_path} has an unsafe target.")
    stack = list(PurePosixPath(entry_path).parts[:-1])
    for part in PurePosixPath(target).parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not stack:
                stop(f"source archive symlink {entry_path} escapes the release root.")
            stack.pop()
        else:
            stack.append(part)
    if not stack or stack[0] == ".git":
        stop(f"source archive symlink {entry_path} has a forbidden target.")
    return target


def build_archive_plan(archive_bytes: bytes) -> ArchivePlan:
    entries: Dict[str, ArchiveEntry] = {}
    explicit_paths = set()
    expanded = 0
    try:
        archive = tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:")
    except (tarfile.TarError, OSError) as error:
        stop(f"pinned source archive is not one uncompressed tar archive: {error}.")
    try:
        members = archive.getmembers()
        if not members or len(members) > MAX_ARCHIVE_ENTRIES:
            stop("source archive entry count is outside its fixed boundary.")
        for member in members:
            pathname = safe_archive_path(member.name)
            if pathname in explicit_paths:
                stop(f"source archive contains duplicate entry {pathname}.")
            explicit_paths.add(pathname)
            if member.isdir():
                entry = ArchiveEntry(pathname, "directory", 0o555, 0)
            elif member.isfile():
                if member.size < 0 or member.size > MAX_ENTRY_BYTES:
                    stop(f"source archive member {pathname} exceeds its byte boundary.")
                expanded += member.size
                if expanded > MAX_EXPANDED_BYTES:
                    stop("source archive expanded bytes exceed the fixed boundary.")
                source = archive.extractfile(member)
                if source is None:
                    stop(f"source archive member {pathname} cannot be read.")
                data = source.read(MAX_ENTRY_BYTES + 1)
                if len(data) != member.size:
                    stop(f"source archive member {pathname} is truncated or oversized.")
                normalized_mode = 0o555 if member.mode & 0o111 else 0o444
                entry = ArchiveEntry(
                    pathname,
                    "file",
                    normalized_mode,
                    len(data),
                    sha256=sha256_bytes(data),
                    data=data,
                )
            elif member.issym():
                target = safe_link_target(pathname, member.linkname)
                entry = ArchiveEntry(
                    pathname,
                    "symlink",
                    0,
                    len(target.encode("utf-8")),
                    link_target=target,
                )
            else:
                stop(f"source archive member {pathname} has a forbidden filesystem type.")
            existing = entries.get(pathname)
            if existing is not None and existing.kind != "directory":
                stop(f"source archive member {pathname} conflicts with an ancestor.")
            entries[pathname] = entry

            parts = PurePosixPath(pathname).parts
            for length in range(1, len(parts)):
                parent = "/".join(parts[:length])
                parent_entry = entries.get(parent)
                if parent_entry is None:
                    entries[parent] = ArchiveEntry(parent, "directory", 0o555, 0)
                elif parent_entry.kind != "directory":
                    stop(f"source archive member {pathname} traverses non-directory {parent}.")
    finally:
        archive.close()
    return ArchivePlan(entries)


def secure_existing_output_parent(pathname: str, label: str) -> None:
    current = pathname
    missing: List[str] = []
    while True:
        try:
            metadata = os.lstat(current)
            break
        except FileNotFoundError:
            missing.append(current)
            parent = os.path.dirname(current)
            if parent == current:
                stop(f"{label} has no existing parent.")
            current = parent
    assert_no_symlink_chain(current, f"existing ancestor for {label}")
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != OUTPUT_UID:
        stop(f"existing ancestor for {label} has the wrong type or owner.")
    if mode_bits(metadata) & 0o022:
        stop(f"existing ancestor for {label} is writable by group or other.")
    if TEST_ROOT is None and current not in ("/srv", "/var/lib/platform-infrastructure/v1"):
        # Existing deeper ancestors are fine; this bounds where missing output
        # directories may start without creating arbitrary system paths.
        if not (
            current.startswith("/srv/platform-infrastructure")
            or current.startswith("/var/lib/platform-infrastructure/v1")
        ):
            stop(f"{label} would create directories outside the fixed install roots.")


def ensure_directory(pathname: str, mode: int, created: List[Tuple[str, int, int]]) -> None:
    try:
        metadata = os.lstat(pathname)
    except FileNotFoundError:
        parent = os.path.dirname(pathname)
        assert_secure_directory(parent, "output parent", OUTPUT_UID)
        try:
            os.mkdir(pathname, mode)
            os.chown(pathname, OUTPUT_UID, OUTPUT_GID)
            os.chmod(pathname, mode)
        except OSError as error:
            stop(f"cannot create fixed install directory {pathname}: {error}.")
        metadata = os.lstat(pathname)
        created.append((pathname, metadata.st_dev, metadata.st_ino))
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        stop(f"fixed install directory {pathname} has the wrong type.")
    if metadata.st_uid != OUTPUT_UID or mode_bits(metadata) != mode:
        stop(f"fixed install directory {pathname} has the wrong owner or mode.")


def fsync_directory(pathname: str) -> None:
    descriptor = os.open(
        pathname,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def remove_private_tree(pathname: str) -> None:
    try:
        metadata = os.lstat(pathname)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        stop("refusing to clean an unexpected install temporary path.")
    for entry in os.scandir(pathname):
        child_metadata = entry.stat(follow_symlinks=False)
        if stat.S_ISDIR(child_metadata.st_mode) and not stat.S_ISLNK(child_metadata.st_mode):
            os.chmod(entry.path, 0o700)
            remove_private_tree(entry.path)
        else:
            os.unlink(entry.path)
    os.rmdir(pathname)


def rollback_created_directories(created: List[Tuple[str, int, int]]) -> None:
    for pathname, device, inode in reversed(created):
        try:
            metadata = os.lstat(pathname)
        except FileNotFoundError:
            continue
        if (
            stat.S_ISDIR(metadata.st_mode)
            and metadata.st_dev == device
            and metadata.st_ino == inode
        ):
            try:
                os.rmdir(pathname)
            except OSError:
                pass


def maybe_inject_fault(pins: Pins, writes: int) -> None:
    if TEST_ROOT is not None and pins.fault_after_writes is not None and writes >= pins.fault_after_writes:
        stop("non-root test fault injected after bounded install writes.")


def materialize_archive(plan: ArchivePlan, pins: Pins, releases_parent: str) -> str:
    temporary = os.path.join(
        releases_parent,
        f".v1-install-{os.getpid()}-{secrets.token_hex(12)}",
    )
    os.mkdir(temporary, 0o700)
    os.chown(temporary, OUTPUT_UID, OUTPUT_GID)
    writes = 0
    try:
        maybe_inject_fault(pins, writes)
        directories = sorted(
            (entry for entry in plan.entries.values() if entry.kind == "directory"),
            key=lambda entry: (len(PurePosixPath(entry.path).parts), entry.path),
        )
        for entry in directories:
            pathname = os.path.join(temporary, *PurePosixPath(entry.path).parts)
            os.mkdir(pathname, 0o700)
            os.chown(pathname, OUTPUT_UID, OUTPUT_GID)

        for entry in sorted(plan.entries.values(), key=lambda value: value.path):
            pathname = os.path.join(temporary, *PurePosixPath(entry.path).parts)
            if entry.kind == "file":
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                descriptor = os.open(pathname, flags, 0o600)
                try:
                    data = entry.data or b""
                    offset = 0
                    while offset < len(data):
                        offset += os.write(descriptor, data[offset:])
                    os.fchown(descriptor, OUTPUT_UID, OUTPUT_GID)
                    os.fchmod(descriptor, entry.mode)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                writes += 1
                maybe_inject_fault(pins, writes)
            elif entry.kind == "symlink":
                os.symlink(entry.link_target or "", pathname)
                os.chown(pathname, OUTPUT_UID, OUTPUT_GID, follow_symlinks=False)
                writes += 1
                maybe_inject_fault(pins, writes)

        for entry in reversed(directories):
            pathname = os.path.join(temporary, *PurePosixPath(entry.path).parts)
            os.chmod(pathname, entry.mode)
            fsync_directory(pathname)
        os.chmod(temporary, 0o555)
        fsync_directory(temporary)
        fsync_directory(releases_parent)
        return temporary
    except BaseException:
        try:
            os.chmod(temporary, 0o700)
            remove_private_tree(temporary)
        except BaseException:
            pass
        raise


def rename_no_replace(source: str, destination: str) -> None:
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is not None:
            renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
            renameat2.restype = ctypes.c_int
            result = renameat2(
                -100,
                os.fsencode(source),
                -100,
                os.fsencode(destination),
                1,
            )
            if result == 0:
                return
            error_number = ctypes.get_errno()
            if error_number == errno.EEXIST:
                raise FileExistsError(error_number, os.strerror(error_number), destination)
            if error_number not in (errno.ENOSYS, errno.EINVAL):
                raise OSError(error_number, os.strerror(error_number), destination)
    if os.path.lexists(destination):
        raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), destination)
    os.rename(source, destination)


def snapshot_installed_file(pathname: str, expected: ArchiveEntry) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(pathname, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != OUTPUT_UID
            or before.st_gid != OUTPUT_GID
            or mode_bits(before) != expected.mode
            or before.st_size != expected.size
        ):
            stop(f"installed release file metadata differs: {expected.path}.")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if stat_identity(before) != stat_identity(after) or digest.hexdigest() != expected.sha256:
            stop(f"installed release file bytes differ: {expected.path}.")
    finally:
        os.close(descriptor)


def verify_installed_release(release: str, plan: ArchivePlan) -> None:
    metadata = os.lstat(release)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != OUTPUT_UID
        or metadata.st_gid != OUTPUT_GID
        or mode_bits(metadata) != 0o555
    ):
        stop("final release root has the wrong identity or metadata.")

    observed = set()
    pending = [(release, "")]
    while pending:
        directory, relative_parent = pending.pop()
        for child in os.scandir(directory):
            relative = child.name if not relative_parent else relative_parent + "/" + child.name
            observed.add(relative)
            expected = plan.entries.get(relative)
            if expected is None:
                stop(f"final release contains unexpected path {relative}.")
            child_metadata = child.stat(follow_symlinks=False)
            if expected.kind == "directory":
                if (
                    stat.S_ISLNK(child_metadata.st_mode)
                    or not stat.S_ISDIR(child_metadata.st_mode)
                    or child_metadata.st_uid != OUTPUT_UID
                    or child_metadata.st_gid != OUTPUT_GID
                    or mode_bits(child_metadata) != expected.mode
                ):
                    stop(f"installed release directory differs: {relative}.")
                pending.append((child.path, relative))
            elif expected.kind == "file":
                snapshot_installed_file(child.path, expected)
            elif expected.kind == "symlink":
                if (
                    not stat.S_ISLNK(child_metadata.st_mode)
                    or child_metadata.st_uid != OUTPUT_UID
                    or child_metadata.st_gid != OUTPUT_GID
                    or child_metadata.st_nlink != 1
                    or os.readlink(child.path) != expected.link_target
                ):
                    stop(f"installed release symlink differs: {relative}.")
            else:
                stop(f"internal archive plan type is invalid: {relative}.")
    if observed != set(plan.entries.keys()):
        stop("final release is missing one or more pinned archive entries.")


def acquire_lock() -> int:
    pathname = physical(LOCK_PATH)
    parent = os.path.dirname(pathname)
    assert_no_symlink_chain(parent, "install lock parent")
    parent_metadata = os.lstat(parent)
    if not stat.S_ISDIR(parent_metadata.st_mode) or parent_metadata.st_uid != OUTPUT_UID:
        stop("install lock parent has the wrong type or owner.")
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(pathname, flags, 0o600)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != OUTPUT_UID
        or mode_bits(metadata) != 0o600
    ):
        os.close(descriptor)
        stop("install lock file has the wrong identity or metadata.")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(descriptor)
        stop("another V1 install-only transaction is active.", 75)
    return descriptor


def validate_existing_receipt(
    snapshot: Snapshot,
    pins: Pins,
) -> Dict[str, object]:
    receipt = exact_keys(
        parse_json(snapshot, "install-only receipt"),
        [
            "activationAuthorized",
            "authorizationSource",
            "backupEvidenceAuthoritative",
            "candidateCommit",
            "candidateTree",
            "dataMutation",
            "dockerMutation",
            "readyButDisabled",
            "releaseRoot",
            "schema",
            "sourceArchiveSha256",
            "status",
        ],
        "install-only receipt",
    )
    if receipt["schema"] != RECEIPT_SCHEMA or receipt["status"] not in (
        "INSTALL_ONLY_COMPLETE",
        "ALREADY_INSTALLED",
    ):
        stop("existing install-only receipt status/schema is invalid.")
    if (
        receipt["candidateCommit"] != pins.commit
        or receipt["candidateTree"] != pins.tree
        or receipt["sourceArchiveSha256"] != pins.archive_sha256
    ):
        stop("existing install-only receipt candidate binding differs.")
    if (
        receipt["releaseRoot"] != FINAL_RELEASE
        or receipt["authorizationSource"] != "ROOT_OPERATOR_EXPLICIT_INSTALL_ONLY"
        or receipt["backupEvidenceAuthoritative"] is not False
        or receipt["activationAuthorized"] is not False
        or receipt["dockerMutation"] is not False
        or receipt["dataMutation"] is not False
        or receipt["readyButDisabled"] != READY_BUT_DISABLED
    ):
        stop("existing install-only receipt differs from the fixed authority boundary.")
    return receipt


def write_receipt(
    receipt: Dict[str, object],
    pins: Pins,
    created_directories: List[Tuple[str, int, int]],
) -> Tuple[Dict[str, object], bool]:
    receipt_path = physical(INSTALL_RECEIPT)
    receipt_parent = os.path.dirname(receipt_path)
    ensure_directory(receipt_parent, 0o755, created_directories)
    if os.path.lexists(receipt_path):
        existing = snapshot_regular_file(
            INSTALL_RECEIPT,
            "install-only receipt",
            2,
            MAX_RECEIPT_BYTES,
            OUTPUT_UID,
        )
        return validate_existing_receipt(existing, pins), False

    data = (canonical_json(receipt) + "\n").encode("utf-8")
    temporary = os.path.join(
        receipt_parent,
        f".install-receipt-{os.getpid()}-{secrets.token_hex(12)}",
    )
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(temporary, flags, 0o600)
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fchown(descriptor, OUTPUT_UID, OUTPUT_GID)
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        rename_no_replace(temporary, receipt_path)
    except FileExistsError:
        os.unlink(temporary)
        existing = snapshot_regular_file(
            INSTALL_RECEIPT,
            "install-only receipt",
            2,
            MAX_RECEIPT_BYTES,
            OUTPUT_UID,
        )
        return validate_existing_receipt(existing, pins), False
    fsync_directory(receipt_parent)
    return receipt, True


def build_receipt(
    status: str,
    pins: Pins,
) -> Dict[str, object]:
    return {
        "activationAuthorized": False,
        "authorizationSource": "ROOT_OPERATOR_EXPLICIT_INSTALL_ONLY",
        "backupEvidenceAuthoritative": False,
        "candidateCommit": pins.commit,
        "candidateTree": pins.tree,
        "dataMutation": False,
        "dockerMutation": False,
        "readyButDisabled": READY_BUT_DISABLED,
        "releaseRoot": FINAL_RELEASE,
        "schema": RECEIPT_SCHEMA,
        "sourceArchiveSha256": pins.archive_sha256,
        "status": status,
    }


def install() -> Dict[str, object]:
    if TEST_ROOT is None and os.geteuid() != 0:
        stop("production install requires effective UID 0.", 77)
    pins = load_pins()
    checkpoint_snapshot = validate_install_checkpoint(pins)
    lock_descriptor = acquire_lock()
    created_directories: List[Tuple[str, int, int]] = []
    temporary: Optional[str] = None
    try:
        staging_identity = validate_staging_checkout(pins)

        archive_parent = physical(
            "/var/lib/platform-infrastructure/v1/predeploy/current"
        )
        assert_secure_directory(
            archive_parent,
            "fixed source archive directory",
            OUTPUT_UID,
        )
        archive_snapshot = snapshot_regular_file(
            SOURCE_ARCHIVE,
            "exact source archive",
            1024,
            MAX_ARCHIVE_BYTES,
            OUTPUT_UID,
        )
        if sha256_bytes(archive_snapshot.data) != pins.archive_sha256:
            stop("source archive bytes differ from the hardcoded V1 archive digest.")
        plan = build_archive_plan(archive_snapshot.data)

        final_release = physical(FINAL_RELEASE)
        releases_parent = os.path.dirname(final_release)
        secure_existing_output_parent(releases_parent, "release store")
        secure_existing_output_parent(
            os.path.dirname(physical(INSTALL_RECEIPT)),
            "install receipt store",
        )

        already_installed = os.path.lexists(final_release)
        if already_installed:
            assert_no_symlink_chain(final_release, "final release")
            verify_installed_release(final_release, plan)

        # Last responsible moment: no install paths are created before all
        # archive structure and checkout identity are checked again.
        revalidate_snapshot(archive_snapshot, "exact source archive", OUTPUT_UID)
        revalidate_snapshot(
            checkpoint_snapshot,
            "fresh PRE-DEPLOY install checkpoint",
            OUTPUT_UID,
        )
        validate_install_checkpoint(pins)
        if validate_staging_checkout(pins) != staging_identity:
            stop("staging checkout identity changed before install.")

        status = "ALREADY_INSTALLED"
        if not already_installed:
            srv_root = physical("/srv")
            assert_secure_directory(srv_root, "release store root", OUTPUT_UID)
            ensure_directory(
                physical("/srv/platform-infrastructure"),
                0o755,
                created_directories,
            )
            ensure_directory(releases_parent, 0o755, created_directories)
            temporary = materialize_archive(plan, pins, releases_parent)
            try:
                rename_no_replace(temporary, final_release)
                temporary = None
            except FileExistsError:
                os.chmod(temporary, 0o700)
                remove_private_tree(temporary)
                temporary = None
                verify_installed_release(final_release, plan)
            fsync_directory(releases_parent)
            verify_installed_release(final_release, plan)
            status = "INSTALL_ONLY_COMPLETE"

        receipt = build_receipt(status, pins)
        receipt, receipt_created = write_receipt(
            receipt,
            pins,
            created_directories,
        )
        if not receipt_created and status == "ALREADY_INSTALLED" and receipt["status"] == "INSTALL_ONLY_COMPLETE":
            receipt = {**receipt, "status": "ALREADY_INSTALLED"}
        return receipt
    except BaseException:
        if temporary is not None and os.path.lexists(temporary):
            try:
                os.chmod(temporary, 0o700)
                remove_private_tree(temporary)
            except BaseException:
                pass
        rollback_created_directories(created_directories)
        raise
    finally:
        os.close(lock_descriptor)


def main(argv: List[str]) -> int:
    if argv != ["install"]:
        sys.stderr.write(
            "v1-brownfield-install-consumer: usage: "
            "platform-v1-brownfield-install-consumer install\n"
        )
        return 64
    try:
        global TEST_ROOT
        TEST_ROOT = initialize_test_root()
        receipt = install()
        sys.stdout.write(canonical_json(receipt) + "\n")
    except InstallStop as error:
        sys.stderr.write(f"v1-brownfield-install-consumer: STOP: {error}\n")
        return error.code
    except BrokenPipeError:
        return 74
    except BaseException as error:
        sys.stderr.write(
            "v1-brownfield-install-consumer: STOP: unexpected bounded install failure: "
            f"{error}\n"
        )
        return 78
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
