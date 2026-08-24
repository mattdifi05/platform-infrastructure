#!/usr/bin/python3 -I
"""Install and attest the one host Node.js runtime required by V1.

This is a deliberately closed, one-operation control-plane helper.  It is
executed from the immutable exact-release tree after that tree has been
installed and before the reconciler's ``prepare`` operation.  The caller
cannot select a package, version, repository, path, or command.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from typing import Dict, Iterable, Optional, Tuple


SCHEMA = "platform.v1-node-runtime-prerequisite-receipt/v1"
INSTALL_RECEIPT_SCHEMA = "platform.v1-brownfield-install-receipt/v1"
STATUS = "NODE_RUNTIME_READY"
RELEASES = "/srv/platform-infrastructure/releases"
SOURCE_ARCHIVE = "/var/lib/platform-infrastructure/v1/predeploy/current/exact-source-archive.tar"
RECEIPT = "/var/lib/platform-infrastructure/v1/local-private/node-runtime-prerequisite-receipt.json"
SCRIPT_RELATIVE = "scripts/v1-node-runtime-prerequisite.py"
PACKAGE_NAME = "nodejs"
PACKAGE_VERSION = "22.22.1+dfsg+~cs22.19.15-1ubuntu1"
PACKAGE_ARCHITECTURE = "amd64"
RUNTIME_VERSION = "v22.22.1"
NODE = "/usr/bin/node"
APT_CACHE = "/usr/bin/apt-cache"
APT_GET = "/usr/bin/apt-get"
DPKG_QUERY = "/usr/bin/dpkg-query"
TEST_ROOT_ENV = "PLATFORM_V1_NODE_RUNTIME_TEST_ROOT"
TEST_APT_CACHE_ENV = "PLATFORM_V1_NODE_RUNTIME_TEST_APT_CACHE"
TEST_APT_GET_ENV = "PLATFORM_V1_NODE_RUNTIME_TEST_APT_GET"
TEST_DPKG_QUERY_ENV = "PLATFORM_V1_NODE_RUNTIME_TEST_DPKG_QUERY"
TEST_NODE_ENV = "PLATFORM_V1_NODE_RUNTIME_TEST_NODE"
MAX_JSON = 128 * 1024
MAX_ARCHIVE = 1024 * 1024 * 1024
MAX_BINARY = 256 * 1024 * 1024
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
GIT_OBJECT_RE = re.compile(r"^[a-f0-9]{40}$")
RELEASE_ID_RE = re.compile(r"^([a-f0-9]{40})-([a-f0-9]{64})$")
RECEIPT_KEYS = (
    "activationAuthorized", "binaryPath", "binarySha256", "candidateCommit", "candidateTree",
    "dataMutation", "dockerMutation", "documentId", "helperSha256", "hostControlMutation",
    "packageArchitecture", "packageName", "packageSource", "packageVersion", "receiptPath",
    "releaseRoot", "runtimeVersion", "schema", "sourceArchiveSha256", "status", "workloadMutation",
)


class Stop(Exception):
    def __init__(self, message: str, code: int = 78):
        super().__init__(message)
        self.code = code


TEST_ROOT: Optional[str] = None


def stop(message: str, code: int = 78) -> None:
    raise Stop(message, code)


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def exact_keys(value: object, keys: Iterable[str], label: str) -> Dict[str, object]:
    if not isinstance(value, dict) or set(value) != set(keys):
        stop(f"{label} is not one exact closed object.")
    return value


def physical(logical: str) -> str:
    if not logical.startswith("/") or os.path.normpath(logical) != logical:
        stop("fixed logical path is invalid.")
    if TEST_ROOT is None:
        return logical
    pathname = os.path.join(TEST_ROOT, logical[1:])
    if os.path.commonpath((TEST_ROOT, pathname)) != TEST_ROOT:
        stop("test path escaped its fixed root.")
    return pathname


def initialize_test_root() -> Optional[str]:
    raw = os.environ.get(TEST_ROOT_ENV)
    if raw is None:
        return None
    if os.geteuid() == 0:
        stop("the Node runtime test-root seam is forbidden to root.", 77)
    pathname = os.path.realpath(raw)
    metadata = os.lstat(pathname)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.geteuid()
    ):
        stop("the Node runtime test root has an invalid identity or mode.", 77)
    return pathname


def expected_uid() -> int:
    return os.geteuid() if TEST_ROOT is not None else 0


def stable_file(
    logical: str,
    label: str,
    maximum: int,
    modes: Tuple[int, ...] = (),
    owners: Optional[Tuple[int, ...]] = None,
) -> bytes:
    pathname = physical(logical)
    try:
        before = os.lstat(pathname)
    except OSError as error:
        stop(f"{label} is unavailable: {error.strerror}.")
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid not in (owners if owners is not None else (expected_uid(),))
        or before.st_nlink != 1
        or before.st_size < 1
        or before.st_size > maximum
        or (modes and stat.S_IMODE(before.st_mode) not in modes)
    ):
        stop(f"{label} has an invalid owner, type, mode, link count, or size.")
    descriptor = os.open(pathname, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        opened = os.fstat(descriptor)
        chunks = []
        total = 0
        while total <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        os.close(descriptor)
    after = os.lstat(pathname)
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_uid, item.st_gid, item.st_mode,
        item.st_nlink, item.st_size, item.st_mtime_ns,
    )
    if identity(before) != identity(opened) or identity(opened) != identity(after) or total > maximum:
        stop(f"{label} changed during stable capture or exceeded its boundary.")
    return b"".join(chunks)


def strict_json(
    logical: str, label: str, owners: Optional[Tuple[int, ...]] = None
) -> Tuple[Dict[str, object], bytes]:
    raw = stable_file(logical, label, MAX_JSON, (0o400, 0o444), owners)
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        stop(f"{label} is not strict JSON.")
    if canonical(value) != raw:
        stop(f"{label} is not canonical JSON.")
    if not isinstance(value, dict):
        stop(f"{label} is not one JSON object.")
    return value, raw


def command_path(production: str, test_variable: str, label: str) -> str:
    pathname = production if TEST_ROOT is None else os.environ.get(test_variable, "")
    if not pathname or not os.path.isabs(pathname):
        stop(f"fixed {label} command is unavailable.", 77)
    if TEST_ROOT is not None and os.path.commonpath((TEST_ROOT, os.path.realpath(pathname))) != TEST_ROOT:
        stop(f"test {label} command escaped its private root.", 77)
    try:
        metadata = os.stat(pathname, follow_symlinks=False)
    except OSError as error:
        stop(f"fixed {label} command is unavailable: {error.strerror}.")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != expected_uid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not stat.S_IMODE(metadata.st_mode) & 0o100
    ):
        stop(f"fixed {label} command identity or mode is invalid.")
    return pathname


def run(command: list[str], label: str, timeout: int = 300) -> subprocess.CompletedProcess[bytes]:
    environment = {
        "DEBIAN_FRONTEND": "noninteractive",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    }
    try:
        result = subprocess.run(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd="/", env=environment, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        stop(f"fixed {label} command failed: {error}.")
    if len(result.stdout) > 4 * 1024 * 1024 or len(result.stderr) > 4 * 1024 * 1024:
        stop(f"fixed {label} command output exceeded its boundary.")
    return result


def installed_package() -> Optional[Dict[str, str]]:
    dpkg = command_path(DPKG_QUERY, TEST_DPKG_QUERY_ENV, "dpkg-query")
    result = run(
        [dpkg, "-W", "-f=${Package}\\t${Status}\\t${Version}\\t${Architecture}\\n", PACKAGE_NAME],
        "Node package query",
        60,
    )
    if result.returncode != 0:
        return None
    try:
        line = result.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        stop("installed Node package metadata is not UTF-8.")
    fields = line.rstrip("\n").split("\t")
    if len(fields) != 4 or "\n" in line.rstrip("\n") or fields[0] != PACKAGE_NAME or fields[1] != "install ok installed":
        stop("installed Node package metadata is non-canonical.")
    return {"architecture": fields[3], "version": fields[2]}


def package_available() -> None:
    apt_cache = command_path(APT_CACHE, TEST_APT_CACHE_ENV, "apt-cache")
    result = run([apt_cache, "show", f"{PACKAGE_NAME}={PACKAGE_VERSION}"], "Node package availability", 60)
    if result.returncode != 0:
        stop("the exact Node package pin is unavailable from configured Ubuntu package sources.")
    try:
        text = result.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        stop("Node package source metadata is not UTF-8.")
    paragraphs = []
    for raw in text.strip().split("\n\n"):
        fields: Dict[str, str] = {}
        for line in raw.splitlines():
            if not line or line[0].isspace() or ": " not in line:
                continue
            name, value = line.split(": ", 1)
            if name in fields:
                stop("Node package source metadata contains duplicate fields.")
            fields[name] = value
        paragraphs.append(fields)
    matches = [
        item for item in paragraphs
        if item.get("Package") == PACKAGE_NAME
        and item.get("Version") == PACKAGE_VERSION
        and item.get("Architecture") == PACKAGE_ARCHITECTURE
    ]
    if len(matches) != 1:
        stop("configured Ubuntu package sources do not expose one exact Node package pin.")


def install_package() -> None:
    apt_get = command_path(APT_GET, TEST_APT_GET_ENV, "apt-get")
    result = run([
        apt_get,
        "-y",
        "--no-install-recommends",
        "--option",
        "Dpkg::Options::=--force-confold",
        "install",
        f"{PACKAGE_NAME}={PACKAGE_VERSION}",
    ], "exact Node package install", 900)
    if result.returncode != 0:
        stop("the exact Node package installation failed; package output was suppressed.")


def validate_runtime() -> Dict[str, str]:
    package = installed_package()
    if package != {"architecture": PACKAGE_ARCHITECTURE, "version": PACKAGE_VERSION}:
        stop("the installed Node package differs from the exact V1 package/version/architecture pin.")
    node = command_path(NODE, TEST_NODE_ENV, "Node runtime")
    logical_node = NODE if TEST_ROOT is None else "/usr/bin/node"
    before = stable_file(logical_node, "installed Node runtime", MAX_BINARY)
    result = run([node, "--version"], "Node runtime version", 30)
    if result.returncode != 0 or result.stdout != (RUNTIME_VERSION + "\n").encode() or result.stderr:
        stop("the installed Node runtime did not return the exact required version.")
    after = stable_file(logical_node, "revalidated installed Node runtime", MAX_BINARY)
    if before != after:
        stop("the installed Node runtime changed during verification.")
    return {
        "binaryPath": NODE,
        "binarySha256": digest(before),
        "packageArchitecture": PACKAGE_ARCHITECTURE,
        "packageName": PACKAGE_NAME,
        "packageSource": "UBUNTU_APT_EXACT_VERSION",
        "packageVersion": PACKAGE_VERSION,
        "runtimeVersion": RUNTIME_VERSION,
    }


def validate_release_identity() -> Dict[str, object]:
    invoked = os.path.realpath(sys.argv[0])
    if TEST_ROOT is None:
        logical = invoked
    else:
        prefix = TEST_ROOT + os.sep
        if not invoked.startswith(prefix):
            stop("test helper invocation escaped its exact-release root.")
        logical = "/" + invoked[len(prefix):]
    expected_suffix = "/" + SCRIPT_RELATIVE
    if not logical.startswith(RELEASES + "/") or not logical.endswith(expected_suffix):
        stop("Node runtime helper was not invoked from an immutable exact-release path.")
    release = logical[:-len(expected_suffix)]
    if os.path.realpath(physical(logical)) != physical(logical) or os.path.realpath(physical(release)) != physical(release):
        stop("Node runtime helper exact-release path traverses a symbolic ancestor.")
    match = RELEASE_ID_RE.fullmatch(os.path.basename(release))
    if match is None or os.path.dirname(release) != RELEASES:
        stop("Node runtime helper release identity is invalid.")
    commit, archive_sha = match.groups()
    helper = stable_file(logical, "exact-release Node runtime helper", 2 * 1024 * 1024, (0o444, 0o555))
    install_receipt_path = f"/var/lib/platform-infrastructure/v1/install-receipts/{commit}-{archive_sha}.json"
    install, _ = strict_json(install_receipt_path, "exact-release install receipt")
    exact_keys(install, (
        "activationAuthorized", "authorizationSource", "backupEvidenceAuthoritative", "candidateCommit",
        "candidateTree", "dataMutation", "dockerMutation", "readyButDisabled", "releaseRoot", "schema",
        "sourceArchiveSha256", "status",
    ), "exact-release install receipt")
    tree = install.get("candidateTree")
    if (
        install.get("schema") != INSTALL_RECEIPT_SCHEMA
        or install.get("status") not in ("INSTALL_ONLY_COMPLETE", "ALREADY_INSTALLED")
        or install.get("activationAuthorized") is not False
        or install.get("backupEvidenceAuthoritative") is not False
        or install.get("dataMutation") is not False
        or install.get("dockerMutation") is not False
        or install.get("authorizationSource") != "ROOT_OPERATOR_EXPLICIT_INSTALL_ONLY"
        or install.get("candidateCommit") != commit
        or not isinstance(tree, str) or GIT_OBJECT_RE.fullmatch(tree) is None
        or install.get("sourceArchiveSha256") != archive_sha
        or install.get("releaseRoot") != release
    ):
        stop("exact-release install receipt does not authorize this fixed prerequisite helper.")
    archive = stable_file(SOURCE_ARCHIVE, "exact source archive", MAX_ARCHIVE, (0o400, 0o444))
    if digest(archive) != archive_sha:
        stop("exact source archive differs from the immutable release/install binding.")
    return {
        "candidateCommit": commit,
        "candidateTree": tree,
        "helperSha256": digest(helper),
        "releaseRoot": release,
        "sourceArchiveSha256": archive_sha,
    }


def fsync_directory(pathname: str) -> None:
    descriptor = os.open(pathname, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_receipt(value: Dict[str, object]) -> bytes:
    data = canonical(value)
    pathname = physical(RECEIPT)
    parent = os.path.dirname(pathname)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    metadata = os.lstat(parent)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        stop("Node runtime receipt directory identity or mode is invalid.")
    descriptor, temporary = tempfile.mkstemp(prefix=".node-runtime-receipt.", dir=parent)
    try:
        os.fchmod(descriptor, 0o444)
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, pathname)
        fsync_directory(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if os.path.exists(temporary):
            os.unlink(temporary)
    observed = stable_file(RECEIPT, "Node runtime prerequisite receipt", MAX_JSON, (0o444,))
    if observed != data:
        stop("Node runtime prerequisite receipt did not persist byte-exactly.")
    return observed


def existing_receipt() -> Optional[Dict[str, object]]:
    pathname = physical(RECEIPT)
    if not os.path.lexists(pathname):
        return None
    value, _ = strict_json(RECEIPT, "existing Node runtime prerequisite receipt")
    exact_keys(value, RECEIPT_KEYS, "existing Node runtime prerequisite receipt")
    base = dict(value)
    document_id = base.pop("documentId", None)
    commit = value.get("candidateCommit")
    tree = value.get("candidateTree")
    archive_sha = value.get("sourceArchiveSha256")
    binary_sha = value.get("binarySha256")
    helper_sha = value.get("helperSha256")
    if (
        not isinstance(document_id, str) or SHA256_RE.fullmatch(document_id) is None
        or document_id != digest(json.dumps(base, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode())
        or value.get("schema") != SCHEMA
        or value.get("status") != STATUS
        or not isinstance(commit, str) or GIT_OBJECT_RE.fullmatch(commit) is None
        or not isinstance(tree, str) or GIT_OBJECT_RE.fullmatch(tree) is None
        or not isinstance(archive_sha, str) or SHA256_RE.fullmatch(archive_sha) is None
        or not isinstance(binary_sha, str) or SHA256_RE.fullmatch(binary_sha) is None
        or not isinstance(helper_sha, str) or SHA256_RE.fullmatch(helper_sha) is None
        or value.get("releaseRoot") != f"{RELEASES}/{commit}-{archive_sha}"
        or value.get("receiptPath") != RECEIPT
        or value.get("packageName") != PACKAGE_NAME
        or value.get("packageVersion") != PACKAGE_VERSION
        or value.get("packageArchitecture") != PACKAGE_ARCHITECTURE
        or value.get("packageSource") != "UBUNTU_APT_EXACT_VERSION"
        or value.get("runtimeVersion") != RUNTIME_VERSION
        or value.get("binaryPath") != NODE
        or not isinstance(value.get("hostControlMutation"), bool)
        or value.get("activationAuthorized") is not False
        or value.get("dataMutation") is not False
        or value.get("dockerMutation") is not False
        or value.get("workloadMutation") is not False
    ):
        stop("existing Node runtime prerequisite receipt is invalid.")
    return value


def apply() -> Dict[str, object]:
    if TEST_ROOT is None and os.geteuid() != 0:
        stop("production Node runtime prerequisite requires effective UID 0.", 77)
    release = validate_release_identity()
    previous = existing_receipt()
    current = installed_package()
    installed = False
    if current is None:
        package_available()
        install_package()
        installed = True
    elif current != {"architecture": PACKAGE_ARCHITECTURE, "version": PACKAGE_VERSION}:
        stop("a foreign Node package is already installed; refusing an implicit upgrade or downgrade.")
    runtime = validate_runtime()
    base: Dict[str, object] = {
        "activationAuthorized": False,
        **release,
        "dataMutation": False,
        "dockerMutation": False,
        "hostControlMutation": installed,
        **runtime,
        "receiptPath": RECEIPT,
        "schema": SCHEMA,
        "status": STATUS,
        "workloadMutation": False,
    }
    if previous is not None:
        same_release = (
            previous.get("candidateCommit") == release["candidateCommit"]
            and previous.get("sourceArchiveSha256") == release["sourceArchiveSha256"]
            and previous.get("releaseRoot") == release["releaseRoot"]
        )
        if same_release:
            expected_previous = {**base, "hostControlMutation": previous["hostControlMutation"]}
            previous_base = dict(previous)
            previous_base.pop("documentId")
            if previous_base != expected_previous:
                stop("existing Node runtime prerequisite receipt conflicts with this exact release/runtime.")
            if not installed:
                return previous
    receipt = {**base, "documentId": digest(json.dumps(base, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode())}
    write_receipt(receipt)
    return receipt


def main() -> None:
    global TEST_ROOT
    TEST_ROOT = initialize_test_root()
    if sys.argv[1:] != ["apply"]:
        stop("usage: v1-node-runtime-prerequisite.py apply", 64)
    receipt = apply()
    sys.stdout.buffer.write(canonical(receipt))


if __name__ == "__main__":
    try:
        main()
    except Stop as error:
        print(f"V1 Node runtime prerequisite stopped: {error}", file=sys.stderr)
        raise SystemExit(error.code)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"V1 Node runtime prerequisite failed closed: {type(error).__name__}.", file=sys.stderr)
        raise SystemExit(78)
