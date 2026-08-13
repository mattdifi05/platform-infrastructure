#!/bin/sh
set -eu

# This script may run as root. Do not let caller-controlled interpreter or
# OpenSSL configuration affect provider verification. Dynamic-loader variables
# are scrubbed for child processes; the privileged caller must still provide a
# trusted /bin/sh process environment.
unset CDPATH ENV BASH_ENV \
  PYTHONHOME PYTHONPATH PYTHONSTARTUP PYTHONINSPECT PYTHONWARNINGS \
  PYTHONBREAKPOINT PYTHONPYCACHEPREFIX PYTHONUSERBASE \
  OPENSSL_CONF OPENSSL_CONF_INCLUDE OPENSSL_MODULES OPENSSL_ENGINES RANDFILE \
  LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT \
  DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH
PYTHONNOUSERSITE=1
PYTHONDONTWRITEBYTECODE=1
PYTHONSAFEPATH=1
LC_ALL=C
LANG=C
export PYTHONNOUSERSITE PYTHONDONTWRITEBYTECODE PYTHONSAFEPATH LC_ALL LANG
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
IFS=$(printf ' \t\n_')
IFS=${IFS%_}
umask 077

MODE=plan
MODE_SELECTED=0
MANIFEST=
SIGNATURE=
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TEST_ROOT=${V1_BROWNFIELD_TEST_ROOT:-}
TEST_ALLOW_NON_ROOT=${V1_BROWNFIELD_TEST_ALLOW_NON_ROOT:-0}
TEST_FAIL_AFTER_STEP=${V1_BROWNFIELD_TEST_FAIL_AFTER_STEP:-0}
TEST_CHECKPOINT_DIR=${V1_BROWNFIELD_TEST_CHECKPOINT_DIR:-}
PYTHON=/usr/bin/python3
OPENSSL=/usr/bin/openssl
ID=/usr/bin/id
TRUST_KEY_LOGICAL=/etc/platform-infrastructure/v1-bootstrap-provider-public-key.pem
ROOT_UID=0
ROOT_GID=0
APPLY_STARTED=0
COMMITTED=0
ROLLBACK_RUNNING=0
CREATED_FILES=
CREATED_DIRECTORIES=
LOCK_RECORD=
MUTATION_STEP=0
REPORT=

usage() {
  printf '%s\n' \
    'Usage: v1-brownfield-bootstrap.sh [--plan|--verify|--apply] [--manifest FILE --signature FILE]' \
    '' \
    'Plan is the read-only default. Verify is read-only. Production apply is' \
    'disabled until the independently pinned Phase-B root installer exists.'
}

fail() {
  printf 'v1-brownfield-bootstrap: %s\n' "$1" >&2
  exit "${2:-1}"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --plan|--verify|--apply)
      [ "$MODE_SELECTED" -eq 0 ] || fail 'exactly one mode may be selected' 64
      MODE=${1#--}
      MODE_SELECTED=1
      ;;
    --manifest)
      shift
      [ "$#" -gt 0 ] && [ -z "$MANIFEST" ] || fail '--manifest requires one value' 64
      MANIFEST=$1
      ;;
    --signature)
      shift
      [ "$#" -gt 0 ] && [ -z "$SIGNATURE" ] || fail '--signature requires one value' 64
      SIGNATURE=$1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1" 64
      ;;
  esac
  shift
done

if [ "$MODE" = apply ] && [ -z "$TEST_ROOT" ]; then
  fail 'production apply is disabled; the independently pinned Phase-B root installer is required' 78
fi

[ -x "$PYTHON" ] || fail 'fixed Python 3 runtime is unavailable' 69
[ -x "$ID" ] || fail 'fixed identity utility is unavailable' 69

reject_unsafe_seam_path() {
  seam_label=$1
  seam_value=$2
  case "$seam_value" in
    ''|*[!A-Za-z0-9_./-]*)
      fail "$seam_label contains bytes that are forbidden in the non-production seam" 64
      ;;
  esac
}

case "$TEST_ROOT" in
  '') ;;
  /*)
    [ "$TEST_ROOT" != / ] && [ "$TEST_ALLOW_NON_ROOT" = 1 ] \
      || fail 'test root is accepted only through the explicit non-production seam' 64
    CURRENT_UID=$($ID -u) || fail 'cannot determine the current uid' 69
    CURRENT_GID=$($ID -g) || fail 'cannot determine the current gid' 69
    [ "$CURRENT_UID" -ne 0 ] \
      || fail 'the non-production root seam cannot run with root authority' 64
    reject_unsafe_seam_path 'test root' "$TEST_ROOT"
    TEST_ROOT_CAPTURE=$(
      "$PYTHON" -I - "$TEST_ROOT" <<'PY'
import os
import sys

original = sys.argv[1]
candidate = os.path.realpath(original)
safe = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./-")
if (candidate == "/" or candidate != original or not os.path.isdir(candidate)
        or os.path.islink(original) or any(character not in safe for character in candidate)):
    raise SystemExit(1)
sys.stdout.write(candidate + "|")
PY
    ) || fail 'test root is not a canonical real directory' 64
    case "$TEST_ROOT_CAPTURE" in
      *'|') TEST_ROOT=${TEST_ROOT_CAPTURE%'|'} ;;
      *) fail 'test root canonicalization returned an invalid identity' 64 ;;
    esac
    reject_unsafe_seam_path 'canonical test root' "$TEST_ROOT"
    [ "$TEST_ROOT" != / ] || fail 'canonical test root cannot be the production root' 64
    ROOT_UID=$CURRENT_UID
    ROOT_GID=$CURRENT_GID
    ;;
  *) fail 'test root must be absolute' 64 ;;
esac

if [ -n "$TEST_CHECKPOINT_DIR" ]; then
  [ -n "$TEST_ROOT" ] || fail 'test checkpoints require the explicit non-production root seam' 64
  case "$TEST_CHECKPOINT_DIR" in
    /*) ;;
    *) fail 'test checkpoint directory must be absolute' 64 ;;
  esac
  reject_unsafe_seam_path 'test checkpoint directory' "$TEST_CHECKPOINT_DIR"
  TEST_CHECKPOINT_CAPTURE=$(
    "$PYTHON" -I - "$TEST_ROOT" "$TEST_CHECKPOINT_DIR" <<'PY'
import os
import stat
import sys

root = os.path.realpath(sys.argv[1])
original = sys.argv[2]
candidate = os.path.realpath(original)
details = os.lstat(candidate)
safe = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./-")
if (candidate != original or not stat.S_ISDIR(details.st_mode) or os.path.islink(original)
        or os.path.commonpath([root, candidate]) != root or candidate == root
        or any(character not in safe for character in candidate)):
    raise SystemExit(1)
sys.stdout.write(candidate + "|")
PY
  ) || fail 'test checkpoint directory is outside the explicit non-production seam' 64
  case "$TEST_CHECKPOINT_CAPTURE" in
    *'|') TEST_CHECKPOINT_DIR=${TEST_CHECKPOINT_CAPTURE%'|'} ;;
    *) fail 'test checkpoint canonicalization returned an invalid identity' 64 ;;
  esac
  reject_unsafe_seam_path 'canonical test checkpoint directory' "$TEST_CHECKPOINT_DIR"
fi

physical_path() {
  logical=$1
  case "$logical" in
    /*) ;;
    *) fail "non-canonical logical path: $logical" 65 ;;
  esac
  if [ -n "$TEST_ROOT" ]; then
    printf '%s%s\n' "$TEST_ROOT" "$logical"
  else
    printf '%s\n' "$logical"
  fi
}

load_identity() {
  identity_path=$1
  IDENTITY=$(
    "$PYTHON" -I - "$identity_path" <<'PY'
import hashlib
import os
import stat
import sys

pathname = sys.argv[1]
try:
    details = os.lstat(pathname)
except FileNotFoundError:
    print("missing")
    raise SystemExit(0)

if stat.S_ISLNK(details.st_mode):
    kind = "symlink"
elif stat.S_ISREG(details.st_mode):
    kind = "file"
elif stat.S_ISDIR(details.st_mode):
    kind = "directory"
else:
    kind = "other"

digest = ""
resolved = os.path.realpath(pathname)
if kind == "file":
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(pathname, flags)
    try:
        before = os.fstat(descriptor)
        hasher = hashlib.sha256()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            hasher.update(block)
        after = os.fstat(descriptor)
        stable = (before.st_dev, before.st_ino, before.st_mode, before.st_uid,
                  before.st_gid, before.st_nlink, before.st_size,
                  before.st_mtime_ns, before.st_ctime_ns)
        repeated = (after.st_dev, after.st_ino, after.st_mode, after.st_uid,
                    after.st_gid, after.st_nlink, after.st_size,
                    after.st_mtime_ns, after.st_ctime_ns)
        initial = (details.st_dev, details.st_ino, details.st_mode, details.st_uid,
                   details.st_gid, details.st_nlink, details.st_size,
                   details.st_mtime_ns, details.st_ctime_ns)
        if initial != stable:
            raise RuntimeError("lstat and opened descriptor identify different objects")
        if stable != repeated:
            raise RuntimeError("file identity changed while hashing")
        if os.path.realpath(pathname) != resolved:
            raise RuntimeError("file pathname changed while hashing")
        digest = hasher.hexdigest()
    finally:
        os.close(descriptor)

print("|".join([
    kind,
    str(details.st_uid),
    str(details.st_gid),
    str(stat.S_IMODE(details.st_mode)),
    str(details.st_nlink),
    str(details.st_dev),
    str(details.st_ino),
    str(details.st_size),
    resolved,
    digest,
    str(details.st_mtime_ns),
    str(details.st_ctime_ns),
]))
PY
  ) || fail "cannot inspect path safely: $identity_path" 65
  old_ifs=$IFS
  IFS='|'
  read -r I_KIND I_UID I_GID I_MODE I_NLINK I_DEV I_INO I_SIZE I_REAL I_SHA I_MTIME I_CTIME <<EOF
$IDENTITY
EOF
  IFS=$old_ifs
}

assert_directory_exact() {
  directory_physical=$1
  directory_label=$2
  expected_mode=$3
  load_identity "$directory_physical"
  [ "$I_KIND" = directory ] \
    && [ "$I_UID" = "$ROOT_UID" ] \
    && [ "$I_GID" = "$ROOT_GID" ] \
    && [ "$I_MODE" = "$expected_mode" ] \
    && [ "$I_REAL" = "$directory_physical" ] \
    || fail "$directory_label has divergent or unsafe identity" 65
}

assert_metadata_file() {
  metadata_path=$1
  metadata_label=$2
  require_root_identity=$3
  exact_mode=${4:-}
  load_identity "$metadata_path"
  [ "$I_KIND" = file ] && [ "$I_NLINK" = 1 ] && [ "$I_REAL" = "$metadata_path" ] \
    || fail "$metadata_label must be one canonical single regular file" 65
  [ $((I_MODE & 18)) -eq 0 ] || fail "$metadata_label is group/world writable" 65
  if [ "$require_root_identity" = 1 ]; then
    [ "$I_UID" = "$ROOT_UID" ] && [ "$I_GID" = "$ROOT_GID" ] \
      || fail "$metadata_label is not root-owned" 65
  fi
  if [ -n "$exact_mode" ]; then
    [ "$I_MODE" = "$exact_mode" ] || fail "$metadata_label has the wrong mode" 65
  fi
}

append_report() {
  report_line=$1
  if [ -n "$REPORT" ]; then
    REPORT="$REPORT
$report_line"
  else
    REPORT=$report_line
  fi
}

if [ -z "$MANIFEST" ] || [ -z "$SIGNATURE" ]; then
  if [ "$MODE" = plan ] && [ -z "$MANIFEST" ] && [ -z "$SIGNATURE" ]; then
    printf '%s\n' 'status=EXTERNAL-PENDING reason=provider install manifest and detached signature are required'
    exit 0
  fi
  fail 'manifest and signature are required together' 78
fi

case "$MANIFEST:$SIGNATURE" in
  *'|'*|*'\n'*|*'\t'*) fail 'manifest/signature path contains forbidden characters' 64 ;;
esac
case "$MANIFEST" in /*) ;; *) fail 'manifest path must be absolute' 64 ;; esac
case "$SIGNATURE" in /*) ;; *) fail 'signature path must be absolute' 64 ;; esac

MANIFEST=$(
  "$PYTHON" -I - "$MANIFEST" <<'PY'
import os
import sys

candidate = sys.argv[1]
if os.path.normpath(candidate) != candidate or any(character in candidate for character in "\n\r\t|"):
    raise SystemExit(1)
print(candidate)
PY
) || fail 'manifest path is not canonical' 64
SIGNATURE=$(
  "$PYTHON" -I - "$SIGNATURE" <<'PY'
import os
import sys

candidate = sys.argv[1]
if os.path.normpath(candidate) != candidate or any(character in candidate for character in "\n\r\t|"):
    raise SystemExit(1)
print(candidate)
PY
) || fail 'signature path is not canonical' 64

assert_metadata_file "$MANIFEST" 'provider install manifest' 0
[ "$I_SIZE" -gt 1 ] && [ "$I_SIZE" -le 1048576 ] || fail 'provider install manifest size is invalid' 65
assert_metadata_file "$SIGNATURE" 'provider detached signature' 0
[ "$I_SIZE" -gt 0 ] && [ "$I_SIZE" -le 65536 ] || fail 'provider detached signature size is invalid' 65

TRUST_PARENT=$(physical_path /etc/platform-infrastructure)
TRUST_KEY=$(physical_path "$TRUST_KEY_LOGICAL")
assert_directory_exact "$TRUST_PARENT" 'provider trust directory' 493
assert_metadata_file "$TRUST_KEY" 'provider trust key' 1 292
[ "$I_SIZE" -gt 0 ] && [ "$I_SIZE" -le 65536 ] || fail 'provider trust key size is invalid' 65
[ -x "$OPENSSL" ] || fail 'fixed signature verifier is unavailable' 69

FORBIDDEN_INNER_SHA256=
INNER_STATE_SUPERVISOR=$SCRIPT_DIR/platform-activation-broker.py
if [ -f "$INNER_STATE_SUPERVISOR" ] && [ ! -L "$INNER_STATE_SUPERVISOR" ]; then
  load_identity "$INNER_STATE_SUPERVISOR"
  if [ "$I_KIND" = file ] && [ "$I_NLINK" = 1 ]; then
    FORBIDDEN_INNER_SHA256=$I_SHA
  fi
fi

MANIFEST_ROWS=$(
  "$PYTHON" -I - \
    "$MANIFEST" "$SIGNATURE" "$TRUST_KEY" "$FORBIDDEN_INNER_SHA256" \
    "$ROOT_UID" "$ROOT_GID" "$OPENSSL" "$TEST_CHECKPOINT_DIR" <<'PY'
from datetime import datetime, timezone
import hashlib
import json
import os
import posixpath
import re
import stat
import subprocess
import sys
import time

(
    manifest_path,
    signature_path,
    trust_key_path,
    forbidden_inner_sha256,
    root_uid_text,
    root_gid_text,
    openssl_path,
    checkpoint_directory,
) = sys.argv[1:]
root_uid, root_gid = int(root_uid_text), int(root_gid_text)

def reject(message):
    print(f"provider manifest: {message}", file=sys.stderr)
    raise SystemExit(1)

def identity(details):
    return (
        details.st_dev,
        details.st_ino,
        details.st_mode,
        details.st_uid,
        details.st_gid,
        details.st_nlink,
        details.st_size,
        details.st_mtime_ns,
        details.st_ctime_ns,
    )

def checkpoint(name):
    if not checkpoint_directory:
        return
    enabled = os.path.join(checkpoint_directory, f"{name}.enabled")
    if not os.path.exists(enabled):
        return
    ready = os.path.join(checkpoint_directory, f"{name}.ready")
    release = os.path.join(checkpoint_directory, f"{name}.release")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(ready, flags, 0o600)
    try:
        os.write(descriptor, b"ready\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    deadline = time.monotonic() + 10
    while True:
        try:
            details = os.lstat(release)
        except FileNotFoundError:
            if time.monotonic() >= deadline:
                reject(f"test checkpoint timed out: {name}")
            time.sleep(0.01)
            continue
        if (not stat.S_ISREG(details.st_mode) or stat.S_ISLNK(details.st_mode)
                or details.st_uid != root_uid or details.st_gid != root_gid
                or details.st_nlink != 1 or stat.S_IMODE(details.st_mode) != 0o600
                or os.path.realpath(release) != release):
            reject(f"test checkpoint release is unsafe: {name}")
        os.unlink(release)
        os.unlink(ready)
        return

def open_exact(pathname, label, *, minimum, maximum, root_owned=False, exact_mode=None):
    try:
        initial = os.lstat(pathname)
    except FileNotFoundError:
        reject(f"{label} is missing")
    checkpoint(f"{label}-after-lstat")
    if not hasattr(os, "O_NOFOLLOW"):
        reject("O_NOFOLLOW is required for provider verification")
    try:
        descriptor = os.open(pathname, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        reject(f"cannot open {label} safely: {error}")
    opened = os.fstat(descriptor)
    if identity(initial) != identity(opened):
        os.close(descriptor)
        reject(f"{label} lstat/open identity is mixed or changed")
    mode = stat.S_IMODE(opened.st_mode)
    if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
            or not minimum <= opened.st_size <= maximum
            or mode & 0o022 or os.path.realpath(pathname) != pathname):
        os.close(descriptor)
        reject(f"{label} is not one canonical safe regular file")
    if root_owned and (opened.st_uid != root_uid or opened.st_gid != root_gid):
        os.close(descriptor)
        reject(f"{label} is not root-owned")
    if exact_mode is not None and mode != exact_mode:
        os.close(descriptor)
        reject(f"{label} mode is not exact")
    return descriptor, identity(opened)

def read_exact(descriptor, expected_identity, label):
    before = os.fstat(descriptor)
    if identity(before) != expected_identity:
        reject(f"{label} descriptor identity changed before read")
    blocks = []
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        blocks.append(block)
    after = os.fstat(descriptor)
    if identity(after) != expected_identity:
        reject(f"{label} descriptor identity changed while read")
    return b"".join(blocks)

def assert_snapshot_unchanged(pathname, descriptor, expected_identity, label):
    if identity(os.fstat(descriptor)) != expected_identity:
        reject(f"{label} descriptor identity changed")
    try:
        current = os.lstat(pathname)
    except FileNotFoundError:
        reject(f"{label} pathname disappeared")
    if identity(current) != expected_identity or os.path.realpath(pathname) != pathname:
        reject(f"{label} pathname changed during verification")

def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            reject(f"duplicate key {key}")
        value[key] = item
    return value

def exact(value, keys, label):
    if not isinstance(value, dict) or sorted(value) != sorted(keys):
        reject(f"{label} is not an exact closed object")
    return value

def canonical(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

def timestamp(value, label):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", value):
        reject(f"{label} is not an exact UTC timestamp")
    return datetime.fromisoformat(value[:-1] + "+00:00")

def safe_absolute(value, label):
    if (not isinstance(value, str) or not value.startswith("/")
            or posixpath.normpath(value) != value or "//" in value
            or not re.fullmatch(r"/[A-Za-z0-9._/-]+", value)):
        reject(f"{label} is not a canonical absolute path")
    return value

manifest_descriptor, manifest_identity = open_exact(
    manifest_path, "manifest", minimum=2, maximum=1048576,
)
signature_descriptor, signature_identity = open_exact(
    signature_path, "signature", minimum=1, maximum=65536,
)
trust_key_descriptor, trust_key_identity = open_exact(
    trust_key_path,
    "provider-trust-key",
    minimum=1,
    maximum=65536,
    root_owned=True,
    exact_mode=0o444,
)

raw = read_exact(manifest_descriptor, manifest_identity, "manifest")
trust_key_bytes = read_exact(trust_key_descriptor, trust_key_identity, "provider trust key")
trusted_key_id = hashlib.sha256(trust_key_bytes).hexdigest()
os.lseek(trust_key_descriptor, 0, os.SEEK_SET)
try:
    verification = subprocess.run(
        [
            openssl_path,
            "dgst",
            "-sha256",
            "-verify",
            f"/dev/fd/{trust_key_descriptor}",
            "-signature",
            f"/dev/fd/{signature_descriptor}",
        ],
        check=False,
        cwd="/",
        env={
            "LANG": "C",
            "LC_ALL": "C",
            "OPENSSL_CONF": "/dev/null",
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        },
        input=raw,
        pass_fds=(trust_key_descriptor, signature_descriptor),
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
    )
except OSError as error:
    reject(f"cannot execute fixed signature verifier: {error}")
if verification.returncode != 0:
    reject("provider install manifest signature verification failed")

checkpoint("after-signature")
try:
    document = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
except (UnicodeError, json.JSONDecodeError) as error:
    reject(f"cannot parse manifest snapshot: {error}")

if raw != (canonical(document) + "\n").encode("utf-8"):
    reject("bytes are not canonical JSON")

exact(document, [
    "binaries", "directories", "expiresAt", "generatedAt", "provider",
    "providerAttested", "schema", "signatureAlgorithm", "status", "version",
], "manifest")
if (document["version"] != 1
        or document["schema"] != "platform-v1-brownfield-install-manifest/v1"
        or document["status"] != "READY"
        or document["providerAttested"] is not True
        or document["signatureAlgorithm"] != "openssl-dgst-sha256"):
    reject("identity/status/provider attestation is invalid")

generated = timestamp(document["generatedAt"], "generatedAt")
expires = timestamp(document["expiresAt"], "expiresAt")
now = datetime.now(timezone.utc)
if generated > now or expires <= now or expires <= generated or (expires - generated).total_seconds() > 86400:
    reject("manifest validity window is invalid or expired")

provider = exact(document["provider"], [
    "event", "keyId", "repository", "runAttempt", "runId", "sourceRef",
    "workflowPath", "workflowSha",
], "provider")
if (provider["keyId"] != trusted_key_id
        or not isinstance(provider["repository"], str)
        or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", provider["repository"])
        or not isinstance(provider["workflowPath"], str)
        or not re.fullmatch(r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml", provider["workflowPath"])
        or not isinstance(provider["workflowSha"], str)
        or not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", provider["workflowSha"])
        or provider["sourceRef"] != "refs/heads/main"
        or provider["event"] != "workflow_dispatch"
        or not isinstance(provider["runId"], str) or not re.fullmatch(r"[1-9][0-9]*", provider["runId"])
        or not isinstance(provider["runAttempt"], int) or isinstance(provider["runAttempt"], bool)
        or provider["runAttempt"] < 1):
    reject("trusted provider identity is invalid")

expected_directories = [
    "/srv/platform-infrastructure",
    "/srv/platform-infrastructure/releases",
    "/srv/platform-infrastructure/release-states",
]
directories = document["directories"]
if not isinstance(directories, list) or len(directories) != len(expected_directories):
    reject("directory set is incomplete")
for entry, pathname in zip(directories, expected_directories):
    exact(entry, ["gid", "mode", "path", "uid"], f"directory {pathname}")
    if entry != {"gid": 0, "mode": "0755", "path": pathname, "uid": 0}:
        reject(f"directory contract is invalid: {pathname}")

expected_binaries = [
    ("activationBroker", "/usr/local/libexec/platform-activation-broker"),
    ("hostedPreparationBroker", "/usr/local/libexec/platform-hosted-preparation-broker"),
    ("originFirewallHelper", "/usr/local/libexec/platform-origin-firewall"),
    ("workloadEgressHelper", "/usr/local/libexec/platform-workload-egress-firewall"),
]
binaries = document["binaries"]
if not isinstance(binaries, list) or len(binaries) != len(expected_binaries):
    reject("binary set is incomplete")
hashes = []
rows = []
for entry, (name, pathname) in zip(binaries, expected_binaries):
    exact(entry, [
        "gid", "mode", "name", "nlink", "path", "providerAttested",
        "sha256", "source", "uid", "version",
    ], f"binary {name}")
    source = safe_absolute(entry["source"], f"binary {name} source")
    if (entry["name"] != name or entry["path"] != pathname
            or entry["providerAttested"] is not True
            or entry["uid"] != 0 or entry["gid"] != 0
            or entry["mode"] != "0555" or entry["nlink"] != 1
            or not isinstance(entry["version"], int) or isinstance(entry["version"], bool)
            or entry["version"] < 1 or entry["version"] > 999999999
            or not isinstance(entry["sha256"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", entry["sha256"])):
        reject(f"binary contract is invalid: {name}")
    if name == "activationBroker" and posixpath.basename(source) == "platform-activation-broker.py":
        reject("refusing to install platform-activation-broker.py as the outer activation broker")
    if name == "activationBroker" and forbidden_inner_sha256 and entry["sha256"] == forbidden_inner_sha256:
        reject("refusing to install a renamed copy of the inner state supervisor as the outer activation broker")
    hashes.append(entry["sha256"])
    rows.append("|".join([
        "B", name, pathname, source, str(entry["version"]), entry["sha256"],
        str(entry["uid"]), str(entry["gid"]), entry["mode"], str(entry["nlink"]),
    ]))
if len(set(hashes)) != len(hashes):
    reject("provider-attested binary hashes must be distinct")
for entry in directories:
    rows.append("|".join(["D", entry["path"], str(entry["uid"]), str(entry["gid"]), entry["mode"]]))

checkpoint("after-parse")
assert_snapshot_unchanged(manifest_path, manifest_descriptor, manifest_identity, "manifest")
assert_snapshot_unchanged(signature_path, signature_descriptor, signature_identity, "signature")
assert_snapshot_unchanged(
    trust_key_path,
    trust_key_descriptor,
    trust_key_identity,
    "provider trust key",
)
for descriptor in (manifest_descriptor, signature_descriptor, trust_key_descriptor):
    os.close(descriptor)
for row in rows:
    print(row)
PY
) || fail 'provider install manifest signature or contract is not complete and exact' 78

SOURCE_ROWS=$(printf '%s\n' "$MANIFEST_ROWS" | /usr/bin/sed -n '/^B|/p')
DIRECTORY_ROWS=$(printf '%s\n' "$MANIFEST_ROWS" | /usr/bin/sed -n '/^D|/p')
[ "$(printf '%s\n' "$SOURCE_ROWS" | /usr/bin/sed '/^$/d' | /usr/bin/wc -l | /usr/bin/tr -d ' ')" = 4 ] \
  || fail 'provider install manifest binary projection is incomplete' 78
[ "$(printf '%s\n' "$DIRECTORY_ROWS" | /usr/bin/sed '/^$/d' | /usr/bin/wc -l | /usr/bin/tr -d ' ')" = 3 ] \
  || fail 'provider install manifest directory projection is incomplete' 78

SERVICE_PARENT=$(physical_path /srv)
LIBEXEC_PARENT=$(physical_path /usr/local/libexec)
assert_directory_exact "$SERVICE_PARENT" 'service parent /srv' 493
assert_directory_exact "$LIBEXEC_PARENT" 'helper parent /usr/local/libexec' 493

check_source() {
  source_logical=$1
  expected_sha=$2
  source_physical=$(physical_path "$source_logical")
  load_identity "$source_physical"
  [ "$I_KIND" = file ] && [ "$I_NLINK" = 1 ] && [ "$I_REAL" = "$source_physical" ] \
    || fail "provider binary source is not one stable regular file: $source_logical" 65
  [ $((I_MODE & 18)) -eq 0 ] || fail "provider binary source is group/world writable: $source_logical" 65
  [ "$I_SHA" = "$expected_sha" ] || fail "provider binary source hash mismatch: $source_logical" 78
}

check_target_file() {
  target_logical=$1
  expected_sha=$2
  allow_missing=$3
  target_physical=$(physical_path "$target_logical")
  load_identity "$target_physical"
  if [ "$I_KIND" = missing ]; then
    [ "$allow_missing" = 1 ] || fail "required installed binary is missing: $target_logical" 65
    CHECK_STATUS=create
    return 0
  fi
  [ "$I_KIND" = file ] \
    && [ "$I_UID" = "$ROOT_UID" ] \
    && [ "$I_GID" = "$ROOT_GID" ] \
    && [ "$I_MODE" = 365 ] \
    && [ "$I_NLINK" = 1 ] \
    && [ "$I_REAL" = "$target_physical" ] \
    && [ "$I_SHA" = "$expected_sha" ] \
    || fail "existing installed binary is divergent or unsafe: $target_logical" 65
  CHECK_STATUS=preserve-exact
}

check_install_directory() {
  directory_logical=$1
  allow_missing=$2
  directory_physical=$(physical_path "$directory_logical")
  load_identity "$directory_physical"
  if [ "$I_KIND" = missing ]; then
    [ "$allow_missing" = 1 ] || fail "required service directory is missing: $directory_logical" 65
    CHECK_STATUS=create
    return 0
  fi
  [ "$I_KIND" = directory ] \
    && [ "$I_UID" = "$ROOT_UID" ] \
    && [ "$I_GID" = "$ROOT_GID" ] \
    && [ "$I_MODE" = 493 ] \
    && [ "$I_REAL" = "$directory_physical" ] \
    || fail "existing service directory is divergent or unsafe: $directory_logical" 65
  CHECK_STATUS=preserve-exact
}

validate_state() {
  validation_mode=$1
  REPORT=
  allow_missing=1
  [ "$validation_mode" != verify ] || allow_missing=0

  while IFS='|' read -r row_type row_path row_uid row_gid row_mode; do
    [ "$row_type" = D ] || continue
    check_install_directory "$row_path" "$allow_missing"
    append_report "directory=$row_path action=$CHECK_STATUS owner=0:0 mode=0755"
  done <<EOF
$DIRECTORY_ROWS
EOF

  while IFS='|' read -r row_type row_name row_path row_source row_version row_sha row_uid row_gid row_mode row_nlink; do
    [ "$row_type" = B ] || continue
    if [ "$validation_mode" != verify ]; then
      check_source "$row_source" "$row_sha"
    fi
    check_target_file "$row_path" "$row_sha" "$allow_missing"
    append_report "binary=$row_path action=$CHECK_STATUS owner=0:0 mode=0555 version=$row_version sha256=$row_sha"
  done <<EOF
$SOURCE_ROWS
EOF
}

if [ "$MODE" = plan ]; then
  validate_state plan
  printf '%s\n' 'status=INSTALL-PLAN-READY-NON-AUTHORITATIVE mode=plan mutation=false providerSignature=verified trustDomain=BOOTSTRAP-INSTALL-ONLY deploymentAuthorized=false providerGates=EXTERNAL-PENDING'
  printf '%s\n' "$REPORT"
  exit 0
fi

if [ "$MODE" = verify ]; then
  validate_state verify
  printf '%s\n' 'status=INSTALL-STATE-VERIFIED-NON-AUTHORITATIVE mode=verify mutation=false providerSignature=verified trustDomain=BOOTSTRAP-INSTALL-ONLY deploymentAuthorized=false providerGates=EXTERNAL-PENDING'
  printf '%s\n' "$REPORT"
  exit 0
fi

[ "$MODE" = apply ] || fail 'internal mode selection failure' 70
if [ -z "$TEST_ROOT" ]; then
  [ "$($ID -u)" = 0 ] || fail '--apply requires root' 77
fi

validate_state apply

create_owned_directory() {
  create_physical=$1
  "$PYTHON" -I - "$create_physical" "$ROOT_UID" "$ROOT_GID" <<'PY'
import errno
import os
import stat
import sys

pathname, uid_text, gid_text = sys.argv[1:]
uid, gid = int(uid_text), int(gid_text)
parent = os.path.dirname(pathname)

def sync_directory(directory):
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        try:
            os.fsync(descriptor)
        except OSError as error:
            if not (sys.platform == "darwin" and error.errno in {errno.EINVAL, errno.ENOTSUP}):
                raise
    finally:
        os.close(descriptor)

created = False
created_identity = None
try:
    os.mkdir(pathname, 0o755)
    created = True
    initial = os.lstat(pathname)
    created_identity = (initial.st_dev, initial.st_ino)
    descriptor = os.open(pathname, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, 0o755)
        os.fsync(descriptor)
        details = os.fstat(descriptor)
        if (not stat.S_ISDIR(details.st_mode) or details.st_uid != uid or details.st_gid != gid
                or stat.S_IMODE(details.st_mode) != 0o755
                or (details.st_dev, details.st_ino) != created_identity):
            raise RuntimeError("created directory identity mismatch")
    finally:
        os.close(descriptor)
    sync_directory(parent)
    print(f"{details.st_dev}|{details.st_ino}")
except BaseException:
    if created:
        try:
            details = os.lstat(pathname)
            if (created_identity is not None and (details.st_dev, details.st_ino) == created_identity
                    and stat.S_ISDIR(details.st_mode) and not stat.S_ISLNK(details.st_mode)
                    and not os.listdir(pathname)):
                os.rmdir(pathname)
                sync_directory(parent)
        except FileNotFoundError:
            pass
    raise
PY
}

install_owned_file() {
  source_physical=$1
  target_physical=$2
  expected_sha=$3
  "$PYTHON" -I - "$source_physical" "$target_physical" "$expected_sha" "$ROOT_UID" "$ROOT_GID" <<'PY'
import errno
import hashlib
import os
import secrets
import stat
import sys

source, target, expected_sha, uid_text, gid_text = sys.argv[1:]
uid, gid = int(uid_text), int(gid_text)
parent = os.path.dirname(target)
temporary = os.path.join(parent, f".v1-brownfield-bootstrap.{os.getpid()}.{secrets.token_hex(12)}")
temporary_created = False
target_created = False
target_identity = None

def sync_directory(directory):
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        try:
            os.fsync(descriptor)
        except OSError as error:
            if not (sys.platform == "darwin" and error.errno in {errno.EINVAL, errno.ENOTSUP}):
                raise
    finally:
        os.close(descriptor)

def read_stable(pathname):
    descriptor = os.open(pathname, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError("provider source identity is unsafe")
        blocks = []
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            blocks.append(block)
            digest.update(block)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in fields):
            raise RuntimeError("provider source changed while being copied")
        if digest.hexdigest() != expected_sha:
            raise RuntimeError("provider source hash mismatch")
        return blocks
    finally:
        os.close(descriptor)

try:
    if os.path.lexists(target):
        raise FileExistsError("refusing to replace an existing helper")
    blocks = read_stable(source)
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o555,
    )
    temporary_created = True
    try:
        initial = os.fstat(descriptor)
        target_identity = (initial.st_dev, initial.st_ino)
        for block in blocks:
            view = memoryview(block)
            while view:
                count = os.write(descriptor, view)
                if count < 1:
                    raise RuntimeError("short helper write")
                view = view[count:]
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, 0o555)
        os.fsync(descriptor)
        staged = os.fstat(descriptor)
        if (staged.st_dev, staged.st_ino) != target_identity:
            raise RuntimeError("staged helper descriptor identity changed")
    finally:
        os.close(descriptor)
    os.link(temporary, target, follow_symlinks=False)
    target_created = True
    os.unlink(temporary)
    temporary_created = False
    sync_directory(parent)
    details = os.lstat(target)
    if (not stat.S_ISREG(details.st_mode) or stat.S_ISLNK(details.st_mode)
            or details.st_uid != uid or details.st_gid != gid
            or stat.S_IMODE(details.st_mode) != 0o555 or details.st_nlink != 1
            or (details.st_dev, details.st_ino) != target_identity):
        raise RuntimeError("installed helper identity mismatch")
    digest = hashlib.sha256(open(target, "rb").read()).hexdigest()
    if digest != expected_sha:
        raise RuntimeError("installed helper hash mismatch")
    print(f"{details.st_dev}|{details.st_ino}")
except BaseException:
    if target_created:
        try:
            details = os.lstat(target)
            if target_identity is not None and (details.st_dev, details.st_ino) == target_identity:
                os.unlink(target)
        except FileNotFoundError:
            pass
    if temporary_created:
        try:
            details = os.lstat(temporary)
            if target_identity is not None and (details.st_dev, details.st_ino) == target_identity:
                os.unlink(temporary)
        except FileNotFoundError:
            pass
    sync_directory(parent)
    raise
PY
}

remove_owned_file() {
  remove_physical=$1
  expected_dev=$2
  expected_ino=$3
  expected_sha=$4
  "$PYTHON" -I - "$remove_physical" "$expected_dev" "$expected_ino" "$expected_sha" "$ROOT_UID" "$ROOT_GID" <<'PY'
import errno
import hashlib
import os
import stat
import sys

pathname, dev_text, ino_text, expected_sha, uid_text, gid_text = sys.argv[1:]
expected_dev, expected_ino, uid, gid = map(int, (dev_text, ino_text, uid_text, gid_text))
details = os.lstat(pathname)
if (not stat.S_ISREG(details.st_mode) or stat.S_ISLNK(details.st_mode)
        or details.st_dev != expected_dev or details.st_ino != expected_ino
        or details.st_uid != uid or details.st_gid != gid
        or stat.S_IMODE(details.st_mode) != 0o555 or details.st_nlink != 1
        or hashlib.sha256(open(pathname, "rb").read()).hexdigest() != expected_sha):
    raise RuntimeError("refusing to remove a file not owned exactly by this transaction")
os.unlink(pathname)
parent = os.path.dirname(pathname)
descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    try:
        os.fsync(descriptor)
    except OSError as error:
        if not (sys.platform == "darwin" and error.errno in {errno.EINVAL, errno.ENOTSUP}):
            raise
finally:
    os.close(descriptor)
PY
}

remove_owned_empty_directory() {
  remove_physical=$1
  expected_dev=$2
  expected_ino=$3
  "$PYTHON" -I - "$remove_physical" "$expected_dev" "$expected_ino" "$ROOT_UID" "$ROOT_GID" <<'PY'
import errno
import os
import stat
import sys

pathname, dev_text, ino_text, uid_text, gid_text = sys.argv[1:]
expected_dev, expected_ino, uid, gid = map(int, (dev_text, ino_text, uid_text, gid_text))
details = os.lstat(pathname)
if (not stat.S_ISDIR(details.st_mode) or stat.S_ISLNK(details.st_mode)
        or details.st_dev != expected_dev or details.st_ino != expected_ino
        or details.st_uid != uid or details.st_gid != gid
        or stat.S_IMODE(details.st_mode) not in {0o700, 0o755}
        or os.listdir(pathname)):
    raise RuntimeError("refusing to remove a directory not owned and empty exactly by this transaction")
os.rmdir(pathname)
parent = os.path.dirname(pathname)
descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    try:
        os.fsync(descriptor)
    except OSError as error:
        if not (sys.platform == "darwin" and error.errno in {errno.EINVAL, errno.ENOTSUP}):
            raise
finally:
    os.close(descriptor)
PY
}

record_created_file() {
  record=$1
  if [ -n "$CREATED_FILES" ]; then
    CREATED_FILES="$record
$CREATED_FILES"
  else
    CREATED_FILES=$record
  fi
}

record_created_directory() {
  record=$1
  if [ -n "$CREATED_DIRECTORIES" ]; then
    CREATED_DIRECTORIES="$record
$CREATED_DIRECTORIES"
  else
    CREATED_DIRECTORIES=$record
  fi
}

maybe_inject_failure() {
  MUTATION_STEP=$((MUTATION_STEP + 1))
  if [ -n "$TEST_ROOT" ] && [ "$TEST_FAIL_AFTER_STEP" = "$MUTATION_STEP" ]; then
    fail "injected failure after mutation step $MUTATION_STEP" 97
  fi
}

rollback_transaction() {
  [ "$ROLLBACK_RUNNING" -eq 0 ] || return 1
  ROLLBACK_RUNNING=1
  rollback_failed=0
  while IFS='|' read -r logical physical dev ino digest; do
    [ -n "$logical" ] || continue
    if ! remove_owned_file "$physical" "$dev" "$ino" "$digest"; then
      printf 'v1-brownfield-bootstrap: rollback refused file %s\n' "$logical" >&2
      rollback_failed=1
    fi
  done <<EOF
$CREATED_FILES
EOF
  while IFS='|' read -r logical physical dev ino; do
    [ -n "$logical" ] || continue
    if ! remove_owned_empty_directory "$physical" "$dev" "$ino"; then
      printf 'v1-brownfield-bootstrap: rollback refused directory %s\n' "$logical" >&2
      rollback_failed=1
    fi
  done <<EOF
$CREATED_DIRECTORIES
EOF
  if [ -n "$LOCK_RECORD" ]; then
    old_ifs=$IFS
    IFS='|'
    read -r lock_physical lock_dev lock_ino <<EOF
$LOCK_RECORD
EOF
    IFS=$old_ifs
    if ! remove_owned_empty_directory "$lock_physical" "$lock_dev" "$lock_ino"; then
      printf '%s\n' 'v1-brownfield-bootstrap: rollback refused transaction lock' >&2
      rollback_failed=1
    fi
  fi
  [ "$rollback_failed" -eq 0 ]
}

on_exit() {
  exit_status=$1
  trap - EXIT HUP INT TERM
  if [ "$exit_status" -ne 0 ] && [ "$APPLY_STARTED" -eq 1 ] && [ "$COMMITTED" -eq 0 ]; then
    rollback_transaction || printf '%s\n' 'v1-brownfield-bootstrap: rollback incomplete; manual read-only inspection required' >&2
  fi
  exit "$exit_status"
}

trap 'on_exit $?' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

LOCK_PARENT=$(physical_path /run/lock)
LOCK_PHYSICAL=$(physical_path /run/lock/platform-v1-brownfield-bootstrap.lock)
assert_directory_exact "$LOCK_PARENT" 'transaction lock parent' 493
load_identity "$LOCK_PHYSICAL"
[ "$I_KIND" = missing ] || fail 'another V1 brownfield bootstrap transaction is active' 75
lock_identity=$(create_owned_directory "$LOCK_PHYSICAL") || fail 'cannot acquire exact transaction lock' 75
LOCK_RECORD="$LOCK_PHYSICAL|$lock_identity"
APPLY_STARTED=1
maybe_inject_failure

validate_state apply

while IFS='|' read -r row_type row_path row_uid row_gid row_mode; do
  [ "$row_type" = D ] || continue
  row_physical=$(physical_path "$row_path")
  load_identity "$row_physical"
  if [ "$I_KIND" = missing ]; then
    created_identity=$(create_owned_directory "$row_physical") || fail "cannot create exact service directory: $row_path" 73
    record_created_directory "$row_path|$row_physical|$created_identity"
    maybe_inject_failure
  else
    check_install_directory "$row_path" 0
  fi
done <<EOF
$DIRECTORY_ROWS
EOF

while IFS='|' read -r row_type row_name row_path row_source row_version row_sha row_uid row_gid row_mode row_nlink; do
  [ "$row_type" = B ] || continue
  row_physical=$(physical_path "$row_path")
  source_physical=$(physical_path "$row_source")
  load_identity "$row_physical"
  if [ "$I_KIND" = missing ]; then
    created_identity=$(install_owned_file "$source_physical" "$row_physical" "$row_sha") \
      || fail "cannot install exact provider binary: $row_path" 73
    record_created_file "$row_path|$row_physical|$created_identity|$row_sha"
    maybe_inject_failure
  else
    check_target_file "$row_path" "$row_sha" 0
  fi
done <<EOF
$SOURCE_ROWS
EOF

validate_state verify

old_ifs=$IFS
IFS='|'
read -r lock_physical lock_dev lock_ino <<EOF
$LOCK_RECORD
EOF
IFS=$old_ifs
remove_owned_empty_directory "$lock_physical" "$lock_dev" "$lock_ino" \
  || fail 'cannot release exact transaction lock' 74
LOCK_RECORD=
COMMITTED=1
printf '%s\n' 'status=INSTALL-APPLIED-NON-AUTHORITATIVE mode=apply providerSignature=verified trustDomain=BOOTSTRAP-INSTALL-ONLY deploymentAuthorized=false providerGates=EXTERNAL-PENDING rollbackBoundary=exact-owned-only'
printf '%s\n' "$REPORT"
