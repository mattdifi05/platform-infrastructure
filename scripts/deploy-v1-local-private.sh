#!/usr/bin/env sh
set -eu
umask 077

SCRIPT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPOSITORY_ROOT=$(CDPATH= cd -- "$SCRIPT_ROOT/.." && pwd)
REMOTE=${DEPLOY_REMOTE:-}
SSH_PORT=${DEPLOY_SSH_PORT:-22}
SSH_KEY_SOURCE=${DEPLOY_SSH_KEY_PATH:-${HOME:?HOME is required}/.ssh/deploy_key}
KNOWN_HOSTS_SOURCE=${DEPLOY_SSH_KNOWN_HOSTS_PATH:-${HOME:?HOME is required}/.ssh/known_hosts}
RECOVERY_PRIVATE_KEY_SOURCE=${DEPLOY_RECOVERY_PRIVATE_KEY_PATH:-${HOME:?HOME is required}/.platform-infrastructure-recovery/v1/operator-recovery-private.pem}
COMPOSE_WRAPPER_SOURCE="$REPOSITORY_ROOT/scripts/compose-vps.sh"
CONTROLLER_SOURCE="$REPOSITORY_ROOT/scripts/v1-local-private-control.py"
INSTALLER_SOURCE="$REPOSITORY_ROOT/scripts/v1-brownfield-install-consumer.py"
RECONCILER_SOURCE="$REPOSITORY_ROOT/scripts/v1-local-private-reconcile.py"
EVIDENCE_PRODUCER_SOURCE="$REPOSITORY_ROOT/scripts/v1-local-private-evidence-producer.py"
SUDOERS_SOURCE="$REPOSITORY_ROOT/sudoers/platform-v1-local-private-control"
UNIT_SOURCE="$REPOSITORY_ROOT/systemd/platform-v1-local-private-control.service"
RECOVERY_CERT_SOURCE="$REPOSITORY_ROOT/config/local-private-recovery-escrow-cert.pem"
WORKLOAD_LOCK_SOURCE="$REPOSITORY_ROOT/config/no-hosted-workloads.local-private.lock.json"
REMOTE_COMMAND='/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-control activate'
REMOTE_CONTROLLER='/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-control'
REMOTE_RECONCILER='/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-reconcile'
REMOTE_ABORTED_RECORD='/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-control aborted-record'
REMOTE_RUNTIME_AUTHORITY='/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-control runtime-authority'
REMOTE_VALIDATION_MODE='/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-control validation-mode'
REMOTE_VALIDATION_CLOSE='/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-reconcile validation-close'
REMOTE_AUTHORITY_CAT='/usr/bin/sudo -n -- /usr/bin/cat /var/lib/platform-infrastructure/v1/local-private/exact-release-authority.json'
REMOTE_OFFHOST_EVIDENCE_CAT='/usr/bin/sudo -n -- /usr/bin/cat /var/lib/platform-infrastructure/v1/predeploy/current/offhost-backup-evidence.json'
REMOTE_SECRETS_EVIDENCE_CAT='/usr/bin/sudo -n -- /usr/bin/cat /var/lib/platform-infrastructure/v1/predeploy/current/secrets-backup-evidence.json'
SSH=/usr/bin/ssh
GIT=/usr/bin/git
OPENSSL=${PLATFORM_V1_LOCAL_PRIVATE_TEST_OPENSSL:-/usr/bin/openssl}
SYSTEM_NAME=$(/usr/bin/uname -s)
if [ "$SYSTEM_NAME" != Linux ]; then
  SSH=${PLATFORM_V1_LOCAL_PRIVATE_TEST_SSH:-$SSH}
  GIT=${PLATFORM_V1_LOCAL_PRIVATE_TEST_GIT:-$GIT}
fi

NODE=${PLATFORM_V1_LOCAL_PRIVATE_TEST_NODE:-${DEPLOY_NODE_PATH:-}}
if [ -z "$NODE" ]; then
  if [ -x /usr/bin/node ]; then
    NODE=/usr/bin/node
  elif [ -x "${HOME:?HOME is required}/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node" ]; then
    NODE="${HOME}/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node"
  else
    NODE=
  fi
fi

fail() {
  echo "$1" >&2
  exit "${2:-64}"
}

hash_file() {
  trap - EXIT HUP INT TERM
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

require_input_file() {
  label=$1
  filename=$2
  [ -f "$filename" ] && [ -r "$filename" ] && [ -s "$filename" ] && [ ! -L "$filename" ] \
    || fail "$label must be one readable, non-empty regular file and not a symlink."
}

[ "$#" -eq 2 ] && [ "$1" = "--authorityFile" ] && [ -n "$2" ] \
  || fail "Usage: deploy-v1-local-private.sh --authorityFile FILE"
AUTHORITY_SOURCE=$2
case "$REMOTE" in *@*) ;; *) fail "DEPLOY_REMOTE must be one canonical user@host endpoint." ;; esac
REMOTE_USER=${REMOTE%@*}
REMOTE_HOST=${REMOTE#*@}
case "$REMOTE_USER" in ""|[!a-z_]*|*[!a-z0-9_-]*) fail "DEPLOY_REMOTE user is invalid." ;; esac
case "$REMOTE_HOST" in ""|[!a-z0-9]*|*[!a-z0-9.-]*|*..*|*[-.]) fail "DEPLOY_REMOTE host is invalid." ;; esac
case "$REMOTE" in *@*@*) fail "DEPLOY_REMOTE must contain exactly one separator." ;; esac
case "$SSH_PORT" in ""|*[!0-9]*) fail "DEPLOY_SSH_PORT must be numeric." ;; esac
[ "$SSH_PORT" -ge 1 ] && [ "$SSH_PORT" -le 65535 ] || fail "DEPLOY_SSH_PORT is outside the accepted range."
[ -x "$SSH" ] || fail "The fixed SSH client is unavailable." 78
[ -x "$GIT" ] || fail "The fixed Git client is unavailable." 78
[ -n "$NODE" ] && [ -x "$NODE" ] || fail "The fixed Node.js runtime is unavailable; set DEPLOY_NODE_PATH." 78
[ -x "$OPENSSL" ] || fail "The fixed OpenSSL client is unavailable." 78
[ -f "$SCRIPT_ROOT/ssh-known-host-endpoint.sh" ] && [ ! -L "$SCRIPT_ROOT/ssh-known-host-endpoint.sh" ] \
  || fail "The exact SSH endpoint verifier is unavailable." 78
[ -f "$SCRIPT_ROOT/pinned-ssh-host-key.mjs" ] && [ ! -L "$SCRIPT_ROOT/pinned-ssh-host-key.mjs" ] \
  || fail "The exact SSH host-key verifier is unavailable." 78
[ -f "$SCRIPT_ROOT/v1-local-private-control-receipt.mjs" ] && [ ! -L "$SCRIPT_ROOT/v1-local-private-control-receipt.mjs" ] \
  || fail "The exact V1 LOCAL_PRIVATE receipt verifier is unavailable." 78
require_input_file "SSH private key" "$SSH_KEY_SOURCE"
require_input_file "SSH known-hosts input" "$KNOWN_HOSTS_SOURCE"
require_input_file "V1 recovery private key" "$RECOVERY_PRIVATE_KEY_SOURCE"
require_input_file "V1 LOCAL_PRIVATE Compose wrapper source" "$COMPOSE_WRAPPER_SOURCE"
require_input_file "V1 LOCAL_PRIVATE controller source" "$CONTROLLER_SOURCE"
require_input_file "V1 LOCAL_PRIVATE installer source" "$INSTALLER_SOURCE"
require_input_file "V1 LOCAL_PRIVATE reconciler source" "$RECONCILER_SOURCE"
require_input_file "V1 LOCAL_PRIVATE evidence producer source" "$EVIDENCE_PRODUCER_SOURCE"
require_input_file "V1 LOCAL_PRIVATE sudoers source" "$SUDOERS_SOURCE"
require_input_file "V1 LOCAL_PRIVATE systemd unit source" "$UNIT_SOURCE"
require_input_file "V1 recovery escrow certificate source" "$RECOVERY_CERT_SOURCE"
require_input_file "V1 LOCAL_PRIVATE workload lock source" "$WORKLOAD_LOCK_SOURCE"
require_input_file "V1 exact release authority" "$AUTHORITY_SOURCE"
"$NODE" --input-type=module - "$RECOVERY_PRIVATE_KEY_SOURCE" <<'NODE'
import fs from "node:fs";
const metadata = fs.lstatSync(process.argv[2]);
if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1
  || metadata.size < 256 || metadata.size > 65536 || (metadata.mode & 0o077) !== 0) {
  throw new Error("V1 recovery private key identity or permissions are invalid.");
}
NODE

work=$(mktemp -d "${TMPDIR:-/tmp}/platform-v1-local-private-client.XXXXXX")
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

ssh_key="$work/ssh-key"
known_hosts="$work/known-hosts"
recovery_private_key="$work/operator-recovery-private.pem"
receipt="$work/local-private-control-receipt.json"
compose_wrapper_snapshot="$work/compose-vps.sh"
controller_snapshot="$work/v1-local-private-control.py"
installer_snapshot="$work/v1-brownfield-install-consumer.py"
reconciler_snapshot="$work/v1-local-private-reconcile.py"
evidence_producer_snapshot="$work/v1-local-private-evidence-producer.py"
sudoers_snapshot="$work/platform-v1-local-private-control.sudoers"
unit_snapshot="$work/platform-v1-local-private-control.service"
recovery_cert_snapshot="$work/local-private-recovery-escrow-cert.pem"
workload_lock_snapshot="$work/no-hosted-workloads.local-private.lock.json"
authority_snapshot="$work/exact-release-authority.json"
key_before=$(hash_file "$SSH_KEY_SOURCE")
known_before=$(hash_file "$KNOWN_HOSTS_SOURCE")
recovery_private_key_before=$(hash_file "$RECOVERY_PRIVATE_KEY_SOURCE")
compose_wrapper_before=$(hash_file "$COMPOSE_WRAPPER_SOURCE")
controller_before=$(hash_file "$CONTROLLER_SOURCE")
installer_before=$(hash_file "$INSTALLER_SOURCE")
reconciler_before=$(hash_file "$RECONCILER_SOURCE")
evidence_producer_before=$(hash_file "$EVIDENCE_PRODUCER_SOURCE")
sudoers_before=$(hash_file "$SUDOERS_SOURCE")
unit_before=$(hash_file "$UNIT_SOURCE")
recovery_cert_before=$(hash_file "$RECOVERY_CERT_SOURCE")
workload_lock_before=$(hash_file "$WORKLOAD_LOCK_SOURCE")
authority_before=$(hash_file "$AUTHORITY_SOURCE")
cp "$SSH_KEY_SOURCE" "$ssh_key"
cp "$KNOWN_HOSTS_SOURCE" "$known_hosts"
cp "$RECOVERY_PRIVATE_KEY_SOURCE" "$recovery_private_key"
cp "$COMPOSE_WRAPPER_SOURCE" "$compose_wrapper_snapshot"
cp "$CONTROLLER_SOURCE" "$controller_snapshot"
cp "$INSTALLER_SOURCE" "$installer_snapshot"
cp "$RECONCILER_SOURCE" "$reconciler_snapshot"
cp "$EVIDENCE_PRODUCER_SOURCE" "$evidence_producer_snapshot"
cp "$SUDOERS_SOURCE" "$sudoers_snapshot"
cp "$UNIT_SOURCE" "$unit_snapshot"
cp "$RECOVERY_CERT_SOURCE" "$recovery_cert_snapshot"
cp "$WORKLOAD_LOCK_SOURCE" "$workload_lock_snapshot"
cp "$AUTHORITY_SOURCE" "$authority_snapshot"
chmod 600 "$ssh_key" "$known_hosts" "$recovery_private_key"
"$OPENSSL" pkey -in "$recovery_private_key" -check -noout >/dev/null 2>&1 \
  || fail "V1 recovery private key is not a valid private key." 65
chmod 400 "$compose_wrapper_snapshot" "$controller_snapshot" "$installer_snapshot" "$reconciler_snapshot" "$evidence_producer_snapshot" "$sudoers_snapshot" "$unit_snapshot" "$recovery_cert_snapshot" "$workload_lock_snapshot" "$authority_snapshot"
[ "$(hash_file "$SSH_KEY_SOURCE")" = "$key_before" ] \
  && [ "$(hash_file "$ssh_key")" = "$key_before" ] \
  || fail "SSH private key changed during stable capture." 65
[ "$(hash_file "$KNOWN_HOSTS_SOURCE")" = "$known_before" ] \
  && [ "$(hash_file "$known_hosts")" = "$known_before" ] \
  || fail "SSH known-hosts input changed during stable capture." 65
[ "$(hash_file "$RECOVERY_PRIVATE_KEY_SOURCE")" = "$recovery_private_key_before" ] \
  && [ "$(hash_file "$recovery_private_key")" = "$recovery_private_key_before" ] \
  || fail "V1 recovery private key changed during stable capture." 65
[ "$(hash_file "$COMPOSE_WRAPPER_SOURCE")" = "$compose_wrapper_before" ] \
  && [ "$(hash_file "$compose_wrapper_snapshot")" = "$compose_wrapper_before" ] \
  || fail "V1 LOCAL_PRIVATE Compose wrapper source changed during stable capture." 65
[ "$(hash_file "$CONTROLLER_SOURCE")" = "$controller_before" ] \
  && [ "$(hash_file "$controller_snapshot")" = "$controller_before" ] \
  || fail "V1 LOCAL_PRIVATE controller source changed during stable capture." 65
[ "$(hash_file "$INSTALLER_SOURCE")" = "$installer_before" ] \
  && [ "$(hash_file "$installer_snapshot")" = "$installer_before" ] \
  || fail "V1 LOCAL_PRIVATE installer source changed during stable capture." 65
[ "$(hash_file "$RECONCILER_SOURCE")" = "$reconciler_before" ] \
  && [ "$(hash_file "$reconciler_snapshot")" = "$reconciler_before" ] \
  || fail "V1 LOCAL_PRIVATE reconciler source changed during stable capture." 65
[ "$(hash_file "$EVIDENCE_PRODUCER_SOURCE")" = "$evidence_producer_before" ] \
  && [ "$(hash_file "$evidence_producer_snapshot")" = "$evidence_producer_before" ] \
  || fail "V1 LOCAL_PRIVATE evidence producer source changed during stable capture." 65
[ "$(hash_file "$SUDOERS_SOURCE")" = "$sudoers_before" ] \
  && [ "$(hash_file "$sudoers_snapshot")" = "$sudoers_before" ] \
  || fail "V1 LOCAL_PRIVATE sudoers source changed during stable capture." 65
[ "$(hash_file "$UNIT_SOURCE")" = "$unit_before" ] \
  && [ "$(hash_file "$unit_snapshot")" = "$unit_before" ] \
  || fail "V1 LOCAL_PRIVATE systemd unit source changed during stable capture." 65
[ "$(hash_file "$RECOVERY_CERT_SOURCE")" = "$recovery_cert_before" ] \
  && [ "$(hash_file "$recovery_cert_snapshot")" = "$recovery_cert_before" ] \
  || fail "V1 recovery escrow certificate source changed during stable capture." 65
[ "$(hash_file "$WORKLOAD_LOCK_SOURCE")" = "$workload_lock_before" ] \
  && [ "$(hash_file "$workload_lock_snapshot")" = "$workload_lock_before" ] \
  || fail "V1 LOCAL_PRIVATE workload lock source changed during stable capture." 65
[ "$(hash_file "$AUTHORITY_SOURCE")" = "$authority_before" ] \
  && [ "$(hash_file "$authority_snapshot")" = "$authority_before" ] \
  || fail "V1 exact release authority changed during stable capture." 65
COMPOSE_WRAPPER_SHA256=$compose_wrapper_before
CONTROLLER_SHA256=$controller_before
INSTALLER_SHA256=$installer_before
RECONCILER_SHA256=$reconciler_before
EVIDENCE_PRODUCER_SHA256=$evidence_producer_before
SUDOERS_SHA256=$sudoers_before
UNIT_SHA256=$unit_before
RECOVERY_CERT_SHA256=$recovery_cert_before
WORKLOAD_LOCK_SHA256=$workload_lock_before
AUTHORITY_SHA256=$authority_before

HEAD_COMMIT=$("$GIT" -C "$REPOSITORY_ROOT" rev-parse --verify 'HEAD^{commit}')
HEAD_TREE=$("$GIT" -C "$REPOSITORY_ROOT" rev-parse --verify 'HEAD^{tree}')
GITHUB_MAIN_COMMIT=$("$GIT" -C "$REPOSITORY_ROOT" rev-parse --verify refs/remotes/github/main)
GIT_STATUS=$("$GIT" -C "$REPOSITORY_ROOT" status --porcelain=v1 --untracked-files=all)
[ -z "$GIT_STATUS" ] || fail "The deploy checkout is not clean." 65
[ "$HEAD_COMMIT" = "$GITHUB_MAIN_COMMIT" ] || fail "The deploy checkout HEAD is not exact refs/remotes/github/main." 65

# Validate the captured authority before crossing the activation boundary. The
# caller-selected local path never crosses SSH; only these immutable bytes bind
# the clean checkout and the controller/sudoers/unit sources used for verification.
"$NODE" --input-type=module - \
  "$AUTHORITY_SOURCE" "$authority_snapshot" "$HEAD_COMMIT" "$HEAD_TREE" \
  "$COMPOSE_WRAPPER_SHA256" "$CONTROLLER_SHA256" "$INSTALLER_SHA256" \
  "$RECONCILER_SHA256" "$EVIDENCE_PRODUCER_SHA256" "$SUDOERS_SHA256" "$UNIT_SHA256" \
  "$RECOVERY_CERT_SHA256" "$recovery_cert_snapshot" "$WORKLOAD_LOCK_SHA256" <<'NODE'
import crypto from "node:crypto";
import fs from "node:fs";

const [sourcePath, snapshotPath, headCommit, headTree, composeWrapperSha256, controllerSha256,
  installerSha256, reconcilerSha256, evidenceProducerSha256, sudoersSha256, unitSha256,
  recoveryCertSha256, recoveryCertPath, workloadLockSha256] = process.argv.slice(2);
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const stableJson = (value) => Array.isArray(value)
  ? `[${value.map(stableJson).join(",")}]`
  : value && typeof value === "object"
    ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`
    : JSON.stringify(value);
const fail = (message) => { throw new Error(message); };
const exactObject = (value, fields, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || stableJson(Object.keys(value).sort()) !== stableJson([...fields].sort())) {
    fail(`${label} has missing or unexpected fields.`);
  }
  return value;
};
const sha = (value, label) => {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) fail(`${label} is invalid.`);
};
const commit = (value, label) => {
  if (typeof value !== "string" || !/^[a-f0-9]{40}$/.test(value)) fail(`${label} is invalid.`);
};

for (const [filename, label] of [[sourcePath, "source"], [snapshotPath, "snapshot"]]) {
  const metadata = fs.lstatSync(filename);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1
    || metadata.size < 2 || metadata.size > 128 * 1024 || (metadata.mode & 0o222) !== 0) {
    fail(`V1 exact release authority ${label} identity is invalid.`);
  }
}
const source = fs.readFileSync(sourcePath);
const raw = fs.readFileSync(snapshotPath);
if (!source.equals(raw)) fail("V1 exact release authority snapshot differs from its source bytes.");
let authority;
try { authority = JSON.parse(raw.toString("utf8")); } catch { fail("V1 exact release authority is not strict JSON."); }
if (`${stableJson(authority)}\n` !== raw.toString("utf8")) fail("V1 exact release authority is not canonical JSON.");
exactObject(authority, [
  "activeManagedContainerNames", "artifacts", "authorityMode", "authorizedDataMutations", "backupToolImages", "candidateCommit",
  "candidateTree", "checkoutProof", "controllerVerificationScope", "disabledComposeServices", "documentId", "evidenceProducer",
  "expectedContainerNames", "legacyNetworkAttachments", "legacyRouteChecks", "legacyUnmanagedContainers", "preservedLegacyContainerNames",
  "recoveryEscrowCertificate", "releaseRoot", "renderEnvironment", "renderSha256", "runtimeIdentity", "schema", "serviceTargets",
  "sourceArchiveSha256", "status",
], "V1 exact release authority");
const withoutId = { ...authority };
delete withoutId.documentId;
if (authority.documentId !== sha256(stableJson(withoutId))
  || authority.schema !== "platform.v1-local-private-exact-release-authority/v1"
  || authority.status !== "AUTHORIZED"
  || authority.authorityMode !== "LOCAL_PRIVATE") {
  fail("V1 exact release authority identity/status is invalid.");
}
commit(authority.candidateCommit, "Authority candidate commit");
commit(authority.candidateTree, "Authority candidate tree");
sha(authority.sourceArchiveSha256, "Authority source archive");
sha(authority.renderSha256, "Authority render");
if (authority.candidateCommit !== headCommit || authority.candidateTree !== headTree) {
  fail("V1 exact release authority differs from the clean deploy checkout.");
}
if (authority.releaseRoot !== `/srv/platform-infrastructure/releases/${authority.candidateCommit}-${authority.sourceArchiveSha256}`
  || authority.controllerVerificationScope !== "AUTHORITY_ARCHIVE_RELEASE_RENDER_ONLY_NOT_GITHUB") {
  fail("V1 exact release authority release binding is invalid.");
}
const exactSortedStrings = (value, label) => {
  if (!Array.isArray(value) || value.length === 0
    || value.some((entry) => typeof entry !== "string" || entry.length === 0)
    || stableJson(value) !== stableJson([...new Set(value)].sort())) {
    fail(`${label} is not a non-empty, unique, canonically sorted string set.`);
  }
  return value;
};
const active = exactSortedStrings(authority.activeManagedContainerNames, "V1 authority active managed containers");
const preserved = exactSortedStrings(authority.preservedLegacyContainerNames, "V1 authority preserved legacy containers");
const expected = exactSortedStrings(authority.expectedContainerNames, "V1 authority expected containers");
if (stableJson([...new Set([...active, ...preserved])].sort()) !== stableJson(expected)) {
  fail("V1 authority expected containers are not the exact active/preserved union.");
}
const legacyReasons = new Set([
  "NO_HOSTED_WORKLOAD_AUTHORITY", "COMPOSE_PROFILE_ADMIN_DISABLED", "COMPOSE_PROFILE_DNS_DISABLED",
  "COMPOSE_PROFILE_RAW_HOST_METRICS_DISABLED", "COMPOSE_PROFILE_LOCAL_RUNTIME_DISABLED",
  "COMPOSE_PROFILE_LEGACY_SHARED_RUNTIME_DISABLED",
]);
if (!Array.isArray(authority.legacyUnmanagedContainers) || authority.legacyUnmanagedContainers.length !== 19) {
  fail("V1 authority legacy unmanaged set is not the exact nineteen-container set.");
}
const legacyNames = authority.legacyUnmanagedContainers.map((rawLegacy, index) => {
  const legacy = exactObject(rawLegacy, ["containerName", "reason", "status"], `V1 authority legacy unmanaged container ${index}`);
  if (!preserved.includes(legacy.containerName) || legacy.status !== "LEGACY_UNMANAGED" || !legacyReasons.has(legacy.reason)) {
    fail("V1 authority contains an invalid legacy unmanaged container classification.");
  }
  return legacy.containerName;
});
if (stableJson(legacyNames) !== stableJson(preserved)) {
  fail("V1 authority legacy unmanaged containers are not canonically aligned with the preserved set.");
}
if (!Array.isArray(authority.serviceTargets) || authority.serviceTargets.length !== active.length) {
  fail("V1 authority service targets do not cover the active managed set.");
}
const targetServices = new Set();
const targetContainers = authority.serviceTargets.map((rawTarget, index) => {
  const target = exactObject(rawTarget, ["configHash", "containerName", "project", "semantic", "service"], `V1 authority service target ${index}`);
  sha(target.configHash, `V1 authority service target ${index} Compose config hash`);
  if (!active.includes(target.containerName) || typeof target.project !== "string" || target.project.length === 0
    || typeof target.service !== "string" || !/^[A-Za-z0-9_.-]+$/.test(target.service)
    || !target.semantic || typeof target.semantic !== "object" || Array.isArray(target.semantic)
    || targetServices.has(target.service)) {
    fail("V1 authority contains an invalid or duplicated service target.");
  }
  targetServices.add(target.service);
  return target.containerName;
});
if (stableJson(targetContainers) !== stableJson(active)) {
  fail("V1 authority service targets are not canonically aligned with active containers.");
}
const runtimeIdentity = exactObject(authority.runtimeIdentity, [
  "candidateId", "commit", "deploymentId", "sourceRenderSha256", "tree", "workloadLockSha256",
], "V1 exact release runtime identity");
commit(runtimeIdentity.commit, "V1 runtime identity commit");
commit(runtimeIdentity.tree, "V1 runtime identity tree");
sha(runtimeIdentity.candidateId, "V1 runtime candidate ID");
sha(runtimeIdentity.sourceRenderSha256, "V1 runtime source render");
sha(runtimeIdentity.workloadLockSha256, "V1 runtime workload lock");
const runtimeSeed = {
  candidateCommit: authority.candidateCommit,
  candidateTree: authority.candidateTree,
  sourceRenderSha256: runtimeIdentity.sourceRenderSha256,
  workloadLockSha256: runtimeIdentity.workloadLockSha256,
};
if (runtimeIdentity.commit !== authority.candidateCommit || runtimeIdentity.tree !== authority.candidateTree
  || runtimeIdentity.candidateId !== sha256(stableJson(runtimeSeed))
  || runtimeIdentity.deploymentId !== `v1-local-private:${runtimeIdentity.candidateId}`) {
  fail("V1 exact release runtime identity is not derived from candidate/tree/source-render/workload-lock.");
}
if (runtimeIdentity.workloadLockSha256 !== workloadLockSha256) {
  fail("Exact-main LOCAL_PRIVATE workload-lock bytes differ from runtime identity.");
}
const backupToolImageKeys = ["mariadbRestore", "minioRestore", "nodeUtility", "postgresRestore", "resticRclone"];
const backupToolImages = exactObject(authority.backupToolImages, backupToolImageKeys, "V1 backup tool images");
for (const name of backupToolImageKeys) {
  const image = exactObject(backupToolImages[name], ["imageId", "imageReference"], `V1 backup tool image ${name}`);
  if (typeof image.imageId !== "string" || !/^sha256:[a-f0-9]{64}$/.test(image.imageId)
    || typeof image.imageReference !== "string" || !/^[^@\s]+@sha256:[a-f0-9]{64}$/.test(image.imageReference)) {
    fail(`V1 backup tool image ${name} binding is invalid.`);
  }
}
const evidenceLogicalKeys = ["anniversary", "fiplatform", "matthewdifilippo", "opstudents", "public", "stexor", "stream", "workcalendar", "pg-stexor", "pg-keycloak", "mariadb", "minio", "keycloak-config", "confidential"];
const producer = exactObject(authority.evidenceProducer, [
  "executor", "executorFlags", "forbiddenResticOperations", "hostingerAllowed", "logicalKeys",
  "offsiteRepository", "operations", "path", "recoveryEscrowPrefix", "sha256",
], "V1 evidence producer");
if (producer.executor !== "/usr/bin/python3"
  || stableJson(producer.executorFlags) !== stableJson(["-I"])
  || stableJson(producer.forbiddenResticOperations) !== stableJson(["forget", "prune"])
  || producer.hostingerAllowed !== false
  || stableJson(producer.logicalKeys) !== stableJson(evidenceLogicalKeys)
  || producer.offsiteRepository !== "rclone:platform-onedrive:platform-infrastructure/restic"
  || stableJson(producer.operations) !== stableJson(["pre", "post"])
  || producer.path !== authority.releaseRoot + "/scripts/v1-local-private-evidence-producer.py"
  || producer.recoveryEscrowPrefix !== "platform-onedrive:platform-infrastructure/key-escrow"
  || producer.sha256 !== evidenceProducerSha256) {
  fail("Exact-main evidence producer differs from the V1 exact release authority.");
}
const recoveryCertificate = exactObject(authority.recoveryEscrowCertificate, ["path", "sha256", "sha256Fingerprint"], "V1 recovery escrow certificate");
if (recoveryCertificate.path !== `${authority.releaseRoot}/config/local-private-recovery-escrow-cert.pem`
  || recoveryCertificate.sha256 !== recoveryCertSha256 || sha256(fs.readFileSync(recoveryCertPath)) !== recoveryCertSha256
  || typeof recoveryCertificate.sha256Fingerprint !== "string" || !/^[a-f0-9]{64}$/.test(recoveryCertificate.sha256Fingerprint)) {
  fail("Exact-main recovery escrow certificate differs from the V1 exact release authority.");
}
const parsedRecoveryCertificate = new crypto.X509Certificate(fs.readFileSync(recoveryCertPath));
if (parsedRecoveryCertificate.fingerprint256.replaceAll(":", "").toLowerCase() !== recoveryCertificate.sha256Fingerprint) {
  fail("Exact-main recovery escrow certificate DER fingerprint differs from authority.");
}
const proof = exactObject(authority.checkoutProof,
  ["clean", "githubMainCommit", "githubMainRef", "headCommit", "headTree", "producer", "status", "verifiedAtUnixSeconds"],
  "V1 exact release checkout proof");
if (proof.clean !== true || proof.status !== "PASS" || proof.producer !== "CLEAN_CHECKOUT_GITHUB_MAIN_V1"
  || proof.githubMainRef !== "refs/remotes/github/main" || proof.githubMainCommit !== authority.candidateCommit
  || proof.headCommit !== authority.candidateCommit || proof.headTree !== authority.candidateTree
  || !Number.isInteger(proof.verifiedAtUnixSeconds)) {
  fail("V1 exact release checkout proof is invalid.");
}
const artifacts = exactObject(authority.artifacts,
  ["composeWrapper", "controller", "installer", "reconciler", "sudoers", "unit"], "V1 exact release artifacts");
const expectedPaths = {
  composeWrapper: `${authority.releaseRoot}/scripts/compose-vps.sh`,
  controller: "/usr/local/libexec/platform-v1-local-private-control",
  installer: "/usr/local/libexec/platform-v1-brownfield-install-consumer",
  reconciler: "/usr/local/libexec/platform-v1-local-private-reconcile",
  sudoers: "/etc/sudoers.d/platform-v1-local-private-control",
  unit: "/etc/systemd/system/platform-v1-local-private-control.service",
};
for (const [name, artifact] of Object.entries(artifacts)) {
  exactObject(artifact, ["path", "sha256"], `V1 exact release ${name} artifact`);
  sha(artifact.sha256, `V1 exact release ${name} artifact`);
  if (artifact.path !== expectedPaths[name]) fail(`V1 exact release ${name} artifact path is invalid.`);
}
const expectedHashes = {
  composeWrapper: composeWrapperSha256,
  controller: controllerSha256,
  installer: installerSha256,
  reconciler: reconcilerSha256,
  sudoers: sudoersSha256,
  unit: unitSha256,
};
for (const [name, expectedHash] of Object.entries(expectedHashes)) {
  if (artifacts[name].sha256 !== expectedHash) {
    fail(`Exact-main ${name} source bytes differ from the V1 exact release authority.`);
  }
}
NODE

sh "$SCRIPT_ROOT/ssh-known-host-endpoint.sh" "$REMOTE_HOST" "$SSH_PORT" "$known_hosts"
"$NODE" "$SCRIPT_ROOT/pinned-ssh-host-key.mjs" verify \
  --remote "$REMOTE" \
  --port "$SSH_PORT" \
  --file "$known_hosts" >/dev/null || fail "Pinned SSH host trust validation failed." 65

remote_once() {
  REMOTE_COMMAND=$1
  set -- \
    -F /dev/null \
    -i "$ssh_key" \
    -p "$SSH_PORT" \
    -o BatchMode=yes \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=yes \
    -o "UserKnownHostsFile=$known_hosts" \
    -o GlobalKnownHostsFile=/dev/null \
    -o UpdateHostKeys=no \
    -o PermitLocalCommand=no \
    -o ClearAllForwardings=yes \
    -o ExitOnForwardFailure=yes
  exec "$SSH" "$@" -- "$REMOTE" "$REMOTE_COMMAND" < /dev/null
}

capture_remote() {
  capture_attempts=$1
  capture_label=$2
  capture_command=$3
  capture_output=$4
  capture_limit=$5
  capture_blocks=$(( (capture_limit + 511) / 512 ))
  capture_attempt=1
  while [ "$capture_attempt" -le "$capture_attempts" ]; do
    capture_temporary="$capture_output.attempt"
    rm -f "$capture_temporary"
    if (
      ulimit -f "$capture_blocks"
      remote_once "$capture_command"
    ) > "$capture_temporary"; then
      [ -f "$capture_temporary" ] && [ ! -L "$capture_temporary" ] && [ -s "$capture_temporary" ] \
        || fail "$capture_label returned no authenticated response." 65
      capture_size=$(wc -c < "$capture_temporary" | tr -d '[:space:]')
      case "$capture_size" in ""|*[!0-9]*) fail "$capture_label response size is invalid." 65 ;; esac
      [ "$capture_size" -le "$capture_limit" ] || fail "$capture_label response exceeds its fixed boundary." 65
      mv "$capture_temporary" "$capture_output"
      chmod 400 "$capture_output"
      return 0
    fi
    rm -f "$capture_temporary"
    capture_attempt=$((capture_attempt + 1))
  done
  return 1
}

validate_protocol_json() {
  protocol_file=$1
  protocol_kind=$2
  protocol_peer=${3:-}
  "$NODE" --input-type=module -e '
import crypto from "node:crypto";
import fs from "node:fs";
const [filename, kind, authorityPath, authoritySha, peerPath] = process.argv.slice(1);
const exactStable = (v) => {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") return JSON.stringify(v);
  if (typeof v === "object" && v !== null && typeof v.__rawNumber === "string") return v.__rawNumber;
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(exactStable).join(",")}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${exactStable(v[k])}`).join(",")}}`;
};
const exactParse = (text) => {
  let i = 0;
  const ws = () => { while (i < text.length && " \t\n\r".includes(text[i])) i++; };
  const string_ = () => {
    if (text[i] !== "\"") throw new Error("q");
    i++; let out = "";
    while (i < text.length) {
      const c = text[i];
      if (c === "\"") { i++; return out; }
      if (c === "\\") {
        i++; const e = text[i];
        if (e === "u") { out += String.fromCharCode(parseInt(text.slice(i + 1, i + 5), 16)); i += 5; continue; }
        out += { b: "\\b", f: "\\f", n: "\\n", r: "\\r", t: "\\t" }[e] ?? e; i++; continue;
      }
      out += c; i++;
    }
    throw new Error("q");
  };
  const value = () => {
    ws(); const c = text[i];
    if (c === "{") {
      i++; const obj = {}; ws();
      if (text[i] === "}") { i++; return obj; }
      for (;;) { ws(); const key = string_(); ws(); if (text[i] !== ":") throw new Error("q"); i++; obj[key] = value(); ws();
        if (text[i] === ",") { i++; continue; } if (text[i] !== "}") throw new Error("q"); i++; return obj; }
    }
    if (c === "[") {
      i++; const arr = []; ws();
      if (text[i] === "]") { i++; return arr; }
      for (;;) { arr.push(value()); ws();
        if (text[i] === ",") { i++; continue; } if (text[i] !== "]") throw new Error("q"); i++; return arr; }
    }
    if (c === "\"") return string_();
    if (text.startsWith("true", i)) { i += 4; return true; }
    if (text.startsWith("false", i)) { i += 5; return false; }
    if (text.startsWith("null", i)) { i += 4; return null; }
    const start = i;
    while (i < text.length && /[-+0-9.eE]/.test(text[i])) i++;
    if (start === i) throw new Error("q");
    return { __rawNumber: text.slice(start, i) };
  };
  const out = value(); ws();
  if (i !== text.length) throw new Error("q");
  return out;
};
const stable = (v) => exactStable(v);
const parse = (pathname, label) => { const raw = fs.readFileSync(pathname); const value = exactParse(raw.toString()); if (raw.toString() !== `${stable(value)}\n`) throw new Error(`${label} is not canonical JSON.`); return value; };
const authority = parse(authorityPath, "authority");
const value = parse(filename, kind);
const sha = /^[a-f0-9]{64}$/;
if (kind === "validation-mode") {
  if (stable(Object.keys(value).sort()) !== stable(["candidateCommit", "schema", "status"].sort())
    || value.schema !== "platform.v1-local-private-validation-mode/v1"
    || value.candidateCommit !== authority.candidateCommit
    || !["PRODUCTION", "VALIDATION"].includes(value.status)) throw new Error("controller validation mode is not exact-authority-bound.");
  process.stdout.write(`${value.status}\n`);
} else if (kind === "begin") {
  if (value.schema !== "platform.v1-local-private-reconciliation/v1" || value.status !== "RECONCILING"
    || value.candidateCommit !== authority.candidateCommit || value.candidateTree !== authority.candidateTree
    || value.sourceArchiveSha256 !== authority.sourceArchiveSha256 || value.releaseRoot !== authority.releaseRoot
    || value.releaseAuthorityDocumentId !== authority.documentId || value.releaseAuthoritySha256 !== authoritySha) throw new Error("begin-maintenance is not authority-bound.");
} else if (kind === "apply" || kind === "apply-validation") {
  const expectedStatus = kind === "apply-validation" ? "VALIDATED_NO_MUTATION" : "APPLIED";
  if (stable(Object.keys(value).sort()) !== stable(["authorityDocumentId", "status", "transactionId"].sort())
    || value.authorityDocumentId !== authority.documentId || value.status !== expectedStatus || !sha.test(value.transactionId)) throw new Error("apply response is not transaction-bound.");
} else if (kind === "evidence") {
  if (stable(Object.keys(value).sort()) !== stable(["evidencePath", "evidenceSha256", "status"].sort())
    || value.evidencePath !== "/var/lib/platform-infrastructure/v1/predeploy/current/runtime-inventory-evidence.json"
    || value.status !== "PASS" || !sha.test(value.evidenceSha256)) throw new Error("evidence response is not canonical PASS evidence.");
} else if (kind === "evidence-validation") {
  const peer = parse(peerPath, "validation apply response");
  if (stable(Object.keys(peer).sort()) !== stable(["authorityDocumentId", "status", "transactionId"].sort())
    || peer.authorityDocumentId !== authority.documentId || peer.status !== "VALIDATED_NO_MUTATION" || !sha.test(peer.transactionId)
    || stable(Object.keys(value).sort()) !== stable(["evidencePath", "evidenceSha256", "status", "transactionId"].sort())
    || value.transactionId !== peer.transactionId
    || value.evidencePath !== `/var/lib/platform-infrastructure/v1/predeploy/current/runtime-inventory-evidence-validation-${value.transactionId}.json`
    || value.status !== "VALIDATION" || !sha.test(value.evidenceSha256)) throw new Error("validation evidence response is not canonical transaction-bound VALIDATION evidence.");
} else if (kind === "abort-record" || kind === "abort-record-no-data" || kind === "abort-record-no-data-after-apply" || kind === "abort-record-no-data-unbound") {
  if (stable(Object.keys(value).sort()) !== stable(["abortRecordPath", "abortRecordSha256", "authorityDocumentId", "status", "transactionId"].sort())
    || value.authorityDocumentId !== authority.documentId || !sha.test(value.transactionId)
    || !["ABORTED_NO_DATA_MUTATION", "ABORTED_WITH_RESIDUAL_DATA_MUTATIONS"].includes(value.status)
    || !sha.test(value.abortRecordSha256)
    || value.abortRecordPath !== `/var/lib/platform-infrastructure/v1/local-private/aborted-reconciliations/${value.transactionId}-${value.abortRecordSha256}.json`) throw new Error("abort response is not record-bound.");
  if (kind === "abort-record-no-data") {
    const peer = parse(peerPath, "validation evidence response");
    if (value.status !== "ABORTED_NO_DATA_MUTATION"
      || stable(Object.keys(peer).sort()) !== stable(["evidencePath", "evidenceSha256", "status", "transactionId"].sort())
      || peer.status !== "VALIDATION" || !sha.test(peer.evidenceSha256) || !sha.test(peer.transactionId)
      || peer.evidencePath !== `/var/lib/platform-infrastructure/v1/predeploy/current/runtime-inventory-evidence-validation-${peer.transactionId}.json`
      || value.transactionId !== peer.transactionId) throw new Error("validation abort is not bound to its no-mutation evidence transaction.");
  } else if (kind === "abort-record-no-data-after-apply") {
    const peer = parse(peerPath, "validation apply response");
    if (value.status !== "ABORTED_NO_DATA_MUTATION"
      || stable(Object.keys(peer).sort()) !== stable(["authorityDocumentId", "status", "transactionId"].sort())
      || peer.authorityDocumentId !== authority.documentId || peer.status !== "VALIDATED_NO_MUTATION" || !sha.test(peer.transactionId)
      || value.transactionId !== peer.transactionId) throw new Error("validation abort is not bound to its no-mutation apply transaction.");
  } else if (kind === "abort-record-no-data-unbound" && value.status !== "ABORTED_NO_DATA_MUTATION") {
    throw new Error("validation abort without a trusted apply response retained a data mutation.");
  }
} else if (kind === "aborted-active") {
  const aborted = value.abortedAuthorizedReconciliation;
  const peer = parse(peerPath, "abort record response");
  if (value.schema !== "platform.v1-local-private-control-receipt/v1" || value.status !== "ACTIVE"
    || value.candidateCommit !== authority.candidateCommit || value.candidateTree !== authority.candidateTree
    || !aborted || aborted.authorityDocumentId !== authority.documentId || aborted.authoritySha256 !== authoritySha
    || aborted.transactionId !== peer.transactionId || aborted.recordSha256 !== peer.abortRecordSha256
    || aborted.recordPath !== peer.abortRecordPath || aborted.status !== peer.status) throw new Error("post-abort ACTIVE receipt is not authority/record-bound.");
} else if (kind === "abort-finalized") {
  const peer = parse(peerPath, "abort record response");
  const finalized = value.authorityDocumentId === authority.documentId && value.status === "ABORT_FINALIZED"
    && value.transactionId === peer.transactionId && value.recordArchivePath === peer.abortRecordPath
    && typeof value.journalArchivePath === "string"
    && value.journalArchivePath.startsWith(`/var/lib/platform-infrastructure/v1/local-private/reconcile-journals/${peer.transactionId}-`)
    && value.journalArchivePath.endsWith(".json");
  const alreadyClean = stable(Object.keys(value).sort()) === stable(["authorityDocumentId", "status", "transactionId"].sort())
    && value.authorityDocumentId === authority.documentId && value.status === "ABORTED" && value.transactionId === null;
  if (!finalized && !alreadyClean) throw new Error("second abort did not finalize the exact transaction.");
} else if (kind === "validation-close") {
  const peer = parse(peerPath, "validation abort response");
  if (stable(Object.keys(value).sort()) !== stable([
      "authorityDocumentId", "authoritySha256", "candidateCommit", "schema", "status",
      "transactionId", "validationLaneSha256",
    ].sort())
    || value.schema !== "platform.v1-local-private-validation-lane-close-result/v1"
    || value.status !== "VALIDATION_LANE_CLOSED"
    || value.authorityDocumentId !== authority.documentId
    || value.authoritySha256 !== authoritySha
    || value.candidateCommit !== authority.candidateCommit
    || value.transactionId !== peer.transactionId
    || peer.status !== "ABORTED_NO_DATA_MUTATION"
    || !sha.test(value.validationLaneSha256)) throw new Error("validation lane closure is not authority/abort-bound.");
} else if (kind === "reconciling-or-active") {
  if (value.status === "ACTIVE") {
    const external = value.externalAuthorizedReconciliation;
    if (!external || external.status !== "SEALED" || external.releaseAuthorityDocumentId !== authority.documentId
      || external.releaseAuthoritySha256 !== authoritySha) throw new Error("ACTIVE response is not sealed to authority.");
    process.stdout.write("ACTIVE\n");
  } else if (value.status === "RECONCILING" && value.schema === "platform.v1-local-private-reconciliation/v1"
    && value.releaseAuthorityDocumentId === authority.documentId && value.releaseAuthoritySha256 === authoritySha) {
    process.stdout.write("RECONCILING\n");
  } else throw new Error("controller response is neither bound ACTIVE nor bound RECONCILING.");
} else throw new Error("unknown local protocol validation kind");
' "$protocol_file" "$protocol_kind" "$authority_snapshot" "$AUTHORITY_SHA256" "$protocol_peer"
}

verify_cms_evidence() {
  cms_phase=$1
  cms_offhost=$2
  cms_secrets=$3
  # The first Node process emits only verified CMS ciphertext. OpenSSL emits
  # plaintext only into the pipe consumed by the second Node process; neither
  # recovery credential is ever written to disk or printed.
  "$NODE" --input-type=module -e '
import crypto from "node:crypto";
import fs from "node:fs";
const [authorityPath, offhostPath, secretsPath, phase, authoritySha] = process.argv.slice(1);
const exactStable = (v) => {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") return JSON.stringify(v);
  if (typeof v === "object" && v !== null && typeof v.__rawNumber === "string") return v.__rawNumber;
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(exactStable).join(",")}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${exactStable(v[k])}`).join(",")}}`;
};
const exactParse = (text) => {
  let i = 0;
  const ws = () => { while (i < text.length && " \t\n\r".includes(text[i])) i++; };
  const string_ = () => {
    if (text[i] !== "\"") throw new Error("q");
    i++; let out = "";
    while (i < text.length) {
      const c = text[i];
      if (c === "\"") { i++; return out; }
      if (c === "\\") {
        i++; const e = text[i];
        if (e === "u") { out += String.fromCharCode(parseInt(text.slice(i + 1, i + 5), 16)); i += 5; continue; }
        out += { b: "\\b", f: "\\f", n: "\\n", r: "\\r", t: "\\t" }[e] ?? e; i++; continue;
      }
      out += c; i++;
    }
    throw new Error("q");
  };
  const value = () => {
    ws(); const c = text[i];
    if (c === "{") {
      i++; const obj = {}; ws();
      if (text[i] === "}") { i++; return obj; }
      for (;;) { ws(); const key = string_(); ws(); if (text[i] !== ":") throw new Error("q"); i++; obj[key] = value(); ws();
        if (text[i] === ",") { i++; continue; } if (text[i] !== "}") throw new Error("q"); i++; return obj; }
    }
    if (c === "[") {
      i++; const arr = []; ws();
      if (text[i] === "]") { i++; return arr; }
      for (;;) { arr.push(value()); ws();
        if (text[i] === ",") { i++; continue; } if (text[i] !== "]") throw new Error("q"); i++; return arr; }
    }
    if (c === "\"") return string_();
    if (text.startsWith("true", i)) { i += 4; return true; }
    if (text.startsWith("false", i)) { i += 5; return false; }
    if (text.startsWith("null", i)) { i += 4; return null; }
    const start = i;
    while (i < text.length && /[-+0-9.eE]/.test(text[i])) i++;
    if (start === i) throw new Error("q");
    return { __rawNumber: text.slice(start, i) };
  };
  const out = value(); ws();
  if (i !== text.length) throw new Error("q");
  return out;
};
const stable = (v) => exactStable(v);
const read = (p, label) => { const raw = fs.readFileSync(p); const v = exactParse(raw.toString()); if (raw.toString() !== `${stable(v)}\n`) throw new Error(`${label} is not canonical JSON.`); return { raw, v }; };
const authorityRead = read(authorityPath, "authority"); const authority = authorityRead.v;
const offhost = read(offhostPath, "off-host evidence").v; const secrets = read(secretsPath, "secrets evidence").v;
const common = ["artifactSetSha256", "authorityDocumentId", "authoritySha256", "backupSetSha256", "backupToolImages", "candidateCommit", "candidateTree", "evidencePhase", "reconciliationSha256", "runId", "sourceArchiveSha256", "transactionId"];
for (const key of common) if (stable(offhost[key]) !== stable(secrets[key])) throw new Error(`evidence common binding differs at ${key}.`);
if (offhost.schema !== "platform.v1-local-private-offhost-backup-evidence/v1" || secrets.schema !== "platform.v1-local-private-secrets-backup-evidence/v1"
  || offhost.status !== "PASS" || secrets.status !== "PASS" || offhost.evidencePhase !== phase
  || offhost.authorityDocumentId !== authority.documentId || offhost.authoritySha256 !== authoritySha
  || offhost.candidateCommit !== authority.candidateCommit || offhost.candidateTree !== authority.candidateTree
  || offhost.sourceArchiveSha256 !== authority.sourceArchiveSha256
  || offhost.repository !== "rclone:platform-onedrive:platform-infrastructure/restic" || offhost.repositoryProvider !== "OneDrive"
  || offhost.hostingerUsed !== false || offhost.noPrune !== true || offhost.retentionSkipped !== true
  || secrets.plaintextTemporaryStateAbsent !== true || secrets.secretValuesRecorded !== false) throw new Error("evidence/provider/candidate binding is invalid.");
const id = /^[a-f0-9]{64}$/; const run = /^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$/;
if (!run.test(offhost.runId) || (phase === "PRE" ? offhost.transactionId !== null || offhost.reconciliationSha256 !== null : !id.test(offhost.transactionId) || !id.test(offhost.reconciliationSha256))) throw new Error("evidence phase transaction binding is invalid.");
const escrow = offhost.recoveryEscrow;
if (stable(escrow) !== stable(secrets.recoveryEscrow) || !escrow || escrow.status !== "PASS" || escrow.remotePayloadByteExact !== true
  || escrow.certificateSha256 !== authority.recoveryEscrowCertificate.sha256
  || escrow.certificateSha256Fingerprint !== authority.recoveryEscrowCertificate.sha256Fingerprint
  || escrow.offHostLocation !== `platform-onedrive:platform-infrastructure/key-escrow/v1-local-private-recovery-${offhost.runId}.cms`
  || typeof escrow.ciphertextBase64 !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(escrow.ciphertextBase64)) throw new Error("CMS escrow cross-binding is invalid.");
const ciphertext = Buffer.from(escrow.ciphertextBase64, "base64");
const digest = crypto.createHash("sha256").update(ciphertext).digest("hex");
const escrowSize = typeof escrow.ciphertextSizeBytes === "object" && escrow.ciphertextSizeBytes !== null ? Number(escrow.ciphertextSizeBytes.__rawNumber) : escrow.ciphertextSizeBytes;
if (ciphertext.length < 256 || ciphertext.length > 65536 || ciphertext.length !== escrowSize || digest !== escrow.ciphertextSha256) throw new Error("CMS ciphertext identity is invalid.");
process.stdout.write(ciphertext);
' "$authority_snapshot" "$cms_offhost" "$cms_secrets" "$cms_phase" "$AUTHORITY_SHA256" \
  | "$OPENSSL" cms -decrypt -binary -inform DER -recip "$recovery_cert_snapshot" -inkey "$recovery_private_key" 2>/dev/null \
  | "$NODE" --input-type=module -e '
import fs from "node:fs";
const [authorityPath, offhostPath, phase] = process.argv.slice(1);
const exactStable = (v) => {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") return JSON.stringify(v);
  if (typeof v === "object" && v !== null && typeof v.__rawNumber === "string") return v.__rawNumber;
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(exactStable).join(",")}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${exactStable(v[k])}`).join(",")}}`;
};
const exactParse = (text) => {
  let i = 0;
  const ws = () => { while (i < text.length && " \t\n\r".includes(text[i])) i++; };
  const string_ = () => {
    if (text[i] !== "\"") throw new Error("q");
    i++; let out = "";
    while (i < text.length) {
      const c = text[i];
      if (c === "\"") { i++; return out; }
      if (c === "\\") {
        i++; const e = text[i];
        if (e === "u") { out += String.fromCharCode(parseInt(text.slice(i + 1, i + 5), 16)); i += 5; continue; }
        out += { b: "\\b", f: "\\f", n: "\\n", r: "\\r", t: "\\t" }[e] ?? e; i++; continue;
      }
      out += c; i++;
    }
    throw new Error("q");
  };
  const value = () => {
    ws(); const c = text[i];
    if (c === "{") {
      i++; const obj = {}; ws();
      if (text[i] === "}") { i++; return obj; }
      for (;;) { ws(); const key = string_(); ws(); if (text[i] !== ":") throw new Error("q"); i++; obj[key] = value(); ws();
        if (text[i] === ",") { i++; continue; } if (text[i] !== "}") throw new Error("q"); i++; return obj; }
    }
    if (c === "[") {
      i++; const arr = []; ws();
      if (text[i] === "]") { i++; return arr; }
      for (;;) { arr.push(value()); ws();
        if (text[i] === ",") { i++; continue; } if (text[i] !== "]") throw new Error("q"); i++; return arr; }
    }
    if (c === "\"") return string_();
    if (text.startsWith("true", i)) { i += 4; return true; }
    if (text.startsWith("false", i)) { i += 5; return false; }
    if (text.startsWith("null", i)) { i += 4; return null; }
    const start = i;
    while (i < text.length && /[-+0-9.eE]/.test(text[i])) i++;
    if (start === i) throw new Error("q");
    return { __rawNumber: text.slice(start, i) };
  };
  const out = value(); ws();
  if (i !== text.length) throw new Error("q");
  return out;
};
const stable = (v) => exactStable(v);
const authority = exactParse(fs.readFileSync(authorityPath).toString()); const evidence = exactParse(fs.readFileSync(offhostPath).toString()); const raw = fs.readFileSync(0);(0);
let value; try { value = exactParse(raw.toString()); } catch { throw new Error("decrypted CMS bootstrap is not JSON."); }
if (raw.toString() !== `${exactStable(value)}\n`) throw new Error("decrypted CMS bootstrap is not canonical JSON.");
const fields = ["authorityDocumentId", "candidateCommit", "candidateTree", "certificateSha256Fingerprint", "confidentialPassphrase", "phase", "reconciliationSha256", "resticPassword", "resticRepository", "runId", "schema", "sourceArchiveSha256", "transactionId"];
if (stable(Object.keys(value).sort()) !== stable(fields.sort()) || value.schema !== "platform.v1-local-private-recovery-bootstrap/v1"
  || value.authorityDocumentId !== authority.documentId || value.candidateCommit !== authority.candidateCommit || value.candidateTree !== authority.candidateTree
  || value.sourceArchiveSha256 !== authority.sourceArchiveSha256 || value.certificateSha256Fingerprint !== authority.recoveryEscrowCertificate.sha256Fingerprint
  || value.phase !== phase || value.runId !== evidence.runId || value.transactionId !== evidence.transactionId || value.reconciliationSha256 !== evidence.reconciliationSha256
  || value.resticRepository !== "rclone:platform-onedrive:platform-infrastructure/restic") throw new Error("decrypted CMS bootstrap binding is invalid.");
for (const key of ["confidentialPassphrase", "resticPassword"]) if (typeof value[key] !== "string" || value[key].length < 16 || value[key].length > 4096 || /[\r\n]/.test(value[key])) throw new Error("decrypted CMS credential shape is invalid.");
process.stdout.write("CMS_RECOVERY_BINDING_PASS\n");
' "$authority_snapshot" "$cms_offhost" "$cms_phase" | grep -qx 'CMS_RECOVERY_BINDING_PASS'
}

fetch_and_verify_cms() {
  evidence_phase=$1
  evidence_prefix=$(printf '%s' "$evidence_phase" | tr '[:upper:]' '[:lower:]')
  evidence_offhost="$work/$evidence_prefix-offhost-backup-evidence.json"
  evidence_secrets="$work/$evidence_prefix-secrets-backup-evidence.json"
  capture_remote 3 "$evidence_phase off-host evidence" "$REMOTE_OFFHOST_EVIDENCE_CAT" "$evidence_offhost" 524288 \
    || fail "$evidence_phase off-host evidence could not be read after bounded retries." 75
  capture_remote 3 "$evidence_phase secrets evidence" "$REMOTE_SECRETS_EVIDENCE_CAT" "$evidence_secrets" 524288 \
    || fail "$evidence_phase secrets evidence could not be read after bounded retries." 75
  verify_cms_evidence "$evidence_phase" "$evidence_offhost" "$evidence_secrets" \
    || fail "$evidence_phase CMS recovery escrow is not decryptable and exactly bound." 65
}

abort_before_commit() {
  abort_record_kind=${1:-abort-record}
  abort_record_peer=${2:-/dev/null}
  abort_record="$work/abort-record-response.json"
  abort_active="$work/abort-active-receipt.json"
  abort_verify="$work/abort-verify-receipt.json"
  abort_finalized="$work/abort-finalized-response.json"
  abort_final_verify="$work/abort-final-verify-receipt.json"
  capture_remote 3 "reconciliation abort" "$REMOTE_RECONCILER abort" "$abort_record" 131072 || return 1
  validate_protocol_json "$abort_record" "$abort_record_kind" "$abort_record_peer" || return 1
  capture_remote 3 "controller abort-maintenance" "$REMOTE_CONTROLLER abort-maintenance" "$abort_active" 131072 || return 1
  validate_protocol_json "$abort_active" aborted-active "$abort_record" || return 1
  capture_remote 3 "controller post-abort verify" "$REMOTE_CONTROLLER verify" "$abort_verify" 131072 || return 1
  validate_protocol_json "$abort_verify" aborted-active "$abort_record" || return 1
  capture_remote 3 "reconciliation abort finalization" "$REMOTE_RECONCILER abort" "$abort_finalized" 131072 || return 1
  validate_protocol_json "$abort_finalized" abort-finalized "$abort_record" || return 1
  capture_remote 3 "controller final post-abort verify" "$REMOTE_CONTROLLER verify" "$abort_final_verify" 131072 || return 1
  validate_protocol_json "$abort_final_verify" aborted-active "$abort_record" || return 1
}

# Bind the server-side authority bytes before any maintenance boundary. This is
# one fixed read-only object; no caller-selected path or command crosses SSH.
remote_authority="$work/remote-exact-release-authority.json"
capture_remote 3 "remote exact release authority" "$REMOTE_AUTHORITY_CAT" "$remote_authority" 131072 \
  || fail "The remote exact release authority could not be read." 75
cmp -s "$remote_authority" "$authority_snapshot" \
  || fail "The remote exact release authority differs byte-for-byte from the local clean-main authority." 65

# PRE is the last backup/restore/off-site gate before maintenance begins.
validation_mode_file="$work/validation-mode.json"
capture_remote 3 "controller validation mode" "$REMOTE_VALIDATION_MODE" "$validation_mode_file" 4096 \
  || fail "The controller validation mode could not be determined after bounded retries." 75
validation_mode=$(validate_protocol_json "$validation_mode_file" validation-mode) \
  || fail "The controller validation mode is not bound to the exact authority." 65
if [ "$validation_mode" = VALIDATION ]; then
  VALIDATION_MODE=1
  echo "VALIDATION LANE ACTIVE: production seal and CMS escrow verification are disabled for this run." >&2
else
  [ "$validation_mode" = PRODUCTION ] || fail "The controller returned an unknown validation mode." 65
  VALIDATION_MODE=0
fi
if [ "$VALIDATION_MODE" != 1 ]; then
  fetch_and_verify_cms PRE
else
  echo "VALIDATION MODE: PRE CMS escrow verification skipped (no fresh escrow upload)." >&2
fi

begin_response="$work/begin-maintenance-response.json"
if ! capture_remote 3 "begin-maintenance" "$REMOTE_CONTROLLER begin-maintenance" "$begin_response" 131072; then
  fail "begin-maintenance remained unreachable after bounded idempotent retries." 75
fi
validate_protocol_json "$begin_response" begin

apply_response="$work/reconcile-apply-response.json"
apply_protocol_kind=$([ "$VALIDATION_MODE" = 1 ] && echo apply-validation || echo apply)
if ! capture_remote 3 "reconcile apply" "$REMOTE_RECONCILER apply" "$apply_response" 131072 \
  || ! validate_protocol_json "$apply_response" "$apply_protocol_kind"; then
  apply_abort_kind=abort-record
  [ "$VALIDATION_MODE" != 1 ] || apply_abort_kind=abort-record-no-data-unbound
  if abort_before_commit "$apply_abort_kind"; then
    fail "reconcile apply failed; the exact pre-commit transaction was rolled back and finalized." 70
  fi
  fail "reconcile apply failed and the pre-commit abort could not be fully verified." 65
fi

# Production evidence may cross APPLIED -> COMMITTING, so an uncertain or
# invalid response closes the abort path. A canonical validation response is
# distinct: it proves the FAST lane remained pre-commit and may be aborted.
evidence_response="$work/reconcile-evidence-response.json"
if ! capture_remote 3 "reconcile evidence" "$REMOTE_RECONCILER evidence" "$evidence_response" 131072 \
  || ! validate_protocol_json "$evidence_response" "$([ "${VALIDATION_MODE:-0}" = 1 ] && echo evidence-validation || echo evidence)" "$apply_response"; then
  if [ "$VALIDATION_MODE" = 1 ]; then
    if abort_before_commit abort-record-no-data-after-apply "$apply_response"; then
      fail "validation evidence failed; the exact no-mutation transaction was rolled back and finalized." 70
    fi
    fail "validation evidence failed and the exact no-mutation transaction could not be fully finalized." 65
  fi
  fail "reconcile evidence remained unverifiable after bounded idempotent retries; abort is closed after possible COMMITTING." 65
fi

# POST recovery material must be locally decryptable before the controller is
# allowed to seal the newly committed runtime.
if [ "$VALIDATION_MODE" != 1 ]; then
  fetch_and_verify_cms POST
else
  echo "VALIDATION MODE: POST CMS escrow verification skipped (no fresh escrow upload)." >&2
fi

if [ "$VALIDATION_MODE" = 1 ]; then
  echo "VALIDATION MODE: production seal is forbidden; closing the pre-commit reconciliation before activation." >&2
  abort_before_commit abort-record-no-data "$evidence_response" \
    || fail "validation reconciliation could not be rolled back, verified, and finalized without a production seal." 65
  capture_remote 3 "validation controller activation" "$REMOTE_COMMAND" "$receipt" 131072 \
    || fail "The post-validation ACTIVE controller receipt could not be retrieved." 75
  cmp -s "$receipt" "$abort_final_verify" \
    || fail "validation activation differs from the verified post-abort ACTIVE receipt." 65
  validate_protocol_json "$receipt" aborted-active "$abort_record" \
    || fail "validation activation is not bound to the finalized abort record." 65
  exported_abort_record="$work/exported-abort-record.json"
  capture_remote 3 "verified immutable abort record" "$REMOTE_ABORTED_RECORD" "$exported_abort_record" 131072 \
    || fail "The immutable validation abort record could not be exported." 75
  runtime_provenance=$(
    "$NODE" --input-type=module - "$receipt" <<'NODE'
import fs from "node:fs";
const receipt = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
if (!receipt || receipt.status !== "ACTIVE" || !receipt.abortedAuthorizedReconciliation) throw new Error("validation receipt is not aborted ACTIVE.");
process.stdout.write(receipt.externalAuthorizedReconciliation ? "EXTERNAL\n" : "HISTORICAL\n");
NODE
  ) || fail "The validation runtime provenance could not be classified." 65
  if [ "$runtime_provenance" = EXTERNAL ]; then
    predecessor_authority="$work/predecessor-runtime-authority.json"
    capture_remote 3 "verified predecessor runtime authority" "$REMOTE_RUNTIME_AUTHORITY" "$predecessor_authority" 131072 \
      || fail "The predecessor runtime authority could not be exported." 75
    "$NODE" "$SCRIPT_ROOT/v1-local-private-control-receipt.mjs" verify \
      --file "$receipt" \
      --authorityFile "$authority_snapshot" \
      --predecessorAuthorityFile "$predecessor_authority" \
      --abortRecordFile "$exported_abort_record" >/dev/null \
      || fail "The post-validation ACTIVE receipt failed canonical mixed-provenance verification." 65
  elif [ "$runtime_provenance" = HISTORICAL ]; then
    "$NODE" "$SCRIPT_ROOT/v1-local-private-control-receipt.mjs" verify \
      --file "$receipt" \
      --authorityFile "$authority_snapshot" \
      --abortRecordFile "$exported_abort_record" >/dev/null \
      || fail "The post-validation ACTIVE receipt failed canonical historical-provenance verification." 65
  else
    fail "The validation runtime provenance classification is invalid." 65
  fi
  validation_close_response="$work/validation-close-response.json"
  capture_remote 3 "validation lane closure" "$REMOTE_VALIDATION_CLOSE" "$validation_close_response" 4096 \
    || fail "The finalized FAST validation lane could not be closed after bounded retries." 75
  validate_protocol_json "$validation_close_response" validation-close "$abort_record" \
    || fail "The finalized FAST validation lane closure is not authority/abort-bound." 65
  cat "$receipt"
  exit 0
fi
seal_response="$work/seal-response.json"
seal_observed=0
if [ "${VALIDATION_MODE:-0}" != 1 ] && capture_remote 1 "controller seal" "$REMOTE_CONTROLLER seal" "$seal_response" 131072; then
  seal_observed=1
else
  uncertain_verify="$work/uncertain-seal-verify.json"
  capture_remote 3 "uncertain seal verify" "$REMOTE_CONTROLLER verify" "$uncertain_verify" 131072 \
    || fail "seal transport was uncertain and controller verify remained unavailable." 75
  uncertain_state=$(validate_protocol_json "$uncertain_verify" reconciling-or-active)
  if [ "$uncertain_state" = ACTIVE ]; then
    cp "$uncertain_verify" "$seal_response"
    chmod 400 "$seal_response"
    seal_observed=1
  elif [ "$uncertain_state" = RECONCILING ]; then
    if capture_remote 2 "controller seal resume" "$REMOTE_CONTROLLER seal" "$seal_response" 131072; then
      seal_observed=1
    else
      resume_verify="$work/resumed-seal-verify.json"
      capture_remote 3 "resumed seal verify" "$REMOTE_CONTROLLER verify" "$resume_verify" 131072 \
        || fail "resumed seal transport was uncertain and controller verify remained unavailable." 75
      [ "$(validate_protocol_json "$resume_verify" reconciling-or-active)" = ACTIVE ] \
        || fail "controller remained RECONCILING after bounded seal resume attempts." 65
      cp "$resume_verify" "$seal_response"
      chmod 400 "$seal_response"
      seal_observed=1
    fi
  fi
fi
[ "$seal_observed" -eq 1 ] || fail "controller seal did not reach a verifiable state." 65

# A separate fixed verify closes both ordinary and lost-stdout seal paths.
capture_remote 3 "final controller verify" "$REMOTE_CONTROLLER verify" "$receipt" 131072 \
  || fail "The final ACTIVE controller receipt could not be retrieved." 75
[ "$(validate_protocol_json "$receipt" reconciling-or-active)" = ACTIVE ] \
  || fail "The final controller state is not ACTIVE." 65
"$NODE" "$SCRIPT_ROOT/v1-local-private-control-receipt.mjs" verify \
  --file "$receipt" \
  --authorityFile "$authority_snapshot" >/dev/null
"$NODE" --input-type=module - "$receipt" "$AUTHORITY_SHA256" <<'NODE'
import fs from "node:fs";
const [receiptPath, authoritySha256] = process.argv.slice(2);
const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
if (receipt?.externalAuthorizedReconciliation?.releaseAuthoritySha256 !== authoritySha256
  || receipt.externalAuthorizedReconciliation.status !== "SEALED") {
  throw new Error("The root ACTIVE receipt is not sealed to the exact authority bytes.");
}
NODE
cat "$receipt"
