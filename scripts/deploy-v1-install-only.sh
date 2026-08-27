#!/usr/bin/env sh
set -eu
umask 077

SCRIPT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPOSITORY_ROOT=$(CDPATH= cd -- "$SCRIPT_ROOT/.." && pwd)
REMOTE=${DEPLOY_REMOTE:-}
SSH_PORT=${DEPLOY_SSH_PORT:-22}
SSH_KEY_SOURCE=${DEPLOY_SSH_KEY_PATH:-${HOME:?HOME is required}/.ssh/deploy_key}
KNOWN_HOSTS_SOURCE=${DEPLOY_SSH_KNOWN_HOSTS_PATH:-${HOME:?HOME is required}/.ssh/known_hosts}
BRIDGE_SOURCE="$SCRIPT_ROOT/v1-brownfield-bootstrap-bridge.py"
CONSUMER_SOURCE="$SCRIPT_ROOT/v1-brownfield-install-consumer.py"
NODE_RUNTIME_SOURCE="$SCRIPT_ROOT/v1-node-runtime-prerequisite.py"
UPLOAD_BRIDGE_REMOTE_COMMAND="/usr/bin/python3 -I -c 'import os,stat,sys,tempfile; d=\"/home/platform_infrastructure/.v1-bootstrap-upload\"; t=d+\"/v1-brownfield-bootstrap-bridge.py\"; os.makedirs(d,mode=0o700,exist_ok=True); s=os.lstat(d); (stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid()) or sys.exit(65); os.chmod(d,0o700); b=sys.stdin.buffer.read(2097153); (0<len(b)<=2097152) or sys.exit(65); fd,p=tempfile.mkstemp(prefix=\".bridge-upload-\",dir=d); f=os.fdopen(fd,\"wb\"); n=f.write(b); n==len(b) or sys.exit(65); f.flush(); os.fsync(f.fileno()); os.fchmod(f.fileno(),0o500); f.close(); os.replace(p,t); s=os.lstat(t); (stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and stat.S_IMODE(s.st_mode)==0o500 and s.st_size==len(b)) or sys.exit(65); q=os.open(d,os.O_RDONLY|os.O_DIRECTORY); os.fsync(q); os.close(q)'"
BOOTSTRAP_REMOTE_COMMAND='/usr/bin/sudo -n -- /usr/bin/python3 -I /home/platform_infrastructure/.v1-bootstrap-upload/v1-brownfield-bootstrap-bridge.py apply'
if [ -n "${PLATFORM_V1_LIVE_ENV:-}" ]; then
  BOOTSTRAP_REMOTE_COMMAND="/usr/bin/sudo -n -- env PLATFORM_V1_LIVE_ENV='${PLATFORM_V1_LIVE_ENV}' PLATFORM_V1_REQUIRE_GREENFIELD_PREIMAGE='${PLATFORM_V1_REQUIRE_GREENFIELD_PREIMAGE:-1}' PLATFORM_V1_LIVE_ENV_PROVENANCE='${PLATFORM_V1_LIVE_ENV_PROVENANCE:?PLATFORM_V1_LIVE_ENV_PROVENANCE is required when PLATFORM_V1_LIVE_ENV is set}' ${BOOTSTRAP_REMOTE_COMMAND}"
fi
PREPARE_REMOTE_COMMAND='/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-reconcile prepare'
READ_AUTHORITY_REMOTE_COMMAND='/usr/bin/sudo -n -- /usr/bin/cat /var/lib/platform-infrastructure/v1/local-private/exact-release-authority.json'
SSH=/usr/bin/ssh
GIT=/usr/bin/git
OPENSSL=${PLATFORM_V1_INSTALL_TEST_OPENSSL:-/usr/bin/openssl}
SYSTEM_NAME=$(/usr/bin/uname -s)
case "$SYSTEM_NAME" in
  Darwin)
    NODE=${HOME:?HOME is required}/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node
    SSH=${PLATFORM_V1_INSTALL_TEST_SSH:-$SSH}
    GIT=${PLATFORM_V1_INSTALL_TEST_GIT:-$GIT}
    NODE=${PLATFORM_V1_INSTALL_TEST_NODE:-$NODE}
    ;;
  Linux) NODE=/usr/bin/node ;;
  *) echo "Unsupported local install client operating system." >&2; exit 78 ;;
esac

fail() { echo "$1" >&2; exit "${2:-64}"; }

hash_file() {
  if [ -x /usr/bin/sha256sum ]; then
    /usr/bin/sha256sum "$1" | /usr/bin/awk '{print $1}'
  elif [ -x /usr/bin/shasum ]; then
    /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'
  else
    fail "No fixed SHA-256 implementation is available." 78
  fi
}

require_input_file() {
  label=$1
  filename=$2
  [ -f "$filename" ] && [ -r "$filename" ] && [ -s "$filename" ] && [ ! -L "$filename" ] \
    || fail "$label must be one readable, non-empty regular file and not a symlink."
}

[ "$#" -eq 10 ] \
  && [ "$1" = "--bootstrapReceiptFile" ] && [ -n "$2" ] \
  && [ "$3" = "--controlArtifactReceiptFile" ] && [ -n "$4" ] \
  && [ "$5" = "--nodeRuntimeReceiptFile" ] && [ -n "$6" ] \
  && [ "$7" = "--prepareReceiptFile" ] && [ -n "$8" ] \
  && [ "$9" = "--authorityFile" ] && [ -n "${10}" ] \
  || fail "Usage: deploy-v1-install-only.sh --bootstrapReceiptFile FILE --controlArtifactReceiptFile FILE --nodeRuntimeReceiptFile FILE --prepareReceiptFile FILE --authorityFile FILE"
BOOTSTRAP_RECEIPT_OUTPUT=$2
CONTROL_ARTIFACT_RECEIPT_OUTPUT=$4
NODE_RUNTIME_RECEIPT_OUTPUT=$6
PREPARE_RECEIPT_OUTPUT=$8
AUTHORITY_OUTPUT=${10}

case "$REMOTE" in *@*) ;; *) fail "DEPLOY_REMOTE must be one canonical user@host endpoint." ;; esac
REMOTE_USER=${REMOTE%@*}
REMOTE_HOST=${REMOTE#*@}
case "$REMOTE_USER" in ""|[!a-z_]*|*[!a-z0-9_-]*) fail "DEPLOY_REMOTE user is invalid." ;; esac
[ "$REMOTE_USER" = platform_infrastructure ] || fail "The V1 bootstrap bridge requires the fixed platform_infrastructure account."
case "$REMOTE_HOST" in ""|[!a-z0-9]*|*[!a-z0-9.-]*|*..*|*[-.]) fail "DEPLOY_REMOTE host is invalid." ;; esac
case "$REMOTE" in *@*@*) fail "DEPLOY_REMOTE must contain exactly one separator." ;; esac
case "$SSH_PORT" in ""|*[!0-9]*) fail "DEPLOY_SSH_PORT must be numeric." ;; esac
[ "$SSH_PORT" -ge 1 ] && [ "$SSH_PORT" -le 65535 ] || fail "DEPLOY_SSH_PORT is outside the accepted range."
[ -x "$SSH" ] || fail "The fixed SSH client is unavailable." 78
[ -x "$GIT" ] || fail "The fixed Git client is unavailable." 78
[ -x "$NODE" ] || fail "The fixed local Node.js runtime is unavailable." 78
for dependency in ssh-known-host-endpoint.sh pinned-ssh-host-key.mjs v1-brownfield-install-receipt.mjs; do
  [ -f "$SCRIPT_ROOT/$dependency" ] && [ ! -L "$SCRIPT_ROOT/$dependency" ] \
    || fail "The exact V1 install dependency $dependency is unavailable." 78
done
require_input_file "V1 one-time bootstrap bridge" "$BRIDGE_SOURCE"
require_input_file "V1 exact-main install consumer" "$CONSUMER_SOURCE"
require_input_file "V1 exact-main Node runtime prerequisite" "$NODE_RUNTIME_SOURCE"
require_input_file "SSH private key" "$SSH_KEY_SOURCE"
require_input_file "SSH known-hosts input" "$KNOWN_HOSTS_SOURCE"

"$NODE" --input-type=module - \
  "$BOOTSTRAP_RECEIPT_OUTPUT" "$CONTROL_ARTIFACT_RECEIPT_OUTPUT" "$NODE_RUNTIME_RECEIPT_OUTPUT" \
  "$PREPARE_RECEIPT_OUTPUT" "$AUTHORITY_OUTPUT" <<'NODE'
import fs from "node:fs";
import path from "node:path";
const targets = process.argv.slice(2);
if (new Set(targets).size !== targets.length) throw new Error("V1 staging output paths must be distinct.");
for (const target of targets) {
  if (!path.isAbsolute(target) || path.normalize(target) !== target || /[\0\r\n]/.test(target)) throw new Error("V1 staging output path is not canonical absolute.");
  const parent = path.dirname(target);
  const metadata = fs.lstatSync(parent);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || fs.realpathSync.native(parent) !== parent || (metadata.mode & 0o022) !== 0) throw new Error("V1 staging output parent identity or permissions are unsafe.");
  try { fs.lstatSync(target); throw new Error("V1 staging output already exists."); }
  catch (error) { if (error?.code !== "ENOENT") throw error; }
}
NODE

REPOSITORY_TOP=$($GIT -C "$REPOSITORY_ROOT" rev-parse --show-toplevel) || fail "The install-only client cannot identify its repository root." 65
[ "$REPOSITORY_TOP" = "$REPOSITORY_ROOT" ] || fail "The install-only client is not running from the selected repository root." 65
CANDIDATE_COMMIT=$($GIT -C "$REPOSITORY_ROOT" rev-parse --verify 'HEAD^{commit}') || fail "The install-only client cannot resolve the exact HEAD commit." 65
CANDIDATE_TREE=$($GIT -C "$REPOSITORY_ROOT" rev-parse --verify 'HEAD^{tree}') || fail "The install-only client cannot resolve the exact HEAD tree." 65
GITHUB_MAIN_COMMIT=$($GIT -C "$REPOSITORY_ROOT" rev-parse --verify refs/remotes/github/main) || fail "The install-only client requires refs/remotes/github/main." 65
case "$CANDIDATE_COMMIT" in ????????????????????????????????????????) ;; *) fail "The selected HEAD commit is not one Git SHA-1 object ID." 65 ;; esac
case "$CANDIDATE_TREE" in ????????????????????????????????????????) ;; *) fail "The selected HEAD tree is not one Git SHA-1 object ID." 65 ;; esac
case "$CANDIDATE_COMMIT$CANDIDATE_TREE" in *[!0-9a-f]*) fail "The selected Git identity is not lowercase hexadecimal." 65 ;; esac
[ "$CANDIDATE_COMMIT" = "$GITHUB_MAIN_COMMIT" ] || fail "The install-only client requires clean HEAD equal to refs/remotes/github/main." 65
GIT_STATUS=$($GIT -C "$REPOSITORY_ROOT" status --porcelain=v1 --untracked-files=all) || fail "The install-only client cannot prove clean checkout state." 65
[ -z "$GIT_STATUS" ] || fail "The install-only client requires a completely clean checkout." 65

work=$(mktemp -d "${TMPDIR:-/tmp}/platform-v1-install-client.XXXXXX")
cleanup() { status=$?; trap - EXIT HUP INT TERM; rm -rf "$work"; exit "$status"; }
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

ssh_key="$work/ssh-key"
known_hosts="$work/known-hosts"
bridge_snapshot="$work/v1-brownfield-bootstrap-bridge.py"
consumer_snapshot="$work/v1-brownfield-install-consumer.py"
source_archive="$work/exact-source-archive.tar"
git_bundle="$work/exact-source.bundle"
transport_checkpoint="$work/bootstrap-transport-checkpoint.json"
transport_sanction="$work/bootstrap-transport-sanction.json"
bootstrap_frame="$work/bootstrap-frame.bin"
bootstrap_envelope="$work/bootstrap-envelope.json"
bootstrap_receipt="$work/bootstrap-receipt.json"
control_artifact_receipt="$work/control-artifact-receipt.json"
node_runtime_receipt="$work/node-runtime-prerequisite-receipt.json"
prepare_receipt="$work/prepare-receipt.json"
authority_first="$work/exact-release-authority.first.json"
authority_second="$work/exact-release-authority.second.json"
upload_response="$work/upload-response"

( ulimit -f 1048576; exec "$GIT" -C "$REPOSITORY_ROOT" archive --format=tar HEAD ) > "$source_archive" \
  || fail "The install-only client cannot materialize the exact clean source archive." 65
[ -s "$source_archive" ] && [ ! -L "$source_archive" ] || fail "The exact source archive is missing." 65
SOURCE_ARCHIVE_SHA256=$(hash_file "$source_archive")
case "$SOURCE_ARCHIVE_SHA256" in ????????????????????????????????????????????????????????????????) ;; *) fail "The exact source archive digest is invalid." 65 ;; esac
case "$SOURCE_ARCHIVE_SHA256" in *[!0-9a-f]*) fail "The exact source archive digest is not lowercase hexadecimal." 65 ;; esac
( ulimit -f 2097152; exec "$GIT" -C "$REPOSITORY_ROOT" bundle create "$git_bundle" HEAD ) \
  || fail "The install-only client cannot materialize the exact Git object bundle." 65
[ -s "$git_bundle" ] && [ ! -L "$git_bundle" ] || fail "The exact Git object bundle is missing." 65
$GIT -C "$REPOSITORY_ROOT" bundle verify "$git_bundle" >/dev/null \
  || fail "The exact Git object bundle does not pass fixed Git verification." 65
BUNDLE_HEADS=$($GIT -C "$REPOSITORY_ROOT" bundle list-heads "$git_bundle") \
  || fail "The exact Git object bundle cannot expose its advertised head." 65
[ "$BUNDLE_HEADS" = "$CANDIDATE_COMMIT HEAD" ] \
  || fail "The exact Git object bundle advertises a ref outside the selected HEAD commit." 65

bridge_before=$(hash_file "$BRIDGE_SOURCE")
consumer_before=$(hash_file "$CONSUMER_SOURCE")
cp "$BRIDGE_SOURCE" "$bridge_snapshot"
cp "$CONSUMER_SOURCE" "$consumer_snapshot"
chmod 500 "$bridge_snapshot" "$consumer_snapshot"
[ "$(hash_file "$BRIDGE_SOURCE")" = "$bridge_before" ] && [ "$(hash_file "$bridge_snapshot")" = "$bridge_before" ] \
  || fail "The V1 bootstrap bridge changed during stable capture." 65
[ "$(hash_file "$CONSUMER_SOURCE")" = "$consumer_before" ] && [ "$(hash_file "$consumer_snapshot")" = "$consumer_before" ] \
  || fail "The V1 exact-main consumer changed during stable capture." 65
[ "$($GIT -C "$REPOSITORY_ROOT" rev-parse --verify 'HEAD^{commit}')" = "$CANDIDATE_COMMIT" ] \
  && [ "$($GIT -C "$REPOSITORY_ROOT" rev-parse --verify 'HEAD^{tree}')" = "$CANDIDATE_TREE" ] \
  && [ -z "$($GIT -C "$REPOSITORY_ROOT" status --porcelain=v1 --untracked-files=all)" ] \
  || fail "The clean exact-main checkout changed during transport capture." 65

CANDIDATE_COMMIT_UNIX=$($GIT -C "$REPOSITORY_ROOT" show -s --format=%ct "$CANDIDATE_COMMIT") \
  || fail "The install-only client cannot read the candidate commit timestamp." 65
case "$CANDIDATE_COMMIT_UNIX" in ''|*[!0-9]*) fail "The candidate commit timestamp is invalid." 65 ;; esac
SANCTION_PRIOR_DOCUMENT_ID=${PLATFORM_V1_TRANSPORT_SANCTION_PRIOR_RECEIPT_DOCUMENT_ID:-}
SANCTION_PRIOR_CHECKPOINT_SHA256=${PLATFORM_V1_TRANSPORT_SANCTION_PRIOR_CHECKPOINT_SHA256:-}
SANCTION_CERT_INPUT=${PLATFORM_V1_TRANSPORT_SANCTION_CERT:-}
SANCTION_KEY_INPUT=${PLATFORM_V1_TRANSPORT_SANCTION_KEY:-}
if [ -n "$SANCTION_PRIOR_DOCUMENT_ID" ] || [ -n "$SANCTION_PRIOR_CHECKPOINT_SHA256" ] \
  || [ -n "$SANCTION_CERT_INPUT" ] || [ -n "$SANCTION_KEY_INPUT" ]; then
  case "$SANCTION_PRIOR_DOCUMENT_ID" in ????????????????????????????????????????????????????????????????) ;; *) fail "Transport sanction prior receipt document id is invalid." 65 ;; esac
  case "$SANCTION_PRIOR_DOCUMENT_ID" in *[!0-9a-f]*) fail "Transport sanction prior receipt document id is not lowercase hexadecimal." 65 ;; esac
  case "$SANCTION_PRIOR_CHECKPOINT_SHA256" in ????????????????????????????????????????????????????????????????) ;; *) fail "Transport sanction prior checkpoint digest is invalid." 65 ;; esac
  case "$SANCTION_PRIOR_CHECKPOINT_SHA256" in *[!0-9a-f]*) fail "Transport sanction prior checkpoint digest is not lowercase hexadecimal." 65 ;; esac
  require_input_file "Transport sanction escrow certificate" "$SANCTION_CERT_INPUT"
  require_input_file "Transport sanction operator signing key" "$SANCTION_KEY_INPUT"
else
  SANCTION_PRIOR_DOCUMENT_ID=""
  SANCTION_PRIOR_CHECKPOINT_SHA256=""
  SANCTION_CERT_INPUT=""
  SANCTION_KEY_INPUT=""
fi

CHECKPOINT_SHA256=$("$NODE" --input-type=module - \
  "$bridge_snapshot" "$consumer_snapshot" "$transport_checkpoint" "$git_bundle" "$source_archive" \
  "$CANDIDATE_COMMIT" "$CANDIDATE_TREE" "$SOURCE_ARCHIVE_SHA256" "$CANDIDATE_COMMIT_UNIX" <<'NODE'
import crypto from "node:crypto";
import fs from "node:fs";
const [bridge, consumer, checkpoint, bundle, archive, candidateCommit, candidateTree, sourceArchiveSha256, commitUnix] = process.argv.slice(2);
const sha = (filename) => crypto.createHash("sha256").update(fs.readFileSync(filename)).digest("hex");
const stable = (value) => Array.isArray(value) ? `[${value.map(stable).join(",")}]` : value && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}` : JSON.stringify(value);
const createdAtUnixSeconds = Number.parseInt(commitUnix, 10);
if (!Number.isInteger(createdAtUnixSeconds) || createdAtUnixSeconds <= 0) throw new Error("Candidate commit timestamp is invalid.");
const checkpointValue = {
  activationAuthorized: false, authoritative: false, backupEvidenceAuthoritative: false,
  bridgeSha256: sha(bridge), candidateCommit, candidateConsumerSha256: sha(consumer), candidateTree,
  createdAtUnixSeconds, gitBundleSha256: sha(bundle),
  purpose: "CONTROL_PLANE_STAGING_ONLY", schema: "platform.v1-bootstrap-transport-checkpoint/v1",
  sourceArchiveSha256, sourceArchiveSizeBytes: fs.statSync(archive).size, transportVerified: true,
};
fs.writeFileSync(checkpoint, `${stable(checkpointValue)}\n`, { flag: "wx", mode: 0o400 });
process.stdout.write(sha(checkpoint));
NODE
) || fail "Transport checkpoint generation failed." 65
case "$CHECKPOINT_SHA256" in ????????????????????????????????????????????????????????????????) ;; *) fail "Transport checkpoint digest is malformed." 65 ;; esac

SANCTION_CERT_STABLE=""
SANCTION_KEY_SNAPSHOT=""
if [ -n "$SANCTION_PRIOR_DOCUMENT_ID" ]; then
  sanction_core="$work/bootstrap-transport-sanction-core.json"
  sanction_sig="$work/bootstrap-transport-sanction.sig"
  SANCTION_CERT_STABLE="$work/sanction-cert.pem"
  cp -- "$SANCTION_CERT_INPUT" "$SANCTION_CERT_STABLE"
  chmod 444 "$SANCTION_CERT_STABLE"
  SANCTION_CERT_SHA256=$(hash_file "$SANCTION_CERT_STABLE")
  [ "$(hash_file "$SANCTION_CERT_INPUT")" = "$SANCTION_CERT_SHA256" ] \
    || fail "The transport sanction escrow certificate changed during stable capture." 65
  printf '%s\n' "{\"checkpointSha256\":\"$CHECKPOINT_SHA256\",\"createdAtUnixSeconds\":$(date -u +%s),\"priorCheckpointAfterSha256\":\"$SANCTION_PRIOR_CHECKPOINT_SHA256\",\"priorReceiptDocumentId\":\"$SANCTION_PRIOR_DOCUMENT_ID\",\"reasonCode\":\"TRANSPORT_CHECKPOINT_REGENERATED_NO_PRIOR_BYTES\",\"schema\":\"platform.v1-transport-checkpoint-sanction/v1\"}" > "$sanction_core"
  "$OPENSSL" cms -sign -binary -in "$sanction_core" -signer "$SANCTION_CERT_STABLE" -inkey "$SANCTION_KEY_INPUT" -outform DER -out "$sanction_sig" 2>/dev/null \
    || fail "The transport sanction CMS signature failed." 65
  "$OPENSSL" base64 -A -in "$sanction_sig" -out "$work/sanction-sig.b64" \
    || fail "The transport sanction signature encoding failed." 65
  export PLATFORM_V1_SANCTION_SIGNABLE_JSON="$sanction_core"
  export PLATFORM_V1_SANCTION_SIGNATURE_B64
  PLATFORM_V1_SANCTION_SIGNATURE_B64=$(cat "$work/sanction-sig.b64")
else
  unset PLATFORM_V1_SANCTION_SIGNABLE_JSON || true
  export PLATFORM_V1_SANCTION_SIGNATURE_B64=""
fi

"$NODE" --input-type=module - \
  "$bridge_snapshot" "$consumer_snapshot" "$transport_checkpoint" "$transport_sanction" "$git_bundle" "$source_archive" "$bootstrap_frame" \
  "$CANDIDATE_COMMIT" "$CANDIDATE_TREE" "$SOURCE_ARCHIVE_SHA256" <<'NODE'
import crypto from "node:crypto";
import fs from "node:fs";
const [bridge, consumer, checkpoint, sanction, bundle, archive, frame, candidateCommit, candidateTree, sourceArchiveSha256] = process.argv.slice(2);
const sha = (filename) => crypto.createHash("sha256").update(fs.readFileSync(filename)).digest("hex");
const stable = (value) => Array.isArray(value) ? `[${value.map(stable).join(",")}]` : value && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}` : JSON.stringify(value);
let sanctionBytes;
if (process.env.PLATFORM_V1_SANCTION_SIGNATURE_B64) {
  const core = JSON.parse(fs.readFileSync(process.env.PLATFORM_V1_SANCTION_SIGNABLE_JSON, "utf8"));
  if (!core || typeof core !== "object" || Array.isArray(core)) throw new Error("Transport sanction core is not an object.");
  sanctionBytes = Buffer.from(`${stable({ ...core, signatureBase64: process.env.PLATFORM_V1_SANCTION_SIGNATURE_B64 })}\n`);
} else {
  sanctionBytes = Buffer.from("{}");
}
fs.writeFileSync(sanction, sanctionBytes, { flag: "wx", mode: 0o400 });
const parts = { bridge, consumer, checkpoint, sanction, gitBundle: bundle, sourceArchive: archive };
const manifest = {
  bridgeSha256: sha(bridge), candidateCommit, candidateTree, checkpointSha256: sha(checkpoint),
  consumerSha256: sha(consumer), gitBundleSha256: sha(bundle),
  lengths: Object.fromEntries(Object.entries(parts).map(([name, filename]) => [name, fs.statSync(filename).size])),
  schema: "platform.v1-brownfield-bootstrap-frame/v1", sanctionSha256: sha(sanction), sourceArchiveSha256,
};
const manifestBytes = Buffer.from(stable(manifest));
if (manifestBytes.length < 2 || manifestBytes.length > 16 * 1024) throw new Error("Bootstrap manifest size is invalid.");
const output = fs.openSync(frame, "wx", 0o400);
try {
  fs.writeSync(output, Buffer.from(manifestBytes.length.toString(16).padStart(8, "0")));
  fs.writeSync(output, manifestBytes);
  for (const name of ["bridge", "consumer", "checkpoint", "sanction", "gitBundle", "sourceArchive"]) {
    const input = fs.openSync(parts[name], "r");
    try {
      const buffer = Buffer.allocUnsafe(1024 * 1024);
      for (;;) { const count = fs.readSync(input, buffer); if (count === 0) break; fs.writeSync(output, buffer, 0, count); }
    } finally { fs.closeSync(input); }
  }
  fs.fsyncSync(output);
} finally { fs.closeSync(output); }
NODE

key_before=$(hash_file "$SSH_KEY_SOURCE")
known_before=$(hash_file "$KNOWN_HOSTS_SOURCE")
cp "$SSH_KEY_SOURCE" "$ssh_key"
cp "$KNOWN_HOSTS_SOURCE" "$known_hosts"
chmod 600 "$ssh_key" "$known_hosts"
[ "$(hash_file "$SSH_KEY_SOURCE")" = "$key_before" ] && [ "$(hash_file "$ssh_key")" = "$key_before" ] || fail "SSH private key changed during stable capture." 65
[ "$(hash_file "$KNOWN_HOSTS_SOURCE")" = "$known_before" ] && [ "$(hash_file "$known_hosts")" = "$known_before" ] || fail "SSH known-hosts input changed during stable capture." 65

sh "$SCRIPT_ROOT/ssh-known-host-endpoint.sh" "$REMOTE_HOST" "$SSH_PORT" "$known_hosts"
"$NODE" "$SCRIPT_ROOT/pinned-ssh-host-key.mjs" verify --remote "$REMOTE" --port "$SSH_PORT" --file "$known_hosts" >/dev/null \
  || fail "Pinned SSH host trust validation failed." 65

set -- -F /dev/null -i "$ssh_key" -p "$SSH_PORT" \
  -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o "UserKnownHostsFile=$known_hosts" -o GlobalKnownHostsFile=/dev/null \
  -o UpdateHostKeys=no -o PermitLocalCommand=no -o ClearAllForwardings=yes -o ExitOnForwardFailure=yes

# The second call is the only root bridge. It transports a closed exact frame,
# stages control-plane bytes, and installs fixed control artifacts; it has no
# workload, data, backup, restore, provider, or activation authority.
( ulimit -f 4096; exec "$SSH" "$@" -- "$REMOTE" "$UPLOAD_BRIDGE_REMOTE_COMMAND" < "$bridge_snapshot" ) > "$upload_response" \
  || fail "The authenticated V1 bridge upload failed." 65
[ ! -s "$upload_response" ] || fail "The V1 bridge upload returned unexpected output." 65
( ulimit -f 512; exec "$SSH" "$@" -- "$REMOTE" "$BOOTSTRAP_REMOTE_COMMAND" < "$bootstrap_frame" ) > "$bootstrap_envelope" \
  || fail "The one-time V1 bootstrap bridge failed." 65

"$NODE" --input-type=module - \
  "$bootstrap_envelope" "$bootstrap_receipt" "$control_artifact_receipt" "$node_runtime_receipt" <<'NODE'
import crypto from "node:crypto";
import fs from "node:fs";
const [source, bootstrapTarget, controlTarget, nodeRuntimeTarget] = process.argv.slice(2);
const bytes = fs.readFileSync(source);
if (bytes.length < 2 || bytes.length > 256 * 1024 || bytes.includes(0) || bytes.includes(13)) throw new Error("Bootstrap envelope bounds/encoding are invalid.");
const stable = (value) => Array.isArray(value) ? `[${value.map(stable).join(",")}]` : value && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}` : JSON.stringify(value);
const envelope = JSON.parse(bytes.toString("utf8"));
if (stable(envelope) + "\n" !== bytes.toString("utf8") || Object.keys(envelope).sort().join(",") !== "bootstrap,controlArtifacts,nodeRuntime,schema" || envelope.schema !== "platform.v1-brownfield-bootstrap-result/v1") throw new Error("Bootstrap envelope is not exact canonical V1 output.");
const bootstrapBytes = Buffer.from(stable(envelope.bootstrap) + "\n");
const controlBytes = Buffer.from(stable(envelope.controlArtifacts) + "\n");
const nodeRuntimeBytes = Buffer.from(stable(envelope.nodeRuntime) + "\n");
if (envelope.bootstrap.controlArtifactReceiptSha256 !== crypto.createHash("sha256").update(controlBytes).digest("hex")) throw new Error("Bootstrap/control receipt binding is invalid.");
if (envelope.bootstrap.nodeRuntimeReceiptSha256 !== crypto.createHash("sha256").update(nodeRuntimeBytes).digest("hex")) throw new Error("Bootstrap/Node runtime receipt binding is invalid.");
for (const [target, value] of [[bootstrapTarget, bootstrapBytes], [controlTarget, controlBytes], [nodeRuntimeTarget, nodeRuntimeBytes]]) {
  fs.writeFileSync(target, value, { flag: "wx", mode: 0o400 });
  const descriptor = fs.openSync(target, "r"); try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}
NODE

"$NODE" "$SCRIPT_ROOT/v1-brownfield-install-receipt.mjs" verify-bootstrap \
  --file "$bootstrap_receipt" --candidateCommit "$CANDIDATE_COMMIT" --candidateTree "$CANDIDATE_TREE" \
  --sourceArchiveSha256 "$SOURCE_ARCHIVE_SHA256" --repositoryRoot "$REPOSITORY_ROOT" >/dev/null
"$NODE" "$SCRIPT_ROOT/v1-brownfield-install-receipt.mjs" verify-control-artifacts \
  --file "$control_artifact_receipt" --candidateCommit "$CANDIDATE_COMMIT" --candidateTree "$CANDIDATE_TREE" \
  --sourceArchiveSha256 "$SOURCE_ARCHIVE_SHA256" --repositoryRoot "$REPOSITORY_ROOT" >/dev/null

# The one-time root bridge invokes the immutable exact-release Node helper and
# binds its separate receipt into the bootstrap envelope.  No second broad
# sudo invocation is admitted by this client.
"$NODE" "$SCRIPT_ROOT/v1-brownfield-install-receipt.mjs" verify-node-runtime \
  --file "$node_runtime_receipt" --candidateCommit "$CANDIDATE_COMMIT" --candidateTree "$CANDIDATE_TREE" \
  --sourceArchiveSha256 "$SOURCE_ARCHIVE_SHA256" --repositoryRoot "$REPOSITORY_ROOT" >/dev/null

( ulimit -f 128; exec "$SSH" "$@" -- "$REMOTE" "$PREPARE_REMOTE_COMMAND" < /dev/null ) > "$prepare_receipt" \
  || fail "The installed V1 reconciler prepare step failed." 65
[ -s "$prepare_receipt" ] && [ "$(wc -c < "$prepare_receipt" | tr -d '[:space:]')" -le 65536 ] || fail "The installed V1 reconciler returned an invalid prepare receipt." 65

for authority_capture in "$authority_first" "$authority_second"; do
  ( ulimit -f 256; exec "$SSH" "$@" -- "$REMOTE" "$READ_AUTHORITY_REMOTE_COMMAND" < /dev/null ) > "$authority_capture" \
    || fail "The root-owned exact release authority read failed." 65
  [ -s "$authority_capture" ] && [ "$(wc -c < "$authority_capture" | tr -d '[:space:]')" -le 131072 ] || fail "The exact release authority size is invalid." 65
done
cmp -s "$authority_first" "$authority_second" || fail "The exact release authority changed between fixed reads." 65
"$NODE" "$SCRIPT_ROOT/v1-brownfield-install-receipt.mjs" verify-authority --file "$authority_first" --repositoryRoot "$REPOSITORY_ROOT" >/dev/null
"$NODE" "$SCRIPT_ROOT/v1-brownfield-install-receipt.mjs" verify-control-artifacts --file "$control_artifact_receipt" --authorityFile "$authority_first" >/dev/null
"$NODE" "$SCRIPT_ROOT/v1-brownfield-install-receipt.mjs" verify-prepare --file "$prepare_receipt" --authorityFile "$authority_first" >/dev/null

"$NODE" --input-type=module - \
  "$bootstrap_receipt" "$BOOTSTRAP_RECEIPT_OUTPUT" "$control_artifact_receipt" "$CONTROL_ARTIFACT_RECEIPT_OUTPUT" \
  "$node_runtime_receipt" "$NODE_RUNTIME_RECEIPT_OUTPUT" \
  "$prepare_receipt" "$PREPARE_RECEIPT_OUTPUT" "$authority_first" "$AUTHORITY_OUTPUT" <<'NODE'
import fs from "node:fs";
const pairs = process.argv.slice(2);
for (let index = 0; index < pairs.length; index += 2) {
  fs.copyFileSync(pairs[index], pairs[index + 1], fs.constants.COPYFILE_EXCL);
  fs.chmodSync(pairs[index + 1], 0o400);
  const descriptor = fs.openSync(pairs[index + 1], "r"); try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
  const metadata = fs.lstatSync(pairs[index + 1]);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || (metadata.mode & 0o777) !== 0o400) throw new Error("Published V1 staging evidence identity is invalid.");
}
NODE
cat "$bootstrap_receipt"
