#!/usr/bin/env sh
set -eu
umask 077

CODE_ROOT=${PLATFORM_OPS_CODE_ROOT:-/opt/platform-infrastructure}
SCRIPT_ROOT="$CODE_ROOT/scripts"
POLICY=${DEPLOY_ADMISSION_POLICY_PATH:-"$CODE_ROOT/governance/deployment-admission.json"}
REMOTE=${DEPLOY_REMOTE:-}
SSH_PORT=${DEPLOY_SSH_PORT:-}
SSH_KEY_SOURCE=${DEPLOY_SSH_KEY_PATH:-/run/platform-deploy/ssh-key}
KNOWN_HOSTS_SOURCE=${DEPLOY_SSH_KNOWN_HOSTS_PATH:-${DEPLOY_KNOWN_HOSTS_PATH:-/run/platform-deploy/known-hosts}}
REPOSITORY=${DEPLOY_REPO:-}
COMMIT_SHA=${DEPLOY_RELEASE_SHA:-}
TREE_SHA=${DEPLOY_RELEASE_TREE:-}
ENVIRONMENT_SHA256=${DEPLOY_ENVIRONMENT_SHA256:-}
ARTIFACT_RECEIPT=${DEPLOY_ARTIFACT_RECEIPT_PATH:-}
ARTIFACT_RECEIPT_SHA256=${DEPLOY_ARTIFACT_RECEIPT_SHA256:-}
DEPLOYMENT_RECEIPT=${DEPLOY_ADMISSION_RECEIPT_PATH:-}
DEPLOYMENT_RECEIPT_SHA256=${DEPLOY_ADMISSION_RECEIPT_SHA256:-}
PROVIDER_METADATA=${DEPLOY_TRUSTED_PROVIDER_METADATA_PATH:-}
PROVIDER_METADATA_SHA256=${DEPLOY_TRUSTED_PROVIDER_METADATA_SHA256:-}
PROVIDER_RUN_ID=${DEPLOY_TRUSTED_PROVIDER_RUN_ID:-}
PROVIDER_RUN_ATTEMPT=${DEPLOY_TRUSTED_PROVIDER_RUN_ATTEMPT:-}
DAST_PROVIDER_RECEIPT=${DEPLOY_DAST_PROVIDER_RECEIPT_PATH:-}
DAST_PROVIDER_RECEIPT_SHA256=${DEPLOY_DAST_PROVIDER_RECEIPT_SHA256:-}
DAST_ACTIVATION_AUTHORIZATION=${DEPLOY_DAST_ACTIVATION_AUTHORIZATION_PATH:-}
DAST_ACTIVATION_AUTHORIZATION_SHA256=${DEPLOY_DAST_ACTIVATION_AUTHORIZATION_SHA256:-}
DAST_PROVIDER_METADATA_SHA256=${DEPLOY_DAST_PROVIDER_METADATA_SHA256:-}
DAST_SIGSTORE_BUNDLE_SHA256=${DEPLOY_DAST_SIGSTORE_BUNDLE_SHA256:-}
DAST_SIGSTORE_SUBJECT=${DEPLOY_DAST_SIGSTORE_SUBJECT:-}
DAST_CHAIN_SHA256=${DEPLOY_DAST_CHAIN_SHA256:-}
RELEASE_BUNDLE_MANIFEST=${DEPLOY_RELEASE_BUNDLE_MANIFEST_PATH:-}
RELEASE_BUNDLE_SHA256=${DEPLOY_RELEASE_BUNDLE_SHA256:-}
RELEASE_BUNDLE_SIZE_BYTES=${DEPLOY_RELEASE_BUNDLE_SIZE_BYTES:-}
RELEASE_BUNDLE_MANIFEST_SHA256=${DEPLOY_RELEASE_BUNDLE_MANIFEST_SHA256:-}
DOCKER_ACTIVATION_ENVELOPE_SHA256=${DEPLOY_DOCKER_ACTIVATION_ENVELOPE_SHA256:-}
DOCKER_ACTIVATION_ENVELOPE_SIZE_BYTES=${DEPLOY_DOCKER_ACTIVATION_ENVELOPE_SIZE_BYTES:-}
DOCKER_ACTIVATION_ENVELOPE_PAYLOAD_TYPE=${DEPLOY_DOCKER_ACTIVATION_ENVELOPE_PAYLOAD_TYPE:-}
DOCKER_ACTIVATION_RUNTIME_INTENT_ID=${DEPLOY_DOCKER_ACTIVATION_RUNTIME_INTENT_ID:-}
DOCKER_ACTIVATION_GENERATION=${DEPLOY_DOCKER_ACTIVATION_GENERATION:-}
CONSUMER_RUN_ID=${DEPLOY_CONSUMER_RUN_ID:-${GITHUB_RUN_ID:-}}
CONSUMER_RUN_ATTEMPT=${DEPLOY_CONSUMER_RUN_ATTEMPT:-${GITHUB_RUN_ATTEMPT:-}}
RECEIPT_OUTPUT=${DEPLOY_ACTIVATION_RECEIPT_PATH:-}

fail() {
  echo "$1" >&2
  exit "${2:-64}"
}

hash_file() {
  # POSIX shells may inherit EXIT traps into command substitutions. The hash
  # subprocess must never run the parent cleanup and remove the request.
  trap - EXIT HUP INT TERM
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

require_sha256() {
  label=$1
  value=$2
  case "$value" in ""|*[!a-f0-9]*) fail "$label must be one lowercase SHA256." ;; esac
  [ "${#value}" -eq 64 ] || fail "$label must be one lowercase SHA256."
}

require_positive_integer() {
  label=$1
  value=$2
  case "$value" in ""|*[!0-9]*|0) fail "$label must be a positive integer." ;; esac
}

require_input_file() {
  label=$1
  filename=$2
  [ -n "$filename" ] || fail "$label path is required."
  [ -f "$filename" ] && [ -r "$filename" ] && [ -s "$filename" ] && [ ! -L "$filename" ] \
    || fail "$label must be one readable, non-empty regular file and not a symlink."
}

enforce_v1_brownfield_admission_stop() {
  fail "Authoritative V1 brownfield admission is unavailable. A canonical COMPLETE baseline, immutable/CAS PRE-DEPLOY backup receipt, exact candidate commit/tree and target root, plus provider and target authorization are required. REBUILD_BACKUP_VERIFIED_NON_AUTHORITATIVE and mutationAuthority=false are deny-only; caller-supplied claims cannot authorize production mutation." 78
}

[ "${PLATFORM_TRUSTED_OPS_RUNNER:-}" = 1 ] || fail \
  "Deployment must execute through the exact provider-attested ops image entrypoint." 78
[ "$#" -eq 0 ] || fail "deploy-vps.sh accepts no positional arguments."
enforce_v1_brownfield_admission_stop

case "$REMOTE" in *@*) ;; *) fail "DEPLOY_REMOTE must be one canonical user@host endpoint." ;; esac
REMOTE_USER=${REMOTE%@*}
REMOTE_HOST=${REMOTE#*@}
case "$REMOTE_USER" in ""|[!a-z_]*|*[!a-z0-9_-]*) fail "DEPLOY_REMOTE user is invalid." ;; esac
case "$REMOTE_HOST" in ""|[!a-z0-9]*|*[!a-z0-9.-]*|*..*|*[-.]) fail "DEPLOY_REMOTE host is invalid." ;; esac
case "$REMOTE" in *@*@*) fail "DEPLOY_REMOTE must contain exactly one separator." ;; esac
require_positive_integer "DEPLOY_SSH_PORT" "$SSH_PORT"
[ "$SSH_PORT" -le 65535 ] || fail "DEPLOY_SSH_PORT is outside the accepted range."
case "$REPOSITORY" in
  [A-Za-z0-9_.-]*/[A-Za-z0-9_.-]* ) ;;
  * ) fail "DEPLOY_REPO must be one owner/repository identifier." ;;
esac
case "$COMMIT_SHA:$TREE_SHA" in *[!a-f0-9:]*|::*|:*|*:) fail "Release commit/tree inputs are invalid." ;; esac
[ "${#COMMIT_SHA}" -eq 40 ] && [ "${#TREE_SHA}" -eq 40 ] || fail "Release commit/tree inputs are incomplete."

require_sha256 "Environment SHA256" "$ENVIRONMENT_SHA256"
require_sha256 "Artifact receipt SHA256" "$ARTIFACT_RECEIPT_SHA256"
require_sha256 "Deployment receipt SHA256" "$DEPLOYMENT_RECEIPT_SHA256"
require_sha256 "Provider metadata SHA256" "$PROVIDER_METADATA_SHA256"
require_sha256 "DAST provider receipt SHA256" "$DAST_PROVIDER_RECEIPT_SHA256"
require_sha256 "DAST activation authorization SHA256" "$DAST_ACTIVATION_AUTHORIZATION_SHA256"
require_sha256 "DAST provider metadata SHA256" "$DAST_PROVIDER_METADATA_SHA256"
require_sha256 "DAST Sigstore bundle SHA256" "$DAST_SIGSTORE_BUNDLE_SHA256"
require_sha256 "DAST chain SHA256" "$DAST_CHAIN_SHA256"
require_sha256 "Release bundle SHA256" "$RELEASE_BUNDLE_SHA256"
require_sha256 "Release bundle manifest SHA256" "$RELEASE_BUNDLE_MANIFEST_SHA256"
require_sha256 "Docker activation envelope SHA256" "$DOCKER_ACTIVATION_ENVELOPE_SHA256"
require_positive_integer "Release bundle size" "$RELEASE_BUNDLE_SIZE_BYTES"
require_positive_integer "Docker activation envelope size" "$DOCKER_ACTIVATION_ENVELOPE_SIZE_BYTES"
require_positive_integer "Docker activation generation" "$DOCKER_ACTIVATION_GENERATION"
[ "$DOCKER_ACTIVATION_ENVELOPE_PAYLOAD_TYPE" = "application/vnd.platform.docker-runtime-activation.v2+json" ] \
  || fail "Docker activation envelope payload type must be the exact v2 media type."
case "$DOCKER_ACTIVATION_RUNTIME_INTENT_ID" in
  [a-z]* ) ;;
  * ) fail "Docker activation runtime intent ID is invalid." ;;
esac
case "$DAST_SIGSTORE_SUBJECT" in "") fail "DAST Sigstore subject is required." ;; esac
[ "${#DAST_SIGSTORE_SUBJECT}" -le 512 ] || fail "DAST Sigstore subject exceeds its boundary."
require_positive_integer "Provider run ID" "$PROVIDER_RUN_ID"
require_positive_integer "Provider run attempt" "$PROVIDER_RUN_ATTEMPT"
require_positive_integer "Consumer run ID" "$CONSUMER_RUN_ID"
require_positive_integer "Consumer run attempt" "$CONSUMER_RUN_ATTEMPT"

require_input_file "Deployment admission policy" "$POLICY"
require_input_file "Artifact receipt" "$ARTIFACT_RECEIPT"
require_input_file "Deployment receipt" "$DEPLOYMENT_RECEIPT"
require_input_file "Provider metadata" "$PROVIDER_METADATA"
require_input_file "DAST provider receipt" "$DAST_PROVIDER_RECEIPT"
require_input_file "DAST activation authorization" "$DAST_ACTIVATION_AUTHORIZATION"
require_input_file "Release bundle manifest" "$RELEASE_BUNDLE_MANIFEST"
require_input_file "SSH private key" "$SSH_KEY_SOURCE"
require_input_file "SSH known-hosts input" "$KNOWN_HOSTS_SOURCE"

[ -x "$SCRIPT_ROOT/activation-request.mjs" ] || fail "The admitted ops image lacks its activation request producer." 78
[ -x "$SCRIPT_ROOT/ssh-known-host-endpoint.sh" ] || fail "The admitted ops image lacks its SSH endpoint verifier." 78
[ -x "$SCRIPT_ROOT/pinned-ssh-host-key.mjs" ] || fail "The admitted ops image lacks its exact SSH host-key verifier." 78
[ -x "$SCRIPT_ROOT/activation-receipt-policy.mjs" ] || fail "The admitted ops image lacks its activation receipt validator." 78

work=$(mktemp -d "${TMPDIR:-/tmp}/platform-activation-client.XXXXXX")
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
request="$work/activation-request.json"
receipt="$work/activation-receipt.json"

key_before=$(hash_file "$SSH_KEY_SOURCE")
known_before=$(hash_file "$KNOWN_HOSTS_SOURCE")
cp "$SSH_KEY_SOURCE" "$ssh_key"
cp "$KNOWN_HOSTS_SOURCE" "$known_hosts"
chmod 600 "$ssh_key" "$known_hosts"
[ "$(hash_file "$SSH_KEY_SOURCE")" = "$key_before" ] \
  && [ "$(hash_file "$ssh_key")" = "$key_before" ] \
  || fail "SSH private key changed during stable capture." 65
[ "$(hash_file "$KNOWN_HOSTS_SOURCE")" = "$known_before" ] \
  && [ "$(hash_file "$known_hosts")" = "$known_before" ] \
  || fail "SSH known-hosts input changed during stable capture." 65

sh "$SCRIPT_ROOT/ssh-known-host-endpoint.sh" "$REMOTE_HOST" "$SSH_PORT" "$known_hosts"
node "$SCRIPT_ROOT/pinned-ssh-host-key.mjs" verify \
  --remote "$REMOTE" \
  --port "$SSH_PORT" \
  --file "$known_hosts" >/dev/null || fail "Pinned SSH host trust validation failed." 65

node "$SCRIPT_ROOT/activation-request.mjs" \
  --policy "$POLICY" \
  --artifactReceipt "$ARTIFACT_RECEIPT" \
  --artifactReceiptSha256 "$ARTIFACT_RECEIPT_SHA256" \
  --deploymentReceipt "$DEPLOYMENT_RECEIPT" \
  --deploymentReceiptSha256 "$DEPLOYMENT_RECEIPT_SHA256" \
  --providerMetadata "$PROVIDER_METADATA" \
  --providerMetadataSha256 "$PROVIDER_METADATA_SHA256" \
  --dastProviderReceipt "$DAST_PROVIDER_RECEIPT" \
  --dastProviderReceiptSha256 "$DAST_PROVIDER_RECEIPT_SHA256" \
  --dastAuthorization "$DAST_ACTIVATION_AUTHORIZATION" \
  --dastAuthorizationSha256 "$DAST_ACTIVATION_AUTHORIZATION_SHA256" \
  --dastProviderMetadataSha256 "$DAST_PROVIDER_METADATA_SHA256" \
  --dastSigstoreBundleSha256 "$DAST_SIGSTORE_BUNDLE_SHA256" \
  --dastSigstoreSubject "$DAST_SIGSTORE_SUBJECT" \
  --dastChainSha256 "$DAST_CHAIN_SHA256" \
  --bundleManifest "$RELEASE_BUNDLE_MANIFEST" \
  --releaseBundleSha256 "$RELEASE_BUNDLE_SHA256" \
  --releaseBundleSizeBytes "$RELEASE_BUNDLE_SIZE_BYTES" \
  --releaseBundleManifestSha256 "$RELEASE_BUNDLE_MANIFEST_SHA256" \
  --dockerActivationEnvelopeSha256 "$DOCKER_ACTIVATION_ENVELOPE_SHA256" \
  --dockerActivationEnvelopeSizeBytes "$DOCKER_ACTIVATION_ENVELOPE_SIZE_BYTES" \
  --dockerActivationEnvelopePayloadType "$DOCKER_ACTIVATION_ENVELOPE_PAYLOAD_TYPE" \
  --dockerActivationRuntimeIntentId "$DOCKER_ACTIVATION_RUNTIME_INTENT_ID" \
  --dockerActivationGeneration "$DOCKER_ACTIVATION_GENERATION" \
  --repository "$REPOSITORY" \
  --commit "$COMMIT_SHA" \
  --tree "$TREE_SHA" \
  --targetHost "$REMOTE_HOST" \
  --environmentSha256 "$ENVIRONMENT_SHA256" \
  --providerRunId "$PROVIDER_RUN_ID" \
  --providerRunAttempt "$PROVIDER_RUN_ATTEMPT" \
  --consumerRunId "$CONSUMER_RUN_ID" \
  --consumerRunAttempt "$CONSUMER_RUN_ATTEMPT" \
  --sshPort "$SSH_PORT" \
  --output "$request" >/dev/null
[ -f "$request" ] && [ -s "$request" ] && [ ! -L "$request" ] \
  || fail "Activation request producer did not create one stable request." 65

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

# The provider/admin-owned promoter must already have installed the exact
# content-addressed release bundle and authenticated Docker activation envelope.
# This client never stages into the trusted CAS, transports raw provider/DAST
# evidence over SSH, or supplies a remote path or candidate executable.
ssh "$@" -- "$REMOTE" '/usr/bin/sudo -n -- /usr/local/libexec/platform-activation-broker activate' \
  < "$request" > "$receipt"

node "$SCRIPT_ROOT/activation-receipt-policy.mjs" \
  --request "$request" \
  --receipt "$receipt" >/dev/null

if [ -n "$RECEIPT_OUTPUT" ]; then
  case "$RECEIPT_OUTPUT" in
    */*) receipt_parent=${RECEIPT_OUTPUT%/*}; [ -n "$receipt_parent" ] || receipt_parent=/ ;;
    *) receipt_parent=. ;;
  esac
  [ -d "$receipt_parent" ] && [ ! -L "$receipt_parent" ] || fail "Activation receipt output parent is invalid."
  (umask 077; set -C; : > "$RECEIPT_OUTPUT") 2>/dev/null \
    || fail "Activation receipt output already exists or is not writable."
  cp "$receipt" "$RECEIPT_OUTPUT"
  chmod 600 "$RECEIPT_OUTPUT"
fi

cat "$receipt"
