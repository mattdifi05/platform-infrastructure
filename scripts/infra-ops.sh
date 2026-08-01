#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INFRA_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
GIT_OBJECT_ROOT=${DEPLOY_GIT_OBJECT_ROOT:-$INFRA_ROOT}

command -v docker >/dev/null 2>&1 || { echo "Docker is required for the admitted ops runner." >&2; exit 127; }
OPS_COMMAND=${1:-}
[ -n "$OPS_COMMAND" ] || { echo "An ops command is required." >&2; exit 64; }
SOURCE_ARCHIVE_INPUT=${DEPLOY_SOURCE_ARCHIVE_PATH:-}
[ -f "$SOURCE_ARCHIVE_INPUT" ] && [ -r "$SOURCE_ARCHIVE_INPUT" ] && [ -s "$SOURCE_ARCHIVE_INPUT" ] && [ ! -L "$SOURCE_ARCHIVE_INPUT" ] || {
  echo "The exact provider-authenticated infrastructure source archive is required." >&2
  exit 78
}
SOURCE_ROOT_RAW=${PROJECT_SOURCE_ROOT:-${PROJECT_SOURCE_DIR:-$INFRA_ROOT/../project}}
if [ -d "$SOURCE_ROOT_RAW" ]; then SOURCE_ROOT=$(CDPATH= cd -- "$SOURCE_ROOT_RAW" && pwd); else SOURCE_ROOT=; fi
INFRA_CONTAINER_ROOT=/workspace
INPUT_CONTAINER_ROOT=/run/platform-input
SOURCE_CONTAINER_ROOT=/project
DATA_CONTAINER_ROOT=/runtime-data
SECRETS_CONTAINER_ROOT=/runtime-secrets
OPS_UID=${PLATFORM_OPS_UID:-$(id -u)}
OPS_GID=${PLATFORM_OPS_GID:-$(id -g)}
OPS_DOCKER_MODE=${PLATFORM_OPS_DOCKER_MODE:-none}

case "$OPS_DOCKER_MODE" in
  none)
    OPS_NETWORK=none
    OPS_DOCKER_HOST=
    OPS_DOCKER_API_VERSION=
    ;;
  *)
    echo "Generic Docker API access is forbidden. A future authenticated fixed-action broker is required for Docker-backed ops." >&2
    exit 78
    ;;
esac

snapshot_dir=$(mktemp -d "${TMPDIR:-/tmp}/platform-ops-source.XXXXXX")
snapshot_archive="$snapshot_dir/infra-source.tar"
cleanup() {
  rm -rf "$snapshot_dir"
}
stop_on_signal() {
  status=$1
  trap - EXIT HUP INT TERM
  cleanup
  exit "$status"
}
trap cleanup EXIT
trap 'stop_on_signal 129' HUP
trap 'stop_on_signal 130' INT
trap 'stop_on_signal 143' TERM
cp "$SOURCE_ARCHIVE_INPUT" "$snapshot_archive"
chmod 400 "$snapshot_archive"
if command -v sha256sum >/dev/null 2>&1; then
  snapshot_sha256=$(sha256sum "$snapshot_archive" | awk '{print $1}')
else
  snapshot_sha256=$(shasum -a 256 "$snapshot_archive" | awk '{print $1}')
fi
EXPECTED_SOURCE_ARCHIVE_SHA256=${DEPLOY_SOURCE_ARCHIVE_SHA256:-}
case "$EXPECTED_SOURCE_ARCHIVE_SHA256" in *[!a-f0-9]*|"") exit 78 ;; esac
[ "${#EXPECTED_SOURCE_ARCHIVE_SHA256}" -eq 64 ] || exit 78
[ "$snapshot_sha256" = "$EXPECTED_SOURCE_ARCHIVE_SHA256" ] || {
  echo "Exact provider-authenticated source archive differs from the trusted deployment receipt." >&2
  exit 1
}

if [ "${PLATFORM_IMMUTABLE_RELEASE_ROOT:-0}" = 1 ]; then
  archive_inspection=$(node "$SCRIPT_DIR/source-archive-policy.mjs" \
    --extractedRoot "$INFRA_ROOT" \
    --archive "$snapshot_archive" \
    --sha256 "$snapshot_sha256" \
    --commit "$DEPLOY_RELEASE_SHA" \
    --requireImmutableOwnership true)
  OPS_GIT_COMMIT=$DEPLOY_RELEASE_SHA
  OPS_GIT_BRANCH=main
else
  archive_inspection=$(node "$SCRIPT_DIR/source-archive-policy.mjs" \
    --archive "$snapshot_archive" \
    --gitRoot "$GIT_OBJECT_ROOT" \
    --commit "$DEPLOY_RELEASE_SHA" \
    --tree "$DEPLOY_RELEASE_TREE" \
    --sha256 "$snapshot_sha256")
  OPS_GIT_COMMIT=$(git -C "$INFRA_ROOT" rev-parse HEAD)
  OPS_GIT_BRANCH=$(git -C "$INFRA_ROOT" rev-parse --abbrev-ref HEAD)
fi
OPS_GIT_TRACKED_FILES_B64=$(printf '%s' "$archive_inspection" | jq -r '.files[]' | awk '{ printf "%s%c", $0, 0 }' | base64 | tr -d '\n')

admitted=$(sh "$SCRIPT_DIR/ops-image-trust.sh") || exit $?
OPS_IMAGE=$(printf '%s' "$admitted" | jq -er '.image')
OPS_IMAGE_ID=$(printf '%s' "$admitted" | jq -er '.imageId')
ADMITTED_SOURCE_ARCHIVE_SHA256=$(printf '%s' "$admitted" | jq -er '.sourceArchiveSha256')
case "$OPS_IMAGE" in [a-z0-9]*/*@sha256:????????????????????????????????????????????????????????????????) ;; *) exit 78 ;; esac
case "$OPS_IMAGE_ID" in sha256:????????????????????????????????????????????????????????????????) ;; *) exit 78 ;; esac
[ "$ADMITTED_SOURCE_ARCHIVE_SHA256" = "$snapshot_sha256" ] || exit 1

# Recheck after image inspection and archive creation. Execution never consumes
# checkout bytes, but any concurrent checkout mutation still invalidates this
# invocation before Docker receives the immutable commit archive.
if [ "${PLATFORM_IMMUTABLE_RELEASE_ROOT:-0}" = 1 ]; then
  node "$SCRIPT_DIR/source-archive-policy.mjs" \
    --extractedRoot "$INFRA_ROOT" \
    --archive "$snapshot_archive" \
    --sha256 "$snapshot_sha256" \
    --commit "$DEPLOY_RELEASE_SHA" \
    --requireImmutableOwnership true >/dev/null
else
  [ "$(git -C "$INFRA_ROOT" rev-parse HEAD)" = "$DEPLOY_RELEASE_SHA" ] \
    && [ "$(git -C "$INFRA_ROOT" rev-parse "${DEPLOY_RELEASE_SHA}^{tree}")" = "$DEPLOY_RELEASE_TREE" ] \
    && [ -z "$(git -C "$INFRA_ROOT" status --porcelain --untracked-files=all)" ] || {
    echo "Ops admission checkout changed after validation; refusing execution." >&2
    exit 1
  }
fi
OPS_GIT_DIRTY=0

if [ "${PLATFORM_IMMUTABLE_RELEASE_ROOT:-0}" = 1 ]; then
  DATA_HOST_ROOT=${PLATFORM_DATA_ROOT:-}
  STATE_HOST_ROOT=${PLATFORM_STATE_ROOT:-}
  SECRETS_HOST_ROOT=${PLATFORM_SECRETS_ROOT:-}
  ENV_HOST_FILE=${PLATFORM_ENV_FILE:-}
else
  DATA_HOST_ROOT=${PLATFORM_DATA_ROOT:-$INFRA_ROOT}
  STATE_HOST_ROOT=${PLATFORM_STATE_ROOT:-$DATA_HOST_ROOT/release-state}
  SECRETS_HOST_ROOT=${PLATFORM_SECRETS_ROOT:-$INFRA_ROOT/secrets}
  ENV_HOST_FILE=${PLATFORM_ENV_FILE:-$INFRA_ROOT/.env}
  for relative in reports backups release .tmp security/sbom security/dast projects-portal/state traefik/acme traefik/certs; do
    mkdir -p "$DATA_HOST_ROOT/$relative"
  done
  mkdir -p "$STATE_HOST_ROOT" "$SECRETS_HOST_ROOT"
fi
for host_root in "$DATA_HOST_ROOT" "$STATE_HOST_ROOT" "$SECRETS_HOST_ROOT"; do
  case "$host_root" in /*) ;; *) echo "Ops host roots must be explicit absolute paths." >&2; exit 78 ;; esac
  [ -d "$host_root" ] && [ ! -L "$host_root" ] || { echo "An admitted ops host root is missing or a symlink." >&2; exit 78; }
done
[ -f "$ENV_HOST_FILE" ] && [ -r "$ENV_HOST_FILE" ] && [ ! -L "$ENV_HOST_FILE" ] || {
  echo "The root-owned admitted environment snapshot is required." >&2
  exit 78
}
if [ "${PLATFORM_IMMUTABLE_RELEASE_ROOT:-0}" = 1 ]; then
  case "$ENV_HOST_FILE" in "$STATE_HOST_ROOT"/environment.env) ;; *) echo "Environment snapshot must be the canonical release-state file." >&2; exit 78 ;; esac
fi

github_capability=0
cloudflare_capability=0
cosign_capability=0
backup_capability=0
mount_backups=0
mount_release=0
mount_temp=0
mount_security=0
mount_project_state=0
mount_traefik_state=0
mount_environment=0
mount_secrets=0
source_capability=0
secrets_mode=ro
case "$OPS_COMMAND" in
  external-uptime-check|github-attestation-evidence|release-artifact-gate|release-evidence|production-go-no-go|github-actions-run-evidence|github-branch-protection|github-environments|github-actions-config|pre-go-live-evidence)
    github_capability=1
    OPS_NETWORK=bridge
    ;;
esac
case "$OPS_COMMAND" in
  cloudflare-access-admin|cloudflare-from-zero)
    cloudflare_capability=1
    OPS_NETWORK=bridge
    ;;
esac
case "$OPS_COMMAND" in
  sign-images) cosign_capability=1; OPS_NETWORK=bridge ;;
esac
case "$OPS_COMMAND" in
  backup-*|restore-*|full-restore-drill|offsite-*|prune-*|retention-evidence|pre-go-live-evidence)
    backup_capability=1
    mount_backups=1
    mount_temp=1
    mount_project_state=1
    mount_environment=1
    mount_secrets=1
    source_capability=1
    ;;
  secret-manager|init-local-secrets)
    secrets_mode=rw
    mount_secrets=1
    ;;
esac
case "$OPS_COMMAND" in
  release-*|github-attestation-evidence|production-go-no-go|pre-go-live-evidence|sign-images)
    mount_release=1
    mount_security=1
    mount_temp=1
    ;;
esac
case "$OPS_COMMAND" in
  platform-admin-audit|audit-log-evidence|execute-backup-job|backup-platform-catalog)
    mount_project_state=1
    ;;
esac
case "$OPS_COMMAND" in
  project-router-tests|backup-applications)
    source_capability=1
    ;;
esac
case "$OPS_COMMAND" in
  production-preflight|pre-go-live-evidence|production-go-no-go|managed-secrets-preflight|dr-readiness-check)
    mount_environment=1
    mount_secrets=1
    ;;
esac
case "$OPS_COMMAND" in
  cloudflare-*|certificate-expiry-check|waf-smoke)
    mount_traefik_state=1
    ;;
esac

# Candidate-controlled code never receives Docker API access. Commands that
# require container mutation remain fail-closed until the root-owned
# fixed-action capability broker is installed.
case "$OPS_COMMAND" in
  backup-*|restore-*|full-restore-drill|offsite-*|prune-*|infra-health|production-preflight|pre-go-live-evidence|vps-preflight|vps-postdeploy|backup-scheduler)
    echo "EXTERNAL-PENDING: Docker-backed ops require the authenticated fixed-action capability broker." >&2
    exit 78
    ;;
esac

require_mount_dir() {
  [ -d "$1" ] && [ ! -L "$1" ] || {
    echo "Required admitted ops data directory is missing or a symlink: $1" >&2
    exit 78
  }
}
require_mount_dir "$DATA_HOST_ROOT/reports"
[ "$mount_backups" -eq 0 ] || require_mount_dir "$DATA_HOST_ROOT/backups"
[ "$mount_release" -eq 0 ] || require_mount_dir "$DATA_HOST_ROOT/release"
[ "$mount_temp" -eq 0 ] || require_mount_dir "$DATA_HOST_ROOT/.tmp"
if [ "$mount_security" -eq 1 ]; then
  require_mount_dir "$DATA_HOST_ROOT/security/sbom"
  require_mount_dir "$DATA_HOST_ROOT/security/dast"
fi
[ "$mount_project_state" -eq 0 ] || require_mount_dir "$DATA_HOST_ROOT/projects-portal/state"
if [ "$mount_traefik_state" -eq 1 ]; then
  require_mount_dir "$DATA_HOST_ROOT/traefik/acme"
  require_mount_dir "$DATA_HOST_ROOT/traefik/certs"
fi

# The trusted receipt authorizes both the digest reference and the exact local
# image ID. --pull=never plus the ID closes tag/digest remapping at execution.
run_ops_container() {
  # Build Docker argv only with positional parameters. In particular, a source
  # path containing whitespace or Docker-looking tokens remains one -v value.
  set -- "$OPS_IMAGE_ID" "$@"
  set -- -w "$INFRA_CONTAINER_ROOT" "$@"
  set -- -v "$DEPLOY_TRUSTED_PROVIDER_METADATA_PATH:$INPUT_CONTAINER_ROOT/provider-run.json:ro" "$@"
  set -- -v "$DEPLOY_ADMISSION_RECEIPT_PATH:$INPUT_CONTAINER_ROOT/deployment-receipt.json:ro" "$@"
  set -- -v "$DEPLOY_ARTIFACT_RECEIPT_PATH:$INPUT_CONTAINER_ROOT/artifact-receipt.json:ro" "$@"
  set -- -v "$snapshot_archive:$INPUT_CONTAINER_ROOT/infra-source.tar:ro" "$@"
  set -- -v "$DATA_HOST_ROOT/reports:$DATA_CONTAINER_ROOT/reports" "$@"
  [ "$mount_backups" -eq 0 ] || set -- -v "$DATA_HOST_ROOT/backups:$DATA_CONTAINER_ROOT/backups" "$@"
  [ "$mount_release" -eq 0 ] || set -- -v "$DATA_HOST_ROOT/release:$DATA_CONTAINER_ROOT/release" "$@"
  [ "$mount_temp" -eq 0 ] || set -- -v "$DATA_HOST_ROOT/.tmp:$DATA_CONTAINER_ROOT/.tmp" "$@"
  if [ "$mount_security" -eq 1 ]; then
    set -- -v "$DATA_HOST_ROOT/security/sbom:$DATA_CONTAINER_ROOT/security/sbom" "$@"
    set -- -v "$DATA_HOST_ROOT/security/dast:$DATA_CONTAINER_ROOT/security/dast" "$@"
  fi
  [ "$mount_project_state" -eq 0 ] || set -- -v "$DATA_HOST_ROOT/projects-portal/state:$DATA_CONTAINER_ROOT/projects-portal/state" "$@"
  if [ "$mount_traefik_state" -eq 1 ]; then
    set -- -v "$DATA_HOST_ROOT/traefik/acme:$DATA_CONTAINER_ROOT/traefik/acme" "$@"
    set -- -v "$DATA_HOST_ROOT/traefik/certs:$DATA_CONTAINER_ROOT/traefik/certs:ro" "$@"
  fi
  [ "$mount_secrets" -eq 0 ] || set -- -v "$SECRETS_HOST_ROOT:$SECRETS_CONTAINER_ROOT:$secrets_mode" "$@"
  [ "$mount_environment" -eq 0 ] || set -- -v "$STATE_HOST_ROOT:$STATE_HOST_ROOT:ro" "$@"
  set -- -e "PLATFORM_INFRA_SNAPSHOT_SHA256=$snapshot_sha256" "$@"
  set -- -e "PLATFORM_INFRA_SNAPSHOT_ARCHIVE=$INPUT_CONTAINER_ROOT/infra-source.tar" "$@"
  set -- -e "PLATFORM_INFRA_ROOT=$INFRA_CONTAINER_ROOT" "$@"
  set -- -e "DEPLOY_TRUSTED_PROVIDER_METADATA_PATH=$INPUT_CONTAINER_ROOT/provider-run.json" "$@"
  set -- -e "DEPLOY_ADMISSION_RECEIPT_PATH=$INPUT_CONTAINER_ROOT/deployment-receipt.json" "$@"
  set -- -e "DEPLOY_ARTIFACT_RECEIPT_PATH=$INPUT_CONTAINER_ROOT/artifact-receipt.json" "$@"
  set -- -e "PLATFORM_OPS_IMAGE=$OPS_IMAGE" "$@"
  set -- -e "PLATFORM_OPS_CONTAINER=1" "$@"
  set -- -e "PLATFORM_INFRA_HOST_ROOT=$INFRA_ROOT" "$@"
  set -- -e "PLATFORM_INFRA_CONTAINER_ROOT=$INFRA_CONTAINER_ROOT" "$@"
  set -- -e "PLATFORM_RELEASE_HOST_ROOT=$INFRA_ROOT" "$@"
  set -- -e "PLATFORM_RELEASE_CONTAINER_ROOT=$INFRA_CONTAINER_ROOT" "$@"
  set -- -e "PLATFORM_DATA_ROOT=$DATA_CONTAINER_ROOT" "$@"
  set -- -e "PLATFORM_DATA_HOST_ROOT=$DATA_HOST_ROOT" "$@"
  set -- -e "PLATFORM_DATA_CONTAINER_ROOT=$DATA_CONTAINER_ROOT" "$@"
  set -- -e "PLATFORM_STATE_ROOT=$STATE_HOST_ROOT" "$@"
  set -- -e "PLATFORM_STATE_HOST_ROOT=$STATE_HOST_ROOT" "$@"
  set -- -e "PLATFORM_STATE_CONTAINER_ROOT=$STATE_HOST_ROOT" "$@"
  set -- -e "PLATFORM_SECRETS_ROOT=$SECRETS_CONTAINER_ROOT" "$@"
  set -- -e "PLATFORM_SECRETS_HOST_ROOT=$SECRETS_HOST_ROOT" "$@"
  set -- -e "PLATFORM_SECRETS_CONTAINER_ROOT=$SECRETS_CONTAINER_ROOT" "$@"
  set -- -e "PLATFORM_ENV_FILE=$STATE_HOST_ROOT/environment.env" "$@"
  set -- -e "PROJECT_STATE_ROOT=$DATA_CONTAINER_ROOT/projects-portal/state" "$@"
  set -- -e "PLATFORM_CLOSED_HOST_PATH_MAPPINGS=1" "$@"
  set -- -e "PLATFORM_GIT_TRACKED_FILES_B64=$OPS_GIT_TRACKED_FILES_B64" "$@"
  set -- -e "PLATFORM_GIT_DIRTY=$OPS_GIT_DIRTY" "$@"
  set -- -e "PLATFORM_GIT_COMMIT=$OPS_GIT_COMMIT" "$@"
  set -- -e "PLATFORM_GIT_TREE=$DEPLOY_RELEASE_TREE" "$@"
  set -- -e "PLATFORM_GIT_BRANCH=$OPS_GIT_BRANCH" "$@"
  set -- -e "PROJECT_SOURCE_ROOT=$SOURCE_CONTAINER_ROOT" "$@"
  set -- -e HOME=/tmp "$@"
  set -- -e "DOCKER_HOST=$OPS_DOCKER_HOST" "$@"
  set -- -e "DOCKER_API_VERSION=$OPS_DOCKER_API_VERSION" "$@"
  for name in \
    DEPLOY_ADMISSION_RECEIPT_SHA256 DEPLOY_ARTIFACT_RECEIPT_SHA256 \
    DEPLOY_REPO DEPLOY_RELEASE_SHA DEPLOY_RELEASE_TREE DEPLOY_SOURCE_ARCHIVE_SHA256 \
    DEPLOY_TRUSTED_PROVIDER_METADATA_SHA256 \
    DEPLOY_TRUSTED_PROVIDER_RUN_ATTEMPT DEPLOY_TRUSTED_PROVIDER_RUN_ID \
    GITHUB_API_VERSION GITHUB_REF GITHUB_REF_NAME GITHUB_REPOSITORY GITHUB_SHA
  do
    set -- -e "$name" "$@"
  done
  set -- -e PLATFORM_IMMUTABLE_RELEASE_ROOT "$@"
  if [ "$github_capability" -eq 1 ]; then
    set -- -e GITHUB_TOKEN "$@"
    set -- -e GH_TOKEN "$@"
  fi
  if [ "$cloudflare_capability" -eq 1 ]; then
    set -- -e CLOUDFLARE_API_TOKEN "$@"
    set -- -e CLOUDFLARE_ACCOUNT_ID "$@"
  fi
  if [ "$cosign_capability" -eq 1 ]; then
    set -- -e COSIGN_KEY "$@"
  fi
  if [ "$backup_capability" -eq 1 ]; then
    for name in \
      BACKUP_SIGNING_KEYS_FILE RESTIC_HOSTNAME RESTIC_IMAGE RESTIC_KEEP_LAST \
      RESTIC_MAX_REPOSITORY_BYTES RESTIC_PASSWORD_FILE RESTIC_REPOSITORY \
      RESTIC_REQUIRE_IMMUTABLE_IMAGE RESTIC_NO_PRUNE RESTIC_SKIP_RETENTION \
      RCLONE_CONFIG \
      AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_DEFAULT_REGION \
      RESTIC_AWS_ASSUME_ROLE_ARN RESTIC_AWS_ASSUME_ROLE_SESSION_NAME \
      RESTIC_AWS_ASSUME_ROLE_EXTERNAL_ID RESTIC_AWS_ASSUME_ROLE_REGION \
      RESTIC_AWS_ASSUME_ROLE_STS_ENDPOINT \
      B2_ACCOUNT_ID B2_ACCOUNT_KEY \
      AZURE_ACCOUNT_NAME AZURE_ACCOUNT_KEY AZURE_ACCOUNT_SAS AZURE_ENDPOINT_SUFFIX \
      GOOGLE_PROJECT_ID GOOGLE_ACCESS_TOKEN \
      OS_AUTH_URL OS_REGION_NAME OS_USERNAME OS_USER_ID OS_PASSWORD \
      OS_TENANT_ID OS_TENANT_NAME OS_USER_DOMAIN_NAME OS_USER_DOMAIN_ID \
      OS_PROJECT_NAME OS_PROJECT_DOMAIN_NAME
    do
      set -- -e "$name" "$@"
    done
  fi
  if [ "$source_capability" -eq 1 ]; then
    [ -n "$SOURCE_ROOT" ] || { echo "An admitted project source root is required for this ops command." >&2; exit 78; }
    set -- -v "$SOURCE_ROOT:$SOURCE_CONTAINER_ROOT:ro" "$@"
  fi
  set -- --network "$OPS_NETWORK" "$@"
  docker run --rm --pull=never -i \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m \
    --tmpfs "$INFRA_CONTAINER_ROOT:rw,nosuid,nodev,size=512m,uid=$OPS_UID,gid=$OPS_GID,mode=0700" \
    --security-opt no-new-privileges:true \
    --cap-drop ALL \
    --user "$OPS_UID:$OPS_GID" \
    "$@"
}

run_ops_container "$@"
