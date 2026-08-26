#!/usr/bin/env bash
set -euo pipefail

# Deterministic render-only wrapper for the V1 LOCAL_PRIVATE GREENFIELD Compose
# projection. Self-contained sibling of compose-vps.sh hard-bound to the
# dedicated greenfield namespace (canonical project platform_infra_greenfield).
# This wrapper never contacts anything beyond the pinned local Docker socket
# endpoint through the pinned Compose binary, never mutates Docker state and
# validates every render through scripts/greenfield-core-policy.mjs against
# config/no-hosted-workloads.greenfield.lock.json.
#
# Request modes:
#   compose-greenfield.sh config --format json   -> canonical render envelope on stdout
#   compose-greenfield.sh render-sha256          -> sha256 of the canonical render envelope
#
# Authority marker: GREENFIELD_RENDER_AUTHORITY=1 is always set internally for
# the LOCAL_PRIVATE derivative chain (compose.local-private.yaml is mandatory
# here and never gated behind PLATFORM_V1_LOCAL_PRIVATE_RENDER).

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PROJECT_NAME=platform_infra_greenfield
CANONICAL_DOCKER_HOST=unix:///var/run/docker.sock
# Trust-zone overlays render physical names as ${PLATFORM_NETWORK_PREFIX}_<zone>;
# the canonical greenfield prefix keeps the platform_ logical suffix so every
# rendered network equals greenfieldNetworkName("<platform>_<zone>").
CANONICAL_NETWORK_PREFIX=platform_infra_greenfield_platform
CANONICAL_MARIADB_DATA_VOLUME=greenfield_mariadb_data
GREENFIELD_LOCK=$ROOT_DIR/config/no-hosted-workloads.greenfield.lock.json
REQUEST_MODE=invalid

sha256_stream() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{ print $1 }'
  else
    shasum -a 256 | awk '{ print $1 }'
  fi
}

if (( $# == 1 )) && [[ "$1" == render-sha256 ]]; then
  REQUEST_MODE=render-sha256
elif (( $# == 3 )) && [[ "$1" == config && "$2" == --format && "$3" == json ]]; then
  REQUEST_MODE=compose-config
else
  printf '%s\n' "Only 'config --format json' and 'render-sha256' request modes are allowed." >&2
  exit 2
fi

for argument in "$@"; do
  case "$argument" in
    -f|-f?*|--file|--file=*|-p|-p?*|--project-name|--project-name=*|--project-directory|--project-directory=*|--env-file|--env-file=*|--profile|--profile=*|--scale|--scale=*|scale)
      printf '%s\n' "Caller-controlled Compose files, environment, projects and profiles are forbidden; this wrapper is bound to the canonical greenfield project platform_infra_greenfield." >&2
      exit 2
      ;;
  esac
done

case "${DOCKER_HOST:-}" in
  ""|"$CANONICAL_DOCKER_HOST") ;;
  *) printf 'Caller-selected DOCKER_HOST is forbidden: %s\n' "$DOCKER_HOST" >&2; exit 2 ;;
esac
case "${DOCKER_CONTEXT:-}" in
  ""|default) ;;
  *) printf 'Caller-selected DOCKER_CONTEXT is forbidden: %s\n' "$DOCKER_CONTEXT" >&2; exit 2 ;;
esac
unset DOCKER_CONTEXT

if [[ -n "${COMPOSE_PROJECT_NAME:-}" ]]; then
  printf '%s\n' "COMPOSE_PROJECT_NAME overrides are forbidden: this wrapper is bound to the canonical project platform_infra_greenfield." >&2
  exit 2
fi

case "${WAF_HTTP_BIND:-}${WAF_HTTPS_BIND:-}" in
  "") ;;
  *) printf '%s\n' "Caller-selected WAF_HTTP_BIND/WAF_HTTPS_BIND are forbidden: edge binds derive only from GREENFIELD_TOPOLOGY." >&2
     exit 2
     ;;
esac
case "${GREENFIELD_TOPOLOGY:-}" in
  PARALLEL)
    WAF_HTTP_BIND=0.0.0.0:18080
    WAF_HTTPS_BIND=0.0.0.0:18443
    ;;
  CUTOVER)
    WAF_HTTP_BIND=0.0.0.0:80
    WAF_HTTPS_BIND=0.0.0.0:443
    ;;
  *)
    printf '%s\n' "GREENFIELD_TOPOLOGY must be PARALLEL or CUTOVER." >&2
    exit 2
    ;;
esac

case "${PLATFORM_NETWORK_PREFIX:-}" in
  ""|"$CANONICAL_NETWORK_PREFIX") ;;
  *)
    printf '%s\n' "PLATFORM_NETWORK_PREFIX is bound to the canonical greenfield namespace platform_infra_greenfield_platform." >&2
    exit 2
    ;;
esac
export PLATFORM_NETWORK_PREFIX=$CANONICAL_NETWORK_PREFIX

case "${MARIADB_DATA_VOLUME:-}" in
  ""|"$CANONICAL_MARIADB_DATA_VOLUME") ;;
  *)
    printf '%s\n' "MARIADB_DATA_VOLUME must be unset or exactly greenfield_mariadb_data." >&2
    exit 2
    ;;
esac
export MARIADB_DATA_VOLUME=$CANONICAL_MARIADB_DATA_VOLUME

# Trust artifacts are issued per-render by the live executor. The parallel
# render may omit them; the cutover render must present freshly issued ones so
# the broker can never mount a brownfield-era intent/receipt pair.
if [[ "$GREENFIELD_TOPOLOGY" = CUTOVER ]]; then
  for trust_variable in \
    DOCKER_ACTION_RUNTIME_INTENT_FILE \
    DOCKER_ACTION_ACTIVE_RECEIPT_FILE \
    DOCKER_ACTION_RUNTIME_INTENT_ID \
    DOCKER_ACTION_ACTIVE_RECEIPT_SHA256; do
    [[ -n "${!trust_variable:-}" ]] || {
      printf 'CUTOVER renders require a freshly issued trust artifact: %s\n' "$trust_variable" >&2
      exit 2
    }
  done
fi

for required_variable in \
  PLATFORM_SECRETS_ROOT \
  CONTROL_CENTER_FIRST_CONFIGURATION_BOOTSTRAP_TOKEN_SECRET_FILE \
  CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE \
  PLATFORM_STATE_DIR \
  PHP_PROJECTS_DIR \
  PLATFORM_CERTS_DIR \
  WAF_TLS_KEY_GID; do
  [[ -n "${!required_variable:-}" ]] || {
    printf 'Required greenfield environment variable is empty or unset: %s\n' "$required_variable" >&2
    exit 2
  }
done

ENV_FILE=${COMPOSE_ENV_FILE:-$ROOT_DIR/.env}
case "$ENV_FILE" in
  /*) ;;
  *) ENV_FILE="$ROOT_DIR/$ENV_FILE" ;;
esac
[[ -f "$ENV_FILE" ]] || {
  printf 'Greenfield compose env file not found: %s\n' "$ENV_FILE" >&2
  exit 1
}

[[ -f "$GREENFIELD_LOCK" ]] || {
  printf 'Greenfield no-hosted workload lock not found: %s\n' "$GREENFIELD_LOCK" >&2
  exit 1
}
node -e 'const lock = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")); if (lock.projectName !== "platform_infra_greenfield") process.exit(1);' "$GREENFIELD_LOCK" || {
  printf '%s\n' "Greenfield no-hosted workload lock is not bound to platform_infra_greenfield." >&2
  exit 1
}

runtime_identity_variables=(
  PLATFORM_RUNTIME_CANDIDATE_ID
  PLATFORM_RUNTIME_COMMIT
  PLATFORM_RUNTIME_TREE
  PLATFORM_RUNTIME_DEPLOYMENT_ID
  PLATFORM_RUNTIME_SOURCE_RENDER_SHA256
  PLATFORM_RUNTIME_WORKLOAD_LOCK_SHA256
)
runtime_identity_count=0
for runtime_identity_variable in "${runtime_identity_variables[@]}"; do
  [[ -z "${!runtime_identity_variable:-}" ]] || runtime_identity_count=$((runtime_identity_count + 1))
done
if (( runtime_identity_count != 0 && runtime_identity_count != ${#runtime_identity_variables[@]} )); then
  printf '%s\n' "Runtime identity labels require the complete approved candidate/deployment tuple." >&2
  exit 1
fi
if (( runtime_identity_count == ${#runtime_identity_variables[@]} )); then
  [[ "$PLATFORM_RUNTIME_CANDIDATE_ID" =~ ^[a-f0-9]{64}$ ]] || { printf '%s\n' "Invalid runtime candidate ID." >&2; exit 1; }
  [[ "$PLATFORM_RUNTIME_COMMIT" =~ ^([a-f0-9]{40}|[a-f0-9]{64})$ ]] || { printf '%s\n' "Invalid runtime commit." >&2; exit 1; }
  [[ "$PLATFORM_RUNTIME_TREE" =~ ^([a-f0-9]{40}|[a-f0-9]{64})$ ]] || { printf '%s\n' "Invalid runtime tree." >&2; exit 1; }
  [[ "$PLATFORM_RUNTIME_DEPLOYMENT_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$ ]] || { printf '%s\n' "Invalid runtime deployment ID." >&2; exit 1; }
  [[ "$PLATFORM_RUNTIME_SOURCE_RENDER_SHA256" =~ ^[a-f0-9]{64}$ ]] || { printf '%s\n' "Invalid runtime source render SHA256." >&2; exit 1; }
  [[ "$PLATFORM_RUNTIME_WORKLOAD_LOCK_SHA256" =~ ^[a-f0-9]{64}$ ]] || { printf '%s\n' "Invalid runtime workload lock SHA256." >&2; exit 1; }
fi

if [[ -n "${PLATFORM_TEST_DOCKER_COMPOSE_BIN:-}" ]]; then
  [[ "$PLATFORM_TEST_DOCKER_COMPOSE_BIN" = /* && -x "$PLATFORM_TEST_DOCKER_COMPOSE_BIN" && ! -d "$PLATFORM_TEST_DOCKER_COMPOSE_BIN" ]] || {
    printf '%s\n' "PLATFORM_TEST_DOCKER_COMPOSE_BIN must be one absolute executable path." >&2
    exit 2
  }
  compose_binary=("$PLATFORM_TEST_DOCKER_COMPOSE_BIN")
else
  command -v docker >/dev/null 2>&1 || {
    printf '%s\n' "The pinned docker compose binary is unavailable." >&2
    exit 1
  }
  compose_cli_version=$(docker compose version --short 2>/dev/null || true)
  [[ "$compose_cli_version" =~ ^v?5\.3\. ]] || {
    printf 'The pinned docker compose binary must be version 5.3.x: %s\n' "${compose_cli_version:-<unavailable>}" >&2
    exit 1
  }
  compose_binary=(docker compose)
fi

handoff_directory=$(mktemp -d "${TMPDIR:-/tmp}/greenfield-compose-handoff.XXXXXX")
chmod 700 "$handoff_directory"
umask 077
cleanup_handoff() {
  /bin/rm -rf -- "$handoff_directory"
}
trap cleanup_handoff EXIT

render_file=$handoff_directory/render.json
environment_snapshot_file=$handoff_directory/environment.env
: > "$render_file"
: > "$environment_snapshot_file"

child_environment=(
  /usr/bin/env
  -i
  "PATH=${PATH:-/usr/bin:/bin}"
  "DOCKER_HOST=$CANONICAL_DOCKER_HOST"
  "GREENFIELD_RENDER_AUTHORITY=1"
  "PLATFORM_NETWORK_PREFIX=$CANONICAL_NETWORK_PREFIX"
  "PLATFORM_SECRETS_ROOT=$PLATFORM_SECRETS_ROOT"
  "CONTROL_CENTER_FIRST_CONFIGURATION_BOOTSTRAP_TOKEN_SECRET_FILE=$CONTROL_CENTER_FIRST_CONFIGURATION_BOOTSTRAP_TOKEN_SECRET_FILE"
  "CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE=$CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE"
  "PLATFORM_STATE_DIR=$PLATFORM_STATE_DIR"
  "PHP_PROJECTS_DIR=$PHP_PROJECTS_DIR"
  "PLATFORM_CERTS_DIR=$PLATFORM_CERTS_DIR"
  "WAF_TLS_KEY_GID=$WAF_TLS_KEY_GID"
  "WAF_HTTP_BIND=$WAF_HTTP_BIND"
  "WAF_HTTPS_BIND=$WAF_HTTPS_BIND"
)
if [[ -n "${HOME:-}" ]]; then
  child_environment+=("HOME=$HOME")
fi
interpolation_passthrough_variables=(
  HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE
  DOCKER_ACTION_ACTIVATION_INBOX
  DOCKER_ACTION_RUNTIME_INTENT_FILE
  DOCKER_ACTION_ACTIVE_RECEIPT_FILE
  DOCKER_ACTION_RUNTIME_INTENT_ID
  DOCKER_ACTION_ACTIVE_RECEIPT_SHA256
  DOCKER_ACTION_COMBINED_RENDER_SHA256
  PLATFORM_BACKUP_SCHEDULER_IMAGE_REPOSITORY
  PLATFORM_BACKUP_SCHEDULER_IMAGE_SHA256
  PLATFORM_PROVIDER_ACTIVATION_SIDECAR_IMAGE_REPOSITORY
  PLATFORM_PROVIDER_ACTIVATION_SIDECAR_IMAGE_SHA256
  PLATFORM_DOCKER_ACTION_BROKER_IMAGE_REPOSITORY
  PLATFORM_DOCKER_ACTION_BROKER_IMAGE_SHA256
  PLATFORM_OPS_IMAGE
  CONTROL_CENTER_IMAGE
  PROJECT_ROUTER_IMAGE
  PLATFORM_ALERT_DISPATCHER_IMAGE
)
for interpolation_variable in "${interpolation_passthrough_variables[@]}"; do
  if [[ -n "${!interpolation_variable:-}" ]]; then
    child_environment+=("$interpolation_variable=${!interpolation_variable}")
  fi
done

{
  for assignment in "${child_environment[@]:2}"; do
    printf '%s\n' "$assignment"
  done
} > "$environment_snapshot_file"

cd "$ROOT_DIR"
compose_arguments=(
  "${compose_binary[@]}"
  --env-file "$ENV_FILE"
  -p "$PROJECT_NAME"
  -f compose.yaml
  -f compose.secrets.yaml
  -f compose.waf.yaml
  -f compose.vps.yaml
  -f compose.vps-waf.yaml
  -f compose.backup-scheduler.yaml
  -f compose.runtime.yaml
  -f compose.networks.yaml
  -f compose.runtime-isolation.yaml
  -f compose.local-private.yaml
)
if (( runtime_identity_count == ${#runtime_identity_variables[@]} )); then
  compose_arguments+=(-f compose.runtime-identity.yaml)
fi
compose_arguments+=(
  -f compose.greenfield.yaml
  --profile backup
  config --format json
)

"${child_environment[@]}" "${compose_arguments[@]}" > "$render_file"

render_sha256=$(sha256_stream < "$render_file")
lock_sha256=$(sha256_stream < "$GREENFIELD_LOCK")

node -e '
const fs = require("fs");
const [, renderPath, envelopePath, projectName, topology, lockSha256, renderSha256] = process.argv;
const config = JSON.parse(fs.readFileSync(renderPath, "utf8"));
if (config === null || typeof config !== "object" || Array.isArray(config)) process.exit(1);
if (config.name !== projectName) process.exit(1);
for (const kind of ["configs", "networks", "secrets", "services", "volumes"]) {
  if (config[kind] === null || typeof config[kind] !== "object" || Array.isArray(config[kind])) process.exit(1);
}
const envelope = { version: 1, projectName, topology, lockSha256, renderSha256, config };
fs.writeFileSync(envelopePath, `${JSON.stringify(envelope)}\n`, { mode: 0o600 });
' "$render_file" "$handoff_directory/envelope.json" "$PROJECT_NAME" "$GREENFIELD_TOPOLOGY" "$lock_sha256" "$render_sha256"

node "$ROOT_DIR/scripts/greenfield-core-policy.mjs" \
  --root "$ROOT_DIR" \
  --lock "$ROOT_DIR/config/no-hosted-workloads.greenfield.lock.json" \
  --config "$render_file" \
  --env "$environment_snapshot_file" \
  > "$handoff_directory/policy-validation.json" || {
  printf '%s\n' "Greenfield render semantic authority validation failed." >&2
  exit 1
}

if [[ "$REQUEST_MODE" = compose-config ]]; then
  /bin/cat "$handoff_directory/envelope.json"
else
  sha256_stream < "$handoff_directory/envelope.json"
fi
