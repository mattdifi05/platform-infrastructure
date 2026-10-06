#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd -P)
ENV_FILE=$ROOT/.env
CONFIRM=${1:-}
if [[ $# != 1 || ( "$CONFIRM" != --apply-empty-vps && "$CONFIRM" != --resume-empty-vps ) ]]; then
  printf 'Usage: %s --apply-empty-vps|--resume-empty-vps\n' "$0" >&2
  exit 64
fi
[[ $(uname -s) = Linux ]] || { echo 'Linux VPS required.' >&2; exit 1; }
[[ -f "$ENV_FILE" && ! -L "$ENV_FILE" ]] || { echo 'A regular .env file is required.' >&2; exit 1; }
[[ $(stat -c %a "$ENV_FILE") = 600 ]] || { echo '.env must have mode 0600.' >&2; exit 1; }
[[ $(id -u) != 0 ]] || { echo 'Run as the non-root deployment user.' >&2; exit 1; }
command -v docker >/dev/null || { echo 'Docker is required.' >&2; exit 1; }
command -v openssl >/dev/null || { echo 'OpenSSL is required.' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'Python 3 is required.' >&2; exit 1; }
source "$ROOT/deployment/host/empty-vps/empty-vps-host-ownership.sh"
if [[ "$CONFIRM" = --apply-empty-vps ]]; then
  [[ -z $(docker ps -aq) && -z $(docker volume ls -q) ]] || {
    echo 'First installation requires an empty Docker host: containers or volumes exist.' >&2
    exit 1
  }
else
  [[ -n $(docker ps -aq --filter label=com.docker.compose.project=platform_infra_vps) ]] || {
    echo 'Resume requires the first installation Compose project.' >&2
    exit 1
  }
  check_empty_vps_host_ownership
fi

env_value() { sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1; }
[[ $(env_value DOMAIN) = stexor.com \
   && $(env_value CONTROL_CENTER_HOST) = portal.stexor.com \
   && $(env_value CONTROL_CENTER_AUTH_RP_ID) = portal.stexor.com \
   && $(env_value CONTROL_CENTER_PUBLIC_ORIGIN) = https://portal.stexor.com \
   && $(env_value CONTROL_CENTER_PUBLIC_URL) = https://portal.stexor.com \
   && $(env_value DOCS_HOST) = docs.stexor.com \
   && $(env_value CONTROL_CENTER_AUTH_MODE) = app-passkey \
   && $(env_value HOSTED_WORKLOAD_MODE) = no-hosted \
   && -z $(env_value HOSTED_WORKLOAD_LOCK) \
   && $(env_value PROJECTS_HOST) = '' \
   && $(env_value PROJECTS_WILDCARD_HOST_REGEXP) = '' \
   && $(env_value NODE_PROJECT_HOSTS) = '' \
   && $(env_value NODE_PROJECT_UPSTREAMS) = '' \
   && $(env_value NODE_PROJECT_COMMANDS) = '' ]] || {
  echo 'The exact empty Stexor VPS environment is required.' >&2
  exit 1
}
CLIENT_CIDRS=$(env_value CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS)
[[ -n "$CLIENT_CIDRS" && "$CLIENT_CIDRS" != *'0.0.0.0/0'* \
   && "$CLIENT_CIDRS" != *'::/0'* \
   && "$CLIENT_CIDRS" != '192.168.1.0/24,127.0.0.0/8,::1/128' ]] || {
  echo 'Set a reviewed Mac client CIDR for initial passkey registration.' >&2
  exit 1
}
if grep -Eq '^[A-Za-z_][A-Za-z0-9_]*=.*(example\.com|localhost|change_me|REPLACE_WITH|example\.invalid)' "$ENV_FILE"; then
  echo 'The environment still has placeholder values.' >&2
  exit 1
fi

cd "$ROOT"
export EMPTY_VPS_HOSTED_LOCK_SHA256=bfc5229f8f1b2e075bc5c0f612016945d2931d8681bdc46c1b9d7d9e2a08a145
[[ $(sha256sum "$ROOT/config/no-hosted-workloads.lock.json" | cut -d ' ' -f 1) = "$EMPTY_VPS_HOSTED_LOCK_SHA256" ]] || {
  echo 'Empty-host workload lock differs from the reviewed candidate.' >&2
  exit 1
}
chmod 0600 "$ROOT/config/no-hosted-workloads.lock.json"
install -d -m 0700 "$ROOT/secrets" "$ROOT/projects-portal/state" "$ROOT/reports"
install -d -m 0700 "$ROOT/../src"
[[ -z $(find "$ROOT/../src" -mindepth 1 -maxdepth 1 -print -quit) ]] || {
  echo 'The hosted source directory must be empty.' >&2
  exit 1
}
# Run the repository's existing secret manager inside a pinned Node image.
# The checkout is read-only; only the ignored secrets directory is writable.
NODE_IMAGE='node:26.10.0-alpine@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80'
if [[ ! -e "$ROOT/secrets/infra-secret-manager-master.key" ]]; then
  docker run --rm --network none --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$ROOT,dst=/workspace,readonly" \
    --mount "type=bind,src=$ROOT/secrets,dst=/workspace/secrets" \
    "$NODE_IMAGE" node /workspace/scripts/infra-secret-manager.mjs init --secretsDir /workspace/secrets
fi
docker run --rm --network none --user "$(id -u):$(id -g)" \
  --mount "type=bind,src=$ROOT,dst=/workspace,readonly" \
  --mount "type=bind,src=$ROOT/secrets,dst=/workspace/secrets" \
  "$NODE_IMAGE" node /workspace/scripts/infra-secret-manager.mjs verify --secretsDir /workspace/secrets
for name in rustfs_access_key rustfs_secret_key; do
  path="$ROOT/secrets/$name.txt"
  if [[ -e "$path" ]]; then
    [[ -f "$path" && ! -L "$path" && ( $(stat -c %a "$path") = 600 || $(stat -c %a "$path") = 640 ) \
       && $(stat -c %g "$path") = "$(id -g)" && -s "$path" ]] || {
      echo "Existing $name credential is invalid; refusing replacement." >&2
      exit 1
    }
  else
    openssl rand -hex 32 > "$path"
    chmod 0600 "$path"
  fi
done
chmod 0640 "$ROOT/secrets/rustfs_access_key.txt" "$ROOT/secrets/rustfs_secret_key.txt"
AUTH_PASSWORD_FILE="$ROOT/secrets/control_center_auth_password.txt"
AUTH_URL_FILE="$ROOT/secrets/control_center_database_url.txt"
if [[ ! -e "$AUTH_PASSWORD_FILE" && ! -e "$AUTH_URL_FILE" ]]; then
  openssl rand -hex 32 > "$AUTH_PASSWORD_FILE"
  chmod 0600 "$AUTH_PASSWORD_FILE"
  python3 - "$AUTH_PASSWORD_FILE" "$AUTH_URL_FILE" <<'PY'
import pathlib, sys
password = pathlib.Path(sys.argv[1]).read_text().strip()
pathlib.Path(sys.argv[2]).write_text(
    f"postgresql://control_center_auth:{password}@postgres:5432/postgres\n"
)
pathlib.Path(sys.argv[2]).chmod(0o600)
PY
else
  python3 - "$AUTH_PASSWORD_FILE" "$AUTH_URL_FILE" <<'PY'
import pathlib, sys
password_path, url_path = map(pathlib.Path, sys.argv[1:])
for path in (password_path, url_path):
    if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o777 != 0o600:
        raise SystemExit('Existing Control Center database credential is invalid; refusing replacement.')
password = password_path.read_text().strip()
expected = f'postgresql://control_center_auth:{password}@postgres:5432/postgres'
if len(password) != 64 or url_path.read_text().strip() != expected:
    raise SystemExit('Existing Control Center database credential pair is inconsistent.')
PY
fi

# The WAF listens only on host loopback during this first installation.
# Generate a disposable local certificate so its HTTPS listener can start.
install -d -m 0700 "$ROOT/traefik/certs"
if [[ ! -e "$ROOT/traefik/certs/local-key.pem" && ! -e "$ROOT/traefik/certs/local-cert.pem" ]]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 2 \
    -subj '/CN=portal.stexor.com' \
    -addext 'subjectAltName=DNS:portal.stexor.com,DNS:docs.stexor.com' \
    -keyout "$ROOT/traefik/certs/local-key.pem" \
    -out "$ROOT/traefik/certs/local-cert.pem" >/dev/null 2>&1
  chmod 0755 "$ROOT/traefik/certs"
  chmod 0640 "$ROOT/traefik/certs/local-key.pem" "$ROOT/traefik/certs/local-cert.pem"
else
  [[ -f "$ROOT/traefik/certs/local-key.pem" && ! -L "$ROOT/traefik/certs/local-key.pem" \
     && $(stat -c %a "$ROOT/traefik/certs/local-key.pem") = 640 \
     && $(stat -c %g "$ROOT/traefik/certs/local-key.pem") = "$(id -g)" \
     && -f "$ROOT/traefik/certs/local-cert.pem" && ! -L "$ROOT/traefik/certs/local-cert.pem" ]] || {
    echo 'Existing local TLS pair is invalid; refusing replacement.' >&2
    exit 1
  }
  openssl x509 -in "$ROOT/traefik/certs/local-cert.pem" -noout >/dev/null 2>&1 || exit 1
  openssl pkey -in "$ROOT/traefik/certs/local-key.pem" -noout >/dev/null 2>&1 || exit 1
fi
chmod 0755 "$ROOT/traefik/certs"

# MariaDB requires a fresh, private internal certificate on the empty host.
# Its daemon receives only the public cert and a group-readable server key.
DB_CERT_DIR="$ROOT/traefik/certs"
if [[ ! -e "$DB_CERT_DIR/mariadb.key" && ! -e "$DB_CERT_DIR/mariadb.fullchain.crt" && ! -e "$DB_CERT_DIR/ca.pem" ]]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
    -subj '/CN=mariadb' -addext 'subjectAltName=DNS:mariadb' \
    -keyout "$DB_CERT_DIR/mariadb.key" \
    -out "$DB_CERT_DIR/mariadb.fullchain.crt" >/dev/null 2>&1
  cp "$DB_CERT_DIR/mariadb.fullchain.crt" "$DB_CERT_DIR/ca.pem"
  chmod 0640 "$DB_CERT_DIR/mariadb.key" "$DB_CERT_DIR/mariadb.fullchain.crt" "$DB_CERT_DIR/ca.pem"
else
  for name in mariadb.key mariadb.fullchain.crt ca.pem; do
    [[ -f "$DB_CERT_DIR/$name" && ! -L "$DB_CERT_DIR/$name" \
       && $(stat -c %a "$DB_CERT_DIR/$name") = 640 ]] || {
      echo 'Existing MariaDB TLS pair is invalid; refusing replacement.' >&2
      exit 1
    }
  done
  openssl x509 -in "$DB_CERT_DIR/mariadb.fullchain.crt" -noout >/dev/null 2>&1 || exit 1
  openssl pkey -in "$DB_CERT_DIR/mariadb.key" -noout >/dev/null 2>&1 || exit 1
fi
# MariaDB's entrypoint drops supplementary groups when switching to uid 999.
# Assign only the database TLS material to that group; WAF key ownership stays
# with the platform deployment user and its own supplementary group.
docker run --rm --network none --user 0:0 \
  --mount "type=bind,src=$DB_CERT_DIR,dst=/certs" \
  nginx:1.30.5-alpine@sha256:0985e772fb9f729e6fa0980da05fca5d9c468e870eed43071545afa9d2e27d94 \
  sh -ec 'chgrp 999 /certs/mariadb.key /certs/mariadb.fullchain.crt /certs/ca.pem; chmod 0640 /certs/mariadb.key /certs/mariadb.fullchain.crt /certs/ca.pem'

COMPOSE=(docker compose --env-file "$ENV_FILE")
AI_ENV=/etc/platform-infrastructure/server-ai/.env.server-ai
AI_ACTIVE=$(docker ps -aq --filter label=com.docker.compose.project=platform_server_ai)
if [[ -n "$AI_ACTIVE" ]]; then
  [[ -f "$AI_ENV" && ! -L "$AI_ENV" && -r "$AI_ENV" ]] || {
    echo 'Server AI is active but its private Compose environment is unreadable.' >&2
    exit 1
  }
  COMPOSE+=(--env-file "$AI_ENV")
fi
COMPOSE+=(-p platform_infra_vps
  -f compose.yaml -f compose.secrets.yaml -f compose.waf.yaml
  -f compose.vps.yaml -f compose.vps-waf.yaml
  -f compose.empty-vps-networks.yaml -f compose.empty-vps-first-install.yaml
  -f compose.empty-vps-qualified-databases.yaml)
if [[ -n "$AI_ACTIVE" ]]; then
  COMPOSE+=(-f compose.server-ai-control-center.yaml -f compose.server-ai-empty-host-control-center.yaml)
fi
CC_CONFIG_FILES=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project.config_files"}}' enterprise-control-center 2>/dev/null || true)
for overlay in \
  deployment/vps-backup/compose.control-center.yaml \
  deployment/cloudflare-dns/compose.control-center.yaml \
  deployment/host/empty-vps/compose.first-enrollment.yaml; do
  case ",$CC_CONFIG_FILES," in
    *,"$ROOT/$overlay",*)
      [[ -f "$ROOT/$overlay" ]] || { echo "The active Control Center overlay is missing: $overlay" >&2; exit 1; }
      COMPOSE+=(-f "$overlay")
      ;;
  esac
done
"${COMPOSE[@]}" config --quiet
if ! docker image inspect platform/runtime-helpers:go1.27.1 >/dev/null 2>&1; then
  docker build --quiet -f deployment/docker/runtime-helpers.Dockerfile -t platform/runtime-helpers:go1.27.1 . >/dev/null
fi
if ! docker image inspect platform/postgres:local >/dev/null 2>&1; then
  docker build --quiet -f deployment/docker/postgres-remediated.Dockerfile -t platform/postgres:local . >/dev/null
fi
if ! docker image inspect platform/mariadb:local >/dev/null 2>&1; then
  docker build --quiet -f deployment/docker/mariadb-remediated.Dockerfile -t platform/mariadb:local . >/dev/null
fi
"${COMPOSE[@]}" up -d --build postgres broker-auth-bootstrap redis
for attempt in {1..60}; do
  if "${COMPOSE[@]}" exec -T postgres pg_isready -U postgres -d postgres >/dev/null 2>&1; then
    break
  fi
  if (( attempt == 60 )); then
    echo 'PostgreSQL did not become ready.' >&2
    exit 1
  fi
  sleep 2
done

# The Control Center owns passkeys in PostgreSQL. Install only its new schema,
# then create one dedicated role; never put the PostgreSQL superuser URL in
# the web service's Docker secret.
"${COMPOSE[@]}" exec -T postgres psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '\''control_center_runtime'\'') THEN CREATE ROLE control_center_runtime NOLOGIN; END IF; END $$;' >/dev/null
"${COMPOSE[@]}" exec -T postgres psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  < control-center/migrations/001_app_passkey.sql >/dev/null
{
  printf "DO \$\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'control_center_auth') THEN CREATE ROLE control_center_auth LOGIN PASSWORD '%s'; END IF; END \$\$;\n" "$(cat "$AUTH_PASSWORD_FILE")"
  printf 'GRANT CONNECT ON DATABASE postgres TO control_center_auth;\n'
  printf 'GRANT USAGE ON SCHEMA control_auth TO control_center_auth;\n'
  printf 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA control_auth TO control_center_auth;\n'
} | "${COMPOSE[@]}" exec -T postgres psql -U postgres -d postgres -v ON_ERROR_STOP=1 >/dev/null

# Initialize the additive Server AI schema before the Control Center starts.
# Each reviewed migration owns its transaction; the login used by the
# Control Center receives only Server AI runtime DML/sequence privileges.
for migration in control-center/migrations/00[2-9]_server_ai_*.sql control-center/migrations/01[0-3]_server_ai_*.sql; do
  [[ -f "$migration" ]] || { echo "Required Server AI migration is missing: $migration" >&2; exit 1; }
  "${COMPOSE[@]}" exec -T postgres psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
    < "$migration" >/dev/null
done
"${COMPOSE[@]}" exec -T postgres psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'GRANT USAGE ON SCHEMA server_ai TO control_center_auth; GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA server_ai TO control_center_auth; GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA server_ai TO control_center_auth;' >/dev/null

"${COMPOSE[@]}" up -d --build control-center traefik waf waf-loopback-proxy
"${COMPOSE[@]}" ps
echo 'Private first installation started on 127.0.0.1:8080 and 127.0.0.1:8443.'
echo 'No public production admission or go-live status is claimed.'
