# Quickstart

## Prerequisites

- Docker Engine or Docker Desktop for local development.
- Git.
- A POSIX shell for the scripts. On Windows, use Git Bash, WSL or a Linux VPS shell.
- Optional: mkcert for trusted local HTTPS.

On a Linux VPS, host Node, pnpm and PHP CLI are not required for platform operations. The ops runner is container-first.

## Clone and configure

```sh
git clone https://github.com/mattdifi05/platform-infrastructure.git
cd platform-infrastructure
cp .env.example .env
```

Review `.env` before starting. Do not commit it.

## Initialize local secrets

```sh
sh ./scripts/infra-secret-manager.sh init
```

The generated secret material belongs in ignored files or Docker secrets, never in Git.

## Start the local stack

```sh
docker compose --env-file .env -p platform_infra_local \
  -f compose.yaml \
  -f compose.build.yaml \
  -f compose.secrets.yaml \
  up -d --build
```

## Health checks

```sh
sh ./scripts/infra-health.sh
sh ./scripts/waf-smoke.sh
```

## Access the Admin Control Center

Default local host:

```text
https://admin.localhost.com
```

Docs:

```text
https://docs.localhost.com
```

## Optional mkcert

```sh
mkcert -install
mkcert -cert-file ./traefik/certs/local-cert.pem -key-file ./traefik/certs/local-key.pem \
  localhost 127.0.0.1 ::1 admin.localhost.com docs.localhost.com app.localhost.com api.localhost.com auth.localhost.com storage.localhost.com grafana.localhost.com
```

## Hosts file

Add only the hosts you need for your profile. Minimal local control-plane hosts:

```text
127.0.0.1 admin.localhost.com docs.localhost.com
```

## Logs and stop

```sh
docker compose -p platform_infra_local logs -f
docker compose -p platform_infra_local down
```

Do not use `down -v` unless you intentionally want to delete volumes.

## Basic troubleshooting

- `404`: the hostname is not routed in the current profile.
- `403`: WAF or admin auth blocked the request.
- `502`: upstream service is not healthy or not attached to the network.
- TLS warning: install and trust mkcert, or use HTTP-only edge profiles locally.
