# Empty VPS first installation

This operator path starts the infrastructure portal privately on a fresh
Ubuntu VPS. It does not activate hosted applications, import previous server
data, or claim production release admission. The existing `deploy-vps.sh` and
canonical release gates remain unchanged.

Use an isolated, reviewed checkout on the new VPS. The installation script
refuses any existing Docker container or volume and a nonempty sibling `src`
directory. It starts PostgreSQL, Redis, the broker configuration bootstrap,
Control Center, Traefik, WAF, and a host-loopback proxy under
`platform_infra_vps`. The core completion script checks all 18 runtime
services for healthy/running state before reporting success.

Before running it, install Docker with `vps-bootstrap-ubuntu.sh` and create a
non-root deployment user with working Docker access. Create a mode-0600 `.env`
from `.env.example` plus the VPS values in `.env.vps.example`. Fill every
placeholder with the new VPS's configuration. At minimum set:

```dotenv
DOMAIN=stexor.com
LOCAL_DOMAIN=stexor.com
ADMIN_HOST=portal.stexor.com
CONTROL_CENTER_HOST=portal.stexor.com
CONTROL_CENTER_AUTH_RP_ID=portal.stexor.com
CONTROL_CENTER_PUBLIC_ORIGIN=https://portal.stexor.com
CONTROL_CENTER_PUBLIC_URL=https://portal.stexor.com
DOCS_HOST=docs.stexor.com
DOCS_PUBLIC_URL=https://docs.stexor.com
HOSTED_WORKLOAD_MODE=no-hosted
HOSTED_WORKLOAD_LOCK=
CONTROL_CENTER_DISCOVER_HOSTED_PROJECTS=false
PROJECTS_HOST=
PROJECTS_WILDCARD_HOST_REGEXP=
NODE_PROJECT_HOSTS=
NODE_PROJECT_UPSTREAMS=
NODE_PROJECT_COMMANDS=
CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS=<reviewed-client-cidr-list>
CONTROL_CENTER_FIRST_CONFIGURATION_TRUSTED_PROXY_CIDRS=<reviewed-docker-and-cloudflare-proxy-cidrs>
NODE_IMAGE=node:26.10.0-alpine@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80
```

Set real mailer/operator addresses and SMTP host/user in `.env` before
installation. The secret manager creates a fresh SMTP secret, which must be
replaced with the real SMTP credential before alert delivery is enabled. Set
`PHP_PROJECTS_DIR` to the empty sibling `src` directory. Do not copy any
application sources, historical catalog, previous volume, old `.env` or old
secret store.

Run as the deployment user from this checkout:

```sh
chmod 600 .env
sh ./scripts/prepare-vps-runtime.sh --apply-empty-vps
```

The script uses the repository's secret manager inside a pinned Node image,
creates new Docker secrets locally (including separate RustFS credentials),
builds the repository's qualified PostgreSQL 18.6 and MariaDB 13.0.2 images,
installs the application-owned `control_auth` schema, and creates a dedicated
PostgreSQL login for Control Center. It prints no credentials. Store the ignored
`secrets/` directory in an operator-controlled backup after a successful start.

The WAF stays on an internal Docker network. A separate unprivileged Nginx
proxy binds only `127.0.0.1:8080` on the host and forwards to WAF. Its
self-signed certificate only supports local WAF startup checks. With a
Cloudflare Tunnel, route `portal.stexor.com` and `docs.stexor.com` to
`http://127.0.0.1:8080`; the overlay disables the local HTTP redirect and the
WAF forwards the HTTPS scheme from the Cloudflare edge. Require an owner-only
Cloudflare Access policy before exposing the tunnel. Check the effective
`X-Forwarded-For` chain, then set the allowed client CIDR and exact trusted
Docker/Cloudflare proxy CIDRs so registration from the Mac passes without
accepting a client-supplied address. The WebAuthn RP and browser origin must
stay exactly `portal.stexor.com` and `https://portal.stexor.com`.

For a new VPS, first confirm with the owner which Cloudflare account owns this
infrastructure; require an account separate from any NAS or other project
account. That account choice is an operator prerequisite, not a property
established by this repository. Create the Tunnel in the selected account and
write its new token only to `/etc/cloudflared/tunnel-token` on the VPS (root
owned, mode `0600`; parent directory root owned, mode `0700`). Install
`deployment/host/systemd/platform-cloudflared-vps.service` as a systemd unit
only after the token file exists. It uses `LoadCredential` and passes the
private systemd credential path to `cloudflared --token-file`, so the token
does not appear in Compose, the unit text, process arguments, or this repo.
The template contains no Tunnel/account identity and does not choose or
create either Cloudflare account or DNS records.

Complete the platform core using the same private port and empty application
inventory:

```sh
sh ./scripts/prepare-vps-runtime.sh --apply-empty-core
```

That adds the standard platform services defined by the fixed Compose set,
including Keycloak, MariaDB, NATS, RustFS, its S3 gateway and observability.
The MinIO Community service is disabled; the gateway alone retains the internal
`minio` DNS alias for compatible S3 clients. The backup broker
and scheduler need a real admitted runtime intent and pinned scheduler image;
`compose.backup-scheduler.yaml` is not loaded by this first-install path.
Server AI is a separate platform subsystem. Start its own project only after
its VPS-specific registry, controller policy, proxy, and credential files have
been generated. When its project is active, the core script requires the
protected `/etc/platform-infrastructure/server-ai/.env.server-ai` and appends
both Control Center AI overlays. Its source/query reader profile remains
disabled because this host has no application sources. No old API key is used.

`cloudflare/from-zero.example.json` must not be applied as-is to the existing
`stexor.com` zone: it contains an apex A record and requires an empty zone.
Create only new `portal` and `docs` records, keep existing hosting records,
omit zone settings, and review any existing WAF ruleset before applying an
additive change. The Tunnel needs no public origin port; keep UFW inbound limited to SSH.
