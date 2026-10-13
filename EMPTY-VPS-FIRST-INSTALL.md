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
The database and RustFS gateway images are local Compose builds tagged
`platform/*:local`, tied to the checked-in Dockerfiles and pinned upstream
base images. Those mutable local tags are scoped to this host installation;
they are not published registry digests or portable release artifacts.

The WAF stays on an internal Docker network. A separate unprivileged Nginx
proxy binds only `127.0.0.1:8080` on the host and forwards to WAF. Its
self-signed certificate only supports local WAF startup checks. With a
Cloudflare Tunnel, route `portal.stexor.com` and `docs.stexor.com` to
`http://127.0.0.1:8080`; the overlay disables the local HTTP redirect and the
WAF forwards the HTTPS scheme from the Cloudflare edge. For the selected
direct-login mode, the portal authenticates with its own passkey and session;
Cloudflare Access is not a permanent login prerequisite. An owner-only Access
application can protect the portal during first enrollment, but remove only
that portal application's coverage after the real passkey is registered and
verify that the portal Tunnel route no longer has "Protect with Access" / an
`originRequest.access.required` JWT requirement. Leave the Tunnel, edge
protections, and unrelated Access applications in place. Check the effective
`X-Forwarded-For` chain, then set the allowed client CIDR and exact trusted
Docker/Cloudflare proxy CIDRs so registration from the Mac passes without
accepting a client-supplied address. The WebAuthn RP and browser origin must
stay exactly `portal.stexor.com` and `https://portal.stexor.com`. The client
CIDR restricts first enrollment; later login still requires the registered
passkey, exact host and origin, a valid session, and CSRF checks.

If the Mac rotates its IPv6 address within the reviewed management `/64`, use
`deployment/host/empty-vps/compose.first-enrollment.yaml` for the first
passkey registration. Set only that reviewed `/64` in the protected VPS `.env`
before loading the overlay. Immediately before the owner uses Touch ID,
generate a random 32-byte lowercase-hex browser token on the owner's Mac.
Keep the raw token in an owner-protected local file, and place only a mode-`0400`,
UID-1000 regular verifier file at
`/etc/platform-infrastructure/first-enrollment/verifier.json` on the VPS.
Its JSON fields are `tokenSha256` (SHA-256 of the raw token), `issuedAt`, and
`expiresAt` (UTC ISO timestamps no more than 15 minutes apart). The overlay
binds that file read-only into Control Center; it contains no token value.
Recreate only Control Center with the complete active Compose overlay chain,
including Server AI, backup, and Cloudflare DNS when present. If the token
expires before registration, replace the verifier with a new short-lived one
and recreate Control Center; do not widen the CIDR. A real registered passkey
closes first enrollment independently of token expiry.

For a new VPS, first confirm with the owner which Cloudflare account owns this
infrastructure. The same Cloudflare account can also host NAS or other
projects; keep this platform's Tunnel, route, and any temporary Access change
scoped to `portal.stexor.com`, without changing those other applications.
The account choice is an operator prerequisite, not a property established by
this repository. Create the Tunnel in the selected account and
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
