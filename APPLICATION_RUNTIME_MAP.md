# Application Runtime Map

Snapshot UTC: 2026-08-30T13:51:06Z

Source of truth: effective live Compose, running containers, Control Center
state, database catalogs, source manifests and functional host probes. The
immutable source coordinates are in `config/v1-local-private-source-lock.json`.

## Platform boundary

The platform repository owns Compose, networks, routers, WAF, common runtime
images and Control Center. Application source is versioned in its owning
private repository and materialized on the host under
`/home/platform_infrastructure/v1-fresh-data/src`. Application `.env` files,
uploads, logs, caches and persistent data are external state.

## Published host matrix

| Host | Runtime target | Source owner | Persistent dependency |
| --- | --- | --- | --- |
| `portal.platform-infrastructure.com` | `control-center:8080` | platform repository | PostgreSQL `control_auth` schema and Control Center state |
| `auth.platform-infrastructure.com` | `keycloak:8080` | pinned Keycloak image plus platform config | PostgreSQL `keycloak` |
| `api.platform-infrastructure.com` | `backend:3000` | `mattdifi05/Stexor-account` | PostgreSQL `stexor`, Redis and NATS |
| `account.platform-infrastructure.com` | `node-account:3000` | `mattdifi05/Stexor-account` | Stexor backend/PostgreSQL `stexor` |
| `ui.platform-infrastructure.com` | `node-ui:3000` | `mattdifi05/Stexor-account` | Stexor backend/PostgreSQL `stexor` |
| `opstudents.platform-infrastructure.com` | `node-opstudents:3000` | `mattdifi05/Platform-hosted-applications` | no application database |
| `anniversary.platform-infrastructure.com` | `php-anniversary:80` | `mattdifi05/Platform-hosted-applications` | MariaDB `anniversary` |
| `fiplatform.platform-infrastructure.com` | `php-fiplatform:80` | `mattdifi05/FeI-Platform` | MariaDB `fiplatform` |
| `fireport.platform-infrastructure.com` | alias of `php-fiplatform:80` | `mattdifi05/FeI-Platform` | MariaDB `fiplatform` |
| `matthewdifilippo.platform-infrastructure.com` | `php-matthewdifilippo:80` | `mattdifi05/Platform-hosted-applications` | no application database |
| `stream.platform-infrastructure.com` | `php-stream:80` | `mattdifi05/Platform-hosted-applications` | MariaDB `stream` |
| `workcalendar.platform-infrastructure.com` | `php-workcalendar:80` | `mattdifi05/Platform-hosted-applications` | MariaDB `workcalendar` |

The 2026-08-30 live probe passed all 12 hosts. CoreDNS is authoritative for
`platform-infrastructure.com` on the LAN and maps the apex and wildcard to
`192.168.1.164`; Traefik routes the explicit portal/auth/API surfaces and the
project-router resolves registered application hosts.

## Workload components

| Source | Runtime services | Build/runtime contract |
| --- | --- | --- |
| FeI Platform | `php-fiplatform` (`fireport` is an alias) | common pinned PHP-Apache image, bind-mounted locked source |
| Stexor | `backend`, `web`, `worker-jobs`, `worker-notifications`, `node-account`, `node-ui` | four local images built by `compose.local-private-applications-build.yaml`; account/UI bind-mounted from the same locked checkout |
| Hosted applications | `node-opstudents`, `php-anniversary`, `php-matthewdifilippo`, `php-stream`, `php-workcalendar` | pinned Node or common pinned PHP-Apache runtime, bind-mounted locked source |

The broad shared `php-apache` service is disabled by the current application
overlay. No application source is recovered from a mutable image alone.

## Persistent state boundary

PostgreSQL persistent databases are `keycloak` and `stexor`; Control Center
authentication lives in its PostgreSQL `control_auth` schema. MariaDB
application databases are `anniversary`, `fiplatform`, `stream` and
`workcalendar`. Redis/NATS operational state, certificates, Docker volumes,
Control Center catalog/Vault/backup metadata, application uploads and every
secret remain outside Git and must be restored from the recovery material.

No user MinIO object set is required by the current application inventory.
MinIO configuration and any required empty bucket/policy are runtime state,
not application source.

## Reproduction gate

No application, source directory, database, alias, route or external-state
class in this map may be removed during V1.1 cleanup until the clean-checkout
proof in `V1.0-LIVE-PARITY.md` is PASS. This map authorizes no deletion.
