# Application Runtime Map

Snapshot UTC: 2026-07-10T03:48:01Z
Source of truth: live Docker runtime, effective Compose, Control Center discovery, source directories, database catalogs, backup inventory and functional HTTP probes.

This map is a migration gate. A resource must not be renamed, moved, recreated, rotated or deleted until its row has an exact rollback and a fresh resource-specific backup.

## Platform boundary

The repository is the hosting and control-plane layer. Hosted application source remains outside this repository under `/home/platform_infrastructure/src`.

The services `enterprise-backend`, `enterprise-web`, `enterprise-worker-jobs` and `enterprise-worker-notifications` are currently built from the external Stexor source tree. They are Stexor workload components, not generic platform core. T18 must remove this ownership ambiguity without interrupting Stexor account or Stexor UI.

## Authoritative application map

| Application ID | Source | Runtime | Host | Database and principal | Storage | Network | Backup identity | Dependencies | Functional state |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| anniversary | `/home/platform_infrastructure/src/anniversary` | `php-anniversary`; image `sha256:a1d1c9cab77a...` | `anniversary.platform-infrastructure.com` | MariaDB `anniversary`; runtime user `anniversary_user`; state currently declares stale owner `anniversary_app` | No MinIO bucket registered | `enterprise_net` | source `applications/anniversary`; DB inside global MariaDB dump | project-router, WAF, Traefik, MariaDB | HTTP 200 |
| fiplatform | `/home/platform_infrastructure/src/fiplatform`; legacy symlink `fireport -> fiplatform` | `php-fiplatform`; image `sha256:a1d1c9cab77a...` | `fiplatform.platform-infrastructure.com`; alias `fireport` | MariaDB `fiplatform`; runtime user `app_runtime` | No MinIO bucket registered | `enterprise_net` | source `applications/fiplatform`; DB inside global MariaDB dump | project-router, WAF, Traefik, MariaDB | HTTP 200 |
| matthewdifilippo | `/home/platform_infrastructure/src/matthewdifilippo` | `php-matthewdifilippo`; image `sha256:a1d1c9cab77a...` | `matthewdifilippo.platform-infrastructure.com` | No application DB found or declared | No MinIO bucket registered | `enterprise_net` | source `applications/matthewdifilippo` | project-router, WAF, Traefik | HTTP 200 |
| stream | `/home/platform_infrastructure/src/stream` | `php-stream`; image `sha256:a1d1c9cab77a...` | `stream.platform-infrastructure.com` | MariaDB `stream`; runtime user `stream_user` | No MinIO bucket registered | `enterprise_net` | source `applications/stream`; DB inside global MariaDB dump | project-router, WAF, Traefik, MariaDB | HTTP 303 redirect |
| workcalendar | `/home/platform_infrastructure/src/workcalendar` | `php-workcalendar`; image `sha256:a1d1c9cab77a...` | `workcalendar.platform-infrastructure.com` | MariaDB `workcalendar`; runtime user `workcalendar_user`; state currently declares stale owner `workcalendar_app` | No MinIO bucket registered | `enterprise_net` | source `applications/workcalendar`; DB inside global MariaDB dump | project-router, WAF, Traefik, MariaDB | HTTP 302 redirect |
| account | `/home/platform_infrastructure/src/stexor` project surface `account` | `node-account`; shared Stexor backend/workers listed below | `account.platform-infrastructure.com` | PostgreSQL `stexor`; owner `stexor_owner`; runtime login `app_user` | No MinIO bucket registered; Stexor backend currently has MinIO root material mounted | `enterprise_net` | shared source artifact `applications/stexor`; DB `postgres/stexor-*.dump` | Stexor UI, Stexor backend, PostgreSQL, Redis, NATS, Keycloak, MinIO | HTTP 200 |
| ui | `/home/platform_infrastructure/src/stexor` project surface `ui` | `node-ui`; shared Stexor backend/workers listed below | `ui.platform-infrastructure.com` | Uses Stexor services and PostgreSQL `stexor`; no independent DB | No MinIO bucket registered | `enterprise_net` | shared source artifact `applications/stexor`; DB follows account dependency | Stexor account/backend, PostgreSQL, Redis, NATS, Keycloak, MinIO | HTTP 200 |
| public | `/home/platform_infrastructure/src/public` | No registered runtime; directory is explicitly excluded by current discovery | expected `public.platform-infrastructure.com` | None found | None registered | None assigned | source `applications/public` exists | unresolved | HTTP 404; OPEN mapping defect |

## Stexor workload components

| Component | Runtime image ID | Current ownership | Data dependencies |
| --- | --- | --- | --- |
| `enterprise-backend` | `sha256:ac1f6769fcb1...` | External Stexor source, currently named as platform service | PostgreSQL `stexor` as `app_user`, Redis, NATS, MinIO, SMTP and Turnstile |
| `enterprise-web` | `sha256:e1214bb57666...` | External Stexor source; appears redundant with the dedicated account/UI runtimes and requires T18 verification | Stexor API and identity |
| `enterprise-worker-jobs` | `sha256:e1685e2c4047...` | External Stexor source | PostgreSQL `stexor`, Redis, NATS |
| `enterprise-worker-notifications` | `sha256:960788c6ebf1...` | External Stexor source | PostgreSQL `stexor`, Redis, NATS, SMTP, Alertmanager webhook |

## Database inventory

PostgreSQL databases: `keycloak`, `postgres`, `stexor`, and legacy restore-test database `platform_restore_test_20260625203102`.

MariaDB application databases: `anniversary`, `fiplatform`, `stream`, and `workcalendar`.

MariaDB drift requiring classification before any delete: `node_demo_app`, `phpmyadmin`, `stexor_auth`, and `u778675014_fip`. No deletion is authorized by this document.

## Isolation gaps observed

All workloads currently share `enterprise_net`. PHP runtimes still receive broad repository/control-state mounts and shared SMTP/signing material. The legacy `php-apache` shared runtime is still running despite its disabled profile. The project-router has broad source and host-parent mounts. Control Center has DB superuser material. Backup scheduler has the production Docker socket.

These are OPEN inputs to T11-T14, not accepted target state.

T11 live adoption on 2026-07-10 moved project-router and the local registry under the single `platform_infra_vps` Compose project. The registry retained the exact `enterprise_local_registry_data` volume and catalog. Other services were not recreated; their historical Compose labels still mention the old ignored overlays, but all future deploy commands use `compose.runtime.yaml` and the canonical wrapper.

## Backup and restore coverage

Fresh local source archives exist for anniversary, fiplatform, matthewdifilippo, public, stexor, stream and workcalendar. Fresh MariaDB global dumps and a Stexor PostgreSQL dump exist.

Current gaps:

- PostgreSQL backup does not prove coverage for the Keycloak identity database.
- Keycloak backup is configuration-only.
- account and ui share one Stexor source artifact and need explicit restore manifests.
- Control Center/Vault state portability is not yet proven.
- off-site evidence is older and predates the current runtime fingerprint.
- no empty-host Ubuntu restore has been executed for this baseline.
- no MinIO buckets exist in the live catalog.

## Health evidence

The probes used the local CA and forced the public host to the local edge. A generic HTTP success is not sufficient for final closure; application login, controlled DB read/write, jobs and storage remain required after each affected rollout.
