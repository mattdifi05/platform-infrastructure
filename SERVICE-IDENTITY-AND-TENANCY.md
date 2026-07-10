# Service Identity and Tenancy Contract

## Decision

The supported security boundary is one credential and one least-privilege role
per workload service. PostgreSQL row-level security is defense in depth for a
trusted service role; it is not a platform-supported tenant boundary. A
multi-tenant product must define tenant-aware authorization and negative tests
inside its own repository before production use.

## Platform responsibility

The infrastructure repository owns:

- PostgreSQL and MariaDB availability, isolation, health and admin boundaries;
- platform database bootstrap, including Keycloak and Control Center state;
- backup, restore, retention, RPO/RTO evidence and off-site transport;
- secret storage and file-based delivery primitives;
- network, cgroup and Docker-socket isolation;
- MinIO root bootstrap without exposing root material to workloads.

The platform does not own application schemas, grants, migrations, service
roles or legacy-principal revocation SQL.

## Workload responsibility

Each external workload repository must provide:

- one named database principal and secret per service that needs database access;
- exact grants and explicit cross-table or cross-schema denials;
- application-owned migration and rollback files;
- a plan-by-default rollout command with separate apply and revoke confirmations;
- fresh backup and restore evidence requirements before credential changes;
- functional and negative probes for every affected service identity.

The workload manifest declares only secret names. Values remain in the platform
secret backend and are never copied into the manifest, lock, Git or evidence.

## Object storage

Hosted workloads never receive MinIO root material. Use one service account per
bucket/prefix through `scripts/minio-service-identity.sh`. The generated policy
may list the selected prefix and read/write/delete objects only inside it.
Cross-prefix, cross-bucket and administrative operations must be denied and
tested before activation.

## Dual-credential rollout

A credential cutover requires a dedicated maintenance window:

1. Produce a fresh exact database backup and successful restore-test evidence.
2. Create or rotate scoped service credentials without removing the legacy path.
3. Apply the application-owned grant migration with its explicit confirmation.
4. Recreate only the affected workload services from a verified workload lock.
5. Prove positive service behavior and negative cross-service access.
6. Archive non-secret cutover evidence.
7. Revoke the legacy principal with a second explicit confirmation.

Emergency rollback may restore only documented bounded capabilities. It must
never restore broad direct grants or MinIO root material.

## T18 ownership status

The Stexor candidate now owns its image definitions, schema, migrations,
service-identity grant/revoke/rollback SQL and plan-by-default commands under
its `deploy/` directory. The infrastructure candidate contains none of those
files. This ownership change is sandbox-verified but not activated on the live
reference server.

## Platform verification

```sh
sh ./scripts/infra-ops.sh testing-hygiene
sh ./scripts/runtime-isolation-check.sh --env-file=.env.vps.example
sh ./scripts/network-segmentation-check.sh --env-file=.env.vps.example
HOSTED_WORKLOAD_CATALOG=/path/hosted-workloads.json \
HOSTED_WORKLOAD_ROOT=/path/applications \
HOSTED_WORKLOAD_LOCK=/path/private/hosted-workloads.lock.json \
COMPOSE_ENV_FILE=.env.vps \
sh ./scripts/prepare-hosted-workloads.sh
MODE=plan MINIO_BUCKET=example MINIO_PREFIX=runtime/ \
  sh ./scripts/minio-service-identity.sh
```

These checks do not apply application migrations, rotate credentials or touch
live data.
