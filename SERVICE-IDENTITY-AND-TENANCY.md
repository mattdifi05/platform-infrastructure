# Service Identity and Tenancy Contract

## Decision

The supported security boundary is one credential and one least-privilege role
per workload. PostgreSQL row-level security remains defense in depth for a
trusted service role; it is not a supported account-to-account tenant boundary.
Any future multi-tenant product must reopen this decision and add tenant-aware
authorization tests before production use.

The current backend and workers are Stexor compatibility workloads hosted by
the platform. They are not platform core. T18 moves their application-specific
schema and build ownership out of this repository without changing the access
contract below.

## PostgreSQL matrix

| Runtime identity | Allowed data operations | Explicit denials |
| --- | --- | --- |
| `app_backend_runtime` | Existing account, auth and audit capability roles; read-only `schema_migrations` preflight | no DB administration, no platform evidence mutation, no DELETE inherited from the capability roles |
| `app_worker_jobs_runtime` | `SELECT, UPDATE` on `audit_outbox`; `SELECT` on `backup_restore_runs` | no account, passkey, session, subscription, audit-event or platform mutation access |
| `app_worker_notifications_runtime` | database connection only for the current compatibility image | no schema/table privileges and no inherited capability role |
| `app_user` | legacy dual-credential rollback principal until cutover evidence exists | disabled with `NOLOGIN` by the explicit revoke step |

`postgres/migrations/014_service_identity_grants.sql` is the safe grant phase.
It supports both the generic `app_account`/`platform_ops` names and the current
Stexor `stexor_account`/`stexor_platform` names. It does not disable the old
login. Revocation and rollback live under `postgres/rollout/` and are never
applied by the automatic migration runner.

On an empty PostgreSQL 18 volume, `platform-postgres-entrypoint` stages the
root-only host secret files and init assets into postgres-owned runtime paths
before the official image drops privileges. The init scripts are POSIX `sh`
compatible; the full `001` through `014` migration sequence is tested from an
empty tmpfs volume.

## Object storage matrix

No live MinIO bucket is currently registered for a hosted application. The
backend therefore receives no MinIO credential at all. Future workloads use
one MinIO service account per bucket/prefix through
`scripts/minio-service-identity.sh`; root material is mounted only into that
one-shot bootstrap. The generated inline policy permits list on the selected
prefix and object read/write/delete inside that prefix. Cross-prefix,
cross-bucket and admin APIs are denied.

## Mail ownership

SMTP is limited to components that currently send mail: the Stexor backend for
transactional account OTP and the notification worker for operations alerts.
T13 removes SMTP from generic PHP runtimes. T18 must either retain both as
explicit application mailers or move account email to a dedicated outbox
consumer before removing SMTP from the backend.

## Dual-credential rollout

The live sequence requires a maintenance window and explicit approval:

1. Create a fresh PostgreSQL backup and successful restore-test evidence.
2. Initialize or rotate the three scoped credentials in the secret manager.
3. Apply migration `014_service_identity_grants` with the standard migration runner.
4. Run `scripts/service-identity-rollout.sh --mode prepare` with recovery evidence.
5. Render the candidate Compose configuration and recreate only backend and workers.
6. Prove backend login/account flows, jobs outbox dispatch and notification delivery.
7. Store non-secret cutover evidence, then run the explicit `revoke` mode.
8. Re-run positive and negative queries and archive the redacted mount inventory.

The emergency rollback re-enables only the bounded legacy capability roles. It
does not restore broad direct grants or MinIO root material.

## Verification

```sh
node scripts/service-identity-policy.mjs
sh scripts/service-identity-sandbox-test.sh
sh scripts/service-identity-rollout.sh --mode plan
MODE=plan MINIO_BUCKET=example MINIO_PREFIX=runtime/ sh scripts/minio-service-identity.sh
```

The sandbox uses disposable PostgreSQL and MinIO containers with tmpfs data. It
tests actual logins, allowed queries, cross-table denials, legacy revocation,
object round-trip, cross-prefix/cross-bucket denials and MinIO admin denial.
It does not touch live volumes or credentials.
