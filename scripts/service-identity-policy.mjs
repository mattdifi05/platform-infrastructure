#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (name) => fs.readFileSync(path.join(root, name), "utf8");
const compose = read("compose.yaml");
const secretsCompose = read("compose.secrets.yaml");
const managedCompose = read("compose.managed-secrets.yaml");
const migration = read("postgres/migrations/014_service_identity_grants.sql");
const revoke = read("postgres/rollout/service-identity-legacy-revoke.sql");
const rollback = read("postgres/rollout/service-identity-legacy-rollback.sql");
const minioBootstrap = read("scripts/minio-service-identity.sh");
const secretManager = read("scripts/infra-secret-manager.mjs");
const infraOps = read("scripts/infra-ops.mjs");
const postgresEntrypoint = read("postgres/entrypoint-with-init-secrets.sh");

let checks = 0;

function assert(condition, message) {
  checks += 1;
  if (!condition) throw new Error(message);
}

function serviceBlock(source, name) {
  const match = source.match(new RegExp(`^  ${name}:\\n([\\s\\S]*?)(?=^  [a-zA-Z0-9_-]+:|^secrets:|^networks:|^volumes:|\\z)`, "m"));
  if (!match) throw new Error(`Missing service block: ${name}`);
  return match[0];
}

const backend = serviceBlock(compose, "backend");
const jobs = serviceBlock(compose, "worker-jobs");
const notifications = serviceBlock(compose, "worker-notifications");
const secretBackend = serviceBlock(secretsCompose, "backend");
const secretJobs = serviceBlock(secretsCompose, "worker-jobs");
const secretNotifications = serviceBlock(secretsCompose, "worker-notifications");

assert(/DATABASE_URL_FILE: \/run\/secrets\/backend_database_url/.test(backend), "Backend must use its dedicated database URL secret.");
assert(/DATABASE_URL_FILE: \/run\/secrets\/worker_jobs_database_url/.test(jobs), "Jobs must use its dedicated database URL secret.");
assert(/DATABASE_URL_FILE: \/run\/secrets\/worker_notifications_database_url/.test(notifications), "Notifications must use its dedicated database URL secret.");
for (const [name, block] of [["backend", backend], ["jobs", jobs], ["notifications", notifications]]) {
  assert(!/DATABASE_URL_FILE: \/run\/secrets\/database_url(?:\s|$)/.test(block), `${name} must not use the legacy union URL.`);
}
assert(!/MINIO_ROOT_(?:USER|PASSWORD)/.test(backend), "Backend must not receive MinIO root identity material.");
assert(!/minio_root_password/.test(secretBackend), "Backend secret mount must not include MinIO root password.");
assert(/- backend_database_url/.test(secretBackend), "Backend dedicated URL must be mounted.");
assert(/- worker_jobs_database_url/.test(secretJobs), "Jobs dedicated URL must be mounted.");
assert(/- worker_notifications_database_url/.test(secretNotifications), "Notifications dedicated URL must be mounted.");

for (const name of ["backend_db_password", "worker_jobs_db_password", "worker_notifications_db_password", "backend_database_url", "worker_jobs_database_url", "worker_notifications_database_url"]) {
  assert(secretsCompose.includes(`${name}:`), `File-backed secret ${name} must be declared.`);
  assert(managedCompose.includes(`${name}:\n    external: true`), `Managed secret ${name} must be external.`);
  assert(secretManager.includes(`name: "${name}"`), `Secret Manager must track ${name}.`);
  assert(infraOps.includes(`name: "${name}"`), `Ops rotation policy must track ${name}.`);
}

for (const role of ["app_backend_runtime", "app_worker_jobs_rw", "app_worker_jobs_runtime", "app_worker_notifications_runtime"]) {
  assert(migration.includes(role), `Migration must declare ${role}.`);
}
assert(/GRANT SELECT, UPDATE ON %I\.audit_outbox TO app_worker_jobs_rw/.test(migration), "Jobs must be limited to select/update on audit outbox.");
assert(/GRANT SELECT ON %I\.backup_restore_runs TO app_worker_jobs_rw/.test(migration), "Jobs must read only backup/restore metrics.");
assert(/revoke_unexpected_memberships/.test(migration) && /app_worker_jobs_runtime/.test(migration) && /app_worker_notifications_runtime/.test(migration), "Worker union capabilities must be revoked explicitly.");
assert(/ALTER ROLE app_user NOLOGIN/.test(revoke), "Legacy union login must be disabled only in explicit revoke SQL.");
assert(/ALTER ROLE app_user LOGIN/.test(rollback), "Rollback must restore login without restoring broad direct grants.");
assert(!/GRANT ALL/.test(rollback), "Rollback must not restore broad direct grants.");

assert(/svcacct add/.test(minioBootstrap) && /--policy/.test(minioBootstrap), "MinIO bootstrap must create a policy-scoped service account.");
assert(/s3:prefix/.test(minioBootstrap), "MinIO policy must restrict list operations by prefix.");
assert(/mc admin info/.test(minioBootstrap), "MinIO verification must prove admin API denial.");
assert(/MODE=\$\{MODE:-plan\}/.test(minioBootstrap), "MinIO bootstrap must default to plan mode.");
assert(/platform-postgres-entrypoint/.test(serviceBlock(compose, "postgres")), "PostgreSQL must stage private init secrets before dropping privileges.");
assert(/chown postgres:postgres/.test(postgresEntrypoint) && /chmod 400/.test(postgresEntrypoint), "PostgreSQL init secrets must be copied with postgres-only access.");
assert(/platform-postgres-init/.test(serviceBlock(compose, "postgres")) && /docker-entrypoint-initdb\.d/.test(postgresEntrypoint), "PostgreSQL init assets must be staged across the privilege drop.");

process.stdout.write(`Service identity policy passed ${checks}/${checks} checks.\n`);
