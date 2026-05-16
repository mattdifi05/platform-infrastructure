# Stexor Enterprise Runbook

## Incident triage

1. Check service health:

   ```sh
   docker ps --format "table {{.Names}}\t{{.Status}}" | grep enterprise-
   ```

2. Check edge and API:

   ```sh
   sh ./scripts/enterprise-hardening-audit.sh
   sh ./scripts/security-smoke.sh
   curl https://api.localhost.com/health
   ```

3. Read scoped logs:

   ```sh
   docker compose -p enterprise_local logs -f traefik backend web postgres
   ```

4. Check database migrations:

   ```sh
   docker exec enterprise-postgres psql -U postgres -d stexor_app -c "select * from stexor_platform.schema_migrations order by applied_at desc;"
   ```

## Alerting

Prometheus sends alerts to Alertmanager, and Alertmanager posts grouped alerts to the notification worker at `worker-notifications:3000/alerts/prometheus`. The worker logs sanitized alert summaries into Loki and exposes delivery counters on `/metrics`.

Key alerts:

```text
ServiceTargetDown
BackendRedisUnavailable
WorkerPostgresUnavailable
AuditOutboxDeadLetters
PostgresBackupStale
RestoreDrillStale
AlertmanagerDeliveryFailed
```

Optional external forwarding:

```sh
ALERT_FORWARD_WEBHOOK_URL=https://hooks.example.invalid/stexor-alerts
```

Keep the URL in the production secret manager if it embeds credentials.

## Resilience drills

Run these before major releases and after infrastructure changes:

```sh
sh ./scripts/fault-injection-tests.sh
node ./scripts/stexor-ops.mjs load-profile --durationSeconds 60 --targetRps 8 --concurrency 8 --maxP95Ms 1000
node ./scripts/stexor-ops.mjs chaos-profile --confirmChaos
```

Acceptance criteria:

- Redis degradation does not bypass sensitive endpoint rate limits.
- PostgreSQL statement timeout cancels slow queries and rolls back cleanly.
- Audit outbox due/dead/failed metrics stay explainable after worker interruption.
- Backend p95 stays under the declared threshold for the selected profile.

The load profile uses a bounded synthetic `X-Forwarded-For` client pool by default so the performance probe does not collide with the security rate-limit budget consumed by smoke and E2E checks. Use `--preserveClientIp` when deliberately testing one-client throttling behavior.

If `AuditOutboxDeadLetters` fires, pause risky account operations, inspect `{job="docker",service="enterprise-worker-jobs"} |= "audit_outbox"`, fix the downstream sink, then replay only events whose `external_event_id` has not already been accepted by the sink.

If `BackendRedisUnavailable` fires, keep login/MFA/DB Console traffic under the degraded memory budget until Redis is healthy. Do not raise rate-limit ceilings during the incident.

## Centralized logs and audit

Promtail reads Docker JSON logs from `/var/lib/docker/containers` without Docker socket service discovery. Its pipeline unwraps Docker log entries, redacts common sensitive fields (`authorization`, `cookie`, `set-cookie`, `x-db-console-access`, `password`, `secret`, `token`, `otp`, passkey credentials and challenges), parses JSON app logs and labels them by `service` and `level`.

Primary operator queries:

```logql
{job="docker",service=~"enterprise-.+",level=~"warn|error"}
{job="docker",service="enterprise-backend"} |= "request failed"
{job="docker",service="enterprise-worker-jobs"} |= "audit_outbox"
```

Use Loki for operational logs and PostgreSQL `stexor_account.audit_events` plus `stexor_account.audit_outbox` for durable security/compliance events. Audit tables are append-only/RLS protected and the DB Console role must not read the outbox.

## Backup

Manual backup:

```sh
sh ./scripts/backup-postgres.sh
```

Daily Linux cron:

```sh
sh ./scripts/install-postgres-backup-cron.sh --cronRoot /opt/stexor/enterprise-infrastructure --backupAt 03:15 --drillAt 04:15 --retentionAt 05:15 --drillWeekday 0
```

The generated crontab covers daily backups, weekly restore drills and daily backup-artifact retention.

## Local secrets

```sh
sh ./scripts/stexor-secret-manager.sh init
sh ./scripts/stexor-secret-manager.sh verify
docker compose -f compose.yaml -f compose.secrets.yaml --env-file .env -p enterprise_local up -d
```

`stexor-secret-manager` is the proprietary local secret manager. It encrypts the canonical store, writes an audit log and materializes `secrets/*.txt` only for Docker Compose. Use `--sanitizeEnv` on `init-local-secrets` only after you are committed to starting local with `compose.secrets.yaml`.

Useful operations:

```sh
sh ./scripts/stexor-secret-manager.sh status
sh ./scripts/stexor-secret-manager.sh rotate --name session_signing_keys
sh ./scripts/stexor-secret-manager.sh rotate --name backup_signing_keys
```

## Restore test

Never trust a backup that has not been restored.

```sh
sh ./scripts/restore-test-postgres.sh --backupFile ./backups/postgres/stexor_app-YYYYMMDD-HHMMSS.dump
```

Scheduled drill:

```sh
sh ./scripts/backup-restore-drill.sh
```

Backup artifact retention:

```sh
sh ./scripts/prune-postgres-backups.sh --dryRun
sh ./scripts/prune-postgres-backups.sh
```

Retention refuses to delete dump artifacts unless `stexor_platform.backup_restore_runs` contains a recent successful `restore_test`.

## Off-site backup

```sh
export RESTIC_REPOSITORY="s3:s3.amazonaws.com/bucket/stexor"
export RESTIC_PASSWORD="use-a-real-secret-manager"
sh ./scripts/offsite-backup-restic.sh
```

## HA and managed secrets

Validate multi-node production overlays before deployment:

```sh
node ./scripts/stexor-ops.mjs ha-config-check
node ./scripts/stexor-ops.mjs managed-secrets-preflight
node ./scripts/stexor-ops.mjs dr-readiness-check
```

Production secret values must come from the approved secret manager or KMS sync
into external Docker secrets. The app accepts `*_FILE` variables for
`SESSION_SECRET`, `SECRET_HASH_KEYS`, `TOTP_ENCRYPTION_KEYS`, database, Redis,
NATS, SMTP and service credentials.

## Production preflight

```sh
sh ./scripts/production-preflight.sh
```

This must pass before public traffic is exposed.

## Access review

Run monthly:

```sh
sh ./scripts/access-review.sh
```

## Production deploy

Release approval is mandatory before public traffic is changed. The approver
must verify the release SHA, immutable image digests, SBOM artifact, provenance
attestation, rollback target and the output of:

```sh
node ./scripts/stexor-ops.mjs release-artifact-gate --requireProvenance
node ./scripts/stexor-ops.mjs governance-check
node ./scripts/stexor-ops.mjs enterprise-10-check
```

1. Build versioned images:

   ```sh
   docker compose -f compose.yaml -f compose.build.yaml --env-file .env build
   ```

2. Push images to the registry configured in `.env`.
3. Run migrations on the target before exposing traffic:

   ```sh
   sh ./scripts/apply-postgres-migrations.sh
   ```

4. Start production:

   ```sh
   docker compose -f compose.yaml -f compose.prod.yaml --env-file .env -p enterprise_prod up -d
   ```

5. Run smoke checks against public domains.
6. Run the mandatory supply-chain gate, then archive the dependency SBOM:

   ```sh
   sh ./scripts/supply-chain-hygiene.sh
   sh ./scripts/generate-sbom.sh
   ```

7. Sign immutable images before deployment:

   ```sh
   sh ./scripts/sign-images.sh
   ```

8. Record the deploy audit trail:

   ```text
   release_sha=<git sha>
   approved_by=<reviewer>
   images=<digest-pinned image refs>
   sbom=<archived sbom artifact>
   provenance=<attestation artifact>
   rollback_target=<previous image refs>
   deployed_at=<utc timestamp>
   ```

## Rollback

1. Keep the previous image tag in the registry.
2. Set `BACKEND_IMAGE`, `WEB_IMAGE`, `WORKER_*_IMAGE` back to the previous tag.
3. Restart only affected services.
4. Do not roll back the database unless a restore plan has been tested.
5. Append rollback reason, operator and restored image digests to the deploy audit trail.
