# Enterprise Infrastructure

Infrastruttura Docker self-hosted per la piattaforma Stexor enterprise. La cartella deve stare accanto al monorepo applicativo:

```text
/opt/stexor
|-- src
|   `-- infrastructure
`-- enterprise-infrastructure
```

La vecchia `src/infrastructure/` resta separata: avvia una sola infrastruttura alla volta.

## Documentazione applicativa

La documentazione maintainer del monorepo vive in `../src/README.md` e `../src/docs/`.
Questa cartella copre il runtime Docker e l'infrastruttura; il monorepo applicativo copre architettura,
flussi end-to-end, sicurezza applicativa, configurazione e quality gate.

## Stack

- Traefik reverse proxy con file provider, senza Docker socket montato.
- PostgreSQL per app e Keycloak.
- Redis per rate limit, OTP, passkey challenge e heartbeat worker.
- Keycloak, NATS JetStream, MinIO, Prometheus, Grafana, Loki e Promtail.
- Backend Fastify, web Next.js, worker notifiche e worker jobs in immagini locali buildate dal monorepo `../src`.

I container usano prefisso `enterprise-`, network `enterprise_net` e volumi `enterprise_*`.

## Avvio locale

```sh
cd /opt/stexor/enterprise-infrastructure
cp .env.example .env
docker compose -f compose.yaml -f compose.build.yaml --env-file .env -p enterprise_local up -d --build
```

Avvio consigliato con Stexor Secret Manager e Docker secrets file-based:

```sh
cd /opt/stexor/enterprise-infrastructure
cp .env.example .env
sh ./scripts/stexor-secret-manager.sh init
docker compose -f compose.yaml -f compose.build.yaml -f compose.secrets.yaml --env-file .env -p enterprise_local up -d --build
```

`stexor-secret-manager` mantiene uno store proprietario cifrato in `secrets/stexor-secret-manager-store.json`, audit JSONL in `secrets/stexor-secret-manager-audit.log` e materializza i file Docker secrets usati da `compose.secrets.yaml`. Backend e worker leggono i secret da `/run/secrets/*`, inclusi `DATABASE_URL_FILE`, `SESSION_SECRET_FILE`, `SESSION_SIGNING_KEYS_FILE`, `REDIS_PASSWORD_FILE`, `NATS_URL_FILE` e `SMTP_PASSWORD_FILE`.

Il dev Docker e' volutamente production-like: usa `NODE_ENV=production`, immagini buildate, nessun hot reload, nessun bind mount del sorgente applicativo e nessuna porta host diretta per database/cache/app. Il traffico passa da Traefik solo sugli host locali dichiarati del progetto.

## Stop, log e reset

```sh
docker compose -p enterprise_local down
docker compose -p enterprise_local logs -f
docker compose -p enterprise_local down -v
```

## URL locali

| Servizio | URL |
| --- | --- |
| UI principale | `https://ui.localhost.com` |
| Account center | `https://account.localhost.com` |
| API backend | `https://api.localhost.com` |
| Keycloak | `https://auth.localhost.com` |
| MinIO console | `https://minio.localhost.com` |
| Grafana | `https://grafana.localhost.com` |
| Traefik dashboard | `http://localhost:8090` |

Alertmanager resta interno alla rete Docker. Prometheus invia gli alert ad Alertmanager, che li inoltra al worker notifiche su `/alerts/prometheus` con token Bearer da Docker secret; il worker produce log Loki e metriche `notification_alert_*`.

I log sono centralizzati via Promtail senza montare `docker.sock`: Promtail legge i log JSON bounded dei container, applica una redaction pipeline su header, token, cookie, OTP e segreti, e promuove `service` e `level` a label Loki per query operative. Backend e worker usano la policy condivisa `@stexor/observability`; gli eventi critici restano anche su audit DB append-only/outbox.

## HTTPS locale

```sh
cd /opt/stexor/enterprise-infrastructure
mkcert -install
mkcert -cert-file ./traefik/certs/local-cert.pem -key-file ./traefik/certs/local-key.pem localhost 127.0.0.1 ::1 ui.localhost.com account.localhost.com api.localhost.com auth.localhost.com minio.localhost.com grafana.localhost.com
docker compose -f compose.yaml -f compose.build.yaml --env-file .env -p enterprise_local up -d --build traefik
curl https://api.localhost.com/health
```

Su Windows, apri PowerShell come amministratore e aggiungi gli host locali:

```powershell
Add-Content -Path "$env:SystemRoot\System32\drivers\etc\hosts" -Value "127.0.0.1 ui.localhost.com account.localhost.com api.localhost.com auth.localhost.com minio.localhost.com grafana.localhost.com"
```

I file in `traefik/certs/` sono ignorati da Git. In container isolati monta la CA mkcert oppure passa `--cacert`.

## Database e migrazioni

Lo schema applicativo vive in `stexor_account` dentro `stexor_app`. Gli init script in `postgres/init/` girano solo al primo avvio del volume; per aggiornamenti successivi:

```sh
cd /opt/stexor/enterprise-infrastructure
sh ./scripts/apply-postgres-migrations.sh
```

Le migrazioni sono tracciate in `stexor_platform.schema_migrations`.

## Backup e restore

```sh
cd /opt/stexor/enterprise-infrastructure
sh ./scripts/backup-postgres.sh
sh ./scripts/backup-restore-drill.sh
sh ./scripts/prune-postgres-backups.sh --dryRun
sh ./scripts/restore-test-postgres.sh --backupFile ./backups/postgres/stexor_app-YYYYMMDD-HHMMSS.dump
sh ./scripts/restore-postgres.sh --backupFile ./backups/postgres/stexor_app-YYYYMMDD-HHMMSS.dump --confirmRestore
```

Il restore reale e' protetto da `--confirmRestore` e accetta solo file sotto `backups/`. La retention dei dump richiede un `restore_test` riuscito recente in `stexor_platform.backup_restore_runs` e mantiene sempre almeno 3 backup regolari e 3 drill.

Backup off-site Restic:

```sh
export RESTIC_REPOSITORY="s3:s3.amazonaws.com/bucket/stexor"
export RESTIC_PASSWORD="use-a-real-secret-manager"
sh ./scripts/offsite-backup-restic.sh
```

Schedulazione Linux consigliata:

```sh
sh ./scripts/install-postgres-backup-cron.sh --cronRoot /opt/stexor/enterprise-infrastructure --backupAt 03:15 --drillAt 04:15 --retentionAt 05:15 --drillWeekday 0
```

Il comando stampa le righe cron da installare sull'host: backup quotidiano, restore drill settimanale e retention quotidiana dei dump.

## Gate e controlli

Quality gate dal monorepo:

```sh
cd /opt/stexor/src
pnpm enterprise:check
```

Audit infrastrutturale diretto:

```sh
cd /opt/stexor/enterprise-infrastructure
sh ./scripts/enterprise-hardening-audit.sh
```

Controlli disponibili:

```sh
sh ./scripts/static-security-check.sh
sh ./scripts/security-smoke.sh
sh ./scripts/fault-injection-tests.sh
sh ./scripts/account-integration-tests.sh
sh ./scripts/load-smoke.sh
sh ./scripts/secret-scan.sh
sh ./scripts/certificate-expiry-check.sh
sh ./scripts/supply-chain-hygiene.sh
sh ./scripts/generate-sbom.sh
sh ./scripts/production-preflight.sh
sh ./scripts/access-review.sh
sh ./scripts/sign-images.sh
```

Tutti gli entrypoint sono Linux/Docker-first; il runner comune e' `scripts/stexor-ops.mjs`.

## Produzione

```sh
cd /opt/stexor/enterprise-infrastructure
sh ./scripts/production-preflight.sh
docker compose -f compose.yaml -f compose.prod.yaml --env-file .env -p enterprise_prod up -d
```

In produzione:

- Traefik pubblica solo 80/443.
- PostgreSQL, Redis, NATS, MinIO, Prometheus e Loki non espongono porte host.
- Le immagini applicative devono essere versionate e pin-nate con digest.
- `.localhost.com` non e' valido per ACME pubblico: servono domini DNS reali.

Build immagini applicative:

```sh
docker compose -f compose.yaml -f compose.build.yaml --env-file .env build
```

Le variabili pubbliche di Next.js (`NEXT_PUBLIC_*` e host account) vengono passate anche come build args, quindi le immagini web devono essere buildate con l'ambiente corretto prima del deploy.

## Sicurezza account

- Sessioni firmate lato server in cookie `HttpOnly`, `Secure`, `SameSite=Lax`.
- Remember-me di 10 anni via `SESSION_COOKIE_MAX_AGE_SECONDS=315360000`; la revoca resta server-side.
- API mutative protette da Origin/Fetch Metadata.
- Passkey, OTP email, backup codes e revoca sessioni sono persistiti su PostgreSQL quando serve e usano Redis solo per stato temporaneo.

## File principali

- `compose.yaml`: stack local/dev production-like.
- `compose.secrets.yaml`: overlay Docker secrets file-based.
- `compose.prod.yaml`: overlay produzione.
- `compose.build.yaml`: build immagini applicative.
- `scripts/*.sh`: entrypoint operativi Linux/Docker.
- `scripts/stexor-ops.mjs`: runner portabile.
- `postgres/init/` e `postgres/migrations/`: schema e migrazioni.
- `RUNBOOK.md`, `SECURITY.md`, `THREAT-MODEL.md`, `ENTERPRISE-MATURITY.md`: governance operativa.
