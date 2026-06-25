# Enterprise Infrastructure

Infrastruttura Docker self-hosted per la piattaforma Platform enterprise. La cartella deve stare accanto al monorepo applicativo:

```text
/opt/platform
|-- src
`-- platform-infrastructure
```

`platform-infrastructure/` e' l'unica infrastruttura attiva: contiene anche la config PHP/Apache, MariaDB, phpMyAdmin, WAF, VPS e operazioni enterprise. I progetti applicativi restano in `src` e nelle cartelle sorgente dedicate, ma non esiste piu' una seconda infra da avviare.

## Documentazione applicativa

La documentazione maintainer del monorepo vive in `../src/README.md` e `../src/docs/`.
Questa cartella copre il runtime Docker e l'infrastruttura; il monorepo applicativo copre architettura,
flussi end-to-end, sicurezza applicativa, configurazione e quality gate.

## Stack

- Traefik reverse proxy con file provider, senza Docker socket montato.
- PostgreSQL per app e Keycloak.
- Redis per rate limit, OTP, passkey challenge e heartbeat worker.
- Keycloak, NATS JetStream, MinIO, Prometheus, node-exporter, cAdvisor, Grafana, Loki e Promtail.
- Backend Fastify, web Next.js, worker notifiche e worker jobs in immagini locali buildate dal monorepo `../src`.

I container usano prefisso `enterprise-`, network `enterprise_net` e volumi `enterprise_*`.

## Avvio locale

```sh
cd /opt/platform/platform-infrastructure
cp .env.example .env
docker compose -f compose.yaml -f compose.build.yaml --env-file .env -p platform_infra_local up -d --build
```

Avvio consigliato con Infra Secret Manager e Docker secrets file-based:

```sh
cd /opt/platform/platform-infrastructure
cp .env.example .env
sh ./scripts/infra-secret-manager.sh init
docker compose -f compose.yaml -f compose.build.yaml -f compose.secrets.yaml --env-file .env -p platform_infra_local up -d --build
```

`infra-secret-manager` mantiene uno store proprietario cifrato in `secrets/infra-secret-manager-store.json`, audit JSONL in `secrets/infra-secret-manager-audit.log` e materializza i file Docker secrets usati da `compose.secrets.yaml`. Lo store usa envelope KMS locale `local-bucket-kms` con KEK ruotabile. Backend, worker e gateway projects leggono i secret da `/run/secrets/*`, inclusi `DATABASE_URL_FILE`, `SESSION_SECRET_FILE`, `SESSION_SIGNING_KEYS_FILE`, `PROJECTS_GATEWAY_SIGNING_KEYS_FILE`, `REDIS_PASSWORD_FILE`, `NATS_URL_FILE` e `SMTP_PASSWORD_FILE`.

Il dev Docker e' volutamente production-like: usa `NODE_ENV=production`, immagini buildate, nessun hot reload, nessun bind mount del sorgente applicativo e nessuna porta host diretta per database/cache/app. Il traffico passa da Traefik solo sugli host locali dichiarati del progetto.

`phpmyadmin` non parte nello stack default. Per manutenzione locale temporanea avvialo esplicitamente con il profilo `admin` e spegnilo a fine intervento:

```sh
docker compose --env-file .env -p platform_infra_local -f compose.yaml -f compose.build.yaml -f compose.secrets.yaml -f compose.waf.yaml --profile admin up -d phpmyadmin traefik waf
docker compose -f compose.yaml -f compose.secrets.yaml --env-file .env -p platform_infra_local stop phpmyadmin
```

## Operazioni container-first

Tutti i wrapper in `scripts/*.sh` delegano a `scripts/infra-ops.sh`, che avvia l'immagine Linux `platform/ops:local` e monta solo repo, sorgente applicativo read-only e Docker socket. L'host non deve avere Node/PHP installati per backup, restore drill, health check, audit o deploy helper.

Per raggiungere i domini locali durante i check runtime, il runner usa `--network host` su Linux e mappa `*.localhost.com` a `host-gateway` su Docker Desktop. Se la tua installazione Docker richiede un target diverso, imposta `PLATFORM_LOCAL_HOST_TARGET`, ad esempio:

```sh
PLATFORM_LOCAL_HOST_TARGET=host.docker.internal sh ./scripts/infra-health.sh
```

## Stop, log e reset

```sh
docker compose -p platform_infra_local down
docker compose -p platform_infra_local logs -f
docker compose -p platform_infra_local down -v
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
| Stexor Control Center | `https://projects.localhost.com` |
| phpMyAdmin locale | `https://phpmyadmin.localhost.com` |

`projects.localhost.com` serve lo Stexor Control Center dal servizio Node `control-center`, separato da PHP Apache. Il pannello e' il progetto Node `@stexor/control-center` e dichiara `@stexor/ui` come dipendenza locale `file:vendor/@stexor/ui`; usa il package vendorizzato reale in `control-center/vendor/@stexor/ui`, legge `package.json`/`api-manifest.json`, carica gli entrypoint ufficiali `styles.css`/`ui.css`, ed espone il contratto del design system da `/control/ui-package`; poi legge i progetti da `PHP_PROJECTS_DIR`, divide runtime PHP e Node, espone la topologia Network Advanced da `/control/network` leggendo Compose e Traefik dynamic config in modalita' read-only, espone la mappa Monitoring Advanced da `/control/monitoring` leggendo Prometheus, Grafana, Loki e Alertmanager config senza query live, permette create metadata-only, enable/disable locale, update metadata, archive e soft delete solo nello stato Control Center, scrive stato in `projects-portal/state/projects.json`, app dichiarative in `projects-portal/state/applications.json`, domini dichiarativi in `projects-portal/state/domains.json`, database dichiarativi in `projects-portal/state/databases.json`, bucket storage dichiarativi in `projects-portal/state/storage-buckets.json`, inventario metadata-only dei materiali sensibili in `projects-portal/state/sensitive-materials.json`, worker/queue/job/scheduler metadata in `projects-portal/state/worker-jobs.json`, admin users/teams/roles/sessioni/access review in `projects-portal/state/identity-access.json`, web spaces in `projects-portal/state/webspaces.json`, resource limits in `projects-portal/state/resource-limits.json`, security policies in `projects-portal/state/security-policies.json`, alert locali in `projects-portal/state/alerts.json`, canali notifica in `projects-portal/state/notification-channels.json`, provider connection metadata in `projects-portal/state/provider-connections.json`, preferenze Settings in `projects-portal/state/settings.json`, audit in `projects-portal/state/audit.jsonl`, operazioni/step in `projects-portal/state/operations.jsonl`, piani deploy/rollback in `projects-portal/state/deployments.jsonl` e piani backup/restore drill in `projects-portal/state/backups.jsonl`. `PHP_SOURCE_DIR` punta a `php-runtime-root`, una root statica neutra: PHP Apache resta solo il runtime dei progetti PHP e non contiene la UI/API del Control Center. In locale `CONTROL_CENTER_AUTH_REQUIRED=false` mantiene il flusso rapido; in staging/VPS imposta `CONTROL_CENTER_AUTH_REQUIRED=true` e `CONTROL_CENTER_ADMIN_PASSWORD_SHA256` con lo SHA-256 della password admin. La sessione e' firmata con `projects_gateway_signing_keys` da Docker secret e il valore password non va mai in `.env`.
Advanced Mode espone lo scheletro delle aree enterprise richieste, inclusi Workers & Jobs, CI/CD & GitHub Governance, Logs/Alerts Advanced, Disaster Recovery, Release Evidence, Security Advanced e Billing / Plans. Queste superfici restano plan/evidence-only finche' un adapter esplicito non esegue apply e verifyRemote.
L'API Advanced read-only e' disponibile su `/control/advanced` e `/control/advanced/:section`; espone capability, guardrail ed evidence metadata senza chiamare provider live, senza toccare Docker e senza marcare evidenza production.
Il registry adapter backend e' disponibile su `/control/adapters` e `/control/adapters/:id`; include Cloudflare, Traefik, Docker, GitHub, Prometheus, Loki, Alertmanager, Backup, Restore, MinIO, Database, Security e Go/No-Go. `/control/adapters/:id/plan` e `/verify` producono piani auditati, mentre `/apply` viene respinto finche' non esiste un backend live esplicito con conferma forte e verifyRemote.

Alertmanager resta interno alla rete Docker. Prometheus invia gli alert ad Alertmanager, che li inoltra al worker notifiche su `/alerts/prometheus` con token Bearer da Docker secret; il worker produce log Loki, metriche `notification_alert_*`, email reali verso `ALERT_EMAIL_TO` quando SMTP e' configurato, e canali opzionali Discord/Telegram tramite secret file. `node-exporter` e `cadvisor` forniscono metriche CPU, RAM, disco e container per alert operativi.

I log sono centralizzati via Promtail senza montare `docker.sock`: Promtail legge i log JSON bounded dei container, applica una redaction pipeline su header, token, cookie, OTP e segreti, e promuove `service` e `level` a label Loki per query operative. Backend e worker usano la policy condivisa `@platform/observability`; gli eventi critici restano anche su audit DB append-only/outbox.

Prometheus, Alertmanager e la dashboard Traefik non hanno route browser locali: restano interni alla rete Docker. Usa Grafana, protetto da login, come superficie browser per metriche, alert e log.

Il monitoraggio esterno e' definito in `monitoring/external-uptime.example.json`: include health pubbliche, discovery OIDC e controlli negativi sugli host admin che devono restare bloccati. Prima di configurare BetterStack, UptimeRobot o Cloudflare Health Checks, valida il manifest e le soglie con:

```sh
sh ./scripts/external-uptime-check.sh --dryRun
```

Il dry-run scrive un report diagnostico in `reports/uptime/` con
`mode=dry-run` e `providerEvidence.verified=false`; serve per archiviare la
validazione del manifest, ma non soddisfa il production go/no-go.

Quando DNS, CDN e TLS sono attivi, crea i monitor nel provider esterno, copia `monitoring/external-uptime-provider.example.json`, compila `monitorId`, `verifiedAt`, regioni reali, ultimo status code, latenza e `lastCheckedAt` letti dal provider, poi esegui:

```sh
sh ./scripts/external-uptime-check.sh --providerEvidence ./monitoring/external-uptime-provider.production.json --validateProviderEvidenceOnly
sh ./scripts/external-uptime-check.sh --envFile .env --providerEvidence ./monitoring/external-uptime-provider.production.json --requireProviderEvidence
```

Il go/no-go accetta `reports/uptime/` solo se i target pubblici sono coperti da provider evidence esterna verificata e con ultimi risultati provider freschi; il secondo comando aggiunge anche una sonda HTTP diretta dal punto in cui lo esegui.

## HTTPS locale

```sh
cd /opt/platform/platform-infrastructure
mkcert -install
mkcert -cert-file ./traefik/certs/local-cert.pem -key-file ./traefik/certs/local-key.pem localhost 127.0.0.1 ::1 ui.localhost.com account.localhost.com api.localhost.com auth.localhost.com minio.localhost.com grafana.localhost.com
docker compose -f compose.yaml -f compose.build.yaml --env-file .env -p platform_infra_local up -d --build traefik
curl https://api.localhost.com/health
```

Su Windows, apri PowerShell come amministratore e aggiungi gli host locali:

```powershell
Add-Content -Path "$env:SystemRoot\System32\drivers\etc\hosts" -Value "127.0.0.1 ui.localhost.com account.localhost.com api.localhost.com auth.localhost.com minio.localhost.com grafana.localhost.com"
```

I file in `traefik/certs/` sono ignorati da Git. In container isolati monta la CA mkcert oppure passa `--cacert`.

## WAF locale

Il profilo WAF mette OWASP CRS/ModSecurity davanti a Traefik. Le porte host `80/443` sono pubblicate solo dal WAF; Traefik resta interno alla rete Docker. L'immagine e' un tag stabile pin-nato con digest, non un rolling tag.

```sh
cd /opt/platform/platform-infrastructure
docker compose --env-file .env -p platform_infra_local \
  -f compose.yaml \
  -f compose.build.yaml \
  -f compose.secrets.yaml \
  -f compose.waf.yaml \
  up -d --build
sh ./scripts/waf-smoke.sh
```

Baseline WAF: CRS paranoia level 2, blocking mode attivo, audit log `RelevantOnly`, request body inspection attiva, response body inspection spenta, file sensibili e scanner path bloccati prima del routing applicativo. PL3/PL4 vanno attivati solo dopo una finestra di tuning sui log, altrimenti il rischio falso positivo diventa alto per dashboard, OAuth e form PHP.

Su Windows/Docker Desktop il certificato mkcert locale e' montato in un container non privilegiato. Se il WAF non riesce a leggere `local-key.pem`, rendi la copia locale leggibile dal runtime Docker e riavvia:

```powershell
docker run --rm --entrypoint sh -u root -v "${PWD}\traefik\certs\local-key.pem:/tmp/server.key" owasp/modsecurity-crs:4.26.0-nginx-202605200705 -c "chmod 0644 /tmp/server.key"
docker compose --env-file .env -p platform_infra_local -f compose.yaml -f compose.build.yaml -f compose.secrets.yaml -f compose.waf.yaml up -d waf
```

## Database e migrazioni

Lo schema applicativo vive in `app_account` dentro `app_db`. Gli init script in `postgres/init/` girano solo al primo avvio del volume; per aggiornamenti successivi:

```sh
cd /opt/platform/platform-infrastructure
sh ./scripts/apply-postgres-migrations.sh
```

Le migrazioni sono tracciate in `platform_ops.schema_migrations`.

## Backup e restore

```sh
cd /opt/platform/platform-infrastructure
sh ./scripts/backup-postgres.sh
sh ./scripts/backup-restore-drill.sh
sh ./scripts/prune-postgres-backups.sh --dryRun
sh ./scripts/restore-test-postgres.sh --backupFile ./backups/postgres/app_db-YYYYMMDD-HHMMSS.dump
sh ./scripts/restore-postgres.sh --backupFile ./backups/postgres/app_db-YYYYMMDD-HHMMSS.dump --confirmRestore
sh ./scripts/backup-mariadb.sh
sh ./scripts/backup-restore-drill-mariadb.sh
sh ./scripts/restore-test-mariadb.sh --backupFile ./backups/mariadb/mariadb-all-YYYYMMDD-HHMMSS.sql.gz
sh ./scripts/backup-minio.sh
sh ./scripts/backup-restore-drill-minio.sh
sh ./scripts/restore-test-minio.sh --backupFile ./backups/minio/minio-data-YYYYMMDD-HHMMSS.tar.gz
sh ./scripts/backup-keycloak.sh
sh ./scripts/backup-restore-drill-keycloak.sh
sh ./scripts/restore-test-keycloak.sh --backupFile ./backups/keycloak/keycloak-config-YYYYMMDD-HHMMSS.tar.gz
sh ./scripts/backup-secret-manager-metadata.sh
sh ./scripts/backup-restore-drill-secret-manager-metadata.sh
sh ./scripts/restore-test-secret-manager-metadata.sh --backupFile ./backups/secret-manager/secret-manager-metadata-YYYYMMDD-HHMMSS.tar.gz
sh ./scripts/full-restore-drill.sh
sh ./scripts/dr-evidence.sh
```

Il restore reale e' protetto da `--confirmRestore` e accetta solo file sotto `backups/`. La retention dei dump richiede un `restore_test` riuscito recente in `platform_ops.backup_restore_runs` e mantiene sempre almeno 3 backup regolari e 3 drill.
I backup MariaDB coprono tutti i database dei progetti PHP locali, sono compressi, hanno sidecar `.sha256` e firma HMAC, e il restore drill importa il dump in un container MariaDB disposable senza toccare il volume reale.
I backup MinIO, Keycloak e Secret Manager metadata sono artifact tar.gz firmati e verificati. I restore drill sono non distruttivi: MinIO usa un volume/container disposable, Keycloak valida la configurazione esportata senza importarla sul realm live, Secret Manager verifica store/KMS metadata senza includere la master key.
Ogni backup manuale, schedulato o eseguito dentro un drill scrive anche un report JSON e Markdown in `reports/backups/` con durata, artifact, dimensione, SHA256 e firma. La cartella `reports/` e' ignorata da Git.
`dr-evidence.sh` aggrega i report ignorati in `reports/backups/`, `reports/restore-drills/` e `reports/offsite-restore-drills/`, calcola eta' backup, media/P95 dei restore e stato RTO/RPO. In staging/VPS usa `--enforce` per fallire se mancano prove fresche o se il restore supera il target.

Backup off-site Restic:

```sh
export RESTIC_REPOSITORY="s3:s3.amazonaws.com/bucket/platform"
sh ./scripts/offsite-backup-restic.sh --passwordFile ./secrets/restic_password.txt
sh ./scripts/offsite-restore-drill-restic.sh --planOnly
sh ./scripts/offsite-restore-drill-restic.sh --dryRun --passwordFile ./secrets/restic_password.txt
sh ./scripts/offsite-restore-drill-restic.sh --passwordFile ./secrets/restic_password.txt
```

Senza `--backupFile`, Restic carica l'ultimo artifact firmato di PostgreSQL, MariaDB, MinIO, Keycloak e Secret Manager metadata. Se manca una famiglia dati, il comando fallisce; usa `--allowPartial` solo durante bootstrap o manutenzione controllata.
`offsite-restore-drill-restic.sh --dryRun` valida repository e snapshot senza scrivere file. Senza `--dryRun`, il comando ripristina gli artifact in percorsi disposable, verifica checksum/firma, lancia i restore-test PostgreSQL, MariaDB, MinIO, Keycloak e Secret Manager metadata, poi scrive evidenza JSON/Markdown in `reports/offsite-restore-drills/`.
Per il go-live il repository Restic deve essere remoto (`s3:`, `b2:`, `azure:`, `gs:`, `sftp:`, `rest:` o `rclone:`) e non deve puntare a localhost, rete Docker o IP privati. Il report production valido deve avere `coverage.complete=true`: tutte le famiglie dati restaurate, nessun `--allowPartial`, e `infra-health` riuscito dopo il restore. Un repository locale o un restore parziale va bene solo per bootstrap o prove meccaniche e non soddisfa il gate production.

Schedulazione consigliata, container-first:

```sh
docker compose --env-file .env -p platform_infra_vps \
  -f compose.yaml \
  -f compose.build.yaml \
  -f compose.secrets.yaml \
  -f compose.vps.yaml \
  -f compose.waf.yaml \
  -f compose.vps-waf.yaml \
  -f compose.backup-scheduler.yaml \
  --profile backup \
  up -d backup-scheduler
```

Il servizio `backup-scheduler` usa l'immagine ops Dockerizzata e `crond` interno, quindi non richiede cron o Node sull'host. Schedula backup giornalieri PostgreSQL, MariaDB, MinIO, Keycloak e Secret Manager metadata, retention PostgreSQL e un `full-restore-drill` settimanale. Lo scheduler rileva i mount host da Docker; su VPS puoi forzarli con `PLATFORM_INFRA_HOST_ROOT` e `PROJECT_SOURCE_HOST_ROOT` se usi percorsi custom. L'upload Restic off-site parte solo con `BACKUP_SCHEDULER_ENABLE_OFFSITE=true` e credenziali reali. Il runtime env file privato dello scheduler viene letto con parser dedicato dai job `--run` e non viene eseguito con `source`.

Schedulazione Linux host fallback:

```sh
sh ./scripts/install-postgres-backup-cron.sh --cronRoot /opt/platform/platform-infrastructure --backupAt 03:15 --drillAt 04:15 --retentionAt 05:15 --drillWeekday 0
sh ./scripts/install-mariadb-backup-cron.sh --cronRoot /opt/platform/platform-infrastructure --backupAt 03:45 --drillAt 04:45 --drillWeekday 0
sh ./scripts/install-offsite-backup-cron.sh --cron-root /opt/platform/platform-infrastructure
```

I comandi stampano le righe cron da installare sull'host: backup quotidiano, restore drill settimanale, retention quotidiana dei dump PostgreSQL e upload off-site degli artifact firmati.

## Gate e controlli

Quality gate dal monorepo, per dev/CI dove Node e pnpm sono gia' presenti:

```sh
cd /opt/platform/src
pnpm enterprise:check
```

Audit infrastrutturale diretto:

```sh
cd /opt/platform/platform-infrastructure
sh ./scripts/enterprise-hardening-audit.sh
```

Controlli disponibili:

```sh
sh ./scripts/static-security-check.sh
sh ./scripts/infra-health.sh
sh ./scripts/compose-healthcheck-coverage.sh
sh ./scripts/rate-limit-evidence.sh
sh ./scripts/audit-log-evidence.sh
sh ./scripts/retention-evidence.sh
sh ./scripts/dr-evidence.sh
sh ./scripts/alert-evidence.sh
sh ./scripts/security-smoke.sh
sh ./scripts/waf-smoke.sh
sh ./scripts/failure-tests.sh
sh ./scripts/failure-tests.sh --confirmServiceStop --targets redis,postgres,minio,keycloak,backend,worker-notifications,worker-jobs,nats,waf
sh ./scripts/fault-injection-tests.sh
sh ./scripts/account-integration-tests.sh
sh ./scripts/load-smoke.sh
sh ./scripts/load-benchmark.sh --profiles 50,100,500
sh ./scripts/load-benchmark.sh --profiles 50,100,500 --url https://api.example.com/health --requirePublicTarget --requireEdgeEvidence --expectedEdgeProvider cloudflare
sh ./scripts/linux-portability-check.sh
sh ./scripts/secret-scan.sh
sh ./scripts/secret-rotation-evidence.sh
sh ./scripts/certificate-expiry-check.sh
sh ./scripts/supply-chain-hygiene.sh
sh ./scripts/generate-sbom.sh
sh ./scripts/production-preflight.sh
sh ./scripts/access-review.sh
sudo sh ./scripts/vps-host-readiness.sh --ssh-port 65002 --enforce
sh ./scripts/github-branch-protection.sh --repo OWNER/REPO --branch main --dryRun
sh ./scripts/github-environments.sh --repo OWNER/REPO --dryRun
sh ./scripts/github-actions-config.sh --repo OWNER/REPO
sh ./scripts/pre-go-live-evidence.sh --repo OWNER/REPO
sh ./scripts/release-evidence.sh --planOnly
sh ./scripts/production-go-no-go.sh
sh ./scripts/rollback-release.sh --rollbackFile ./release/previous-images.json
sh ./scripts/sign-images.sh
sh ./scripts/dast-zap-baseline.sh https://api-staging.example.com
```

`alert-evidence.sh` verifica configurazione Alertmanager, bearer secret, metriche worker e alert di failure delivery. In staging/VPS usa `alert-evidence.sh --sendTest`; con canali reali configurati puoi aggiungere `--requireEmailDelivery`, `--requireDiscordDelivery` o `--requireTelegramDelivery` per rendere la consegna un gate.

`secret-rotation-evidence.sh` scrive un report non-secret in `reports/secret-rotation/` con stato dello store Infra Secret Manager, audit log, KMS attivo, eta' dei secret rispetto a `rotationDays`, file materializzati e risultato di `infra-secret-manager verify`. In produzione usa `--enforce`: il go/no-go accetta solo `mode=evidence`, `status=passed`, zero secret scaduti e zero file mancanti.

`compose-healthcheck-coverage` renderizza gli stack local WAF, VPS WAF e backup scheduler, poi scrive `reports/healthchecks/healthcheck-coverage-*.json`/`.md`. Fallisce se un servizio operativo del render Compose non ha una healthcheck.

`rate-limit-evidence.sh` scrive un report in `reports/rate-limits/` che verifica il rate limit Traefik, i router local/VPS, i budget backend e, quando il sorgente Platform e' montato, anche Fastify fail-closed, fallback Redis->memoria e test 429. In CI resta infra-only se il progetto applicativo non e' presente.

`audit-log-evidence.sh` scrive un report in `reports/audit-logs/` che verifica schema audit append-only, outbox durevole, RLS, dead-letter, alert Prometheus, dashboard Grafana e, quando il sorgente Platform e' montato, anche scrittura transazionale backend, dispatcher worker, sink NATS e test di crash/retry.

`retention-evidence.sh` scrive un report in `reports/retention/` che verifica logging Docker bounded, retention Loki/Promtail, retention TSDB Prometheus, datasource/pannelli Grafana e, quando il sorgente Platform e' montato, anche log JSON strutturati e redazione dei campi sensibili. In CI resta infra-only se il progetto applicativo non e' presente.

`load-benchmark.sh` senza `--url` misura il backend dentro la rete Docker ed e' utile per regressioni locali. Per il go-live devi usare l'URL pubblico e `--requirePublicTarget`; con Cloudflare CDN attivo aggiungi `--requireEdgeEvidence --expectedEdgeProvider cloudflare`. Il report in `reports/load/` include profili 50/100/500, snapshot CPU/RAM Docker, target evidence pubblico/edge e `status`. Anche i fallimenti scrivono report diagnostici, ma il go/no-go accetta solo `status=passed`.

Tutti gli entrypoint sono Linux/Docker-first; il runner comune e' `scripts/infra-ops.sh`.
Sul VPS non servono Node, pnpm o una toolchain JS installati sull'host: i wrapper
`scripts/*.sh` costruiscono e usano automaticamente il runner containerizzato
`platform/ops:local` da `docker/ops.Dockerfile`. L'host deve avere solo Ubuntu LTS,
Docker Engine, Docker Compose plugin e Git.

La policy GitHub live e' versionata in `governance/github-branch-protection.json`.
Usa `scripts/github-branch-protection.sh` in dry-run, poi `--apply` e
`--verifyRemote` con un token GitHub admin prima del primo deploy pubblico.
Gli environment di deploy sono versionati in `governance/github-environments.json`.
Configura `GITHUB_PRODUCTION_REVIEWERS=user:login` o `team:slug`, poi usa
`scripts/github-environments.sh --dryRun`, `--apply` e `--verifyRemote` per
abilitare approvazione, wait timer e branch policy su staging/production.
La runtime config GitHub Actions e' versionata in
`governance/github-actions-runtime.json`: `DAST_TARGET`, `DEPLOY_SSH_KEY`,
`DEPLOY_REMOTE`, `DEPLOY_REMOTE_DIR`, `DEPLOY_SSH_PORT`,
`VPS_HARDENED_SSH_PORT`, `PUBLIC_API_HEALTH_URL`, `CLOUDFLARE_ACCOUNT_ID`,
`EXTERNAL_UPTIME_PROVIDER_EVIDENCE_JSON` e
`CLOUDFLARE_API_TOKEN` piu' `CLOUDFLARE_ACCESS_ADMIN_MANIFEST_JSON` vengono verificati da
`scripts/github-actions-config.sh --verifyRemote` senza stampare valori
segreti. Per il go-live finale registra anche la run CI remota del commit di
release con
`GITHUB_TOKEN=<token> sh ./scripts/github-actions-run-evidence.sh --repo OWNER/REPO --workflow enterprise-infra.yml --branch main --sha <release-sha> --verifyRemote`;
il report finisce in `reports/github-actions/` e deve avere `status=passed` e
`run.conclusion=success`. La workflow `enterprise-infra-run-evidence` produce
automaticamente la stessa evidenza dopo ogni completamento di `enterprise-infra`
su `main` e carica `reports/github-actions/` come artifact non-secret. La CI dell'infra non esegue checkout di repository progetto: collega
Collega i repository applicativi solo tramite `PROJECT_SOURCE_DIR` quando devi buildarli.
La workflow manuale `enterprise-live-evidence` gira nell'environment GitHub
`production` e raccoglie prove live non mutanti: uptime provider, load benchmark
pubblico via Cloudflare, Cloudflare Access `--verifyRemote`, go/no-go live e
bundle completo.
La workflow manuale `enterprise-vps-evidence` gira nello stesso environment,
entra nel VPS con `DEPLOY_SSH_KEY`, `DEPLOY_REMOTE` e `DEPLOY_SSH_PORT`, puo'
applicare bootstrap/hardening solo con conferma esplicita, esegue
`vps-host-readiness --enforce` sulla porta `VPS_HARDENED_SSH_PORT` e carica i
report `reports/vps-*` come artifact.
Il gate `scripts/infra-ops.sh repo-coverage-check` misura la copertura dei
file tracciati della repo: ogni file deve rientrare in una categoria
infrastrutturale e il workflow deve esercitare tutti i gate CI obbligatori.
Prima del go-live genera un evidence pack con
`scripts/pre-go-live-evidence.sh --repo OWNER/REPO`: il comando scrive JSON e
Markdown in `reports/go-live/` con `status`, `missingOptions` e `issues`,
aggrega gate locali e dry-run provider, e segnala cio' che resta da provare su
VPS/Cloudflare/GitHub live. Su staging o VPS puoi aggiungere
`--includeRuntime`, `--includeRestoreDrill` e `--includeOffsiteRestoreDryRun`,
poi `--verifyGithubRemote` quando GitHub e' configurato. I report diagnostici
con `status=failed` non soddisfano il production go/no-go.

Prima del deploy pubblico esegui anche `scripts/production-go-no-go.sh`. Il
comando legge i report ignorati da Git e scrive JSON/Markdown in
`reports/go-no-go/`. In summary mode mostra `go` o `no-go`; con `--enforce`
blocca la release se mancano VPS bootstrap/hardening apply, VPS host readiness,
Cloudflare Access `--verifyRemote`, GitHub Actions run remota passata,
secret rotation evidence, DR/off-site restore, alert email reale, uptime
esterno, load pubblico 50/100/500, release evidence o pre-go-live evidence
completo. Ogni
report `no-go` include anche `remediation` in JSON e una sezione Markdown con
azioni, comandi ed evidenza attesa per chiudere i check falliti sulla VPS.
Dopo un `go`, esegui anche `scripts/production-readiness-live.sh`: valida la
checklist production-ready da 20 punti contro l'ultimo `production-go-no-go` e
scrive l'evidenza in `reports/production-readiness/`.

Quando i report sono pronti, genera un archivio non committato con le evidenze
operative:

```sh
sh ./scripts/evidence-bundle.sh
sh ./scripts/evidence-bundle-verify.sh --requireComplete
```

Il bundle finisce in `.tmp/evidence-bundles/`, include gli ultimi report
JSON/Markdown per categoria, documentazione operativa e manifest SHA256, ed
esclude sempre `secrets/`, artifact di backup, `.env`, SBOM/release artifact e
altri file sensibili. Usa `--allReports` solo se devi consegnare tutta la
cronologia report della finestra di validazione. `evidence-bundle-verify.sh`
rilegge `manifest.json`, ricontrolla SHA256, size, policy anti-segreti e, con
`--requireComplete`, fallisce se manca una qualunque evidenza richiesta.

`scripts/linux-portability-check.sh` verifica BOM UTF-8, CRLF, path Windows e
dipendenze PowerShell/cmd nei file operativi, poi valida gli shell script dentro
Alpine. Scrive report in `reports/linux-portability/`. Usa
`scripts/linux-portability-check.sh --fix` per normalizzare BOM/CRLF prima di
committare o spostare la stack su Ubuntu.

Per ogni release candidata genera anche il manifest operativo:

```sh
sh ./scripts/release-evidence.sh --planOnly
sh ./scripts/release-evidence.sh --requireProvenance --provenance ./release/provenance.json --previousImagesFile ./release/previous-images.json
```

  Il comando valida immagini digest-pinned, SBOM, provenance opzionale, firma opzionale con `--verifyCosign`, scrive report in `reports/release/` con `status`/`issues` e, quando riceve i digest precedenti, produce `release/previous-images.json`. La provenance deve essere una statement/bundle DSSE in-toto con `predicateType` SLSA v1, `predicate.buildDefinition.buildType`, subject `sha256` per ogni immagine di release e riferimento al commit di release; `--skipProvenanceCommitCheck` e' solo per eccezioni provider revisionate. In evidence mode esegue anche la dry-run di rollback non distruttiva, valida `docker compose config` con i digest precedenti e collega il report `reports/rollback/rollback-plan-*.json` dentro l'evidence pack della release. I fallimenti scrivono comunque report diagnostici, ma il go/no-go accetta solo `status=passed`.

## Produzione

### VPS hardening e Cloudflare origin-lock

Prima del deploy pubblico su VPS/Ubuntu LTS:

```sh
sudo sh ./scripts/vps-bootstrap-ubuntu.sh --apply --deploy-user deploy
sudo sh ./scripts/vps-hardening-ubuntu.sh --apply --ssh-port 65002 --reload-sshd
sudo sh ./scripts/vps-host-readiness.sh --ssh-port 65002 --enforce
sudo sh ./scripts/cloudflare-origin-lock-ufw.sh --apply --ports "80"
```

`vps-bootstrap-ubuntu.sh` e' dry-run di default e genera report JSON/Markdown in
`reports/vps-bootstrap/`. Con `--apply` configura il repository apt ufficiale
Docker per Ubuntu, installa Git, Docker Engine, Buildx e Docker Compose plugin,
poi verifica `docker`, `docker compose` e `git`.

`vps-hardening-ubuntu.sh` e' dry-run di default e genera report JSON/Markdown in
`reports/vps-hardening/`. Con `--apply` applica SSH hardening, sysctl, UFW,
fail2ban, unattended upgrades, auditd/AppArmor e Docker daemon hardening. Se
`/etc/docker/daemon.json` non esiste, scrive direttamente la config hardened e
riavvia Docker; se esiste ma manca chiavi Platform, fallisce finche' non rivedi
`/etc/docker/daemon.json.platform-template` e rilanci con
`--replace-docker-daemon-config`, che crea backup prima della sostituzione.
Usa `--reload-sshd` solo dopo aver verificato accesso con chiave e nuova porta:
il comando valida `sshd -t`, ricarica `ssh`/`sshd` e registra
`ssh-service-reload=applied` nel report.
Archivia il report insieme al successivo `vps-host-readiness --ssh-port 65002 --enforce`.

Se Cloudflare parla con l'origin anche su 443, usa `--ports "80 443"`. Dopo aver verificato DNS proxied e traffico Cloudflare, rimuovi eventuali vecchie regole UFW generiche `allow 80/tcp` e `allow 443/tcp`: l'origin non deve accettare bypass diretti.
`vps-host-readiness.sh --ssh-port 65002 --enforce` genera report JSON/Markdown in `reports/vps-host/` e
verifica Ubuntu LTS, Docker Engine, Compose plugin, Git, UFW, fail2ban, SSH
hardening, porta SSH attesa, regola UFW per quella porta, Docker daemon
hardening, auditd/AppArmor, risorse minime e runtime host non necessari. Ogni
check include anche una remediation operativa, cosi' il report fallito diventa
la checklist correttiva da applicare sulla VPS.
Per prove Linux locali dentro container usa `--diagnostic`: scrive in
`reports/vps-host-diagnostics/` e non viene considerato dal go/no-go di
produzione.
In GitHub Actions puoi raccogliere la stessa evidenza con la workflow manuale
`enterprise-vps-evidence`; usa `DEPLOY_SSH_PORT` per la porta corrente di accesso
e `VPS_HARDENED_SSH_PORT` per la porta che la readiness deve provare.

Le regole edge Cloudflare versionate sono in `cloudflare/`. Il WAF Cloudflare blocca admin host, file sensibili e scanner path prima della VPS; il WAF interno OWASP CRS resta attivo come secondo livello. `cloudflare/access-admin.example.json` rende versionate anche le applicazioni Cloudflare Access per phpMyAdmin, Grafana, Prometheus, Alertmanager, MinIO, Traefik, Projects e Keycloak Admin.

### Staging

Staging usa gli stessi overlay della produzione ma domini, volumi e secret separati:

```sh
cp .env.staging.example .env.staging
sh ./scripts/infra-secret-manager.sh init
docker compose --env-file .env.staging -p platform_infra_staging \
  -f compose.yaml \
  -f compose.build.yaml \
  -f compose.secrets.yaml \
  -f compose.vps.yaml \
  -f compose.waf.yaml \
  -f compose.vps-waf.yaml \
  -f compose.staging.yaml \
  up -d --build
```

Esegui DAST solo su staging:

```sh
sh ./scripts/dast-zap-baseline.sh https://api-staging.example.com
```

### VPS prod-like con TLS esterno

Usa questo profilo quando dominio e certificati sono gestiti fuori da Docker, per esempio da VPS o da Cloudflare davanti alla VPS. Traefik resta il reverse proxy interno, ascolta solo HTTP sulla porta 80 e inoltra alle app `X-Forwarded-Proto=https`.

```sh
cd /opt/platform/platform-infrastructure
cp .env.example .env
# copia i valori di .env.vps.example dentro .env e sostituisci tutti i domini example.com
sh ./scripts/infra-secret-manager.sh init
sh ./scripts/vps-preflight.sh .env
docker compose --env-file .env -p platform_infra_vps \
  -f compose.yaml \
  -f compose.build.yaml \
  -f compose.secrets.yaml \
  -f compose.vps.yaml \
  -f compose.waf.yaml \
  -f compose.vps-waf.yaml \
  up -d --build
sh ./scripts/vps-postdeploy.sh .env
```

`vps-preflight.sh` valida env, secret file e render completo dello stesso
set Compose usato dal deploy VPS, inclusi `compose.waf.yaml` e
`compose.vps-waf.yaml`.

`vps-postdeploy.sh` carica `.env`, usa gli URL pubblici reali e lancia
WAF smoke piu' `infra-health` per default. Con `DEPLOY_RUN_GO_NO_GO=1` esegue
anche `production-go-no-go.sh --enforce` e `production-readiness-live.sh`. Per
il go-live finale puoi abilitarlo anche da `deploy-vps.sh` con:

```sh
DEPLOY_RUN_PRE_GO_LIVE=1 \
DEPLOY_RUN_GO_NO_GO=1 \
DEPLOY_REPO=OWNER/REPO \
sh ./scripts/deploy-vps.sh
```

I drill piu' pesanti restano opt-in: usa
`DEPLOY_PRE_GO_LIVE_RESTORE_DRILL=1`,
`DEPLOY_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN=1` e
`DEPLOY_PRE_GO_LIVE_GITHUB_REMOTE=1` solo quando staging/VPS, Restic e GitHub
sono pronti.

Per ridurre errori manuali sulla VPS, usa l'orchestratore safe-by-default:

```sh
sh ./scripts/vps-go-live.sh --planOnly --repo OWNER/REPO
sh ./scripts/vps-go-live.sh --confirmLive --repo OWNER/REPO --start-stack
sh ./scripts/vps-go-live.sh --confirmLive --repo OWNER/REPO --bootstrap --apply-hardening --reload-sshd --full-evidence --start-stack
sh ./scripts/vps-go-live.sh --confirmLive --repo OWNER/REPO --apply-hardening --reload-sshd --replace-docker-daemon-config --full-evidence --start-stack
```

Senza `--confirmLive` scrive solo il piano in `reports/vps-go-live/`.
Con `--confirmLive` puo' eseguire bootstrap host, hardening, `vps-host-readiness
--enforce`, `vps-preflight`, opzionalmente `docker compose up`,
post-deploy, go/no-go, checklist live production-ready, `evidence-bundle` e
verifica integrita' bundle, fermandosi al primo errore e
lasciando un report JSON/Markdown non sensibile. Usa
`--reload-sshd` solo dopo aver verificato che la chiave SSH e la porta target
funzionano; senza questa prova il go/no-go non accetta l'hardening host come
production evidence. Usa
`--replace-docker-daemon-config` solo dopo aver rivisto il template Docker
generato quando una VPS esistente ha gia' `/etc/docker/daemon.json`.

Nel profilo VPS:

- Il WAF pubblica la porta 80; Traefik resta interno e riceve solo traffico filtrato.
- SSL, redirect HTTPS e CDN stanno all'edge esterno, per esempio VPS/Cloudflare.
- PostgreSQL, MariaDB, Redis, NATS, MinIO, Prometheus, Loki, Grafana, phpMyAdmin e dashboard Traefik non sono pubblici.
- Le app Node di piattaforma usano `UI_HOST`, `ACCOUNT_HOST`, `API_HOST` e `AUTH_HOST`; `PROJECTS_HOST` resta la dashboard locale del Control Center Node.
- I progetti PHP e Node condividono `PHP_PROJECTS_DIR` come sorgente universale. `PROJECTS_HOST` apre lo Stexor Control Center Node, `PHP_SOURCE_DIR` resta una root Apache neutra per il solo runtime PHP, `PROJECTS_WILDCARD_HOST_REGEXP` accetta i domini progetto, `PROJECT_HOST_SUFFIX` costruisce gli host e `NODE_PROJECT_UPSTREAMS` collega progetti Node a servizi Docker gia' avviati. Traefik espone i domini progetto tramite `local-projects`, che punta al `project-router` Node e non a un portale PHP. Il `project-router` prova PHP e Node contemporanei con `project-router-tests`; quando un progetto Node gestito viene disabilitato dal Control Center, il processo locale viene fermato e riparte solo alla riabilitazione.
- MariaDB usa `secrets/mariadb_root_password.txt` tramite Docker secret, non una password root in `.env`.
- `phpmyadmin` resta fuori dal profilo di default; su VPS pubblica usa preferibilmente SSH e client CLI, non una UI DB esposta.

### Produzione full con ACME

```sh
cd /opt/platform/platform-infrastructure
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
- `compose.vps.yaml`: overlay VPS prod-like dietro TLS esterno.
- `compose.waf.yaml`: overlay OWASP CRS/ModSecurity davanti a Traefik.
- `compose.vps-waf.yaml`: adattamento WAF per VPS con TLS/CDN esterno.
- `compose.backup-scheduler.yaml`: scheduler backup/restore drill container-first.
- `compose.build.yaml`: build immagini applicative.
- `traefik/traefik.edge-http.yml`: Traefik per edge TLS esterno.
- `scripts/*.sh`: entrypoint operativi Linux/Docker.
- `scripts/infra-ops.sh`: entrypoint container-first che non richiede Node sull'host.
- `scripts/infra-ops.mjs`: runner applicativo eseguito dentro il container ops.
- `docker/ops.Dockerfile`: immagine operativa con Node, Docker CLI e Compose plugin.
- `postgres/init/` e `postgres/migrations/`: schema e migrazioni.
- `RUNBOOK.md`, `SECURITY.md`, `THREAT-MODEL.md`, `ENTERPRISE-MATURITY.md`: governance operativa.
