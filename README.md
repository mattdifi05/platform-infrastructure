# Platform Infrastructure

Infrastruttura Docker self-hosted prod-like per Platform Infrastructure.
Questa repository rappresenta solo la piattaforma: runtime, Control Center,
documentazione, provider, monitoring, security, backup/restore, governance ed
evidence. Le applicazioni ospitate non vivono in questa repository e non sono
necessarie per far passare i gate della piattaforma.

Layout consigliato quando vuoi collegare sorgenti esterni:

```text
/opt/platform
|-- applications        # opzionale, fuori repo
`-- platform-infrastructure
```

Le applicazioni si collegano dopo tramite manifest esterni, immagini release o
cartelle sorgente dichiarate esplicitamente (`PROJECT_SOURCE_DIR`,
`PHP_PROJECTS_DIR`, manifest release). La discovery automatica dei progetti e'
disabilitata di default (`CONTROL_CENTER_DISCOVER_HOSTED_PROJECTS=false`) e il
portal deve funzionare anche con zero applicazioni.

## Platform vs Applications

Questa cartella copre solo infrastruttura e operazioni. Le Applications sono
risorse esterne collegate dal portal come metadati, manifest o sorgenti montati
in modo esplicito. `Projects` e `Applications` sono sezioni interne del portal,
non host DNS pubblici. Gli host pubblici finali della piattaforma sono:

- `portal.<domain>`: Infrastructure Portal / Control Center.
- `docs.<domain>`: documentazione operativa.
- `app.<domain>`: applicazione pubblica esterna quando collegata.
- `api.<domain>`: API pubblica.
- `auth.<domain>`: autenticazione.
- `storage.<domain>`: storage.
- `grafana.<domain>`: Grafana, solo quando protetto e verificato.

La classificazione aggiornata di Platform, Example, Fixture, Legacy e Hosted
Application e' in `PLATFORM-APPLICATION-SEPARATION-AUDIT.md`.

## Modello operativo corrente

Parti da `DOCUMENTATION-INDEX.md` per scegliere il documento giusto.
Il deep-dive completo e' `INFRASTRUCTURE-DEEP-DIVE.md`.
Il documento operativo corrente e' `CURRENT-OPERATING-MODEL.md`. Usali come
fonte pratica per:

- percorsi server correnti;
- overlay Compose prod-like;
- servizi, volumi e storage NVMe verificati;
- confine tra infrastruttura, Control Center e applicazioni ospitate;
- comandi sicuri di deploy e recreate mirato;
- stato GO/NO-GO live e prove ancora mancanti;
- checklist di migrazione verso un nuovo server.

Il runtime prod-like supportato e' Ubuntu LTS con Docker Engine sul server.
Mac e Windows sono client di sviluppo/Git/SSH/browser: non sono il runtime
autoritativo per deploy, readiness o prove production.

Questa repository documenta e valida l'infrastruttura. I progetti ospitati sono
workload esterni; fanno eccezione solo `control-center/`, che e' il pannello
operativo dell'infrastruttura. `project-router`, PHP Apache, Node e Static sono
capacita' di hosting della piattaforma, non proof funzionali dei progetti
esterni.

Terminologia canonica:

- **Infrastructure Portal**: nome prodotto della superficie operativa.
- **Control Center**: componente Node interno che serve Portal, docs e API
  `/control/*`.
- **`portal.<domain>`**: host pubblico del Portal.
- **`docs.<domain>`**: host pubblico della documentazione.
- **Admin identity plane**: metadata e policy per operatori del Control Center,
  Cloudflare Access, GitHub/VPS e audit amministrativo.
- **Account/passkey workload compatibility**: eventuali flussi utente di app
  ospitate; non sono gate GO/NO-GO dell'infrastruttura.
- **`backend`, `web`, `worker-*`**: nomi storici dei runtime/template generici
  della piattaforma. Non rappresentano applicazioni ospitate; quando vengono
  usati da sorgenti esterni, la sorgente resta fuori repo.

## Stack

- Traefik reverse proxy con file provider, senza Docker socket montato.
- PostgreSQL/MariaDB come servizi database gestiti e database collegati
  esplicitamente alle applicazioni ospitate.
- Redis per rate limit, cache/runtime state, heartbeat worker e uso applicativo
  opzionale.
- Keycloak, NATS JetStream, MinIO, Prometheus, node-exporter, cAdvisor, Grafana, Loki e Promtail.
- Runtime Node/PHP e worker generici, usati solo quando un'application esterna viene collegata tramite sorgente o immagini release esplicite.

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

`infra-secret-manager` mantiene uno store proprietario cifrato in `secrets/infra-secret-manager-store.json`, audit JSONL in `secrets/infra-secret-manager-audit.log` e materializza i file Docker secrets usati da `compose.secrets.yaml`. Lo store usa envelope KMS locale `local-bucket-kms` con KEK ruotabile. I runtime platform/generici leggono i secret da `/run/secrets/*`, inclusi `DATABASE_URL_FILE`, `SESSION_SECRET_FILE`, `SESSION_SIGNING_KEYS_FILE`, `PROJECTS_GATEWAY_SIGNING_KEYS_FILE`, `REDIS_PASSWORD_FILE`, `NATS_URL_FILE` e `SMTP_PASSWORD_FILE`.

Lo stesso manager funziona anche come secret vault locale per valori arbitrari non presenti nella whitelist platform. I nomi devono usare solo lettere minuscole, numeri e underscore. Esempio:

```sh
printf '%s\n' "$TOKEN" | sh ./scripts/infra-secret-manager.sh set --name github_token --stdin --owner github --minLength 40
sh ./scripts/infra-secret-manager.sh verify
```

I valori non vengono stampati: `status` mostra solo metadati, owner, scope e fingerprint. Le operazioni GitHub caricano automaticamente `secrets/github_token.txt` come `GITHUB_TOKEN` dentro il container ops quando il vault contiene `github_token` e la variabile non e' gia' impostata.

Il dev Docker e' volutamente production-like: usa `NODE_ENV=production`, immagini buildate, nessun hot reload, nessun bind mount implicito del sorgente esterno e nessuna porta host diretta per database/cache/app. Il traffico platform passa da Traefik solo su `portal` e `docs` nel profilo default.

`phpmyadmin` non parte nello stack default. Per manutenzione locale temporanea avvialo esplicitamente con il profilo `admin` e spegnilo a fine intervento:

```sh
docker compose --env-file .env -p platform_infra_local -f compose.yaml -f compose.build.yaml -f compose.secrets.yaml -f compose.waf.yaml --profile admin up -d phpmyadmin traefik waf
docker compose -f compose.yaml -f compose.secrets.yaml --env-file .env -p platform_infra_local stop phpmyadmin
```

## Operazioni container-first

Tutti i wrapper in `scripts/*.sh` delegano a `scripts/infra-ops.sh`, che avvia l'immagine Linux `platform/ops:local` e monta solo repo, eventuale sorgente esterno read-only e Docker socket. L'host non deve avere Node/PHP installati per backup, restore drill, health check, audit o deploy helper.

Per raggiungere i domini locali durante i check runtime, il runner usa `--network host` su Linux e mappa `*.localhost.com` a `host-gateway` su Docker Desktop. Se la tua installazione Docker richiede un target diverso, imposta `PLATFORM_LOCAL_HOST_TARGET`, ad esempio:

```sh
PLATFORM_LOCAL_HOST_TARGET=host.docker.internal sh ./scripts/infra-health.sh
```

## Stop, log e reset

```sh
docker compose -p platform_infra_local down
docker compose -p platform_infra_local logs -f
```

Non usare `docker compose down -v` su server live, reference server, VPS,
staging con dati reali o qualunque ambiente con volumi da preservare. La
rimozione di volumi e' una procedura distruttiva separata: richiede backup
verificato, rollback chiaro e conferma esplicita.

## URL locali

| Servizio | URL |
| --- | --- |
| Portal / Control Center | `https://portal.localhost.com` |
| Docs | `https://docs.localhost.com` |

Superficie HTTP consigliata:

- `portal.localhost.com`: pannello principale per gestire infrastruttura, provider, runtime, backup, sicurezza, observability, readiness e metadata Applications. E' il Control Center Node.
- `docs.localhost.com`: documentazione operativa organizzata. Serve solo file Markdown whitelisted dal repo, non espone il filesystem.
- `backend`, `web`, Keycloak, MinIO, Grafana e i tool DB admin restano servizi interni Docker. Non hanno route Traefik pubbliche nel profilo default/VPS/prod, salvo route operative esplicitamente documentate.
- `app.localhost.com`, `api.localhost.com`, `auth.localhost.com`, `storage.localhost.com` e `grafana.localhost.com`: nomi finali riservati a superfici live o applicazioni esterne, non pubblicati dal profilo platform default.
- `projects.localhost.com` e wildcard progetto: disabilitati nella route pubblica. La lista e enable/disable restano in `portal`.

`portal.localhost.com` serve l'Infrastructure Portal dal servizio Node `control-center`, separato da PHP Apache. Il componente e' il progetto Node `@platform/control-center` e usa un sistema visivo locale: componenti dichiarati in `control-center/components/ui/controlCenterUi.mjs`, token `--cc-*` e CSS in `control-center/styles/control-center.css`, servito da `/assets/control-center/control-center.css` ed esposto da `/control/ui-package`. Il Control Center non deve dipendere da applicazioni reali: con discovery disabilitata Applications puo' essere zero e la UI mostra `No applications attached.`. Quando `CONTROL_CENTER_DISCOVER_HOSTED_PROJECTS=true`, puo' leggere sorgenti esterni da `PHP_PROJECTS_DIR` per generare metadata locali, ma quei progetti non diventano parte della repository. Il Control Center espone la topologia Network Advanced da `/control/network` leggendo Compose e Traefik dynamic config in modalita' read-only, espone la mappa Monitoring Advanced da `/control/monitoring` leggendo Prometheus, Grafana, Loki e Alertmanager config senza query live, permette create metadata-only, enable/disable locale, update metadata, archive e soft delete solo nello stato Control Center, scrive stato in `projects-portal/state/*.json` e audit/operazioni in `projects-portal/state/*.jsonl`. `PHP_SOURCE_DIR` punta a `php-runtime-root`, una root statica neutra: PHP Apache resta solo runtime generico e non contiene la UI/API del Control Center. In locale `CONTROL_CENTER_AUTH_REQUIRED=false` mantiene il flusso rapido; in staging/VPS imposta `CONTROL_CENTER_AUTH_REQUIRED=true` e setta `CONTROL_CENTER_ADMIN_PASSWORD_SHA256` con lo SHA-256 della password admin. La sessione e' firmata con `projects_gateway_signing_keys` da Docker secret e il valore password non va mai in `.env`. `PROJECTS_HOST` resta solo alias legacy opzionale e non va configurato per nuove installazioni.
Advanced Mode espone lo scheletro delle aree enterprise richieste, inclusi Workers & Jobs, CI/CD & GitHub Governance, Logs/Alerts Advanced, Disaster Recovery, Release Evidence, Security Advanced e Billing / Plans. Queste superfici restano plan/evidence-only finche' un adapter esplicito non esegue apply e verifyRemote.
L'API Advanced read-only e' disponibile su `/control/advanced` e `/control/advanced/:section`; espone capability, guardrail ed evidence metadata senza chiamare provider live, senza toccare Docker e senza marcare evidenza production. `/control/readiness` legge i manifest `governance/enterprise-requirements.json` e `governance/production-readiness.json` montati read-only, pubblica una matrice repo/live-proof sanificata e mantiene `productionEvidence=false` finche' non passano le prove live.
Il registry adapter server-side e' disponibile su `/control/adapters` e `/control/adapters/:id`; include Cloudflare, Traefik, Docker, GitHub, Prometheus, Loki, Alertmanager, Backup, Restore, MinIO, Database, Security e Go/No-Go. `/control/adapters/:id/plan` e `/verify` producono piani auditati, mentre `/apply` viene respinto finche' non esiste un adapter live esplicito con conferma forte e verifyRemote.

La pagina `Stato` del Control Center e' un cruscotto operativo GO/NO-GO della
piattaforma, non un report sulla qualita' interna del Control Center. Il
pulsante `Avvia test reali` esegue solo controlli read-only e non distruttivi:
percorso Portal attraverso WAF, blocco file sensibili, lettura report go/no-go,
decisione produzione e matrice readiness. I test solo-Control Center, come UI
contract, simple/advanced mode, `__health` interno o asset CSS, restano coperti
dai test codice e non compaiono nello stato production. Le prove classificate
come `pending-live-proof` o `pending-provider` richiedono evidence esterna reale
quando riguardano dominio pubblico, Cloudflare, uptime provider, benchmark
pubblico, off-site restore o GitHub/Sigstore provenance: un server Ubuntu in LAN
puo' prepararle, ma non puo' renderle vere production evidence da solo.

Lettura sintetica:

```text
Platform readiness: GO per repository e runtime Ubuntu corrente.
Enterprise requirements: GO per copertura repo/tooling.
Production go-live: NO-GO finche' mancano prove live/provider esterne.
```

Alertmanager resta interno alla rete Docker. Prometheus invia gli alert ad Alertmanager, che li inoltra al worker notifiche su `/alerts/prometheus` con token Bearer da Docker secret; il worker produce log Loki, metriche `notification_alert_*`, email reali verso `ALERT_EMAIL_TO` quando SMTP e' configurato, e canali opzionali Discord/Telegram tramite secret file. `node-exporter` e `cadvisor` forniscono metriche CPU, RAM, disco e container per alert operativi.

I log sono centralizzati via Promtail senza montare `docker.sock`: Promtail legge i log JSON bounded dei container, applica una redaction pipeline su header, token, cookie, OTP e segreti, e promuove `service` e `level` a label Loki per query operative. `backend` e `worker-*` sono runtime/template platform che usano la policy condivisa `@platform/observability`; gli eventi critici restano anche su audit DB append-only/outbox.

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
mkcert -cert-file ./traefik/certs/local-cert.pem -key-file ./traefik/certs/local-key.pem localhost 127.0.0.1 ::1 portal.localhost.com docs.localhost.com
docker compose -f compose.yaml -f compose.build.yaml --env-file .env -p platform_infra_local up -d --build traefik
curl https://portal.localhost.com/__health
```

Su Windows, apri PowerShell come amministratore e aggiungi gli host locali:

```powershell
Add-Content -Path "$env:SystemRoot\System32\drivers\etc\hosts" -Value "127.0.0.1 portal.localhost.com docs.localhost.com"
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

Baseline WAF: CRS paranoia level 2, blocking mode attivo, audit log `RelevantOnly`, request body inspection attiva, response body inspection spenta, file sensibili e scanner path bloccati prima del routing verso runtime o app collegate. PL3/PL4 vanno attivati solo dopo una finestra di tuning sui log, altrimenti il rischio falso positivo diventa alto per dashboard, OAuth e form PHP.

Su Windows/Docker Desktop il certificato mkcert locale e' montato in un container non privilegiato. Se il WAF non riesce a leggere `local-key.pem`, rendi la copia locale leggibile dal runtime Docker e riavvia:

```powershell
docker run --rm --entrypoint sh -u root -v "${PWD}\traefik\certs\local-key.pem:/tmp/server.key" owasp/modsecurity-crs:4.26.0-nginx-202605200705 -c "chmod 0644 /tmp/server.key"
docker compose --env-file .env -p platform_infra_local -f compose.yaml -f compose.build.yaml -f compose.secrets.yaml -f compose.waf.yaml up -d waf
```

## Database gestiti

PostgreSQL e MariaDB sono servizi gestiti dalla piattaforma hosting. Il GO/NO-GO
infrastrutturale verifica disponibilita', backup, restore, retention,
isolamento, admin tooling e prove DR/off-site; non verifica schema o business
logic delle applicazioni ospitate.

`postgres/init/`, `postgres/migrations/` e lo schema storico `app_account` sono
compatibilita' legacy per workload applicativi che espongono un layer account o
audit. Se un'app esterna li usa, la sua procedura di migrazione deve vivere nel
runbook dell'app e deve essere eseguita come passo workload separato. Non usare
migration applicative per promuovere la piattaforma hosting a GO-LIVE.

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

Gate infrastrutturale canonico:

```sh
cd /opt/platform/platform-infrastructure
sh ./scripts/infra-ops.sh enterprise-requirements-check
sh ./scripts/infra-ops.sh enterprise-requirements-check --manifest governance/production-readiness.json
```

Se lavori in un vecchio monorepo applicativo puoi trovare ancora riferimenti a
`/opt/platform/src` e `pnpm enterprise:check`; sono compatibilita' legacy e non
sono necessari per validare questa repository infrastrutturale.

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
sh ./scripts/platform-admin-audit.sh
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

`secret-rotation-evidence.sh` scrive un report non-secret in `reports/secret-rotation/` con stato dello store Infra Secret Manager, audit log, KMS attivo, eta' dei secret rispetto a `rotationDays`, file materializzati, secret vault e risultato di `infra-secret-manager verify`. In produzione usa `--enforce`: il go/no-go accetta solo `mode=evidence`, `status=passed`, zero secret scaduti e zero file mancanti.

`compose-healthcheck-coverage` renderizza gli stack local WAF, VPS WAF e backup scheduler, poi scrive `reports/healthchecks/healthcheck-coverage-*.json`/`.md`. Fallisce se un servizio operativo del render Compose non ha una healthcheck.

`rate-limit-evidence.sh` scrive un report in `reports/rate-limits/` che verifica il rate limit Traefik, i router local/VPS e i budget dei runtime platform generici. Eventuali prove applicative montate da sorgenti esterni sono compatibilita' workload e non cambiano il GO/NO-GO dell'infrastruttura.

`audit-log-evidence.sh` scrive un report in `reports/audit-logs/` che verifica audit amministrativo, outbox durevole, dead-letter, alert Prometheus e dashboard Grafana. Eventuali audit table dei workload ospitati restano fuori dai gate platform.

`retention-evidence.sh` scrive un report in `reports/retention/` che verifica logging Docker bounded, retention Loki/Promtail, retention TSDB Prometheus, datasource/pannelli Grafana e, quando il sorgente runtime e' montato, anche log JSON strutturati e redazione dei campi sensibili. In CI resta infra-only se il sorgente esterno non e' presente.

`load-benchmark.sh` senza `--url` misura il backend dentro la rete Docker ed e' utile per regressioni locali. Per il go-live devi usare l'URL pubblico e `--requirePublicTarget`; con Cloudflare CDN attivo aggiungi `--requireEdgeEvidence --expectedEdgeProvider cloudflare`. Il report in `reports/load/` include profili 50/100/500, snapshot CPU/RAM Docker, target evidence pubblico/edge e `status`. Anche i fallimenti scrivono report diagnostici, ma il go/no-go accetta solo `status=passed`.

Le vecchie suite account/passkey e le migration account sono compatibilita'
workload. Non fanno parte dei gate GO/NO-GO della piattaforma hosting e non
devono essere usate come evidence per promuovere `platform-infrastructure`.

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
`GITHUB_TOKEN=... sh ./scripts/github-actions-run-evidence.sh --repo OWNER/REPO --workflow enterprise-infra.yml --branch main --sha <release-sha> --verifyRemote`;
il report finisce in `reports/github-actions/` e deve avere `status=passed` e
`run.conclusion=success`. La workflow `enterprise-infra-run-evidence` produce
automaticamente la stessa evidenza dopo ogni completamento di `enterprise-infra`
su `main` e carica `reports/github-actions/` come artifact non-secret. La CI dell'infra non esegue checkout di repository progetto:
collega i repository applicativi solo tramite `PROJECT_SOURCE_DIR` quando devi buildarli.
La workflow `release-attestation` usa GitHub Artifact Attestations/Sigstore
ufficiale, OIDC (`id-token: write`) e GHCR (`packages: write`) per produrre
provenance firmata senza dominio reale:

```sh
gh workflow run release-attestation.yml --repo mattdifi05/platform-infrastructure --ref main
gh run watch --repo mattdifi05/platform-infrastructure
gh run download --repo mattdifi05/platform-infrastructure --name github-sigstore-release-evidence --dir .tmp/github-sigstore-release-evidence
```

Per una release applicativa completa, dichiara le immagini in un manifest come
`config/project-manifest.example.json` e passa `--imageManifest <file>` ai gate
release. Ogni immagine deve essere digest-pinned e avere un report verificato da
`gh attestation verify` che copre il relativo digest. I vecchi env
`BACKEND_IMAGE`, `WEB_IMAGE` e `WORKER_*_IMAGE` restano fallback compatibile. La
provenance locale SLSA resta accettata come evidenza parziale; il go/no-go
richiede `github-signed-attestation` completa.
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
Markdown in `reports/go-live/` con `status`, `missingOptions`, `issues` e
`pendingLiveProofs`, aggrega gate locali e dry-run provider, e segnala cio' che
resta da provare su VPS/Cloudflare/GitHub live. Su staging o VPS puoi aggiungere
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
report `no-go` include anche `summary`, `blockingRequired`,
`pendingRequired`, `remediation` in JSON e una sezione Markdown con azioni,
comandi ed evidenza attesa. I blocchi risolvibili nel repository restano
`failed`; DNS/HTTPS pubblici, Cloudflare, uptime provider, benchmark pubblico,
off-site restore e attestazioni GitHub live restano `pending-live-proof` oppure
`pending-provider` finche' non esiste evidenza reale.
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
gh workflow run release-attestation.yml --repo OWNER/REPO --ref main
sh ./scripts/release-evidence.sh --requireProvenance --imageManifest .tmp/release-attestation/release-subjects.json --sbom reports/release/github-release-sbom-<run-id>.cdx.json --githubAttestation reports/release/github-sigstore-attestation-<stamp>.json --previousImagesFile ./release/previous-images.json
```

  Il workflow `release-attestation.yml` usa GitHub Artifact Attestations/Sigstore, builda l'immagine infra PHP Apache su GHCR, abilita SBOM BuildKit, firma anche `release-subjects.json` e carica artifact non sensibili. Per release multi-immagine passa `release_images_json` con riferimenti gia' digest-pinned: il manifest firmato viene usato dal gate per coprire tutti i subject dichiarati. Il comando valida immagini digest-pinned, SBOM, provenance opzionale, firma opzionale con `--verifyCosign`, scrive report in `reports/release/` con `status`/`issues` e, quando riceve i digest precedenti, produce `release/previous-images.json`. `--provenance` accetta una statement/bundle DSSE in-toto SLSA v1 come evidenza locale parziale; `--githubAttestation` accetta uno o piu' report GitHub/Sigstore normalizzati e verificati. Per essere completa, la GitHub attestation deve risultare `verified=true`, indicare repository, workflow run id, commit SHA, subject name e subject digest, e coprire ogni digest immagine della release. In evidence mode esegue anche la dry-run di rollback non distruttiva, valida `docker compose config` con i digest precedenti e collega il report `reports/rollback/rollback-plan-*.json` dentro l'evidence pack della release. I fallimenti scrivono comunque report diagnostici, ma il go/no-go accetta solo `status=passed` con `github-signed-attestation` completa.

## Produzione

### VPS hardening e Cloudflare origin-lock

Prima del deploy pubblico su VPS/Ubuntu LTS:

```sh
sudo sh ./scripts/vps-bootstrap-ubuntu.sh --apply --deploy-user deploy
sudo sh ./scripts/vps-hardening-ubuntu.sh --apply --ssh-port 65002 --reload-sshd
sudo sh ./scripts/vps-host-readiness.sh --ssh-port 65002 --enforce
sudo sh ./scripts/cloudflare-origin-lock-ufw.sh --apply --ports "80"
```

Per il server home-VPS/LAN attuale non cambiare porta SSH: usa la stessa
procedura con `--ssh-port 22` dopo aver confermato l'accesso con chiave.

```sh
sudo sh ./scripts/vps-hardening-ubuntu.sh --apply --ssh-port 22 --reload-sshd
sh ./scripts/vps-host-readiness.sh --ssh-port 22 --enforce
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

Lo script scrive l'hardening SSH in
`/etc/ssh/sshd_config.d/01-platform-hardening.conf`, prima dei frammenti
cloud-init come `50-cloud-init.conf`. La verifica accettata e' l'output
effettivo di `sshd -T`: deve mostrare `passwordauthentication no`, non basta che
un file contenga `PasswordAuthentication no`.

Se Cloudflare parla con l'origin anche su 443, usa `--ports "80 443"`. Dopo aver verificato DNS proxied e traffico Cloudflare, rimuovi eventuali vecchie regole UFW generiche `allow 80/tcp` e `allow 443/tcp`: l'origin non deve accettare bypass diretti.
`vps-host-readiness.sh --ssh-port 65002 --enforce` genera report JSON/Markdown in `reports/vps-host/` e
verifica Ubuntu LTS, Docker Engine, Compose plugin, Git, UFW, fail2ban, SSH
hardening, porta SSH attesa, regola UFW per quella porta, Docker daemon
hardening, auditd/AppArmor, risorse minime e runtime host non necessari. Ogni
check include anche una remediation operativa, cosi' il report fallito diventa
la checklist correttiva da applicare sulla VPS.
Per il server home-VPS/LAN corrente il comando di readiness e'
`vps-host-readiness.sh --ssh-port 22 --enforce` finche' una modifica separata
della porta SSH non viene approvata e testata.
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

Sul reference server corrente il path operativo e'
`/home/platform_infrastructure/platform-infrastructure` e il runtime usa anche
un override locale `.tmp/vps-runtime-override.yaml` per collegare sorgenti e
runtime dedicati. Quell'override e' stato-specifico: per nuovi server ricrea lo
stesso intento in modo revisionato invece di copiarlo alla cieca.

```sh
cd /home/platform_infrastructure/platform-infrastructure
docker compose -p platform_infra_vps \
  -f compose.yaml \
  -f compose.build.yaml \
  -f compose.secrets.yaml \
  -f compose.vps.yaml \
  -f compose.waf.yaml \
  -f compose.vps-waf.yaml \
  -f .tmp/vps-runtime-override.yaml \
  ps
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

Per il server home-VPS/LAN senza DNS pubblico, mantieni i valori production in
`.env` e punta i client/operatori ai nomi canonici tramite DNS locale o
`/etc/hosts`. Gli override sotto validano il runtime LAN senza introdurre host
temporanei: i gate production pubblici restano NO-GO finche' DNS, CDN e TLS
provider non sono verificati.

```sh
DEPLOY_PORTAL_BASE=http://portal.platform-infrastructure.com \
DEPLOY_DOCS_BASE=http://docs.platform-infrastructure.com \
DEPLOY_APP_BASE=http://app.platform-infrastructure.com \
DEPLOY_API_BASE=http://api.platform-infrastructure.com \
DEPLOY_AUTH_BASE=http://auth.platform-infrastructure.com \
DEPLOY_AUTH_ORIGIN=https://auth.platform-infrastructure.com \
DEPLOY_GRAFANA_BASE=http://grafana.platform-infrastructure.com/login \
DEPLOY_GRAFANA_BLOCKED=1 \
DEPLOY_ADMIN_SCHEME=http \
DEPLOY_ALLOW_HTTP_NO_HSTS=1 \
DEPLOY_RUN_PRE_GO_LIVE=1 \
DEPLOY_PRE_GO_LIVE_PRODUCTION_PREFLIGHT=0 \
DEPLOY_REPO=OWNER/REPO \
sh ./scripts/vps-postdeploy.sh .env
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
- `CONTROL_CENTER_HOST` apre il portal Node e `DOCS_HOST` apre la documentazione operativa. Sono le sole route pubbliche previste.
- I progetti PHP e Node condividono `PHP_PROJECTS_DIR` come sorgente universale. `PROJECTS_HOST` resta solo alias legacy e deve restare vuoto nelle nuove installazioni, `PROJECTS_WILDCARD_HOST_REGEXP` resta vuoto di default e Traefik non espone wildcard progetto. Il `project-router` resta disponibile come servizio interno e continua a essere coperto da `project-router-tests`.
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
- Le immagini runtime o dei workload collegati devono essere versionate e pin-nate con digest.
- `.localhost.com` non e' valido per ACME pubblico: servono domini DNS reali.

Build immagini runtime/template:

```sh
docker compose -f compose.yaml -f compose.build.yaml --env-file .env build
```

Le variabili pubbliche dei runtime web collegati, inclusi eventuali
`NEXT_PUBLIC_*`, vengono passate come build args solo quando un workload esterno
richiede una build. Questo non e' un requisito per validare la piattaforma
hosting senza applicazioni collegate.

## Hosted Workload Auth Compatibility

Questa sezione descrive compatibilita' per workload applicativi esterni, non
requisiti della piattaforma:

- Sessioni firmate lato server in cookie `HttpOnly`, `Secure`, `SameSite=Lax`.
- API mutative protette da Origin/Fetch Metadata.
- Passkey, OTP email, backup codes e revoca sessioni possono usare PostgreSQL e
  Redis quando l'app li implementa.

La piattaforma hosting deve esporre runtime, database, Redis, proxy, WAF,
backup, observability e deployment sicuri. I flussi utente specifici restano
fuori dal GO/NO-GO infra.

## File principali

- `compose.yaml`: stack local/dev production-like.
- `compose.secrets.yaml`: overlay Docker secrets file-based.
- `compose.prod.yaml`: overlay produzione.
- `compose.vps.yaml`: overlay VPS prod-like dietro TLS esterno.
- `compose.waf.yaml`: overlay OWASP CRS/ModSecurity davanti a Traefik.
- `compose.vps-waf.yaml`: adattamento WAF per VPS con TLS/CDN esterno.
- `compose.backup-scheduler.yaml`: scheduler backup/restore drill container-first.
- `compose.build.yaml`: build immagini runtime/template.
- `traefik/traefik.edge-http.yml`: Traefik per edge TLS esterno.
- `scripts/*.sh`: entrypoint operativi Linux/Docker.
- `scripts/infra-ops.sh`: entrypoint container-first che non richiede Node sull'host.
- `scripts/infra-ops.mjs`: runner operativo eseguito dentro il container ops.
- `docker/ops.Dockerfile`: immagine operativa con Node, Docker CLI e Compose plugin.
- `postgres/init/` e `postgres/migrations/`: bootstrap DB e compatibilita'
  workload legacy; non sono gate GO/NO-GO infra.
- `RUNBOOK.md`, `SECURITY.md`, `THREAT-MODEL.md`, `ENTERPRISE-MATURITY.md`: governance operativa.
