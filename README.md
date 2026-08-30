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
- **Hosted workload**: applicazione esterna con manifest, Compose overlay,
  immagini, environment non-secret e migrazioni posseduti dalla repository
  applicativa. Account, passkey e business worker appartengono a questo scope.
- **Platform service**: componente necessario anche con zero workload collegati,
  per esempio Traefik, WAF, Control Center, project-router, database condivisi,
  backup scheduler, observability e `platform-alert-dispatcher`.

## Stack

- Traefik reverse proxy con file provider, senza Docker socket montato.
- PostgreSQL/MariaDB come servizi database gestiti e database collegati
  esplicitamente alle applicazioni ospitate.
- Redis per rate limit, cache/runtime state, heartbeat worker e uso applicativo
  opzionale.
- Keycloak, NATS JetStream, MinIO, Prometheus, node-exporter, cAdvisor, Grafana, Loki e Promtail.
- Runtime Node/PHP/Static collegati soltanto tramite un contratto workload
  esterno verificato; nessun backend, frontend o worker applicativo e' core.

I container usano prefisso `enterprise-`, network `enterprise_net` e volumi `enterprise_*`.

## Contratto workload esterno

Il core si renderizza e passa i gate con zero applicazioni. Per collegare un
workload, la repository applicativa fornisce un manifest, un overlay Compose
image-only, un environment non-secret ignorato da Git e le proprie migrazioni.
La preparazione non e' un comando portabile da eseguire con `.env.vps`. Il
protocollo Hosted legacy/greenfield installa sul target l'environment root-owned
`0640`, prepara il lock target-local e successivamente emette runtime intent,
admission e release context v3. Questa terminologia non definisce l'ordine V1
brownfield. Per un host esistente la Phase A approvata e' esclusivamente una
autorizzazione provider read-only precedente al preflight; installazione,
preparazione del lock e receipt target-root appartengono alla Phase B e sono
vietate finche' preflight e backup PRE-DEPLOY non risultano verificati. L'ordine
completo e' fissato in `V1-BROWNFIELD-DEPLOYMENT.md`. Entrambe le fasi restano
`EXTERNAL-PENDING`; questo checkout non costituisce un sostituto del provider e
non offre un percorso production manuale equivalente.

La preparazione valida digest immutabili, nomi, route, secret dichiarati,
network e budget, confronta render core e combinato e scrive un lock `0600` con
SHA-256 di ogni input. Lock e snapshot content-addressed devono stare nello
stesso parent deployment-owned `0700`, fuori da `projects-portal/state`; il
resolver crea e finalizza gli snapshot con operazioni descriptor-relative
`openat`/`O_NOFOLLOW`. Il deploy copia il lock su un inode privato subito
unlinkato, valida quei byte in memoria e ricava core, progetto, Compose ed
environment da un unico bundle digest-bound. Consegna poi copie
digest-verificate di Compose/environment tramite file descriptor persistenti,
senza riaprire i pathname workload dopo la verifica; il router riceve soltanto
il lock in read-only. L'identita' Unix che prepara ed esegue il deploy resta una
trust boundary amministrativa e non deve essere condivisa con servizi workload.
Il runtime richiede `HOSTED_WORKLOAD_MODE=hosted` con un lock non vuoto; lo
stato senza workload richiede invece `HOSTED_WORKLOAD_MODE=no-hosted`, lock
vuoto e il lock canonico `config/no-hosted-workloads.lock.json`.
Non crea database, non applica migrazioni e non avvia container. La verifica
locale del lock procede soltanto dopo che `ops-image-trust.sh` ha verificato
policy repository-owned, receipt artifact/deployment, metadata del run
provider, release immutabile autenticata dall'archivio sorgente (oppure un
checkout Git locale pulito ed esatto), digest dell'immagine ops e relativo
image ID locale. Il runner viene
eseguito tramite quell'ID con `--pull=never`; non esiste un fallback locale,
auto-build o host-Node. Il deploy usa soltanto un lock `verified`; se il
producer non e' configurato o un input cambia, fallisce chiuso finche' il lock
non viene rigenerato e approvato. La policy versionata in questa baseline resta
`EXTERNAL-PENDING`: finche' il provider non fornisce autorizzazione e receipt
firmate di Phase A e prova di preservazione target-local, il percorso Hosted
production si arresta prima di eseguire il container ops.

Il deploy approvato proietta su ogni container core una tupla runtime completa
tramite `compose.runtime-identity.yaml`: ID candidato FG-048, commit, tree,
deployment ID, digest del render canonico e digest del workload lock. I sei
valori devono essere presenti insieme e in formato esatto; un workload esterno
deve proiettare le stesse label sui propri servizi. Il fingerprint rifiuta un
servizio senza label, un container precedente all'evento di deploy o una tupla
mista.

Ogni route del manifest dichiara `slug`, host DNS canonico esatto, eventuali
alias e porta. Il validatore assegna route e alias a un solo workload, rifiuta
collisioni globali di slug, host e upstream (incluse le superfici riservate del
core) e scrive nel lock la tupla completa di ownership. In produzione il
`project-router` accetta esclusivamente queste tuple verificate: discovery dal
filesystem, wildcard e mappe upstream da environment sono disponibili soltanto
nei test che abilitano esplicitamente la compatibilita' legacy.

Un servizio workload che entra nella zona `cache` o `bus` deve inoltre firmare
nel manifest la propria policy broker completa. Il lock lega digest, username,
secret esterno, prefissi Redis, account e utenti NATS per servizio, subject,
queue e response policy. I valori delle credenziali non entrano mai nel
manifest o nel lock. Collisioni, prefissi Redis sovrapposti, comandi ampliati,
subject globali, credenziali condivise ed export/import NATS non approvati fanno
fallire il render prima dell'attivazione.

Prima dell'avvio, il servizio isolato `broker-auth-bootstrap` legge il lock
verificato e i soli secret esterni dichiarati, quindi genera fuori dal repository
un file ACL Redis `0600`: l'utente `default` e' disabilitato, ogni workload ha
un utente e una password indipendenti, e puo' usare soltanto i propri prefissi
di chiavi/canali con l'allowlist di comandi firmata nel lock. Redis parte solo
dopo il completamento riuscito del bootstrap. Le prove di comportamento sul
broker reale (cross-tenant, rotazione, persistenza e restart) restano un gate
runtime obbligatorio prima del deploy.

Lo stesso bootstrap genera un `nats-server.conf` `0600`, con un account distinto
per workload e un utente distinto per ogni ruolo di servizio. Publish, subscribe,
queue group, reply limit e deny `$SYS.>`/`$JS.>` derivano soltanto dalla policy
firmata; non esiste piu' un `--user`/`--pass` globale e gli export/import restano
chiusi finche' non esiste un'approvazione direzionale esatta. Redis e NATS
verificano il digest del proprio file prima di avviarsi. Le rotazioni diventano
effettive solo tramite una nuova attivazione ammessa dal broker root-owned;
`compose-vps.sh` resta un entrypoint di verifica read-only.
La matrice reale di pub/sub/queue, persistenza, restart e rotazione resta un gate
runtime obbligatorio.

## Avvio locale

```sh
cd /opt/platform/platform-infrastructure
cp .env.example .env
docker compose -f compose.yaml --env-file .env -p platform_infra_local up -d --build
```

Avvio consigliato con Infra Secret Manager e Docker secrets file-based:

```sh
cd /opt/platform/platform-infrastructure
cp .env.example .env
sh ./scripts/infra-secret-manager.sh init
docker compose -f compose.yaml -f compose.secrets.yaml --env-file .env -p platform_infra_local up -d --build
```

`infra-secret-manager` mantiene uno store proprietario cifrato in `secrets/infra-secret-manager-store.json`, audit JSONL in `secrets/infra-secret-manager-audit.log` e materializza i file Docker secrets usati da `compose.secrets.yaml`. Lo store usa envelope KMS locale `local-bucket-kms` con KEK ruotabile. I servizi core leggono solo i secret platform da `/run/secrets/*`. I secret applicativi non sono richiesti dal core: vengono dichiarati nel manifest del workload e devono esistere nel backend prima della preparazione del relativo lock.

Lo store non persiste fingerprint derivati dal plaintext. Gli store legacy devono essere riscritti con `sh ./scripts/infra-secret-manager.sh migrate-metadata` prima di `verify` o del backup metadata; il comando conserva `updatedAt` confrontando i valori decifrati soltanto in memoria.

Lo stesso manager funziona anche come secret vault locale per valori arbitrari non presenti nella whitelist platform. I nomi devono usare solo lettere minuscole, numeri e underscore. Esempio:

```sh
printf '%s\n' "$TOKEN" | sh ./scripts/infra-secret-manager.sh set --name github_token --stdin --owner github --minLength 40
sh ./scripts/infra-secret-manager.sh verify
```

I valori non vengono stampati: `status` mostra solo metadati, owner, scope e fingerprint. Le operazioni GitHub caricano automaticamente `secrets/github_token.txt` come `GITHUB_TOKEN` dentro il container ops quando il vault contiene `github_token` e la variabile non e' gia' impostata.

Il dev Docker e' volutamente production-like: usa `NODE_ENV=production`, immagini buildate, nessun hot reload, nessun bind mount implicito del sorgente esterno e nessuna porta host diretta per database/cache/app. Il traffico platform passa da Traefik solo su `portal` e `docs` nel profilo default.

`phpmyadmin` non parte nello stack default. Per manutenzione locale temporanea avvialo esplicitamente con il profilo `admin` e spegnilo a fine intervento:

```sh
docker compose --env-file .env -p platform_infra_local -f compose.yaml -f compose.secrets.yaml -f compose.waf.yaml --profile admin up -d phpmyadmin traefik waf
docker compose -f compose.yaml -f compose.secrets.yaml --env-file .env -p platform_infra_local stop phpmyadmin
```

## Operazioni privilegiate fail-closed

`scripts/infra-ops.sh` non costruisce immagini, non accetta label locali e non
espone un bypass host-Node. Il percorso positivo richiede un producer trusted
con repo, workflow, revisione, ref `main`, run/attempt provider autenticati e
receipt legate al checkout pulito ed esatto. Esegue poi esclusivamente l'image
ID locale ammesso con `--pull=never`. Finche'
`governance/deployment-admission.json` resta `EXTERNAL-PENDING`, il wrapper
termina con codice 78. I job CI non privilegiati eseguono direttamente il
modulo Node dal checkout esatto; questo non abilita operazioni VPS o una
receipt production.

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

`portal.localhost.com` serve l'Infrastructure Portal dal servizio Node `control-center`, separato da PHP Apache. Il componente e' il progetto Node `@platform/control-center` e usa un sistema visivo locale: componenti dichiarati in `control-center/components/ui/controlCenterUi.mjs`, icone self-hosted in `control-center/components/ui/controlIcons.mjs`, token `--cc-*` e CSS in `control-center/styles/control-center.css`, servito da `/assets/control-center/control-center.css` ed esposto da `/control/ui-package`. Il Control Center non deve dipendere da applicazioni reali: con discovery disabilitata Applications puo' essere zero e la UI mostra `No applications attached.`. Quando `CONTROL_CENTER_DISCOVER_HOSTED_PROJECTS=true`, puo' leggere sorgenti esterni da `PHP_PROJECTS_DIR` per generare metadata locali, ma quei progetti non diventano parte della repository. Il Control Center espone la topologia Network Advanced da `/control/network` leggendo Compose e Traefik dynamic config in modalita' read-only, espone la mappa Monitoring Advanced da `/control/monitoring` leggendo Prometheus, Grafana, Loki e Alertmanager config senza query live, permette create metadata-only, enable/disable locale, update metadata, archive e soft delete solo nello stato Control Center. Lo state adapter in `control-center/state/` conserva i formati JSON/JSONL esistenti con letture strict, write atomiche private, lock, revisioni e snapshot rollback; resta un design single-writer e non e' HA. Database distruttivi, principal e Vault mantengono store specializzati. L'API versionata e' `/control/v1/*`; `/control/*` resta alias compatibile. `PHP_SOURCE_DIR` punta a `php-runtime-root`, una root statica neutra: PHP Apache resta solo runtime generico e non contiene la UI/API del Control Center. L'accesso amministrativo e' sempre fail-closed: il V1 usa direttamente WebAuthn verificato da SimpleWebAuthn con credenziali e sessioni nel PostgreSQL `control_auth`; `oidc-passkey` resta solo una modalita' compatibilita' esplicita. Non esiste login locale con password. La sola modalita' senza auth e' `test-disabled`, accettata esclusivamente con `NODE_ENV=test` e bind loopback. `PROJECTS_HOST` resta solo alias legacy opzionale e non va configurato per nuove installazioni. Dettagli e procedura candidata: `control-center/CONTROL-CENTER-CORE.md` e `control-center/STATE-STORE-MIGRATION.md`.
Advanced Mode espone lo scheletro delle aree enterprise richieste, inclusi Workers & Jobs, CI/CD & GitHub Governance, Logs/Alerts Advanced, Disaster Recovery, Release Evidence, Security Advanced e Billing / Plans. Queste superfici restano plan/evidence-only finche' un adapter esplicito non esegue apply e verifyRemote.
L'API Advanced read-only e' disponibile su `/control/advanced` e `/control/advanced/:section`; espone capability, guardrail ed evidence metadata senza chiamare provider live, senza toccare Docker e senza marcare evidenza production. `/control/readiness` legge i manifest `governance/enterprise-requirements.json` e `governance/production-readiness.json` montati read-only, pubblica una matrice repo/live-proof sanificata e mantiene `productionEvidence=false` finche' non passano le prove live.
Il registry adapter server-side e' disponibile su `/control/adapters` e `/control/adapters/:id`; include Cloudflare, Traefik, Docker, GitHub, Prometheus, Loki, Alertmanager, Backup, Restore, MinIO, Database, Security e Go/No-Go. `/control/adapters/:id/plan` e `/verify` producono piani auditati, mentre `/apply` viene respinto finche' non esiste un adapter live esplicito con conferma forte e verifyRemote.

La pagina `Stato` del Control Center e' un cruscotto operativo GO/NO-GO della
piattaforma, non un report sulla qualita' interna del Control Center. Il
pulsante di esecuzione usa un catalogo tipizzato per tutti i controlli della
selezione. Ogni risultato dichiara se e' una probe reale, una rivalidazione di
evidence o un requisito esterno; gli snapshot non sono piu' presentati come
test reali. Gli eventi ordinati `run-started`, `check-started`,
`check-completed` e `run-completed` sono disponibili da
`/control/v1/status/events`. I test solo-Control Center, come UI contract,
`__health` interno o asset CSS, restano coperti dai test codice e non compaiono
nello stato production. Le prove classificate
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

Alertmanager resta interno alla rete Docker. Prometheus invia gli alert ad
Alertmanager, che li inoltra a `platform-alert-dispatcher` su
`/alerts/prometheus` con token Bearer da Docker secret; il token e'
materializzato `0640` e condiviso solo tramite `ALERTMANAGER_SECRET_GID`.
L'healthcheck richiede sia `/-/ready` sia la leggibilita' del token. Il
dispatcher produce log Loki, metriche `platform_alert_*`, email reali verso
`ALERT_EMAIL_TO` e un forward webhook opzionale da secret file.
`alert-evidence --sendTest` entra dall'API Alertmanager e richiede un receipt
correlato downstream: non chiama direttamente il dispatcher. `node-exporter`
fornisce le metriche host e legge le serie workload generate dal collector
host-side `platform-container-metrics.service`. Il collector riconcilia
`docker ps`, `docker stats` e i soli campi non-secret necessari di
`docker inspect`, conserva gli zero reali, espone i limiti cgroup effettivi e
fallisce se manca un container in esecuzione. cAdvisor resta una scrape di
compatibilita', ma il suo healthcheck non e' prova di copertura workload. Vedi
`WORKLOAD-METRICS.md`.

I log sono centralizzati via Promtail senza montare `docker.sock`: Promtail
legge i log JSON bounded dei container, applica una redaction pipeline su
header, token, cookie, OTP e segreti, e promuove `service` e `level` a label
Loki per query operative. I workload esterni devono emettere log compatibili,
ma i loro audit e outbox restano app-owned e fuori dai gate platform.

Prometheus, Alertmanager e la dashboard Traefik non hanno route browser locali: restano interni alla rete Docker. Usa Grafana, protetto da login, come superficie browser per metriche, alert e log.

Per email production configura SMTP nel Secret Manager, imposta
`ALERT_EMAIL_TO`, `MAILER_FROM`, `MAILER_REPLY_TO`, `SMTP_HOST`, `SMTP_PORT` e
`SMTP_USER`, poi pubblica e verifica SPF, DKIM e DMARC per il dominio mittente.
Il gate si chiude solo con `alert-evidence --sendTest --requireEmailDelivery`
contro il destinatario reale; la sola presenza delle variabili non e' prova di
consegna.

Il monitoraggio esterno e' definito in `monitoring/external-uptime.example.json`: include health pubbliche, discovery OIDC e controlli negativi sugli host admin che devono restare bloccati. Prima di configurare BetterStack, UptimeRobot o Cloudflare Health Checks, valida il manifest e le soglie con:

```sh
sh ./scripts/external-uptime-check.sh --dryRun
```

Il dry-run scrive un report diagnostico in `reports/uptime/` con
`mode=dry-run` e `providerEvidence.verified=false`; serve per archiviare la
validazione del manifest, ma non soddisfa il production go/no-go.

Quando DNS, CDN e TLS sono attivi, crea i monitor nel provider esterno, copia `monitoring/external-uptime-provider.example.json`, compila `monitorId`, `verifiedAt`, regioni reali, ultimo status code, latenza e `lastCheckedAt` letti dal provider. Il file deve essere prodotto da un workflow GitHub dedicato e attestato con GitHub Artifact Attestations: un campo locale `verified: true` non e' evidence. Poi esegui:

```sh
PROVIDER_EVIDENCE_ARGS="--providerEvidenceAttestation online --providerEvidenceRepository OWNER/REPO --providerEvidenceWorkflow OWNER/REPO/.github/workflows/provider-evidence.yml --providerEvidenceSourceDigest FULL_GIT_SHA --providerEvidenceSourceRef refs/heads/main"
sh ./scripts/external-uptime-check.sh --providerEvidence ./monitoring/external-uptime-provider.production.json $PROVIDER_EVIDENCE_ARGS --validateProviderEvidenceOnly
sh ./scripts/external-uptime-check.sh --envFile .env --providerEvidence ./monitoring/external-uptime-provider.production.json $PROVIDER_EVIDENCE_ARGS --requireProviderEvidence
```

Il go/no-go accetta `reports/uptime/` solo se il digest esatto del file e' verificato crittograficamente, i target pubblici sono coperti da provider evidence esterna fresca e i risultati passano; il secondo comando aggiunge anche una sonda HTTP diretta dal punto in cui lo esegui.

## HTTPS locale

```sh
cd /opt/platform/platform-infrastructure
mkcert -install
mkcert -cert-file ./traefik/certs/local-cert.pem -key-file ./traefik/certs/local-key.pem localhost 127.0.0.1 ::1 portal.localhost.com docs.localhost.com
docker compose -f compose.yaml --env-file .env -p platform_infra_local up -d --build traefik
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
  -f compose.secrets.yaml \
  -f compose.waf.yaml \
  up -d --build
sh ./scripts/waf-smoke.sh
```

Baseline WAF: CRS paranoia level 2, blocking mode attivo, audit log
`RelevantOnly` limitato alle parti non sensibili `A/K/Z`, request body inspection
attiva ma body e header di autenticazione/sessione esclusi da stdout, response
body inspection spenta, file sensibili e scanner path bloccati prima del routing
verso runtime o app collegate. Promtail scarta inoltre in modo fail-closed ogni
evento che presenti campi body, Authorization, Cookie o Set-Cookie prima di
Loki. PL3/PL4 vanno attivati solo dopo una finestra di tuning sui log, altrimenti
il rischio falso positivo diventa alto per dashboard, OAuth e form PHP.

Nel profilo VPS la porta pubblica 80 del WAF esegue sempre un redirect
permanente verso HTTPS; soltanto il listener TLS 8443 puo' inoltrare
`X-Forwarded-Proto: https`. Questi due valori sono fissi nell'overlay e non
sono sovrascrivibili dall'env o dagli header del client. La zona interna
`platform_edge` ammette esattamente WAF e Traefik, quindi il middleware che
propaga lo schema HTTPS opera soltanto dietro il terminatore dichiarato.

La chiave del rate limit usa l'identita' client validata: Traefik accetta gli
header forwarded soltanto dal peer WAF fisso `172.30.250.2`, quindi scorre
`X-Forwarded-For` da destra e salta esclusivamente i CIDR Cloudflare fissati in
`cloudflare/trusted-proxy-cidrs.json`. Non usare `depth`, wildcard o proxy
aggiuntivi impliciti. `cloudflare-origin-lock-ufw.sh` confronta i range ottenuti
dal provider con lo snapshot prima di proporre o applicare qualunque regola;
una differenza interrompe l'operazione e richiede una revisione congiunta di
firewall e middleware.

Su Windows/Docker Desktop il certificato mkcert locale e' montato in un container non privilegiato. Se il WAF non riesce a leggere `local-key.pem`, rendi la copia locale leggibile dal runtime Docker e riavvia:

```powershell
docker run --rm --entrypoint sh -u root -v "${PWD}\traefik\certs\local-key.pem:/tmp/server.key" owasp/modsecurity-crs:4.26.0-nginx-202605200705 -c "chmod 0644 /tmp/server.key"
docker compose --env-file .env -p platform_infra_local -f compose.yaml -f compose.secrets.yaml -f compose.waf.yaml up -d waf
```

## Database gestiti

PostgreSQL e MariaDB sono servizi gestiti dalla piattaforma hosting. Il GO/NO-GO
infrastrutturale verifica disponibilita', backup, restore, retention,
isolamento, admin tooling e prove DR/off-site; non verifica schema o business
logic delle applicazioni ospitate.

Questa repository inizializza soltanto i database di piattaforma, per esempio
Keycloak. Schema, migrazioni, rollout delle identita' database e rollback di una
applicazione devono vivere nella repository del workload. Non usare migrazioni
applicative per promuovere la piattaforma hosting a GO-LIVE.

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
I dump PostgreSQL preesistenti non vengono mai firmati automaticamente. `sign-existing-postgres-backups` verifica soltanto artifact già firmati e può spostare gli unsigned in quarantena con `--quarantine`. L’import di un singolo dump richiede `import-postgres-backup`, un documento `platform.backup-import-provenance/v1`, il digest del documento ricevuto fuori banda, identità sorgente esatta e la conferma esatta mostrata dal comando.
I backup MariaDB coprono tutti i database dei progetti PHP locali, sono compressi, hanno sidecar `.sha256` e firma HMAC, e il restore drill importa il dump in un container MariaDB disposable senza toccare il volume reale.
Anche i dump PostgreSQL vengono aperti soltanto in un container disposable digest-pinned, senza rete, volumi o secret live e sotto il ruolo `restore_runner` privo di privilegi amministrativi; il superuser del sandbox esegue esclusivamente il bootstrap statico e non interpreta mai il dump.
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

Restic carica esclusivamente l'ultimo manifest platform completo e firmato, tutti gli artifact dichiarati e i sidecar obbligatori; lo snapshot viene taggato con identità e digest del manifest.
`offsite-restore-drill-restic.sh --dryRun` verifica soltanto raggiungibilità e metadata dello snapshot e resta `EXTERNAL-PENDING`. Senza `--dryRun`, il comando verifica firma e tag del manifest, confronta esattamente path snapshot/restaurati/attesi, rifiuta file mancanti, extra, duplicati o sostituiti ed esegue il restore-test tipizzato per ogni risorsa dichiarata.
Per il go-live il repository Restic deve essere remoto (`s3:`, `b2:`, `azure:`, `gs:`, `sftp:`, `rest:` o `rclone:`). Il report è completo soltanto con firma manifest verificata, set esatto, ogni resource ID riuscito e `infra-health` positivo. Restore per famiglie e `--allowPartial` sono rifiutati e non possono produrre evidenza completa.

La schedulazione container-first production e' parte della release immutabile
ammessa: `backup-scheduler` puo' essere attivato o aggiornato soltanto dal
workflow trusted `deploy-vps.sh`, non con un comando Compose diretto.

Il wrapper `compose-vps.sh` e' l'unico entrypoint supportato per rendere e
ispezionare lo scheduler: carica anche gli overlay runtime, network e isolamento
che non devono essere ricostruiti manualmente. Il servizio `backup-scheduler` usa l'immagine ops
Dockerizzata e `crond` interno, quindi non richiede cron o Node sull'host.
Schedula backup giornalieri PostgreSQL, MariaDB, MinIO, Keycloak e Secret
Manager metadata, retention PostgreSQL e un `full-restore-drill` settimanale.
Lo scheduler rileva i mount host da Docker; su VPS puoi forzarli con
`PLATFORM_INFRA_HOST_ROOT` e `PROJECT_SOURCE_HOST_ROOT` se usi percorsi custom.
L'upload Restic off-site parte solo con `BACKUP_SCHEDULER_ENABLE_OFFSITE=true` e
credenziali reali. Il runtime env file privato dello scheduler viene letto con
parser dedicato dai job `--run` e non viene eseguito con `source`.

Le richieste privilegiate di backup del Control Center non scrivono direttamente
file `queued`: consumano l'operazione autorizzata e immutabile e attraversano
lo stesso ledger atomico usato dallo scheduler. L'overlay
`compose.backup-scheduler.yaml` passa a entrambi i servizi gli stessi limiti
`BACKUP_QUEUE_*` per profondita', rate per principal, concorrenza, scansione e
retention. Il Control Center limita i documenti terminali durante
l'ammissione; la rimozione dei log correlati resta proprieta' dello scheduler,
che monta `backup_scheduler_logs`.

Schedulazione Linux host fallback:

```sh
sh ./scripts/install-postgres-backup-cron.sh --cronRoot /opt/platform/platform-infrastructure --backupAt 03:15 --drillAt 04:15 --retentionAt 05:15 --drillWeekday 0
sh ./scripts/install-mariadb-backup-cron.sh --cronRoot /opt/platform/platform-infrastructure --backupAt 03:45 --drillAt 04:45 --drillWeekday 0
sh ./scripts/install-offsite-backup-cron.sh --cron-root /opt/platform/platform-infrastructure
```

I comandi stampano le righe cron da installare sull'host: backup quotidiano, restore drill settimanale, retention quotidiana dei dump PostgreSQL e upload off-site degli artifact firmati.

## Gate e controlli

Il gate infrastrutturale canonico gira nei job non privilegiati del workflow
`enterprise-infra.yml` sul checkout esatto. Non esiste un equivalente locale
ammesso tramite `infra-ops.sh` finche' il producer ops trusted resta
`EXTERNAL-PENDING`.

Se lavori in un vecchio monorepo applicativo puoi trovare ancora riferimenti a
`/opt/platform/src` e `pnpm enterprise:check`; sono compatibilita' legacy e non
sono necessari per validare questa repository infrastrutturale.

Le interfacce shell sotto restano documentate come catalogo operativo, ma ogni
comando che delega a `infra-ops.sh` deve attualmente terminare con codice 78;
non usarne l'output come evidence positiva.

Audit infrastrutturale (bloccato senza runner ammesso):

```sh
cd /opt/platform/platform-infrastructure
sh ./scripts/enterprise-hardening-audit.sh
```

Interfacce di controllo (bloccate senza runner ammesso):

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
sh ./scripts/failure-tests.sh --confirmServiceStop --targets redis,postgres,minio,keycloak,nats,waf,platform-alert-dispatcher,backup-scheduler
sh ./scripts/fault-injection-tests.sh
sh ./scripts/load-smoke.sh
sh ./scripts/load-benchmark.sh --profiles 50,100,500
sh ./scripts/load-benchmark.sh --profiles 50,100,500 --url 'https://api.example.com/health?proof=unique-release-nonce' --requirePublicTarget --requireEdgeEvidence --expectedEdgeProvider cloudflare --edgeProviderEvidence ./monitoring/edge-traversal-provider.production.json --edgeProviderEvidenceAttestation online --edgeProviderEvidenceRepository OWNER/REPO --edgeProviderEvidenceWorkflow OWNER/REPO/.github/workflows/provider-evidence.yml --edgeProviderEvidenceSourceDigest FULL_GIT_SHA --edgeProviderEvidenceSourceRef refs/heads/main
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

`alert-evidence.sh` verifica configurazione Alertmanager, bearer secret, metriche
del `platform-alert-dispatcher`, alert di failure delivery e ricevuta correlata
del probe. In staging/VPS usa `alert-evidence.sh --sendTest`; con canali reali
configurati puoi aggiungere `--requireEmailDelivery` o
`--requireForwardDelivery` per rendere la consegna un gate.

`secret-rotation-evidence.sh` scrive un report non-secret in `reports/secret-rotation/` con stato dello store Infra Secret Manager, audit log, KMS attivo, eta' dei secret rispetto a `rotationDays`, file materializzati, secret vault e risultato di `infra-secret-manager verify`. In produzione usa `--enforce`: il go/no-go accetta solo `mode=evidence`, `status=passed`, zero secret scaduti e zero file mancanti.

`compose-healthcheck-coverage` renderizza gli stack local WAF, VPS WAF e backup scheduler, poi scrive `reports/healthchecks/healthcheck-coverage-*.json`/`.md`. Fallisce se un servizio operativo del render Compose non ha una healthcheck.

`rate-limit-evidence.sh` scrive un report in `reports/rate-limits/` che verifica il rate limit Traefik, i router local/VPS e i budget dei runtime platform generici. Eventuali prove applicative montate da sorgenti esterni sono compatibilita' workload e non cambiano il GO/NO-GO dell'infrastruttura.

`audit-log-evidence.sh` scrive un report in `reports/audit-logs/` che verifica audit amministrativo, outbox durevole, dead-letter, alert Prometheus e dashboard Grafana. Eventuali audit table dei workload ospitati restano fuori dai gate platform.

`retention-evidence.sh` scrive un report in `reports/retention/` che verifica logging Docker bounded, retention Loki/Promtail, retention TSDB Prometheus, datasource/pannelli Grafana e, quando il sorgente runtime e' montato, anche log JSON strutturati e redazione dei campi sensibili. In CI resta infra-only se il sorgente esterno non e' presente.

`runtime-fingerprint` consuma un manifest `platform.runtime-target/v1` con la
`candidate` `platform.release-candidate/v1` prodotta da FG-048, deployment ID e
timestamp, digest aggregato dei config hash e lista ordinata
`service/configHash/imageRef/imageId`. Il file deve essere regolare, non
scrivibile da gruppo/altri e accompagnato dal suo SHA-256 approvato. Il runtime
PASS confronta ref e ID immagine esatti, config hash Compose, commit/tree,
candidate/render/workload lock label, evento di deploy, servizio, progetto e
salute; un digest sintatticamente valido ma diverso non e' accettato.

`load-benchmark.sh` senza `--url` misura il Control Center dentro la rete Docker
ed e' utile per regressioni locali della piattaforma. Per il go-live devi usare
l'URL pubblico del Portal e `--requirePublicTarget`; con Cloudflare CDN attivo
aggiungi `--requireEdgeEvidence --expectedEdgeProvider cloudflare` e passa un
`platform.edge-traversal-evidence/v1` fresco, legato a URL/request ID/status e
candidate ID, con attestazione GitHub/Sigstore verificata. Gli header HTTP
(`CF-Ray`, `Server`, cache header) restano diagnostica non autenticata e non
possono soddisfare il gate; senza prova provider il risultato resta
`EXTERNAL-PENDING`. Il report in
`reports/load/` include profili 50/100/500, snapshot CPU/RAM Docker, target
evidence pubblico/edge e `status`. Anche i fallimenti scrivono report
diagnostici, ma il go/no-go accetta solo `status=passed`.

Le vecchie suite account/passkey e le migration account sono compatibilita'
workload. Non fanno parte dei gate GO/NO-GO della piattaforma hosting e non
devono essere usate come evidence per promuovere `platform-infrastructure`.

Gli entrypoint privilegiati convergono su `scripts/infra-ops.sh`. Il codice
preserva un percorso positivo solo per l'immagine ops digest-pinned e per
l'image ID locale autenticati dalla catena provider; la policy inclusa resta
bloccata finche' tale producer non viene configurato. Non viene costruita o
taggata alcuna immagine locale e nessuna label dell'immagine e' considerata
prova di trust.

La policy GitHub live e' versionata in `governance/github-branch-protection.json`.
Usa `scripts/github-branch-protection.sh` in dry-run, poi `--apply` e
`--verifyRemote` con un token GitHub admin prima del primo deploy pubblico.
Gli environment di deploy sono versionati in `governance/github-environments.json`.
Le identita' reviewer sono versionate con tipo e ID GitHub immutabile; usa
`scripts/github-environments.sh --dryRun`, `--apply` e `--verifyRemote` per
applicare e confrontare esattamente reviewer, self-review, wait timer e branch
policy su staging/production. Reviewer mancanti o aggiuntivi fanno fallire la
verifica.
La runtime config GitHub Actions e' versionata in
`governance/github-actions-runtime.json`: `DAST_TARGET`, `DEPLOY_SSH_KEY`,
`DEPLOY_SSH_HOST_KEY`, `DEPLOY_REMOTE`, `DEPLOY_REMOTE_DIR`, `DEPLOY_SSH_PORT`,
`VPS_HARDENED_SSH_PORT`, `PUBLIC_API_HEALTH_URL`, `CLOUDFLARE_ACCOUNT_ID`,
`EXTERNAL_UPTIME_PROVIDER_EVIDENCE_JSON`, `EDGE_PROVIDER_EVIDENCE_JSON` e
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
provenance locale non firmata e i report JSON normalizzati non sono trust input.
Il go/no-go richiede che il gate invochi direttamente il verifier GitHub/Sigstore
con signer workflow, commit, ref, issuer, timestamp e subject digest esatti.
La workflow manuale `enterprise-live-evidence` gira nell'environment GitHub
`production` e raccoglie prove live non mutanti: uptime provider, load benchmark
pubblico via Cloudflare, Cloudflare Access `--verifyRemote`, go/no-go live e
bundle completo.
La workflow manuale `enterprise-vps-evidence` e' disabilitata per questa V1
brownfield: **V1 brownfield: unconditional STOP 78** prima di installare la
chiave SSH e quindi prima di qualsiasi SSH, Git fetch, bootstrap, hardening o
produzione di receipt. Input `confirm`, variabili e report locali sono
`NONAUTHORITATIVE` e non possono aggirare lo stop. Non esiste ancora un consumer
di admission V1 autorevole che possa abilitarla; plan/read-only/local tests remain available.
Il codice di trasporto irraggiungibile conserva comunque il pin che contiene
soltanto `algoritmo base64-host-key`; hostname e porta arrivano da variabili
separate e vengono legati in un `known_hosts` a voce singola. Non e' ammesso
trust-on-first-use.
Il job CI `node scripts/infra-ops.mjs repo-coverage-check` misura la copertura dei
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
EVIDENCE_REPORT_PHASE=production-live \
  sh ./scripts/evidence-bundle.sh \
    --phase production-live \
    --notBefore <latest-relevant-event-rfc3339> \
    --strict
sh ./scripts/evidence-bundle-verify.sh \
  --phase production-live \
  --notBefore <latest-relevant-event-rfc3339> \
  --ownerPinnedManifestSha256 <independently-approved-sha256> \
  --requireComplete
```

Il bundle finisce in `.tmp/evidence-bundles/`, include gli ultimi report
JSON/Markdown per categoria, documentazione operativa e manifest SHA256, ed
esclude sempre `secrets/`, artifact di backup, `.env`, SBOM/release artifact e
altri file sensibili. Usa `--allReports` solo se devi consegnare tutta la
cronologia report della finestra di validazione. `evidence-bundle-verify.sh`
rilegge `manifest.json`, ricontrolla SHA256, size, policy anti-segreti e, con
`--requireComplete`, fallisce se manca una qualunque evidenza richiesta. Il
digest del manifest deve essere approvato e fissato dal release owner fuori dal
bundle; senza `--ownerPinnedManifestSha256` la verifica resta
`EXTERNAL-PENDING`. Un digest copiato dal manifest o dal summary contenuto nello
stesso bundle non e' un trust anchor. Ogni report JSON scritto dal tool include
un contesto `platform.evidence-report-context/v1` con fase, commit, tree, stato
clean e metadati GitHub non sensibili. La verifica strict rifiuta report
mancanti, duplicati, stale, anteriori all'evento indicato, prodotti in un'altra
fase o legati a commit/tree/repository/candidato differenti. `candidate-ci` e'
una fase completa ma solo candidate-scoped: non puo' essere riusata come prova
`production-live`. La fase live richiede inoltre il candidato completo
(repository, commit, tree, Compose project, workload lock e render digest) e il
set di prove production previsto dalla policy.

`scripts/linux-portability-check.sh` verifica BOM UTF-8, CRLF, path Windows e
dipendenze PowerShell/cmd nei file operativi, poi valida gli shell script dentro
Alpine. Scrive report in `reports/linux-portability/`. Usa
`scripts/linux-portability-check.sh --fix` per normalizzare BOM/CRLF prima di
committare o spostare la stack su Ubuntu.

Per ogni release candidata genera anche il manifest operativo:

```sh
sh ./scripts/release-evidence.sh --planOnly
gh workflow run release-attestation.yml --repo OWNER/REPO --ref main
GITHUB_REF=refs/heads/main sh ./scripts/release-evidence.sh --requireProvenance --repo OWNER/REPO --sourceRef refs/heads/main --imageManifest reports/release/release-subjects-<run-id>.json --sbom reports/release/github-release-sbom-<run-id>.cdx.json --buildkitSbom reports/release/buildkit-sbom-<run-id>.spdx.json --registryDescriptor reports/release/registry-descriptor-<run-id>.json --registryResolution reports/release/registry-resolution-<run-id>.json --previousImagesFile ./release/previous-images.json
```

Il workflow `release-attestation.yml` usa GitHub Artifact Attestations/Sigstore,
builda l'immagine infra PHP Apache su GHCR per la piattaforma esatta
`linux/amd64`, estrae e consuma l'inventario SPDX dell'attestation SBOM BuildKit,
lo proietta in un CycloneDX con dipendenze reali e componenti subject distinti,
risolve l'indice OCI e lega root digest, child platform digest e descriptor.
Attesta anche `release-subjects.json` e carica receipt non sensibili. Il gate non rilegge tali
receipt come prova: invoca direttamente il GitHub CLI checksum-pinned e vincola
repository, signer workflow, source/signer digest, ref, issuer, SLSA v1, runner
GitHub-hosted, timestamp verificato e subject digest. Per verifica offline sono
obbligatori insieme `--attestationBundle` e `--trustedRoot`; `--provenance`,
`--githubAttestation` e `--skipProvenanceCommitCheck` sono respinti. In evidence
mode esegue anche la dry-run di rollback, valida `docker compose config` con i
digest precedenti e collega `reports/rollback/rollback-plan-*.json`.

## Produzione

> **Boundary brownfield V1:** i comandi di bootstrap/hardening qui sotto sono
> destinati a un host nuovo o gia' coperto da un piano di recovery verificato.
> Sul server esistente non eseguire `--apply`, hardening, teardown Compose,
> prune, reinstallazione o ricostruzione finche' non sono soddisfatti il
> [contratto brownfield V1](V1-BROWNFIELD-DEPLOYMENT.md), il backup PRE-DEPLOY
> completo su storage separato e tutti e tre i gate provider autorevoli. Una
> ricostruzione puo' sostituire identita' Docker solo dopo quella prova di
> recovery; la baseline point-in-time da sola non e' autorizzazione.

### VPS hardening e Cloudflare origin-lock

Prima del deploy pubblico su VPS/Ubuntu LTS:

```sh
sudo sh ./scripts/vps-bootstrap-ubuntu.sh --apply --deploy-user deploy
sudo sh ./scripts/vps-hardening-ubuntu.sh --apply --ssh-port 65002 --reload-sshd
COMPOSE_ENV_FILE=.env COMPOSE_PROJECT_NAME=platform_infra_vps bash ./scripts/compose-vps.sh config --format json > /tmp/platform-compose.json
sudo sh ./scripts/cloudflare-origin-lock-ufw.sh --apply --compose-json /tmp/platform-compose.json --ssh-port 65002
sudo sh ./scripts/vps-host-readiness.sh --ssh-port 65002 --enforce
```

Per il server home-VPS/LAN attuale non cambiare porta SSH: usa la stessa
procedura con `--ssh-port 22` dopo aver confermato l'accesso con chiave.

```sh
sudo sh ./scripts/vps-hardening-ubuntu.sh --apply --ssh-port 22 --reload-sshd
COMPOSE_ENV_FILE=.env COMPOSE_PROJECT_NAME=platform_infra_vps bash ./scripts/compose-vps.sh config --format json > /tmp/platform-compose.json
sudo sh ./scripts/cloudflare-origin-lock-ufw.sh --apply --compose-json /tmp/platform-compose.json --ssh-port 22
sh ./scripts/vps-host-readiness.sh --ssh-port 22 --enforce
```

L'origin-lock richiede esattamente una regola recovery SSH IPv4 e una IPv6 gia'
presenti, scarica i due elenchi CIDR dagli URL HTTPS Cloudflare senza redirect,
valida semanticamente famiglie, prefissi e overlap, imposta il default inbound
`deny` e salva un receipt con hash e digest del ruleset. La verifica successiva
consuma solo quello stato salvato; file CIDR/receipt espliciti sono test-only.

`vps-bootstrap-ubuntu.sh` e' dry-run di default e genera report JSON/Markdown in
`reports/vps-bootstrap/`. Con `--apply` configura il repository apt ufficiale
Docker per Ubuntu, installa Git, `jq`, Python 3, Docker Engine, Buildx e Docker
Compose plugin, poi verifica `docker`, `docker compose`, `git` e `jq`.

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
Prima di ogni applicazione lo script scarica entrambi gli elenchi IP Cloudflare
e pretende uguaglianza esatta con `cloudflare/trusted-proxy-cidrs.json`; se il
provider ha aggiunto o rimosso un CIDR, aggiorna e revisiona lo snapshot e il
middleware di rate limit nello stesso cambiamento. La freschezza dei range e le
bucket separate per client devono comunque essere provate sul provider/VPS
reale prima del deploy.
La riconciliazione termina con una verifica fail-closed dell'intero set IPv4/IPv6; il deploy usa solo `--verify` e non modifica UFW.
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
La workflow manuale `enterprise-vps-evidence` non raccoglie questa evidenza in
V1: termina incondizionatamente con exit 78 prima delle credenziali SSH. Le prove
plan/read-only/local tests remain available, ma non sono evidenza VPS live.

Le regole edge Cloudflare versionate sono in `cloudflare/`. Il WAF Cloudflare blocca admin host, file sensibili e scanner path prima della VPS; il WAF interno OWASP CRS resta attivo come secondo livello. `cloudflare/access-admin.example.json` rende versionate anche le applicazioni Cloudflare Access per phpMyAdmin, Grafana, Prometheus, Alertmanager, MinIO, Traefik, Projects e Keycloak Admin.

### Staging

Staging usa gli stessi overlay della produzione ma domini, volumi e secret separati:

```sh
cp .env.staging.example .env.staging
sh ./scripts/infra-secret-manager.sh init
docker compose --env-file .env.staging -p platform_infra_staging \
  -f compose.yaml \
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

Questa esecuzione manuale produce solo report diagnostici e non autorizza un
deploy. Il percorso di release protetto richiede la request `PENDING`, il digest
dell'archivio con i tre report, la validazione semantica di un secondo provider
indipendente e la relativa attestazione GitHub/Sigstore, tutti vincolati allo
stesso runtime intent e allo stesso inventario staging pre/post scansione.

### VPS prod-like con TLS esterno

Usa questo profilo quando dominio e certificati sono gestiti fuori da Docker, per esempio da VPS o da Cloudflare davanti alla VPS. Traefik resta il reverse proxy interno, ascolta solo HTTP sulla porta 80 e inoltra alle app `X-Forwarded-Proto=https`.

```sh
cd /opt/platform/platform-infrastructure
cp .env.example .env
# copia i valori di .env.vps.example dentro .env e sostituisci tutti i domini example.com
sh ./scripts/infra-secret-manager.sh init
sh ./scripts/vps-preflight.sh .env
COMPOSE_ENV_FILE=.env COMPOSE_PROJECT_NAME=platform_infra_vps \
  bash ./scripts/compose-vps.sh config --format json > /tmp/platform-compose.json
```

Questo prepara e rende ispezionabile il modello, ma non lo attiva. La produzione
puo' essere avviata solo dalla workflow trusted che invoca `deploy-vps.sh`, lega
commit/tree, artifact, admission receipt, image digest e UFW, quindi usa
`--no-build --pull never`. Al momento il trusted bootstrap esterno e'
`EXTERNAL-PENDING`, quindi il percorso corretto e' intenzionalmente deny-all.

Sul reference server corrente il path operativo e'
`/home/platform_infrastructure/platform-infrastructure` e il runtime usa anche
gli overlay tracked `compose.runtime.yaml`, `compose.networks.yaml` e
`compose.runtime-isolation.yaml` per collegare runtime dedicati, trust zone e
limiti cgroup/mount. Per nuovi server ricrea lo stesso
intento in modo revisionato invece di copiare stato live alla cieca.

```sh
cd /home/platform_infrastructure/platform-infrastructure
docker compose -p platform_infra_vps \
  -f compose.yaml \
  -f compose.secrets.yaml \
  -f compose.vps.yaml \
  -f compose.waf.yaml \
  -f compose.vps-waf.yaml \
  -f compose.runtime.yaml \
  -f compose.networks.yaml \
  -f compose.runtime-isolation.yaml \
  ps
```

`vps-preflight.sh` valida env, secret file e render completo dello stesso
set Compose usato dal deploy VPS, inclusi `compose.waf.yaml` e
`compose.vps-waf.yaml`.

`deploy-vps.sh` non accetta piu' branch mobili: richiede commit e tree SHA
esatti, receipt artifact-verification e trusted-deployment con checksum attesi,
origin GitHub canonica e checkout puliti. Il remoto esegue i gate evidence
prima di mutare UFW, poi riconcilia e verifica l'origin-lock dal Compose
renderizzato; solo dopo puo' preparare il runtime e fare `compose up` con
`--no-build --pull never`. Prima del checkout salva il modello Compose precedente, richiede
storage/reti invariati e lega quel modello all'image ID gia' in esecuzione. Un
errore dopo il confine di mutazione attiva un rollback bounded di UFW e runtime;
il rollback ripristina l'esatto commit/tree precedente e verifica tutti gli
image ID in esecuzione e le identita' dei volumi, fallendo hard se non puo'
ripristinarli. I gate preflight, pre-go-live, provider remoto, DR/off-site,
go/no-go, WAF e health sono obbligatori e non hanno un valore production che li
disabiliti. `vps-postdeploy.sh` dopo l'attivazione resta limitato a WAF smoke e
`infra-health`.

Il repository non dispone ancora di un produttore esterno autenticato di
trusted deployment receipt: `governance/deployment-admission.json` resta
`EXTERNAL-PENDING` e il workflow blocca intenzionalmente prima di installare la
chiave SSH. Non impostare localmente `READY` e non usare receipt auto-dichiarate.
Lo stesso limite vale per `PLATFORM_OPS_IMAGE`, il backup scheduler e la
preparazione dei workload: nessuno di questi ha un default mutabile o un
percorso auto-build.

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

Per ottenere soltanto un piano locale non autoritativo:

```sh
sh ./scripts/vps-go-live.sh --planOnly --repo OWNER/REPO
```

Il piano scritto in `reports/vps-go-live/` resta `NONAUTHORITATIVE`.
**V1 brownfield: unconditional STOP 78**: `--confirmLive` termina prima di
bootstrap, hardening, readiness, preflight, Docker restart o evidence bundle.
Nessun flag o stato locale puo' abilitarlo finche' non esiste un consumer di
admission V1 autorevole. I plan/read-only/local tests remain available. Su un
host nuovo e dimostrabilmente vuoto si usano separatamente gli script standalone
fresh-host; questa non e' un'autorizzazione per il server V1 esistente.

Nel profilo VPS:

- Il WAF pubblica la porta 80; Traefik resta interno e riceve solo traffico filtrato.
- SSL, redirect HTTPS e CDN stanno all'edge esterno, per esempio VPS/Cloudflare.
- PostgreSQL, MariaDB, Redis, NATS, MinIO, Prometheus, Loki, Grafana, phpMyAdmin e dashboard Traefik non sono pubblici.
- `CONTROL_CENTER_HOST` apre il portal Node e `DOCS_HOST` apre la documentazione operativa. Sono le sole route pubbliche previste.
- I progetti PHP e Node condividono `PHP_PROJECTS_DIR` come sorgente universale. `PROJECTS_HOST` resta solo alias legacy e deve restare vuoto nelle nuove installazioni, `PROJECTS_WILDCARD_HOST_REGEXP` resta vuoto di default e Traefik non espone wildcard progetto. Il `project-router` resta disponibile come servizio interno e continua a essere coperto da `project-router-tests`.
- L'overlay finale monta a ogni workload solo la propria sorgente read-only, applica CPU/RAM/PID/FD/I/O e rootfs read-only, e impedisce accesso a repository parent, backup, stato Control Center e Docker socket. I PHP usano una copia tmpfs per il runtime; i Node avviano soltanto artifact precompilati.
- Solo `docker-operation-gateway` riceve il socket raw. Non pubblica porte host e accetta esclusivamente job di backup/restore enumerati, autenticati con la credenziale Docker secret dedicata al principal `backup-scheduler` e montata solo nei due servizi; scheduler e workload non ricevono mai `DOCKER_HOST`.
- MariaDB usa `secrets/mariadb_root_password.txt` tramite Docker secret, non una password root in `.env`.
- `phpmyadmin` resta fuori dal profilo di default; su VPS pubblica usa preferibilmente SSH e client CLI, non una UI DB esposta.

### Produzione full con ACME

Render e preflight locali sono sola evidenza preparatoria. L'attivazione o la
ricreazione production deve passare esclusivamente dal workflow trusted
`deploy-vps.sh`, dopo admission della release e approvazione dell'environment.
Finche' le policy del provider GitHub e il bootstrap del verifier non sono
provati esternamente, questa operazione resta `EXTERNAL-PENDING`/`NO-GO`.

In produzione:

- Traefik pubblica solo 80/443.
- PostgreSQL, Redis, NATS, MinIO, Prometheus e Loki non espongono porte host.
- Le immagini runtime o dei workload collegati devono essere versionate e pin-nate con digest.
- `.localhost.com` non e' valido per ACME pubblico: servono domini DNS reali.

Le immagini runtime/template production sono costruite e attestate soltanto dal
workflow `release-attestation.yml`; una build Compose locale non e' un artefatto
ammissibile per il deploy.

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

## V1.0 LOCAL_PRIVATE corrente

La V1.0 attiva non e' piu' descritta dal solo core. Il contratto riproducibile
e' composto da questa repository, dal lock
`config/v1-local-private-source-lock.json` e dalle tre revisioni applicative
immutabili indicate nel lock. Le sorgenti vengono materializzate sotto
`PHP_PROJECTS_DIR` con le directory `fiplatform`, `stexor`, `anniversary`,
`matthewdifilippo`, `opstudents`, `stream` e `workcalendar`; dati, `.env`,
upload, log e cache restano esterni a Git.

Il runtime si rende caricando, nell'ordine registrato nel lock, il core, gli
overlay VPS/WAF, `compose.backup-scheduler.yaml`, gli overlay runtime/network,
`compose.local-private.yaml`, `compose.local-private-applications.yaml` e per
ultimo `compose.greenfield.yaml`. Il file backup-scheduler completa le
definizioni referenziate dagli overlay di rete, ma il profilo `backup` resta
inattivo: il lock abilita esattamente il solo profilo `admin` e registra anche
renderer e profili intenzionalmente inattivi. I backup diretti del Control
Center non richiedono l'attivazione della vecchia transaction. Le variabili
provider richieste dal parsing devono comunque essere definite nell'ambiente
esterno.

Le quattro immagini Stexor vengono costruite dalla revisione bloccata con
`compose.local-private-applications-build.yaml`; le altre applicazioni usano
runtime PHP/Node con sorgenti bind-mounted. `runtime.env`, certificati,
segreti, stato Control Center e volumi database non appartengono a Git e
devono essere ripristinati separatamente. Inventario, eccezioni intenzionali
e prova di parita' sono in `V1.0-LIVE-PARITY.md`.

## File principali

- `compose.yaml`: stack local/dev production-like.
- `compose.secrets.yaml`: overlay Docker secrets file-based.
- `compose.prod.yaml`: overlay produzione.
- `compose.vps.yaml`: overlay VPS prod-like dietro TLS esterno.
- `compose.runtime.yaml`: servizi runtime platform opzionali; non definisce app concrete.
- `compose.networks.yaml`: trust zone core e reti ingress/data/egress per workload.
- `compose.runtime-isolation.yaml`: overlay di hardening core con mount allowlist, proxy Docker e budget cgroup; nella V1.0 precede le proiezioni LOCAL_PRIVATE, applicative e greenfield.
- `compose.waf.yaml`: overlay OWASP CRS/ModSecurity davanti a Traefik.
- `compose.vps-waf.yaml`: adattamento WAF per VPS con TLS/CDN esterno.
- `compose.backup-scheduler.yaml`: scheduler backup/restore drill container-first.
- `compose.local-private-applications.yaml`: topologia applicativa esatta della V1.0 LOCAL_PRIVATE.
- `compose.local-private-applications-build.yaml`: build riproducibile delle immagini Stexor bloccate.
- `config/v1-local-private-source-lock.json`: repository, commit, tree, layout sorgenti e ordine Compose della V1.0.
- `config/hosted-workloads.example.json`: catalogo di esempio per workload esterni.
- `scripts/prepare-hosted-workloads.sh`: prepara core/combined render e lock solo sul target, dentro l'image ID ops autenticato. Un env non-default deve essere l'esatto `/srv/platform-infrastructure/release-states/<releaseId>-<envSha256>/environment.env`, root-owned, group-readable dal deployment e mode `0640`; il bind nel runner e' file-only/read-only. Il lock risultante e' target-local, non portabile. Con la policy inclusa il percorso termina `EXTERNAL-PENDING`.
- `scripts/hosted-workload-contract.mjs`: valida manifest, immagini immutabili, route, environment e confini core/workload.
- `scripts/hosted-workload-lock.sh`: verifica hash, permessi e file Compose/environment bloccati dal lock.
- `traefik/traefik.edge-http.yml`: Traefik per edge TLS esterno.
- `scripts/*.sh`: entrypoint operativi Linux/Docker.
- `scripts/infra-ops.sh`: confine fail-closed; esegue solo l'image ID ammesso, senza host Node, pull o build.
- `scripts/infra-ops.mjs`: implementazione usata direttamente dai job CI non privilegiati e dal runner ops dopo admission.
- `docker/ops.Dockerfile`: definizione dell'immagine ops; non viene auto-buildata ne' auto-ammessa.
- `BACKUP-RECOVERY-COVERAGE.md`: catalogo dati, retention e recovery della piattaforma.
- `DATABASE-DELETION-SAFETY.md`: gate, state machine e recovery per le cancellazioni DB.
- `NETWORK-SEGMENTATION.md`: matrice di comunicazione, SSRF boundary e rollout reti T12.
- `SUPPLY-CHAIN.md`: lock di action/immagini/download, sandbox build e procedura di aggiornamento T15.
- `RELEASE-TRUST-AND-WORKFLOW-SECURITY.md`: verifier crittografico, governance GitHub esatta e input SSH sicuri T16.
- `RUNTIME-ISOLATION.md`: contratto T13, test, rollout progressivo e rollback per-app.
- `SERVICE-IDENTITY-AND-TENANCY.md`: identita DB T14, policy MinIO per prefisso, contratto tenancy e rollout dual-credential.
- `postgres/init/`: solo bootstrap database platform. Migrazioni applicative e
  relativi rollback appartengono alle repository dei workload.
- `RUNBOOK.md`, `SECURITY.md`, `THREAT-MODEL.md`, `ENTERPRISE-MATURITY.md`: governance operativa.
