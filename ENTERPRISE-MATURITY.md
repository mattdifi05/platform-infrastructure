# Platform Enterprise Maturity Matrix

Questo documento traduce i 30 punti enterprise in controlli concreti. Le voci `repo-ready` sono implementate o automatizzate nel repository; le voci `environment-ready` richiedono VPS, DNS, provider o policy operative reali.

Lettura sintetica dello stato:

```text
Platform readiness: GO per repository e runtime Ubuntu prod-like.
Enterprise requirements: GO per copertura repo/tooling, salvo prove live esplicitamente marcate.
Production go-live: NO-GO finche' mancano dominio/provider/evidence esterne.
```

## Stato sintetico

| # | Area | Stato | Controllo |
|---|------|-------|-----------|
| 1 | VPS hardening OS/firewall/fail2ban | Gate-ready | Preflight e runbook bloccano deploy incompleto |
| 2 | DNS reali | Gate-ready | `production-preflight.sh` verifica domini pubblici e risoluzione DNS |
| 3 | HTTPS pubblico ACME | Repo-ready | `compose.prod.yaml` con Let's Encrypt HTTP challenge |
| 4 | Secrets manager | Proprietary integrated | `infra-secret-manager`, encrypted store, audit log, `/run/secrets/*`, `*_FILE`, keyring rotation |
| 5 | Rotazione credenziali | Repo-ready | Runbook e secret scan gate |
| 6 | Registry immagini privato | Repo-ready | Dockerfile prod e `compose.build.yaml`; prod usa immagini versionate |
| 7 | CI/CD remoto | Repo-ready | Workflow GitHub, `pnpm enterprise:check` e release/deploy gate |
| 8 | Backup off-site e restore drill | Repo-ready + environment action | Backup e restore drill PostgreSQL, MariaDB, MinIO, Keycloak, Secret Manager metadata; Restic richiede repository off-site reale |
| 9 | Alerting reale | Gate-ready | Prometheus, Alertmanager, worker notifiche, Loki/Grafana e runbook provider |
| 10 | Log centralizzati/redaction/audit | Gate-ready | Loki/Promtail con label strutturate, redaction condivisa, audit DB append-only |
| 11 | WAF/rate limit/bot protection | Repo-ready | Traefik rate limit + Fastify Redis-backed rate limit |
| 12 | RBAC admin plane | Repo-ready | Control Center identity metadata, Cloudflare Access policy, platform-admin-audit |
| 13 | Hosted workload isolation | Repo-ready | project-router, wildcard boundary, audit separazione platform/app |
| 14 | Email production SPF/DKIM/DMARC | Gate-ready | SMTP configurabile; checklist record dominio |
| 15 | Application onboarding governance | Repo-ready | Control Center add/archive/stop metadata e audit amministrativo |
| 16 | Database service governance | Repo-ready | Backup/restore PostgreSQL/MariaDB come servizio gestito, senza migration app |
| 17 | SAST/DAST/dependency/container scan | Gate-ready | Audit, secret scan, SBOM, Renovate; DAST esterno da collegare |
| 18 | Pen-test applicativo | Gate-ready | Threat model + checklist; richiede test professionale/manuale |
| 19 | Load/performance test | Repo-ready | `load-smoke.sh`, `load-profile`, `load-benchmark.sh` 50/100/500 con report CPU/RAM e `infra-health` |
| 20 | Incident runbook RTO/RPO | Repo-ready | `RUNBOOK.md`, backup/restore, restore drill |
| 21 | HA/multi-node | Environment-ready | Richiede infrastruttura multi-node reale |
| 22 | Zero-downtime deploy | Gate-ready | Immagini immutabili, firma e `rollback-release.sh`; blue/green richiede target reale |
| 23 | Staging identico alla prod | Gate-ready | Prod overlay replicabile con project/env separati |
| 24 | Feature flags/kill switch | Repo-ready | Policy documentata; implementazione applicativa futura |
| 25 | SIEM/security monitoring | Gate-ready | Log/alert esportabili; SIEM esterno da collegare |
| 26 | Vulnerability disclosure | Repo-ready | `SECURITY.md` come base |
| 27 | Supply-chain SBOM/firma/provenance | Gate-ready | SBOM, audit, image signing, BuildKit provenance |
| 28 | Compliance GDPR/SOC2-like | Repo-ready | Security/threat model/runbook; audit formale esterno |
| 29 | Data classification | Repo-ready | Threat model e security doc |
| 30 | Periodic admin access review | Repo-ready | `platform-admin-audit`, Cloudflare Access, GitHub/VPS admin review |

## Gate locale

Il gate canonico della repository infrastrutturale e':

```sh
cd /opt/platform/platform-infrastructure
sh ./scripts/enterprise-hardening-audit.sh
sh ./scripts/infra-ops.sh enterprise-requirements-check
sh ./scripts/infra-ops.sh enterprise-requirements-check --manifest governance/production-readiness.json
sh ./scripts/infra-ops.sh enterprise-requirements-check --manifest governance/production-readiness.json --requireLiveProofs
```

Eventuali riferimenti a account, passkey, backup code, `app_account` o migration
applicative sono controlli di workload ospitato e non partecipano al GO/NO-GO
dell'infrastruttura hosting.

Eventuali riferimenti a `/opt/platform/src` o `pnpm enterprise:check` sono
compatibilita' per vecchi workspace/monorepo applicativi. Non sono richiesti per
validare questa repository `platform-infrastructure`.

La matrice machine-readable vive in `governance/enterprise-requirements.json`.
Il comando `enterprise-requirements-check` verifica i 30 requisiti contro file,
pattern, comandi ops e gate GitHub Actions, poi scrive evidenza non sensibile in
`reports/enterprise-requirements/`.
La checklist production-ready da 19 punti vive in
`governance/production-readiness.json` e produce report in
`reports/production-readiness/`.
Senza `--requireLiveProofs` il gate verifica la copertura repo/infra e segnala le
prove live mancanti come `pending-external-evidence`; con `--requireLiveProofs`
fallisce finche' l'ultimo `production-go-no-go` non contiene prove reali `go`
per VPS, Cloudflare, monitor esterni, alert, restore e rollback.

## Redis enterprise runtime

Redis viene usato dall'infrastruttura per rate limit distribuito, heartbeat
worker e metriche Prometheus. Workload ospitati possono usarlo anche per OTP o
challenge applicative, ma quei flussi non sono gate dell'infrastruttura.

PostgreSQL e MariaDB sono servizi dati gestiti dalla piattaforma hosting. Schemi
applicativi come `app_account` sono compatibilita' workload e non source of truth
del GO/NO-GO infrastrutturale.

## Secret manager locale

```sh
cd /opt/platform/platform-infrastructure
sh ./scripts/infra-secret-manager.sh init
docker compose -f compose.yaml -f compose.secrets.yaml --env-file .env -p platform_infra_local up -d
sh ./scripts/infra-secret-manager.sh verify
docker compose -f compose.yaml -f compose.secrets.yaml --env-file .env -p platform_infra_local config --quiet
```
