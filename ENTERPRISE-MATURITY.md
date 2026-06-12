# Stexor Enterprise Maturity Matrix

Questo documento traduce i 30 punti enterprise in controlli concreti. Le voci `repo-ready` sono implementate o automatizzate nel repository; le voci `environment-ready` richiedono VPS, DNS, provider o policy operative reali.

## Stato sintetico

| # | Area | Stato | Controllo |
|---|------|-------|-----------|
| 1 | VPS hardening OS/firewall/fail2ban | Gate-ready | Preflight e runbook bloccano deploy incompleto |
| 2 | DNS reali | Gate-ready | `production-preflight.sh` verifica domini pubblici e risoluzione DNS |
| 3 | HTTPS pubblico ACME | Repo-ready | `compose.prod.yaml` con Let's Encrypt HTTP challenge |
| 4 | Secrets manager | Proprietary integrated | `stexor-secret-manager`, encrypted store, audit log, `/run/secrets/*`, `*_FILE`, keyring rotation |
| 5 | Rotazione credenziali | Repo-ready | Runbook e secret scan gate |
| 6 | Registry immagini privato | Repo-ready | Dockerfile prod e `compose.build.yaml`; prod usa immagini versionate |
| 7 | CI/CD remoto | Repo-ready | Workflow GitHub e `pnpm enterprise:check` |
| 8 | Backup off-site e restore drill | Gate-ready | Backup, restore test schedulato, retention dump e hook Restic off-site |
| 9 | Alerting reale | Gate-ready | Prometheus, Alertmanager, worker notifiche, Loki/Grafana e runbook provider |
| 10 | Log centralizzati/redaction/audit | Gate-ready | Loki/Promtail con label strutturate, redaction condivisa, audit DB append-only |
| 11 | WAF/rate limit/bot protection | Repo-ready | Traefik rate limit + Fastify Redis-backed rate limit |
| 12 | RBAC completa | Repo-ready | `account_roles`, role gate applicativi |
| 13 | Passkey recovery multi-device | Repo-ready | Passkey, OTP, backup code |
| 14 | Email production SPF/DKIM/DMARC | Gate-ready | SMTP configurabile; checklist record dominio |
| 15 | Migrazioni DB rollback-safe | Repo-ready | Cartella migrations e runner Linux/Docker |
| 16 | GDPR/privacy data lifecycle | Repo-ready | Export account, soft-delete, audit/retention policy |
| 17 | SAST/DAST/dependency/container scan | Gate-ready | Audit, secret scan, SBOM; DAST esterno da collegare |
| 18 | Pen-test applicativo | Gate-ready | Threat model + checklist; richiede test professionale/manuale |
| 19 | Load/performance test | Repo-ready | `load-smoke.sh`, metriche e health |
| 20 | Incident runbook RTO/RPO | Repo-ready | `RUNBOOK.md`, backup/restore, restore drill |
| 21 | HA/multi-node | Environment-ready | Richiede infrastruttura multi-node reale |
| 22 | Zero-downtime deploy | Gate-ready | Immagini immutabili e firma; blue/green richiede target reale |
| 23 | Staging identico alla prod | Gate-ready | Prod overlay replicabile con project/env separati |
| 24 | Feature flags/kill switch | Repo-ready | Policy documentata; implementazione applicativa futura |
| 25 | SIEM/security monitoring | Gate-ready | Log/alert esportabili; SIEM esterno da collegare |
| 26 | Vulnerability disclosure | Repo-ready | `SECURITY.md` come base |
| 27 | Supply-chain SBOM/firma/provenance | Gate-ready | SBOM, audit, image signing, BuildKit provenance |
| 28 | Compliance GDPR/SOC2-like | Repo-ready | Security/threat model/runbook; audit formale esterno |
| 29 | Data classification | Repo-ready | Threat model e security doc |
| 30 | Periodic access review | Repo-ready | RBAC in DB, `access-review.sh`, runbook mensile |

## Gate locale

```sh
cd /opt/stexor/src
pnpm enterprise:check
```

Oppure direttamente:

```sh
cd /opt/stexor/enterprise-infrastructure
sh ./scripts/enterprise-hardening-audit.sh
```

## Redis enterprise runtime

Redis viene usato per rate limit distribuito, OTP, challenge WebAuthn/passkey, heartbeat worker e metriche Prometheus.

PostgreSQL rimane source of truth per account, sessioni, passkey, audit, ruoli e backup code.

## Secret manager locale

```sh
cd /opt/stexor/enterprise-infrastructure
sh ./scripts/stexor-secret-manager.sh init
docker compose -f compose.yaml -f compose.secrets.yaml --env-file .env -p enterprise_local up -d
sh ./scripts/stexor-secret-manager.sh verify
docker compose -f compose.yaml -f compose.secrets.yaml --env-file .env -p enterprise_local config --quiet
```
