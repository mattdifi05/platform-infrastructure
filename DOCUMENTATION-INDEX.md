# Documentation Index

Last docs alignment: 2026-06-29.

Use this index to choose the right document before changing or deploying the
platform. Do not read secrets, dumps, backups or provider live state unless the
operation explicitly requires it and has approval.

## Primary Documents

| File | Use it for |
| --- | --- |
| `README.md` | Fast orientation, local/VPS command examples and main operator concepts. |
| `CURRENT-OPERATING-MODEL.md` | Current reference server facts, live compose profile, paths, status and migration checklist. |
| `INFRASTRUCTURE-DEEP-DIVE.md` | Complete infrastructure map: services, overlays, secrets names, Control Center, routing, go/no-go and migration. |
| `RUNBOOK.md` | Day-2 operations, incidents, backup/restore, deploy and production go/no-go procedures. |
| `VPS-PREDEPLOY-CHECKLIST.md` | Checklist before exposing public traffic on an Ubuntu VPS/server. |
| `READINESS-REPORT.md` | Current readiness state, completed repository evidence and remaining external proof. |
| `FINAL-READINESS-AUDIT.md` | Historical final audit notes and evidence summary. |
| `PLATFORM-APPLICATION-SEPARATION-AUDIT.md` | Boundary between infrastructure and hosted applications. |
| `SECURITY.md` | Security baseline, roles, secrets policy and recurring checks. |
| `THREAT-MODEL.md` | Assets, trust boundaries, primary threats and production non-negotiables. |
| `ENTERPRISE-MATURITY.md` | Enterprise maturity matrix and 30-point readiness model. |
| `ENTERPRISE-10-PLAN.md` | Enterprise roadmap and acceptance criteria. |

## Supporting Documents

| File | Use it for |
| --- | --- |
| `cloudflare/README.md` | Cloudflare edge, Access and origin-lock workflow. |
| `cloudflare/LIVE-CHANGES.md` | Cloudflare live-change audit notes. |
| `keycloak/README.md` | Keycloak import and realm bootstrap notes. |
| `minio/README.md` | MinIO setup and production exposure notes. |
| `secrets/README.md` | Infra Secret Manager files, rotation and Docker secret rules. |

## Source Of Truth Order

1. Current live server evidence, when refreshed safely and non-destructively.
2. Compose files and scripts in the current worktree.
3. Governance manifests under `governance/`.
4. Current reports under ignored `reports/`, when present and known fresh.
5. Documentation.

Documentation is not production evidence by itself. If docs disagree with
Compose, scripts or current live state, refresh the docs after verifying the
technical source.

## Read Before Common Tasks

| Task | Read first |
| --- | --- |
| Understand the platform | `README.md`, then `INFRASTRUCTURE-DEEP-DIVE.md`. |
| Work on the current reference server | `CURRENT-OPERATING-MODEL.md`, then `RUNBOOK.md`. |
| Prepare a new Ubuntu server | `VPS-PREDEPLOY-CHECKLIST.md`, then `RUNBOOK.md`. |
| Decide GO/NO-GO | `READINESS-REPORT.md`, `RUNBOOK.md`, `governance/production-go-no-go.json`. |
| Change Control Center | `INFRASTRUCTURE-DEEP-DIVE.md`, `control-center/tests/control-center.test.mjs`, `RUNBOOK.md`. |
| Change WAF/Traefik/DNS | `INFRASTRUCTURE-DEEP-DIVE.md`, `cloudflare/README.md`, `RUNBOOK.md`. |
| Change secrets | `secrets/README.md`, `SECURITY.md`, `RUNBOOK.md`. |
| Change backup/restore | `RUNBOOK.md`, `READINESS-REPORT.md`, `VPS-PREDEPLOY-CHECKLIST.md`. |
| Prepare release evidence | `RUNBOOK.md`, `FINAL-READINESS-AUDIT.md`, `governance/production-go-no-go.json`. |

## Safety Rules For Documentation Updates

- Do not paste secret values, tokens, passwords, private keys, dumps or backup
  contents.
- Document secret names, file paths and verification commands only.
- Keep hosted applications outside platform readiness unless the check validates
  an infrastructure capability.
- Mark LAN-only and dry-run evidence as non-production.
- Keep destructive operations separate and require explicit confirmation.
- Prefer current commands that create JSON/Markdown evidence under ignored
  `reports/`.
