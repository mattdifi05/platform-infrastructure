# Platform Compliance Evidence Matrix

This matrix is non-secret governance evidence for the platform infrastructure.
It is not a legal certification and it does not claim formal GDPR, SOC2 or ISO
certification. Formal compliance still requires an external audit and the final
production provider evidence.

## Scope

In scope:

- Ubuntu host hardening, Docker Compose runtime and network boundaries.
- Traefik/WAF edge routing and admin access controls.
- Control Center operator actions, audit logs and metadata stores.
- Managed platform services: PostgreSQL, MariaDB, Redis, NATS, MinIO, Keycloak,
  Prometheus, Grafana, Loki and Alertmanager.
- Backup, restore, retention, secret-management and release evidence.

Out of scope:

- Hosted application business logic.
- Hosted application customer consent and legal basis.
- Hosted application account flows and app-owned datasets.
- External provider contractual/legal review.

## Control Matrix

| Area | Platform control | Evidence | Owner | Review cadence |
| --- | --- | --- | --- | --- |
| Access control | Admin surfaces require operator authorization and production MFA/provider policy. | `platform-admin-audit`, GitHub environment policy, Cloudflare Access evidence when provider is live. | Platform owner | Monthly and before go-live |
| Change management | Deploy and rollback are gated by runbook, branch protection and release evidence. | `release-evidence`, `rollback-release`, GitHub Actions reports. | Platform owner | Every release |
| Auditability | Control Center operations and platform audit events are append-only evidence. | `audit-log-evidence`, Control Center audit JSONL. | Platform owner | Monthly |
| Security monitoring | Alerts, logs and metrics are centralized and redacted. | `alert-evidence`, `retention-evidence`, Loki/Grafana config. | Platform owner | Monthly |
| Data retention | Logs, metrics and backup artifacts have bounded retention and restore gates. | `retention-evidence`, backup prune reports, restore drill reports. | Platform owner | Monthly |
| Backup and recovery | Platform backup families and restore drills are verified before production claims. | `dr-evidence`, backup reports, restore drill reports. | Platform owner | Before go-live and monthly |
| Secrets | Secrets stay out of Git and are stored through the vault/secret manager or external KMS. | `secret-rotation-evidence`, `managed-secrets-preflight`, secret scan reports. | Platform owner | Every rotation and release |
| Supply chain | SBOM, dependency hygiene, image signing and release provenance are required. | `generate-sbom`, `supply-chain-hygiene`, `sign-images`, release attestation. | Platform owner | Every release |
| Incident response | Runbook defines triage, evidence capture, restore, rollback and provider escalation. | `RUNBOOK.md`, DR reports, alert evidence. | Platform owner | Quarterly |
| Vulnerability disclosure | Private reporting and approved public disclosure process are documented. | `SECURITY.md`, vulnerability disclosure evidence report. | Platform owner | Quarterly |

## GDPR-Like Mapping

| Principle | Platform posture |
| --- | --- |
| Data minimization | Platform controls render metadata and evidence only; secrets and payload data are redacted. |
| Integrity and confidentiality | Admin access, secrets, WAF, least privilege and audit evidence protect infrastructure data. |
| Availability and resilience | Backup, restore drill, healthcheck and DR evidence cover platform availability controls. |
| Accountability | Reports under `reports/` and runbooks provide non-secret operational accountability. |
| Retention limitation | Retention evidence covers logs, metrics and backup artifact policy. |

## SOC2-Like Mapping

| Trust service area | Platform posture |
| --- | --- |
| Security | WAF, admin access controls, secret management, audit and supply-chain gates. |
| Availability | Healthchecks, backup scheduler, restore drills, DR evidence and alerting. |
| Processing integrity | Release evidence, rollback plans, CI checks and immutable artifact controls. |
| Confidentiality | Secret redaction, private reporting, vault-backed material and no public data stores. |
| Privacy | Hosted application privacy obligations are out of scope; platform avoids exposing personal data in evidence. |

## Approval

- Approved scope: platform-infrastructure only.
- Approved evidence type: non-secret repository governance plus generated reports.
- Formal certification: not claimed.
- External audit: required only when a customer, regulator or production contract requires it.
