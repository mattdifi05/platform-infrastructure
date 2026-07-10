# Platform Feature Flags And Kill Switches

This document defines infrastructure-level kill switches. It does not claim
hosted application feature-flag coverage; application flags remain app-owned.

## Policy

Risky platform behavior must have an operator-owned disable path that does not
require code changes. A valid kill switch must define scope, owner, trigger,
disable action, recovery action and evidence.

## Kill Switch Matrix

| Switch | Scope | Trigger | Disable action | Recovery action | Evidence |
| --- | --- | --- | --- | --- | --- |
| Hosted app public exposure | One hosted application route | Abuse, broken deploy, data exposure risk | Stop/disable the app from Control Center or remove its Traefik/project-router route metadata. | Re-enable app after health and owner approval. | Control Center audit event and app status. |
| Project router boundary | All hosted workload routing | Routing leak or wildcard boundary failure | Recreate router with safe config or block project-router at Traefik/WAF layer. | Restore tested route config and rerun project-router tests. | `project-router-tests`, WAF smoke. |
| Admin portal public access | Control Center/admin surface | Suspicious admin activity or provider access issue | Enable provider Access/MFA requirement, block public route, or restrict to operator network. | Restore provider policy after audit. | `platform-admin-audit`, provider evidence. |
| Off-site backup upload | Restic/off-site provider writes | Provider credential issue, quota incident, corrupted remote | Set `BACKUP_SCHEDULER_ENABLE_OFFSITE=false` or remove remote credentials from scheduler env. | Re-enable after credential rotation and restore drill. | Backup scheduler report and DR evidence. |
| Release/deploy pipeline | Production deployment | Bad artifact, bad workflow, incident freeze | Disable production environment approval or revoke deploy secret. | Re-enable after release evidence and approval. | GitHub environment/audit evidence. |
| Alert delivery channel | External notification channel | Token leak, noisy provider, bad routing | Disable the affected Alertmanager receiver or rotate bearer/SMTP credentials. | Re-enable after send-test evidence. | `alert-evidence`. |
| WAF/rate limiting policy | Public edge filtering | False positives or attack spike | Switch to known-good WAF dynamic config or tighten/relax rate limit middleware. | Rerun WAF smoke and rate-limit evidence. | `waf-smoke`, `rate-limit-evidence`. |
| Managed secret materialization | Secret file rollout | Suspected secret leakage or bad rotation | Stop materialization/rotate affected secret and restart only dependent service. | Verify secret manager and service health. | `secret-rotation-evidence`, `infra-health`. |

## Verification

The platform verifies kill-switch readiness by checking that:

- each switch has an owner and an explicit disable action;
- disable actions are operational actions, not code changes;
- recovery requires evidence before re-enable;
- audit or report evidence exists for the affected control surface;
- application-owned feature flags are not counted as platform evidence.

## Operating Rules

- Use the smallest switch that removes the risk.
- Prefer route disable, provider access block or secret revocation before
  destructive action.
- Never delete volumes or backups as a kill switch.
- Keep a non-secret audit trail for every switch activation.
