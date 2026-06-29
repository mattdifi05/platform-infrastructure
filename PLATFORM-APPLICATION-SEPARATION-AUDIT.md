# Platform / Applications Separation Audit

Generated for the platform-only readiness track.

## Scope

This repository is the Platform Infrastructure repository. It may contain:

- Docker and Compose infrastructure runtime.
- Control Center / Infrastructure Portal.
- Documentation and operational runbooks.
- Provider plans and manifests.
- Monitoring, security, backup, restore and governance tooling.
- Neutral examples and test fixtures.

Hosted applications do not live in this repository. They attach later through
external manifests, release image manifests or explicitly mounted source
directories.

## Classification

| Area | Classification | Status |
| --- | --- | --- |
| `compose*.yaml` base, WAF, VPS, staging, HA, DR, backup scheduler | Platform | Keep. Defines infrastructure services and overlays. |
| `control-center/` | Platform | Keep. Portal owns metadata-only Applications, readiness, providers, monitoring, backup, restore and audit views. |
| `project-router/` | Platform runtime capability | Keep internal. Supports optional external PHP/Node application routing; not production evidence for hosted apps. |
| `php-runtime-root/` and PHP Apache image | Platform runtime capability | Keep as neutral runtime root. Real PHP projects stay outside repo. |
| `docker/backend.Dockerfile`, `docker/web.Dockerfile`, `docker/worker.Dockerfile` | Platform runtime capability | Keep as historical generic build/runtime templates. Service ids `backend`, `web` and `worker-*` are not hosted application names. |
| `config/platform.example.json` | Example | Keep as neutral platform config example. |
| `config/project-manifest.example.json` | Example | Keep as neutral external application manifest example using `example-app`. |
| `monitoring/external-uptime*.example.json` | Example | Keep as provider-neutral examples. Live provider evidence must be supplied externally. |
| `cloudflare/*.example.json` | Example/provider plan | Keep. Dry-run/provider-plan only until explicit live authorization. |
| `control-center/tests/`, `project-router/tests/` | Fixture | Keep. Use neutral fixture names such as `example-app`, `php-demo`, `node-demo`; these are not hosted projects. |
| `projects-portal/state/.gitkeep` | Platform state placeholder | Keep only placeholder. Runtime state files remain uncommitted. |
| `reports/`, `backups/`, `.tmp/`, `.codex-backups/` | Runtime/generated artifacts | Do not commit. Existing local/server artifacts are evidence only. |
| Real hosted project names or databases | Hosted Application | Must stay outside repo. Current tracked sources do not reference known real hosted projects. |
| `PROJECTS_HOST`, `ACCOUNT_*`, `UI_*` compatibility variables | Legacy compatibility | Keep only where required by existing service interfaces or attached workload manifests. They are not platform go-live evidence. Defaults point to final reviewed hostnames or stay empty. |
| `*.sslip.io`, `account.*`, `ui.*`, `admin.*` production evidence | Legacy | Rejected by go/no-go as final platform evidence. |

## Final Host Contract

`Projects` and `Applications` are portal sections, not DNS hosts.

| Host | Purpose |
| --- | --- |
| `portal.<domain>` | Infrastructure Portal / Control Center |
| `docs.<domain>` | Documentation |
| `app.<domain>` | Public external application surface |
| `api.<domain>` | API |
| `auth.<domain>` | Authentication |
| `storage.<domain>` | Storage |
| `grafana.<domain>` | Grafana when protected and verified |

## Gate Rules

Local/platform evidence may satisfy repository, health, WAF, audit, backup,
restore, monitoring, retention, logs, provider-plan and Control Center gates.

The following must remain pending until live external evidence exists:

- Public DNS and HTTPS.
- Cloudflare Access or Cloudflare WAF verification.
- External uptime provider evidence.
- Off-site Restic backup/restore.
- Public edge load benchmark.
- GitHub verifyRemote and GitHub/Sigstore release attestations.

## Current Evidence Pointers

- Control Center supports zero Applications and renders `No applications attached.`
- `CONTROL_CENTER_DISCOVER_HOSTED_PROJECTS=false` by default.
- `production-go-no-go` ignores legacy public-load benchmark reports from non-final hostnames.
- Platform Admin Audit uses portal events only: login, logout, readiness access, providers access, monitoring access, verify, plan and metadata update.
