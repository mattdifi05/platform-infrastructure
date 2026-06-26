# Admin Control Center

The Admin Control Center is the platform control plane. Its canonical host is:

```text
admin.<domain>
```

It is not `portal.<domain>`, `projects.<domain>` or `ui.<domain>`. Projects are an internal section.

## Modes

- Simple Mode: daily operations and concise status.
- Advanced Mode: detailed topology, governance, evidence and provider planning.

## Capabilities

- Overview
- Projects
- Applications
- Domains/Subdomains
- Web Spaces
- Resources
- Security
- Backups
- Logs/Alerts
- Release Evidence
- Go/No-Go
- Settings
- Advanced

## Adapter registry

Adapters expose plan, verify and apply semantics:

- `plan`: describes intended changes.
- `verify`: reads configuration or evidence.
- `apply`: must be guarded by explicit confirmation and a live backend implementation.

Without a live adapter, apply actions are rejected or metadata-only.

## Auth and state

Local development can disable admin auth. Staging and VPS profiles should set:

- `CONTROL_CENTER_AUTH_REQUIRED=true`
- `CONTROL_CENTER_ADMIN_PASSWORD_SHA256=<sha256>`

State and audit metadata are written under `projects-portal/state/`. Values are sanitized and should not include secrets.

## Docs UI

The docs surface is served by the same Node process and exposes whitelisted Markdown files only. Labels are intentionally human-readable for a maintainer.

## Related surfaces

Keycloak, storage and Grafana hosts can exist in protected profiles, but they are not required for local quickstart and should not be public admin surfaces by default.
