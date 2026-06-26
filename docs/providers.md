# Providers

`PROVIDER_PROFILE` describes environment behavior. It is not branding.

## Supported profiles

- `local`: developer workstation.
- `home-vps`: LAN/home server with Linux and Docker.
- `generic-vps`: provider-neutral VPS.
- `hostinger`: optional Hostinger profile.
- `aws`: future/provider-specific profile.
- `custom`: custom provider integration.

## Provider-neutral by default

The platform can run without Cloudflare or a specific VPS vendor. Provider scripts should support dry-run and evidence generation before apply.

## Provider evidence

Live provider evidence proves that the external system really exists and matches the intended state. Examples:

- DNS zone and records.
- Cloudflare Access applications.
- External uptime monitor status.
- GitHub branch protection and Actions runs.

Dry-run reports are useful diagnostics but do not satisfy production go/no-go.
