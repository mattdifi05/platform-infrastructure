# Cloudflare Live Changes

Date: 2026-06-23

## Reverted

The DNS proxy changes below were reverted immediately after review because the
existing Cloudflare state must not be changed while preparing the new
enterprise edge baseline.

Current verified state after revert:

- `project.example.com`
  - `ftp.project.example.com`: proxied.
  - `autoconfig.project.example.com`: proxied.
  - `autodiscover.project.example.com`: proxied.
  - `provider-mail-a._domainkey.project.example.com`: proxied.
  - `provider-mail-b._domainkey.project.example.com`: proxied.
  - `provider-mail-c._domainkey.project.example.com`: proxied.

- `portfolio.example.com`
  - `ftp.portfolio.example.com`: proxied.

## Superseded Change Log

Applied through the connected Cloudflare API:

- `project.example.com`
  - Set `ftp.project.example.com` to DNS-only.
  - Set `autoconfig.project.example.com` to DNS-only.
  - Set `autodiscover.project.example.com` to DNS-only.
  - Set `provider-mail-a._domainkey.project.example.com` to DNS-only.
  - Set `provider-mail-b._domainkey.project.example.com` to DNS-only.
  - Set `provider-mail-c._domainkey.project.example.com` to DNS-only.

- `portfolio.example.com`
  - Set `ftp.portfolio.example.com` to DNS-only.

This section is kept only as an audit trail of the temporary change that has
now been reverted.

Blocked by current Cloudflare token permissions:

- Zone settings such as `always_use_https`, `ssl`, `min_tls_version` and
  `brotli`.
- WAF custom ruleset entrypoint for `http_request_firewall_custom`.

The intended rules and settings are versioned in this directory:

- `zone-waf-rules.json`
- `zone-settings.json`
