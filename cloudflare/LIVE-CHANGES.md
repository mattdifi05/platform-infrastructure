# Cloudflare Live Changes

Date: 2026-06-23

## Reverted

The DNS proxy changes below were reverted immediately after review because the
existing Cloudflare state must not be changed while preparing the new
enterprise edge baseline.

Current verified state after revert:

- `fireport.top`
  - `ftp.fireport.top`: proxied.
  - `autoconfig.fireport.top`: proxied.
  - `autodiscover.fireport.top`: proxied.
  - `hostingermail-a._domainkey.fireport.top`: proxied.
  - `hostingermail-b._domainkey.fireport.top`: proxied.
  - `hostingermail-c._domainkey.fireport.top`: proxied.

- `matthewdifilippo.com`
  - `ftp.matthewdifilippo.com`: proxied.

## Superseded Change Log

Applied through the connected Cloudflare API:

- `fireport.top`
  - Set `ftp.fireport.top` to DNS-only.
  - Set `autoconfig.fireport.top` to DNS-only.
  - Set `autodiscover.fireport.top` to DNS-only.
  - Set `hostingermail-a._domainkey.fireport.top` to DNS-only.
  - Set `hostingermail-b._domainkey.fireport.top` to DNS-only.
  - Set `hostingermail-c._domainkey.fireport.top` to DNS-only.

- `matthewdifilippo.com`
  - Set `ftp.matthewdifilippo.com` to DNS-only.

This section is kept only as an audit trail of the temporary change that has
now been reverted.

Blocked by current Cloudflare token permissions:

- Zone settings such as `always_use_https`, `ssl`, `min_tls_version` and
  `brotli`.
- WAF custom ruleset entrypoint for `http_request_firewall_custom`.

The intended rules and settings are versioned in this directory:

- `stexor-zone-waf-rules.json`
- `zone-settings.json`
