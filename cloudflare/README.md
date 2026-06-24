# Cloudflare Enterprise Edge

The edge posture is code-first and additive-only. Do not run Cloudflare changes
against existing records or existing rulesets unless the exact resources have
been reviewed and approved.

- `from-zero.example.json` is the clean-zone bootstrap manifest.
- `scripts/cloudflare-from-zero.sh` creates only missing resources and refuses
  to modify existing DNS records or existing custom WAF rulesets. Zone settings
  are applied only when the zone is created by the same script run.
- `zone-waf-rules.json` defines reusable WAF rule content that blocks
  admin hosts, sensitive file probes and scanner paths before traffic reaches
  the VPS.
- `access-admin.example.json` defines Cloudflare Access self-hosted
  applications for admin consoles. `scripts/cloudflare-access-admin.sh`
  validates the manifest by default, creates only missing Access applications
  and policies with `--apply`, and verifies the live account with
  `--verifyRemote`. Both successful and failed live verifications write
  `reports/cloudflare-access/` evidence for audit and troubleshooting. MFA is
  enforced through the configured identity provider IDs.
- `zone-settings.json` lists safe zone settings plus manual-review items.
- `scripts/cloudflare-origin-lock-ufw.sh` must run on the VPS so direct-origin
  bypass is blocked at the host firewall.

Recommended live sequence:

1. Copy `from-zero.example.json` to a new manifest for a new zone or new host
   set.
2. Run `sh ./scripts/cloudflare-from-zero.sh --manifest <manifest>` and review
   the dry-run output.
3. Run with `--apply` only on a clean/new zone or for absent records. If a zone
   already exists, remove `settings` from the manifest and review them manually
   instead of letting automation change live settings.
4. Validate admin Access policy with
   `sh ./scripts/cloudflare-access-admin.sh --manifest cloudflare/access-admin.example.json`;
   on the live account use `--apply` only after replacing placeholders, then
   run `--verifyRemote`.
5. Confirm public hostnames work through Cloudflare.
6. Run `sudo sh ./scripts/cloudflare-origin-lock-ufw.sh --apply` on the VPS.
7. Remove old generic UFW `allow 80/tcp` and `allow 443/tcp` rules only after
   Cloudflare traffic is confirmed.
8. Keep phpMyAdmin, Grafana, Prometheus, Alertmanager, MinIO console and Traefik
   dashboard off public DNS.

Cloudflare WAF and the internal OWASP CRS WAF are intentionally both active:
Cloudflare filters at the CDN edge, while the local WAF protects the origin if
traffic reaches the VPS.
