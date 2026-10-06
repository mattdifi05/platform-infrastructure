# VPS Cloudflare DNS token integration

The existing Control Center provider connection and Vault entries are metadata and
encrypted storage, not Cloudflare API consumers. This optional adapter consumes a
protected FILE reference directly, without copying a token into portal state,
process environment values, audit logs or Vault reveal routes.

Use the user-approved permanent API token (no expiration), with Zone DNS Edit
restricted to exactly `stexor.com`, `scriptastudents.com` and
`matthewdifilippo.com`. Fireport is excluded. No account, Access, tunnel, WAF or
NAS credential is accepted or required. The adapter supports DNS inventory and explicitly reviewed record changes.
No bulk import, zone creation, or provider policy change is implemented.

Root provisioning after review:

- `/etc/platform-infrastructure/cloudflare-dns` root-owned mode 0700.
- `api-token` owner UID 1000, mode 0400; deliver only through the approved protected
  channel, never a command-line value or committed environment file.
- `zones.json` root-owned mode 0444, containing `{"zones":[{"name":"stexor.com",
  "id":"<actual-zone-id>"}, ...]}` with all three exact names and distinct actual
  32-character zone IDs. Obtain IDs from the authorized dashboard; no Zone Read
  permission is needed when IDs are configured explicitly.
- Append `deployment/cloudflare-dns/compose.control-center.yaml` to the existing
  complete core + AI + backup Compose chain. Rebuild only Control Center and
  preserve its current auth/proxy settings. Refresh actual admin/backup container
  pins afterwards. No timer, capture or FTP activation follows from this overlay.

The existing owner:fresh `GET /control/advanced/cloudflare` returns
`data.dnsIntegration`. With no optional config it preserves the previous response.
A configured adapter reports actual DNS GET verification, per-zone counts and
record names/types/proxy/TTL, omitting contents/comments and token material.
Failures report unavailable, not a configured/verified success. Account policy,
expiry and write permission are not inferred from a successful DNS read.

The adapter contacts only fixed HTTPS Cloudflare DNS record endpoints, rejects
redirects, bounds pagination and requests, and never calls Access/Tunnel APIs.
The temporary Access-app deletion token must never be installed in these paths.
`POST /control/cloudflare/dns/change` uses the existing owner:fresh and CSRF
checks. Supply `zoneId`, `action` (`create`, `update`, `delete`), `recordId` for
update/delete and `record` for create/update. Editable record fields are `type`,
`name`, `content`, `ttl`, `proxied`, and MX `priority`; types A/AAAA/CNAME/TXT/MX
only. Mail/TXT records require `proxied:false`. NS and NAS names are excluded.

The default request is a live read-only plan returning the complete original
record, requested fields, revision and `confirmationRequired`. After reviewing
these, submit the same request with `apply:true`, `expectedRevision` equal to the
plan revision and `confirm` equal to its confirmation string. A changed remote
record invalidates the plan. The adapter PATCHes only selected fields, preserving
other provider metadata, and verifies the resulting record or deletion with GET.
It rejects conflicting CNAME/NS records, exact duplicates and duplicate SPF.
Cloudflare has no transactional compare-and-swap in this flow; coordinate other
DNS writers during the short review/apply window. Timeout or verification failure
means read current state before retrying; the adapter never retries mutations.

Successful inventory proves DNS read access only; `writePermissionVerified:false`
remains explicit until an actual authorized change succeeds. Token permissions
and absence of expiration are set in Cloudflare, not inferred by the adapter.

Cloudflare documents DNS Read or DNS Write as sufficient for this endpoint:
https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/
