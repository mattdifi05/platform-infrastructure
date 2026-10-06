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

## Portal page

When the optional FILE configuration is present, the existing sidebar includes
Cloudflare DNS (`/?section=cloudflare`). The page requires a fresh owner session
and is excluded from HTML caches. It loads the three scoped zone names and record
metadata from the API. Edit reads the original through the same owner/CSRF guarded
endpoint with `action:inspect`; DNS values appear only to that owner in the form
and plan, never in audit text or AI context. The form supports the five record
types above. Delete opens a review of the original record. Apply stays disabled
until the owner checks the confirmation box; changing form data invalidates the
plan. After success the inventory is refreshed and the page reports the actual
write/readback result. Reading the inventory alone never claims write success.

## Deployment smoke: real DNS reads without an owner session

After the reviewed source, protected FILEs and overlay are installed, run this
inside the actual UID-1000 Control Center. It invokes the production consumer
against the three real zone IDs. It prints only status and counts, never the
credential, record values, comments or raw provider response. It performs only
GETs. Do not fabricate an owner session or submit any DNS mutation for this test.

```sh
docker exec -i --user 1000:1000 enterprise-control-center node --input-type=module - <<'JS'
import { readCloudflareDnsStatus } from '/app/providers/cloudflare-dns.mjs';
const result = await readCloudflareDnsStatus();
const expected = ['matthewdifilippo.com', 'scriptastudents.com', 'stexor.com'];
const names = result?.zones?.map(zone => zone.name).sort();
const ok = result?.status === 'verified-dns-read'
  && JSON.stringify(names) === JSON.stringify(expected);
console.log(JSON.stringify({
  ok,
  status: result?.status || 'not-configured',
  zones: result?.zones?.map(({ name, recordCount }) => ({ name, recordCount })) || [],
  writePermissionVerified: false,
}));
if (!ok) process.exitCode = 1;
JS
```

Separately check container health and anonymous HTTP behavior (login, 401/403,
or 423 while first enrollment is incomplete; never a successful protected DNS
API response). After human passkey enrollment,
the owner can open the page and use Refresh to qualify the authenticated UI read
path. A successful direct consumer smoke does not prove owner login, HTTP/CSRF
policy, browser interaction, DNS writes or Access/Tunnel behavior. The local test
suite covers authorization and reviewed CRUD with simulated provider responses;
those tests are not live mutation evidence. Record the real smoke result only
once the command has actually succeeded on the deployed image.
