# Application visibility through Cloudflare

The Control Center application detail offers Public, Private and Offline.
Private creates an exact-host Access application with one owner-email allow
policy. Every configured related hostname, including API hosts, is protected
and independently read back before a route is published. Offline removes the
managed DNS/route and retains Access. Public removes only the application's
owned Access resources after route verification. No other site is enrolled or
changed automatically.

This integration is disabled on a clean installation. Install a root-owned,
non-writable configuration at
`/etc/platform-infrastructure/cloudflare-visibility/projects.json` and mount it
read-only using `compose.application-visibility.yaml`. The existing protected
Cloudflare DNS zone admission is also required. Each admitted project declares:

```json
{
  "id": "example",
  "hostname": "example.com",
  "relatedHostnames": ["api.example.com"],
  "baseDomain": "example.com",
  "ownerEmail": "owner@example.com",
  "originService": "http://127.0.0.1:8080",
  "cloneOriginService": "http://127.0.0.1:18181"
}
```

The top-level object contains `accountId`, `tunnelId` and `projects`. Use the
actual account, tunnel and zone identities. Origin services must be exact,
reviewed loopback services; an unrelated hosting record cannot be adopted.
Configuration files and their directories remain root-owned and protected.
The separate token file is mode 0600 and readable by the Control Center UID;
mount it read-only. Keep credentials out of the repository, browser output and
catalog. Required token permissions are Account Access Apps/Policies Edit,
Account Cloudflare Tunnel Edit and Zone DNS Edit in the admitted account/zones.
Restrict token client IPs to the server's actual outbound addresses.

GET status and plans perform no writes. Changes require a fresh owner passkey,
CSRF validation, the exact reviewed revision and explicit confirmation. The
provider rejects conflicting ownership, broadened Access policies and stale
plans. It serializes its own tunnel writes and rechecks provider configuration
immediately before PUT; an independent external writer can still race that PUT.

Private copies derive `local.example.com` for an apex and
`local-api.example.com` for a subdomain. No extra domain purchase or WARP client
is required; Cloudflare Access authenticates the owner in the browser.
Cloning is a separate, opt-in host operator described in
[APPLICATION-OPERATOR.md](APPLICATION-OPERATOR.md). A copy is eligible only when
its data, dependencies and runtime have an explicit root-reviewed profile.
Installations with an exact signed backup membership must also admit clone
capture and recovery before enabling the operator. A catalog entry alone is
not backup coverage. Never enable a clone that would block existing backups.
