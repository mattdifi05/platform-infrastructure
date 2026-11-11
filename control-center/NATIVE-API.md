# Native Control Center API

The native client uses JSON HTTPS requests and AuthenticationServices passkeys.
It does not load dashboard HTML or depend on browser login. The existing
`/control/...` JSON API (also `/control/v1/...`) remains canonical for operations.
The application file manager is excluded from native capabilities. Existing
plan/apply, role, CSRF, freshness, Vault revision and destructive-operation gates
continue to apply; HTTP 202 is acceptance/planning, not proof of completion.

## Domain association and request headers

Set `CONTROL_CENTER_APPLE_ASSOCIATED_APP_IDS` to an explicit comma-separated
list of application identifier prefixes and bundle identifiers. The reviewed
development identity is `MPN7YVX5FY.com.stexor.controlcenter`. There is no default
association, wildcard, caller-provided application identity, or extra trusted
WebAuthn origin. A missing setting returns an empty association list.

`GET /.well-known/apple-app-site-association` returns
`{"webcredentials":{"apps":[...]}}` anonymously on the exact configured public
host. It must be routed directly to this service over HTTPS, with no redirect
or intermediary login, including for Apple's associated-domain CDN. This public
association endpoint intentionally does not require management-LAN admission;
authentication and operation endpoints retain configured network restrictions.

The signed app entitlement must contain `webcredentials:<rpId>`.
[Apple's passkey documentation](https://developer.apple.com/documentation/authenticationservices/supporting-passkeys)
requires associated domains for native assertions and registration.
[Apple's association documentation](https://developer.apple.com/documentation/xcode/supporting-associated-domains)
describes the matching application identifier and HTTPS/no-redirect requirements.
The server continues to verify the unmodified client data against its exact
configured HTTPS origin and RP ID; verify the first real device ceremony before
claiming production compatibility, especially if the configured RP ID is a
parent domain rather than the public API hostname.

Every mutation sends `Origin: <CONTROL_CENTER_PUBLIC_ORIGIN>`,
`Sec-Fetch-Site: same-origin`, `Accept: application/json`, and JSON content type.
Authenticated mutations additionally send `X-CSRF-Token: <bootstrap.csrfToken>`
and the session/CSRF cookie pair. These headers are request validation, not app
attestation; authorization still requires a cryptographically verified passkey
session. No CORS permission or missing-origin exemption is introduced.

## Native passkey authentication

1. `GET /auth/native/bootstrap` returns
   `{schemaVersion:1,authentication:{mode,origin,rpId,freshAuthSeconds,associationConfigured},firstConfiguration:{required,complete}}`.
   It exposes no session, passkey identifiers or private configuration.
2. `POST /auth/passkey/login/options` with `{}` returns `{options}`. Decode
   `options.challenge` from base64url to Data; initialize
   `ASAuthorizationPlatformPublicKeyCredentialProvider` with `options.rpId`.
   Pass the allowed credential IDs and require user verification.
3. Submit the assertion to `POST /auth/passkey/login/verify`:

```json
{
  "challenge": "original-options-challenge-base64url",
  "credential": {
    "id": "credentialID-base64url",
    "rawId": "credentialID-base64url",
    "type": "public-key",
    "response": {
      "clientDataJSON": "rawClientDataJSON-base64url",
      "authenticatorData": "rawAuthenticatorData-base64url",
      "signature": "signature-base64url",
      "userHandle": "userID-base64url"
    },
    "clientExtensionResults": {}
  }
}
```

All Data fields use unpadded base64url. Preserve Apple's raw clientDataJSON
bytes exactly. Verification responds `{ok:true,redirect:"/"}` and sets
`__Host-platform_cc_session` (HttpOnly) and `__Host-platform_cc_csrf` cookies.
The native client ignores `redirect` and retains both cookies in its URLSession
cookie store. Challenges are short-lived, single-use and bound to the admitted
peer; changing network during a ceremony can require restarting it.

4. `GET /api/native/v1/bootstrap` requires the session and returns
   `{schemaVersion:1,authentication,session:{subject,email,displayName,role,roles,authTime,expiresAt},csrfToken,capabilities}`.
   Each capability contains `{method,operationId,capability,template,allowed,requiresFreshAuthentication}`.
   Metadata comes from the same authorization catalog used for dispatch. The
   server enforces permissions regardless of displayed capability metadata.
5. `POST /logout` with JSON Accept, cookies and CSRF returns `{ok:true}` and
   revokes the server session and expires its cookies.

HTTP 401 means authenticate again. HTTP 428 with
`error: "admin_reauthentication_required"` means repeat the same native passkey
ceremony, accept the replacement cookies, refetch bootstrap for its new CSRF,
then retry the reviewed action. Never navigate to `reauthUrl` from native UI.
HTTP 403 is a permission/origin/CSRF rejection and must not trigger a retry loop.

First enrollment uses the existing guarded JSON register/options and
register/verify endpoints only when first configuration is enabled/incomplete.
Both include `bootstrapToken`; verify includes `{challenge,bootstrapToken,credential}`,
whose response contains `clientDataJSON`, `attestationObject`, and optional
`transports:["internal"]`. Existing approved-CIDR and expiring token gates remain.

## Host chart history

`GET /control/v1/resources/host/history` returns `{samples}` with at most 25
observations at two-second intervals over the last 46 seconds plus one preceding
point, covering the native chart's delayed 40-second presentation. Each sample has `capturedAt` (UTC evaluation time) and nullable numeric
fields `cpu`, `memory`, `disk`, `receive`, `send`, `diskRead`, and `diskWrite`.
CPU, memory, and disk capacity are percentages. Transfer rates are bytes per
second. Stale or unreachable exporter samples are omitted. The live endpoint's
`observedAt` uses the server clock; `freshness.sampledAt` remains the actual
exporter scrape time.

## Native catalog and command facades

`GET /api/native/v1/applications` returns
`{projects,applications,observed,folders,databases,engines,destructiveOperations,resources,redis}`.
`folders` is the existing applicationFolderCatalog object. Each database may
include `adminTool:{label,url}` for a separate phpMyAdmin/phpPgAdmin browser tool;
the native app's URLSession cookies are not automatically shared with Safari.
These optional external tools are independent of native authentication.

`POST /api/native/v1/database-command` and `/api/native/v1/database-delete-command`
require a fresh owner session and accept the exact existing database command
payload. Actions are `create`, `update`, `credential`, `backup`, `restore`,
`delete`, `delete-approve`, `delete-execute`, and `delete-now`. The last action is
accepted only through the separate database-delete-command route. Existing
confirmation strings, current evidence, recovery and principal-ownership checks
remain authoritative. These routes always return JSON, including validation
errors, without redirecting to dashboard pages.

Redis facades use the existing verified backup implementation:

| Route under `/api/native/v1/` | Body | Capability |
| --- | --- | --- |
| `redis-backup-command` | `{action:"backup"}` | admin |
| `redis-restore-command` | `{action:"restore",backupId}` | owner:fresh |
| `redis-backup-delete-command` | `{action:"delete",backupId}` | owner:fresh |

`GET /control/vault` (owner) additionally returns `revision`, safe project
identifiers/names and `runtime` catalog metadata alongside `items` and `overview`.
No encrypted payloads or plaintext values are included. Existing
`POST /control/vault/secrets/:id/versions` accepts
`{itemId,newValue,expectedVaultRevision}` and returns encrypted-version metadata.
Reveal remains a separate fresh-owner action; it is never part of bootstrap or
catalog responses.

## Complete operation inventory

The machine-readable inventory is `bootstrap.capabilities`, generated directly
from `listNativeRouteDefinitions()` in `auth/route-capabilities.mjs`. It covers
status/events, applications/folders/hosting, domains/network, webspaces,
databases, storage, secret materials/Vault/runtime, workers/queues/schedules,
identity, runtime/host updates, resources, monitoring, security, logs/alerts,
providers, settings/readiness, backup/restore, deployments, adapters, operations
and audit. Route templates include named resource parameters and exact methods.
Internal ForwardAuth routes and the dashboard/file-view/browser-admin login
routes are excluded. Existing JSON-capable legacy POST routes remain available
for controls whose command payload has not yet gained a dedicated Control API.
