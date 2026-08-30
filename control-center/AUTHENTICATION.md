# Control Center Administrative Authentication

## Invariant

The Control Center is fail-closed. The V1 default is application-owned
WebAuthn (`CONTROL_CENTER_AUTH_MODE=app-passkey`): the browser talks directly to
the Control Center, SimpleWebAuthn verifies the assertion, and only the
credential public key/counter plus opaque sessions are stored in the dedicated
PostgreSQL `control_auth` schema. There is no Keycloak redirect, impersonation,
bootstrap token or client secret in this mode. A local password, password hash,
email OTP, SMS OTP or password fallback is not a supported authentication path.

`oidc-passkey` remains an explicitly selected compatibility mode for deployments
that still use an external identity provider; it is not required by the direct
V1 flow described below.

The only bypass mode is `test-disabled`. Startup accepts it only when
`NODE_ENV=test` and `CONTROL_CENTER_BIND_HOST` is a loopback address.

## Application-owned request flow (`app-passkey`)

1. `GET /first-configuration` is available only on the exact portal host and
   management LAN. Its single action calls `POST /auth/passkey/register/options`.
2. The browser invokes `navigator.credentials.create()` with resident,
   user-verifying credentials. The response is sent to
   `POST /auth/passkey/register/verify`; the one-use, peer-bound challenge is
   consumed and verified against the exact `CONTROL_CENTER_PUBLIC_ORIGIN` and
   RP ID.
3. The verified credential public key, counter and authenticator metadata are
   stored in PostgreSQL. One credential is sufficient and remains registered
   independently from the daily session (`CONTROL_CENTER_PASSKEY_TTL_SECONDS`,
   default ten years).
4. Registration creates an opaque 24-hour session. Subsequent login uses
   `POST /auth/passkey/login/options` and `POST /auth/passkey/login/verify`; a
   successful assertion updates the counter and creates a fresh session.
5. State-changing requests still require the exact portal Origin,
   `Sec-Fetch-Site: same-origin` and the session CSRF token. Challenge and
   login-start throttles are persisted in PostgreSQL.

The application flow never calls Keycloak. The `/auth/callback`, handoff and
OIDC provider-event endpoints are unavailable in this mode.

## External OIDC request flow (`oidc-passkey` compatibility mode)

1. `GET /auth/login` creates a cryptographically random state, nonce and PKCE
   verifier. Only hashes of state and nonce are retained; the transaction has a
   five-minute maximum lifetime.
2. The browser is redirected to the exact configured Keycloak issuer with
   `code_challenge_method=S256`, the required passkey ACR and `prompt=login`.
3. `GET /auth/callback` atomically consumes state, exchanges the code through
   the exact issuer-scoped HTTPS Keycloak endpoint and validates signature, issuer, audience,
   nonce, expiry, authentication time, ACR, AMR and Control Center role.
   Token exchange rejects HTTP redirects instead of forwarding the
   authorization code to a redirect target.
4. The browser receives an opaque `__Host-platform_cc_session` cookie. Only its
   SHA-256 hash is stored in PostgreSQL.
5. Logout revokes the server-side row before clearing the cookie. Replaying the
   previous cookie is rejected.
6. `POST /auth/backchannel-logout` accepts only a bounded, signed OIDC Logout
   Token from the exact issuer. It validates audience, age, event, replay JTI,
   and issuer-scoped `sid` or `sub`, then atomically revokes matching sessions.
   A revocation watermark prevents an older identity-provider session from
   racing the logout signal and creating a new local session.
7. `POST /auth/provider-security-event` accepts only a bounded, signed Security
   Event Token (`application/secevent+jwt`) from the same exact issuer and
   singleton audience, with protected type `secevent+jwt`. The closed event vocabulary contains account-disabled and
   authorization-changed. Both are subject-wide: all local sessions are
   revoked so a new login must obtain current account and role claims.

Malformed, expired, wrongly signed or otherwise invalid provider tokens receive
a generic 4xx rejection. Transient JWKS or database failures receive 503 so the
provider can retry. If revocation commits but the accepted audit append fails,
the endpoint reports a retryable audit-unavailable 503 and never mislabels the
committed operation as an unchanged-token rejection. Replay receipts make that
retry idempotent.

Administrative sessions have a hard maximum lifetime of 15 minutes. The local
consumer for signed account and role events is implemented and fail-closed, but
Keycloak does not gain that custom event-delivery integration from a realm
import or from Back-Channel Logout configuration. Provider-side production and
delivery of both event types is `PROVIDER-EXTERNAL` until independently proved.
Without that external proof, account and role changes remain bounded by the
15-minute lifetime and must not be described as instantaneously revalidated.

Every state-changing request also requires the exact configured portal Origin,
`Sec-Fetch-Site: same-origin` and a random CSRF token bound to the server-side
session. The browser receives that token in a host-only Secure SameSite=Strict
cookie and echoes it in `X-CSRF-Token`; it is never accepted as authentication.
Request bodies are limited to 64 KiB at the Node boundary.

No access token, ID token, passkey credential or raw browser session token is
persisted by the Control Center.

## Role policy

| Keycloak role | Effective role | Read | Normal mutation | Sensitive operation |
| --- | --- | --- | --- | --- |
| `viewer` | viewer | yes | no | no |
| `admin` | admin | yes | yes | no |
| `owner` | owner | yes | yes | yes, subject to fresh re-auth in T02 |

Sensitive operations include Vault access, database administration, backup or
restore, identity administration, settings and temporary database UIs. They
require an OIDC `auth_time` no older than five minutes; otherwise the API
returns 428 with a passkey re-authentication URL.

Authorization resolves an exact HTTP method and route identity after applying
the same `/control/v1/*` normalization as the API dispatcher. The complete
catalog classifies every implemented Control read and mutation. Its fresh-owner
entries cover Vault inventory/store/import/reveal/delete, database creation and
per-database backup, and backup file enumeration/preview/run/delete under both
`/control/*` and `/control/v1/*`. Overview and parameterized Advanced detail
reads use the same boundary because they project backup records or inventory.
Dynamic identifiers occupy one exact route segment; longer, shorter, or
similarly named paths do not match.
Legacy Vault, database, backup, identity, settings, and temporary database UI
actions retain the same fresh-owner boundary. The HTML shell at `/` and
`/index.html` is also fresh-owner-only because it constructs a single context
containing Vault and backup metadata; every non-GET method on those two paths is
denied. Every unclassified Control method or route fails closed with
`endpoint_capability_denied` before CSRF/body parsing, context construction, or
handler execution. Adding any Control endpoint therefore requires an explicit
catalog entry and role-matrix test.

## Required configuration

For the V1 direct flow:

- `CONTROL_CENTER_AUTH_MODE=app-passkey`
- `CONTROL_CENTER_AUTH_STORE=postgres`
- exact HTTPS `CONTROL_CENTER_PUBLIC_ORIGIN` (for this deployment,
  `https://portal.platform-infrastructure.com`)
- `CONTROL_CENTER_AUTH_RP_ID` equal to that host (or an explicitly intended
  parent suffix) and `CONTROL_CENTER_AUTH_RP_NAME`
- `CONTROL_CENTER_FIRST_CONFIGURATION_MODE=required`
- ten-year passkey registration (`CONTROL_CENTER_PASSKEY_TTL_SECONDS`, default
  `315360000`) with one-day session limits (default `86400`)
- database URL supplied only through
  `CONTROL_CENTER_AUTH_DATABASE_URL_FILE`
- management and trusted-proxy CIDRs; the first registration remains LAN-bound

The application connects with the dedicated `control_center_runtime` role.
Apply `migrations/001_auth_sessions.sql`, `migrations/002_session_security.sql`,
`migrations/003_oidc_provider_revocation.sql` (session/throttle tables remain
shared), `migrations/004_first_configuration.sql`, and
`migrations/006_app_passkeys.sql` before starting the service. Migration 006
creates the public-key and one-use challenge tables and grants only bounded CRUD
to the runtime role.

When `CONTROL_CENTER_AUTH_MODE=oidc-passkey` is explicitly selected, also supply
the external HTTPS issuer, authorization/token/JWKS endpoints and the OIDC
client settings described in the compatibility section above.

Apply `migrations/001_auth_sessions.sql`,
`migrations/002_session_security.sql`, and
`migrations/003_oidc_provider_revocation.sql` to the dedicated control-plane
PostgreSQL database before starting the service. A LOCAL_PRIVATE deployment
with guided First Configuration must also apply
`migrations/004_first_configuration.sql`. Migration 004 fails closed unless
the dedicated `control_center_runtime` PostgreSQL role already exists, then
grants that role the bounded CRUD access required by both authentication and
First Configuration. The application must connect with that same runtime role;
the migration identity must remain separate.

Outside First Configuration, the runtime identity requires only CRUD access to `control_auth.oidc_transactions`,
`control_auth.sessions`, `control_auth.login_throttle`,
`control_auth.provider_event_tokens`, and `control_auth.provider_revocations`; schema
migration and backup identities remain separate.

## LOCAL_PRIVATE guided First Configuration

With `app-passkey`, First Configuration is intentionally reduced to one
network-bounded action: open the exact portal URL, press **Registra la
passkey**, complete the normal browser authenticator prompt, and continue. The
first verified credential immediately closes the setup state; there is no
administrator handoff, external origin, second-passkey requirement or
Keycloak/impersonation step. The credential and its counter are retained in
PostgreSQL for one day, after which the setup/login flow can require a new
registration.

The remainder of this section documents the separate `oidc-passkey`
compatibility mode and is not part of the direct V1 path.

Guided First Configuration is enabled only with
`CONTROL_CENTER_FIRST_CONFIGURATION_MODE=required` and a LOCAL_PRIVATE
`CONTROL_CENTER_ENV`. It is not a second authentication mode. Until its
persistent state reaches `FIRST_CONFIGURATION_COMPLETE`, the Control Center
allows only health, OIDC/provider callbacks and the bounded
`/first-configuration` workflow; all other application reads redirect to the
workflow and API or mutation requests fail with 423.

The deployment supplies two separate root-owned secrets: a high-entropy
bootstrap code and the temporary Keycloak service-client secret. Neither is an
environment value or persisted in clear text. The bootstrap code is accepted
only from the configured management CIDRs, exact HTTPS host and exact same
origin. A successful use revokes every earlier setup session. While setup is
incomplete, replacing the deployment-owned bootstrap secret rotates its hash
and revokes all setup sessions, providing an explicit recovery path without a
permanent bypass.

The closed workflow is:

1. reconcile the exact staged Keycloak realm/client/flow structure while the
   realm still uses the ordinary `browser` flow;
2. confirm the one configured owner subject and issue a temporary password
   solely for personal Account Console enrollment;
3. require at least two `webauthn-passwordless` credentials for that exact
   subject and the operator's explicit confirmation that both were tested and
   are independent;
4. verify the exact passkey readiness contract, then bind
   `platform-passkey-browser` as the realm browser flow;
5. require a real Control Center callback carrying the exact passkey ACR and
   AMR before removing the temporary password and required enrollment action;
6. revoke the resulting local session, require a second real passkey login,
   then disable the temporary Keycloak service client and close First
   Configuration.

The finalization transition is persistent and retryable. A process or network
failure must leave `FIRST_CONFIGURATION_FINALIZING`, never report completion,
and allow the authenticated operator to retry the idempotent service-client
disable. Completion is recorded only after the client is disabled (or the
precise post-disable `invalid_client` result is observed during recovery).

Before personal enrollment the only truthful operational state is
`ACTIVE / FIRST CONFIGURATION READY / USER ACTION REQUIRED`. Deployment or
automated tests must not describe passkey authentication as active or complete
until the two user-controlled credentials, first login, logout revocation and
second login have all succeeded.

## Keycloak contract

Keycloak 26.6.3 on the reference server exposes the supported provider IDs
`webauthn-authenticator-passwordless` and `oidc-amr-mapper`. The final realm
configuration must:

- require user verification and discoverable passwordless credentials;
- send Back-Channel Logout Tokens to
  `https://<control-center-host>/auth/backchannel-logout`, include the OIDC
  session ID, and revoke offline sessions;
- deliver signed subject-wide Security Event Tokens for account disable and
  authorization change to
  `https://<control-center-host>/auth/provider-security-event`; this requires a
  separately reviewed Keycloak event-listener/bridge and remains
  `PROVIDER-EXTERNAL` until its issuer, audience, retry and delivery receipts
  are captured;
- bind RP ID and allowed origin to the real identity host;
- use a browser flow with no password, OTP or recovery-code execution;
- add the AMR mapper to the Control Center client;
- assign only `owner`, `admin` or `viewer` to authorized administrators;
- disable direct grants and use exact redirect URIs with PKCE S256;
- enable brute-force protection and bounded lockout in T02;
- keep a separate LAN-only break-glass identity protected by a dedicated
  hardware passkey.

Every administrator, including break-glass, must have at least two independent
passkeys before production cutover. The current live realm has no platform
users or passkeys, so deploying the fail-closed image before enrollment would
cause an administrative lockout.

`scripts/keycloak-passkey-readiness.sh` is the fail-closed runtime verifier. It
checks realm lockout policy, the passwordless flow, PKCE client, AMR mapper,
authorized role and at least two passwordless credentials for every username
listed in `CONTROL_CENTER_ADMIN_USERS`. It also derives
`<CONTROL_CENTER_PUBLIC_ORIGIN>/auth/backchannel-logout` and requires the exact
URL, session-required and offline-revocation attributes on the unique client.
It never prints credential material.

Realm imports do not update an existing client. Use the read-only plan and the
explicitly confirmed, idempotent updater documented in `keycloak/README.md`:

```sh
CONTROL_CENTER_PUBLIC_ORIGIN=https://portal.example.test \
  sh scripts/keycloak-backchannel-configure.sh

CONTROL_CENTER_PUBLIC_ORIGIN=https://portal.example.test \
KEYCLOAK_BACKCHANNEL_APPLY=true \
KEYCLOAK_BACKCHANNEL_CONFIRM=CONFIGURE-OIDC-BACKCHANNEL-LOGOUT \
  sh scripts/keycloak-backchannel-configure.sh
```

Editing `keycloak/import/platform-realm.json` or passing local tests is not
evidence that an existing Keycloak realm has this runtime configuration.

## PostgreSQL integration verification

`npm run test:postgres-auth` is safe to invoke without a configured database;
it reports `POSTGRES_AUTH_STORE_PROVIDER_REVOCATION_NOT_RUN`. The real integration run
requires an explicitly disposable PostgreSQL database because it drops and
recreates `control_auth`:

```sh
TEST_DATABASE_URL=postgresql://... \
TEST_DATABASE_DISPOSABLE=1 \
  npm run test:postgres-auth
```

The integration covers migration 003, issuer isolation, provider-event replay,
`sid` and subject revocation, stale-versus-fresh post-event authentication, and
both deterministic create-session/revocation transaction orderings.

## Cutover gate

Before the live recreate:

1. back up Keycloak and the control-plane database and verify both artifacts;
2. apply all three auth database migrations with the migration identity;
3. run the Back-Channel Logout plan, review it, apply it with both confirmation
   gates, and rerun the plan until it reports `status=ready`;
4. configure the remaining exact client settings, AMR mapper and passkey-only
   flow;
5. enroll and verify two independent passkeys for each administrator;
6. verify the separate break-glass identity from the allowed management path;
7. run `keycloak-passkey-readiness.sh` with the exact
   `CONTROL_CENTER_PUBLIC_ORIGIN` and require `backchannel=exact`;
8. build and identify the immutable Control Center image;
9. render Compose and confirm there is no password verifier or source bind;
10. keep a second authenticated browser session while testing the first;
11. require anonymous GET and POST to return 401, viewer mutation to return 403,
    owner login to succeed, browser logout replay to return 401, and a signed
    Back-Channel Logout Token to revoke only its issuer-scoped session while a
    duplicate JTI remains idempotent.
12. keep account-disable and authorization-change delivery explicitly
    `PROVIDER-EXTERNAL` until two signed provider-originated test events revoke
    all sessions for only their target subject and duplicate delivery is
    idempotent.

If cutover fails, do not restore the anonymous image on a public route. Remove
the portal route or restrict it to the management LAN while restoring the
previous image and Keycloak/database backups.
