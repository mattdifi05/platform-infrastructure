# Control Center Administrative Authentication

## Invariant

The Control Center is fail-closed. Administrative access uses Keycloak OIDC
Authorization Code with PKCE and a passkey-only authentication flow. A local
password, password hash, shared secret, email OTP, SMS OTP or password fallback
is not a supported authentication path.

The only bypass mode is `test-disabled`. Startup accepts it only when
`NODE_ENV=test` and `CONTROL_CENTER_BIND_HOST` is a loopback address.

## Request flow

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

- `CONTROL_CENTER_AUTH_MODE=oidc-passkey`
- `CONTROL_CENTER_AUTH_STORE=postgres`
- external HTTPS issuer, authorization endpoint and callback URI
- internal token and JWKS endpoints reachable only by the control plane
- public client ID `platform-control-center`; no client secret
- required ACR `urn:platform:loa:passkey`
- required AMR `webauthn`
- session policy version, five-minute fresh-auth window and shared PostgreSQL
  login-start throttle
- database URL supplied only through
  `CONTROL_CENTER_AUTH_DATABASE_URL_FILE`

Apply `migrations/001_auth_sessions.sql`,
`migrations/002_session_security.sql`, and
`migrations/003_oidc_provider_revocation.sql` to the dedicated control-plane
PostgreSQL database before starting the service. The runtime identity requires
only CRUD access to `control_auth.oidc_transactions`,
`control_auth.sessions`, `control_auth.login_throttle`,
`control_auth.provider_event_tokens`, and `control_auth.provider_revocations`; schema
migration and backup identities remain separate.

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
