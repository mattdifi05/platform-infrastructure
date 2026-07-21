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

Apply `migrations/001_auth_sessions.sql` and
`migrations/002_session_security.sql` to the dedicated control-plane
PostgreSQL database before starting the service. The runtime identity requires
only CRUD access to `control_auth.oidc_transactions` and
`control_auth.sessions`; schema migration and backup identities remain
separate.

## Keycloak contract

Keycloak 26.6.3 on the reference server exposes the supported provider IDs
`webauthn-authenticator-passwordless` and `oidc-amr-mapper`. The final realm
configuration must:

- require user verification and discoverable passwordless credentials;
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
listed in `CONTROL_CENTER_ADMIN_USERS`. It never prints credential material.

## Cutover gate

Before the live recreate:

1. back up Keycloak and the control-plane database and verify both artifacts;
2. apply the database migration with the migration identity;
3. configure the exact client, AMR mapper and passkey-only flow;
4. enroll and verify two independent passkeys for each administrator;
5. verify the separate break-glass identity from the allowed management path;
6. build and identify the immutable Control Center image;
7. render Compose and confirm there is no password verifier or source bind;
8. keep a second authenticated browser session while testing the first;
9. require anonymous GET and POST to return 401, viewer mutation to return 403,
   owner login to succeed and post-logout replay to return 401.

If cutover fails, do not restore the anonymous image on a public route. Remove
the portal route or restrict it to the management LAN while restoring the
previous image and Keycloak/database backups.
