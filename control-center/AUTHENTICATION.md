# Control Center authentication

The Control Center owns its administrator authentication. It uses
SimpleWebAuthn for one passkey and PostgreSQL for the public credential,
one-use challenges, login throttling and revocable sessions. It does not use
Keycloak, OIDC callbacks, a bootstrap password or a client secret.

## First access

With `CONTROL_CENTER_FIRST_CONFIGURATION_MODE=required`, the first request is
redirected to `/first-configuration`. The page has one action: register a
passkey for the configured administrator. Successful WebAuthn verification
stores the credential public key in `control_auth.passkeys`, creates the
session and closes onboarding automatically. A second passkey is not required.

This is an intentional trust-on-first-use ceremony. Before a fresh start, set
`CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS` to the narrowest management
network that must perform enrollment (use a single-address CIDR when stable).
Exact host/origin checks and the management-network boundary are mandatory;
concurrent enrollment is serialized so only one credential can win.

The registration and login ceremonies require:

- the exact HTTPS `CONTROL_CENTER_PUBLIC_ORIGIN` and RP ID;
- the exact public Host header;
- a client address allowed by the management CIDR list;
- same-origin Fetch Metadata for every mutation;
- user presence and user verification;
- a one-use, peer-bound challenge.

## Sessions and reauthentication

The defaults for both maximum and idle session lifetime are 86,400 seconds.
After one day the session is invalid and the browser is sent to
`/auth/login`. Logout revokes the PostgreSQL row and redirects to that same
login page.

Sensitive operations use the route capability catalog and require an owner
session authenticated within `CONTROL_CENTER_FRESH_AUTH_SECONDS` (300 seconds
by default). Browser requests are redirected to the native passkey login;
JSON callers receive `admin_reauthentication_required` and the same reauth
URL. Mutations additionally require the double-submit CSRF token.

## Database

Apply the idempotent migration before the first start:

```sh
psql "$CONTROL_CENTER_ADMIN_DATABASE_URL" \\
  -v ON_ERROR_STOP=1 \\
  -f control-center/migrations/001_app_passkey.sql
```

The runtime URL is read only from
`CONTROL_CENTER_AUTH_DATABASE_URL_FILE`. The `control_center_runtime` role
receives CRUD on these active tables only:

- `control_auth.sessions`;
- `control_auth.login_throttle`;
- `control_auth.passkeys`;
- `control_auth.webauthn_challenges`.

The migration retains three harmless session columns used by databases
created before application-owned passkeys. They remain empty compatibility
fields; no OIDC runtime behavior depends on them. Existing legacy tables are
not dropped automatically and can be removed only in a separately backed-up
database maintenance operation.

## Required runtime configuration

```dotenv
CONTROL_CENTER_AUTH_MODE=app-passkey
CONTROL_CENTER_AUTH_STORE=postgres
CONTROL_CENTER_AUTH_DATABASE_URL_FILE=/run/secrets/control_center_database_url
CONTROL_CENTER_PUBLIC_ORIGIN=https://portal.platform-infrastructure.com
CONTROL_CENTER_AUTH_RP_ID=portal.platform-infrastructure.com
CONTROL_CENTER_AUTH_RP_NAME=Platform Control Center
CONTROL_CENTER_FIRST_CONFIGURATION_MODE=required
CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_USERNAME=admin
CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_EMAIL=admin@example.com
CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS=192.168.1.0/24,127.0.0.0/8,::1/128
CONTROL_CENTER_FIRST_CONFIGURATION_TRUSTED_PROXY_CIDRS=172.16.0.0/12,127.0.0.0/8,::1/128
CONTROL_CENTER_SESSION_MAX_AGE_SECONDS=86400
CONTROL_CENTER_SESSION_IDLE_SECONDS=86400
CONTROL_CENTER_FRESH_AUTH_SECONDS=300
```

`CONTROL_CENTER_AUTH_STORE=memory` and `test-disabled` are accepted only
with `NODE_ENV=test` on a loopback bind address.

## Verification

```sh
cd control-center
npm ci --ignore-scripts
npm test
npm run test:postgres-auth
```

The PostgreSQL integration test requires an isolated disposable database and
`TEST_DATABASE_DISPOSABLE=1`. Without `TEST_DATABASE_URL` it reports a clear
NOT RUN marker and performs no database operation.
