# Keycloak platform identity

`keycloak/import/platform-realm.json` is the first-boot realm contract. It is
validated against the pinned Keycloak 26.6.3 image and defines:

- brute-force protection with bounded temporary lockout;
- disabled password reset and remember-me;
- required WebAuthn user verification and discoverable credentials;
- an unbound, passwordless-only `platform-passkey-browser` flow while the
  first-boot binding remains the built-in `browser` flow;
- the public `platform-control-center` client with exact callback, PKCE S256 and
  the built-in `oidc-amr-mapper`;
- the first-boot Back-Channel Logout reference attributes (exact URL, required
  session ID and offline-session revocation);
- owner, admin and viewer realm roles;
- seven-day non-secret user-event audit retention.

Import files do not overwrite an existing realm during normal startup. Changes
to the reference server therefore require a separately backed up and reviewed
Keycloak admin operation; editing this JSON alone is not runtime evidence. The
URL in the import is a localhost reference and must not be treated as the
production URL.

For an existing realm, derive and inspect the exact contract without applying
a change:

```sh
CONTROL_CENTER_PUBLIC_ORIGIN=https://portal.example.test \
  sh scripts/keycloak-backchannel-configure.sh
```

The command exits successfully when the three client attributes already match
and exits non-zero with `action=update-required` when they drift. After a fresh
Keycloak backup and review of that plan, the narrowly scoped update requires
both explicit gates:

```sh
CONTROL_CENTER_PUBLIC_ORIGIN=https://portal.example.test \
KEYCLOAK_BACKCHANNEL_APPLY=true \
KEYCLOAK_BACKCHANNEL_CONFIRM=CONFIGURE-OIDC-BACKCHANNEL-LOGOUT \
  sh scripts/keycloak-backchannel-configure.sh
```

The update is idempotent, changes only the three Back-Channel Logout client
attributes, and re-reads them before reporting `status=ready`. It keeps the
temporary `kcadm` credential file inside the Keycloak container and removes it
on exit. A local origin-only validation that does not inspect Docker is
available with `KEYCLOAK_BACKCHANNEL_VALIDATE_ONLY=true`.

## Existing-realm passkey reconciliation

The realm import is first-boot input only: Keycloak does not merge it into an
existing `platform` realm. Existing realms use
`scripts/keycloak-passkey-reconcile.mjs`; a successful import, by itself, is
never evidence that the live realm was updated.

The staged contract uses these exact public endpoints:

- identity origin and WebAuthn RP ID:
  `https://auth.platform-infrastructure.com` and
  `auth.platform-infrastructure.com`;
- OIDC issuer:
  `https://auth.platform-infrastructure.com/realms/platform`;
- Control Center origin and callback:
  `https://portal.platform-infrastructure.com` and
  `https://portal.platform-infrastructure.com/auth/callback`;
- Back-Channel Logout:
  `https://portal.platform-infrastructure.com/auth/backchannel-logout`;
- ACR and AMR: `urn:platform:loa:passkey` and exactly `webauthn`.

Before First Configuration, export the exact runtime values. The client-secret
variable must already name the deployment-owned, readable secret file; never
put the secret value on the command line or in this document.

```sh
export KEYCLOAK_REALM=platform
export KEYCLOAK_IDENTITY_ORIGIN=https://auth.platform-infrastructure.com
export KEYCLOAK_PASSKEY_RP_ID=auth.platform-infrastructure.com
export CONTROL_CENTER_PUBLIC_ORIGIN=https://portal.platform-infrastructure.com
export CONTROL_CENTER_OIDC_ISSUER=https://auth.platform-infrastructure.com/realms/platform
export CONTROL_CENTER_OIDC_REDIRECT_URI=https://portal.platform-infrastructure.com/auth/callback
export CONTROL_CENTER_OIDC_CLIENT_ID=platform-control-center
export CONTROL_CENTER_OIDC_REQUIRED_ACR=urn:platform:loa:passkey
export CONTROL_CENTER_OIDC_REQUIRED_AMR=webauthn
export CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_ID=platform-first-configuration
: "${CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE:?must name the deployment-owned secret file}"
export CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE
```

Inspect the current staged state, reconcile it only after the reviewed plan and
fresh backup, then re-run staged readiness:

```sh
KEYCLOAK_PASSKEY_ACTION=plan \
KEYCLOAK_PASSKEY_EXPECT_BINDING=staged \
  node scripts/keycloak-passkey-reconcile.mjs

KEYCLOAK_PASSKEY_ACTION=apply-staged \
KEYCLOAK_PASSKEY_CONFIRM=RECONCILE-PLATFORM-PASSKEY-STAGED \
  node scripts/keycloak-passkey-reconcile.mjs

KEYCLOAK_PASSKEY_READINESS_PHASE=staged \
  sh scripts/keycloak-passkey-readiness.sh
```

`apply-staged` leaves `realm.browserFlow=browser`. It creates or reconciles the
temporary confidential `platform-first-configuration` service client with
standard, implicit and direct grants disabled, an empty redirect/origin
surface, and only the `realm-management` roles `manage-clients`,
`manage-realm` and `manage-users`. Its assigned shared `roles` scope must have
the exact OIDC client-role access-token mapper and no role scope mappings. The
reconciler refuses to repair a modified shared scope globally.

The guided First Configuration flow is the sole normal owner of browser-flow
binding. It persists one exact owner subject, verifies at least two distinct
`webauthn-passwordless` credentials on that same enabled owner, the `owner`
realm role, and the operator's persisted confirmation that both authenticators
were tested and are independent. It then:

1. evaluates the reusable structural and enrollment contract without writes;
2. changes only `browserFlow` to `platform-passkey-browser`, as the final
   cutover write, and reads the complete cutover contract back;
3. rolls back only `browserFlow` to `browser` on any bind/read-back drift;
4. waits for a real Control Center callback that has already verified exact
   ACR, AMR and fresh `auth_time` before deleting password credentials and only
   the managed passwordless-registration required action;
5. completes the logout/relogin proof, then disables both the temporary client
   and its service account. A precise OAuth `invalid_client` is the bounded
   retry receipt when the terminal disable response was lost.

Do not run the reconciler's separately confirmed `bind` action concurrently
with the wizard. It exists only as a bounded recovery tool using the same
persisted subject and independence evidence; it is not a substitute for the
callback and finalization state machine.

After First Configuration is complete, terminal readiness expects the passkey
browser binding and the temporary client disabled. It deliberately does not
read the retired client secret:

```sh
: "${CONTROL_CENTER_ADMIN_SUBJECT:?must be the subject persisted by First Configuration}"
: "${CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_USERNAME:?must be the persisted owner username}"
export CONTROL_CENTER_ADMIN_SUBJECT
export CONTROL_CENTER_ADMIN_USERS=$CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_USERNAME
export CONTROL_CENTER_MIN_PASSKEYS=2
export KEYCLOAK_PASSKEY_INDEPENDENCE_CONFIRMED=true
export KEYCLOAK_PASSKEY_READINESS_PHASE=cutover
export KEYCLOAK_PASSKEY_EXPECT_BINDING=cutover
sh scripts/keycloak-passkey-readiness.sh
```

The emergency rollback is a separate, explicit operation and mutates only
`realm.browserFlow`:

```sh
KEYCLOAK_PASSKEY_ACTION=rollback-browser \
KEYCLOAK_PASSKEY_CONFIRM=ROLLBACK-PLATFORM-BROWSER-FLOW \
  node scripts/keycloak-passkey-reconcile.mjs
```

Rollback does not recreate a password, re-enable the temporary service client,
or change callbacks, RP/origin, flows, mappers, roles or credentials. Running
`apply-staged` after terminal completion would intentionally re-enable the
temporary client and therefore requires a new, explicitly authorized setup
cycle rather than a routine health check.

Readiness output contains only bounded identities, counts and drift labels. It
never prints passkey material, bearer tokens, client secrets or Keycloak
passwords. A failed check leaves the Control Center deployment unchanged.

Back-Channel Logout covers provider-session termination. Account disable and
role changes use the separate signed Security Event Token consumer at
`/auth/provider-security-event`. The realm import and the back-channel helper
do not install a Keycloak event-listener/bridge for those two custom events.
That provider integration, retry path and real delivery test remain
`PROVIDER-EXTERNAL`; local tests prove only signature/claim validation,
subject-wide revocation and replay safety at the Control Center sink.
