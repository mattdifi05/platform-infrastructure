# Keycloak platform identity

`keycloak/import/platform-realm.json` is the first-boot realm contract. It is
validated against the pinned Keycloak 26.6.3 image and defines:

- brute-force protection with bounded temporary lockout;
- disabled password reset and remember-me;
- required WebAuthn user verification and discoverable credentials;
- a passwordless-only `platform-passkey-browser` flow;
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

Before binding the passkey-only browser flow on an existing realm:

1. verify a fresh Keycloak backup;
2. configure the exact real RP ID, identity origin, portal callback and client;
3. enroll at least two independent passwordless WebAuthn credentials for every
   administrator and for the separate break-glass identity;
4. remove any temporary bootstrap credential;
5. run `CONTROL_CENTER_PUBLIC_ORIGIN=https://portal.example.test
   CONTROL_CENTER_ADMIN_USERS=user1,user2 sh
   scripts/keycloak-passkey-readiness.sh`;
6. keep a second authenticated session while testing the first login;
7. apply the Control Center cutover only after the readiness command passes.

The readiness command also derives the exact Back-Channel Logout endpoint from
`CONTROL_CENTER_PUBLIC_ORIGIN` and requires all three client attributes to
match. It prints usernames and credential counts only; it does not print
passkey material, tokens or Keycloak passwords. A failed check must leave the
live Control Center image unchanged.

Back-Channel Logout covers provider-session termination. Account disable and
role changes use the separate signed Security Event Token consumer at
`/auth/provider-security-event`. The realm import and the back-channel helper
do not install a Keycloak event-listener/bridge for those two custom events.
That provider integration, retry path and real delivery test remain
`PROVIDER-EXTERNAL`; local tests prove only signature/claim validation,
subject-wide revocation and replay safety at the Control Center sink.
