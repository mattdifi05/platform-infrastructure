# Keycloak platform identity

`keycloak/import/platform-realm.json` is the first-boot realm contract. It is
validated against the pinned Keycloak 26.6.3 image and defines:

- brute-force protection with bounded temporary lockout;
- disabled password reset and remember-me;
- required WebAuthn user verification and discoverable credentials;
- a passwordless-only `platform-passkey-browser` flow;
- the public `platform-control-center` client with exact callback, PKCE S256 and
  the built-in `oidc-amr-mapper`;
- owner, admin and viewer realm roles;
- seven-day non-secret user-event audit retention.

Import files do not overwrite an existing realm during normal startup. Changes
to the reference server therefore require a separately backed up and reviewed
Keycloak admin operation; editing this JSON alone is not runtime evidence.

Before binding the passkey-only browser flow on an existing realm:

1. verify a fresh Keycloak backup;
2. configure the exact real RP ID, identity origin, portal callback and client;
3. enroll at least two independent passwordless WebAuthn credentials for every
   administrator and for the separate break-glass identity;
4. remove any temporary bootstrap credential;
5. run `CONTROL_CENTER_ADMIN_USERS=user1,user2 sh
   scripts/keycloak-passkey-readiness.sh`;
6. keep a second authenticated session while testing the first login;
7. apply the Control Center cutover only after the readiness command passes.

The readiness command prints usernames and credential counts only. It does not
print passkey material, tokens or Keycloak passwords. A failed check must leave
the live Control Center image unchanged.
