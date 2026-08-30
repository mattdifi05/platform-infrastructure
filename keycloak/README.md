# Keycloak application identity

Keycloak remains the identity provider for application workloads that use the
`platform` realm. It is not part of Control Center authentication; the Control
Center owns its passkey and session data in PostgreSQL.

`keycloak/import/platform-realm.json` is first-boot input for the pinned
Keycloak image. The matching file under `keycloak/templates/` is the editable
example. The realm keeps:

- registration and password reset disabled by default;
- bounded brute-force protection;
- required WebAuthn user verification settings for application clients that
  choose to use them;
- the public `platform-web` client;
- realm roles used by application authorization;
- seven-day, non-secret user-event retention.

The old `platform-control-center` client, its callback/backchannel endpoints
and its custom browser-flow bootstrap are intentionally absent. Do not add
them back for Control Center access.

Realm imports do not overwrite an existing realm during normal startup.
Changing either JSON file is therefore not proof that live Keycloak changed.
Any existing-realm modification requires an independent database backup, an
exact reviewed admin operation and application login smoke tests. The V1.1
cleanup does not apply a realm mutation to the live server.

The localhost URLs in the import are reference defaults. A deployment must
render exact application origins and redirect URIs for its environment without
placing client secrets or administrator credentials in Git.
