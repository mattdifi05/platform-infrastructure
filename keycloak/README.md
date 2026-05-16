# Keycloak import directory

Put realm export files in `keycloak/import/` before the first startup if you want
Keycloak to import them automatically.

The default Compose file starts Keycloak with `--import-realm`, but the directory
is intentionally empty so local and production hostnames can be chosen from
`.env` without importing stale redirect URIs.

Future passwordless/WebAuthn setup should be configured in the `enterprise`
realm after the first boot, then exported here when the policy is stable.
