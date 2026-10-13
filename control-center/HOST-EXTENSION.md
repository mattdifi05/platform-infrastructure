# Optional existing-host compatibility

A clean installation contains no application integrations or default application catalog. Host state, vault keys, passkeys, databases and application directories remain independent of this optional code extension.

An existing installation can explicitly set `CONTROL_CENTER_HOST_EXTENSION_FILE=/run/platform-host-extension/index.mjs`. Mount its reviewed host-only code bundle at `/run/platform-host-extension:ro`. The directory, entrypoint, all bundled files and ancestors must be root-owned, regular files/directories, without symlinks or group/world write permissions. No other extension path is accepted. Keep the bundle outside Git and outside application source directories; do not include credentials, configuration, catalogs or application data in it.

The default export optionally provides the existing database integration, observation rendering, database-panel rendering, backup-contract functions and backup-catalog reader. Absent hooks leave the generic core active. Configured external database metadata without its required extension fails closed. Existing signed backup profiles retain their exact field names and resource identities through the reviewed host extension; do not rewrite those profiles or reset admission/replay state to fit a clean installation.

DNS scope comes exclusively from the existing protected `CONTROL_CENTER_CLOUDFLARE_DNS_CONFIG_FILE` zone list. No DNS integration is enabled without configuration; the repository contains no enrolled customer domains.

The extension does not change authentication configuration or perform catalog migrations. Preserve the existing host's origin, RP ID, auth database, vault files and keys. `CONTROL_CENTER_REQUIRE_MANAGEMENT_CIDR=true` preserves a host's management-network access policy; its default is false.

The optional `dedicatedRuntimeName(project)` hook can return an existing host runtime name for a project. Return `undefined` or `null` to use the generic runtime-prefix naming. Explicit names must be 1–128 characters, start with an ASCII letter or digit, and contain only ASCII letters, digits, underscores, periods or hyphens. Keep existing-host mappings in the protected extension; the core has no application-specific naming rules.
