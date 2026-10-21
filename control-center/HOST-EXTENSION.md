# Optional existing-host compatibility

A clean installation contains no application integrations or default application catalog. Host state, vault keys, passkeys, databases and application directories remain independent of this optional code extension.

An existing installation can explicitly set `CONTROL_CENTER_HOST_EXTENSION_FILE=/run/platform-host-extension/index.mjs`. Mount its reviewed host-only code bundle at `/run/platform-host-extension:ro`. The directory, entrypoint, all bundled files and ancestors must be root-owned, regular files/directories, without symlinks or group/world write permissions. No other extension path is accepted. Keep the bundle outside Git and outside application source directories; do not include credentials, configuration, catalogs or application data in it.

The default export optionally provides the existing database integration, observation rendering, database-panel rendering, backup-contract functions and backup-catalog reader. Absent hooks leave the generic core active. Configured external database metadata without its required extension fails closed. Existing signed backup profiles retain their exact field names and resource identities through the reviewed host extension; do not rewrite those profiles or reset admission/replay state to fit a clean installation.

DNS scope comes exclusively from the existing protected `CONTROL_CENTER_CLOUDFLARE_DNS_CONFIG_FILE` zone list. No DNS integration is enabled without configuration; the repository contains no enrolled customer domains.

The extension does not change authentication configuration or perform catalog migrations. Preserve the existing host's origin, RP ID, auth database, vault files and keys. `CONTROL_CENTER_REQUIRE_MANAGEMENT_CIDR=true` preserves a host's management-network access policy; its default is false.

The optional `dedicatedRuntimeName(project)` hook can return an existing host runtime name for a project. Return `undefined` or `null` to use the generic runtime-prefix naming. Explicit names must be 1–128 characters, start with an ASCII letter or digit, and contain only ASCII letters, digits, underscores, periods or hyphens. Keep existing-host mappings in the protected extension; the core has no application-specific naming rules.


## Multiple trusted database profiles

An existing single-profile installation can retain `CONTROL_CENTER_TRUSTED_EXTERNAL_DATABASE_FILE` and `CONTROL_CENTER_TRUSTED_EXTERNAL_DATABASE_SHA256` unchanged. To admit additional existing databases, set `CONTROL_CENTER_ADDITIONAL_TRUSTED_DATABASES` to a JSON array of objects containing exactly `file` and `digest`:

```json
[{"file":"/run/trusted-db/profiles/example.json","digest":"<64 lowercase hexadecimal characters>"}]
```

Mount protected metadata separately, for example `/run/trusted-db:ro`; catalogs and configuration must remain outside the host-extension code bundle. The parser accepts at most eight additional entries and 8192 characters, requires absolute file paths of at most 1024 characters and lowercase SHA256 digests, and rejects extra fields. Duplicate admitted database IDs fail startup instead of overriding another profile.

The digest is the reviewed extension's canonical profile digest, not necessarily the raw file checksum. It must originate in a root/operator admission, never a browser payload or automatically discovered database name. The extension remains responsible for secure file reads, exact approved identity and connection policy, digest verification and preserving the existing single-profile contract. Additional profiles are read with `{ approvedDigest, expectedId: null }`, indicating that the extension must resolve an identity only from its explicit host registry; the legacy single-profile call does not change.

An extension providing configured trusted database profiles supplies these hooks:

- `readTrustedExternalDatabase(file, options)`: returns an admitted server-side profile or fails closed.
- `externalDatabaseRecord(profile)`: exposes non-secret display metadata for that profile.
- `externalDatabaseCapabilities(profile)`: returns its allowed `browse`, `backup`, `restore` and management capabilities.
- `externalDatabaseAdminTarget(profile)`: supplies the exact admitted host, TLS server ID and access metadata; an optional `readOnly` flag describes presentation and does not grant SQL privileges.
- `externalDatabaseAdminCredentials(profile, readPasswordFile)`: reads only the dedicated admitted credential file. Keep the returned value inside the authenticated login adapter.
- `assertExternalDatabaseAction(profile, action)`: rejects every unsupported operation, including destructive principal or database changes.
- `TRUSTED_EXTERNAL_DATABASE_IDS`: an array of reserved database IDs. Stored records colliding with these IDs are omitted, and a reserved ID without its loaded admission cannot fall through to generic credentials or host routing.
- `TRUSTED_EXTERNAL_PROJECT_IDS`: an array of reserved project identities. The generic UI and server creation guard suppress parallel principal/database creation for those projects and their aliases.

Keep application identities, approved hosts, credential paths and capability decisions in the protected host extension, outside Git. The generic core holds the admitted profiles in a private map, reuses the standard database row and authenticated administration flow, and never falls back to platform credentials for those IDs. Approval/execution checkpoints recheck the resolved database ID, rather than relying on an operation ID supplied to a controller.

Grant data editing through the dedicated database role's actual SQL privileges; opening the browser does not itself grant owner, superuser, database-drop or role-management privileges. Backup and restore authority remain with the existing reviewed backup contracts. Unsupported capability buttons are omitted from the UI and their server operations remain rejected. An installation without an extension or admissions retains the generic core behavior.

The synthetic regression tests in `tests/additional-trusted-databases.test.mjs` exercise multi-profile admission, stored-state collisions, isolated routing/credentials, capability rendering, parallel-creation guards and destructive-operation checkpoints without a live host integration or database.
