# Control Center Vault Key Lifecycle

## Security contract

The Control Center Vault uses a dedicated versioned keyring. Session and project-gateway signing keys are not valid Vault encryption keys and there is no environment-value fallback.

Each keyring entry uses `key_id=base64url_material`. New ciphertext is version 2 and stores the stable `keyId` used for AES-256-GCM. Decryption selects that exact key, so reordering the keyring does not affect existing ciphertext. The Infra Secret Manager generates sortable, unique key IDs; an externally supplied keyring can set `CONTROL_CENTER_VAULT_ACTIVE_KEY_ID` explicitly.

The legacy project-gateway keyring is mounted read-only only as `CONTROL_CENTER_VAULT_LEGACY_KEY_FILE`. It can decrypt version 1 records during a controlled migration, but it is never used for new encryption.

## Safe migration sequence

1. Keep the live Control Center unchanged.
2. Initialize and verify `control_center_vault_keys` through the Infra Secret Manager.
3. Create private backup and escrow directories outside the repository, mode `0700`.
4. Run `scripts/control-center-vault-reencrypt.mjs --dry-run` with explicit Vault, dedicated keyring and legacy keyring paths.
5. Require a successful dry-run for every active item. Do not continue if any ciphertext cannot be authenticated.
6. During an approved maintenance window, rerun with `--apply`, both external directories and `--confirm REENCRYPT-CONTROL-CENTER-VAULT`.
7. Verify the resulting version 2 state in a restore sandbox before restarting the live Control Center.
8. Retain the pre-migration state backup and both key escrow files under the backup retention and access policy.

The apply path copies and byte-verifies the pre-migration state, escrows key material with mode `0600`, writes the new state atomically, and emits only item IDs and key IDs. It never prints plaintext values.

## Rotation

Rotate `control_center_vault_keys` only as a coordinated operation. Keep prior keys in the ring until all records and retained backups that reference them have expired or have passed a restore test. Reordering retained keys is safe. Removing a referenced key is not.

## Rollback

Stop the Control Center, restore the verified pre-migration Vault state and matching escrowed key files, then restart with the previous image/configuration. Do not delete the version 2 state, old keys, or escrow while rollback remains possible.

## Backup previews

Database dump formats `.sql`, `.sql.gz`, and `.dump` are metadata-only in the browser. The Control Center does not read, decompress, redact, or return their contents. Verification of database contents belongs to an isolated restore drill.

Unclassified `.txt`, `.md`, and generic `.json` backup files are also
metadata-only: heuristic secret-name matching is not a confidentiality control.
Only one bounded checksum record and a strict backup-signature sidecar schema
can produce content. Signature bytes are omitted. Unknown fields, malformed or
binary input, files above the small per-schema limit, symlinks, and files that
change while read all fail closed to an empty metadata-only preview.

## Current rollout gate

The implementation is sandbox-verified only. Live key initialization, Vault inventory read, migration, key rotation, Control Center restart, and deletion of any old key require a separate authorized maintenance gate and T08 restore evidence.
