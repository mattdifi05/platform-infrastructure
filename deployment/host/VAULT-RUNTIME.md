# Application Vault runtime delivery

The Control Center and the native operator use the same encrypted Vault store
and lock. Versions are immutable AES-256-GCM ciphertexts. Runtime files remain
necessary application inputs, with their original restricted ownership and modes.
The encryption key can remain on the VPS; it is never returned by this interface.

## Installation

Install these tracked files beneath `/usr/local/libexec/platform-vault`, retaining
their repository-relative layout and root ownership without group/world writes:

- `deployment/host/libexec/platform-vault-runtime.mjs`
- `deployment/host/libexec/vault-materialize.mjs`
- `control-center/vault/store.mjs`
- `control-center/vault/keyring.mjs`

Install `systemd/platform-vault-runtime.service` in `/etc/systemd/system`.
Create `/etc/platform-infrastructure/vault` as `0750 root:1000`, with a random
binary `bridge-token` of at least 32 bytes as `0440 root:1000` and a reviewed
`bindings.json` as `0600 root:root`. Use `vault-bindings.example.json` as a format
example, never as actual application enrollment. All paths, field names, file
ownership, ancestor metadata, container IDs and HTTP probe targets are approved
by root. A browser cannot select them.

Create `/var/lib/platform-vault/{plans,operations}` as `0700 root:root`. Include
that persistent state in the existing recovery profile, preserving its signed
generation, predecessor, replay ledger and operation state. Coordinate deployment
with the existing global operation lock; advance the Control Center runtime pin
through a signed successor. Preserve the operator's native backup choices.

Install `libexec/vault-runtime-client.mjs` in the existing root-owned, read-only
Control Center host extension and export its `vaultRuntime` function. Add only
these read-only mounts to the Control Center:

```yaml
volumes:
  - /run/platform-vault:/run/platform-vault:ro
  - /etc/platform-infrastructure/vault/bridge-token:/run/secrets/control_center_vault_bridge_token:ro
```

The socket has `0660 root:1000` permissions. The native service runs without
interactive shell access, behind HMAC authentication, bounded request bodies,
timestamp validation and persisted nonces. Vault portal routes require an owner
session, with CSRF validation for mutations. Revealing a value additionally
requires recent passkey authentication; inventory and management do not prompt
for another passkey.

## Lifecycle

1. **Adopt** reads only an enrolled existing credential, verifies its runtime
   consumer and seals a version. It changes no credential or application file.
2. **New version** stores the owner's replacement as encrypted ciphertext.
   It does not change a running service.
3. **Plan** checks the policy, Vault revision, binding revision and current
   runtime. It lists only the affected services and produces a five-minute,
   single-use confirmation token.
4. **Apply** takes the global maintenance lock and shared Vault lock. It checks
   identities again, updates only approved destinations, restarts the same
   pinned consumer containers and verifies the delivered value and service health.
5. **Rollback** prepares a plan for the previous immutable version and verifies
   the restored consumer. An apply failure restores previous files and state;
   an interrupted or unverified recovery is explicitly marked for reconciliation.

Directory-mounted files use atomic replacement and parent-directory fsync.
Single-file Docker binds require in-place fsync preserving the inode; replacing
their pathname alone would leave the running consumer on the old inode.
Runtime permissions and unrelated JSON/environment fields are preserved.

The UI separately reports delivery, application health and provider verification,
including the verification timestamp. OpenAI and Groq checks use their official
model-list endpoints without sending a prompt or returning response bodies.
Other providers are marked unverified unless a dedicated verifier is implemented.

Database/Redis credentials are marked `coupled-service`: delivery of the current
value is supported, while changing only a client credential is rejected. A
database-side rotation adapter is required before enabling coordinated rotation.
External provider keys must be created at that provider before being entered as
new versions; this operator does not revoke the predecessor automatically.

## Exclusions and recovery

Application-owned accounts/session/encryption authorities, private signing keys,
APNs/TLS keys, Vault/master keys and backup-admission custody material are not
ordinary runtime bindings. Generic imports exclude their paths before any value
read or fingerprint calculation. Existing provider and application catalogs are
not seeded into the clean-install repository.

Do not delete an active binding's Vault item or version. A missing or altered
consumer, path, owner, mode, revision or policy fails closed. The operator stops
new mutations while an operation requires reconciliation.

The shared writer lock is not automatically stolen after a crash. Root must
confirm that every previous writer has exited, reconcile an interrupted operation
against the immutable predecessor and exact runtime targets, and only then
remove the abandoned lock. Never reset operation/replay history to clear an error.
Never log plaintext, ciphertext fingerprints, provider responses or private key
material during reconciliation.
