# FG-043 offline proof of concept

This PoC validates the authorization root cause shared by `CAN-148` and
`CAN-208` at the exact affected Git object. It does not start the Control
Center, authenticate to an identity provider, access a database, enumerate a
backup directory, read Vault state, or use a network.

Requirements are Node.js, Git, `tar`, and a checkout containing commit
`68cd05895b8d479ffb8167344282e7d922958bfc`.

Run from this directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper verifies the exact commit and tree and extracts a clean archive
under a random, sentinel-owned temporary root. The probe verifies hashes for
the OIDC authorization source, server routes, and authentication policy. It
then extracts and executes the actual `authorize()` method and
`isSensitivePath()` function in an isolated JavaScript context.

Synthetic viewer, admin, stale-owner, and fresh-owner sessions exercise backup
enumeration, backup preview, and Vault metadata reads, including the canonical
and `/control/v1` route forms. Existing sensitive action routes are positive
controls. A reference capability map demonstrates the expected fixed matrix.

Before the positive run, a negative regression plants a pre-existing output
directory. The probe rejects it before analysis and the wrapper verifies its
contents remain unchanged. The inner output cleanup binds its target and
sentinel to unchanged device/inode identities; the outer wrapper separately
requires its exact physical temporary path and ownership sentinel.

Representative output:

```text
[GUARD] preexisting_output_rejected=true evidence_preserved=true source_mutations=0
[+] archived revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5
[+] safety exact source slices, synthetic sessions, no server, identity provider, database, backup, Vault, or network
[+] confinement wrapper_realpath_exact=true source_exact_child=true sentinel_valid=true
[+] source hashes oidc=true server=true policy=true
[VULNERABLE] backup_files viewer=200 admin=200 stale_owner=200 fresh_owner=200
[VULNERABLE] backup_preview viewer=200 admin=200 stale_owner=200 fresh_owner=200
[VULNERABLE] vault_metadata viewer=200 admin=200 stale_owner=200 fresh_owner=200
[VULNERABLE] canonical_and_v1_aliases_equivalent=true
[POSITIVE-CONTROL] sensitive_actions viewer=403 admin=403 stale_owner=428 fresh_owner=200
[SINK] backup_inventory_fields=8 vault_metadata_fields=14 preview_nonkeyword_text_survives=true
[NEGATIVE] vault_plaintext_returned=false sealed_value_returned=false password_canary_returned=false
[REFERENCE] explicit_capabilities viewer=403 admin=403 stale_owner=428 fresh_owner=200
[+] safety server_starts=0 idp_calls=0 database_calls=0 backup_reads=0 vault_reads=0 network_attempts=0
[+] result=VULNERABLE
[+] cleanup sentinel_owned_output_removed=true
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

The supplied checkout is read only. Every generated artifact remains below the
wrapper-owned temporary root and is removed after verification.
