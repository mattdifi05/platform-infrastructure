# Offline PostgreSQL restore-boundary PoC

This PoC validates the source path tracked as `CAN-201` at the exact affected
Git commit and tree. It does not run PostgreSQL, Docker, `pg_dump`, `pg_restore`,
or SQL. It does not inspect a live cluster, open a database connection, read a
secret, or contact a network service.

Requirements are Node.js, Git, `tar`, and a checkout containing commit
`68cd05895b8d479ffb8167344282e7d922958bfc`.

Run from this directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper resolves the checkout to its physical path, verifies the exact
commit and tree, and creates a clean Git archive of that commit. Dirty
worktree files are never used. It records the archive SHA-256 and runs the
probe beneath a random wrapper-ownership sentinel.

The probe verifies exact source hashes for `scripts/infra-ops.mjs` and
`compose.yaml`. It extracts only the affected backup/restore functions and the
closest isolated MariaDB comparison. Static assertions establish that:

- application PostgreSQL resources are dumped from `enterprise-postgres`;
- the typed restore path sends them back to `enterprise-postgres`;
- the restore test creates a database in that cluster and invokes
  `pg_restore` as the default `postgres` role with `--no-owner --no-acl`;
- the same service owns the persistent live data volume and joins the platform
  network;
- the MariaDB restore test instead starts a separate `--network none`
  container and removes it in `finally`.

The demonstration object is metadata only. It records a synthetic application
owner, `securityDefiner: true`, and no function body. The model applies the
documented `--no-owner` ownership transition and shows that the affected plan
recreates the object under the restore role, `postgres`. No executable SQL is
present anywhere in the PoC.

A reference admission gate rejects the source-derived plan because it targets
the live cluster, uses a superuser, shares the live network and volume, and
destroys only a database. A negative control proves that changing to a
restricted role is still insufficient while the target remains the live
cluster. The fixed control is accepted only with a distinct disposable
cluster, restricted role, disabled network, no live mounts or secrets,
validator-only client access, and whole-cluster destruction.

Before the source trace, the wrapper plants a pre-existing output target. The
probe must refuse it, and the wrapper verifies that the sentinel bytes are
unchanged. Generated output is removed only after realpath, parent-directory,
device, inode, token, and sentinel-content checks. If ownership validation
fails, cleanup stops and the PoC fails closed.

Representative output:

```text
[GUARD] preexisting_output_rejected=true evidence_preserved=true source_mutations=0
[+] archived revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5 archive_sha256=<archive SHA-256>
[+] confinement wrapper_realpath_exact=true source_exact_child=true sentinel_valid=true
[SOURCE] postgres_backup_application_content=true restore_target_live_cluster=true restore_role_superuser=true
[SOURCE] maria_comparison_disposable_container=true maria_network_none=true maria_finally_cleanup=true
[VULNERABLE] owner_before=application_owner owner_after=postgres security_definer_authority_rebound=true
[NEGATIVE-CONTROL] restricted_role_but_live_cluster=REJECTED
[FIXED-CONTROL] isolated_cluster=true restricted_role=true network_none=true live_mounts=0 decision=ACCEPTED
[CLOSURE] synthetic_live_cluster_fingerprint_unchanged=true
[RECEIPT] generated_at=<UTC timestamp> sha256=<receipt SHA-256>
[+] result=VULNERABLE-SOURCE-PATH live_exploitation=NOT-TESTED
[+] safety docker_calls=0 database_connections=0 restores=0 sql_payloads=0 network_calls=0 source_mutations=0
[+] cleanup sentinel_owned_output_removed=true
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

The receipt contains only source facts, the inert ownership model, policy-gate
decisions, and a synthetic before/after closure fingerprint. It is hashed and
then removed with the sentinel-owned output directory. `VULNERABLE-SOURCE-PATH`
proves the affected source composition; live exploitation remains
`NOT-TESTED`.
