# Typed platform administration

`libexec/platform-admin.py` provides bounded infrastructure operations over a
private Unix socket. It does not expose a shell, project file reader, application
database query API or secret API. The portable VPS configuration enrolls exact
infrastructure container identities and installed services; application workloads
remain outside its management scope.

The VPS unit is `systemd/platform-admin-vps.service`, installed as
`/etc/systemd/system/platform-admin.service`. It runs
`/usr/local/libexec/platform-admin.py` and loads only
`/etc/platform-infrastructure/admin/admin-host.env`. That protected file sets
`PLATFORM_ADMIN_CONFIG=/etc/platform-infrastructure/admin/admin-host.json`.
The fixed companion paths are `infrastructure-inventory.json` and
`infrastructure-token` in the same private directory. The token stays unchanged
during a path migration and is never printed.

The service creates `/run/platform-admin/admin.sock` with root ownership and
group 1000 access. `RuntimeDirectoryPreserve=restart` keeps its directory stable
across service restarts. Its durable operation, audit and replay ledger is
`/var/lib/platform-admin/operations.sqlite`, in a root-owned `0700` directory.
Enabling `platform-admin.service` provides normal boot persistence.

`empty-vps/enroll-platform-admin.py` creates a new protected enrollment only on
an explicitly prepared empty host. It refuses to replace existing configuration.
Do not run it to refresh an existing host: preserve its enrolled scope and update
actual container pins through the host's reviewed admission procedure.

For a path migration, finish or reconcile outstanding operations before stopping
the old unit. Move the existing ledger intact and preserve its requests, jobs and
audit rows. Move the existing token without rotation, update the protected
configuration and environment reference, install the neutral unit and code, then
verify the service socket and its metadata-only capabilities before retiring old
paths. Never initialize an empty replacement ledger to bypass prior replay state.

The native VPS backup runner snapshots this SQLite ledger through SQLite's backup
API. Its signed capture profile must include `/var/lib/platform-admin`. A new
profile follows the current generation and predecessor chain; retained signed
profiles and restore/replay history stay byte-identical. Do not alter the
generation, admission authority or application runtime records during this change.

Run the preserved scope checks with:

```sh
python3 deployment/host/tests/admin-host-config.test.py
python3 deployment/host/tests/admin-infrastructure-scope.test.py
python3 scripts/application-operator.test.py
```
