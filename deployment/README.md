# Clean host deployment

A fresh VPS uses `host/empty-vps/` for core infrastructure and `vps-backup/` for its configured backup and restore service. Application catalogs, credentials, historical manifests and recovery state are not distributed with the repository. Generate and review the new host's configuration before installation.

`host/libexec/` retains the infrastructure administration bridge, scoped Docker observer proxy, GPU snapshot, DNS probe and database TLS metrics helpers. Their systemd units require explicit host paths, identities and credentials. The first-install and enrollment scripts install only the helpers they name; the directory is not a bulk-install recipe.

## Optional existing-host native backup compatibility

The LOCAL_PRIVATE broker, scheduler and signed backup contracts remain available. Their native-v2 socket adapter is optional: the admission CLI selects it only when the operator explicitly supplies `--nativeResources`. The default LOCAL_PRIVATE backup overlay does not mount the native operator socket.

Native-v2 requires a separately maintained, reviewed host backend at `/run/platform-backup-operator/operator.sock`, with the exact identities and helper pins required by its signed admission. The historical home-server FTPS, recovery, completeness and generation-specific helper chain and its systemd units are not part of the clean distribution. This repository does not install or reconstruct that backend. Its contract is retained to communicate with an existing authorized backend; it is not a generic new-host deployment configuration.

Keep any required existing-host code outside Git, separately from credentials, catalogs and application data. Removing its source snapshots from this distribution does not uninstall or update the running host. Preserve installed helpers, signing custody, admissions, generation/predecessor continuity, replay journals, recovery catalogs, service policies and application data. Do not reset or regenerate live state to match a clean installation.

`vps-backup/home-pin-inventory.py` is an existing-host inspection helper. It requires the installed historical backend on that host and is not part of the fresh-VPS backend installation.

The phpMyAdmin image consumes the dependency graph in `phpmyadmin/composer.lock` through `composer install`; platform checks and dependency auditing remain enabled.

## Optional DNS probe

The DNS probe is disabled until `PLATFORM_DNS_PROBE_HOST`, `PLATFORM_DNS_PROBE_ADDRESS` (IPv4) and `PLATFORM_DNS_PROBE_OUTPUT` are explicitly configured. With no target configuration it prints `notconfigured` and exits before network or write operations. The service optionally reads `/etc/platform-infrastructure/dns-probe.env`; keep that file root-owned, mode 0600, and its ancestors root-owned without group/world write access.

Output must be a `.prom` file in `/var/lib/platform-infrastructure/node-exporter-textfile`, a protected root-owned directory that the operator creates and exposes to the metrics collector. TLS uses only `/etc/platform-infrastructure/tls/portal-root.pem`, or an explicit `PLATFORM_DNS_PROBE_CA` file in that same protected directory. CA files must be regular, root-owned and not writable by group/others. There is no default hostname, address or metrics output file. Existing installed home-server probes are unaffected by these distribution changes.
