# Installed runtime updates

Settings → Updates inventories the actual installed containers, not the application catalog or an assumed Compose version. It shows the observed version, upstream stable release, compatible candidate, affected services and asynchronous operation result. It does not install missing components or update application source/dependencies.

## Host enrollment

Run `python3 scripts/install-runtime-updates.py` as root on the target host. The installer discovers installed Compose workloads, excludes retained rollback containers, creates a dedicated 32-byte bridge capability and enables `platform-runtime-updates.service`. It does not upgrade any runtime. Re-running enrollment retains component IDs for the same enrolled services.

Mount these into Control Center without exposing the Docker socket:

* `/run/platform-updates:/run/platform-updates:ro`
* `/etc/platform-infrastructure/updates/bridge-key:/run/secrets/control_center_updates_bridge_token:ro`

Defaults are `CONTROL_CENTER_UPDATES_SOCKET=/run/platform-updates/updates.sock` and `CONTROL_CENTER_UPDATES_KEY_FILE=/run/secrets/control_center_updates_bridge_token`. The key is root-owned, group-readable by UID/GID 1000, never committed or returned by an API. Without the bridge, the screen reports unavailable and cannot apply changes.

The root-owned policy is `/etc/platform-infrastructure/updates/config.json`; local jobs, plans, logs, desired image references and recovery journals are in `/var/lib/platform-updates/`. Do not reset those records during upgrades. The worker accepts only enrolled component IDs and exact immutable plans, never a command, image URL or filesystem path from the browser.

## Update behavior

* Catalog reads require a viewer; checking stable releases requires an administrator. Reviewing/applying a plan requires an owner with fresh passkey authentication and CSRF protection.
* Plans expire after 15 minutes and bind the container/configuration fingerprint, catalog revision, candidate version and registry digest. State is checked again after downloading/building, immediately before changing a service. Idempotency is committed before starting the worker.
* PHP rebuilds the reviewed Apache image so installed extensions are retained. Node layers the same-major binary over the exact deployed application image. Isolated binary/configuration checks and service health verify the result.
* Database updates stay within the admitted series. Before starting a new database or stateful tool image, the worker stops the old service and creates an ownership-preserving consistent copy of its persistent directories. Recovery copies count toward a 20 GiB default maintenance quota; inadequate space rejects the update. This is an explicit maintenance recovery point, not a recurring backup.
* An old database is never automatically started over data that the new version may have written. Such a failure remains visible and blocks new mutations until an operator reconciles the protected journal. A restart with an unfinished mutation journal also blocks new mutations.
* Stateless failure restores the original container identity, mounts, network membership, restart policy and running/stopped state. The old image/container remains retained for recovery. Successful updates refresh only affected signed admission references and keep generation/predecessor continuity.
* Runtime changes persist in Docker and in the protected desired-image record. A later independent Compose/source deployment must deliberately retain or reconcile those image choices; the updater never silently overwrites a new application deployment.

Official Docker library metadata and curated upstream GitHub releases supply explicit stable tags. The registry manifest digest and architecture are verified; prereleases, floating tags, downgrades, unsupported series and incomplete/failed lookups do not become an update candidate. Custom platform builds or tools without a verified release path remain visible with an explicit assisted-maintenance reason.

## Verification

`python3 -m unittest discover -s deployment/host/tests -p 'test_runtime_*.py'`

`npm --prefix control-center test`

The suites cover authenticated Unix transport, roles/CSRF/passkey, replay/idempotency, stale plans, release filtering/digests, durable journals, stopped services, mount retention, rollback and database recovery gates. UI fixtures simulate operations only in an isolated local server; they never authenticate or mutate production.
