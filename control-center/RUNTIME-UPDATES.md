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
* “Update all” reviews one immutable plan containing every eligible family and its latest stable target. All candidate images are prepared before the first service is stopped. The worker then reports the current service, verified/completed service counts and a durable result for every service. A failure stops the batch; already committed families remain updated, while the current stateless family is rolled back.
* PHP rebuilds the reviewed Apache image so installed extensions are retained. Each runtime family has one shared target version for all enrolled services. Node prepares a separate layer over each exact deployed application image, checks declared engine compatibility and native addons in isolation, then updates the whole family; an incompatible image blocks the group before any service is stopped. Isolated binary/configuration checks and service health verify the result.
* Database updates stay within the admitted series. Before starting a new database or stateful tool image, the worker stops the old service and creates an ownership-preserving consistent copy of its persistent directories. Recovery copies count toward a 20 GiB default maintenance quota; inadequate space rejects the update. This is an explicit maintenance recovery point, not a recurring backup.
* An old database is never automatically started over data that the new version may have written. Such a failure remains visible and blocks new mutations until an operator reconciles the protected journal. A restart with an unfinished mutation journal also blocks new mutations.
* Stateless failure restores the original container identity, mounts, network membership, restart policy and running/stopped state. The old image/container remains retained for recovery. Successful updates refresh only affected signed admission references and keep generation/predecessor continuity.
* Runtime changes persist in Docker and in the protected desired-image record. A later independent Compose/source deployment must deliberately retain or reconcile those image choices; the updater never silently overwrites a new application deployment.

Official Docker library metadata and curated upstream GitHub releases supply explicit stable tags. The destination is the latest verified stable version, without forcing intermediate patch/minor releases. A database major migration or a component without a verified update path is shown as requiring assisted maintenance rather than silently selecting an older destination. The registry manifest digest and architecture are verified; prereleases, floating tags, downgrades and incomplete/failed lookups do not become an update candidate.

While a job runs, the UI polls only its inexpensive status endpoint every two seconds, retains the job through temporary connection failures and refreshes inventory when it finishes. Background inventory refreshes do not display a fake update progress state. Service verification and final family registration are shown separately; the bar reaches completion only after the operation succeeds.

The compact list places available updates first, without category filters. Stable keyed rows preserve open details and focus during polling; only changed states and actual row movements animate, respecting reduced motion. Per-service details remain available without expanding completed results by default.

Settings panels inherit the same surface padding and border tokens as other portal sections. Grafana's offline profile disables remote plugin checks and key retrieval while retaining embedded-key signature verification; runtime upgrades remain host-managed. The optional host-metrics overlay includes only a read-only udev metadata directory alongside its finite proc-file bindings. Redis hosts persist the kernel overcommit policy needed for background persistence.

An idle native backup queue performs no capture admission. Explicit, protected OFF state denies queued backup work before capture, upload or recovery side effects; activation and restore still require the full signed inventory. Runtime recreation uses the canonical Docker no-new-privileges syntax without weakening the existing protection.

## Server errors and warnings

The separate “Errori e avvisi” navigation page is a read-only viewer capability. It uses the authenticated native bridge without loading the application catalog and refreshes every fifteen seconds only while visible. The collector coalesces requests for twelve seconds and reads bounded systemd, Docker, update-journal and host-capacity metadata. System journal events are limited to the current boot, the last twenty-four hours and an explicit infrastructure-unit/kernel allowlist; application logs and environment variables are not read.

Active observations and recent history are distinct. Historical journal entries do not imply that a problem is still active or has been resolved. Failed sources, truncated feeds and stale cached results are explicit and never produce an all-clear. Messages are redacted and bounded before leaving the host; the HTTP projection returns only documented fields and the frontend renders them as text. This page cannot acknowledge, delete, restart or repair services.

## Operating system

A separate panel above runtime updates shows APT status and counts without listing packages. Checking refreshes APT metadata and simulates the upgrade. An owner with fresh passkey authentication reviews an expiring plan before applying the exact package versions; automatic/manual package flags and existing configuration files are preserved. Changes to installed versions or package candidates invalidate the plan. Host maintenance shares the global operation lock with container updates.

The bridge keeps its filesystem sandbox. Fixed, root-owned companion workers execute APT through transient systemd units; neither the browser nor the bridge API accepts a command or arbitrary worker path. Package failures never claim automatic rollback. Reboot is separately confirmed with `REBOOT`, available only when the OS requires it, journaled before acknowledgement, and scheduled after the HTTP response. A changed boot ID and service health establish completion after reconnection. Installing this feature and opening the panel do not run an upgrade or reboot.

Traefik updates additionally require all effective file-provider configuration to live on read-only persistent mounts. Plans bind its contents and require a root-configured HTTP route probe after startup: a healthy ping with a missing portal route is a failed update.

Host package maintenance runs independently of the bridge connection. The worker persists progress and its final result before attempting to send output; a closed pipe must not interrupt dpkg or automatic-package flag restoration. After a bridge restart, the service reads that durable result and verifies package versions, a clean dpkg audit, restored package flags and the original service baseline before declaring success. It never silently retries an interrupted upgrade.

When syncing infrastructure source, preserve deployment-private activation inputs even when an older installation stores them inside the checkout. In particular, do not overlay an active router's workload lock with the repository's factory template or change its expected digest, owner or private file mode. Inspect active mounts and activation receipts first; deploy code separately from those runtime inputs and retain their existing permissions.

## Verification

`python3 -m unittest discover -s deployment/host/tests -p 'test_runtime_*.py'`

`python3 -m unittest discover -s deployment/host/tests -p 'test_host_updates.py'`

`python3 -m unittest discover -s deployment/host/tests -p 'test_server_events.py'`

`npm --prefix control-center test`

The suites cover authenticated Unix transport, roles/CSRF/passkey, replay/idempotency, stale plans, release filtering/digests, durable journals, stopped services, mount retention, rollback and database recovery gates. UI fixtures simulate operations only in an isolated local server; they never authenticate or mutate production.
