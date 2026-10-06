# Fresh VPS backup preparation

Status: **installed but not activated; no backup generated and no remote objects changed**.
The runner implements capture and authenticated encrypted verification. The signed
root profile currently denies capture and offsite publication. Timer is not enabled.
AI admin continues to announce zero backup jobs. Human first-owner/passkey setup must precede
the first full server backup.

## Destination and quota

VPS owns `/platform-server-public-backups`; home keeps `/server-platform-backups`.
Only these two folders count toward 70,000,000,000 bytes. Other account folders are
neither listed nor included. VPS retention is maximum 14 days / six complete points,
subject to available combined space. Preserve the newest verified VPS point until a
replacement has been uploaded, downloaded, decrypted and authenticated. Never prune
home points from VPS or vice versa. If retention and newest-point preservation
conflict, fail closed and report the conflict; never silently delete the last point.

`platform_ftps_shared_quota.py` provides a remote exclusive MKD writer lock at
`/.platform-server-backup-writer-lock`, outside both archives, and bounded recursive
accounting. Both writers must hold it for the whole mutation, including pruning,
partial uploads and receipt publication. All bytes in the peer folder count,
including unfinished uploads and supplements. No peer owner/HMAC verification or
peer deletion is performed. Lost sessions leave an abandoned lock; an operator must
first reconcile both writers before removing it. No age-based lock theft is allowed.
A local configuration flag alone is **not** evidence the other host cooperates.

`home-shared-quota.patch` is a review artifact, not applied to the source helper or
home. It preserves owner marker and public receipt quota at 70 GB while reserving
peer bytes in the existing helper's working capacity. All home mutation CLI paths
are wrapped, including generation supplements. Read-only latest selection remains
unchanged. Existing retention/point verification is unchanged. The module SHA is
transitively bound by the patched helper. Applying this patch changes the helper's
admission hash and requires the existing signed admission/source qualification
workflow; do not substitute hashes in an active document, reuse a home private key,
or claim a new generation from stale proof.

Qualification before activation:

1. Review this patch against the actual installed helper and native supplement
   dependencies. Verify all account writers use the lock (no old timer/manual
   process still running).
2. Verify provider MKD is exclusive using two independent TLS sessions against the
   dedicated lock directory, with both writers paused. Existing lock must fail.
3. Prepare the dedicated VPS folder outside public_html; home flat-folder inventory
   stays unchanged. Read-back exact endpoint, certificate and folders.
4. Requalify the home helper through the existing admission authority procedure;
   no home authority material is copied to VPS or inspected by this preparation.
5. Install qualified writer code on both hosts, then set `bothWritersQualified` true
   in root-owned `/etc/platform-ftps-backup/shared-quota.json`. The provided example
   is false so staged code cannot write prematurely.
6. Enable only after full VPS capture/recovery qualification and parent approval.

## Live inventory and completeness

`inventory.py` is read-only and emits actual running Docker image/container IDs,
mounts and volume names from projects `platform_infra_vps` and `platform_server_ai`.
It refuses unclassified running containers and omits environment/command values.
This is a capture plan, **not** a signed backup manifest or successful proof.
Observed 2026-10-06: 21 containers, 13 named volumes, 54 distinct bind sources.
Regenerate after any core/container change. No source/project reader is admitted.

Capture all persistent volumes or explicitly justify their reconstruction; do not
quietly apply home's rebuild-only assumptions. PostgreSQL/MariaDB need consistent
logical dumps plus roles/grants/config and their actual pinned images. RustFS needs
a consistent native encrypted snapshot and isolated semantic restore. Redis/NATS
volumes include persistent/auth state; Grafana/Prometheus/Loki/Alertmanager volumes
are real state even on an empty-app host. Keycloak persistent state and PostgreSQL
must be coherent. Runtime sockets under `/run` and Docker sockets are recreated,
never archived. Bind-mounted config, TLS, auth, first-owner/passkeys, Vault/Secret
Manager and AI file secrets belong only in the encrypted host capsule; no plaintext
Git or report output. SQLite state requires its native online-backup API.

The existing `platform-host-recovery.py` already handles encrypted capsules and
SQLite safely, but its gf-postgres/gf-mariadb/gf-redis commands and home paths must
be parameterized for this host. Existing native catalog covers keycloak DB,
RustFS/Control Center/Secret Manager; it does **not** currently cover all above
volumes. Do not label its existing catalog a complete VPS backup.

## Remaining native integration (blocking activation)

- Parameterize the existing capture/dedup/restore helpers with a root-owned VPS
  profile; preserve default home behavior. Read FTP credentials only from the exact
  authorized native FTPS config; no complete rclone config or OneDrive OAuth copy.
- Native v2 admission currently fixes the home folder, host paths, broker identity
  and previous FTPS activation proof. Add an explicit fresh-host genesis flow whose
  genuine generation-1 authority and first local manifest precede the first remote
  receipt. Do not synthesize activation evidence or repurpose home generation 18.
- Generate new VPS encryption/HMAC/repository credentials using native CSPRNG and a
  fresh admission authority under protected custody. Mac recovery custody must be
  an explicitly protected dedicated location containing the recovery material and
  public inventory; do not read/copy/hash the existing Mac private authority leaf.
  Fresh VPS-only encryption and manifest keys and Ed25519 root-profile authority were generated on the VPS. Protected independent custody exists on the Mac at `$HOME/.local/share/platform-recovery/platform-server-public-genesis-20261006` (directory 0700, files 0600). No home key was read or copied.
- Reuse existing authenticated backup queue/manual-restore portal contracts and
  immutable operation bindings; a shell backup command is not panel integration.
  Manual restoration must preserve owner freshness/passkey checks and persistent
  operation/replay state, with first restore isolated before any production action.
- Complete product owner-authenticated queue wiring and native v2 admission integration before announcing panel restore capability. The root capture profile is a distinct signed configuration and must not be presented as the existing v2 broker admission.
- Backup runtime/service/timer files are installed but no timer is enabled; no capture or upload has run.

Timer is M/W/F 04:05 Europe/Rome with Persistent=true. It runs capture followed by
FTPS publication; both signed profile gates are currently false. ExecStopPost
recovers only writer container IDs in the protected pause journal. Targeted local
quota tests cover traversal, unsupported objects, missing sizes, two-folder totals,
contention, unqualified peer and capacity failure; provider MKD semantics and native
admission integration have not yet been tested live.


## Implemented native runner

`enroll.py` creates an independent signed root-owned capture profile from actual
Docker IDs/images/mounts, with all execution gates false. Existing enrollment is
never overwritten. `install.sh` copies runtime and the existing product manifest
contract into root-owned paths, preventing platform-user code substitution.

`platform-vps-backup-runner.py capture` exports online PostgreSQL/MariaDB logical
backups, snapshots the other volume filesystems and encrypted host configuration,
and saves actual pinned Docker image contents. Database volumes are represented
by their full logical exports rather than unsafe hot physical copies. Writer pause
is limited to a 30-second critical section; DB, Control Center and Keycloak are
never paused or restarted. Manifest and artifact signatures use the product's
existing schema/HMAC domains, with independent fresh VPS keys. AES256 GPG output
is decrypted again and every artifact SHA/HMAC checked. A successful local capture
explicitly states that no engine boot restore or offsite recovery has yet occurred.

`ftps-sync.py` consumes only
`/etc/platform-infrastructure/backup-vps/ftps-config.json` (provided by root from the
native home JSON containing exactly FTPS fields). Under the shared writer lease it
uploads bounded parts, downloads them, verifies each hash, decrypts the full
bundle and validates product manifest/artifact authentication before publishing a
receipt. Only then can it remove authenticated expired/excess VPS points. If a new
point does not fit while retaining all current points, it fails without pruning.
Interrupted remote uploads require reconciliation; unknown objects are never
silently deleted. `--restore-manifest-id` verifies one immutable authenticated point
in protected temporary storage and never restores over production.

Read-only FTPS observation on 2026-10-06: certificate verified, home namespace 38
files / 26,209,164,424 bytes, VPS namespace absent (550). This was not an upload or
proof of backup. Root must qualify HOME shared quota before creating the VPS folder
or opening offsite execution. Root must also confirm user passkey setup before
opening the full-capture gate.


## Existing owner-authenticated panel queue

The optional `control-center/backup/vps-catalog.mjs` adapter reads a root-owned,
read-only metadata catalog. The server source change is limited to that explicit
VPS catalog and leaves existing owner:fresh route authorization intact. It never
requires fake plaintext artifact files: manifests describe actual archived members
whose ciphertext was downloaded and authenticated by the root runner.

`panel-queue.py` reuses the product's queue claim/finish/unknown lifecycle. It checks
exact resource equality with the signed fresh VPS profile, rejects applications and
caller-supplied commands, binds a root-owned request journal before execution and
refuses replay. Backup runs the same capture+verified FTPS path; restore-drill
selects one exact immutable VPS manifest and verifies it in isolated scratch.
Production overwrite restore is **not** implemented by this adapter. Do not label
an archive-integrity drill as a full server boot recovery.

The queue timer and periodic backup timer stay disabled until root activation.
Catalog output records actual timer states; manual requests are rejected while the
queue worker is inactive. `compose.control-center.yaml` supplies only the read-only
catalog and existing typed queue mounts, not Docker or arbitrary host file access.
Applying that overlay recreates Control Center and requires refreshing both AI and
backup pins from the actual new container before enabling the native worker.

The VPS schedule is staggered to M/W/F 04:05 Europe/Rome, one hour after home. A proven existing shared lease triggers up to 30 minutes of bounded retries in the existing FTPS runner; other failures do not retry blindly. No lock stealing or successful-skip result is used.
