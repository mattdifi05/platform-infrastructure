# Fresh VPS backup preparation

Status: **capture and production recovery gates remain closed pending qualification**.
The dedicated remote namespace and shared writer quota admission are prepared; see
`HOME-FORWARD-QUOTA.md`. Namespace preparation is not a verified recovery point.
The runner implements capture and authenticated encrypted verification. The signed
root profile currently denies capture and offsite publication. Timer is not enabled.
AI admin continues to announce zero backup jobs. Human first-owner/passkey setup must precede
the first full server backup.

## Destination and quota

VPS owns `/platform-server-public-backups`; home keeps `/server-platform-backups`.
Only these two folders count toward 70,000,000,000 bytes. Other account folders are
neither listed nor included. VPS retention is maximum 14 days / two complete points,
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
The separately gated `restore-production` operation implements same-host runtime
recovery as described below. It remains disabled until native semantic recovery
of a real selected point has passed and root explicitly authorizes activation.

The queue timer and periodic backup timer stay disabled until root activation.
Catalog output records actual timer states; manual requests are rejected while the
queue worker is inactive. `compose.control-center.yaml` supplies only the read-only
catalog and existing typed queue mounts, not Docker or arbitrary host file access.
Applying that overlay recreates Control Center and requires refreshing both AI and
backup pins from the actual new container before enabling the native worker.

The VPS schedule is weekly Friday 06:05 Europe/Rome, provisionally staggered from home. Align it with the first actual Hostinger weekly recovery point when its timing is known. Hostinger frequency alone does not establish an existing recovery point. A proven existing shared lease triggers up to 30 minutes of bounded retries in the existing FTPS runner; other failures do not retry blindly. No lock stealing or successful-skip result is used.


## Manual production runtime recovery (activation gate closed)

The Backup VPS page exposes an owner:fresh GET catalog and owner:fresh, CSRF-protected
POST plan/apply operation. The owner reviews an immutable manifest and current
signed profile digest, types the selected manifest ID, acknowledges downtime and
confirms. AI and legacy queue producers cannot submit `restore-production`.
An accepted queue request is not a completed restore. The root consumer binds its
request journal before executing and refuses replay. `productionRestoreAuthorized`
defaults to false independently of capture/offsite activation.

The scope is **same host, same enrolled images and mount topology**: thirteen named
persistent volumes, native PostgreSQL/MariaDB logical exports with roles/grants,
and enrolled runtime bind configurations under the deployment directory. Broad
host-context mounts are excluded. SSH, network, OS, Cloudflare/first-enrollment
credentials, AI authority/tokens, backup authority and current queue are preserved.
The encrypted OS capsule is for separately operated offline Hostinger recovery;
this operation does not restore a complete VM or change images automatically.
The portal's users/passkeys and application data return to the selected point.
Successful recovery adopts the selected point’s running/stopped service states;
rollback restores the pre-operation service states. All 21 enrolled identities remain
covered even when only 19 are running. Capture reports both counts explicitly.

Before downtime, the selected remote receipt, ciphertext, manifest and every
artifact are authenticated using existing native FILE-based keys. Bounded archive
extraction rejects traversal and escaping links, preserving numeric UID/GID and
permissions. PostgreSQL and MariaDB restore into isolated, networkless temporary
containers using the enrolled image IDs; strict import and captured schema, row
count, role and grant comparisons must pass. No database restart or live overwrite
occurs during this qualification. Use Python 3.12+ (provided on the target Ubuntu)
for the standard tar extraction data filter. The existing `restore-drill` queue
operation performs this same staging/semantic qualification without a live switch.
Actual engine qualification remains pending the first genuine encrypted point;
source unit tests are not evidence that a production restore has run.

After staging, the root consumer rechecks the profile, stops clients before the
DB engines, and switches same-filesystem paths while retaining original siblings.
It restarts databases before the services running in the selected point and checks
that running/stopped state and health. Original-state rollback uses the pre-operation
service states. Database/TLS numeric UID/GID and modes come from metadata captured
inside the original database containers, never from a staging directory fallback.
Failure triggers rollback to retained originals; a process interruption requires
explicit root reconciliation, never blind retry. The protected journal is
`/var/lib/platform-vps-backup/production-restore.json`. For an interrupted operation,
root may invoke the installed `production-restore.py --recover-rollback`; it checks
profile signature, container pins and exact enrolled paths before switching back.
A completed journal is deliberately not accepted by this recovery command.

An incomplete journal blocks capture, queue claims and further restores. A completed
or fully rolled-back journal is terminal only after runtime health has been verified.
The next native operation moves that journal to the root-protected `restore-journals`
directory, retaining the replay ledger and original copies; weekly backups then
continue normally. Original siblings are root-owned and private, with their original
permissions recorded for rollback. Capture excludes those retained siblings. Root
reviews and removes only the specific old rollback/staging copies when appropriate;
no automatic cleanup deletes the last rollback copy. Unknown queue outcomes still
require explicit reconciliation. Neither the UI nor timers trigger a production restore
automatically. Gates remain closed until review and the real isolated-engine test.

The strict container compatibility comparison excludes only Control Center's
`CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS`,
`CONTROL_CENTER_FIRST_CONFIGURATION_TRUSTED_PROXY_CIDRS`, and
`CONTROL_CENTER_FIRST_CONFIGURATION_TOKEN_FILE`. These current management-bootstrap
settings stay in place. Database variables, all other environment entries, images,
mounts, user, command and entrypoint must still match the selected point.


The root journal is durable before decrypting or creating staging paths/containers.
Each temporary database container carries the operation label and its planned name,
image and bounded mount are recorded before create; the returned ID is recorded
before start. Interrupted pre-stop recovery validates these fields and network
`none`, removes only that operation's temporary containers/scratch/siblings, and
checks the unchanged production state. It never switches production paths when
`productionStopped=false`. Interrupted remote shared leases still require the
existing explicit quota-lock reconciliation; this routine does not steal leases.
Journal atomic replacements and data-path renames fsync their parent directories.
Staged files are flushed on their filesystems before recording stop/switch intent.
