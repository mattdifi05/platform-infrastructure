# Private application operator (opt-in)

`platform-application-operator.py` exposes POST `/v1/operator` over
`/run/platform-application-operator/operator.sock`. Install it as
`/usr/local/libexec/platform-application-operator.py` with the accompanying service.
It never executes caller-supplied commands, paths, image names or endpoints.
No application is enrolled by default. Installation does not clone an app.

Create root-owned directories `/var/lib/platform-application-operator` (0700),
its `clones` child (0700), and `ingress` child (0755). Configuration is the
root-owned, non-group/world-writable regular file
`/etc/platform-infrastructure/application-operator.json`; its ancestors must
also be root-owned and protected. The socket is 0600, owned by `peerUid`.
Root must admit the full Control Center Docker container ID as `peerContainerId`.
Linux SO_PEERCRED supplies both the UID and kernel PID; the operator checks the
process owner and exact full Docker cgroup identity, and reads back that the
pinned container is still running. A shared UID alone grants no admission. Mount the runtime socket
**directory** into that Control Center, not a stale socket inode.

## Profile

```json
{
  "version": 1,
  "cloneRecoveryAdmitted": false,
  "peerUid": 1000,
  "peerContainerId": "<full current Control Center Docker container ID>",
  "cloneRoot": "/var/lib/platform-application-operator/clones",
  "routingNetwork": "platform_private_apps",
  "ingress": {
    "container": "platform-private-apps-ingress",
    "containerId": "<full current Docker container ID>",
    "imageId": "sha256:<admitted image digest>",
    "configRoot": "/var/lib/platform-application-operator/ingress"
  },
  "apps": {}
}
```

After a Control Center container replacement, update its root-owned full pin
under the deployment lock before admitting requests. The previous or sibling
container is rejected even if it shares UID 1000 and a socket mount. No caller
can supply the peer PID or container pin. Root processes controlling Docker
remain outside this isolation boundary.

The placeholders above must be replaced with actual root-reviewed identities;
they are not accepted by validation. `routingNetwork` must be a separate Docker
**internal** network. The pinned ingress mounts `configRoot` read-only at
`/etc/nginx/conf.d`. It listens on container port **8080**, published only on
`127.0.0.1:18181`. Its root-provisioned default server must reject unknown hosts.
Activation verifies that this is its only published port and that the admitted
internal routing network is its only Docker network.
On Docker hosts that suppress port publishing for internal-only containers,
the declared binding alone does not create a listener. Provision a separate
host loopback relay to the admitted ingress container's internal IP and port
8080, and verify it by HTTP readback. Do not give the clones an external network
to work around this behavior. The operator itself does not provision a relay.
Do not connect original production containers to this network. The CC provider
must secure the exact hostname through private Access before activation.

Each `apps` entry is keyed by a safe managed application ID and has these required fields:

- `container`, `containerId`, `imageId`: current source container and immutable
  admitted image; stale identities fail closed.
- `domain`, `baseDomain`: explicit source hostname and operator-approved zone.
  An apex gets `local.`; a subdomain gets `local-` before its first label.
  No public-suffix guessing occurs.
- `sourceRoot`: absolute canonical host path mounted by that source container.
- `include`, `exclude`, `sqlite`: relative path arrays. Include is an explicit
  nonempty allowlist of files/directories; exclusions apply recursively.
  SQLite files must be listed separately and are backed up with SQLite's
  online backup API, including committed WAL data. Their parent directories
  must be root-owned/protected to prevent a privileged SQLite open race.
- `dataRoots`: zero or more `{sourceRoot,mountPath,include,exclude,sqlite}`
  manifests for uploaded/persistent data outside the main source tree.
  Destinations must be unique `/application-data/<safe-id>` paths. All writable
  source bind/volume mounts must be represented; unregistered data is not
  silently omitted. Adapt the admitted runtime configuration to these paths.
- `database`: null, or `{engine,container,containerId,imageId,name}` with engine
  `postgres` or `mariadb`. This is a dedicated **application database**, never
  the engine's data directory. An app using multiple databases needs an
  explicit supported adapter; this version accepts one SQL database.
- `runtime`: `{argv,uid,gid,environment,mountPath,databaseBinding,healthcheck,port}`.
  The executable in `argv` and `healthcheck` must be absolute. UID/GID are
  non-root. `mountPath` is exactly `/application`. `port` is the foreground web
  service's HTTP port. `environment` is a public literal map: source container
  environment is never inherited, and inherited image environment is cleared.
  `databaseBinding` is null or `{environmentName:"DATABASE_URL_FILE",
  format:"postgres-url"}` (or `mysql-url`). The application must support the
  declared FILE interface. New credentials are mounted read-only separately.

Images, foreground commands, healthchecks, file manifests and public settings
are privileged **root-reviewed admission metadata**. Image contents must have
no embedded production secrets or automatic email/payment/background jobs.
The operator never derives shell commands from source `.env` files. It excludes
`.git`, `.env*`, `.pem`, `.key`, `.p12` and `.pfx` files, plus declared exclusions;
it cannot detect arbitrary credentials embedded inside otherwise admitted code.

## Requests and state

- `{operation:"list"}` returns `{apps:[{id,domain,baseDomain}]}` only after root
  recovery admission; otherwise it returns `{apps:[]}`.
- `{operation:"plan",requestId,sourceId,targetId}` validates current identities
  and returns the bounded hostname/image/network projection, without mutation.
- `{operation:"clone",requestId,sourceId,targetId}` reserves a unique target,
  returns a durable job, and copies asynchronously. `requestId` is a canonical
  UUID; reusing it for a different request is rejected. Poll
  `{operation:"status",requestId}`.
- `{operation:"activate",requestId,publication:{hostname,verifiedAt,
  accessApplicationId}}` is sent **only by the authenticated CC owner route
  after provider readback**, with a Unix-seconds timestamp no older than 60s
  and actual Access application UUID. Never accept this receipt from browser
  input. The native bridge trusts that dedicated peer's provider verification;
  it does not independently call Cloudflare or possess its API credentials.
  The source PID must also belong to the root-admitted Control Center cgroup.
- `{operation:"cancel",requestId}` requests cancellation and stops only
  containers bearing that job UUID label; it removes only that job's generated
  ingress configuration. A running native dump/restore can take up to its
  bounded operation timeout before observing cancellation.

Jobs persist in `jobs.sqlite`. States are `queued`, `running`, `staged`,
`activating`, `available`, `failed`, `activation_failed`, `cancelled`,
`interrupted`. Interrupted work is never automatically replayed; recorded
in-flight clone containers are stopped on daemon startup. Partial destination
artifacts are retained privately for explicit operator inspection/removal.
No endpoint deletes production resources or edits their configuration.

Copy rejects symlinks, hard links, devices and sockets and uses descriptor-relative
opens. Ordinary file copies are not a coordinated application-wide transaction;
SQL dumps and individual SQLite backups have their native consistency semantics.
PostgreSQL uses `pg_dump -Fc` and restores as a newly generated restricted role.
MariaDB uses a single-transaction dump and a new schema-scoped account. Sources
with non-InnoDB tables, routines, triggers or events are rejected rather than
silently producing an incomplete clone. Both engines restore into a newly
created, pinned-image database container on the clone's private internal network;
no CREATE/GRANT/RESTORE is executed against the source database container.
Root/admin and application passwords are independently generated and private.
The native engine account UID/GID is resolved from the pinned image in a
temporary container with no network; only the newly created database data
directory is assigned that ownership for hardened engine initialization.

The foreground app and optional static companion are created stopped; no
separate scheduler or worker is started. Dedicated SQL and fresh Redis
dependencies run during staging for restore/readiness verification. It uses no host networking, Docker socket, source mount, published port,
privileged flag or added capability. Its copied files/data are writable; its
image root filesystem is read-only. Database containers have only their newly
created data and generated credential mounts. They remain off the routing network.
Activation connects only the clone app to the internal private ingress network,
starts it, waits for the admitted Docker healthcheck, writes its exact-host nginx
configuration, validates it with `nginx -t`, and reloads the pinned ingress.
`available` requires all these steps. Activation failure stops clone containers.
CC must additionally verify the actual external authenticated route before
showing an end-to-end availability claim.

## Validation

Run `python3 scripts/application-operator.test.py`. Tests use real local files and
SQLite WAL backup, plus mocked Docker/SQL tools for destination scope, durable
idempotency, secret exclusions, staging, private receipt checks, health-gated
activation and generated nginx reload. They do not prove live Docker, database
image entrypoints, credentials, Access policy or browser routing on a host.
An explicitly authorized isolated fixture exercise remains necessary before
registering a real production application. The default empty registry performs
no clone and grants no authority to an unregistered application.

## Internal ingress loopback relay

Use `platform-private-apps-proxy.socket` and `platform-private-apps-proxy.service`
when the host's Docker internal bridge suppresses published-port listeners.
The socket binds exactly `127.0.0.1:18181`; `systemd-socket-proxyd` runs as a
separate dynamic unprivileged user with no capabilities. The templates fail
closed until the root installer admits a destination:

1. Inspect the newly provisioned ingress by its full pinned container ID.
   Verify its image, read-only configuration mount, single internal network,
   and that the selected IPv4 address belongs to that network. Do not resolve
   a user-provided hostname or take an IP from a browser request.
2. Write a root-owned 0600 regular file
   `/etc/platform-infrastructure/private-ingress-proxy.env` containing only
   `PLATFORM_PRIVATE_INGRESS_TARGET=<admitted-ingress-IPv4>:8080`.
   Its parent directory must be root-owned and not writable by other users.
3. Write a root-owned service drop-in with `[Service]` and
   `IPAddressAllow=<admitted-ingress-IPv4>/32`. The template denies all other
   outbound IP destinations. Neither the dynamic address nor secrets belong
   in version control.
4. Reload systemd and enable/start the **socket**. Verify HTTP readback using
   the exact admitted private hostname and compare its application response.
   Docker binding metadata and an active socket are insufficient proof.

When the ingress is intentionally recreated, stop the socket and relay before
changing its root-owned target metadata, validate the replacement identities,
and then restart/read back. The container's private IP must be treated as stale
until re-admitted. Do not attach original apps or cloned apps to an external
network to make port publishing work. No permanent units were installed by the
fixture verification. On the verified VPS both `/usr/lib/systemd/systemd-socket-proxyd`
and `/lib/systemd/systemd-socket-proxyd` were executable.

## Current production application admission assessment (2026-10-14)

Read-only inspection of the current Scripta Students and Stexor Calendar image
metadata and bundled code identified their required dependency and encryption
adapters. The expanded disposable fixture passed PostgreSQL restore, live
SQLite WAL backup, retained encryption FILE, fresh Redis, static homepage and
API-through-companion HTTP readback. Those results prove the generic adapters;
neither actual production application has been enrolled or cloned, and backup
recovery admission remains false on the target deployment.

Both current APIs run as UID/GID 1000, execute Node from `/app`, use persistent
`/data`, and need PostgreSQL plus Redis. Scripta also uses `/processing`. The
images have baked application code, while their secret and TLS mounts are
separate and read-only. Redis configuration checks that the `rediss:` URL and
CA configuration agree. A root-reviewed clone adapter must create an isolated
Redis container with its own credential FILE, decide whether ephemeral Redis
state should be empty or preserved, and supply a matching transport. No source
Redis password, network, or TLS private key should be implicitly inherited.
The optional `cache` adapter below supplies a fresh Redis URL FILE. It does
not copy Redis data, sessions or work queues from production.

The APIs verify the request Host against their configured origin. A clone must
set the exact private origin; merely routing the hostname to an unchanged API
is insufficient. Scripta uses an application secret in AI cache handling and
has AI, SMTP, Apple/Google sign-in and APNS integrations. These require explicit
private-clone behavior and must not silently inherit production credentials or
send production notifications. Provider-dependent features remain unavailable
without separately admitted sandbox credentials and an intentional egress
policy; the current clone policy permits no external egress.

Calendar derives at-rest encryption keys from `SCRIPTA_ACCOUNT_SECRET` using
HKDF and its calendar-specific salt. A freshly generated application secret
cannot decrypt all copied encrypted application data. A data-preserving clone therefore uses a separately root-admitted
`secretBindings` entry for the persistent at-rest key, copied opaquely from its
read-only mount. This is covered by the authorized project clone. Outbound
provider credentials remain excluded. Resetting encrypted fields would be a
sanitized clone and must never be presented as a complete equivalent. Account secret
values were not read or printed during this inspection.

Scripta's original ingress also serves an independent static public-site tree
and an index file, with explicit routes before its API fallback. A proxy to the
API alone omits this website. The optional `frontend` adapter provides an isolated companion
nginx/static-site projection with explicit copy manifests and root-generated
upstreams pointing solely to the clone API. Calendar's ingress directly proxies
the API. Original nginx configurations cannot be reused verbatim because their
upstreams still identify original containers.

A real application admission still needs proof of the complete copied app
stack, environment settings, interactive data access and recovery coverage
before adding either real app entry. An empty registry is a valid installed core, but it does not demonstrate
production cloning capability.

For dynamic backups, reuse the same reviewed dependency/file manifests, bind
the snapshot manifest to the admitted application/container/image identities,
and retain native SQL dumps and SQLite backups as separate consistency proofs.
The current clone job deletes its SQL dump after restoration and is not a
backup endpoint or backup retention policy. A durable backup operation needs
its own typed operation, retention/storage admission, integrity readback and
restore verification. Ordinary copied files are not synchronized atomically
with a SQL dump: require an admitted application quiesce/export mechanism when
application-wide transaction consistency is necessary. Never discover data or
secrets by inheriting arbitrary source environment values.

## Recovery admission gate

`cloneRecoveryAdmitted` is an optional root-profile boolean and defaults to
**false**. With false or an omitted field, `list` yields no eligible apps and
both `plan` and `clone` fail before a Docker call or job reservation. This is a
root review gate, not a new backup proof framework. Set true only after the
installation's signed backup policy and capture/restore adapters actually
include dynamically created clone files, retained encryption material, SQL
volumes, relevant dependencies and operator job state, with verified restore.
Existing fixed capture roots alone do not prove this coverage. Disposable
fixtures explicitly use true for their synthetic throwaway data; their success
does not admit production recovery. The current target VPS must keep the
operator disabled and profiles unenrolled until that coverage exists.

## Optional reviewed dependency adapters

- `secretBindings`: up to four entries, each exactly
  `{sourcePath,environmentName,purpose:"data-encryption",ownerUid}`. The
  environment name is an encryption/account-secret/data-key `_FILE` variable;
  outbound provider names are refused. `ownerUid` is explicitly root-admitted
  as root or the application runtime UID. All ancestors are root-protected,
  the source is a regular single-link file with no group/world write permission,
  and the file is within a read-only source-container bind mount. The source
  key is copied opaquely into the clone's separate read-only credential mount;
  it is never returned by status or inherited from source environment values.
- `cache`: exactly `{container,containerId,imageId,environmentName}`, with
  `environmentName:"STUDENTS_REDIS_URL_FILE"`. The source identity admits the
  Redis engine image only. A new container on the private clone network starts
  with a fresh random password in an opaque configuration FILE, an empty
  tmpfs-backed data directory and persistence disabled. The application gets
  its own Redis URL FILE. No source cache directory, source password or source
  TLS private key is copied. Plain Redis is confined to that internal network;
  leave `STUDENTS_REDIS_TLS_CA_FILE` unset for this `redis:` URL.
- `frontend`: exactly `{container,containerId,imageId,sourceRoot,include,exclude,
  sitePath,indexPath,uid,gid}`. The reviewed immutable image must provide
  `/usr/sbin/nginx` and `/usr/bin/wget`. Includes must map to read-only mounts
  of the pinned source frontend. Serving paths are relative allowlisted paths;
  symlinks and special files are rejected. Copied assets mount read-only at
  `/site`. The operator generates configuration for the copied homepage,
  static files, `/api/` and API fallback, and never copies production upstream
  configuration. Both API and companion must become healthy before the exact
  private hostname is published. Only the companion joins the ingress network.
  This generic routing projection is not proof that every custom source-nginx
  location, header or redirect has equivalent behavior: verify actual routes
  when reviewing each application profile.

For the observed images, Calendar supports
`STEXOR_CALENDAR_DISABLE_JOBS=1`; its bundled code checks that exact string
before starting the scheduler. Scripta disables APNS whenever
`SCRIPTA_APNS_ENABLED` is not `true`; admit `false`. No SMTP, AI, OAuth, APNS or
external-provider credential FILE is projected by these adapters. Both APIs
must use `/usr/local/bin/node /app/server.js`, an exact private origin, the
copied data paths, the new SQL/Redis FILE paths and the retained at-rest secret.
The images and application-specific public environment still require runtime
verification. A generic Docker healthcheck cannot prove authenticated feature
parity, background-job suppression or backup completeness.
